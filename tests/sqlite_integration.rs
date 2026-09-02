use std::sync::{Arc, Mutex};
use std::time::Duration;

use dioxus_auth::{
    Argon2Hasher, AuthEngine, AuthError, AuthResult, AuthUser, PasswordHasher, PasswordUserStore,
    Session, SessionId, SessionStore, UserStore,
};
use rusqlite::{Connection, OptionalExtension, params};

#[derive(Clone, Debug, PartialEq, Eq)]
struct IntegrationSqlUser {
    id: u64,
    email: String,
    password_hash: String,
}

impl AuthUser for IntegrationSqlUser {
    type Id = u64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> Option<&str> {
        Some(&self.password_hash)
    }
}

#[derive(Clone)]
struct TestSqlStore {
    conn: Arc<Mutex<Connection>>,
}

impl TestSqlStore {
    fn new_memory() -> Self {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at_unix INTEGER NOT NULL,
                expires_at_unix INTEGER NOT NULL,
                auth_hash TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            ",
        )
        .unwrap();
        Self {
            conn: Arc::new(Mutex::new(conn)),
        }
    }

    fn insert_user(&self, email: &str, password_hash: &str) -> IntegrationSqlUser {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO users (email, password_hash) VALUES (?1, ?2)",
            params![email, password_hash],
        )
        .unwrap();
        let id = conn.last_insert_rowid() as u64;
        IntegrationSqlUser {
            id,
            email: email.to_string(),
            password_hash: password_hash.to_string(),
        }
    }
}

impl UserStore for TestSqlStore {
    type User = IntegrationSqlUser;

    async fn find_by_id(&self, id: &u64) -> AuthResult<Option<IntegrationSqlUser>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuthError::Store(e.to_string()))?;
        let user = conn
            .query_row(
                "SELECT id, email, password_hash FROM users WHERE id = ?1",
                params![id],
                |row| {
                    Ok(IntegrationSqlUser {
                        id: row.get(0)?,
                        email: row.get(1)?,
                        password_hash: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(|e| AuthError::Store(e.to_string()))?;
        Ok(user)
    }
}

impl PasswordUserStore for TestSqlStore {
    async fn find_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<(IntegrationSqlUser, String)>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuthError::Store(e.to_string()))?;
        let result = conn
            .query_row(
                "SELECT id, email, password_hash FROM users WHERE email = ?1",
                params![identifier],
                |row| {
                    let hash: String = row.get(2)?;
                    let user = IntegrationSqlUser {
                        id: row.get(0)?,
                        email: row.get(1)?,
                        password_hash: hash.clone(),
                    };
                    Ok((user, hash))
                },
            )
            .optional()
            .map_err(|e| AuthError::Store(e.to_string()))?;
        Ok(result)
    }
}

impl SessionStore<u64> for TestSqlStore {
    async fn save_session(&self, session: Session<u64>) -> AuthResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuthError::Store(e.to_string()))?;
        conn.execute(
            "
            INSERT INTO sessions (id, user_id, created_at_unix, expires_at_unix, auth_hash)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(id) DO UPDATE SET
                expires_at_unix = excluded.expires_at_unix,
                auth_hash = excluded.auth_hash
            ",
            params![
                session.id().as_str(),
                session.user_id(),
                session.created_at_unix(),
                session.expires_at_unix(),
                session.auth_hash(),
            ],
        )
        .map_err(|e| AuthError::Store(e.to_string()))?;
        Ok(())
    }

    async fn find_session(&self, id: &SessionId) -> AuthResult<Option<Session<u64>>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuthError::Store(e.to_string()))?;
        let session = conn
            .query_row(
                "SELECT id, user_id, created_at_unix, expires_at_unix, auth_hash FROM sessions WHERE id = ?1",
                params![id.as_str()],
                |row| {
                    let s_id = SessionId::new(row.get::<_, String>(0)?);
                    let u_id = row.get::<_, u64>(1)?;
                    let c_at = row.get::<_, u64>(2)?;
                    let e_at = row.get::<_, u64>(3)?;
                    let hash = row.get::<_, Option<String>>(4)?;

                    let mut s = Session::new(s_id, u_id, c_at, e_at);
                    if let Some(h) = hash {
                        s = s.with_auth_hash(h);
                    }
                    Ok(s)
                },
            )
            .optional()
            .map_err(|e| AuthError::Store(e.to_string()))?;
        Ok(session)
    }

    async fn delete_session(&self, id: &SessionId) -> AuthResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuthError::Store(e.to_string()))?;
        conn.execute("DELETE FROM sessions WHERE id = ?1", params![id.as_str()])
            .map_err(|e| AuthError::Store(e.to_string()))?;
        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: &u64) -> AuthResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuthError::Store(e.to_string()))?;
        conn.execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id])
            .map_err(|e| AuthError::Store(e.to_string()))?;
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn sqlite_adapter_external_integration_test() {
    let store = Arc::new(TestSqlStore::new_memory());
    let hasher = Argon2Hasher::new();
    let raw_pass = "secure_integration_123";
    let hash = hasher.hash_password(raw_pass).unwrap();

    let user = store.insert_user("sql_user@example.com", &hash);

    let engine = AuthEngine::builder(store.clone(), store.clone())
        .session_ttl(Duration::from_secs(3600))
        .build();

    // 1. Successful authentication against SQLite
    let (authed_user, session) = engine
        .login("sql_user@example.com", raw_pass)
        .await
        .expect("Login against SQLite must succeed");
    assert_eq!(authed_user, user);

    // 2. Validate SQLite session
    let validated = engine
        .validate_session(session.id())
        .await
        .unwrap()
        .expect("Session must exist in SQLite");
    assert_eq!(validated, user);

    // 3. Revoke session in SQLite
    engine.logout(session.id()).await.unwrap();
    assert_eq!(engine.validate_session(session.id()).await.unwrap(), None);
}
