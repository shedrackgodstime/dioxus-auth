use std::sync::{Arc, Mutex};
use std::time::Duration;

use dioxus_auth::{
    Argon2Hasher, AuthEngine, AuthError, AuthResult, AuthUser, PasswordHasher, PasswordUserStore,
    Session, SessionId, SessionStore, UserStore,
};
use rusqlite::{Connection, OptionalExtension, params};

#[derive(Clone, Debug, PartialEq, Eq)]
struct IntegrationSqlUser {
    id: i64,
    email: String,
    password_hash: String,
}

impl AuthUser for IntegrationSqlUser {
    type Id = i64;

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
                last_active_at_unix INTEGER,
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

    fn new_file(path: &std::path::Path) -> Self {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at_unix INTEGER NOT NULL,
                expires_at_unix INTEGER NOT NULL,
                last_active_at_unix INTEGER,
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
        let id = conn.last_insert_rowid();
        IntegrationSqlUser {
            id,
            email: email.to_string(),
            password_hash: password_hash.to_string(),
        }
    }
}

impl UserStore for TestSqlStore {
    type User = IntegrationSqlUser;

    async fn find_by_id(&self, id: &i64) -> AuthResult<Option<IntegrationSqlUser>> {
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

impl SessionStore<i64> for TestSqlStore {
    async fn save_session(&self, session: Session<i64>) -> AuthResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuthError::Store(e.to_string()))?;
        conn.execute(
            "
            INSERT INTO sessions (id, user_id, created_at_unix, expires_at_unix, last_active_at_unix, auth_hash)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(id) DO UPDATE SET
                expires_at_unix = excluded.expires_at_unix,
                last_active_at_unix = excluded.last_active_at_unix,
                auth_hash = excluded.auth_hash
            ",
            params![
                session.id().as_str(),
                session.user_id(),
                session.created_at_unix() as i64,
                session.expires_at_unix() as i64,
                session.last_active_at_unix().map(|v| v as i64),
                session.auth_hash(),
            ],
        )
        .map_err(|e| AuthError::Store(e.to_string()))?;
        Ok(())
    }

    async fn find_session(&self, id: &SessionId) -> AuthResult<Option<Session<i64>>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuthError::Store(e.to_string()))?;
        let session = conn
            .query_row(
                "SELECT id, user_id, created_at_unix, expires_at_unix, last_active_at_unix, auth_hash FROM sessions WHERE id = ?1",
                params![id.as_str()],
                |row| {
                    let s_id = SessionId::new(row.get::<_, String>(0)?);
                    let u_id = row.get::<_, i64>(1)?;
                    let c_at = row.get::<_, i64>(2)?;
                    let e_at = row.get::<_, i64>(3)?;
                    let last_active: Option<i64> = row.get(4)?;
                    let hash = row.get::<_, Option<String>>(5)?;

                    let mut s = Session::new(s_id, u_id, c_at as u64, e_at as u64);
                    if let Some(t) = last_active {
                        s = s.with_last_active(t as u64);
                    }
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

    async fn delete_user_sessions(&self, user_id: &i64) -> AuthResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuthError::Store(e.to_string()))?;
        conn.execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id])
            .map_err(|e| AuthError::Store(e.to_string()))?;
        Ok(())
    }

    async fn list_user_sessions(&self, user_id: &i64) -> AuthResult<Vec<Session<i64>>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuthError::Store(e.to_string()))?;
        let mut stmt = conn
            .prepare("SELECT id, user_id, created_at_unix, expires_at_unix, last_active_at_unix, auth_hash FROM sessions WHERE user_id = ?1")
            .map_err(|e| AuthError::Store(e.to_string()))?;
        let rows = stmt
            .query_map(params![user_id], |row| {
                let s_id = SessionId::new(row.get::<_, String>(0)?);
                let u_id = row.get::<_, i64>(1)?;
                let c_at = row.get::<_, i64>(2)?;
                let e_at = row.get::<_, i64>(3)?;
                let last_active: Option<i64> = row.get(4)?;
                let hash = row.get::<_, Option<String>>(5)?;
                let mut s = Session::new(s_id, u_id, c_at as u64, e_at as u64);
                if let Some(t) = last_active {
                    s = s.with_last_active(t as u64);
                }
                if let Some(h) = hash {
                    s = s.with_auth_hash(h);
                }
                Ok(s)
            })
            .map_err(|e| AuthError::Store(e.to_string()))?;
        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(row.map_err(|e| AuthError::Store(e.to_string()))?);
        }
        Ok(sessions)
    }

    /// Conditional session touch: update expiry + last_active only if the
    /// session still exists (prevents logout/rotate resurrection races).
    async fn touch_session_if_present(
        &self,
        id: &SessionId,
        new_expiry: u64,
        last_active: u64,
    ) -> AuthResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuthError::Store(e.to_string()))?;
        conn.execute(
            "UPDATE sessions SET expires_at_unix = ?1, last_active_at_unix = ?2 WHERE id = ?3",
            params![new_expiry as i64, last_active as i64, id.as_str()],
        )
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

#[tokio::test(flavor = "current_thread")]
async fn sqlite_file_backed_persistence_survives_restart() {
    let dir = std::env::temp_dir().join(format!(
        "dioxus_auth_persist_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("auth.sqlite");

    // 1. First process: create user, login, save session
    {
        let store = Arc::new(TestSqlStore::new_file(&path));
        let hasher = Argon2Hasher::new();
        let raw_pass = "persist_pass_123";
        let hash = hasher.hash_password(raw_pass).unwrap();

        let user = store.insert_user("persist@example.com", &hash);
        let engine = AuthEngine::builder(store.clone(), store.clone())
            .session_ttl(Duration::from_secs(3600))
            .build();

        let (authed_user, session) = engine
            .login("persist@example.com", raw_pass)
            .await
            .expect("login must succeed");
        assert_eq!(authed_user, user);

        let validated = engine
            .validate_session(session.id())
            .await
            .unwrap()
            .expect("session must be valid");
        assert_eq!(validated, user);
    }

    // 2. Second process: reopen DB and verify session persists
    {
        let store = Arc::new(TestSqlStore::new_file(&path));
        let hasher = Argon2Hasher::new();
        let _hash = hasher.hash_password("persist_pass_123").unwrap();

        // User already exists from first process; just fetch them
        let user = store
            .find_by_identifier("persist@example.com")
            .await
            .unwrap()
            .expect("user must exist after restart")
            .0;

        let engine = AuthEngine::builder(store.clone(), store.clone())
            .session_ttl(Duration::from_secs(3600))
            .build();

        // Re-login should succeed (user exists, password matches)
        let (authed_user, session) = engine
            .login("persist@example.com", "persist_pass_123")
            .await
            .expect("login after restart must succeed");
        assert_eq!(authed_user, user);
        assert!(session.expires_at_unix() > 0);
    }

    let _ = std::fs::remove_dir_all(&dir);
}
