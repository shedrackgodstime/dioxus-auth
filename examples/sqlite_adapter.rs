//! Real SQLite / Turso-compatible Storage Adapter with `AuthEngine` and Argon2id.
//!
//! Demonstrates how an application implements `PasswordUserStore` and `SessionStore`
//! to integrate with `dioxus-auth::AuthEngine` with real SQL queries and password hashing.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use dioxus::prelude::*;
use dioxus_auth::{
    Argon2Hasher, AuthEngine, AuthError, AuthProvider, AuthResult, AuthStatus, AuthUser,
    PasswordHasher, PasswordUserStore, Session, SessionId, SessionStore, UserStore,
};
use rusqlite::{Connection, OptionalExtension, params};

/// Application custom User model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DbUser {
    pub id: u64,
    pub username: String,
    pub email: String,
    pub password_hash: String,
}

impl AuthUser for DbUser {
    type Id = u64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> Option<&str> {
        Some(&self.password_hash)
    }
}

/// A real SQLite database storage adapter implementing `UserStore`, `PasswordUserStore`, and `SessionStore`.
#[derive(Clone)]
pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStore {
    /// Initialize an in-memory SQLite database and create tables.
    pub fn new_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.create_tables()?;
        Ok(store)
    }

    /// Create the `users` and `sessions` tables.
    pub fn create_tables(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at_unix INTEGER NOT NULL,
                expires_at_unix INTEGER NOT NULL,
                auth_hash TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            ",
        )?;
        Ok(())
    }

    /// Insert a new user into the database with an Argon2-hashed password.
    pub fn create_user(
        &self,
        username: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<DbUser, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?1, ?2, ?3)",
            params![username, email, password_hash],
        )?;
        let id = conn.last_insert_rowid() as u64;
        Ok(DbUser {
            id,
            username: username.to_string(),
            email: email.to_string(),
            password_hash: password_hash.to_string(),
        })
    }
}

impl UserStore for SqliteStore {
    type User = DbUser;

    async fn find_by_id(&self, id: &u64) -> AuthResult<Option<DbUser>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuthError::Store(e.to_string()))?;
        let user = conn
            .query_row(
                "SELECT id, username, email, password_hash FROM users WHERE id = ?1",
                params![id],
                |row| {
                    Ok(DbUser {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        email: row.get(2)?,
                        password_hash: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(|e| AuthError::Store(e.to_string()))?;

        Ok(user)
    }
}

impl PasswordUserStore for SqliteStore {
    async fn find_by_identifier(&self, identifier: &str) -> AuthResult<Option<(DbUser, String)>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuthError::Store(e.to_string()))?;
        let result = conn
            .query_row(
                "SELECT id, username, email, password_hash FROM users WHERE email = ?1 OR username = ?1",
                params![identifier],
                |row| {
                    let hash: String = row.get(3)?;
                    let user = DbUser {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        email: row.get(2)?,
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

impl SessionStore<u64> for SqliteStore {
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
                    let sess_id = SessionId::new(row.get::<_, String>(0)?);
                    let user_id = row.get::<_, u64>(1)?;
                    let created_at = row.get::<_, u64>(2)?;
                    let expires_at = row.get::<_, u64>(3)?;
                    let auth_hash = row.get::<_, Option<String>>(4)?;

                    let mut s = Session::new(sess_id, user_id, created_at, expires_at);
                    if let Some(hash) = auth_hash {
                        s = s.with_auth_hash(hash);
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

#[tokio::main(flavor = "current_thread")]
async fn main() {
    println!("=== Testing AuthEngine with Real SQLite Store ===");

    // 1. Setup SQLite Store and password hasher
    let store = Arc::new(SqliteStore::new_in_memory().unwrap());
    let hasher = Argon2Hasher::new();

    // 2. Insert test user with Argon2-hashed password
    let raw_password = "correct_horse_battery_staple";
    let password_hash = hasher.hash_password(raw_password).unwrap();
    let user = store
        .create_user("charlie", "charlie@example.com", &password_hash)
        .unwrap();
    println!(
        "✓ User created in SQLite: {} ({})",
        user.username, user.email
    );

    // 3. Build AuthEngine wired to SQLite store
    let engine = AuthEngine::builder(store.clone(), store.clone())
        .session_ttl(Duration::from_secs(7200))
        .build();

    // 4. Test failed login
    let failed = engine.login("charlie@example.com", "wrong_password").await;
    assert_eq!(failed.unwrap_err(), AuthError::Unauthenticated);
    println!("✓ Wrong password correctly rejected by AuthEngine");

    // 5. Test successful login
    let (authed_user, session) = engine
        .login("charlie@example.com", raw_password)
        .await
        .expect("Login failed");
    assert_eq!(authed_user, user);
    println!(
        "✓ AuthEngine::login verified Argon2 password and issued session: {}",
        session.id().as_str()
    );

    // 6. Test session validation
    let validated = engine
        .validate_session(session.id())
        .await
        .unwrap()
        .expect("Session should be valid in SQLite");
    assert_eq!(validated, user);
    println!("✓ AuthEngine::validate_session loaded active session from SQLite");

    // 7. Test Dioxus UI mount
    let mut vdom = VirtualDom::new_with_props(App, AppProps { user: authed_user });
    vdom.rebuild_in_place();
    println!("✓ Dioxus AuthProvider successfully mounted with SQLite authenticated user");

    // 8. Test logout
    engine.logout(session.id()).await.unwrap();
    assert_eq!(engine.validate_session(session.id()).await.unwrap(), None);
    println!("✓ AuthEngine::logout revoked session in SQLite");

    println!("\n=== All SQLite + AuthEngine tests completed successfully! ===");
}

#[derive(Props, Clone, PartialEq)]
struct AppProps {
    user: DbUser,
}

#[component]
fn App(props: AppProps) -> Element {
    rsx! {
        AuthProvider::<DbUser> {
            initial_status: AuthStatus::Authenticated(props.user.clone()),
            Dashboard {}
        }
    }
}

#[component]
fn Dashboard() -> Element {
    let auth = dioxus_auth::use_auth::<DbUser>();
    let user = auth.user().unwrap();

    rsx! {
        div {
            h1 { "Welcome to Dashboard" }
            p { "User: {user.username} (ID: {user.id})" }
            p { "Email: {user.email}" }
        }
    }
}
