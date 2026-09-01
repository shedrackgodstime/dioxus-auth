//! Proof-of-Concept: Real SQLite / Turso-compatible Storage Adapter for `dioxus-auth`.
//!
//! This demonstrates how a real SQL database integrates with `dioxus-auth`
//! by implementing `UserStore` and `SessionStore` without leaking database
//! specifics or connection pools into Dioxus UI components.

use std::sync::{Arc, Mutex};

use dioxus::prelude::*;
use dioxus_auth::{
    AuthError, AuthProvider, AuthResult, AuthStatus, AuthUser, Session, SessionId,
    SessionStore, UserStore,
};
use rusqlite::{params, Connection, OptionalExtension};

/// The application's custom User model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DbUser {
    pub id: u64,
    pub username: String,
    pub email: String,
}

impl AuthUser for DbUser {
    type Id = u64;

    fn id(&self) -> Self::Id {
        self.id
    }
}

/// A real SQLite database storage adapter implementing `UserStore` and `SessionStore`.
///
/// Uses standard SQL compatible with SQLite, Turso / libSQL, and other SQL backends.
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

    /// Create the required `users` and `sessions` database tables.
    pub fn create_tables(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE
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

    /// Helper to insert a new user for testing.
    pub fn insert_user(&self, username: &str, email: &str) -> Result<DbUser, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO users (username, email) VALUES (?1, ?2)",
            params![username, email],
        )?;
        let id = conn.last_insert_rowid() as u64;
        Ok(DbUser {
            id,
            username: username.to_string(),
            email: email.to_string(),
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
                "SELECT id, username, email FROM users WHERE id = ?1",
                params![id],
                |row| {
                    Ok(DbUser {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        email: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(|e| AuthError::Store(e.to_string()))?;

        Ok(user)
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

                    let mut session = Session::new(sess_id, user_id, created_at, expires_at);
                    if let Some(hash) = auth_hash {
                        session = session.with_auth_hash(hash);
                    }
                    Ok(session)
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

        conn.execute(
            "DELETE FROM sessions WHERE id = ?1",
            params![id.as_str()],
        )
        .map_err(|e| AuthError::Store(e.to_string()))?;

        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: &u64) -> AuthResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuthError::Store(e.to_string()))?;

        conn.execute(
            "DELETE FROM sessions WHERE user_id = ?1",
            params![user_id],
        )
        .map_err(|e| AuthError::Store(e.to_string()))?;

        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    println!("=== Running dioxus-auth SQLite Adapter Proof of Concept ===");

    // 1. Initialize SQLite Database Store
    let store = SqliteStore::new_in_memory().expect("Failed to initialize SQLite");

    // 2. Insert test user into SQLite
    let created_user = store
        .insert_user("alice", "alice@example.com")
        .expect("Failed to insert user");
    println!("✓ Inserted user in SQLite: {created_user:?}");

    // 3. Verify user retrieval via UserStore trait
    let fetched_user = store
        .find_by_id(&created_user.id)
        .await
        .expect("Query failed")
        .expect("User not found");
    assert_eq!(fetched_user, created_user);
    println!("✓ UserStore::find_by_id returned: {fetched_user:?}");

    // 4. Create and save a session into SQLite
    let session_id = SessionId::new("sqlite-session-tok-999");
    let now = 1_700_000_000;
    let expires = now + 3600;
    let session = Session::new(session_id.clone(), created_user.id, now, expires)
        .with_auth_hash("argon2_hash_sample");

    store
        .save_session(session.clone())
        .await
        .expect("Failed to save session");
    println!("✓ SessionStore::save_session saved to SQLite sessions table");

    // 5. Retrieve session from SQLite
    let fetched_session = store
        .find_session(&session_id)
        .await
        .expect("Query failed")
        .expect("Session not found");
    assert_eq!(fetched_session, session);
    println!("✓ SessionStore::find_session loaded session from SQLite");

    // 6. Delete session and verify revocation
    store
        .delete_session(&session_id)
        .await
        .expect("Failed to delete session");
    assert_eq!(
        store.find_session(&session_id).await.unwrap(),
        None
    );
    println!("✓ SessionStore::delete_session revoked session in SQLite");

    // 7. Verify Dioxus UI component integration
    let mut vdom = VirtualDom::new_with_props(
        App,
        AppProps {
            user: created_user.clone(),
        },
    );
    vdom.rebuild_in_place();
    println!("✓ Dioxus AuthProvider successfully mounted with SQLite-backed User!");

    println!("\n=== All SQLite Proof of Concept assertions passed successfully! ===");
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
            UserView {}
        }
    }
}

#[component]
fn UserView() -> Element {
    let auth = dioxus_auth::use_auth::<DbUser>();
    let user = auth.user().unwrap();

    rsx! {
        div {
            h2 { "Profile" }
            p { "User ID: {user.id}" }
            p { "Username: {user.username}" }
            p { "Email: {user.email}" }
        }
    }
}
