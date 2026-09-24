//! Copy-paste `SQLite` reference store for dioxus-auth (1d).
//!
//! You own this file: copy it into your app, rename the tables, add columns,
//! swap the user type. The crate never scaffolds, migrates, or touches your
//! database. The schema in `README.md` is documentation you apply yourself,
//! and this module is one honest implementation of it.
//!
//! Shape: authentication subjects live in `subjects` with the app link
//! (`app_ref`) on the subject row, never on credential rows. Credentials
//! (`accounts`) and sessions point at the subject and cascade on subject
//! deletion. Your application rows (`users`) carry zero auth columns.
//!
//! [`SqliteStore`] implements [`SubjectStore`], [`CredentialStore`],
//! [`SessionStore`], and [`UserStore`] over a single `rusqlite` connection
//! behind a lock. The driver is synchronous on purpose: the engine's store
//! traits are sync, so an async driver would need `block_on` plumbing that
//! panics inside the server's blocking pool. `rusqlite` keeps every engine
//! path panic-free, including server functions.
//!
//! Style note: this file uses idiomatic tail expressions and `?`, not the
//! root crate's explicit-return idiom. It is written to be copied into apps
//! with default lints, where `needless_return` would fire.

use std::fmt;
use std::path::Path;

use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};

use dioxus_auth::{
    AuthError, AuthSubject, AuthUser, CredentialStore, Session, SessionId, SessionStore,
    SubjectStore, UserStore,
};

/// The documented shape, also embedded verbatim in `README.md`.
///
/// A test (`schema_doc_matches_const`) asserts the README contains this exact
/// string, so the copy-paste SQL cannot rot away from the DDL the store runs.
///
/// One documented deviation: the 4-table shape in the auth guides omits
/// `sessions.created_at`, but the engine's absolute-TTL math
/// (`created_at + ttl`, see `validate_session`) needs it persisted.
/// Everything else follows the guide's column names.
pub const SCHEMA_SQL: &str = "CREATE TABLE subjects (
    auth_id INTEGER PRIMARY KEY,
    app_ref INTEGER UNIQUE,
    auth_hash TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL,
    email_verified_at INTEGER,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
CREATE TABLE accounts (
    provider TEXT NOT NULL DEFAULT 'email',
    provider_account_id TEXT NOT NULL PRIMARY KEY,
    auth_id INTEGER NOT NULL REFERENCES subjects (auth_id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL
);
CREATE TABLE sessions (
    id TEXT NOT NULL PRIMARY KEY,
    auth_id INTEGER NOT NULL REFERENCES subjects (auth_id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_active_at INTEGER,
    auth_hash TEXT,
    ip TEXT,
    user_agent TEXT
);
CREATE TABLE verifications (
    id TEXT NOT NULL PRIMARY KEY,
    identifier TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
);
";

/// Shared session column list for both reads.
///
/// The by-id lookup and the per-subject listing derive from it, so the two
/// reads cannot disagree on column order.
const SESSION_COLUMNS: &str =
    "id, auth_id, created_at, expires_at, last_active_at, auth_hash, ip, user_agent";

/// Application user for the reference deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppUser {
    /// Stable row id (`users.id`).
    pub id: i64,
    /// Login identifier (`users.email`, engine-normalized upstream).
    pub email: String,
    /// Display name (`users.name`).
    pub name: String,
}

impl AuthUser for AppUser {
    type Id = i64;

    fn id(&self) -> Self::Id {
        self.id
    }
}

/// Signup material for the reference store.
///
/// Either links an existing application row or carries a full row the store
/// persists alongside the subject, all inside one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqliteAppSetup {
    /// Link an existing `users` row by id (adoption).
    Existing(i64),
    /// Persist a new `users` row with the subject.
    New(AppUser),
}

/// SQLite-backed subject, credential, session, and application store.
///
/// One connection behind a lock: `rusqlite` connections are `Send` but not
/// `Sync`, so the mutex is what makes this type shareable. Provisioning runs
/// in an immediate transaction, so the identifier claim is atomic.
///
/// `Debug` is manual: a connection carries no debuggable state worth
/// rendering.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteStore(..)")
    }
}

impl SqliteStore {
    /// Opens (or creates) a file-backed store, applying the documented schema.
    ///
    /// # Errors
    /// Returns `AuthError::Internal` if the database cannot be opened or the
    /// schema cannot be applied.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuthError> {
        let conn = Connection::open(path).map_err(internal)?;
        Self::init(conn)
    }

    /// Opens an isolated in-memory store. Tests use this; production passes a
    /// file path to [`SqliteStore::open`].
    ///
    /// # Errors
    /// Returns `AuthError::Internal` if the schema cannot be applied.
    pub fn open_in_memory() -> Result<Self, AuthError> {
        let conn = Connection::open_in_memory().map_err(internal)?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, AuthError> {
        conn.execute_batch(SCHEMA_SQL).map_err(internal)?;
        conn.pragma_update(None, "foreign_keys", true)
            .map_err(internal)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Loads one user row by id.
    fn load_user(conn: &Connection, id: i64) -> Result<Option<AppUser>, AuthError> {
        let mut statement = conn
            .prepare("SELECT id, email, name FROM users WHERE id = ?1")
            .map_err(internal)?;
        statement
            .query_row([id], |row| {
                Ok(AppUser {
                    id: row.get(0)?,
                    email: row.get(1)?,
                    name: row.get(2)?,
                })
            })
            .optional()
            .map_err(internal)
    }

    /// Loads one subject row by auth id.
    fn load_subject(
        conn: &Connection,
        auth_id: i64,
    ) -> Result<Option<AuthSubject<i64, i64>>, AuthError> {
        let mut statement = conn
            .prepare("SELECT auth_id, app_ref, auth_hash FROM subjects WHERE auth_id = ?1")
            .map_err(internal)?;
        statement
            .query_row([auth_id], |row| {
                Ok(AuthSubject {
                    auth_id: row.get(0)?,
                    app_ref: row.get(1)?,
                    auth_hash: row.get(2)?,
                })
            })
            .optional()
            .map_err(internal)
    }

    /// Loads one session row by storage-form id.
    fn load_session(conn: &Connection, id: &str) -> Result<Option<Session<i64>>, AuthError> {
        let mut statement = conn
            .prepare(&format!(
                "SELECT {SESSION_COLUMNS} FROM sessions WHERE id = ?1"
            ))
            .map_err(internal)?;
        statement
            .query_row([id], row_to_session)
            .optional()
            .map_err(internal)
    }

    /// Mints a fresh subject id inside the provisioning transaction.
    ///
    /// `MAX+1` is safe here because provisioning holds the single
    /// connection: no concurrent claim can interleave.
    fn mint_auth_id(tx: &rusqlite::Transaction<'_>) -> Result<i64, AuthError> {
        tx.query_row(
            "SELECT COALESCE(MAX(auth_id), 0) + 1 FROM subjects",
            [],
            |row| row.get(0),
        )
        .map_err(internal)
    }
}

/// Maps one session row. Shared by the by-id lookup and the per-subject
/// listing so the two reads cannot disagree on column order or NULL handling.
fn row_to_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<Session<i64>> {
    let stored_id: String = row.get(0)?;
    let auth_id: i64 = row.get(1)?;
    let created: i64 = row.get(2)?;
    let expires: i64 = row.get(3)?;
    let last_active: Option<i64> = row.get(4)?;
    let auth_hash: Option<String> = row.get(5)?;
    let ip: Option<String> = row.get(6)?;
    let user_agent: Option<String> = row.get(7)?;
    let mut session = Session::new(
        SessionId::new(stored_id),
        auth_id,
        timestamp(created)?,
        timestamp(expires)?,
    );
    if let Some(active) = last_active {
        session = session.with_last_active(timestamp(active)?);
    }
    if let Some(hash) = auth_hash {
        session = session.with_auth_hash(hash);
    }
    if let Some(ip) = ip {
        session = session.with_ip_address(ip);
    }
    if let Some(user_agent) = user_agent {
        session = session.with_user_agent(user_agent);
    }
    Ok(session)
}

/// Reads a UNIX-timestamp column, rejecting corrupt rows loudly instead of
/// wrapping them into the engine.
fn timestamp(value: i64) -> Result<u64, rusqlite::Error> {
    u64::try_from(value).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            "negative UNIX timestamp".into(),
        )
    })
}

/// Writes a UNIX timestamp, rejecting out-of-range values.
///
/// Rejection happens before values reach the driver (`as` casts would wrap
/// silently).
fn stamp(value: u64) -> Result<i64, AuthError> {
    i64::try_from(value).map_err(|_| AuthError::Internal(String::from("timestamp out of range")))
}

/// Maps a driver failure to the crate's internal error.
fn internal(error: impl std::fmt::Display) -> AuthError {
    AuthError::Internal(error.to_string())
}

/// Whether a driver failure is a uniqueness conflict.
///
/// Distinguishes taken identifiers and ids from real outages.
fn is_conflict(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

impl SubjectStore for SqliteStore {
    type AuthId = i64;
    type AppRef = i64;
    type AppSetup = SqliteAppSetup;

    fn provision_subject(
        &self,
        id_override: Option<Self::AuthId>,
        app: Self::AppSetup,
        identifier: &str,
        secret_hash: &str,
    ) -> Result<Option<AuthSubject<Self::AuthId, Self::AppRef>>, AuthError> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction().map_err(internal)?;
        if tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM accounts WHERE provider_account_id = ?1)",
                [identifier],
                |row| row.get::<_, bool>(0),
            )
            .map_err(internal)?
        {
            return Ok(None);
        }
        let auth_id = match id_override {
            Some(id) => id,
            None => Self::mint_auth_id(&tx)?,
        };
        let app_ref = match app {
            SqliteAppSetup::Existing(app_id) => {
                let exists: bool = tx
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1)",
                        [app_id],
                        |row| row.get(0),
                    )
                    .map_err(internal)?;
                if !exists {
                    return Err(AuthError::InvalidCredentials);
                }
                app_id
            }
            SqliteAppSetup::New(user) => {
                if let Err(error) = tx.execute(
                    "INSERT INTO users (id, email, name) VALUES (?1, ?2, ?3)",
                    params![user.id, user.email, user.name],
                ) {
                    if is_conflict(&error) {
                        return Ok(None);
                    }
                    return Err(internal(error));
                }
                user.id
            }
        };
        if let Err(error) = tx.execute(
            "INSERT INTO subjects (auth_id, app_ref, auth_hash) VALUES (?1, ?2, ?3)",
            params![auth_id, app_ref, secret_hash],
        ) {
            if is_conflict(&error) {
                // Dropping `tx` without commit rolls back; a taken subject
                // id must not leave the app row behind.
                return Ok(None);
            }
            return Err(internal(error));
        }
        if let Err(error) = tx.execute(
            "INSERT INTO accounts (provider, provider_account_id, auth_id, password_hash)
             VALUES ('email', ?1, ?2, ?3)",
            params![identifier, auth_id, secret_hash],
        ) {
            if is_conflict(&error) {
                return Ok(None);
            }
            return Err(internal(error));
        }
        tx.commit().map_err(internal)?;
        Ok(Some(AuthSubject {
            auth_id,
            app_ref: Some(app_ref),
            auth_hash: Some(secret_hash.to_string()),
        }))
    }

    fn find_subject(
        &self,
        auth_id: &Self::AuthId,
    ) -> Result<Option<AuthSubject<Self::AuthId, Self::AppRef>>, AuthError> {
        let conn = self.conn.lock();
        Self::load_subject(&conn, *auth_id)
    }

    fn set_app_link(
        &self,
        auth_id: &Self::AuthId,
        app_ref: &Self::AppRef,
    ) -> Result<bool, AuthError> {
        let conn = self.conn.lock();
        let current: Option<Option<i64>> = conn
            .query_row(
                "SELECT app_ref FROM subjects WHERE auth_id = ?1",
                [*auth_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(internal)?;
        let Some(link) = current else {
            return Err(AuthError::InvalidCredentials);
        };
        if link.is_some_and(|linked| linked != *app_ref) {
            return Ok(false);
        }
        conn.execute(
            "UPDATE subjects SET app_ref = ?1 WHERE auth_id = ?2",
            params![app_ref, auth_id],
        )
        .map_err(internal)?;
        Ok(true)
    }

    fn find_auth_id(&self, app_ref: &Self::AppRef) -> Result<Option<Self::AuthId>, AuthError> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT auth_id FROM subjects WHERE app_ref = ?1",
            [*app_ref],
            |row| row.get(0),
        )
        .optional()
        .map_err(internal)
    }

    fn delete_subject(&self, auth_id: &Self::AuthId) -> Result<(), AuthError> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM subjects WHERE auth_id = ?1", [*auth_id])
            .map_err(internal)?;
        Ok(())
    }
}

impl CredentialStore for SqliteStore {
    fn find_credential(
        &self,
        identifier: &str,
    ) -> Result<Option<(AuthSubject<Self::AuthId, Self::AppRef>, String)>, AuthError> {
        let conn = self.conn.lock();
        let mut statement = conn
            .prepare(
                "SELECT s.auth_id, s.app_ref, s.auth_hash, a.password_hash
             FROM subjects s JOIN accounts a ON a.auth_id = s.auth_id
             WHERE a.provider = 'email' AND a.provider_account_id = ?1",
            )
            .map_err(internal)?;
        statement
            .query_row([identifier], |row| {
                let subject = AuthSubject {
                    auth_id: row.get(0)?,
                    app_ref: row.get(1)?,
                    auth_hash: row.get(2)?,
                };
                let hash: String = row.get(3)?;
                Ok((subject, hash))
            })
            .optional()
            .map_err(internal)
    }

    fn attach_credential(
        &self,
        auth_id: &Self::AuthId,
        identifier: &str,
        secret_hash: &str,
    ) -> Result<bool, AuthError> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction().map_err(internal)?;
        let subject_exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM subjects WHERE auth_id = ?1)",
                [*auth_id],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if !subject_exists {
            return Err(AuthError::InvalidCredentials);
        }
        if let Err(error) = tx.execute(
            "INSERT INTO accounts (provider, provider_account_id, auth_id, password_hash)
             VALUES ('email', ?1, ?2, ?3)",
            params![identifier, auth_id, secret_hash],
        ) {
            if is_conflict(&error) {
                return Ok(false);
            }
            return Err(internal(error));
        }
        tx.commit().map_err(internal)?;
        Ok(true)
    }

    fn rotate_secret(&self, auth_id: &Self::AuthId, new_hash: &str) -> Result<(), AuthError> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE accounts SET password_hash = ?1 WHERE auth_id = ?2",
            params![new_hash, auth_id],
        )
        .map_err(internal)?;
        conn.execute(
            "UPDATE subjects SET auth_hash = ?1 WHERE auth_id = ?2",
            params![new_hash, auth_id],
        )
        .map_err(internal)?;
        Ok(())
    }
}

impl SessionStore for SqliteStore {
    type AuthId = i64;

    fn save_session(&self, session: Session<Self::AuthId>) -> Result<(), AuthError> {
        let created = stamp(session.created_at_unix())?;
        let expires = stamp(session.expires_at_unix())?;
        let last_active = session.last_active_at_unix().map(stamp).transpose()?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO sessions
             (id, auth_id, created_at, expires_at, last_active_at, auth_hash, ip, user_agent)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                session.id().as_str(),
                session.auth_id(),
                created,
                expires,
                last_active,
                session.auth_hash(),
                session.ip_address(),
                session.user_agent(),
            ],
        )
        .map_err(internal)?;
        Ok(())
    }

    fn find_session(&self, id: &SessionId) -> Result<Option<Session<Self::AuthId>>, AuthError> {
        let conn = self.conn.lock();
        Self::load_session(&conn, id.as_str())
    }

    fn delete_session(&self, id: &SessionId) -> Result<(), AuthError> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM sessions WHERE id = ?1", [id.as_str()])
            .map_err(internal)?;
        Ok(())
    }

    fn touch_session_if_present(
        &self,
        id: &SessionId,
        new_expiry: u64,
        last_active: u64,
    ) -> Result<(), AuthError> {
        let expires = stamp(new_expiry)?;
        let active = stamp(last_active)?;
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE sessions SET expires_at = ?1, last_active_at = ?2 WHERE id = ?3",
            params![expires, active, id.as_str()],
        )
        .map_err(internal)?;
        Ok(())
    }

    fn delete_subject_sessions(&self, auth_id: &Self::AuthId) -> Result<(), AuthError> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM sessions WHERE auth_id = ?1", [auth_id])
            .map_err(internal)?;
        Ok(())
    }

    fn list_subject_sessions(
        &self,
        auth_id: &Self::AuthId,
    ) -> Result<Vec<Session<Self::AuthId>>, AuthError> {
        let conn = self.conn.lock();
        let mut statement = conn
            .prepare(&format!(
                "SELECT {SESSION_COLUMNS} FROM sessions WHERE auth_id = ?1 ORDER BY rowid"
            ))
            .map_err(internal)?;
        let rows = statement
            .query_map([auth_id], row_to_session)
            .map_err(internal)?;
        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(row.map_err(internal)?);
        }
        Ok(sessions)
    }
}

impl UserStore for SqliteStore {
    type User = AppUser;

    fn resolve(&self, app_ref: &Self::AppRef) -> Result<Option<Self::User>, AuthError> {
        let conn = self.conn.lock();
        Self::load_user(&conn, *app_ref)
    }
}
