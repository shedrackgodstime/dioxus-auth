//! Copy-paste `SQLite` reference store for dioxus-auth (1d).
//!
//! You own this file: copy it into your app, rename the tables, add columns,
//! swap the user type. The crate never scaffolds, migrates, or touches your
//! database. The schema in `README.md` is documentation you apply yourself,
//! and this module is one honest implementation of it.
//!
//! Shape (R1): the application key serves as the subject key, so there is
//! no subjects table. Credentials (`accounts`) and sessions point at the
//! app key with cascading deletes; your application rows (`users`) carry
//! zero auth columns, and adopting an existing row is a single credential
//! insert. Session binding is derived from the current secret: rotation
//! rewrites every credential row, so sessions bound to the old secret stop
//! matching with no version column anywhere.
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
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use dioxus_auth::{
    Argon2Hasher, AuthError, AuthSubject, AuthUser, CredentialStore, InMemoryRateLimiter,
    PasswordHasher, RateLimiter, Session, SessionId, SessionStore, SubjectStore, UserStore,
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
pub const SCHEMA_SQL: &str = "CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL,
    email_verified_at INTEGER,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
CREATE TABLE IF NOT EXISTS accounts (
    provider TEXT NOT NULL DEFAULT 'email',
    provider_account_id TEXT NOT NULL PRIMARY KEY,
    app_key INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS accounts_app_key ON accounts (app_key);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT NOT NULL PRIMARY KEY,
    app_key INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_active_at INTEGER,
    auth_hash TEXT,
    ip TEXT,
    user_agent TEXT
);
CREATE INDEX IF NOT EXISTS sessions_app_key ON sessions (app_key);
CREATE TABLE IF NOT EXISTS verifications (
    id TEXT NOT NULL PRIMARY KEY,
    identifier TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
);
";

/// Shared session column list for both reads.
///
/// The by-id lookup and the per-key listing derive from it, so the two reads
/// cannot disagree on column order.
const SESSION_COLUMNS: &str =
    "id, app_key, created_at, expires_at, last_active_at, auth_hash, ip, user_agent";

/// Application user for the reference deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppUser {
    /// Stable row id (`users.id`), also the subject key on this path.
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
/// persists alongside the credential, all inside one transaction. In both
/// cases the app key doubles as the subject key: no minting, no override
/// machinery, no link states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqliteAppSetup {
    /// Link an existing `users` row by id (adoption).
    Existing(i64),
    /// Persist a new `users` row with the credential.
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

    /// Whether an application row exists.
    fn app_row_exists(tx: &rusqlite::Transaction<'_>, id: i64) -> Result<bool, AuthError> {
        tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1)",
            [id],
            |row| row.get(0),
        )
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
}

/// Maps one session row. Shared by the by-id lookup and the per-key listing
/// so the two reads cannot disagree on column order or NULL handling.
fn row_to_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<Session<i64>> {
    let stored_id: String = row.get(0)?;
    let app_key: i64 = row.get(1)?;
    let created: i64 = row.get(2)?;
    let expires: i64 = row.get(3)?;
    let last_active: Option<i64> = row.get(4)?;
    let auth_hash: Option<String> = row.get(5)?;
    let ip: Option<String> = row.get(6)?;
    let user_agent: Option<String> = row.get(7)?;
    let mut session = Session::new(
        SessionId::new(stored_id),
        app_key,
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
/// Distinguishes taken identifiers from real outages. Foreign-key failures
/// never reach this check: app-row existence is verified explicitly first,
/// so the only conflicts possible here are taken identifiers.
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
        _id_override: Option<Self::AuthId>,
        app: Self::AppSetup,
        provider: &str,
        identifier: &str,
        secret_hash: &str,
    ) -> Result<Option<AuthSubject<Self::AuthId, Self::AppRef>>, AuthError> {
        // R1 carries no separate auth identity: the app key serves, so there
        // is nothing to mint and no override to honor. Keys arrive through
        // `AppSetup` (a new row's id, or an existing row's).
        let mut conn = self.conn.lock();
        let tx = conn.transaction().map_err(internal)?;
        if tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM accounts WHERE provider = ?1 AND provider_account_id = ?2)",
                params![provider, identifier],
                |row| row.get::<_, bool>(0),
            )
            .map_err(internal)?
        {
            return Ok(None);
        }
        let app_key = match app {
            SqliteAppSetup::Existing(app_id) => {
                if !Self::app_row_exists(&tx, app_id)? {
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
            "INSERT INTO accounts (provider, provider_account_id, app_key, password_hash)
             VALUES (?1, ?2, ?3, ?4)",
            params![provider, identifier, app_key, secret_hash],
        ) {
            if is_conflict(&error) {
                // Dropping `tx` without commit rolls back; a taken second row
                // must not leave the first row behind.
                return Ok(None);
            }
            return Err(internal(error));
        }
        tx.commit().map_err(internal)?;
        Ok(Some(AuthSubject {
            auth_id: app_key,
            app_ref: Some(app_key),
            auth_hash: Some(secret_hash.to_string()),
        }))
    }

    fn find_subject(
        &self,
        auth_id: &Self::AuthId,
    ) -> Result<Option<AuthSubject<Self::AuthId, Self::AppRef>>, AuthError> {
        // A subject exists exactly while it holds credentials: no rows, no
        // subject. The binding reads back the row's own secret.
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT password_hash FROM accounts WHERE app_key = ?1 LIMIT 1",
            [*auth_id],
            |row| {
                let hash: String = row.get(0)?;
                Ok(AuthSubject {
                    auth_id: *auth_id,
                    app_ref: Some(*auth_id),
                    auth_hash: Some(hash),
                })
            },
        )
        .optional()
        .map_err(internal)
    }

    fn set_app_link(
        &self,
        auth_id: &Self::AuthId,
        app_ref: &Self::AppRef,
    ) -> Result<bool, AuthError> {
        // Links are structural here (subject key equals app key), so there is
        // nothing to mutate: same-key links confirm existence, cross-key
        // links are unrepresentable and report false.
        if auth_id != app_ref {
            return Ok(false);
        }
        let exists = self.find_subject(auth_id)?.is_some();
        if !exists {
            return Err(AuthError::InvalidCredentials);
        }
        Ok(true)
    }

    fn find_auth_id(&self, app_ref: &Self::AppRef) -> Result<Option<Self::AuthId>, AuthError> {
        // Trivially the same value under R1; the lookup still verifies the
        // subject exists rather than echoing the input.
        let found = self.find_subject(app_ref)?;
        Ok(found.map(|subject| subject.auth_id))
    }

    fn delete_subject(&self, auth_id: &Self::AuthId) -> Result<(), AuthError> {
        // Application rows are the application's own cascade, never this
        // call's: only auth rows go.
        let conn = self.conn.lock();
        conn.execute("DELETE FROM accounts WHERE app_key = ?1", [*auth_id])
            .map_err(internal)?;
        conn.execute("DELETE FROM sessions WHERE app_key = ?1", [*auth_id])
            .map_err(internal)?;
        Ok(())
    }
}

impl CredentialStore for SqliteStore {
    fn find_credential(
        &self,
        provider: &str,
        identifier: &str,
    ) -> Result<Option<(AuthSubject<Self::AuthId, Self::AppRef>, String)>, AuthError> {
        let conn = self.conn.lock();
        let mut statement = conn
            .prepare(
                "SELECT app_key, password_hash FROM accounts
             WHERE provider = ?1 AND provider_account_id = ?2",
            )
            .map_err(internal)?;
        statement
            .query_row(params![provider, identifier], |row| {
                let app_key: i64 = row.get(0)?;
                let hash: String = row.get(1)?;
                let subject = AuthSubject {
                    auth_id: app_key,
                    app_ref: Some(app_key),
                    auth_hash: Some(hash.clone()),
                };
                Ok((subject, hash))
            })
            .optional()
            .map_err(internal)
    }

    fn attach_credential(
        &self,
        auth_id: &Self::AuthId,
        provider: &str,
        identifier: &str,
        secret_hash: &str,
    ) -> Result<bool, AuthError> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction().map_err(internal)?;
        if !Self::app_row_exists(&tx, *auth_id)? {
            return Err(AuthError::InvalidCredentials);
        }
        if let Err(error) = tx.execute(
            "INSERT INTO accounts (provider, provider_account_id, app_key, password_hash)
             VALUES (?1, ?2, ?3, ?4)",
            params![provider, identifier, auth_id, secret_hash],
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
            "UPDATE accounts SET password_hash = ?1 WHERE app_key = ?2",
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
             (id, app_key, created_at, expires_at, last_active_at, auth_hash, ip, user_agent)
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
        conn.execute("DELETE FROM sessions WHERE app_key = ?1", [auth_id])
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
                "SELECT {SESSION_COLUMNS} FROM sessions WHERE app_key = ?1 ORDER BY rowid"
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

/// Timing-defense constant for the claim path.
///
/// Never a real password. Precomputed once per [`EmailClaims`] so every
/// taken or mismatch path burns identical verifier work without re-hashing
/// per call. Distinct from the engine's own dummy so the two defenses stay
/// independently auditable.
const CLAIM_DUMMY_PASSWORD: &str = "dioxus-auth-claim-timing-defense-dummy-password-do-not-use";

/// Normalizes a login identifier: trim plus lowercase, once.
///
/// Same rule as the engine: stores compare byte-for-byte and never fold
/// case or whitespace themselves. Deliberately not email
/// canonicalization (plus-addressing, dot-folding, IDNA stay untouched).
fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Transaction-scoped email credential claim (Direction D primitive).
///
/// Attaches an email/password credential to an already-created application
/// identity inside the caller-owned transaction:
///
/// ```text
/// let tx = conn.transaction()?;
/// tx.execute("INSERT INTO users (...) VALUES (...)", ...)?;
/// claims.claim(&tx, "alice@example.com", "password", app_id)?;
/// tx.commit()?;
/// ```
///
/// Contract: statements only, never begins, commits, or rolls back. The
/// handle must be an open transaction, never a bare connection in
/// autocommit mode. On any failure the caller rolls back and neither the
/// app row nor the credential commits. First and additional credentials
/// share this one operation: attaching to a fresh key is adoption, and
/// re-claiming the same identifier for the same key succeeds idempotently
/// (so retries self-heal), while any other conflict fails
/// indistinguishably. Unknown app keys fail without writing; dangling
/// links fail closed downstream and never authenticate.
///
/// Rate limiting is opt-in via [`EmailClaims::with_rate_limiter`]:
/// without it, gate signup endpoints at your edge.
#[derive(Debug)]
pub struct EmailClaims {
    hasher: Argon2Hasher,
    dummy_hash: String,
    limiter: Option<InMemoryRateLimiter>,
}

impl EmailClaims {
    /// Creates claim machinery with the default Argon2id hasher.
    ///
    /// Precomputes the timing-defense dummy hash once; construction cost
    /// is one hash, per-claim cost stays one hash plus one verify.
    ///
    /// # Errors
    /// Returns `AuthError` if the dummy hash cannot be precomputed.
    pub fn new() -> Result<Self, AuthError> {
        let hasher = Argon2Hasher::new();
        let dummy_hash = hasher.hash(CLAIM_DUMMY_PASSWORD).map_err(internal)?;
        Ok(Self {
            hasher,
            dummy_hash,
            limiter: None,
        })
    }

    /// Attaches a rate limiter shared with the login gate.
    ///
    /// Probing identifiers through signup counts toward the same budgets
    /// as login attempts, so enumeration cannot dodge the gate by
    /// switching verbs.
    #[must_use]
    pub fn with_rate_limiter(mut self, limiter: InMemoryRateLimiter) -> Self {
        self.limiter = Some(limiter);
        self
    }

    /// Claims an email/password credential for an app key in your transaction.
    ///
    /// Normalizes, hashes, checks the taken state, and inserts exactly one
    /// credential row. Taken identifiers, unknown app keys, and mismatched
    /// re-claims all fail as `InvalidCredentials` with identical Argon2
    /// work, so identifier and key state stay unobservable.
    ///
    /// # Errors
    /// Returns `InvalidCredentials` for taken identifiers and unknown app
    /// keys, `RateLimited` when a configured limiter trips, or a store or
    /// hasher error. On any error, roll back: the transaction is yours.
    pub fn claim(
        &self,
        tx: &Transaction<'_>,
        email: &str,
        password: &str,
        app_key: i64,
    ) -> Result<(), AuthError> {
        let normalized = normalize_email(email);
        if let Some(limiter) = &self.limiter {
            limiter.check(&normalized)?;
        }
        let hash = self.hasher.hash(password).map_err(internal)?;
        self.claim_inner(tx, &normalized, password, &hash, app_key)
    }

    /// Claims an imported pre-hashed credential in your transaction.
    ///
    /// Same shape as [`claim`](Self::claim) minus hashing: for migrations
    /// carrying valid hashes, where no plaintext exists to verify. Trust
    /// applies exactly as documented there, with one addition: there is no
    /// plaintext to burn verifier work with, so the imported hash stands in
    /// on taken paths (cost, not content) and empty hashes are rejected
    /// outright. No session is minted by either claim form.
    ///
    /// # Errors
    /// Returns `InvalidCredentials` for taken identifiers, unknown app
    /// keys, mismatches, and empty hashes; `RateLimited` when a configured
    /// limiter trips; or a store error. On any error, roll back.
    pub fn claim_hash(
        &self,
        tx: &Transaction<'_>,
        email: &str,
        password_hash: &str,
        app_key: i64,
    ) -> Result<(), AuthError> {
        let normalized = normalize_email(email);
        if let Some(limiter) = &self.limiter {
            limiter.check(&normalized)?;
        }
        if password_hash.is_empty() {
            return Err(AuthError::InvalidCredentials);
        }
        self.claim_inner(tx, &normalized, password_hash, password_hash, app_key)
    }

    /// Runs the shared claim body once the secret material is final.
    ///
    /// `burn` feeds the dummy verifier on failure branches (the plaintext
    /// password when one exists, otherwise the imported hash: only the
    /// work matters); `secret_hash` is what lands in the credential row.
    /// Idempotent re-claim succeeds, every other conflict fails
    /// indistinguishably, and races report taken without writing.
    fn claim_inner(
        &self,
        tx: &Transaction<'_>,
        normalized: &str,
        burn: &str,
        secret_hash: &str,
        app_key: i64,
    ) -> Result<(), AuthError> {
        let existing: Option<i64> = tx
            .query_row(
                "SELECT app_key FROM accounts WHERE provider = 'email' AND provider_account_id = ?1",
                [normalized],
                |row| row.get(0),
            )
            .optional()
            .map_err(internal)?;
        match existing {
            Some(bound) if bound == app_key => {
                self.record_success(normalized);
                return Ok(());
            }
            Some(_) => {
                self.record_failure(normalized);
                self.dummy_verify(burn);
                return Err(AuthError::InvalidCredentials);
            }
            None => {}
        }
        // The reference knows its own schema, so it checks app-row existence
        // explicitly. Generic adapters may rely on a foreign key or on
        // fail-closed resolution instead; the contract requires none of these.
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1)",
                [app_key],
                |row| row.get(0),
            )
            .map_err(internal)?;
        if !exists {
            self.record_failure(normalized);
            self.dummy_verify(burn);
            return Err(AuthError::InvalidCredentials);
        }
        if let Err(error) = tx.execute(
            "INSERT INTO accounts (provider, provider_account_id, app_key, password_hash)
             VALUES ('email', ?1, ?2, ?3)",
            params![normalized, app_key, secret_hash],
        ) {
            if is_conflict(&error) {
                // Lost a race with a concurrent claim: same observable as taken.
                self.record_failure(normalized);
                self.dummy_verify(burn);
                return Err(AuthError::InvalidCredentials);
            }
            return Err(internal(error));
        }
        self.record_success(normalized);
        Ok(())
    }

    /// Burns one verifier pass so failure branches cost what hits cost.
    fn dummy_verify(&self, password: &str) {
        let _ = self.hasher.verify(password, &self.dummy_hash);
    }

    /// Records a failed claim against the configured budgets, if any.
    fn record_failure(&self, identifier: &str) {
        if let Some(limiter) = &self.limiter {
            limiter.record_attempt(identifier);
        }
    }

    /// Clears the budgets for an identifier after a successful claim.
    fn record_success(&self, identifier: &str) {
        if let Some(limiter) = &self.limiter {
            limiter.record_success(identifier);
        }
    }
}
