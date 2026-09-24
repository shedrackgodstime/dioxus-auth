//! End-to-end proof of the transaction-scoped claim primitive: the
//! application owns its transaction and User rows, auth attaches
//! credentials inside that transaction, and both commit or neither does.
//!
//! Style note: like `src/lib.rs`, these tests use idiomatic tail expressions
//! so the file stays clean under default lints when copied.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use dioxus_auth::{Auth, AuthEngine, AuthError, CredentialStore, InMemoryRateLimiter, UserStore};
use rusqlite::params;
use sqlite_reference::{EmailClaims, SqliteStore};

/// Hands out unique database files: every test gets an isolated database
/// because the claim path joins caller-owned connections to one file.
static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Opens a file-backed store (schema applied) with its path for raw access.
fn setup() -> (Arc<SqliteStore>, std::path::PathBuf) {
    let n = DB_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "dioxus-auth-claims-{}-{}.db",
        std::process::id(),
        n
    ));
    let _ = std::fs::remove_file(&path);
    let store = Arc::new(SqliteStore::open(&path).expect("file store must open"));
    (store, path)
}

/// Removes a test database file, best effort.
fn teardown(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
}

/// Builds an engine over one store for the login side of each flow.
fn engine_for(store: &Arc<SqliteStore>) -> AuthEngine<SqliteStore, SqliteStore> {
    AuthEngine::builder(Arc::clone(store), Arc::clone(store))
        .build()
        .expect("engine construction must succeed")
}

/// Inserts an application User row through the caller's own SQL.
fn insert_user(tx: &rusqlite::Transaction<'_>, id: i64, email: &str, name: &str) {
    assert_eq!(
        tx.execute(
            "INSERT INTO users (id, email, name) VALUES (?1, ?2, ?3)",
            params![id, email, name],
        )
        .expect("app-row insert must succeed"),
        1,
        "exactly one application row must land"
    );
}

#[test]
fn tx_joined_signup_commits_user_and_credential_together() {
    let (store, path) = setup();
    let claims = EmailClaims::new().expect("claim machinery must construct");
    let mut raw = rusqlite::Connection::open(&path).expect("raw connection must open");
    let tx = raw.transaction().expect("dev transaction must open");
    insert_user(&tx, 1, "alice@example.com", "alice");
    claims
        .claim(&tx, "alice@example.com", "s3cret-password", 1)
        .expect("claim must succeed");
    tx.commit().expect("commit must succeed");

    let auth = Auth::from_engine(engine_for(&store));
    let (user, session) = auth
        .sign_in_email("alice@example.com", "s3cret-password")
        .expect("login must succeed");
    assert_eq!(user.id, 1);
    assert!(
        auth.engine()
            .validate_session(&session)
            .expect("validation must succeed")
            .is_some(),
        "the session must validate"
    );
    teardown(&path);
}

#[test]
fn taken_identifier_rolls_back_claim_and_app_row() {
    let (store, path) = setup();
    let claims = EmailClaims::new().expect("claim machinery must construct");
    let engine = engine_for(&store);
    let mut raw = rusqlite::Connection::open(&path).expect("raw connection must open");
    let tx = raw.transaction().expect("dev transaction must open");
    insert_user(&tx, 1, "alice@example.com", "alice");
    claims
        .claim(&tx, "alice@example.com", "s3cret-password", 1)
        .expect("first claim must succeed");
    tx.commit().expect("commit must succeed");

    let mut raw = rusqlite::Connection::open(&path).expect("raw connection must open");
    let tx = raw.transaction().expect("dev transaction must open");
    insert_user(&tx, 2, "mallory@example.com", "mallory");
    assert_eq!(
        claims
            .claim(&tx, "alice@example.com", "other-password", 2)
            .expect_err("taken identifier must fail"),
        AuthError::InvalidCredentials
    );
    drop(tx);

    assert!(
        store.resolve(&2).expect("lookup must succeed").is_none(),
        "the rolled-back app row must be gone"
    );
    let auth = Auth::from_engine(engine);
    let (user, _) = auth
        .sign_in_email("alice@example.com", "s3cret-password")
        .expect("the winner's credential must be untouched");
    assert_eq!(user.id, 1);
    teardown(&path);
}

#[test]
fn unknown_app_key_fails_without_writing() {
    let (store, path) = setup();
    let claims = EmailClaims::new().expect("claim machinery must construct");
    let mut raw = rusqlite::Connection::open(&path).expect("raw connection must open");
    let tx = raw.transaction().expect("dev transaction must open");

    assert_eq!(
        claims
            .claim(&tx, "ghost@example.com", "password", 404)
            .expect_err("unknown app key must fail"),
        AuthError::InvalidCredentials
    );
    drop(tx);

    assert!(
        store
            .find_credential("email", "ghost@example.com")
            .expect("lookup must succeed")
            .is_none(),
        "a rejected claim must write nothing"
    );
    teardown(&path);
}

#[test]
fn reclaiming_the_same_identifier_for_the_same_key_succeeds() {
    let (store, path) = setup();
    let claims = EmailClaims::new().expect("claim machinery must construct");
    let mut raw = rusqlite::Connection::open(&path).expect("raw connection must open");
    let tx = raw.transaction().expect("dev transaction must open");
    insert_user(&tx, 1, "alice@example.com", "alice");
    claims
        .claim(&tx, "alice@example.com", "s3cret-password", 1)
        .expect("first claim must succeed");
    tx.commit().expect("commit must succeed");

    let mut raw = rusqlite::Connection::open(&path).expect("raw connection must open");
    let tx = raw.transaction().expect("dev transaction must open");
    claims
        .claim(&tx, "alice@example.com", "s3cret-password", 1)
        .expect("idempotent re-claim must succeed");
    drop(tx);

    let auth = Auth::from_engine(engine_for(&store));
    auth.sign_in_email("alice@example.com", "s3cret-password")
        .expect("login must still succeed");
    teardown(&path);
}

#[test]
fn same_identifier_for_a_different_key_is_taken() {
    let (_store, path) = setup();
    let claims = EmailClaims::new().expect("claim machinery must construct");
    let mut raw = rusqlite::Connection::open(&path).expect("raw connection must open");
    let tx = raw.transaction().expect("dev transaction must open");
    insert_user(&tx, 1, "alice@example.com", "alice");
    claims
        .claim(&tx, "alice@example.com", "s3cret-password", 1)
        .expect("first claim must succeed");
    tx.commit().expect("commit must succeed");

    let mut raw = rusqlite::Connection::open(&path).expect("raw connection must open");
    let tx = raw.transaction().expect("dev transaction must open");
    insert_user(&tx, 2, "mallory@example.com", "mallory");
    assert_eq!(
        claims
            .claim(&tx, "alice@example.com", "other-password", 2)
            .expect_err("cross-key claim must fail"),
        AuthError::InvalidCredentials
    );
    drop(tx);
    teardown(&path);
}

#[test]
fn additional_credentials_attach_through_the_same_operation() {
    let (store, path) = setup();
    let claims = EmailClaims::new().expect("claim machinery must construct");
    let mut raw = rusqlite::Connection::open(&path).expect("raw connection must open");
    let tx = raw.transaction().expect("dev transaction must open");
    insert_user(&tx, 1, "alice@example.com", "alice");
    claims
        .claim(&tx, "alice@example.com", "s3cret-password", 1)
        .expect("first claim must succeed");
    tx.commit().expect("commit must succeed");

    let mut raw = rusqlite::Connection::open(&path).expect("raw connection must open");
    let tx = raw.transaction().expect("dev transaction must open");
    claims
        .claim(&tx, "alice-2@example.com", "other-secret", 1)
        .expect("second login attach must succeed");
    tx.commit().expect("commit must succeed");

    let auth = Auth::from_engine(engine_for(&store));
    for (identifier, secret) in [
        ("alice@example.com", "s3cret-password"),
        ("alice-2@example.com", "other-secret"),
    ] {
        let (user, _) = auth
            .sign_in_email(identifier, secret)
            .expect("each login must work");
        assert_eq!(user.id, 1, "both logins resolve one application user");
    }
    teardown(&path);
}

#[test]
fn imported_hash_claims_verify_against_the_original_password() {
    let (store, path) = setup();
    let claims = EmailClaims::new().expect("claim machinery must construct");
    let engine = engine_for(&store);
    let hash = engine
        .hasher()
        .hash("s3cret-password")
        .expect("hash must succeed");

    let mut raw = rusqlite::Connection::open(&path).expect("raw connection must open");
    let tx = raw.transaction().expect("dev transaction must open");
    insert_user(&tx, 1, "alice@example.com", "alice");
    claims
        .claim_hash(&tx, "alice@example.com", &hash, 1)
        .expect("hash claim must succeed");
    tx.commit().expect("commit must succeed");

    let auth = Auth::from_engine(engine);
    let (user, _) = auth
        .sign_in_email("alice@example.com", "s3cret-password")
        .expect("original password must verify against the import");
    assert_eq!(user.id, 1);

    let mut raw = rusqlite::Connection::open(&path).expect("raw connection must open");
    let tx = raw.transaction().expect("dev transaction must open");
    assert_eq!(
        claims
            .claim_hash(&tx, "alice@example.com", "", 1)
            .expect_err("empty hash must fail"),
        AuthError::InvalidCredentials,
        "empty hashes are rejected outright"
    );
    drop(tx);
    teardown(&path);
}

#[test]
fn claim_probing_counts_toward_the_shared_rate_gate() {
    use std::time::Duration;

    let (_store, path) = setup();
    let seeded = EmailClaims::new().expect("claim machinery must construct");
    let mut raw = rusqlite::Connection::open(&path).expect("raw connection must open");
    let tx = raw.transaction().expect("dev transaction must open");
    insert_user(&tx, 1, "alice@example.com", "alice");
    seeded
        .claim(&tx, "alice@example.com", "s3cret-password", 1)
        .expect("seed claim must succeed");
    tx.commit().expect("commit must succeed");

    let claims = EmailClaims::new()
        .expect("claim machinery must construct")
        .with_rate_limiter(InMemoryRateLimiter::new(1, Duration::from_secs(60)));
    let mut raw = rusqlite::Connection::open(&path).expect("raw connection must open");
    let tx = raw.transaction().expect("dev transaction must open");
    assert_eq!(
        claims
            .claim(&tx, "alice@example.com", "password", 2)
            .expect_err("taken identifier must fail"),
        AuthError::InvalidCredentials
    );
    assert_eq!(
        claims
            .claim(&tx, "alice@example.com", "password", 2)
            .expect_err("budget must be spent"),
        AuthError::RateLimited
    );
    drop(tx);
    teardown(&path);
}
