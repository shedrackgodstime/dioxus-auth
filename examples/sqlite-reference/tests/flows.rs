//! End-to-end proof that the reference store drives the engine: the same
//! verbs the memory quickstart uses, over `SQLite`, plus the store-level
//! behaviors (atomic provisioning, touch semantics) the engine depends on.
//!
//! Behavioral parity with `tests/conformance/` (which pins `MemoryStore`):
//! the suites are not code-shared because seeding (`insert_user…`) is not
//! part of the capability traits — only engine-reachable behavior is. If the
//! engine gains a store-visible behavior, it gets a test here too.
//!
//! Style note: like `src/lib.rs`, these tests use idiomatic tail expressions
//! so the file stays clean under default lints when copied.

use std::sync::Arc;

use dioxus_auth::{
    Auth, AuthEngine, AuthError, DefaultUser, PasswordUserStore, SessionId, SessionStore,
};
use sqlite_reference::{AppUser, SCHEMA_SQL, SqliteStore};

fn user(id: i64, email: &str) -> AppUser {
    AppUser {
        id,
        email: String::from(email),
        name: String::from(email),
    }
}

fn auth() -> Auth<SqliteStore> {
    let store = Arc::new(SqliteStore::open_in_memory().expect("in-memory store must open"));
    let engine = AuthEngine::builder(Arc::clone(&store), store)
        .build()
        .expect("engine construction must succeed");
    Auth::from_engine(engine)
}

#[test]
fn schema_doc_matches_the_const_the_store_runs() {
    let readme = include_str!("../README.md");
    assert!(
        readme.contains(SCHEMA_SQL),
        "the copy-paste schema in README.md must be byte-identical to SCHEMA_SQL"
    );
}

#[test]
fn sign_up_sign_in_validate_and_sign_out_roundtrip() {
    let auth = auth();

    let (signed_up, _) = auth
        .sign_up_email(
            "alice@example.com",
            "s3cret-password",
            user(1, "alice@example.com"),
        )
        .expect("sign-up must succeed");
    assert_eq!(signed_up.id, 1);

    let (signed_in, session) = auth
        .sign_in_email("alice@example.com", "s3cret-password")
        .expect("sign-in must succeed");
    assert_eq!(signed_in.id, 1);

    let validated = auth
        .engine()
        .validate_session(&session)
        .expect("validation must succeed");
    assert_eq!(validated.expect("session must validate").id, 1);

    auth.sign_out(&session).expect("sign-out must succeed");
    assert!(
        auth.engine()
            .validate_session(&session)
            .expect("validation must succeed")
            .is_none(),
        "a signed-out session must not validate"
    );
}

#[test]
fn taken_identifiers_and_wrong_passwords_share_invalid_credentials() {
    let auth = auth();
    auth.sign_up_email(
        "alice@example.com",
        "s3cret-password",
        user(1, "alice@example.com"),
    )
    .expect("sign-up must succeed");

    assert_eq!(
        auth.sign_up_email(
            "alice@example.com",
            "other-password",
            user(2, "alice@example.com")
        )
        .expect_err("a taken identifier must fail"),
        AuthError::InvalidCredentials
    );
    assert_eq!(
        auth.sign_in_email("alice@example.com", "wrong-password")
            .expect_err("a wrong password must fail"),
        AuthError::InvalidCredentials
    );
    assert_eq!(
        auth.sign_in_email("nobody@example.com", "s3cret-password")
            .expect_err("an unknown identifier must fail"),
        AuthError::InvalidCredentials
    );
}

#[test]
fn change_password_rotates_the_credential_and_revokes_sessions() {
    let auth = auth();
    let (_, session) = auth
        .sign_up_email(
            "alice@example.com",
            "old-secret",
            user(1, "alice@example.com"),
        )
        .expect("sign-up must succeed");

    auth.change_password("alice@example.com", "old-secret", "new-secret")
        .expect("password change must succeed");

    assert!(
        auth.engine()
            .validate_session(&session)
            .expect("validation must succeed")
            .is_none(),
        "pre-change sessions must die with the credential"
    );
    assert!(
        auth.sign_in_email("alice@example.com", "old-secret")
            .is_err()
    );
    let (user, _) = auth
        .sign_in_email("alice@example.com", "new-secret")
        .expect("the new credential must work");
    assert_eq!(user.id, 1);
}

#[test]
fn provision_rejects_duplicate_ids_without_side_effects() {
    let store = SqliteStore::open_in_memory().expect("in-memory store must open");
    store
        .provision_user_with_password(user(1, "alice@example.com"), "alice@example.com", "hash")
        .expect("first claim must succeed");

    assert!(
        !store
            .provision_user_with_password(user(1, "bob@example.com"), "bob@example.com", "hash")
            .expect("provisioning must succeed"),
        "a taken user id must be rejected"
    );
    assert!(
        store
            .find_by_identifier("bob@example.com")
            .expect("lookup must succeed")
            .is_none(),
        "a rejected claim must write nothing"
    );
}

#[test]
fn touch_missing_sessions_is_a_noop_and_single_active_rotates() {
    let store = Arc::new(SqliteStore::open_in_memory().expect("in-memory store must open"));
    store
        .touch_session_if_present(&SessionId::generate(), 9_999_999_999, 1_000)
        .expect("touching a missing session must succeed silently");

    let engine = AuthEngine::builder(Arc::clone(&store), Arc::clone(&store))
        .single_active_session(true)
        .build()
        .expect("engine construction must succeed");
    let auth = Auth::from_engine(engine);
    auth.sign_up_email(
        "alice@example.com",
        "s3cret-password",
        user(1, "alice@example.com"),
    )
    .expect("sign-up must succeed");
    let (_, first) = auth
        .sign_in_email("alice@example.com", "s3cret-password")
        .expect("first sign-in must succeed");
    let (_, second) = auth
        .sign_in_email("alice@example.com", "s3cret-password")
        .expect("second sign-in must succeed");

    assert!(
        auth.engine()
            .validate_session(&first)
            .expect("validation must succeed")
            .is_none(),
        "single-active rotation must retire the first session"
    );
    assert!(
        auth.engine()
            .validate_session(&second)
            .expect("validation must succeed")
            .is_some(),
        "the newest session must survive rotation"
    );
}

/// Graduation across the real boundary: the memory quickstart (`DefaultUser`)
/// and the own-DB store (`AppUser`) answer identically — same verbs, same
/// error codes. Written out on both sides: the facades have different store
/// types, so the parity is literal.
#[test]
fn graduation_from_memory_quickstart_preserves_behavior() {
    let quick = Auth::memory().expect("quickstart must construct");
    quick
        .sign_up_email(
            "alice@example.com",
            "password",
            DefaultUser {
                id: 1,
                email: String::from("alice@example.com"),
                name: String::from("alice"),
            },
        )
        .expect("sign-up must succeed");

    let owned = Auth::new(SqliteStore::open_in_memory().expect("store must open"))
        .expect("facade must construct");
    owned
        .sign_up_email(
            "alice@example.com",
            "password",
            user(1, "alice@example.com"),
        )
        .expect("sign-up must succeed");

    assert_eq!(
        quick
            .sign_in_email("alice@example.com", "wrong")
            .expect_err("wrong password must fail"),
        AuthError::InvalidCredentials
    );
    assert_eq!(
        owned
            .sign_in_email("alice@example.com", "wrong")
            .expect_err("wrong password must fail"),
        AuthError::InvalidCredentials
    );
    assert_eq!(
        quick
            .sign_in_email("nobody@example.com", "password")
            .expect_err("unknown identifier must fail"),
        AuthError::InvalidCredentials
    );
    assert_eq!(
        owned
            .sign_in_email("nobody@example.com", "password")
            .expect_err("unknown identifier must fail"),
        AuthError::InvalidCredentials
    );

    let (_, quick_session) = quick
        .sign_in_email("alice@example.com", "password")
        .expect("sign-in must succeed");
    let (_, owned_session) = owned
        .sign_in_email("alice@example.com", "password")
        .expect("sign-in must succeed");
    quick
        .sign_out(&quick_session)
        .expect("sign-out must succeed");
    owned
        .sign_out(&owned_session)
        .expect("sign-out must succeed");
}
