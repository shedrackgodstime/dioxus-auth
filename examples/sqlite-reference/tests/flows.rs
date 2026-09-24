//! End-to-end proof that the reference store drives the engine: the same
//! verbs the memory quickstart uses, over `SQLite`, plus the store-level
//! behaviors (atomic provisioning, adoption, cascade, touch semantics) the
//! engine depends on.
//!
//! R1 representation scope: this suite pins what the reference shape
//! guarantees (app-key-keyed credentials and sessions, adoption without
//! app-table writes, cascade on app-row delete, secret-derived binding).
//! Shared trait semantics live in `tests/conformance/` (which pins
//! `MemoryStore`); representation-specific behavior lives here. If the
//! engine gains a store-visible behavior, it gets a test here too.
//!
//! Style note: like `src/lib.rs`, these tests use idiomatic tail expressions
//! so the file stays clean under default lints when copied.

use std::sync::Arc;

use dioxus_auth::{
    Auth, AuthEngine, AuthError, CredentialStore, DefaultUserInput, SessionId, SessionStore,
    SubjectStore, UserStore,
};
use sqlite_reference::{AppUser, SCHEMA_SQL, SqliteAppSetup, SqliteStore};

fn user(id: i64, email: &str) -> SqliteAppSetup {
    SqliteAppSetup::New(AppUser {
        id,
        email: String::from(email),
        name: String::from(email),
    })
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
    assert_eq!(validated.expect("session must validate").auth_id, 1);

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
        .provision_subject(
            None,
            user(1, "alice@example.com"),
            "email",
            "alice@example.com",
            "hash",
        )
        .expect("first claim must succeed");

    assert!(
        store
            .provision_subject(
                None,
                user(1, "bob@example.com"),
                "email",
                "bob@example.com",
                "hash"
            )
            .expect("provisioning must succeed")
            .is_none(),
        "a taken app id must be rejected"
    );
    assert!(
        store
            .find_credential("email", "bob@example.com")
            .expect("lookup must succeed")
            .is_none(),
        "a rejected claim must write nothing"
    );
}

#[test]
fn attach_adds_a_second_login_and_rejects_taken_or_missing() {
    let auth = auth();
    let (subject, _) = auth
        .sign_up_subject(
            "alice@example.com",
            "s3cret-password",
            user(1, "alice@example.com"),
        )
        .expect("sign-up must succeed");

    auth.attach_email_credential(&subject.auth_id, "alice-2@example.com", "other-secret")
        .expect("attach must succeed");
    let (user, _) = auth
        .sign_in_email("alice-2@example.com", "other-secret")
        .expect("the attached login must work");
    assert_eq!(user.id, 1);

    assert!(
        auth.attach_email_credential(&subject.auth_id, "alice@example.com", "pw")
            .is_err(),
        "a taken identifier must be rejected"
    );
    assert_eq!(
        auth.attach_email_credential(&404, "ghost@example.com", "pw")
            .expect_err("unknown user must fail"),
        AuthError::InvalidCredentials
    );
}

#[test]
fn existing_app_rows_adopt_without_rewriting_them() {
    let setup = Arc::new(SqliteStore::open_in_memory().expect("setup store must open"));
    let engine = AuthEngine::builder(Arc::clone(&setup), Arc::clone(&setup))
        .build()
        .expect("engine construction must succeed");
    setup
        .provision_subject(
            None,
            user(1, "alice@example.com"),
            "email",
            "alice@example.com",
            "hash",
        )
        .expect("seed claim must succeed");
    let seeded = setup
        .find_credential("email", "alice@example.com")
        .expect("lookup must succeed")
        .expect("seed credential must exist");
    setup
        .delete_subject(&seeded.0.auth_id)
        .expect("strip must succeed");
    assert!(
        setup.resolve(&1).expect("lookup must succeed").is_some(),
        "stripping auth must leave the app row behind"
    );

    let adopted = setup
        .provision_subject(
            None,
            SqliteAppSetup::Existing(1),
            "email",
            "alice-2@example.com",
            &engine.hasher().hash("pw2").expect("hash must succeed"),
        )
        .expect("adopt must not error")
        .expect("existing row must adopt");
    assert_eq!(adopted.app_ref, Some(1));

    let auth = Auth::from_engine(engine);
    let (user, _) = auth
        .sign_in_email("alice-2@example.com", "pw2")
        .expect("adopted login must work");
    assert_eq!(user.id, 1);
}

#[test]
fn deleting_the_app_row_cascades_credentials_and_sessions() {
    let path = std::env::temp_dir().join(format!("dioxus-auth-cascade-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let store = Arc::new(SqliteStore::open(&path).expect("file store must open"));
    let auth = Auth::from_engine(
        AuthEngine::builder(Arc::clone(&store), Arc::clone(&store))
            .build()
            .expect("engine construction must succeed"),
    );
    auth.sign_up_email(
        "alice@example.com",
        "s3cret-password",
        user(1, "alice@example.com"),
    )
    .expect("sign-up must succeed");
    let (_, session) = auth
        .sign_in_email("alice@example.com", "s3cret-password")
        .expect("sign-in must succeed");

    rusqlite::Connection::open(&path)
        .expect("raw connection must open")
        .execute("DELETE FROM users WHERE id = 1", [])
        .expect("app-row delete must succeed");

    assert!(
        store
            .find_credential("email", "alice@example.com")
            .expect("lookup must succeed")
            .is_none(),
        "credentials must cascade with the app row"
    );
    assert!(
        auth.engine()
            .validate_session(&session)
            .expect("validation must succeed")
            .is_none(),
        "sessions must cascade with the app row"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn rotated_secrets_invalidate_old_sessions_lazily() {
    let store = Arc::new(SqliteStore::open_in_memory().expect("in-memory store must open"));
    let auth = Auth::from_engine(
        AuthEngine::builder(Arc::clone(&store), Arc::clone(&store))
            .build()
            .expect("engine construction must succeed"),
    );
    auth.sign_up_email(
        "alice@example.com",
        "old-secret",
        user(1, "alice@example.com"),
    )
    .expect("sign-up must succeed");
    let (_, stale) = auth
        .sign_in_email("alice@example.com", "old-secret")
        .expect("sign-in must succeed");

    let rotated = auth
        .engine()
        .hasher()
        .hash("new-secret")
        .expect("hash must succeed");
    store
        .rotate_secret(&1, &rotated)
        .expect("rotation must succeed");

    assert!(
        auth.engine()
            .validate_session(&stale)
            .expect("validation must succeed")
            .is_none(),
        "sessions bound to the old secret must die on next use"
    );
    assert!(
        store
            .find_session(&stale.hash_for_storage())
            .expect("lookup must succeed")
            .is_none(),
        "the lazy drop must remove the row"
    );
    auth.sign_in_email("alice@example.com", "new-secret")
        .expect("the new secret must work");
}

#[test]
fn reopening_a_file_database_keeps_data_and_stays_usable() {
    let path = std::env::temp_dir().join(format!("dioxus-auth-reopen-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let first = SqliteStore::open(&path).expect("first open must succeed");
    first
        .provision_subject(
            None,
            user(1, "alice@example.com"),
            "email",
            "alice@example.com",
            "hash",
        )
        .expect("seed claim must succeed");
    drop(first);

    let second = SqliteStore::open(&path).expect("reopen must succeed on existing tables");
    assert!(
        second
            .find_credential("email", "alice@example.com")
            .expect("lookup must succeed")
            .is_some(),
        "credentials survive the reopen"
    );
    second
        .provision_subject(
            None,
            user(2, "bob@example.com"),
            "email",
            "bob@example.com",
            "hash",
        )
        .expect("post-reopen claims must work");
    let _ = std::fs::remove_file(&path);
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

/// Graduation across the real boundary: the memory quickstart (name-only
/// input) and the own-DB store (`AppUser`) answer identically, with the same
/// verbs and the same error codes. Written out on both sides: the facades
/// have different store types, so the parity is literal.
#[test]
fn graduation_from_memory_quickstart_preserves_behavior() {
    let quick = Auth::memory().expect("quickstart must construct");
    quick
        .sign_up_email(
            "alice@example.com",
            "password",
            DefaultUserInput::new("alice"),
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
