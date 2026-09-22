//! Tests for the `Auth` entry facade (slices 1a–1b: shell plus M1 verbs).

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

#[path = "common/mod.rs"]
mod common;
#[path = "common/password.rs"]
mod password;

use std::sync::Arc;
use std::time::Duration;

use common::TestUser;
use dioxus_auth::prelude::{
    Auth, AuthEngine, AuthError, AuthUser, ErrorCode, InMemoryRateLimiter, MemoryStore,
};
use password::hash_password;

#[test]
fn memory_constructs_with_secure_defaults() {
    let auth = Auth::<MemoryStore<TestUser>>::memory().expect("memory facade must construct");
    assert_eq!(auth.engine().session_ttl_secs(), 60 * 60 * 24 * 7);
    return;
}

#[test]
fn new_wraps_caller_store() {
    let db = Arc::new(MemoryStore::<TestUser>::new());
    let auth = Auth::new(Arc::clone(&db)).expect("facade must construct over caller store");
    assert_eq!(auth.engine().session_ttl_secs(), 60 * 60 * 24 * 7);
    return;
}

#[test]
fn facade_delegates_to_engine_lifecycle() {
    let auth = Auth::<MemoryStore<TestUser>>::memory().expect("memory facade must construct");
    auth.engine().user_store().insert_user_with_password(
        TestUser::new(1, "alice"),
        "alice",
        hash_password("s3cret"),
    );
    let (user, session) = auth
        .engine()
        .login("alice", "s3cret")
        .expect("login through the facade engine must succeed");
    assert_eq!(user.id(), 1);
    let current = auth
        .engine()
        .validate_session(session.id())
        .expect("validation must not error");
    assert!(current.is_some());
    auth.engine()
        .logout(session.id())
        .expect("revocation must not error");
    return;
}

#[test]
fn facade_clone_shares_engine() {
    let auth = Auth::<MemoryStore<TestUser>>::memory().expect("memory facade must construct");
    let again = auth.clone();
    assert!(Arc::ptr_eq(auth.engine(), again.engine()));
    return;
}

#[test]
fn facade_debug_names_auth() {
    let auth = Auth::<MemoryStore<TestUser>>::memory().expect("memory facade must construct");
    let rendered = format!("{auth:?}");
    assert!(rendered.starts_with("Auth("));
    return;
}

#[test]
fn sign_up_provisions_and_signs_in() {
    let auth = Auth::<MemoryStore<TestUser>>::memory().expect("memory facade must construct");
    let (user, session) = auth
        .sign_up("alice", "s3cret", TestUser::new(1, "alice"))
        .expect("sign-up must succeed");
    assert_eq!(user.id(), 1);
    let current = auth
        .engine()
        .validate_session(&session)
        .expect("validation must not error");
    assert!(current.is_some());
    return;
}

#[test]
fn sign_up_taken_matches_unknown_sign_in() {
    let auth = Auth::<MemoryStore<TestUser>>::memory().expect("memory facade must construct");
    auth.sign_up("alice", "s3cret", TestUser::new(1, "alice"))
        .expect("first sign-up must succeed");
    let taken = auth
        .sign_up("alice", "other", TestUser::new(2, "mallory"))
        .expect_err("taken identifier must fail");
    let unknown = auth
        .sign_in("nobody", "whatever")
        .expect_err("unknown identifier must fail");
    assert_eq!(taken, AuthError::InvalidCredentials);
    assert_eq!(taken, unknown);
    return;
}

#[test]
fn sign_up_taken_counts_toward_the_shared_rate_gate() {
    let db = MemoryStore::<TestUser>::new();
    db.insert_user_with_password(TestUser::new(1, "alice"), "alice", hash_password("pw"));
    let db = Arc::new(db);
    let limiter = InMemoryRateLimiter::new(2, Duration::from_secs(60));
    let engine = AuthEngine::builder(Arc::clone(&db), db)
        .rate_limiter(limiter)
        .build()
        .expect("engine construction must succeed");
    let auth = Auth::from_engine(engine);

    let first = auth
        .sign_up("alice", "pw", TestUser::new(2, "mallory"))
        .expect_err("taken identifier must fail");
    let second = auth
        .sign_up("alice", "pw", TestUser::new(2, "mallory"))
        .expect_err("taken identifier must fail again");
    assert_eq!(first, AuthError::InvalidCredentials);
    assert_eq!(second, AuthError::InvalidCredentials);

    // reason: the taken probes were recorded as attempts, so the next
    // credential operation on the same identifier is throttled — the sign-up
    // gate and the login gate are one window, not two.
    let throttled = auth
        .sign_in("alice", "pw")
        .expect_err("throttled sign-in must fail");
    assert_eq!(throttled, AuthError::RateLimited);

    let blocked = auth
        .sign_up("alice", "pw", TestUser::new(2, "mallory"))
        .expect_err("throttled sign-up must fail");
    assert_eq!(blocked, AuthError::RateLimited);
    return;
}

#[test]
fn sign_in_rejects_wrong_password_without_oracle() {
    let auth = Auth::<MemoryStore<TestUser>>::memory().expect("memory facade must construct");
    auth.sign_up("alice", "s3cret", TestUser::new(1, "alice"))
        .expect("sign-up must succeed");
    let wrong = auth
        .sign_in("alice", "wrong")
        .expect_err("wrong password must fail");
    assert_eq!(wrong, AuthError::InvalidCredentials);
    return;
}

#[test]
fn sign_out_revokes_session() {
    let auth = Auth::<MemoryStore<TestUser>>::memory().expect("memory facade must construct");
    let (_, session) = auth
        .sign_up("alice", "s3cret", TestUser::new(1, "alice"))
        .expect("sign-up must succeed");
    auth.sign_out(&session).expect("sign-out must succeed");
    let current = auth
        .engine()
        .validate_session(&session)
        .expect("validation must not error");
    assert!(current.is_none());
    return;
}

#[test]
fn change_password_rotates_and_revokes() {
    let auth = Auth::<MemoryStore<TestUser>>::memory().expect("memory facade must construct");
    let (_, session) = auth
        .sign_up("alice", "old-secret", TestUser::new(1, "alice"))
        .expect("sign-up must succeed");
    auth.change_password("alice", "old-secret", "new-secret")
        .expect("change must succeed");
    let stale = auth
        .sign_in("alice", "old-secret")
        .expect_err("old password must fail");
    assert_eq!(stale, AuthError::InvalidCredentials);
    let (user, _) = auth
        .sign_in("alice", "new-secret")
        .expect("new password must work");
    assert_eq!(user.id(), 1);
    let current = auth
        .engine()
        .validate_session(&session)
        .expect("validation must not error");
    assert!(current.is_none());
    return;
}

#[test]
fn change_password_rejects_bad_current_without_oracle() {
    let auth = Auth::<MemoryStore<TestUser>>::memory().expect("memory facade must construct");
    auth.sign_up("alice", "s3cret", TestUser::new(1, "alice"))
        .expect("sign-up must succeed");
    let wrong = auth
        .change_password("alice", "wrong", "new-secret")
        .expect_err("wrong current password must fail");
    let unknown = auth
        .change_password("nobody", "wrong", "new-secret")
        .expect_err("unknown identifier must fail");
    assert_eq!(wrong, AuthError::InvalidCredentials);
    assert_eq!(wrong, unknown);
    return;
}

#[test]
fn error_codes_map_stably() {
    assert_eq!(
        AuthError::InvalidCredentials.code(),
        ErrorCode::InvalidCredentials
    );
    assert_eq!(AuthError::PasswordHashError.code(), ErrorCode::PasswordHash);
    assert_eq!(AuthError::RateLimited.code(), ErrorCode::RateLimited);
    assert_eq!(AuthError::Csrf.code(), ErrorCode::Csrf);
    assert_eq!(
        AuthError::Internal(String::from("boom")).code(),
        ErrorCode::Internal
    );
    assert_eq!(
        ErrorCode::InvalidCredentials.as_str(),
        "invalid_credentials"
    );
    assert_eq!(ErrorCode::PasswordHash.as_str(), "password_hash_error");
    assert_eq!(ErrorCode::RateLimited.as_str(), "rate_limited");
    assert_eq!(ErrorCode::Csrf.as_str(), "csrf_validation_failed");
    assert_eq!(ErrorCode::Internal.as_str(), "internal_error");
    return;
}
