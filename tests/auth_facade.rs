//! Tests for the `Auth` entry facade: shell plus email/password verbs.

// reason: project style requires explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

#[path = "common/mod.rs"]
mod common;
#[path = "common/password.rs"]
mod password;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::TestUser;
use dioxus_auth::{
    Argon2Hasher, Auth, AuthEngine, AuthError, AuthUser, DefaultUser, ErrorCode,
    InMemoryRateLimiter, MemoryStore, PasswordHasher,
};
use password::hash_password;

#[test]
fn memory_constructs_with_secure_defaults() {
    let auth = Auth::new(MemoryStore::<TestUser>::new()).expect("facade must construct");
    assert_eq!(auth.engine().session_ttl_secs(), 60 * 60 * 24 * 7);
    return;
}

#[test]
fn new_takes_the_store_by_value() {
    let auth =
        Auth::new(MemoryStore::<TestUser>::new()).expect("facade must construct over caller store");
    assert_eq!(auth.engine().session_ttl_secs(), 60 * 60 * 24 * 7);
    return;
}

#[test]
fn facade_delegates_to_engine_lifecycle() {
    let auth = Auth::new(MemoryStore::<TestUser>::new()).expect("facade must construct");
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
    let auth = Auth::new(MemoryStore::<TestUser>::new()).expect("facade must construct");
    let again = auth.clone();
    assert!(Arc::ptr_eq(auth.engine(), again.engine()));
    return;
}

#[test]
fn facade_debug_names_auth() {
    let auth = Auth::new(MemoryStore::<TestUser>::new()).expect("facade must construct");
    let rendered = format!("{auth:?}");
    assert!(rendered.starts_with("Auth("));
    return;
}

#[test]
fn sign_up_provisions_and_signs_in() {
    let auth = Auth::new(MemoryStore::<TestUser>::new()).expect("facade must construct");
    let (user, session) = auth
        .sign_up_email("alice", "s3cret", TestUser::new(1, "alice"))
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
    let auth = Auth::new(MemoryStore::<TestUser>::new()).expect("facade must construct");
    auth.sign_up_email("alice", "s3cret", TestUser::new(1, "alice"))
        .expect("first sign-up must succeed");
    let taken = auth
        .sign_up_email("alice", "other", TestUser::new(2, "mallory"))
        .expect_err("taken identifier must fail");
    let unknown = auth
        .sign_in_email("nobody", "whatever")
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
        .sign_up_email("alice", "pw", TestUser::new(2, "mallory"))
        .expect_err("taken identifier must fail");
    let second = auth
        .sign_up_email("alice", "pw", TestUser::new(2, "mallory"))
        .expect_err("taken identifier must fail again");
    assert_eq!(first, AuthError::InvalidCredentials);
    assert_eq!(second, AuthError::InvalidCredentials);

    // reason: the taken probes were recorded as attempts, so the next
    // credential operation on the same identifier is throttled. The sign-up
    // gate and the login gate are one window, not two.
    let throttled = auth
        .sign_in_email("alice", "pw")
        .expect_err("throttled sign-in must fail");
    assert_eq!(throttled, AuthError::RateLimited);

    let blocked = auth
        .sign_up_email("alice", "pw", TestUser::new(2, "mallory"))
        .expect_err("throttled sign-up must fail");
    assert_eq!(blocked, AuthError::RateLimited);
    return;
}

#[test]
fn throttle_window_is_shared_across_identifier_spellings() {
    // Spacing and case are display variants, not separate budgets: every
    // credential verb funnels through one normalized throttle key.
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
        .sign_in_email("  Alice", "wrong")
        .expect_err("first bad attempt must fail");
    assert_eq!(first, AuthError::InvalidCredentials);
    let second = auth
        .sign_in_email("ALICE ", "wrong")
        .expect_err("second bad attempt must fail");
    assert_eq!(second, AuthError::InvalidCredentials);
    let throttled = auth
        .sign_in_email("alice", "pw")
        .expect_err("canonical spelling must throttle");
    assert_eq!(throttled, AuthError::RateLimited);
    return;
}

#[test]
fn sign_in_rejects_wrong_password_without_oracle() {
    let auth = Auth::new(MemoryStore::<TestUser>::new()).expect("facade must construct");
    auth.sign_up_email("alice", "s3cret", TestUser::new(1, "alice"))
        .expect("sign-up must succeed");
    let wrong = auth
        .sign_in_email("alice", "wrong")
        .expect_err("wrong password must fail");
    assert_eq!(wrong, AuthError::InvalidCredentials);
    return;
}

#[test]
fn sign_out_revokes_session() {
    let auth = Auth::new(MemoryStore::<TestUser>::new()).expect("facade must construct");
    let (_, session) = auth
        .sign_up_email("alice", "s3cret", TestUser::new(1, "alice"))
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
    let auth = Auth::new(MemoryStore::<TestUser>::new()).expect("facade must construct");
    let (_, session) = auth
        .sign_up_email("alice", "old-secret", TestUser::new(1, "alice"))
        .expect("sign-up must succeed");
    auth.change_password("alice", "old-secret", "new-secret")
        .expect("change must succeed");
    let stale = auth
        .sign_in_email("alice", "old-secret")
        .expect_err("old password must fail");
    assert_eq!(stale, AuthError::InvalidCredentials);
    let (user, _) = auth
        .sign_in_email("alice", "new-secret")
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
    let auth = Auth::new(MemoryStore::<TestUser>::new()).expect("facade must construct");
    auth.sign_up_email("alice", "s3cret", TestUser::new(1, "alice"))
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

/// A [`PasswordHasher`] that counts hash and verify calls so tests can assert
/// the Argon2 work a credential path performs, not just its outcome.
#[derive(Debug)]
struct CountingHasher {
    inner: Argon2Hasher,
    hashes: Arc<AtomicUsize>,
    verifies: Arc<AtomicUsize>,
}

impl CountingHasher {
    fn counters(&self) -> (Arc<AtomicUsize>, Arc<AtomicUsize>) {
        return (Arc::clone(&self.hashes), Arc::clone(&self.verifies));
    }
}

impl PasswordHasher for CountingHasher {
    fn hash(&self, password: &str) -> Result<String, AuthError> {
        let encoded = self.inner.hash(password);
        self.hashes.fetch_add(1, Ordering::SeqCst);
        return encoded;
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, AuthError> {
        let result = self.inner.verify(password, hash);
        self.verifies.fetch_add(1, Ordering::SeqCst);
        return result;
    }
}

#[test]
fn sign_up_taken_and_free_paths_cost_equal_argon2_work() {
    let db = Arc::new(MemoryStore::<TestUser>::new());
    let hasher = CountingHasher {
        inner: Argon2Hasher::new(),
        hashes: Arc::new(AtomicUsize::new(0)),
        verifies: Arc::new(AtomicUsize::new(0)),
    };
    let (hash_counter, verify_counter) = hasher.counters();
    let engine = AuthEngine::builder(Arc::clone(&db), Arc::clone(&db))
        .hasher(hasher)
        .build()
        .expect("counting engine must construct");
    let auth = Auth::from_engine(engine);
    // Construction precomputes the timing-defense dummy hash (one `hash`
    // call); that is engine setup, not per-request credential work. Measure
    // from the first request onward.
    hash_counter.store(0, Ordering::SeqCst);
    verify_counter.store(0, Ordering::SeqCst);

    // Free path: an unknown identifier is provisioned and signed in.
    let free = auth.sign_up_email("free-alice", "s3cret", TestUser::new(1, "alice"));
    assert!(free.is_ok(), "free identifier must provision");
    let free_work = (
        hash_counter.load(Ordering::SeqCst),
        verify_counter.load(Ordering::SeqCst),
    );

    // Taken path: the same identifier again must cost the same total work.
    hash_counter.store(0, Ordering::SeqCst);
    verify_counter.store(0, Ordering::SeqCst);
    let taken = auth.sign_up_email("free-alice", "other", TestUser::new(2, "bob"));
    assert_eq!(
        taken.expect_err("taken identifier must fail").code(),
        ErrorCode::InvalidCredentials
    );
    let taken_work = (
        hash_counter.load(Ordering::SeqCst),
        verify_counter.load(Ordering::SeqCst),
    );

    assert_eq!(
        free_work, taken_work,
        "identifier state must not be timing-visible through Argon2 work"
    );
    assert_eq!(free_work, (1, 1), "free path: one hash plus one verify");
    assert_eq!(taken_work, (1, 1), "taken path: one hash plus one verify");
    return;
}

#[test]
fn default_user_constructor_flows_through_memory() {
    let auth = Auth::memory().expect("quickstart must construct");
    let alice = DefaultUser::new(1, "alice@example.com", "alice");
    assert_eq!(alice.id(), 1);
    assert_eq!(alice.email, "alice@example.com");
    let (user, _) = auth
        .sign_up_email("alice@example.com", "pw", alice)
        .expect("sign-up must succeed");
    assert_eq!(user, DefaultUser::new(1, "alice@example.com", "alice"));
    return;
}
