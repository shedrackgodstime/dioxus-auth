//! Engine policy tests: single sessions, rate limiting, TTL, getters.

// reason: project style requires explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::sync::Arc;
use std::time::Duration;

use super::common::TestUser;
use super::password::hash_password;
use dioxus_auth::{
    AuthEngine, AuthError, InMemoryRateLimiter, MemoryStore, SessionId, SessionStore, UserStore,
};

use super::seeded_engine;

#[test]
fn revoke_all_user_sessions_invalidates_every_active_session() {
    let engine = seeded_engine();

    let (_, first) = engine.login("alice", "s3cret").unwrap();
    let (_, second) = engine.login("alice", "s3cret").unwrap();
    assert!(engine.validate_session(first.id()).unwrap().is_some());
    assert!(engine.validate_session(second.id()).unwrap().is_some());

    engine.revoke_all_user_sessions(&1).unwrap();

    assert!(engine.validate_session(first.id()).unwrap().is_none());
    assert!(engine.validate_session(second.id()).unwrap().is_none());
}

#[test]
fn single_active_session_invalidates_the_previous_session() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", hash_password("pw"));
    let store = Arc::new(store);
    let engine = AuthEngine::builder(Arc::clone(&store), store)
        .single_active_session(true)
        .build()
        .expect("engine construction must succeed");

    let (_, first) = engine.login("alice", "pw").unwrap();
    let (_, second) = engine.login("alice", "pw").unwrap();

    assert!(engine.validate_session(first.id()).unwrap().is_none());
    assert!(engine.validate_session(second.id()).unwrap().is_some());
}

/// A corrupt stored hash must be indistinguishable from a wrong password in
/// the login error channel: same `InvalidCredentials` variant, so a corrupted
/// row cannot confirm "identifier exists" to an attacker probing login.
#[test]
fn malformed_stored_hash_is_indistinguishable_from_wrong_password() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", "not-a-phc-hash");
    let corrupt = Arc::new(store);
    let corrupt_engine = AuthEngine::builder(Arc::clone(&corrupt), corrupt)
        .build()
        .expect("engine construction must succeed");

    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "bob"), "bob", hash_password("pw"));
    let healthy = Arc::new(store);
    let healthy_engine = AuthEngine::builder(Arc::clone(&healthy), healthy)
        .build()
        .expect("engine construction must succeed");

    let corrupt_result = corrupt_engine.login("alice", "whatever");
    let wrong_password_result = healthy_engine.login("bob", "wrong");
    let unknown_user_result = healthy_engine.login("ghost", "wrong");

    assert_eq!(
        corrupt_result.unwrap_err(),
        AuthError::InvalidCredentials,
        "corrupt stored hash must not surface a distinct error variant"
    );
    assert_eq!(
        wrong_password_result.unwrap_err(),
        AuthError::InvalidCredentials
    );
    assert_eq!(
        unknown_user_result.unwrap_err(),
        AuthError::InvalidCredentials
    );

    // The hasher's `Err` channel stays intact for direct callers, where no
    // enumeration oracle exists.
    assert_eq!(
        corrupt_engine.hasher().verify("pw", "not-a-phc-hash"),
        Err(AuthError::PasswordHashError)
    );
}

#[test]
fn failed_attempts_are_rate_limited() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", hash_password("pw"));
    let store = Arc::new(store);
    let limiter = InMemoryRateLimiter::new(2, std::time::Duration::from_secs(60));
    let engine = AuthEngine::builder(Arc::clone(&store), store)
        .rate_limiter(limiter)
        .build()
        .expect("engine construction must succeed");

    assert!(engine.login("alice", "wrong-1").is_err());
    assert!(engine.login("alice", "wrong-2").is_err());

    let result = engine.login("alice", "wrong-3");
    assert_eq!(result.unwrap_err(), AuthError::RateLimited);
}

#[test]
fn engine_getters_expose_configured_defaults() {
    let engine = seeded_engine();

    assert_eq!(engine.session_ttl_secs(), 7 * 24 * 60 * 60);
    assert_eq!(engine.idle_timeout_secs(), None);
    assert!(!engine.single_active_session());
    assert!(engine.user_store().find_by_id(&1).unwrap().is_some());
    assert!(
        engine
            .session_store()
            .find_session(&SessionId::new("0".repeat(64)))
            .unwrap()
            .is_none()
    );
    assert!(
        engine
            .hasher()
            .verify("s3cret", &hash_password("s3cret"))
            .unwrap()
    );
}

#[test]
fn builder_ttl_and_idle_timeout_flow_through_to_getters() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", hash_password("pw"));
    let store = Arc::new(store);
    let engine = AuthEngine::builder(Arc::clone(&store), store)
        .session_ttl(Duration::from_secs(30))
        .idle_timeout(Duration::from_secs(10))
        .build()
        .expect("engine construction must succeed");

    assert_eq!(engine.session_ttl_secs(), 30);
    assert_eq!(engine.idle_timeout_secs(), Some(10));
}

/// Empty and whitespace-only identifiers normalize to nothing and share the
/// unknown-identifier path: `InvalidCredentials`, no panic, no oracle.
#[test]
fn empty_identifiers_share_the_unknown_identifier_path() {
    let engine = seeded_engine();

    for identifier in ["", "   ", "\t\n "] {
        assert_eq!(
            engine.login(identifier, "s3cret").unwrap_err(),
            AuthError::InvalidCredentials
        );
    }
}
