//! Direct unit tests for public API items (session ids, session records,
//! hashing, cookie config, token storage, rate limiting).

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

mod common;

use std::sync::Arc;

use common::{IdentityHasher, TestUser, hash_password};
use dioxus_auth::prelude::{
    Argon2Hasher, AuthEngine, AuthError, AuthStatus, CookieConfig, InMemoryRateLimiter,
    LoginOptions, MemoryStore, MemoryTokenStorage, OriginValidation, PasswordHasher,
    PasswordUserStore, RateLimiter, SameSite, Session, SessionId, SessionStore, TokenStorage,
    UserStore,
};

fn storage_session() -> Session<u64> {
    return Session::new(SessionId::generate(), 1, 1000, 2000);
}

fn seeded_login_engine() -> AuthEngine<MemoryStore<TestUser>, MemoryStore<TestUser>> {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", hash_password("pw"));
    let store = Arc::new(store);
    return AuthEngine::builder(Arc::clone(&store), store)
        .build()
        .expect("engine construction must succeed");
}

#[test]
fn session_id_generates_valid_128_hex_chars() {
    let id = SessionId::generate();
    let raw = id.as_str();
    assert_eq!(raw.len(), 64);
    assert!(SessionId::is_valid_wire_format(raw));
    let reparsed = id.into_string();
    assert_eq!(reparsed.len(), 64);
}

#[test]
fn session_id_rejects_oversized_and_non_hex_tokens() {
    assert!(!SessionId::is_valid_wire_format("short"));
    assert!(!SessionId::is_valid_wire_format(&"a".repeat(65)));
    assert!(!SessionId::is_valid_wire_format(&"g".repeat(64)));
    assert!(!SessionId::is_valid_wire_format(&"A".repeat(64)));
}

#[test]
fn session_id_storage_form_is_deterministic_sha256() {
    let id = SessionId::new("deadbeef".repeat(8));
    let first = id.hash_for_storage();
    let second = id.hash_for_storage();
    assert_eq!(first.as_str(), second.as_str());
    assert_eq!(first.as_str().len(), 64);
    assert_ne!(first.as_str(), id.as_str());
}

#[test]
fn session_id_debug_and_display_are_redacted() {
    let id = SessionId::new("a".repeat(64));
    assert!(!format!("{id}").contains('a'));
    assert!(!format!("{id:?}").contains('a'));
    assert!(format!("{id:?}").contains("***"));
}

#[test]
fn session_record_accessors_and_expiry() {
    let session = storage_session()
        .with_last_active(1500)
        .with_auth_hash("h")
        .with_ip_address("127.0.0.1")
        .with_user_agent("test-agent");

    assert_eq!(session.user_id(), &1);
    assert_eq!(session.created_at_unix(), 1000);
    assert_eq!(session.expires_at_unix(), 2000);
    assert_eq!(session.last_active_at_unix(), Some(1500));
    assert_eq!(session.auth_hash(), Some("h"));
    assert_eq!(session.ip_address(), Some("127.0.0.1"));
    assert_eq!(session.user_agent(), Some("test-agent"));
    assert!(!session.is_expired_at(1999));
    assert!(session.is_expired_at(2000));
}

#[test]
fn session_set_expiry_and_last_active_updates_both() {
    let session = storage_session().set_expiry_and_last_active(9000, 8000);
    assert_eq!(session.expires_at_unix(), 9000);
    assert_eq!(session.last_active_at_unix(), Some(8000));
}

#[test]
fn session_debug_redacts_id_and_auth_hash() {
    let session = storage_session().with_auth_hash("hunter2");
    let debug = format!("{session:?}");
    assert!(!debug.contains("hunter2"));
    assert!(!debug.contains("session\""));
}

#[test]
fn argon2_hash_verify_roundtrip() {
    let hasher = Argon2Hasher::new();
    let hash = hasher.hash("correct horse").unwrap();
    assert!(hasher.verify("correct horse", &hash).unwrap());
    assert!(!hasher.verify("wrong horse", &hash).unwrap());
}

#[test]
fn argon2_verify_malformed_hash_is_error() {
    let hasher = Argon2Hasher::new();
    assert_eq!(
        hasher.verify("pw", "not-a-phc-hash"),
        Err(AuthError::PasswordHashError)
    );
}

#[test]
fn cookie_config_defaults_are_secure() {
    let config = CookieConfig::new();
    assert_eq!(config.name(), "session");
    assert!(config.http_only());
    assert!(config.secure());
    assert_eq!(config.same_site(), SameSite::Lax);
    assert_eq!(config.path(), "/");
    assert_eq!(config.domain(), None);
    assert_eq!(config.max_age(), None);
}

#[test]
fn cookie_config_setters_override_defaults() {
    let config = CookieConfig::new()
        .with_name("sid".into())
        .with_http_only(false)
        .with_same_site(SameSite::Strict)
        .with_path("/app".into())
        .with_domain(Some("example.com".into()))
        .with_max_age(Some(3600));
    assert_eq!(config.name(), "sid");
    assert!(!config.http_only());
    assert!(config.secure());
    assert_eq!(config.same_site(), SameSite::Strict);
    assert_eq!(config.path(), "/app");
    assert_eq!(config.domain(), Some("example.com"));
    assert_eq!(config.max_age(), Some(3600));
}

#[test]
fn origin_validation_matches_exact_origins() {
    let validation = OriginValidation::new(vec!["https://app.example.com".into()]);
    assert!(validation.validate("https://app.example.com"));
    assert!(!validation.validate("https://evil.example.com"));
}

#[test]
fn memory_token_storage_roundtrip_and_clear() {
    let mut storage = MemoryTokenStorage::new();
    assert_eq!(storage.retrieve().unwrap(), None);
    storage.store("token-1").unwrap();
    assert_eq!(storage.retrieve().unwrap(), Some("token-1".to_string()));
    storage.clear().unwrap();
    assert_eq!(storage.retrieve().unwrap(), None);
}

#[test]
fn rate_limiter_blocks_after_max_attempts_and_resets_on_success() {
    let limiter = InMemoryRateLimiter::new(2, std::time::Duration::from_secs(60));
    assert!(limiter.check("alice").is_ok());
    limiter.record_attempt("alice");
    assert!(limiter.check("alice").is_ok());
    limiter.record_attempt("alice");
    assert_eq!(limiter.check("alice"), Err(AuthError::RateLimited));

    limiter.record_success("alice");
    assert!(limiter.check("alice").is_ok());
}

#[test]
fn rate_limiter_default_tracks_ten_attempts_per_15_minutes() {
    let limiter = InMemoryRateLimiter::default();
    for _ in 0..10 {
        limiter.record_attempt("bob");
    }
    assert_eq!(limiter.check("bob"), Err(AuthError::RateLimited));
    assert!(limiter.check("carol").is_ok());
}

#[test]
fn auth_status_variants_compare_by_value() {
    assert_eq!(
        AuthStatus::<u64>::Authenticated(7),
        AuthStatus::<u64>::Authenticated(7)
    );
    assert_ne!(
        AuthStatus::<u64>::Authenticated(7),
        AuthStatus::<u64>::Authenticated(8)
    );
    assert_eq!(AuthStatus::<u64>::Guest, AuthStatus::<u64>::Guest);
    assert_eq!(AuthStatus::<u64>::Loading, AuthStatus::<u64>::Loading);
}

#[test]
fn malformed_wire_tokens_are_cheap_rejections() {
    let engine = seeded_login_engine();
    let malformed = SessionId::new("not-a-64-char-hex-token");

    assert!(engine.validate_session(&malformed).unwrap().is_none());
    assert!(engine.logout(&malformed).is_ok());
    assert!(!engine.revoke_session(&malformed).unwrap());
}

#[test]
fn login_options_accessors_and_helpers() {
    let empty = LoginOptions::new();
    assert_eq!(empty.ip_address(), None);
    assert_eq!(empty.user_agent(), None);
    assert_eq!(LoginOptions::default(), empty);

    let filled = empty
        .with_ip_address(Some("198.51.100.1"))
        .with_user_agent(Some("agent"));
    assert_eq!(filled.ip_address(), Some("198.51.100.1"));
    assert_eq!(filled.user_agent(), Some("agent"));
}

#[test]
fn login_without_options_has_no_client_metadata() {
    let engine = seeded_login_engine();

    let (_, session) = engine.login("alice", "pw").unwrap();
    assert_eq!(session.ip_address(), None);
    assert_eq!(session.user_agent(), None);
}

#[test]
fn login_with_options_records_ip_and_user_agent() {
    let engine = seeded_login_engine();
    let options = LoginOptions::new()
        .with_ip_address(Some("203.0.113.7"))
        .with_user_agent(Some("dioxus-test/1.0"));

    let (user, session) = engine.login_with_options("alice", "pw", options).unwrap();
    assert_eq!(user.id, 1);
    assert_eq!(session.ip_address(), Some("203.0.113.7"));
    assert_eq!(session.user_agent(), Some("dioxus-test/1.0"));

    let storage_id = session.id().hash_for_storage();
    let stored = engine
        .session_store()
        .find_session(&storage_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.ip_address(), Some("203.0.113.7"));
    assert_eq!(stored.user_agent(), Some("dioxus-test/1.0"));
}

#[test]
fn custom_hasher_override_is_used_for_verification() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", String::from("correct"));
    let store = Arc::new(store);
    let engine = AuthEngine::builder(Arc::clone(&store), Arc::clone(&store))
        .hasher(IdentityHasher)
        .build()
        .expect("engine construction must succeed");

    assert!(engine.hasher().verify("x", "x").unwrap());
    let (user, _) = engine.login("alice", "correct").unwrap();
    assert_eq!(user.id, 1);
    let result = engine.login("alice", "wrong");
    assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
}

#[test]
fn memory_store_clone_is_independent() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", hash_password("pw"));
    let session = Session::new(SessionId::generate().hash_for_storage(), 1, 100, 200);
    store.save_session(session.clone()).unwrap();

    let clone = store.clone();
    assert!(clone.find_by_identifier("alice").unwrap().is_some());
    assert!(clone.find_session(session.id()).unwrap().is_some());

    clone.insert_user(TestUser::new(2, "bob"));
    clone.delete_session(session.id()).unwrap();

    assert!(store.find_by_id(&2).unwrap().is_none());
    assert!(clone.find_by_id(&2).unwrap().is_some());
    assert!(store.find_session(session.id()).unwrap().is_some());
    assert!(clone.find_session(session.id()).unwrap().is_none());
}
