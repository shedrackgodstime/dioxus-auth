//! Hashing, cookie, origin, storage, and rate-limit unit tests.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dioxus_auth::prelude::{
    Argon2Hasher, AuthError, CookieConfig, InMemoryRateLimiter, MemoryTokenStorage,
    OriginValidation, PasswordHasher, RateLimiter, RateLimiterClock, SameSite, TokenStorage,
};

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

/// Window expiry must be driven by the injected clock, deterministically and
/// without sleeping: attempts inside the window count, attempts older than the
/// window are pruned on the next check.
#[test]
fn rate_limiter_window_expiry_follows_the_injected_clock() {
    let now = Arc::new(parking_lot::Mutex::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000),
    ));
    let clock: RateLimiterClock = {
        let now = Arc::clone(&now);
        Arc::new(move || return *now.lock())
    };
    let limiter = InMemoryRateLimiter::with_clock(2, Duration::from_secs(60), clock);

    limiter.record_attempt("dana");
    limiter.record_attempt("dana");
    assert_eq!(limiter.check("dana"), Err(AuthError::RateLimited));

    // Advance past the window: the old attempts prune and the budget resets.
    *now.lock() = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000 + 120);
    assert!(limiter.check("dana").is_ok());
    limiter.record_attempt("dana");
    assert!(limiter.check("dana").is_ok());
}
