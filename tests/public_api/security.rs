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
fn cookie_host_only_and_origins_roundtrip_through_setters() {
    let config = CookieConfig::new()
        .with_host_only(true)
        .with_expected_origins(vec![String::from("https://app.example.com")]);
    assert!(config.host_only());
    let expected = config.expected_origins().expect("origins must be set");
    assert!(expected.validate("https://app.example.com"));
    assert!(!CookieConfig::new().host_only());
    assert!(CookieConfig::new().expected_origins().is_none());
}

#[test]
fn check_origin_passes_without_config_and_enforces_with_config() {
    let open = CookieConfig::new();
    assert!(open.check_origin(None).is_ok());
    assert!(open.check_origin(Some("https://evil.example.com")).is_ok());

    let gated =
        CookieConfig::new().with_expected_origins(vec![String::from("https://app.example.com")]);
    assert!(gated.check_origin(Some("https://app.example.com")).is_ok());
    assert_eq!(gated.check_origin(None), Err(AuthError::Csrf));
    assert_eq!(
        gated.check_origin(Some("https://evil.example.com")),
        Err(AuthError::Csrf)
    );
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
fn rate_limiter_prod_matches_the_documented_ceiling() {
    let limiter = InMemoryRateLimiter::prod();
    for _ in 0..99 {
        limiter.record_attempt("bob");
    }
    assert!(limiter.check("bob").is_ok());
    limiter.record_attempt("bob");
    assert_eq!(limiter.check("bob"), Err(AuthError::RateLimited));
    assert!(limiter.check("carol").is_ok());
}

#[test]
fn rate_limiter_window_expiry_follows_the_injected_clock() {
    // Window expiry is driven by the injected clock without sleeping: attempts
    // inside the window count, attempts older than the window prune on the
    // next check.
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
    return;
}

#[test]
fn rate_limiter_evicts_stale_entries_at_the_tracking_ceiling() {
    // A flood of distinct identifiers must not grow the map without limit:
    // once the ceiling is reached, lapsed entries are reclaimed and the fresh
    // arrival is admitted without dropping live budgets.
    let now = Arc::new(parking_lot::Mutex::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000),
    ));
    let clock: RateLimiterClock = {
        let now = Arc::clone(&now);
        Arc::new(move || return *now.lock())
    };
    let limiter =
        InMemoryRateLimiter::with_clock(1, Duration::from_secs(60), clock).with_max_tracked(3);
    for index in 0..3 {
        limiter.record_attempt(&format!("stale-{index}"));
    }
    assert_eq!(limiter.tracked_identifiers(), 3);
    *now.lock() = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000 + 120);
    limiter.record_attempt("newcomer");
    assert_eq!(limiter.tracked_identifiers(), 1);
    assert!(limiter.check("stale-0").is_ok());
    assert_eq!(limiter.check("newcomer"), Err(AuthError::RateLimited));
    return;
}
