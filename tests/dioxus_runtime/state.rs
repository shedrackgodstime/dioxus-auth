//! State-transition tests: restore, login, logout, validate.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use dioxus_auth::prelude::{AuthStatus, MemoryTokenStorage, SessionId, TokenStorageHandle};

use super::common::TestUser;
use super::harness::{context, mount, seed_valid_token, seeded_engine, state_dom};

#[test]
fn provider_restores_guest_from_empty_storage() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let mut vdom = state_dom(engine, storage);
    mount(&mut vdom);

    let auth = context();
    assert!(!auth.is_loading());
    assert!(!auth.is_authenticated());
    assert_eq!(auth.status(), AuthStatus::Guest);
    assert!(auth.user().is_none());
    assert!(auth.token().is_none());
    assert!(!auth.token_persisted());
}

#[test]
fn provider_restores_authenticated_user_from_stored_token() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let wire = seed_valid_token(&storage, &engine);
    let mut vdom = state_dom(engine, storage);
    mount(&mut vdom);

    let auth = context();
    assert!(!auth.is_loading());
    assert!(auth.is_authenticated());
    assert_eq!(
        auth.status(),
        AuthStatus::Authenticated(TestUser::new(1, "alice"))
    );
    assert_eq!(auth.user().expect("a restored user must be present").id, 1);
    assert_eq!(
        auth.token().as_ref().map(SessionId::as_str),
        Some(wire.as_str())
    );
    assert!(auth.token_persisted());
}

#[test]
fn login_roundtrip_persists_token_and_sets_status() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let mut vdom = state_dom(engine, storage.clone());
    mount(&mut vdom);
    let auth = context();

    let result = auth.login("alice", "pw");
    assert!(result.is_ok());
    mount(&mut vdom);

    assert_eq!(
        auth.status(),
        AuthStatus::Authenticated(TestUser::new(1, "alice"))
    );
    assert!(auth.token_persisted());
    let stored = storage.retrieve().expect("storage must be readable");
    assert_eq!(
        stored.as_deref(),
        Some(auth.token().expect("a token must be set").as_str())
    );
}

#[test]
fn login_rejects_wrong_password_and_leaves_guest_state() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let mut vdom = state_dom(engine, storage.clone());
    mount(&mut vdom);
    let auth = context();

    let result = auth.login("alice", "nope");
    assert!(result.is_err());
    mount(&mut vdom);

    assert_eq!(auth.status(), AuthStatus::Guest);
    assert!(!auth.token_persisted());
    assert!(
        storage
            .retrieve()
            .expect("storage must be readable")
            .is_none()
    );
}

#[test]
fn logout_clears_guest_and_revokes_the_session() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let mut vdom = state_dom(engine, storage.clone());
    mount(&mut vdom);
    let auth = context();
    assert!(auth.login("alice", "pw").is_ok());

    let result = auth.logout();
    assert!(result.is_ok());
    mount(&mut vdom);

    assert_eq!(auth.status(), AuthStatus::Guest);
    assert!(auth.token().is_none());
    assert!(!auth.token_persisted());
    assert!(
        storage
            .retrieve()
            .expect("storage must be readable")
            .is_none()
    );

    let validated = auth.validate();
    assert!(
        validated
            .expect("validation of a revoked session must not error")
            .is_none()
    );
}

#[test]
fn validate_reports_guest_when_the_token_is_revoked() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let wire = seed_valid_token(&storage, &engine);
    let mut vdom = state_dom(engine, storage);
    mount(&mut vdom);
    let auth = context();
    assert!(auth.is_authenticated());

    let revoked = auth.logout();
    assert!(revoked.is_ok());
    let _ = wire;

    let validated = auth.validate();
    assert!(validated.expect("validation must not error").is_none());
    assert_eq!(auth.status(), AuthStatus::Guest);
}

#[test]
fn restore_demotes_stale_tokens_to_guest_but_keeps_storage() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let stale = format!("ab{}", "c".repeat(62));
    storage
        .store(&stale)
        .expect("storing a stale token must succeed");
    let mut vdom = state_dom(engine, storage.clone());
    mount(&mut vdom);

    let auth = context();
    assert!(!auth.is_loading());
    assert_eq!(auth.status(), AuthStatus::Guest);
    let retained = storage.retrieve().expect("storage must be readable");
    assert_eq!(retained.as_deref(), Some(stale.as_str()));
}

#[test]
fn restore_demotes_malformed_tokens_to_guest() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    storage
        .store("not-a-wire-token")
        .expect("storing must succeed");
    let mut vdom = state_dom(engine, storage);
    mount(&mut vdom);

    let auth = context();
    assert!(!auth.is_loading());
    assert_eq!(auth.status(), AuthStatus::Guest);
}
