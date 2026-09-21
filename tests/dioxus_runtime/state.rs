//! State-transition tests: restore, login, logout, validate.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::sync::Arc;

use dioxus_auth::prelude::{
    AuthEngineHandle, AuthError, AuthOperations, AuthStatus, MemoryTokenStorage, RestoreVerdict,
    SessionId, TokenStorage, TokenStorageHandle,
};

use super::common::TestUser;
use super::harness::{
    context, erased_state_dom, mount, seed_valid_token, seeded_engine, state_dom,
};

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

/// A token storage whose reads always fail, simulating broken persistence
/// (quota errors, private-mode restrictions, driver failures).
#[derive(Debug)]
struct FailingTokenStorage;

impl FailingTokenStorage {
    const fn new() -> Self {
        return Self;
    }
}

impl TokenStorage for FailingTokenStorage {
    fn store(&mut self, _token: &str) -> Result<(), AuthError> {
        return Err(AuthError::Internal(String::from("storage unavailable")));
    }

    fn retrieve(&self) -> Result<Option<String>, AuthError> {
        return Err(AuthError::Internal(String::from("storage unavailable")));
    }

    fn clear(&mut self) -> Result<(), AuthError> {
        return Err(AuthError::Internal(String::from("storage unavailable")));
    }
}

/// An erased engine whose validation never produces an answer, simulating a
/// transport failure between the client runtime and a remote engine.
#[derive(Debug)]
struct UnknownEngine;

impl AuthOperations<TestUser> for UnknownEngine {
    fn login(
        &self,
        _identifier: &str,
        _password: &str,
    ) -> Result<(TestUser, SessionId), AuthError> {
        return Err(AuthError::Internal(String::from("transport down")));
    }

    fn logout(&self, _session_id: &SessionId) -> Result<(), AuthError> {
        return Err(AuthError::Internal(String::from("transport down")));
    }

    fn validate(&self, _session_id: &SessionId) -> Result<Option<TestUser>, AuthError> {
        return Err(AuthError::Internal(String::from("transport down")));
    }
}

/// An erased engine that definitively rejects every token it is asked about.
#[derive(Debug)]
struct RejectedEngine;

impl AuthOperations<TestUser> for RejectedEngine {
    fn login(
        &self,
        _identifier: &str,
        _password: &str,
    ) -> Result<(TestUser, SessionId), AuthError> {
        return Err(AuthError::InvalidCredentials);
    }

    fn logout(&self, _session_id: &SessionId) -> Result<(), AuthError> {
        return Err(AuthError::InvalidCredentials);
    }

    fn validate(&self, _session_id: &SessionId) -> Result<Option<TestUser>, AuthError> {
        return Err(AuthError::InvalidCredentials);
    }
}

#[test]
fn restore_keeps_loading_when_storage_fails() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(FailingTokenStorage::new());
    let mut vdom = state_dom(engine, storage);
    mount(&mut vdom);

    let auth = context();
    // The storage failure never answered the session question, so the
    // provider must NOT demote the context to guest.
    assert!(auth.is_loading());
    assert_eq!(auth.status(), AuthStatus::Loading);
    assert_eq!(auth.restore(), RestoreVerdict::Unknown);
}

#[test]
fn restore_keeps_loading_when_the_engine_answer_is_unknown() {
    let engine = AuthEngineHandle::from_erased(Arc::new(UnknownEngine));
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let token = "a".repeat(64);
    storage
        .store(&token)
        .expect("storing a well-formed token must succeed");
    let mut vdom = erased_state_dom(engine, storage.clone());
    mount(&mut vdom);

    let auth = context();
    assert!(auth.is_loading());
    assert_eq!(auth.status(), AuthStatus::Loading);
    assert_eq!(auth.restore(), RestoreVerdict::Unknown);
    // An unknown outcome must not have cleared the stored token.
    let retained = storage.retrieve().expect("storage must be readable");
    assert_eq!(retained.as_deref(), Some(token.as_str()));
}

#[test]
fn restore_demotes_to_guest_on_a_definitive_engine_rejection() {
    let engine = AuthEngineHandle::from_erased(Arc::new(RejectedEngine));
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let token = "a".repeat(64);
    storage
        .store(&token)
        .expect("storing a well-formed token must succeed");
    let mut vdom = erased_state_dom(engine, storage.clone());
    mount(&mut vdom);

    let auth = context();
    assert!(!auth.is_loading());
    assert_eq!(auth.status(), AuthStatus::Guest);
    assert_eq!(auth.restore(), RestoreVerdict::Unauthenticated);
    // A definitive rejection leaves the (dead) token in storage; third-party
    // backends keep their own retry semantics.
    let retained = storage.retrieve().expect("storage must be readable");
    assert_eq!(retained.as_deref(), Some(token.as_str()));
}

#[test]
fn restore_reports_the_restored_verdict_on_success() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let _wire = seed_valid_token(&storage, &engine);
    let mut vdom = state_dom(engine, storage);
    mount(&mut vdom);

    let auth = context();
    assert!(auth.is_authenticated());
    // A repeat restore re-validates the live session and says so.
    assert_eq!(auth.restore(), RestoreVerdict::Restored);
    assert!(auth.is_authenticated());
}
