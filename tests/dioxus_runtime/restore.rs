//! Restore-verdict tests: loading, rejection, and success classification.

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
