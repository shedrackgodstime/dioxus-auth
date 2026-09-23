//! State-transition tests: restore, login, logout, validate.

// reason: project style requires explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::sync::Arc;

use dioxus_auth::{
    Auth, AuthEngineHandle, AuthError, AuthOperations, AuthStatus, MemoryTokenStorage, SessionId,
    TokenStorageHandle,
};

use super::common::TestUser;
use super::harness::{
    context, erased_state_dom, mount, seed_valid_token, seeded_engine, state_dom,
};

#[test]
fn provider_restores_guest_from_empty_storage() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let mut vdom = state_dom(&engine, storage);
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
    let mut vdom = state_dom(&engine, storage);
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
    let mut vdom = state_dom(&engine, storage.clone());
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
    let mut vdom = state_dom(&engine, storage.clone());
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
    let mut vdom = state_dom(&engine, storage.clone());
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
    let mut vdom = state_dom(&engine, storage);
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
    let mut vdom = state_dom(&engine, storage.clone());
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
    let mut vdom = state_dom(&engine, storage);
    mount(&mut vdom);

    let auth = context();
    assert!(!auth.is_loading());
    assert_eq!(auth.status(), AuthStatus::Guest);
}

#[test]
fn login_and_logout_route_through_the_single_engine_spelling() {
    /// Counts engine login/logout invocations so the test can prove the
    /// context delegates (one spelling), rather than re-implementing the
    /// credential work next to `sign_in_email` / `AuthOperations::login`.
    #[derive(Debug, Default)]
    struct CountingEngine {
        logins: std::sync::atomic::AtomicUsize,
        logouts: std::sync::atomic::AtomicUsize,
    }

    impl AuthOperations<TestUser> for CountingEngine {
        fn login(
            &self,
            _identifier: &str,
            _password: &str,
        ) -> Result<(TestUser, SessionId), AuthError> {
            let _ = self
                .logins
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return Ok((TestUser::new(1, "alice"), SessionId::generate()));
        }

        fn logout(&self, _session_id: &SessionId) -> Result<(), AuthError> {
            let _ = self
                .logouts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return Ok(());
        }

        fn validate(&self, _session_id: &SessionId) -> Result<Option<TestUser>, AuthError> {
            return Ok(None);
        }
    }

    let counts = Arc::new(CountingEngine::default());
    let erased: Arc<dyn AuthOperations<TestUser>> = counts.clone();
    let handle = AuthEngineHandle::from_erased(erased);
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let mut vdom = erased_state_dom(handle, storage);
    mount(&mut vdom);
    let auth = context();

    let login_result = auth.login("alice", "pw");
    assert!(login_result.is_ok());
    let logout_result = auth.logout();
    assert!(logout_result.is_ok());

    assert_eq!(
        counts.logins.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one context login must be exactly one engine login"
    );
    assert_eq!(
        counts.logouts.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one context logout must be exactly one engine logout"
    );
}

/// Facade verbs and runtime twins agree: same store, same credentials, same
/// user, sessions that validate to the same identity, same error codes.
#[test]
fn facade_and_runtime_twins_produce_identical_results() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let mut vdom = state_dom(&engine, storage);
    mount(&mut vdom);
    let context = context();
    let auth = Auth::from_engine((*engine).clone());

    let (facade_user, facade_session) = auth
        .sign_in_email("alice", "pw")
        .expect("facade sign-in must succeed");
    context
        .login("alice", "pw")
        .expect("context login must succeed");
    let context_user = context.user().expect("context must be authenticated");
    assert_eq!(facade_user, context_user);

    let context_session = context.token().expect("token must be set");
    for session in [&facade_session, &context_session] {
        let validated = engine
            .validate_session(session)
            .expect("validation must succeed")
            .expect("both sessions must validate");
        assert_eq!(validated, facade_user);
    }

    assert_eq!(
        auth.sign_in_email("alice", "wrong")
            .expect_err("facade must reject"),
        AuthError::InvalidCredentials
    );
    assert_eq!(
        context
            .login("alice", "wrong")
            .expect_err("context must reject"),
        AuthError::InvalidCredentials
    );
    return;
}
