//! Tests for the type-erased engine handle.

// reason: project style requires explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::sync::Arc;

use dioxus_auth::{AuthEngineHandle, AuthError, AuthOperations, SessionId};

use super::common::TestUser;

/// A canned engine implementation for handle tests.
#[derive(Debug)]
struct StubEngine;

impl AuthOperations<TestUser> for StubEngine {
    fn login(
        &self,
        _identifier: &str,
        _password: &str,
    ) -> Result<(TestUser, SessionId), AuthError> {
        return Ok((TestUser::new(1, "alice"), SessionId::generate()));
    }

    fn logout(&self, _session_id: &SessionId) -> Result<(), AuthError> {
        return Ok(());
    }

    fn validate(&self, _session_id: &SessionId) -> Result<Option<TestUser>, AuthError> {
        return Ok(None);
    }
}

#[test]
fn erased_handle_delegates_operations_through_the_trait_object() {
    let handle = AuthEngineHandle::from_erased(Arc::new(StubEngine));

    let (user, session) = handle
        .engine()
        .login("alice", "pw")
        .expect("stub login must succeed");
    assert_eq!(user.id, 1);
    assert!(SessionId::is_valid_wire_format(session.as_str()));

    handle
        .engine()
        .logout(&session)
        .expect("stub logout must succeed");
    let validated = handle
        .engine()
        .validate(&session)
        .expect("stub validation must not error");
    assert!(validated.is_none());
}
