//! Type-erased engine operations and the prop handle that wraps them.

use std::fmt;
use std::sync::Arc;

use crate::engine::AuthEngine;
use crate::error::AuthError;
use crate::status::SessionId;
use crate::store::{PasswordUserStore, SessionStore};
use crate::user::AuthUser;

/// Erased authorization operations used by the runtime layer.
///
/// The runtime is generic over the application user type only; the concrete
/// user/session store generics are hidden behind this trait object so hooks
/// and components never leak `MemoryStore<…>`-style types.
pub trait AuthOperations<T: AuthUser>: Send + Sync {
    /// Authenticates and returns the user with a fresh raw wire session.
    ///
    /// # Errors
    /// Mirrors [`AuthEngine::login`](crate::engine::AuthEngine::login).
    fn login(&self, identifier: &str, password: &str) -> Result<(T, SessionId), AuthError>;

    /// Revokes a session, identified here by its raw wire token.
    ///
    /// # Errors
    /// Mirrors [`AuthEngine::logout`](crate::engine::AuthEngine::logout).
    fn logout(&self, session_id: &SessionId) -> Result<(), AuthError>;

    /// Validates a raw wire token and resolves the current user.
    ///
    /// # Errors
    /// Mirrors [`AuthEngine::validate_session`](crate::engine::AuthEngine::validate_session).
    fn validate(&self, session_id: &SessionId) -> Result<Option<T>, AuthError>;
}

impl<U, S> AuthOperations<U::User> for AuthEngine<U, S>
where
    U: PasswordUserStore,
    S: SessionStore<Id = U::Id>,
{
    fn login(&self, identifier: &str, password: &str) -> Result<(U::User, SessionId), AuthError> {
        return match Self::login(self, identifier, password) {
            Ok((user, session)) => Ok((user, session.id().clone())),
            Err(e) => Err(e),
        };
    }

    fn logout(&self, session_id: &SessionId) -> Result<(), AuthError> {
        return Self::logout(self, session_id);
    }

    fn validate(&self, session_id: &SessionId) -> Result<Option<U::User>, AuthError> {
        return Self::validate_session(self, session_id);
    }
}

/// Cloneable, erasable engine handle named in component props.
///
/// `PartialEq` compares the shared `Arc` identity: prop diffing cannot and must
/// not compare erased engines field by field.
#[derive(Clone)]
pub struct AuthEngineHandle<T: AuthUser>(pub(crate) Arc<dyn AuthOperations<T>>);

impl<T: AuthUser> AuthEngineHandle<T> {
    /// Wraps a type-erased authorization implementation.
    #[must_use]
    pub fn from_erased(engine: Arc<dyn AuthOperations<T>>) -> Self {
        return Self(engine);
    }

    /// Accesses the erased engine.
    #[must_use]
    pub fn engine(&self) -> &Arc<dyn AuthOperations<T>> {
        return &self.0;
    }
}

impl<T: AuthUser> fmt::Debug for AuthEngineHandle<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return f.write_str("AuthEngineHandle(..)");
    }
}

impl<T: AuthUser> PartialEq for AuthEngineHandle<T> {
    // reason: erased engines have no meaningful structural equality for prop
    // diffing; the shared Arc identity is the only sound equivalence.
    fn eq(&self, other: &Self) -> bool {
        return Arc::ptr_eq(&self.0, &other.0);
    }
}

impl<T: AuthUser> Eq for AuthEngineHandle<T> {}

impl<U, S> From<Arc<AuthEngine<U, S>>> for AuthEngineHandle<U::User>
where
    U: PasswordUserStore + 'static,
    S: SessionStore<Id = U::Id> + 'static,
{
    fn from(engine: Arc<AuthEngine<U, S>>) -> Self {
        return Self(engine);
    }
}
