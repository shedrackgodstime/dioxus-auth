//! Type-erased engine operations and the prop handle that wraps them.

use std::fmt;
use std::sync::Arc;

use crate::auth::Auth;
use crate::engine::AuthEngine;
use crate::error::AuthError;
use crate::status::SessionId;
use crate::store::{PasswordUserStore, SessionStore, UserStore};
use crate::user::AuthUser;

/// Erased authorization operations used by the runtime layer.
///
/// The runtime is generic over the application user type only; the concrete
/// user/session store generics are hidden behind this trait object so hooks
/// and components never leak `MemoryStore<…>`-style types.
///
/// Single-spelling rule: credential verification lives in exactly one place —
/// lives in exactly one place — [`AuthEngine::login`](crate::engine::AuthEngine::login)
/// and its helpers. The [`AuthContext`](super::context::AuthContext) calls these
/// operations rather than the [`Auth`](crate::auth::Auth) facade verbs because
/// it holds the erased handle (no concrete `Auth<D>` exists here to delegate
/// through) and does its own signal/token shaping around the same engine calls.
/// No third login spelling may be introduced beside these two layers.
pub trait AuthOperations<T: AuthUser>: Send + Sync {
    /// Authenticates and returns the user with a fresh raw wire session.
    ///
    /// # Errors
    /// Mirrors [`AuthEngine::login`](crate::engine::AuthEngine::login).
    #[must_use = "the authenticated user and wire session must be used"]
    fn login(&self, identifier: &str, password: &str) -> Result<(T, SessionId), AuthError>;

    /// Revokes a session, identified here by its raw wire token.
    ///
    /// # Errors
    /// Mirrors [`AuthEngine::logout`](crate::engine::AuthEngine::logout).
    #[must_use = "session revocation errors must be handled"]
    fn logout(&self, session_id: &SessionId) -> Result<(), AuthError>;

    /// Validates a raw wire token and resolves the current user.
    ///
    /// # Errors
    /// Mirrors [`AuthEngine::validate_session`](crate::engine::AuthEngine::validate_session).
    #[must_use = "the validated user must be used"]
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
pub struct AuthEngineHandle<T: AuthUser>(pub(crate) Arc<dyn AuthOperations<T>>);

impl<T: AuthUser> Clone for AuthEngineHandle<T> {
    fn clone(&self) -> Self {
        return Self(Arc::clone(&self.0));
    }
}

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

/// Bridges the `Auth` facade to the engine handle that [`AuthProvider`](super::provider::AuthProvider) consumes.
///
/// Before this impl, a Door-1 caller had to write
/// `AuthEngineHandle::from(Arc::clone(auth.engine()))` — three concepts
/// (`Arc`, `AuthEngineHandle`, erasure) that the first-page budget forbids.
/// `Auth::into()` keeps that bridge to a single word.
impl<D> From<Auth<D>> for AuthEngineHandle<D::User>
where
    D: PasswordUserStore + SessionStore<Id = <D as UserStore>::Id> + 'static,
{
    fn from(auth: Auth<D>) -> Self {
        // Coerce the concrete engine Arc to the erased trait-object Arc,
        // then clone the erased handle (Arc<AuthEngine> does not coerce when
        // passed directly into Arc::clone's expected type).
        let erased: Arc<dyn AuthOperations<D::User>> = auth.engine;
        return Self(erased);
    }
}
