//! Type-erased engine operations and the prop handle that wraps them.

use std::fmt;
use std::sync::Arc;

use crate::auth::Auth;
use crate::engine::AuthEngine;
use crate::error::AuthError;
use crate::status::SessionId;
use crate::store::session::SessionStore;
use crate::store::user::{CredentialStore, SubjectStore, UserStore};
use crate::user::AuthUser;

/// Erased authorization operations used by the runtime layer.
///
/// The runtime is generic over the application user type only; the concrete
/// store generics are hidden behind this trait object so hooks and components
/// never leak store types.
///
/// The engine authenticates subjects; this layer resolves them to application
/// users through [`UserStore`]. Resolution failures close differently per
/// verb: login treats an unresolvable subject as bad credentials (fail
/// closed), while validation treats it as no session (definitive rejection
/// demotes to guest instead of erroring the tree). Store outages propagate
/// in both, so transient failures never demote.
///
/// Single-spelling rule: credential verification lives in exactly one place,
/// [`AuthEngine::login`](crate::engine::AuthEngine::login) and its helpers.
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

    /// Attaches a credential to the session owner's subject.
    ///
    /// Privilege comes from session possession: only the session owner can
    /// extend their own logins.
    ///
    /// # Errors
    /// Mirrors [`AuthEngine::attach_current`](crate::engine::AuthEngine::attach_current).
    #[must_use = "session credential attachment must be handled"]
    fn attach_current(
        &self,
        session_id: &SessionId,
        identifier: &str,
        password: &str,
    ) -> Result<(), AuthError>;

    /// Changes a password after proving the current one.
    ///
    /// # Errors
    /// Mirrors [`AuthEngine::change_password`](crate::engine::AuthEngine::change_password).
    #[must_use = "a failed password change must be handled"]
    fn change_password(
        &self,
        identifier: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), AuthError>;
}

impl<C, S> AuthOperations<C::User> for AuthEngine<C, S>
where
    C: CredentialStore + UserStore,
    S: SessionStore<AuthId = <C as SubjectStore>::AuthId>,
{
    fn login(&self, identifier: &str, password: &str) -> Result<(C::User, SessionId), AuthError> {
        let (subject, session) = match Self::login(self, identifier, password) {
            Ok((subject, session)) => (subject, session),
            Err(e) => return Err(e),
        };
        let user = match Self::resolve_user(self, &subject) {
            Ok(user) => user,
            Err(e) => return Err(e),
        };
        return Ok((user, session.id().clone()));
    }

    fn logout(&self, session_id: &SessionId) -> Result<(), AuthError> {
        return Self::logout(self, session_id);
    }

    fn attach_current(
        &self,
        session_id: &SessionId,
        identifier: &str,
        password: &str,
    ) -> Result<(), AuthError> {
        return Self::attach_current(self, session_id, identifier, password);
    }

    fn change_password(
        &self,
        identifier: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        return Self::change_password(self, identifier, current_password, new_password);
    }

    fn validate(&self, session_id: &SessionId) -> Result<Option<C::User>, AuthError> {
        let subject = match Self::validate_session(self, session_id) {
            Ok(subject) => subject,
            Err(e) => return Err(e),
        };
        let Some(subject) = subject else {
            return Ok(None);
        };
        let Some(app_ref) = subject.app_ref.as_ref() else {
            return Ok(None);
        };
        let user = match self.store.resolve(app_ref) {
            Ok(user) => user,
            Err(e) => return Err(e),
        };
        return Ok(user);
    }
}

impl<C, S> AuthEngine<C, S>
where
    C: CredentialStore + UserStore,
    S: SessionStore<AuthId = <C as SubjectStore>::AuthId>,
{
    /// Resolves an authenticated subject to its application user.
    ///
    /// Shared by the login path above; validation inlines its own variant
    /// because unresolvable subjects read as no-session there instead of an
    /// error. A subject without resolvable app data fails closed: callers
    /// must never receive a session paired with no user. Store outages
    /// propagate instead of masquerading as bad credentials.
    fn resolve_user(
        &self,
        subject: &crate::store::AuthSubject<C::AuthId, C::AppRef>,
    ) -> Result<C::User, AuthError> {
        let Some(app_ref) = subject.app_ref.as_ref() else {
            return Err(AuthError::InvalidCredentials);
        };
        let user = match self.store.resolve(app_ref) {
            Ok(Some(user)) => user,
            Ok(None) => return Err(AuthError::InvalidCredentials),
            Err(error) => return Err(error),
        };
        return Ok(user);
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

impl<C, S> From<Arc<AuthEngine<C, S>>> for AuthEngineHandle<C::User>
where
    C: CredentialStore + UserStore + 'static,
    S: SessionStore<AuthId = <C as SubjectStore>::AuthId> + 'static,
{
    fn from(engine: Arc<AuthEngine<C, S>>) -> Self {
        return Self(engine);
    }
}

/// Bridges the `Auth` facade to the engine handle that [`AuthProvider`](super::provider::AuthProvider) consumes.
///
/// Before this impl, a quickstart caller had to write
/// `AuthEngineHandle::from(Arc::clone(auth.engine()))`, naming three concepts
/// (`Arc`, `AuthEngineHandle`, erasure) that the beginner budget forbids.
/// `Auth::into()` keeps that bridge to a single word.
impl<D> From<Auth<D>> for AuthEngineHandle<D::User>
where
    D: CredentialStore + SessionStore<AuthId = <D as SubjectStore>::AuthId> + UserStore + 'static,
{
    fn from(auth: Auth<D>) -> Self {
        // Coerce the concrete engine Arc to the erased trait-object Arc,
        // then clone the erased handle (Arc<AuthEngine> does not coerce when
        // passed directly into Arc::clone's expected type).
        let erased: Arc<dyn AuthOperations<D::User>> = auth.engine;
        return Self(erased);
    }
}
