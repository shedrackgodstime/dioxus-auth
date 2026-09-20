//! Reactive authentication context shared through the component tree.

use std::sync::Arc;

use ::dioxus::prelude::Signal;
use ::dioxus_signals::{ReadableExt, WritableExt};

use crate::error::AuthError;
use crate::status::{AuthStatus, SessionId};
use crate::user::AuthUser;

use super::operations::{AuthEngineHandle, AuthOperations};
use super::storage::TokenStorageHandle;

/// Reactive authentication state for the subtree under an
/// [`AuthProvider`](crate::dioxus::AuthProvider).
///
/// Clone is cheap: the engine and storage handles are `Arc`-shared and the
/// signals are copyable handles. Components read it through
/// [`use_auth`](crate::prelude::use_auth) and call the state methods directly.
#[derive(Clone)]
pub struct AuthContext<T: AuthUser + Clone> {
    engine: Arc<dyn AuthOperations<T>>,
    storage: TokenStorageHandle,
    status: Signal<AuthStatus<T>>,
    token: Signal<Option<SessionId>>,
    token_persisted: Signal<bool>,
}

impl<T: AuthUser + Clone> AuthContext<T> {
    /// Constructs a context. Only the provider builds one.
    pub(crate) fn new(
        engine: AuthEngineHandle<T>,
        storage: TokenStorageHandle,
        status: Signal<AuthStatus<T>>,
        token: Signal<Option<SessionId>>,
        token_persisted: Signal<bool>,
    ) -> Self {
        return Self {
            engine: engine.0,
            storage,
            status,
            token,
            token_persisted,
        };
    }

    /// Current authentication status.
    #[must_use]
    pub fn status(&self) -> AuthStatus<T> {
        return self.status.read().clone();
    }

    /// The authenticated user, when authentication is settled.
    #[must_use]
    pub fn user(&self) -> Option<T> {
        return match &*self.status.read() {
            AuthStatus::Authenticated(user) => Some(user.clone()),
            _ => None,
        };
    }

    /// The current raw wire session token, when authenticated.
    #[must_use]
    pub fn token(&self) -> Option<SessionId> {
        return self.token.read().clone();
    }

    /// Whether the current token was written to storage.
    ///
    /// A login whose persistence failed still holds an in-memory session, but
    /// that session is lost on reload.
    #[must_use]
    pub fn token_persisted(&self) -> bool {
        return *self.token_persisted.read();
    }

    /// Whether the auth state is still being restored from storage.
    #[must_use]
    pub fn is_loading(&self) -> bool {
        return matches!(&*self.status.read(), AuthStatus::Loading);
    }

    /// Whether an authenticated user is present.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        return matches!(&*self.status.read(), AuthStatus::Authenticated(_));
    }

    /// Authenticates, records the token and signals the identity reactively.
    ///
    /// The session is persisted to the token storage; a persistence failure
    /// leaves the in-memory session in place and is surfaced through
    /// [`AuthContext::token_persisted`].
    ///
    /// # Errors
    /// Returns the engine error when credentials or rate limiting reject the
    /// login; the state is left untouched in that case.
    #[must_use = "the login result must be handled"]
    pub fn login(&self, identifier: &str, password: &str) -> Result<(), AuthError> {
        return match self.engine.login(identifier, password) {
            Ok((user, wire)) => {
                let persist = self.storage.store(wire.as_str());
                let mut token = self.token;
                let mut status = self.status;
                let mut persisted = self.token_persisted;
                *token.write() = Some(wire);
                *status.write() = AuthStatus::Authenticated(user);
                match persist {
                    Ok(()) => *persisted.write() = true,
                    Err(_) => *persisted.write() = false,
                }
                Ok(())
            }
            Err(e) => Err(e),
        };
    }

    /// Logs out: revokes the session, clears the stored token and shifts to
    /// guest state.
    ///
    /// # Errors
    /// Returns the first failure encountered while revoking the session or
    /// clearing the token storage; local state is cleared regardless.
    #[must_use = "the logout result must be handled"]
    pub fn logout(&self) -> Result<(), AuthError> {
        let wire = match self.token.read().clone() {
            Some(wire) => wire,
            None => return Ok(()),
        };
        let revoke_failure = self.engine.logout(&wire).err();
        let clear_failure = self.storage.clear().err();
        self.set_guest();
        return match (revoke_failure, clear_failure) {
            (Some(e), _) | (None, Some(e)) => Err(e),
            (None, None) => Ok(()),
        };
    }

    /// Re-validates the current session token against the engine.
    ///
    /// On success the status is refreshed to the resolved identity. A session
    /// the engine no longer accepts moves the context to guest state.
    ///
    /// # Errors
    /// Returns the engine error; the current state is left untouched.
    #[must_use = "the validation result must be handled"]
    pub fn validate(&self) -> Result<Option<T>, AuthError> {
        let wire = match self.token.read().clone() {
            Some(wire) => wire,
            None => return Ok(None),
        };
        return match self.engine.validate(&wire) {
            Ok(Some(user)) => {
                let mut status = self.status;
                *status.write() = AuthStatus::Authenticated(user.clone());
                Ok(Some(user))
            }
            Ok(None) => {
                self.set_guest();
                Ok(None)
            }
            Err(e) => Err(e),
        };
    }

    /// Restores state from the persisted token (used by the provider on mount).
    ///
    /// A stored token the engine rejects demotes the context to guest; the
    /// stale token is left in storage so third-party backends keep their own
    /// retry semantics.
    ///
    /// # Errors
    /// Returns a storage error when the token cannot be read; the context is
    /// demoted to guest so callers can treat failure as a fresh start.
    #[must_use = "the restore result must be handled"]
    pub fn restore(&self) -> Result<(), AuthError> {
        let stored = match self.storage.retrieve() {
            Ok(stored) => stored,
            Err(e) => {
                self.set_guest();
                return Err(e);
            }
        };
        return match stored {
            Some(raw) if SessionId::is_valid_wire_format(&raw) => {
                let wire = SessionId::new(raw);
                match self.engine.validate(&wire) {
                    Ok(Some(user)) => {
                        let mut token = self.token;
                        let mut status = self.status;
                        let mut persisted = self.token_persisted;
                        *token.write() = Some(wire);
                        *status.write() = AuthStatus::Authenticated(user);
                        *persisted.write() = true;
                        Ok(())
                    }
                    Ok(None) => {
                        self.set_guest();
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            _ => {
                self.set_guest();
                Ok(())
            }
        };
    }

    /// Demotes the context to guest state, used by the provider on restore
    /// failure so the tree always settles into a defined status.
    pub(crate) fn set_guest(&self) {
        let mut token = self.token;
        let mut status = self.status;
        let mut persisted = self.token_persisted;
        *token.write() = None;
        *status.write() = AuthStatus::Guest;
        *persisted.write() = false;
    }
}
