//! Reactive authentication context shared through the component tree.

use std::fmt;
use std::sync::Arc;

use ::dioxus::prelude::Signal;
use ::dioxus_signals::{ReadableExt, WritableExt};

use crate::error::{AuthError, ErrorCode};
use crate::status::{AuthStatus, SessionId};
use crate::user::AuthUser;

use super::operations::{AuthEngineHandle, AuthOperations};
use super::restore::{RestoreClassify, RestoreVerdict};
use super::state::SessionState;
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
    restore_unavailable: Signal<Option<ErrorCode>>,
}

/// Reactive signals owned by an [`AuthContext`].
///
/// Bundles the four signals so [`AuthContext::new`] stays within the
/// parameter limit. The bundle is built once, by the provider, through
/// [`AuthSignals::new`].
pub struct AuthSignals<T: AuthUser + Clone> {
    /// Reactive authentication status.
    pub status: Signal<AuthStatus<T>>,
    /// Raw wire session token, when authenticated.
    pub token: Signal<Option<SessionId>>,
    /// Whether the current token was written to storage.
    pub token_persisted: Signal<bool>,
    /// Last unknown-class restore failure, if the session question is open.
    pub restore_unavailable: Signal<Option<ErrorCode>>,
}

impl<T: AuthUser + Clone> AuthSignals<T> {
    /// Bundles the provider's freshly-initialized signals into the single
    /// set the context is built from.
    pub const fn new(
        status: Signal<AuthStatus<T>>,
        token: Signal<Option<SessionId>>,
        token_persisted: Signal<bool>,
        restore_unavailable: Signal<Option<ErrorCode>>,
    ) -> Self {
        return Self {
            status,
            token,
            token_persisted,
            restore_unavailable,
        };
    }
}

impl<T: AuthUser + Clone> fmt::Debug for AuthContext<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return f.write_str("AuthContext(..)");
    }
}

impl<T: AuthUser + Clone> AuthContext<T> {
    /// Whether an authenticated user is present.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        return matches!(&*self.status.read(), AuthStatus::Authenticated(_));
    }

    /// Whether the auth state is still being restored from storage.
    #[must_use]
    pub fn is_loading(&self) -> bool {
        return matches!(&*self.status.read(), AuthStatus::Loading);
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

    /// Constructs a context. Only the provider builds one.
    pub(crate) fn new(
        engine: AuthEngineHandle<T>,
        storage: TokenStorageHandle,
        signals: &AuthSignals<T>,
    ) -> Self {
        return Self {
            engine: engine.0,
            storage,
            status: signals.status,
            token: signals.token,
            token_persisted: signals.token_persisted,
            restore_unavailable: signals.restore_unavailable,
        };
    }

    /// Restores state from the persisted token (used by the provider on mount).
    ///
    /// The outcome is classified (see [`RestoreVerdict`]):
    ///
    /// - [`RestoreVerdict::Restored`]: a stored token was accepted and the
    ///   context is authenticated.
    /// - [`RestoreVerdict::Unauthenticated`]: no usable token existed, or the
    ///   server definitively rejected the stored token — the context is a
    ///   guest. The rejected token is left in storage so third-party backends
    ///   keep their own retry semantics.
    /// - [`RestoreVerdict::Unknown`]: the attempt failed before the session
    ///   question could be answered (storage read failure, rate limiting,
    ///   transport errors surfacing as [`AuthError::Internal`]) — the context
    ///   is deliberately left in Loading so a network blip never silently
    ///   demotes a live session to guest. Callers may retry.
    #[must_use = "the restore verdict must be handled"]
    pub fn restore(&self) -> RestoreVerdict {
        let stored = match self.storage.retrieve() {
            Ok(stored) => stored,
            Err(e) => {
                // Storage failures do not answer the session question; leave
                // the context in Loading for a retry.
                self.record_unavailable(&e);
                return e.restore_verdict();
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
                        let mut unavailable = self.restore_unavailable;
                        *token.write() = Some(wire);
                        *status.write() = AuthStatus::Authenticated(user);
                        *persisted.write() = true;
                        *unavailable.write() = None;
                        RestoreVerdict::Restored
                    }
                    Ok(None) => {
                        self.set_guest();
                        RestoreVerdict::Unauthenticated
                    }
                    Err(e) => {
                        let verdict = e.restore_verdict();
                        if verdict == RestoreVerdict::Unauthenticated {
                            // A definitive rejection must also settle the
                            // context; unknown outcomes stay in Loading.
                            self.set_guest();
                        } else {
                            self.record_unavailable(&e);
                        }
                        verdict
                    }
                }
            }
            _ => {
                self.set_guest();
                RestoreVerdict::Unauthenticated
            }
        };
    }

    /// Re-runs the restore attempt after an
    /// [`SessionState::Unavailable`](crate::prelude::SessionState::Unavailable)
    /// read.
    ///
    /// This is the retry half of the semantics: an unknown outcome left
    /// the tree rendering and the session question open, so a component (or
    /// a timer) may ask again. A definitive rejection settles to guest here
    /// exactly as in [`AuthContext::restore`]. Dioxus vocabulary, so `restart`
    /// is the primary name.
    #[must_use = "the retry verdict must be handled"]
    pub fn restart(&self) -> RestoreVerdict {
        return self.restore();
    }

    /// Demotes the context to guest state, used by the provider on restore
    /// failure so the tree always settles into a defined status.
    pub(crate) fn set_guest(&self) {
        let mut token = self.token;
        let mut status = self.status;
        let mut persisted = self.token_persisted;
        let mut unavailable = self.restore_unavailable;
        *token.write() = None;
        *status.write() = AuthStatus::Guest;
        *persisted.write() = false;
        *unavailable.write() = None;
    }

    /// Records an unknown-class failure so the reactive read reports
    /// `Unavailable` instead of a bare `Pending` until the next settle.
    fn record_unavailable(&self, error: &AuthError) {
        let mut unavailable = self.restore_unavailable;
        *unavailable.write() = Some(error.code());
    }

    /// Current authentication status.
    #[must_use]
    pub fn status(&self) -> AuthStatus<T> {
        return self.status.read().clone();
    }

    /// The reactive session read: an exhaustive
    /// [`SessionState`](crate::prelude::SessionState) instead of a struct of
    /// optional fields.
    ///
    /// Branch on the variant; `Unavailable` carries the stable
    /// [`ErrorCode`](crate::prelude::ErrorCode) for logging and interop.
    /// Subscribes to the underlying signals, so components re-render when
    /// the state changes.
    #[must_use = "the session read must be used"]
    pub fn session_state(&self) -> SessionState<T> {
        return SessionState::from_parts(&self.status.read(), *self.restore_unavailable.read());
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

    /// The authenticated user, when authentication is settled.
    #[must_use]
    pub fn user(&self) -> Option<T> {
        return match &*self.status.read() {
            AuthStatus::Authenticated(user) => Some(user.clone()),
            _ => None,
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
}
