//! Hooks for reading the auth context and the reactive session state.

use ::dioxus::prelude::use_context;

use crate::user::AuthUser;

use super::context::AuthContext;
use super::state::SessionState;

/// Reads the [`AuthContext`] provided by an ancestor
/// [`AuthProvider`](crate::dioxus::AuthProvider).
///
/// # Panics
/// Panics when no enclosing [`AuthProvider`](crate::dioxus::AuthProvider) has
/// been mounted above the calling component.
#[must_use]
pub fn use_auth<T: AuthUser + Clone>() -> AuthContext<T> {
    return use_context::<AuthContext<T>>();
}

/// Reads the reactive session state as an exhaustive
/// [`SessionState<T>`](crate::prelude::SessionState).
///
/// The read half of the runtime: [`SessionState::SignedIn`] renders the
/// identity, [`SessionState::Guest`] renders signed-out UI,
/// [`SessionState::Pending`] means the restore question is still open, and
/// [`SessionState::Unavailable`] means it could not be asked — call
/// [`AuthContext::refetch`] to retry. For the verb half (login, logout,
/// validate) use [`use_auth`](crate::prelude::use_auth).
///
/// # Panics
/// Panics when no enclosing [`AuthProvider`](crate::dioxus::AuthProvider) has
/// been mounted above the calling component.
#[must_use]
pub fn use_session<T: AuthUser + Clone>() -> SessionState<T> {
    return use_context::<AuthContext<T>>().session_state();
}
