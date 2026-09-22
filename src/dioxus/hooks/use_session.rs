//! Hook for the reactive session state read.

use ::dioxus::prelude::use_context;

use crate::user::AuthUser;

use crate::dioxus::context::AuthContext;
use crate::dioxus::state::SessionState;

/// Reads the reactive session state as an exhaustive
/// [`SessionState<T>`](crate::prelude::SessionState).
///
/// The read half of the runtime: [`SessionState::SignedIn`] renders the
/// identity, [`SessionState::Guest`] renders signed-out UI,
/// [`SessionState::Pending`] means the restore question is still open, and
/// [`SessionState::Unavailable`] means it could not be asked — call
/// [`AuthContext::refetch`](crate::dioxus::AuthContext::refetch) to retry.
/// For the verb half (login, logout, validate) use
/// [`use_auth`](crate::prelude::use_auth).
///
/// # Panics
/// Panics when no enclosing [`AuthProvider`](crate::dioxus::AuthProvider) has
/// been mounted above the calling component.
#[must_use]
pub fn use_session<T: AuthUser + Clone>() -> SessionState<T> {
    return use_context::<AuthContext<T>>().session_state();
}
