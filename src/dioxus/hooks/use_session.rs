//! Hook for the reactive session state read.

use ::dioxus::prelude::use_context;

use crate::user::AuthUser;

use crate::dioxus::context::AuthContext;
use crate::dioxus::state::SessionState;

/// Reads the reactive session state as an exhaustive
/// [`SessionState<T>`](crate::SessionState).
///
/// The read half of the runtime: [`SessionState::SignedIn`] renders the
/// identity, [`SessionState::Guest`] renders signed-out UI,
/// [`SessionState::Pending`] means the restore question is still open, and
/// [`SessionState::Unavailable`] means it could not be asked — call
/// [`AuthContext::restart`](crate::dioxus::AuthContext::restart) to retry.
/// For the verb half (login, logout, validate) use
/// [`use_auth`](crate::use_auth).
///
/// Hook rules apply: call at the top level of a component (or another hook),
/// unconditionally and in the same order on every render.
///
/// # Examples
///
/// ```no_run
/// use dioxus::prelude::*;
/// use dioxus_auth::{SessionState, use_session};
///
/// # #[derive(Debug, Clone, PartialEq)]
/// # struct User { id: u64, name: String }
/// # impl dioxus_auth::AuthUser for User {
/// #     type Id = u64;
/// #     fn id(&self) -> u64 { return self.id; }
/// #     fn email(&self) -> &str { return &self.name; }
/// # }
/// # fn Greeting() -> Element {
/// let state = use_session::<User>();
/// match state {
///     SessionState::SignedIn(user) => rsx! { "Hello, {user.name}" },
///     SessionState::Guest => rsx! { "Sign in" },
///     SessionState::Pending => rsx! { "Loading..." },
///     SessionState::Unavailable(_code) => rsx! { "Retry" },
/// }
/// # }
/// ```
///
/// # Panics
/// Panics when no enclosing [`AuthProvider`](crate::dioxus::AuthProvider) has
/// been mounted above the calling component.
#[doc(alias = "session")]
#[doc(alias = "auth state")]
#[must_use]
pub fn use_session<T: AuthUser + Clone>() -> SessionState<T> {
    return use_context::<AuthContext<T>>().session_state();
}
