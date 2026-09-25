//! Hook for reading the auth context.

use ::dioxus::prelude::use_context;

use crate::user::AuthUser;

use crate::dioxus::context::AuthContext;

/// Reads the [`AuthContext`] provided by an ancestor
/// [`AuthProvider`](crate::dioxus::AuthProvider).
///
/// Hook rules apply: call at the top level of a component (or another hook),
/// unconditionally and in the same order on every render.
///
/// # Examples
///
/// ```no_run
/// use dioxus::prelude::*;
/// use dioxus_auth::use_auth;
///
/// # #[derive(Debug, Clone, PartialEq)]
/// # struct User { id: u64, name: String }
/// # impl dioxus_auth::AuthUser for User {
/// #     type Id = u64;
/// #     fn id(&self) -> u64 { return self.id; }
/// # }
/// # fn Profile() -> Element {
/// let auth = use_auth::<User>();
/// let greeting = if auth.is_authenticated() { "welcome back" } else { "please sign in" };
/// rsx! { "{greeting}" }
/// # }
/// ```
///
/// # Panics
/// Panics when no enclosing [`AuthProvider`](crate::dioxus::AuthProvider) has
/// been mounted above the calling component.
#[doc(alias = "auth")]
#[must_use]
pub fn use_auth<T: AuthUser + Clone>() -> AuthContext<T> {
    return use_context::<AuthContext<T>>();
}
