//! Hook for reading the auth context.

use ::dioxus::prelude::use_context;

use crate::user::AuthUser;

use super::context::AuthContext;

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
