//! Consume the reactive authentication context.

use dioxus::prelude::*;

use crate::dioxus::context::Auth;

/// Consume the current [`Auth`] context from any component.
///
/// This is the heart of the client API — authentication state is reactive
/// global state: every component holding the handle re-renders on
/// [`Auth::set_user`] / [`Auth::logout`].
///
/// # Panics
/// Panics if called outside an [`crate::dioxus::AuthProvider`] tree.
pub fn use_auth<User: Clone + 'static>() -> Auth<User> {
    use_context::<Auth<User>>()
}
