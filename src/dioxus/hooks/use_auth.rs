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
/// Panics if called outside an [`crate::dioxus::AuthProvider`] tree. Use
/// [`try_use_auth`] for the non-panicking variant.
///
/// # Rules of hooks
/// Must be called unconditionally at the top level of a component (it is a
/// context hook, cached on first render). To use [`Auth`] inside an event
/// handler or `spawn`, capture the handle in the closure — it is `Copy`:
///
/// ```ignore
/// let auth = use_auth::<User>();
/// spawn(async move { auth.logout(); });
/// ```
#[doc(alias = "use_current_user")]
#[must_use]
#[track_caller]
pub fn use_auth<User: Clone + 'static>() -> Auth<User> {
    use_context::<Auth<User>>()
}

/// Try to consume the current [`Auth`] context, returning `None` outside an
/// [`crate::dioxus::AuthProvider`] tree.
///
/// Non-panicking variant of [`use_auth`] — useful for components that render
/// both under and outside the provider (embeds, test shells), or for probing
/// during SSR. Like [`use_auth`], it is a hook: call unconditionally at the
/// top level of a component; the value is captured once on first render.
#[doc(alias = "try_current_user")]
#[must_use]
#[track_caller]
pub fn try_use_auth<User: Clone + 'static>() -> Option<Auth<User>> {
    try_use_context::<Auth<User>>()
}
