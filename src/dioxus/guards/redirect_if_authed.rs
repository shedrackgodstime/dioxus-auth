//! Guest gate: renders children only while unauthenticated.

use std::marker::PhantomData;

use ::dioxus::prelude::{Element, Props, component, use_signal};
use ::dioxus_router::use_navigator;

use crate::dioxus::hooks::use_auth;
use crate::user::AuthUser;

use super::{GuardRedirect, guard_body, no_redirect_issued};

/// Renders `children` only while guest; otherwise pushes a single redirect to
/// `redirect_to` per authenticated period.
///
/// Typical use is a login page that bounces already-authenticated visitors.
///
/// Requires a [`Router`](dioxus_router::Router) ancestor.
///
/// # Panics
/// Panics when no [`Router`](dioxus_router::Router) encloses this component or
/// no [`AuthProvider`](crate::dioxus::AuthProvider) provides the context.
#[component]
pub fn RedirectIfAuthed<T>(
    redirect_to: String,
    children: Element,
    #[props(default)] generic: PhantomData<fn() -> T>,
) -> Element
where
    T: AuthUser + Clone,
{
    let auth = use_auth::<T>();
    let navigator = use_navigator();
    let redirected = use_signal(no_redirect_issued);
    return guard_body(
        !auth.is_authenticated(),
        children,
        GuardRedirect {
            to: redirect_to,
            issued: redirected,
            navigator,
        },
    );
}
