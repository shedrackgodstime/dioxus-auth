//! Authentication gate: renders children only while authenticated.

use std::marker::PhantomData;

use ::dioxus::prelude::{Element, Props, component, rsx, use_signal};
use ::dioxus_router::use_navigator;

use crate::dioxus::hooks::use_auth;
use crate::user::AuthUser;

use super::{GuardRedirect, guard_body, no_redirect_issued};

/// Gates a subtree behind authentication.
///
/// Renders `children` only while authenticated; otherwise pushes a single
/// redirect to `redirect_to` per guest period.
///
/// Requires a [`Router`](dioxus_router::Router) ancestor.
///
/// # Panics
/// Panics when no [`Router`](dioxus_router::Router) encloses this component or
/// no [`AuthProvider`](crate::dioxus::AuthProvider) provides the context.
#[component]
pub fn RequireAuth<T>(
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

    // During Loading the identity has not settled yet — render nothing and
    // issue no navigation. The provider gates its initial restore on the same
    // condition, so this branch is only taken before the first settle; once
    // the status becomes Authenticated or Guest the guard re-evaluates and
    // either renders children or issues at most one redirect.
    if auth.is_loading() {
        return rsx!();
    }

    return guard_body(
        auth.is_authenticated(),
        children,
        GuardRedirect {
            to: redirect_to,
            issued: redirected,
            navigator,
        },
    );
}
