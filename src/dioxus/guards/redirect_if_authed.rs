//! Guest gate: renders children only while unauthenticated.

use std::marker::PhantomData;

use ::dioxus::prelude::{Element, Props, component, rsx, use_signal};
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
/// # Examples
///
/// ```no_run
/// use dioxus::prelude::*;
/// use dioxus_auth::prelude::RedirectIfAuthed;
///
/// # fn LoginForm() -> Element { rsx! { "login form" } }
/// # fn App() -> Element {
/// rsx! {
///     RedirectIfAuthed::<User> { redirect_to: "/",
///         LoginForm {}
///     }
/// }
/// # }
/// # #[derive(Debug, Clone, PartialEq)]
/// # struct User;
/// # impl dioxus_auth::prelude::AuthUser for User {
/// #     type Id = u64;
/// #     fn id(&self) -> u64 { return 1; }
/// #     fn email(&self) -> &str { return "user@example.com"; }
/// # }
/// ```
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

    // Mirrors `RequireAuth`: during Loading the identity has not settled yet,
    // so rendering the guest subtree would flash the login form before restore
    // answers. Render nothing and issue no navigation until the first settle.
    if auth.is_loading() {
        return rsx!();
    }

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
