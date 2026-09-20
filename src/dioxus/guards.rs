//! Route guards: component-level redirection driven by auth state.

use std::marker::PhantomData;

use ::dioxus::prelude::{Element, Props, rsx, use_signal};
use ::dioxus_router::use_navigator;
use ::dioxus_signals::{ReadableExt, WritableExt};

use crate::user::AuthUser;

use super::hooks::use_auth;

/// Props for [`RequireAuth`].
#[derive(Clone, Props)]
pub struct RequireAuthProps<T: AuthUser + Clone> {
    /// Route to navigate to while the context is not authenticated.
    pub redirect_to: String,
    /// Children rendered only while authenticated.
    pub children: Element,
    /// Type marker completing the generic; never set by callers.
    #[props(default)]
    pub generic: PhantomData<fn() -> T>,
}

impl<T: AuthUser + Clone> PartialEq for RequireAuthProps<T> {
    fn eq(&self, other: &Self) -> bool {
        let redirects_agree = self.redirect_to == other.redirect_to;
        let children_agree = self.children == other.children;
        return redirects_agree && children_agree;
    }
}

/// The initial redirect flag for a guard: no redirect has been issued yet.
const fn no_redirect_issued() -> bool {
    return false;
}

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
#[allow(non_snake_case)]
// reason: dioxus components follow PascalCase naming, which the `non_snake_case`
// lint otherwise rejects.
// reason: clippy's `missing_errors_doc` cannot apply to `Element`, which is not
// a `Result`; the attributes the lint inspects are only reachable through the
// component machinery, so it is masked here.
#[allow(clippy::missing_errors_doc)]
pub fn RequireAuth<T>(props: RequireAuthProps<T>) -> Element
where
    T: AuthUser + Clone,
{
    let auth = use_auth::<T>();
    let navigator = use_navigator();
    let redirected = use_signal(no_redirect_issued);

    if auth.is_authenticated() {
        let mut redirected = redirected;
        *redirected.write() = false;
        return rsx! {
            {props.children}
        };
    }

    if !*redirected.read() {
        let mut redirected = redirected;
        *redirected.write() = true;
        let _redirection_failure = navigator.push(props.redirect_to);
        // reason: an interior route target never yields an external-navigation
        // failure, so the Option only reports unsupported (external) targets
        // that are intentionally ignored here.
    }

    return rsx!();
}

/// Props for [`RedirectIfAuthed`].
#[derive(Clone, Props)]
pub struct RedirectIfAuthedProps<T: AuthUser + Clone> {
    /// Route to navigate to while authenticated.
    pub redirect_to: String,
    /// Children rendered only while not authenticated.
    pub children: Element,
    /// Type marker completing the generic; never set by callers.
    #[props(default)]
    pub generic: PhantomData<fn() -> T>,
}

impl<T: AuthUser + Clone> PartialEq for RedirectIfAuthedProps<T> {
    fn eq(&self, other: &Self) -> bool {
        let redirects_agree = self.redirect_to == other.redirect_to;
        let children_agree = self.children == other.children;
        return redirects_agree && children_agree;
    }
}

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
#[allow(non_snake_case)]
// reason: see [`RequireAuth`] for the `missing_errors_doc` masking rationale.
#[allow(clippy::missing_errors_doc)]
pub fn RedirectIfAuthed<T>(props: RedirectIfAuthedProps<T>) -> Element
where
    T: AuthUser + Clone,
{
    let auth = use_auth::<T>();
    let navigator = use_navigator();
    let redirected = use_signal(no_redirect_issued);

    if !auth.is_authenticated() {
        let mut redirected = redirected;
        *redirected.write() = false;
        return rsx! {
            {props.children}
        };
    }

    if !*redirected.read() {
        let mut redirected = redirected;
        *redirected.write() = true;
        let _redirection_failure = navigator.push(props.redirect_to);
        // reason: an interior route target never yields an external-navigation
        // failure, so the Option only reports unsupported (external) targets
        // that are intentionally ignored here.
    }

    return rsx!();
}
