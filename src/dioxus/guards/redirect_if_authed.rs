//! Guest gate: renders children only while unauthenticated.

use std::fmt;
use std::marker::PhantomData;

use ::dioxus::prelude::{Element, Props, use_signal};
use ::dioxus_router::use_navigator;

use crate::dioxus::hooks::use_auth;
use crate::user::AuthUser;

use super::{GuardRedirect, children_agree, guard_body, no_redirect_issued};

/// Props for [`RedirectIfAuthed`].
///
/// Fields are public because the Dioxus `Props` derive requires it. `Debug`
/// is redacted: rendering children would dump the subtree on every diff log.
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

impl<T: AuthUser + Clone> fmt::Debug for RedirectIfAuthedProps<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return f.write_str("RedirectIfAuthedProps(..)");
    }
}

impl<T: AuthUser + Clone> PartialEq for RedirectIfAuthedProps<T> {
    fn eq(&self, other: &Self) -> bool {
        // reason: the generic marker carries no rendered state, so equality
        // only compares the redirect target and children.
        return self.redirect_to == other.redirect_to
            && children_agree(&self.children, &other.children);
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
// reason: dioxus components follow PascalCase naming, which the `non_snake_case`
// lint otherwise rejects.
// reason: see [`RequireAuth`](super::require_auth::RequireAuth) for the
// `missing_errors_doc` masking rationale.
#[allow(clippy::missing_errors_doc)]
pub fn RedirectIfAuthed<T>(props: RedirectIfAuthedProps<T>) -> Element
where
    T: AuthUser + Clone,
{
    let auth = use_auth::<T>();
    let navigator = use_navigator();
    let redirected = use_signal(no_redirect_issued);
    return guard_body(
        !auth.is_authenticated(),
        props.children,
        GuardRedirect {
            to: props.redirect_to,
            issued: redirected,
            navigator,
        },
    );
}
