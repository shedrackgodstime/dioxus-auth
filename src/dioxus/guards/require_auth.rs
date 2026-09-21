//! Authentication gate: renders children only while authenticated.

use std::fmt;
use std::marker::PhantomData;

use ::dioxus::prelude::{Element, Props, use_signal};
use ::dioxus_router::use_navigator;

use crate::dioxus::hooks::use_auth;
use crate::user::AuthUser;

use super::{GuardRedirect, children_agree, guard_body, no_redirect_issued};

/// Props for [`RequireAuth`].
///
/// Fields are public because the Dioxus `Props` derive requires it. `Debug`
/// is redacted: rendering children would dump the subtree on every diff log.
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

impl<T: AuthUser + Clone> fmt::Debug for RequireAuthProps<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return f.write_str("RequireAuthProps(..)");
    }
}

impl<T: AuthUser + Clone> PartialEq for RequireAuthProps<T> {
    fn eq(&self, other: &Self) -> bool {
        // reason: the generic marker carries no rendered state, so equality
        // only compares the redirect target and children.
        return self.redirect_to == other.redirect_to
            && children_agree(&self.children, &other.children);
    }
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
    return guard_body(
        auth.is_authenticated(),
        props.children,
        GuardRedirect {
            to: props.redirect_to,
            issued: redirected,
            navigator,
        },
    );
}
