//! Route guards: component-level redirection driven by auth state.

mod redirect_if_authed;
mod require_auth;

pub use redirect_if_authed::{RedirectIfAuthed, RedirectIfAuthedProps};
pub use require_auth::{RequireAuth, RequireAuthProps};

use ::dioxus::prelude::{Element, Signal, rsx};
use ::dioxus_router::Navigator;
use ::dioxus_signals::{ReadableExt, WritableExt};

/// The initial redirect flag for a guard: no redirect has been issued yet.
const fn initial_redirect_state() -> bool {
    return false;
}

/// Navigation state for a guard redirect.
pub struct GuardRedirect {
    /// Where to navigate when the rendered subtree is not at home.
    pub to: String,
    /// Whether a redirect was already issued for the current period.
    pub issued: Signal<bool>,
    /// Router navigator used to issue the redirect.
    pub navigator: Navigator,
}

/// Shared redirect-or-render body for the route guards.
///
/// `at_home` is true when the current state matches the rendered subtree:
/// authenticated for [`RequireAuth`], guest for [`RedirectIfAuthed`].
///
/// The returned [`Element`](::dioxus::prelude::Element) is itself `#[must_use]`,
/// so call sites cannot silently drop the rendered subtree.
pub fn guard_body(at_home: bool, children: Element, redirect: GuardRedirect) -> Element {
    if at_home {
        let mut issued = redirect.issued;
        *issued.write() = false;
        return rsx! {
            {children}
        };
    }

    if !*redirect.issued.read() {
        let mut issued = redirect.issued;
        *issued.write() = true;
        if redirect.navigator.push(redirect.to).is_some() {
            // reason: `push` reports `Some` only for external targets the
            // router cannot open. Unlatch so a later render retries instead of
            // sitting blank forever with the redirect marked done.
            *issued.write() = false;
        }
    }

    return rsx!();
}
