//! Route guards: component-level redirection driven by auth state.

mod redirect_if_authed;
mod require_auth;

pub use redirect_if_authed::{RedirectIfAuthed, RedirectIfAuthedProps};
pub use require_auth::{RequireAuth, RequireAuthProps};

use ::dioxus::prelude::{Element, Signal, rsx};
use ::dioxus_router::Navigator;
use ::dioxus_signals::{ReadableExt, WritableExt};

/// The initial redirect flag for a guard: no redirect has been issued yet.
const fn no_redirect_issued() -> bool {
    return false;
}

/// Navigation state for a guard redirect.
pub struct GuardRedirect {
    pub to: String,
    pub issued: Signal<bool>,
    pub navigator: Navigator,
}

/// Shared redirect-or-render body for the route guards.
///
/// `at_home` is true when the current state matches the rendered subtree:
/// authenticated for [`RequireAuth`], guest for [`RedirectIfAuthed`].
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
        let _redirection_failure = redirect.navigator.push(redirect.to);
        // reason: an interior route target never yields an external-navigation
        // failure, so the Option only reports unsupported (external) targets
        // that are intentionally ignored here.
    }

    return rsx!();
}
