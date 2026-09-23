//! Test components and routes for the runtime suites.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::rc::Rc;

use dioxus::prelude::{Callback, Element, Props, VNode, rsx};
use dioxus_auth::prelude::{AuthProvider, RedirectIfAuthed, RequireAuth, use_auth};
use dioxus_history::History;
use dioxus_router::{
    Routable,
    components::{HistoryProvider, Router},
};

use super::common::TestUser;
use super::harness::{CONTEXT_SLOT, PROBE_MOUNTED, SeededStore};

/// Probes the provided auth context into the context slot and records its
/// mount.
#[derive(Clone, PartialEq, Props)]
struct ProbeProps {
    #[props(default)]
    marker: u8,
}

// reason: Dioxus components are PascalCase fns by framework convention.
#[expect(non_snake_case)]
fn Probe(_: ProbeProps) -> Element {
    let auth = use_auth::<TestUser>();
    CONTEXT_SLOT.with(|slot| *slot.borrow_mut() = Some(auth));
    PROBE_MOUNTED.with(|flag| {
        flag.set(true);
    });
    return rsx! {
        "probe"
    };
}

/// Captures the provided auth context regardless of the auth state, so tests
/// can drive the context while the gated probe is absent.
#[derive(Clone, PartialEq, Props)]
struct ContextCaptureProps {
    #[props(default)]
    marker: u8,
}

// reason: Dioxus components are PascalCase fns by framework convention.
#[expect(non_snake_case)]
fn ContextCapture(_: ContextCaptureProps) -> Element {
    let auth = use_auth::<TestUser>();
    CONTEXT_SLOT.with(|slot| *slot.borrow_mut() = Some(auth));
    return rsx! {
        "captured"
    };
}

/// The routes exercised by the guard tests.
#[derive(Clone, Routable, PartialEq)]
enum Route {
    #[route("/")]
    Home {},
    #[route("/login")]
    Login {},
}

#[derive(Clone, PartialEq, Props)]
struct HomeProps {
    #[props(default)]
    marker: u8,
}

// reason: Dioxus components are PascalCase fns by framework convention.
#[expect(non_snake_case)]
fn Home(_: HomeProps) -> Element {
    return rsx! {
        RequireAuth::<TestUser> {
            redirect_to: "/login",
            Probe {}
        }
    };
}

#[derive(Clone, PartialEq, Props)]
struct LoginProps {
    #[props(default)]
    marker: u8,
}

// reason: Dioxus components are PascalCase fns by framework convention.
#[expect(non_snake_case)]
fn Login(_: LoginProps) -> Element {
    return rsx! {
        RedirectIfAuthed::<TestUser> {
            redirect_to: "/",
            "login form"
        }
    };
}

/// Root for the state-only tests: provider plus a probe, no router.
#[derive(Clone)]
pub struct StateRootProps {
    pub auth: dioxus_auth::prelude::Auth<SeededStore>,
}

// reason: Dioxus components are PascalCase fns by framework convention.
#[expect(non_snake_case)]
pub fn StateRoot(props: StateRootProps) -> Element {
    return rsx! {
        AuthProvider::<SeededStore> {
            auth: props.auth,
            Probe {}
        }
    };
}

/// Root for the guard tests: history, router, then the provider so route
/// components can consume both contexts.
#[derive(Clone)]
pub struct RouterRootProps {
    pub history: Rc<dyn History>,
    pub auth: dioxus_auth::prelude::Auth<SeededStore>,
}

// reason: Dioxus components are PascalCase fns by framework convention.
#[expect(non_snake_case)]
pub fn RouterRoot(props: RouterRootProps) -> Element {
    let history = props.history;
    let history_callback = Callback::new(move |()| {
        return history.clone();
    });
    return rsx! {
        HistoryProvider {
            history: history_callback,
            AuthProvider::<SeededStore> {
                auth: props.auth,
                ContextCapture {},
                Router::<Route> {}
            }
        }
    };
}
