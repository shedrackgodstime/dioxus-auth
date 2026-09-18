//! The route-gating component that renders `Outlet`, fallback, or redirect.

use dioxus::prelude::*;

use crate::dioxus::guards::GuardOutcome;
#[cfg(target_arch = "wasm32")]
use crate::dioxus::return_to::capture_return_to;

/// Component that gates access to child routes based on a [`GuardOutcome`].
///
/// If allowed, renders `Outlet::<R> {}`.
/// If pending, renders the optional `fallback` element (or a default loading indicator).
/// If redirect, navigates to the target route using [`use_navigator`].
///
/// With `preserve_intent` (the default), a redirect also **parks the current
/// URL** so the login page can land the user back on their original
/// destination via [`consume_return_to`](crate::consume_return_to) — spec 17
/// §3. Capture is browser-only (no-op on SSR/native) and open-redirect-safe.
#[component]
pub fn RouteGate<R: Routable + Clone + PartialEq + 'static>(
    outcome: GuardOutcome<R>,
    #[props(default = true)] preserve_intent: bool,
    #[props(default)] fallback: Option<Element>,
) -> Element {
    let nav = use_navigator();

    match outcome {
        GuardOutcome::Allow => rsx! {
            Outlet::<R> {}
        },
        GuardOutcome::Pending => {
            if let Some(fb) = fallback {
                rsx! { {fb} }
            } else {
                rsx! {
                    div { class: "dioxus-auth-pending", "Loading session..." }
                }
            }
        }
        GuardOutcome::Redirect(target) => {
            use_effect(move || {
                #[cfg(target_arch = "wasm32")]
                if preserve_intent {
                    // Park the full current URL (path + query + hash).
                    if let Some(loc) = web_sys::window().map(|w| w.location()) {
                        if let (Ok(path), Ok(search), Ok(hash)) =
                            (loc.pathname(), loc.search(), loc.hash())
                        {
                            capture_return_to(&format!("{path}{search}{hash}"));
                        }
                    }
                }
                let _ = preserve_intent;
                nav.replace(target.clone());
            });
            rsx! {}
        }
    }
}
