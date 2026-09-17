//! The route-gating component that renders `Outlet`, fallback, or redirect.

use dioxus::prelude::*;

use crate::dioxus::guards::GuardOutcome;

/// Component that gates access to child routes based on a [`GuardOutcome`].
///
/// If allowed, renders `Outlet::<R> {}`.
/// If pending, renders the optional `fallback` element (or a default loading indicator).
/// If redirect, navigates to the target route using [`use_navigator`].
#[component]
pub fn RouteGate<R: Routable + Clone + PartialEq + 'static>(
    outcome: GuardOutcome<R>,
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
                nav.replace(target.clone());
            });
            rsx! {}
        }
    }
}
