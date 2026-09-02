use dioxus::prelude::*;

use crate::dioxus::context::Auth;
use crate::session::AuthStatus;

/// Component that injects the reactive authentication context into the component tree.
#[component]
pub fn AuthProvider<User: Clone + PartialEq + 'static>(
    #[props(default)] initial_status: Option<AuthStatus<User>>,
    children: Element,
) -> Element {
    let status_signal = use_context_provider(|| Signal::new(initial_status.unwrap_or_default()));
    let auth = Auth::new(status_signal);
    provide_context(auth);

    rsx! {
        {children}
    }
}
