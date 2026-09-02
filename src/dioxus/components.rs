use std::marker::PhantomData;

use dioxus::prelude::*;

use crate::dioxus::context::use_auth;

/// Props for [`SignedIn`] and [`SignedOut`] components.
#[derive(Props, Clone, PartialEq)]
pub struct AuthStateProps<User: PartialEq + 'static> {
    pub children: Element,
    #[props(default)]
    _marker: PhantomData<User>,
}

/// Convenience component that only renders its children if an authenticated user session is active.
#[component]
pub fn SignedIn<User: Clone + PartialEq + 'static>(props: AuthStateProps<User>) -> Element {
    let auth = use_auth::<User>();
    if auth.is_authenticated() {
        rsx! { {props.children} }
    } else {
        rsx! {}
    }
}

/// Convenience component that only renders its children if the user is explicitly unauthenticated.
#[component]
pub fn SignedOut<User: Clone + PartialEq + 'static>(props: AuthStateProps<User>) -> Element {
    let auth = use_auth::<User>();
    if auth.is_unauthenticated() {
        rsx! { {props.children} }
    } else {
        rsx! {}
    }
}
