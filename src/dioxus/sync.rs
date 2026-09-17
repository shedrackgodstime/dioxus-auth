use core::marker::PhantomData;

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[cfg(target_family = "wasm")]
use wasm_bindgen::JsCast;

use crate::session::AuthStatus;
use crate::use_auth;

/// Messages broadcast across tabs for cross-tab auth synchronization.
#[derive(Serialize, Deserialize, Clone)]
pub enum CrossTabMessage<User> {
    /// Another tab authenticated `user`.
    Login { user: User },
    /// Another tab cleared the session.
    Logout,
}

/// Cross-tab synchronization for authentication state.
///
/// Listens for auth changes in the current tab and broadcasts them to other
/// tabs via `BroadcastChannel`. Incoming broadcasts from other tabs update
/// the local [`Auth`] state.
///
/// Mount once near the app root (inside [`crate::AuthProvider`]); the
/// broadcast handler lives for the document's lifetime.
///
/// # Requirements
///
/// - `wasm32` target with browser `BroadcastChannel` support. On non-wasm
///   targets the component renders nothing (no-op).
/// - `User` must implement [`serde::Serialize`] and
///   [`serde::de::DeserializeOwned`] so the authenticated user can cross
///   tabs as JSON.
///
/// # Example
///
/// ```rust,ignore
/// rsx! {
///     AuthProvider::<AppUser> {
///         CrossTabSync::<AppUser> {}
///         Router::<Route> {}
///     }
/// }
/// ```
#[component]
pub fn CrossTabSync<User: Clone + Serialize + for<'de> Deserialize<'de> + 'static>(
    /// Override the BroadcastChannel name (default: `dioxus-auth-sync`).
    #[props(default)]
    channel_name: Option<String>,
    /// Type-level marker so the `User` parameter is carried by the generated
    /// props struct; callers never pass this.
    #[props(default)]
    _marker: PhantomData<fn() -> User>,
) -> Element {
    #[cfg(target_family = "wasm")]
    {
        let channel_name = channel_name.unwrap_or_else(|| "dioxus-auth-sync".to_string());
        let auth = use_auth::<User>();

        use_effect(move || {
            let Ok(channel) = web_sys::BroadcastChannel::new(&channel_name) else {
                return;
            };
            let auth_signal = auth.signal();

            let on_message = move |event: web_sys::MessageEvent| {
                let Some(text) = event.data().as_string() else {
                    return;
                };
                let Ok(msg) = serde_json::from_str::<CrossTabMessage<User>>(&text) else {
                    return;
                };
                // Signal handles are Copy: rebind mutably inside the Fn
                // closure (dioxus 0.7 closure-scoping convention) so `set`
                // has its `&mut` receiver without making the closure FnMut.
                let mut auth_signal = auth_signal;
                match msg {
                    CrossTabMessage::Login { user } => {
                        auth_signal.set(AuthStatus::Authenticated(user));
                    }
                    CrossTabMessage::Logout => {
                        auth_signal.set(AuthStatus::Unauthenticated);
                    }
                }
            };

            let listener = wasm_bindgen::closure::Closure::wrap(
                Box::new(on_message) as Box<dyn Fn(web_sys::MessageEvent)>
            );
            channel.set_onmessage(Some(listener.as_ref().unchecked_ref()));
            // The handler must outlive the effect that installed it, so the
            // channel keeps receiving for the document's lifetime.
            listener.forget();
        });
    }
    #[cfg(not(target_family = "wasm"))]
    {
        let _ = channel_name;
    }

    rsx! {}
}
