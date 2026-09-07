use std::fmt;

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

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
/// # Requirements
///
/// - `wasm32` target with browser `BroadcastChannel` support.
/// - `User` must implement [`Serialize`] and [`DeserializeOwned`] so the
///   authenticated user can be sent across tabs.
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
    #[props(default)] channel_name: Option<String>,
) -> Element {
    let channel_name = channel_name.unwrap_or_else(|| "dioxus-auth-sync".to_string());
    let mut auth = use_auth::<User>();

    use_effect(move || {
        let window = match web_sys::window() {
            Some(w) => w,
            None => return,
        };
        let channel = match window.broadcast_channel(&channel_name) {
            Ok(c) => c,
            Err(_) => return,
        };

        let auth_signal = auth.signal();
        let on_message = {
            let auth_signal = auth_signal.clone();
            move |event: web_sys::MessageEvent| {
                let data = match event.data().dyn_into::<js_sys::JsString>() {
                    Ok(s) => match s.into_string() {
                        Ok(t) => t,
                        Err(_) => return,
                    },
                    Err(_) => return,
                };
                let msg: CrossTabMessage<User> = match serde_json::from_str(&data) {
                    Ok(m) => m,
                    Err(_) => return,
                };
                match msg {
                    CrossTabMessage::Login { user } => {
                        auth_signal.set(AuthStatus::Authenticated(user));
                    }
                    CrossTabMessage::Logout => {
                        auth_signal.set(AuthStatus::Unauthenticated);
                    }
                }
            }
        };

        let on_message_handle = on_message.clone();
        let closure = web_sys::Closure::wrap(Box::new(on_message_handle)
            as Box<dyn Fn(web_sys::MessageEvent)>);
        let _ = channel.set_onmessage(Some(closure.as_ref().unchecked_ref()));
        closure.forget();

        move || {
            let _ = channel.close();
        }
    });

    rsx! {}
}
