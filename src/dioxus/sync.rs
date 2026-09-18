use core::marker::PhantomData;

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[cfg(target_family = "wasm")]
use wasm_bindgen::JsCast;

// Host builds: the component body is cfg'd out, so these would be unused —
// but each is consumed by exactly one of the two cfg branches below.
#[cfg(target_family = "wasm")]
use crate::session::AuthStatus;
#[cfg(target_family = "wasm")]
use crate::use_auth;

/// Messages broadcast across tabs for cross-tab auth synchronization.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum CrossTabMessage<User> {
    /// Another tab authenticated `user`.
    Login {
        /// The authenticated user, serialized as JSON on the wire.
        user: User,
    },
    /// Another tab cleared the session.
    Logout,
}

/// Default `BroadcastChannel` name used by [`CrossTabSync`] and
/// [`use_auth_broadcaster`].
pub const DEFAULT_CROSS_TAB_CHANNEL: &str = "dioxus-auth-sync";

/// The effective channel name mounted by [`CrossTabSync`], provided into
/// context so [`use_auth_broadcaster`] can emit on the same channel even when
/// the receiver was mounted with a custom `channel_name`.
#[derive(Clone, PartialEq)]
struct SyncChannelName(String);

/// Broadcast auth changes from this tab to the others — the **emit half** of
/// [`CrossTabSync`], which only receives. Opt-in: nothing is emitted unless
/// your login/logout flows call it.
///
/// Each emit opens a short-lived `BroadcastChannel`, posts, and drops it
/// (auth events are rare — no long-lived channel to clean up).
/// `BroadcastChannel` does not echo to the sender, so this never loops.
///
/// Channel parity is automatic: the hook reads the channel name
/// [`CrossTabSync`] provided (defaulting to [`DEFAULT_CROSS_TAB_CHANNEL`]).
/// Emitting with no receiver mounted elsewhere is harmless — nobody listens.
///
/// # Example
///
/// ```rust,ignore
/// let mut auth = use_auth::<AppUser>();
/// let broadcaster = use_auth_broadcaster::<AppUser>();
///
/// let sign_in = move |_| {
///     spawn(async move {
///         if let Ok(user) = login_server(email(), password()).await {
///             auth.set_user(user.clone());
///             broadcaster.login(&user); // other tabs sign in too
///         }
///     });
/// };
/// ```
#[must_use]
pub fn use_auth_broadcaster<User: Serialize + 'static>() -> AuthBroadcaster<User> {
    let channel = try_use_context::<SyncChannelName>()
        .map(|s| s.0)
        .unwrap_or_else(|| DEFAULT_CROSS_TAB_CHANNEL.to_string());
    AuthBroadcaster {
        channel,
        _marker: PhantomData,
    }
}

/// Cheap handle for broadcasting auth changes to other tabs. See
/// [`use_auth_broadcaster`] for the hook that creates it.
#[derive(Clone, PartialEq)]
pub struct AuthBroadcaster<User> {
    channel: String,
    _marker: PhantomData<fn() -> User>,
}
impl<User: Serialize + 'static> AuthBroadcaster<User> {
    /// Serialize and post one message on the sync channel. Silently does
    /// nothing off-wasm and when the browser lacks `BroadcastChannel`.
    pub fn broadcast(&self, msg: &CrossTabMessage<User>) {
        self.post(msg);
    }

    /// The single serde/transport seam. Generic over the message *shape* so
    /// `login` can serialize a borrowed-user variant (`CrossTabMessage<&User>`
    /// wires identically to `CrossTabMessage<User>`) without requiring
    /// `User: Clone`.
    fn post<M: Serialize>(&self, msg: &M) {
        #[cfg(target_family = "wasm")]
        if let Ok(payload) = serde_json::to_string(msg) {
            if let Ok(channel) = web_sys::BroadcastChannel::new(&self.channel) {
                let _ = channel.post_message(&wasm_bindgen::JsValue::from_str(&payload));
            }
            // The channel is dropped here: posted messages survive the
            // sender's channel closing (per the BroadcastChannel spec).
        }
        #[cfg(not(target_family = "wasm"))]
        let _ = msg;
    }

    /// Tell other tabs that this tab authenticated `user`.
    pub fn login(&self, user: &User) {
        self.post(&CrossTabMessage::Login { user });
    }

    /// Tell other tabs that this tab cleared the session.
    pub fn logout(&self) {
        self.post(&CrossTabMessage::<User>::Logout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire format is a cross-app contract: apps may emit/receive raw
    /// strings (utmelab's emit half hand-builds `{"Login":{"user":…}}` and
    /// `"Logout"` with `json!`). Pin the exact bytes so receiver/emit can
    /// never drift apart.
    #[test]
    fn wire_format_matches_the_documented_shapes() {
        let user = serde_json::json!({ "id": 7, "name": "Grace" });
        let login = CrossTabMessage::Login { user: user.clone() };
        assert_eq!(
            serde_json::to_string(&login).unwrap(),
            r#"{"Login":{"user":{"id":7,"name":"Grace"}}}"#
        );
        assert_eq!(
            serde_json::to_string(&CrossTabMessage::<serde_json::Value>::Logout).unwrap(),
            "\"Logout\""
        );

        // And the receiver parses those same bytes back (round-trip).
        let parsed: CrossTabMessage<serde_json::Value> =
            serde_json::from_str(r#"{"Login":{"user":{"id":7,"name":"Grace"}}}"#).unwrap();
        assert_eq!(
            parsed,
            CrossTabMessage::Login {
                user: serde_json::json!({ "id": 7, "name": "Grace" })
            }
        );
        let parsed: CrossTabMessage<serde_json::Value> =
            serde_json::from_str("\"Logout\"").unwrap();
        assert_eq!(parsed, CrossTabMessage::Logout);
    }

    /// Off-wasm, every emit path is a silent no-op — this only asserts it
    /// compiles and does not panic on host targets.
    #[test]
    fn broadcaster_is_a_noop_off_wasm() {
        let broadcaster = AuthBroadcaster::<serde_json::Value> {
            channel: DEFAULT_CROSS_TAB_CHANNEL.to_string(),
            _marker: PhantomData,
        };
        broadcaster.login(&serde_json::json!({ "id": 1 }));
        broadcaster.logout();
        broadcaster.broadcast(&CrossTabMessage::Logout);
    }
}

/// Cross-tab synchronization for authentication state — the **receive half**:
/// listens for auth broadcasts from other tabs and applies them to the local
/// [`Auth`] state. Pair with [`use_auth_broadcaster`] to emit; the two
/// halves share a channel (default: [`DEFAULT_CROSS_TAB_CHANNEL`]).
///
/// Mount once near the app root (inside [`crate::AuthProvider`]); the
/// broadcast handler lives for the document's lifetime. On non-wasm targets
/// this component renders nothing (no-op).
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
        let channel_name = channel_name.unwrap_or_else(|| DEFAULT_CROSS_TAB_CHANNEL.to_string());
        let auth = use_auth::<User>();

        // Parity: publish the effective channel so use_auth_broadcaster in
        // any descendant emits on exactly this channel.
        use_context_provider(|| SyncChannelName(channel_name.clone()));

        use_effect(move || {
            let Ok(channel) = web_sys::BroadcastChannel::new(&channel_name) else {
                return;
            };
            let auth_signal = auth.signal();

            let on_message = move |event: web_sys::MessageEvent| {
                let Some(text) = event.data().as_string() else {
                    // Non-string payloads are not ours; ignoring is correct.
                    return;
                };
                let Ok(msg) = serde_json::from_str::<CrossTabMessage<User>>(&text) else {
                    // A string that isn't a valid CrossTabMessage usually means
                    // the tabs run different User serializations (deploy skew)
                    // — a silent drop here wastes hours, so surface it.
                    web_sys::console::warn_1(
                        &format!("dioxus-auth: dropped malformed cross-tab message: {text:.120}")
                            .into(),
                    );
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
            //
            // Leak note (deliberate): `forget()` intentionally never runs the
            // destructor — this component is a root-mounted singleton, the
            // closure is idle until the next message, and the channel is
            // garbage-collected with the document. Not a bug; do not "fix" it.
            listener.forget();
        });
    }
    #[cfg(not(target_family = "wasm"))]
    {
        let _ = channel_name;
    }

    rsx! {}
}
