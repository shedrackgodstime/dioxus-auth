/// Generate ready-made `\[server\]` authentication functions for a Dioxus fullstack app.
///
/// This macro expands to four common server functions that wrap [`ServerAuthContext`]:
///
/// - `login_server(identifier: String, password: String) -> Result<User, ServerFnError>`
/// - `logout_server() -> Result<(), ServerFnError>`
/// - `get_current_user() -> Result<Option<User>, ServerFnError>`
/// - `require_user() -> Result<User, ServerFnError>`
///
/// The generated `login_server` is **cookie-only** — it sets an `HttpOnly` session cookie
/// and returns the user. The raw token never reaches JavaScript. The generated
/// `logout_server` revokes the current session (cookie or bearer) and clears the cookie
/// if a cookie session was active.
///
/// The generated functions use [`crate::dioxus::ServerAuthContext::from_request`] internally when the
/// `dioxus-fullstack` feature is enabled, so they must be called from within a `\[server\]` function
/// context. For unit tests or non-request contexts, use [`crate::dioxus::ServerAuthContext::new`] directly.
///
/// # Requirements
/// - The `dioxus-fullstack` feature must be enabled.
/// - `User` must implement [`crate::user::AuthUser`] and be `Serialize + Deserialize + 'static`.
/// - `$engine` and `$cookie_config` must be expressions that evaluate to `&AuthEngine` and `&CookieConfig`.
///   Typically these are references into a `LazyLock` static.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::{Arc, LazyLock};
/// use dioxus_auth::{fullstack_server_fns, AuthEngine, CookieConfig, MemoryStore};
///
/// static SERVER_STATE: LazyLock<(Arc<MemoryStore<AppUser>>, AuthEngine<MemoryStore<AppUser>, MemoryStore<AppUser>>, CookieConfig)> =
///     LazyLock::new(|| { /* ... */ });
///
/// fullstack_server_fns! {
///     AppUser,
///     &SERVER_STATE.1,
///     &SERVER_STATE.2
/// }
/// ```
#[macro_export]
macro_rules! fullstack_server_fns {
    ($user:ty, $engine:expr, $cookie_config:expr $(,)?) => {
        #[server]
        pub async fn login_server(
            identifier: String,
            password: String,
        ) -> ::core::result::Result<$user, ServerFnError> {
            let ctx = $crate::dioxus::ServerAuthContext::from_request($engine, $cookie_config)
                .ok_or_else(|| ServerFnError::new("not in a request context"))?;
            ctx.login_cookie(&identifier, &password)
                .await
                .map_err(|e| ServerFnError::new(format!("login failed: {e}")))
        }

        #[server]
        pub async fn logout_server() -> ::core::result::Result<(), ServerFnError> {
            let ctx = $crate::dioxus::ServerAuthContext::from_request($engine, $cookie_config)
                .ok_or_else(|| ServerFnError::new("not in a request context"))?;
            ctx.logout_current()
                .await
                .map_err(|e| ServerFnError::new(format!("logout failed: {e}")))
        }

        #[server]
        pub async fn get_current_user() -> ::core::result::Result<Option<$user>, ServerFnError> {
            let ctx = $crate::dioxus::ServerAuthContext::from_request($engine, $cookie_config)
                .ok_or_else(|| ServerFnError::new("not in a request context"))?;
            ctx.current_user_from_request()
                .await
                .map_err(|e| ServerFnError::new(format!("restore failed: {e}")))
        }

        #[server]
        pub async fn require_user() -> ::core::result::Result<$user, ServerFnError> {
            let ctx = $crate::dioxus::ServerAuthContext::from_request($engine, $cookie_config)
                .ok_or_else(|| ServerFnError::new("not in a request context"))?;
            ctx.require_user_from_request()
                .await
                .map_err(|e| ServerFnError::new(format!("unauthorized: {e}")))
        }
    };
}
