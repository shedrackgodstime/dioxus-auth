/// Generate ready-made `#[server]` authentication functions for a Dioxus fullstack app.
///
/// This macro expands to four common server functions that wrap [`ServerAuthContext`]:
///
/// - `login_server(identifier: String, password: String) -> Result<(User, String), ServerFnError>`
/// - `logout_server() -> Result<(), ServerFnError>`
/// - `get_current_user() -> Result<Option<User>, ServerFnError>`
/// - `require_user() -> Result<User, ServerFnError>`
///
/// The generated functions use [`ServerAuthContext::from_request`] internally, so they
/// must be called from within a `#[server]` function context. For unit tests or
/// non-request contexts, use [`ServerAuthContext::new`] directly.
///
/// # Requirements
///
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
        ) -> ::core::result::Result<($user, String), ServerFnError> {
            let ctx = $crate::dioxus::ServerAuthContext::from_request($engine, $cookie_config)
                .ok_or_else(|| ServerFnError::new("not in a request context"))?;
            ctx.login_and_set_cookie(&identifier, &password)
                .await
                .map_err(|e| ServerFnError::new(format!("login failed: {e}")))
        }

        #[server]
        pub async fn logout_server() -> ::core::result::Result<(), ServerFnError> {
            let ctx = $crate::dioxus::ServerAuthContext::from_request($engine, $cookie_config)
                .ok_or_else(|| ServerFnError::new("not in a request context"))?;
            if let Some(session_id) = ctx.session_id() {
                ctx.logout_and_clear_cookie(&session_id)
                    .await
                    .map_err(|e| ServerFnError::new(format!("logout failed: {e}")))?;
            }
            Ok(())
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
