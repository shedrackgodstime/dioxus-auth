//! Server-function generation for cookie-driven auth endpoints.
//!
//! [`fullstack_server_fns!`] expands three Dioxus server functions — login,
//! logout, and current session — that the application registers with its
//! router. All three are _cookie-only_: the session token travels in an
//! `HttpOnly` cookie, never in the request body.
//!
//! # Prerequisites
//!
//! The invoking crate must:
//!
//! - depend on `dioxus-fullstack` with its `server` feature active on the
//!   server target,
//! - depend on `dioxus-server` (the generated handlers reference the
//!   `dioxus_server` crate directly), and
//! - declare a `server` feature, per dioxus-fullstack's own convention:
//!
//! ```toml
//! [dependencies]
//! dioxus-fullstack = { version = "0.7" }
//! dioxus-server = "0.7"
//!
//! [features]
//! server = []
//! ```
//!
//! and, before serving, configure the engine with
//! [`server_init`](super::registry::server_init) or an axum
//! [`AuthLayer`](super::axum::AuthLayer).

use dioxus_fullstack::ServerFnError;

use crate::dioxus::server::ServerError;
use crate::dioxus::server::server_fn::auth_error_status;
use crate::error::AuthError;

/// The wire input for the generated login server function.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LoginRequest {
    /// The user identifier.
    pub identifier: String,
    /// The plaintext password.
    pub password: String,
}

/// Generates the `dioxus_auth_login`, `dioxus_auth_logout`, and
/// `dioxus_auth_session` server functions for the given user type.
///
/// Endpoints default to `POST /api/auth/login`, `POST /api/auth/logout`, and
/// `POST /api/auth/session`; a second macro arm accepts the three endpoint
/// paths explicitly.
#[macro_export]
macro_rules! fullstack_server_fns {
    ($user:ty) => {
        $crate::fullstack_server_fns!(
            $user,
            "/api/auth/login",
            "/api/auth/logout",
            "/api/auth/session"
        );
    };

    ($user:ty, $login:literal, $logout:literal, $session:literal) => {
        #[doc = concat!("Authenticates the user and sets the session cookie. `", $login, "`.")]
        #[::dioxus_fullstack::post($login)]
        // reason: generated fns keep the crate's explicit-return style, use `?`
        // for the fallible wire calls, and are async per the server-fn contract.
        #[allow(
            clippy::needless_return,
            clippy::question_mark_used,
            clippy::unused_async
        )]
        #[must_use = "the authenticated user must be used"]
        pub async fn dioxus_auth_login(
            args: $crate::prelude::LoginRequest,
        ) -> $crate::prelude::ServerFnResult<$user> {
            let context = $crate::prelude::ServerAuthContext::<$user>::from_request().await?;
            let (user, token) = context.login(&args.identifier, &args.password).await?;
            $crate::prelude::write_session_cookie(context.config().cookie(), Some(token.as_str()))?;
            return Ok(user);
        }

        #[doc = concat!("Revokes the current session and clears the cookie. The clearing cookie is always emitted, so guest logout is idempotent. `", $logout, "`.")]
        #[::dioxus_fullstack::post($logout)]
        // reason: generated fns keep the crate's explicit-return style, use `?`
        // for the fallible wire calls, and are async per the server-fn contract.
        #[allow(
            clippy::needless_return,
            clippy::question_mark_used,
            clippy::unused_async
        )]
        #[must_use = "sign-out must be acknowledged"]
        pub async fn dioxus_auth_logout() -> $crate::prelude::ServerFnResult<()> {
            let context = $crate::prelude::ServerAuthContext::<$user>::from_request().await?;
            if let Some(token) = context.token().cloned() {
                context.logout(&token).await?;
            }
            $crate::prelude::write_session_cookie(context.config().cookie(), None)?;
            return Ok(());
        }

        #[doc = concat!("Resolves the current session. `", $session, "`.")]
        #[::dioxus_fullstack::post($session)]
        // reason: generated fns keep the crate's explicit-return style, use `?`
        // for the fallible wire calls, and are async per the server-fn contract.
        #[allow(
            clippy::needless_return,
            clippy::question_mark_used,
            clippy::unused_async
        )]
        #[must_use = "the resolved user must be used"]
        pub async fn dioxus_auth_session() -> $crate::prelude::ServerFnResult<$user> {
            let user = $crate::prelude::require_user::<$user>().await?;
            return Ok(user);
        }
    };
}

impl From<AuthError> for ServerFnError {
    fn from(error: AuthError) -> Self {
        let code = auth_error_status(&error);
        return Self::ServerError {
            message: error.to_string(),
            code,
            details: None,
        };
    }
}

impl From<ServerError> for ServerFnError {
    fn from(error: ServerError) -> Self {
        return Self::ServerError {
            code: error.status_code(),
            message: error.to_string(),
            details: None,
        };
    }
}
