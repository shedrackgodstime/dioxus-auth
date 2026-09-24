//! Server-function generation for cookie-driven auth endpoints.
//!
//! [`fullstack_server_fns!`] expands five Dioxus server functions (login,
//! logout, current session, attach, and change-password) that the
//! application registers with its router. All five are _cookie-only_:
//! the session token travels in an `HttpOnly` cookie, never in the
//! request body.
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

use std::fmt;

use dioxus_fullstack::ServerFnError;

use crate::dioxus::server::ServerError;
use crate::dioxus::server::error::auth_error_status;
use crate::error::AuthError;
use crate::status::REDACTED;

/// The wire input for the generated login server function.
///
/// `Debug` is **manual and redacted**: the wire input carries the plaintext
/// password, so a derived impl would render it into logs.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LoginRequest {
    /// The user identifier.
    pub identifier: String,
    /// The plaintext password.
    pub password: String,
}

impl fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return f
            .debug_struct("LoginRequest")
            .field("identifier", &self.identifier)
            .field("password", &REDACTED)
            .finish();
    }
}

/// The wire input for the generated attach server function.
///
/// `Debug` is **manual and redacted**: the wire input carries the plaintext
/// password, so a derived impl would render it into logs.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttachRequest {
    /// The new login identifier to bind to the calling session's subject.
    pub identifier: String,
    /// The plaintext password for the new credential.
    pub password: String,
}

impl fmt::Debug for AttachRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return f
            .debug_struct("AttachRequest")
            .field("identifier", &self.identifier)
            .field("password", &REDACTED)
            .finish();
    }
}

/// The wire input for the generated change-password server function.
///
/// `Debug` is **manual and redacted**: both password fields are plaintext
/// secrets, so a derived impl would render them into logs.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChangePasswordRequest {
    /// The login identifier whose credential rotates.
    pub identifier: String,
    /// The current plaintext password (proof of knowledge).
    pub current_password: String,
    /// The replacement plaintext password.
    pub new_password: String,
}

impl fmt::Debug for ChangePasswordRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return f
            .debug_struct("ChangePasswordRequest")
            .field("identifier", &self.identifier)
            .field("current_password", &REDACTED)
            .field("new_password", &REDACTED)
            .finish();
    }
}

/// Generates the `dioxus_auth_login`, `dioxus_auth_logout`,
/// `dioxus_auth_session`, `dioxus_auth_attach`, and
/// `dioxus_auth_change_password` server functions for the given user type.
///
/// Endpoints default to `POST /api/auth/login`, `POST /api/auth/logout`,
/// `POST /api/auth/session`, `POST /api/auth/attach`, and
/// `POST /api/auth/change-password`; a three-path arm preserves the
/// original login/logout/session surface, and a five-path arm configures
/// all five endpoints explicitly.
#[macro_export]
macro_rules! fullstack_server_fns {
    ($user:ty) => {
        $crate::fullstack_server_fns!(
            $user,
            "/api/auth/login",
            "/api/auth/logout",
            "/api/auth/session",
            "/api/auth/attach",
            "/api/auth/change-password"
        );
    };

    ($user:ty, $login:literal, $logout:literal, $session:literal) => {
        $crate::fullstack_server_fns!(
            $user,
            $login,
            $logout,
            $session,
            "/api/auth/attach",
            "/api/auth/change-password"
        );
    };

    ($user:ty, $login:literal, $logout:literal, $session:literal, $attach:literal, $change_password:literal) => {
        #[doc = concat!("Authenticates the user and sets the session cookie. `", $login, "`.")]
        #[::dioxus_fullstack::post($login)]
        // reason: generated fns keep the crate's explicit-return style, use `?`
        // for the fallible wire calls, and are async per the server-fn contract.
        #[expect(
            clippy::needless_return,
            clippy::question_mark_used,
            clippy::unused_async
        )]
        #[must_use = "the authenticated user must be used"]
        pub async fn dioxus_auth_login(
            args: $crate::LoginRequest,
        ) -> ::dioxus_fullstack::ServerFnResult<$user> {
            let context = $crate::ServerAuthContext::<$user>::from_request().await?;
            let (user, token) = context.login(&args.identifier, &args.password).await?;
            $crate::write_session_cookie(context.config().cookie(), Some(token.as_str()))?;
            return Ok(user);
        }

        #[doc = concat!("Revokes the current session and clears the cookie. The clearing cookie is always emitted, so guest logout is idempotent. `", $logout, "`.")]
        #[::dioxus_fullstack::post($logout)]
        // reason: generated fns keep the crate's explicit-return style, use `?`
        // for the fallible wire calls, and are async per the server-fn contract.
        #[expect(
            clippy::needless_return,
            clippy::question_mark_used,
            clippy::unused_async
        )]
        #[must_use = "sign-out must be acknowledged"]
        pub async fn dioxus_auth_logout() -> ::dioxus_fullstack::ServerFnResult<()> {
            let context = $crate::ServerAuthContext::<$user>::from_request().await?;
            if let Some(token) = context.token() {
                context.logout(token).await?;
            }
            $crate::write_session_cookie(context.config().cookie(), None)?;
            return Ok(());
        }

        #[doc = concat!("Resolves the current session. `", $session, "`.")]
        #[::dioxus_fullstack::post($session)]
        // reason: generated fns keep the crate's explicit-return style, use `?`
        // for the fallible wire calls, and are async per the server-fn contract.
        #[expect(
            clippy::needless_return,
            clippy::question_mark_used,
            clippy::unused_async
        )]
        #[must_use = "the resolved user must be used"]
        pub async fn dioxus_auth_session() -> ::dioxus_fullstack::ServerFnResult<$user> {
            let user = $crate::require_user::<$user>().await?;
            return Ok(user);
        }

        #[doc = concat!("Attaches a credential to the calling session's subject. Privilege comes from the session cookie: only the session owner can extend their own logins. `", $attach, "`.")]
        #[::dioxus_fullstack::post($attach)]
        // reason: generated fns keep the crate's explicit-return style, use `?`
        // for the fallible wire calls, and are async per the server-fn contract.
        #[expect(
            clippy::needless_return,
            clippy::question_mark_used,
            clippy::unused_async
        )]
        #[must_use = "session credential attachment must be handled"]
        pub async fn dioxus_auth_attach(
            args: $crate::AttachRequest,
        ) -> ::dioxus_fullstack::ServerFnResult<()> {
            let context = $crate::ServerAuthContext::<$user>::from_request().await?;
            let token = match context.token() {
                Some(token) => token,
                None => return Err($crate::ServerError::MissingSession.into()),
            };
            context
                .attach_current(token, &args.identifier, &args.password)
                .await?;
            return Ok(());
        }

        #[doc = concat!("Changes a password after proving the current one. `", $change_password, "`.")]
        #[::dioxus_fullstack::post($change_password)]
        // reason: generated fns keep the crate's explicit-return style, use `?`
        // for the fallible wire calls, and are async per the server-fn contract.
        #[expect(
            clippy::needless_return,
            clippy::question_mark_used,
            clippy::unused_async
        )]
        #[must_use = "a failed password change must be handled"]
        pub async fn dioxus_auth_change_password(
            args: $crate::ChangePasswordRequest,
        ) -> ::dioxus_fullstack::ServerFnResult<()> {
            let context = $crate::ServerAuthContext::<$user>::from_request().await?;
            context
                .change_password(&args.identifier, &args.current_password, &args.new_password)
                .await?;
            return Ok(());
        }
    };
}

impl From<AuthError> for ServerFnError {
    fn from(error: AuthError) -> Self {
        let code = auth_error_status(&error);
        // reason: store and hasher internals (statement text, file paths) must
        // never reach clients; the stable code carries the whole signal, so
        // internal failures render a static message.
        let message = match &error {
            AuthError::Internal(_) => String::from("internal error"),
            _ => error.to_string(),
        };
        return Self::ServerError {
            message,
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
