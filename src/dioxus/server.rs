//! Server-side integration for Dioxus fullstack applications.
//!
//! This module requires the `dioxus-fullstack` feature. It provides:
//!
//! - [`ServerAuthConfig`] and [`ServerAuthContext`]: request-scoped access to
//!   the authentication engine and the current session token.
//! - the [`fullstack_server_fns!`] macro: cookie-driven login, logout,
//!   session, attach, and change-password server functions the application
//!   registers with its router.
//! - [`server_init`], [`current_user`], [`require_user`]: application-level
//!   server helpers and one-step guards.
//! - [`AuthLayer`] and [`RequireAuthLayer`]: axum middleware that
//!   make the engine available to every Dioxus fullstack request (SSR renders
//!   and server functions alike).
//!
//! The core [`AuthEngine`](crate::engine::AuthEngine) stays synchronous; the
//! server slice dispatches engine calls to `tokio::task::spawn_blocking`
//! when a tokio runtime hosts the request (see the `blocking` module),
//! falling back to an inline call under other executors.

pub(crate) mod axum;
mod blocking;
mod cookies;
pub(crate) mod error;
pub(crate) mod fullstack;
pub(crate) mod registry;
pub(crate) mod server_fn;

pub use axum::{AuthLayer, AuthService, RequireAuthLayer, RequireAuthService};
pub use cookies::write_session_cookie;
pub use error::ServerError;
pub use fullstack::{AttachRequest, ChangePasswordRequest, LoginRequest};
pub use registry::{current_user, require_user, server_init};
pub use server_fn::{ServerAuthConfig, ServerAuthContext};

pub use crate::fullstack_server_fns;
