//! Server-side integration for Dioxus fullstack applications.
//!
//! This module requires the `dioxus-fullstack` feature. It provides:
//!
//! - [`ServerAuthConfig`] and [`ServerAuthContext`]: request-scoped access to
//!   the authentication engine and the current session token.
//! - the [`fullstack_server_fns!`] macro: cookie-driven login, logout, and
//!   session server functions the application registers with its router.
//! - [`server_init`], [`current_user`], [`require_user`]: application-level
//!   server helpers and one-step guards.
//! - [`AuthLayer`] and [`RequireAuthLayer`]: axum middleware that
//!   make the engine available to every Dioxus fullstack request (SSR renders
//!   and server functions alike).
//!
//! The core [`AuthEngine`](crate::engine::AuthEngine) stays synchronous; the
//! server slice calls it directly inside async handlers. Long-running work
//! (Argon2 hashing) therefore occupies a runtime worker briefly — an async
//! store adapter remains a documented follow-up.

pub mod axum;
mod cookies;
pub mod fullstack;
pub mod registry;
pub mod server_fn;

pub use axum::{AuthLayer, AuthService, RequireAuthLayer, RequireAuthService};
pub use cookies::write_session_cookie;
pub use fullstack::LoginRequest;
pub use registry::{current_user, require_user, server_init};
pub use server_fn::{ServerAuthConfig, ServerAuthContext, ServerError};

pub use crate::fullstack_server_fns;
