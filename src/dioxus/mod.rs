//! Dioxus runtime integration: auth context/hooks, route guards, cross-tab
//! sync, and server-function/axum extraction helpers.
//!
//! Organized by role, following the dioxus-router convention:
//! - [`hooks`] — `use_*` reactive surfaces (one file per hook)
//! - `components` — declarative components (`RouteGate`, `SignedIn`, `SignedOut`)
//! - `context` — the [`Auth`] handle (reactive state wrapper)
//! - `guards` — pure guard logic (outcomes, predicates)
//! - `provider` — [`AuthProvider`] tree setup

mod components;
mod context;
#[cfg(feature = "dioxus-fullstack")]
mod fullstack;
mod guards;
pub mod helpers;
pub mod hooks;
mod provider;
#[cfg(feature = "dioxus-fullstack")]
mod registry;
pub mod restore;
mod return_to;
mod server_fn;

#[cfg(target_arch = "wasm32")]
mod sync;

#[cfg(feature = "axum")]
mod axum;

#[cfg(feature = "axum")]
pub use axum::{
    AuthenticatedUser, RequireAuthUser, auth_middleware, permission_middleware,
    require_auth_middleware,
};
pub use components::{RouteGate, SignedIn, SignedOut};
pub use context::Auth;
pub use guards::{
    GuardOutcome, RedirectIfAuthed, RequireAuth, RouteGuard, redirect_if_authed, require_auth,
};
pub use helpers::{clear_persisted_token, persist_token};
pub use hooks::{try_use_auth, use_auth, use_auth_restore, use_token_storage};
pub use provider::{AuthProvider, TokenStorageRef};
#[cfg(feature = "dioxus-fullstack")]
pub use registry::{current_user, logout_current, require_user, server_init};
pub use restore::{RestoreClassify, RestoreVerdict};
pub use return_to::{
    AUTH_INTENT_KEY, capture_return_to, clear_return_to, consume_return_to, is_safe_return_to,
};
pub use server_fn::ServerAuthContext;

#[cfg(target_arch = "wasm32")]
pub use sync::CrossTabSync;
