mod components;
mod context;
mod fullstack;
mod guards;
mod provider;
mod server_fn;

#[cfg(feature = "axum")]
mod axum;

#[cfg(feature = "axum")]
pub use axum::{
    AuthenticatedUser, RequireAuthUser, auth_middleware, permission_middleware,
    require_auth_middleware,
};
pub use components::{SignedIn, SignedOut};
pub use context::{
    Auth, clear_persisted_token, persist_token, use_auth, use_auth_restore, use_token_storage,
};
pub use guards::{
    GuardOutcome, RedirectIfAuthed, RequireAuth, RouteGate, RouteGuard, redirect_if_authed,
    require_auth,
};
pub use provider::{AuthProvider, TokenStorageRef};
pub use server_fn::ServerAuthContext;
