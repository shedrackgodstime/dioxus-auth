//! Feature-gated Dioxus runtime layer.
//!
//! The runtime is generic over the application [`AuthUser`](crate::AuthUser)
//! type only; the concrete user/session store generics are hidden behind the
//! erased [`AuthOperations`] interface so hooks and components never leak them.
//!
//! Component conventions: Dioxus `Props` structs declare `pub` fields as the
//! `Props` derive requires, and components are declarative constructors
//! consumed by `rsx!` rather than `#[must_use]`-checked call sites.
//!
//! The documented import path for every public item here is the crate root
//! (`use dioxus_auth::{AuthProvider, use_session, …}`); this module stays
//! importable for custom setups that prefer layer paths.
//!
//! Dioxus-coupling note (re-audit on every Dioxus bump): this layer touches
//! only long-lived framework surface: `#[component]` + `Props`, `rsx!` +
//! `Element`, `use_context` / `use_context_provider`, `use_signal` +
//! `Readable` / `Writable` signal access, `use_effect` / `use_hook`, and on
//! the router side `Router`, `Navigator`, `use_navigator`. The engine behind
//! [`AuthOperations`] never names a Dioxus type, so a framework upgrade can
//! move components and hooks without touching authentication semantics. Do
//! not adopt alpha-only APIs (`ReadSignal` / `WriteSignal` split, `use_action`)
//! until the MSRV-bumped Dioxus upgrade plan says so.

mod context;
mod guards;
mod hooks;
mod operations;
mod provider;
mod restore;
mod state;
mod storage;

#[cfg(feature = "dioxus-fullstack")]
pub mod server;

pub use context::AuthContext;
pub use guards::{RedirectIfAuthed, RedirectIfAuthedProps, RequireAuth, RequireAuthProps};
pub use hooks::{AuthStateEvent, on_auth_state_change, use_auth, use_session};
pub use operations::{AuthEngineHandle, AuthOperations};
pub use provider::{AuthProvider, AuthProviderProps};
pub use restore::{RestoreClassify, RestoreVerdict};
pub use state::SessionState;
pub use storage::TokenStorageHandle;

#[cfg(feature = "dioxus-fullstack")]
pub use server::{
    AttachRequest, AuthLayer, AuthService, ChangePasswordRequest, LoginRequest, RequireAuthLayer,
    RequireAuthService, ServerAuthConfig, ServerAuthContext, ServerError, current_user,
    fullstack_server_fns, require_user, server_init, write_session_cookie,
};

#[cfg(feature = "dioxus-fullstack")]
pub use dioxus_fullstack::{ServerFnError, ServerFnResult};
