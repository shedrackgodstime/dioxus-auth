//! Feature-gated Dioxus runtime layer.
//!
//! The runtime is generic over the application [`AuthUser`] type only; the
//! concrete user/session store generics are hidden behind the erased
//! [`AuthOperations`] interface so hooks and components never leak them.
//!
//! Component conventions: Dioxus `Props` structs declare `pub` fields as the
//! `Props` derive requires, and components are declarative constructors
//! consumed by `rsx!` rather than `#[must_use]`-checked call sites.
//!
//! All public items here are re-exported through the crate's
//! [`prelude`](crate::prelude).

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
pub use hooks::{use_auth, use_session};
pub use operations::{AuthEngineHandle, AuthOperations};
pub use provider::{AuthProvider, AuthProviderProps};
pub use restore::{RestoreClassify, RestoreVerdict};
pub use state::SessionState;
pub use storage::TokenStorageHandle;

#[cfg(feature = "dioxus-fullstack")]
pub use server::{
    AuthLayer, AuthService, LoginRequest, RequireAuthLayer, RequireAuthService, ServerAuthConfig,
    ServerAuthContext, ServerError, current_user, fullstack_server_fns, require_user, server_init,
    write_session_cookie,
};

#[cfg(feature = "dioxus-fullstack")]
pub use dioxus_fullstack::{ServerFnError, ServerFnResult};
