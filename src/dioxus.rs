//! Feature-gated Dioxus runtime layer.
//!
//! The runtime is generic over the application [`AuthUser`] type only; the
//! concrete user/session store generics are hidden behind the erased
//! [`AuthOperations`] interface so hooks and components never leak them.
//!
//! All public items here are re-exported through the crate's
//! [`prelude`](crate::prelude).

mod context;
mod guards;
mod hooks;
mod operations;
mod provider;
mod storage;

pub use context::AuthContext;
pub use guards::{RedirectIfAuthed, RedirectIfAuthedProps, RequireAuth, RequireAuthProps};
pub use hooks::use_auth;
pub use operations::{AuthEngineHandle, AuthOperations};
pub use provider::{AuthProvider, AuthProviderProps};
pub use storage::TokenStorageHandle;
