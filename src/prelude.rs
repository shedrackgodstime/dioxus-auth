//! Curated public API surface.
//!
//! This is the only public import path: `use dioxus_auth::prelude::*`.

#[doc(inline)]
pub use crate::builder::AuthEngineBuilder;

#[doc(inline)]
pub use crate::engine::{AuthEngine, LoginOptions};

#[doc(inline)]
pub use crate::error::AuthError;

#[doc(inline)]
pub use crate::hash::Argon2Hasher;

#[doc(inline)]
pub use crate::rate_limit::{InMemoryRateLimiter, RateLimiter, RateLimiterClock};

#[doc(inline)]
pub use crate::security::{CookieConfig, OriginValidation, PasswordHasher, SameSite};

#[doc(inline)]
pub use crate::session::Session;

#[doc(inline)]
pub use crate::status::{AuthStatus, SessionId};

#[doc(inline)]
pub use crate::store::{MemoryStore, PasswordUserStore, SessionStore, UserStore};

#[doc(inline)]
pub use crate::token::MemoryTokenStorage;

#[doc(inline)]
pub use crate::transport::TokenStorage;

#[doc(inline)]
pub use crate::user::AuthUser;

#[cfg(feature = "dioxus")]
#[doc(inline)]
pub use crate::dioxus::{
    AuthContext, AuthEngineHandle, AuthOperations, AuthProvider, AuthProviderProps,
    RedirectIfAuthed, RedirectIfAuthedProps, RequireAuth, RequireAuthProps, RestoreClassify,
    RestoreVerdict, TokenStorageHandle, use_auth,
};

#[cfg(feature = "dioxus-fullstack")]
#[doc(inline)]
pub use crate::dioxus::{
    AuthLayer, AuthService, LoginRequest, RequireAuthLayer, RequireAuthService, ServerAuthConfig,
    ServerAuthContext, ServerError, ServerFnError, ServerFnResult, current_user,
    fullstack_server_fns, require_user, server_init, write_session_cookie,
};
