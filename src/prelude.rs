//! Curated public API surface.

#[doc(inline)]
pub use crate::builder::AuthEngineBuilder;

#[doc(inline)]
pub use crate::engine::{AuthEngine, LoginOptions};

#[doc(inline)]
pub use crate::error::{AuthError, AuthResult};

#[doc(inline)]
pub use crate::hash::Argon2Hasher;

#[doc(inline)]
pub use crate::rate_limit::{InMemoryRateLimiter, RateLimiter};

#[doc(inline)]
pub use crate::security::{CookieConfig, OriginValidation, PasswordHasher, SameSite};

#[doc(inline)]
pub use crate::session::Session;

#[doc(inline)]
pub use crate::status::{AuthStatus, SessionId};

#[doc(inline)]
pub use crate::store::{MemoryStore, PasswordUserStore, SessionStore, UserStore};

#[doc(inline)]
pub use crate::transport::{
    extract_session_token, MemoryTokenStorage, TokenStorage,
};

#[doc(inline)]
pub use crate::user::AuthUser;

#[cfg(feature = "dioxus")]
#[doc(inline)]
pub use crate::dioxus::*;