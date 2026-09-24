//! dioxus-auth: authentication and session management for Dioxus.
//!
//! The crate is layered: the core engine has zero Dioxus dependency, and the
//! Dioxus runtime ships as a feature-gated layer (`dioxus`). Application
//! storage is pluggable through capability traits such as [`UserStore`].
//!
//! # Features
//!
//! | Feature | Enables |
//! |---|---|
//! | *(default)* | Core engine: sessions, email+password, stores, hashing, rate limiting |
//! | `dioxus` | Client runtime: `AuthProvider`, `use_session`, route guards |
//! | `dioxus-fullstack` | Server fns, cookie/origin policy, axum middleware |
//! | `server` | `dioxus-fullstack`'s server compile-phase gate |
//!
//! # Example
//!
//! ```
//! use dioxus_auth::{Auth, DefaultUserInput};
//!
//! # fn main() -> Result<(), dioxus_auth::AuthError> {
//! let auth = Auth::memory()?;
//!
//! let (user, session) =
//!     auth.sign_up_email("alice", "password", DefaultUserInput::new("alice"))?;
//! let (user, _session) = auth.sign_in_email("alice", "password")?;
//! assert_eq!(user.name, "alice");
//! auth.sign_out(&session)?;
//! # return Ok(());
//! # }
//! ```
//!
//! # Guides
//!
//! The root `README.md` covers quickstart, security configuration, and status.
//! `docs/README.md` is the guide index (getting started, core concepts, auth
//! methods, client, server, shipping & operating, examples).
//!
//! The only documented import path is the crate root
//! (`use dioxus_auth::{Auth, AuthProvider, RequireAuth, …}`); advanced items
//! stay reachable through their modules, and deep implementation paths are
//! closed.

#![forbid(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
// reason: the Props derive emits `#[allow(missing_docs)]` on its generated
// builder items, and `forbid` would reject that allow. `deny` still fails any
// undocumented hand-written item while letting the derive annotate its own
// generated surface. Mirrors the resolution used in dioxus's own crates.
#![deny(clippy::missing_panics_doc)]
#![deny(clippy::missing_errors_doc)]
#![deny(clippy::missing_safety_doc)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_in_result)]
#![deny(clippy::panic_in_result_fn)]
#![allow(clippy::needless_return)]
// reason: project style requires explicit `return` on every tail expression,
// which the style-group lint `needless_return` then flags. The explicit-return
// rule is stricter, so the conflicting style lint is disabled crate-wide.

//! README mirror anchor: the rust blocks in `README.md` compile as
//! doctests, so the guide cannot rot away from the API. Component trees and
//! server wiring stay `rust,ignore` with symbol pins in
//! `tests/readme_snippets.rs`.
#[doc(hidden)]
#[doc = include_str!("../README.md")]
mod readme_mirror {}

pub mod auth;
pub mod builder;
#[cfg(feature = "dioxus")]
pub mod dioxus;
pub mod engine;
pub mod error;
pub mod hash;
pub(crate) mod hooks;
pub(crate) mod login;
pub(crate) mod logout;
pub(crate) mod methods;
pub mod rate_limit;
pub mod security;
pub mod session;
pub mod status;
pub mod store;
pub mod token;
pub mod transport;
pub mod user;
pub(crate) mod validate;

#[doc(inline)]
pub use crate::auth::Auth;

#[doc(inline)]
pub use crate::builder::AuthEngineBuilder;

#[doc(inline)]
pub use crate::engine::{AuthEngine, LoginOptions};

#[doc(inline)]
pub use crate::error::{AuthError, ErrorCode};

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
pub use crate::store::{
    AuthSubject, CredentialStore, DefaultStore, MemoryStore, SessionStore, StoredCredential,
    SubjectClaim, SubjectStore, UserStore,
};

#[doc(inline)]
pub use crate::token::MemoryTokenStorage;

#[doc(inline)]
pub use crate::transport::TokenStorage;

#[doc(inline)]
pub use crate::user::{AuthUser, DefaultUser, DefaultUserInput};

#[cfg(feature = "dioxus")]
#[doc(inline)]
pub use crate::dioxus::{
    AuthContext, AuthEngineHandle, AuthOperations, AuthProvider, AuthProviderProps, AuthStateEvent,
    RedirectIfAuthed, RedirectIfAuthedProps, RequireAuth, RequireAuthProps, RestoreClassify,
    RestoreVerdict, SessionState, TokenStorageHandle, on_auth_state_change, use_auth, use_session,
};

#[cfg(feature = "dioxus-fullstack")]
#[doc(inline)]
pub use crate::dioxus::{
    AuthLayer, AuthService, LoginRequest, RequireAuthLayer, RequireAuthService, ServerAuthConfig,
    ServerAuthContext, ServerError, current_user, require_user, server_init, write_session_cookie,
};
// Note: `fullstack_server_fns!` needs no re-export: `#[macro_export]` places it
// at the crate root, where `dioxus_auth::fullstack_server_fns!(…)` finds it.
