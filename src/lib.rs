//! dioxus-auth — authentication and session management for Dioxus.
//!
//! The crate is layered: the core engine has zero Dioxus dependency, and the
//! Dioxus runtime ships as a feature-gated layer (`dioxus`). Application
//! storage is pluggable through the capability traits in the [`prelude`].
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
//! use dioxus_auth::prelude::{Auth, AuthUser, MemoryStore};
//!
//! # #[derive(Debug, Clone)]
//! # struct User { id: u64, name: String }
//! # impl AuthUser for User {
//! #     type Id = u64;
//! #     fn id(&self) -> u64 { return self.id; }
//! #     fn email(&self) -> &str { return &self.name; }
//! # }
//! # fn main() -> Result<(), dioxus_auth::prelude::AuthError> {
//! let auth = Auth::<MemoryStore<User>>::memory()?;
//!
//! let user = User { id: 1, name: String::from("alice") };
//! let (user, session) = auth.sign_up_email("alice", "password", user)?;
//! let (user, _session) = auth.sign_in_email("alice", "password")?;
//! assert_eq!(user.id(), 1);
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
//! The only intended import path is [`prelude`]; internal modules are
//! `pub(crate)`.

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
// reason: RULES 13.5/14.5 require explicit `return` on every tail expression,
// which the style-group lint `needless_return` then flags. The explicit-return
// rule is stricter, so the conflicting style lint is disabled crate-wide.
pub(crate) mod auth;
pub(crate) mod builder;
#[cfg(feature = "dioxus")]
mod dioxus;
pub(crate) mod engine;
pub(crate) mod error;
pub(crate) mod hash;
pub(crate) mod hooks;
pub(crate) mod login;
pub(crate) mod logout;
pub(crate) mod methods;
pub mod prelude;
pub(crate) mod rate_limit;
pub(crate) mod security;
pub(crate) mod session;
pub(crate) mod status;
pub(crate) mod store;
pub(crate) mod token;
pub(crate) mod transport;
pub(crate) mod user;
pub(crate) mod validate;
