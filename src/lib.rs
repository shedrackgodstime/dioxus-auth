//! dioxus-auth — authentication and session management for Dioxus.
//!
//! The crate is layered: the core engine has zero Dioxus dependency, and the
//! Dioxus runtime is planned as a feature-gated layer. Application storage is
//! pluggable through the capability traits in the [`prelude`].
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

pub(crate) mod builder;
#[cfg(feature = "dioxus")]
mod dioxus;
pub(crate) mod engine;
pub(crate) mod error;
pub(crate) mod hash;
pub(crate) mod hooks;
pub(crate) mod login;
pub(crate) mod logout;
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
