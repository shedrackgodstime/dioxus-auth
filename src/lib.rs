//! dioxus-auth — authentication and session management for Dioxus.
//!
//! The crate is layered: the core engine has zero Dioxus dependency, and the
//! Dioxus runtime is feature-gated behind the `dioxus` feature. Application
//! storage is pluggable through the capability traits in [`store`].

#![forbid(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(clippy::missing_panics_doc)]
#![deny(clippy::missing_errors_doc)]
#![deny(clippy::missing_safety_doc)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_in_result)]
#![deny(clippy::panic_in_result_fn)]

pub mod builder;
#[cfg(feature = "dioxus")]
pub mod dioxus;
pub mod engine;
pub mod error;
pub mod hash;
pub mod hooks;
pub mod login;
pub mod logout;
pub mod prelude;
pub mod rate_limit;
pub mod security;
pub mod session;
pub mod status;
pub mod store;
pub mod token;
pub mod transport;
pub mod user;
pub mod validate;