//! dioxus-auth — authentication and session management for Dioxus.
//!
//! The crate is layered: the core engine has zero Dioxus dependency, and the
//! Dioxus runtime is feature-gated behind the `dioxus` feature. Application
//! storage is pluggable through the capability traits in [`store`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

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