#![forbid(unsafe_code)]
#![deny(clippy::pedantic)]
#![deny(missing_docs)]

//! dioxus-auth — authentication and session management for Dioxus.

pub mod builder;
pub mod dioxus;
pub mod engine;
pub mod error;
pub mod security;
pub mod status;
pub mod store;
pub mod transport;
pub mod user;

/// Curated public API surface.
pub mod prelude;
