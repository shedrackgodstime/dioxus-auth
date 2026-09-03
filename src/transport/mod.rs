//! Client-side transport: bearer/cookie token extraction and persistent token storage.
//!
//! This module compiles without the `dioxus` feature. It owns:
//! - the dual-extract helper that prefers `Authorization: Bearer` and falls back to a
//!   `Cookie` header,
//! - the [`TokenStorage`] trait and its v0.1 implementations (memory, native file with
//!   0600 permissions, web `localStorage`).
//!
//! `TokenStorage` is **client persistence** (native restart / SPA). `SessionStore` in
//! `crate::storage` is **server persistence** (DB). They are intentionally separate
//! traits.

mod extract;
mod memory;
mod token;

#[cfg(not(target_arch = "wasm32"))]
mod file;
#[cfg(target_arch = "wasm32")]
mod web;

pub use extract::extract_session_token;
pub use memory::MemoryTokenStorage;
pub use token::TokenStorage;

#[cfg(not(target_arch = "wasm32"))]
pub use file::FileTokenStorage;

#[cfg(target_arch = "wasm32")]
pub use web::WebTokenStorage;
