//! Hooks are the primary client surface of `dioxus-auth` — one file per hook,
//! following the dioxus-router/dioxus-hooks convention.

pub use use_auth::{try_use_auth, use_auth};
pub use use_auth_restore::use_auth_restore;
pub use use_token_storage::use_token_storage;

mod use_auth;
mod use_auth_restore;
mod use_token_storage;
