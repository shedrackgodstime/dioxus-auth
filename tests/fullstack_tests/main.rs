//! End-to-end tests for the fullstack server slice: the generated server
//! functions, cookie handling, and the fullstack middleware.
//!
//! Runs natively with both the `dioxus-fullstack` and `server` features:
//! `cargo test --features dioxus-fullstack,server --test fullstack_tests`.
//!
//! Every test scopes its request with the configuration attached as a request
//! extension, so the process-global registry (exercised by
//! `tests/fullstack_global_tests.rs`) never leaks into these results.

#[path = "../common/mod.rs"]
mod common;
#[path = "../common/fullstack_shared.rs"]
mod fullstack_shared;
#[path = "../common/identity_hasher.rs"]
mod identity_hasher;

mod blocking;
mod cookies;
mod harness;
mod middleware;
mod origins;
mod redaction;
mod server_fns;

use common::TestUser;

dioxus_auth::fullstack_server_fns!(TestUser);
