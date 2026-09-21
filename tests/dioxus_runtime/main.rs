//! End-to-end tests for the Dioxus runtime layer: provider restore, context
//! state transitions and route-guard behavior.

#[path = "../common/mod.rs"]
mod common;
#[path = "../common/identity_hasher.rs"]
mod identity_hasher;

mod components;
mod guards;
mod handles;
mod harness;
mod state;
