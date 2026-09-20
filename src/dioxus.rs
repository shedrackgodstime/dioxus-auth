//! Dioxus runtime layer.

pub mod client;
pub mod components;
pub mod hooks;
pub mod server;

use std::fmt::Debug;

/// Dioxus authentication entry point.
#[derive(Debug)]
pub struct DioxusAuth;
