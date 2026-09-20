//! Server-side Dioxus runtime.

use std::fmt::Debug;

/// The server-side auth context.
#[derive(Debug)]
pub struct ServerAuthContext;

/// Macro for generating server functions.
#[macro_export]
macro_rules! fullstack_server_fns {
    () => {};
}
