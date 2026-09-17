//! Declarative components — the composition-model surface of `dioxus-auth`.

pub use route_gate::RouteGate;
pub use signed_in_out::{SignedIn, SignedOut};

mod route_gate;
mod signed_in_out;
