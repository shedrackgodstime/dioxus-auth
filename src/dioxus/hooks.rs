//! Hooks for reading the auth context and the reactive session state.
//!
//! Each hook lives in its own file (RULES §18.3): [`use_auth`] in
//! `use_auth.rs`, [`use_session`] in `use_session.rs`, and
//! [`on_auth_state_change`] in `use_auth_state_change.rs`.

mod use_auth;
mod use_auth_state_change;
mod use_session;

pub use use_auth::use_auth;
pub use use_auth_state_change::{AuthStateEvent, on_auth_state_change};
pub use use_session::use_session;
