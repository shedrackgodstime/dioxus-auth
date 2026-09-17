//! Core authentication engine: password login, session lifecycle, and
//! revocation, generic over user/session stores and password hashers.
#![allow(clippy::type_complexity)]

mod auth_engine;
mod builder;

pub use auth_engine::AuthEngine;
pub use builder::AuthEngineBuilder;
