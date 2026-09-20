//! Dioxus hooks.

use std::fmt::Debug;

/// Hook for authentication state.
#[derive(Debug)]
pub struct UseAuth;

/// Hook for restoring authentication.
#[derive(Debug)]
pub struct UseAuthRestore;

/// Hook for token storage.
#[derive(Debug)]
pub struct UseTokenStorage;
