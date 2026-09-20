//! Client-side Dioxus runtime.

use std::fmt::Debug;

/// The auth provider component.
#[derive(Debug)]
pub struct AuthProvider;

/// A reference to a token storage.
#[derive(Debug)]
pub struct TokenStorageRef;

/// Auth context for client components.
#[derive(Debug, Clone)]
pub struct Auth<U> {
    status: crate::status::AuthStatus<U>,
}

impl<U> Auth<U> {
    /// Creates a new auth context.
    #[must_use]
    pub const fn new(status: crate::status::AuthStatus<U>) -> Self {
        Self { status }
    }

    /// Returns the current auth status.
    #[must_use]
    pub const fn status(&self) -> &crate::status::AuthStatus<U> {
        &self.status
    }

    /// Sets the auth status.
    pub fn set_status(&mut self, status: crate::status::AuthStatus<U>) {
        self.status = status;
    }
}

/// Hook for authentication state.
#[derive(Debug)]
pub struct UseAuth;

/// Hook for restoring authentication.
#[derive(Debug)]
pub struct UseAuthRestore;

/// Hook for token storage.
#[derive(Debug)]
pub struct UseTokenStorage;
