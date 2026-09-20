//! Token storage implementations.

use crate::error::AuthError;
use crate::transport::TokenStorage;

/// In-memory token storage for native/dev clients.
#[derive(Debug, Default)]
pub struct MemoryTokenStorage {
    token: Option<String>,
}

impl MemoryTokenStorage {
    /// Creates a new memory token storage.
    #[must_use]
    pub const fn new() -> Self {
        return Self { token: None };
    }
}

impl TokenStorage for MemoryTokenStorage {
    fn store(&mut self, token: &str) -> Result<(), AuthError> {
        self.token = Some(token.to_string());
        return Ok(());
    }

    fn retrieve(&self) -> Result<Option<String>, AuthError> {
        return Ok(self.token.clone());
    }

    fn clear(&mut self) -> Result<(), AuthError> {
        self.token = None;
        return Ok(());
    }
}
