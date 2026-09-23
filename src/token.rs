//! Token storage implementations.

use std::fmt;

use crate::error::AuthError;
use crate::status::REDACTED;
use crate::transport::TokenStorage;

/// In-memory token storage for native/dev clients.
///
/// `Debug` is **manual and redacted**: a derived impl would render the raw
/// wire token — logging the storage would otherwise dump a hijackable
/// credential.
#[derive(Default)]
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

impl fmt::Debug for MemoryTokenStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return f
            .debug_struct("MemoryTokenStorage")
            .field("token", &self.token.as_ref().map(|_| return REDACTED))
            .finish();
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
