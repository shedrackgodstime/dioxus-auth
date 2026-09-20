//! Token storage implementations.

use crate::error::AuthError;
use crate::transport::TokenStorage;

/// Memory token storage.
#[derive(Debug, Default)]
pub struct MemoryTokenStorage {
    token: Option<String>,
}

impl MemoryTokenStorage {
    /// Creates a new memory token storage.
    #[must_use]
    pub const fn new() -> Self {
        Self { token: None }
    }
}

impl TokenStorage for MemoryTokenStorage {
    fn store(&mut self, token: &str) -> Result<(), AuthError> {
        self.token = Some(token.to_string());
        Ok(())
    }

    fn retrieve(&self) -> Result<Option<String>, AuthError> {
        Ok(self.token.clone())
    }

    fn clear(&mut self) -> Result<(), AuthError> {
        self.token = None;
        Ok(())
    }
}

/// File token storage (non-WASM).
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Default)]
pub struct FileTokenStorage;

#[cfg(not(target_arch = "wasm32"))]
impl FileTokenStorage {
    /// Creates a new file token storage.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl TokenStorage for FileTokenStorage {
    fn store(&mut self, _token: &str) -> Result<(), AuthError> {
        Ok(())
    }

    fn retrieve(&self) -> Result<Option<String>, AuthError> {
        Ok(None)
    }

    fn clear(&mut self) -> Result<(), AuthError> {
        Ok(())
    }
}

/// Web token storage (WASM).
#[cfg(target_arch = "wasm32")]
#[derive(Debug, Default)]
pub struct WebTokenStorage;

#[cfg(target_arch = "wasm32")]
impl WebTokenStorage {
    /// Creates a new web token storage.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(target_arch = "wasm32")]
impl TokenStorage for WebTokenStorage {
    fn store(&mut self, _token: &str) -> Result<(), AuthError> {
        Ok(())
    }

    fn retrieve(&self) -> Result<Option<String>, AuthError> {
        Ok(None)
    }

    fn clear(&mut self) -> Result<(), AuthError> {
        Ok(())
    }
}