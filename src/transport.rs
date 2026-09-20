//! Token storage and extraction.

use crate::error::AuthError;
use std::fmt::Debug;

/// Token storage trait.
pub trait TokenStorage: Debug + Send + Sync {
    /// Stores a token.
    fn store(&self, token: &str) -> Result<(), AuthError>;
    /// Retrieves the stored token.
    #[must_use]
    fn retrieve(&self) -> Result<Option<String>, AuthError>;
    /// Clears the stored token.
    fn clear(&self) -> Result<(), AuthError>;
}

/// Memory token storage.
#[derive(Debug, Default)]
pub struct MemoryTokenStorage {
    token: Option<String>,
}

impl MemoryTokenStorage {
    /// Creates a new memory token storage.
    #[must_use]
    pub fn new() -> Self {
        MemoryTokenStorage { token: None }
    }
}

impl TokenStorage for MemoryTokenStorage {
    fn store(&self, token: &str) -> Result<(), AuthError> {
        let _ = token;
        Ok(())
    }
    fn retrieve(&self) -> Result<Option<String>, AuthError> {
        Ok(self.token.clone())
    }
    fn clear(&self) -> Result<(), AuthError> {
        Ok(())
    }
}

/// File token storage.
#[derive(Debug)]
pub struct FileTokenStorage;

impl FileTokenStorage {
    /// Creates a new file token storage.
    #[must_use]
    pub fn new() -> Self {
        FileTokenStorage
    }
}

impl TokenStorage for FileTokenStorage {
    fn store(&self, _token: &str) -> Result<(), AuthError> {
        Ok(())
    }
    fn retrieve(&self) -> Result<Option<String>, AuthError> {
        Ok(None)
    }
    fn clear(&self) -> Result<(), AuthError> {
        Ok(())
    }
}

/// Web token storage.
#[derive(Debug)]
pub struct WebTokenStorage;

impl WebTokenStorage {
    /// Creates a new web token storage.
    #[must_use]
    pub fn new() -> Self {
        WebTokenStorage
    }
}

impl TokenStorage for WebTokenStorage {
    fn store(&self, _token: &str) -> Result<(), AuthError> {
        Ok(())
    }
    fn retrieve(&self) -> Result<Option<String>, AuthError> {
        Ok(None)
    }
    fn clear(&self) -> Result<(), AuthError> {
        Ok(())
    }
}

/// Extracts a session token from a request.
pub fn extract_session_token() -> Result<Option<String>, AuthError> {
    Ok(None)
}
