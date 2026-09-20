//! Token storage trait and extraction.

use std::fmt::Debug;

use crate::error::AuthError;

#[cfg(not(target_arch = "wasm32"))]
pub use crate::token::FileTokenStorage;
pub use crate::token::MemoryTokenStorage;
#[cfg(target_arch = "wasm32")]
pub use crate::token::WebTokenStorage;

/// Stores and retrieves the persistent session token on the client.
pub trait TokenStorage: Debug + Send + Sync {
    /// Stores a token.
    ///
    /// # Errors
    /// Returns an error if the underlying storage fails.
    fn store(&mut self, token: &str) -> Result<(), AuthError>;

    /// Retrieves the stored token.
    ///
    /// # Errors
    /// Returns an error if the underlying storage fails.
    fn retrieve(&self) -> Result<Option<String>, AuthError>;

    /// Clears the stored token.
    ///
    /// # Errors
    /// Returns an error if the underlying storage fails.
    fn clear(&mut self) -> Result<(), AuthError>;
}

/// Extracts the raw session token from the current request.
///
/// No-op outside a configured web/transport context.
///
/// # Errors
/// Returns an error if the token cannot be extracted from the request.
pub const fn extract_session_token() -> Result<Option<String>, AuthError> {
    Ok(None)
}