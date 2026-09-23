//! Token storage trait for the client-side session token.

use std::fmt::Debug;

use crate::error::AuthError;

/// Stores and retrieves the persistent session token on the client.
///
/// Implementations are application-selected; the engine never reads or writes
/// tokens itself. Reads and writes run synchronously inside component renders
/// (provider restore, login, logout), so implementations must be fast and
/// non-blocking. A storage call that waits on the network stalls the render
/// worker.
pub trait TokenStorage: Debug + Send + Sync {
    /// Stores a token.
    ///
    /// # Errors
    /// Returns an error if the underlying storage fails.
    #[must_use = "a failed storage write must be handled"]
    fn store(&mut self, token: &str) -> Result<(), AuthError>;

    /// Retrieves the stored token.
    ///
    /// # Errors
    /// Returns an error if the underlying storage fails.
    #[must_use = "the stored token must be used"]
    fn retrieve(&self) -> Result<Option<String>, AuthError>;

    /// Clears the stored token.
    ///
    /// # Errors
    /// Returns an error if the underlying storage fails.
    #[must_use = "a failed storage clear must be handled"]
    fn clear(&mut self) -> Result<(), AuthError>;
}
