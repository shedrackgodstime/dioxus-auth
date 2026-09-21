//! Error types for authentication operations.

use thiserror::Error;

/// All authentication errors.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// The provided credentials are invalid.
    #[error("invalid credentials")]
    InvalidCredentials,
    /// The password hash is malformed.
    #[error("password hash error")]
    PasswordHashError,
    /// Rate limit exceeded.
    #[error("rate limit exceeded")]
    RateLimited,
    /// Cross-site request forgery: a state-changing cookie operation arrived
    /// without a present, matching origin.
    #[error("csrf validation failed")]
    Csrf,
    /// An internal error occurred.
    #[error("internal error")]
    Internal(String),
}
