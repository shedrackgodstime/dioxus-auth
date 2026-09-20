//! Error types for authentication operations.

use thiserror::Error;

/// All authentication errors.
#[derive(Error, Debug)]
pub enum AuthError {
    /// The provided credentials are invalid.
    #[error("invalid credentials")]
    InvalidCredentials,
    /// The session could not be found or is expired.
    #[error("session not found")]
    SessionNotFound,
    /// The user could not be found.
    #[error("user not found")]
    UserNotFound,
    /// The password hash is malformed.
    #[error("password hash error")]
    PasswordHashError,
    /// The token is malformed or expired.
    #[error("token error")]
    TokenError,
    /// An internal error occurred.
    #[error("internal error")]
    Internal(String),
}

/// Creates an `AuthError::Internal` from a string.
pub fn internal_error(msg: String) -> AuthError {
    AuthError::Internal(msg)
}
