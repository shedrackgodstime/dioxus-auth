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

/// Stable machine-readable code for an [`AuthError`].
///
/// Branch on these variants, never on message text: messages are human-facing
/// and may change, codes are the interop contract. [`#[non_exhaustive]`](https://doc.rust-lang.org/reference/attributes/type_system.html)
/// so new methods add codes without breaking downstream matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// Credentials rejected — unknown identifiers and wrong secrets share it.
    InvalidCredentials,
    /// Stored hash malformed (surfaced outside the login oracle path only).
    PasswordHash,
    /// Rate limit exceeded.
    RateLimited,
    /// CSRF origin validation failed.
    Csrf,
    /// Internal failure.
    Internal,
}

impl ErrorCode {
    /// Stable wire string for logging and interop.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        return match self {
            Self::InvalidCredentials => "invalid_credentials",
            Self::PasswordHash => "password_hash_error",
            Self::RateLimited => "rate_limited",
            Self::Csrf => "csrf_validation_failed",
            Self::Internal => "internal_error",
        };
    }
}

impl AuthError {
    /// Maps the error to its stable code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        return match self {
            Self::InvalidCredentials => ErrorCode::InvalidCredentials,
            Self::PasswordHashError => ErrorCode::PasswordHash,
            Self::RateLimited => ErrorCode::RateLimited,
            Self::Csrf => ErrorCode::Csrf,
            Self::Internal(_) => ErrorCode::Internal,
        };
    }
}
