//! Unified error type for all authentication and session operations.

use thiserror::Error;

/// Convenience alias for `Result` values that fail with an [`AuthError`].
pub type AuthResult<T> = Result<T, AuthError>;

/// Errors produced by authentication and session operations.
///
/// Semantic failures (invalid credentials, expired/revoked sessions, CSRF,
/// rate limiting) are structured variants; infrastructure failures from the
/// backing stores surface as [`AuthError::Store`].
#[derive(Clone, Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum AuthError {
    /// No session credential was presented where one is required.
    #[error("missing authentication session")]
    MissingSession,
    /// A session credential was presented but is unknown, malformed, or revoked.
    #[error("invalid authentication session")]
    InvalidSession,
    /// The session credential exceeded its absolute or idle lifetime.
    #[error("expired authentication session")]
    ExpiredSession,
    /// The user behind the session no longer satisfies authentication
    /// requirements (deleted, deactivated, or credential-mismatched).
    #[error("user is not authenticated")]
    Unauthenticated,
    /// A state-changing request failed cross-site request forgery validation.
    #[error("cross-site request forgery attempt detected")]
    Csrf,
    /// The request was rejected by the login rate limiter.
    #[error("too many authentication attempts, try again later")]
    RateLimited,
    /// A user or session store operation failed; carries the store's message.
    #[error("authentication store error: {0}")]
    Store(String),
}
