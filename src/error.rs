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
    /// The presented identifier/password pair was rejected at login.
    ///
    /// Returned for **both** an unknown identifier and a wrong password — the
    /// two are deliberately indistinguishable so the error channel cannot be
    /// used to enumerate registered accounts (the timing side-channel is
    /// already closed by the dummy-hash verification; this closes the
    /// error-matching side door).
    #[error("invalid credentials")]
    InvalidCredentials,
    /// No session credential was presented where one is required.
    #[error("missing authentication session")]
    MissingSession,
    /// A session credential was presented but is unknown, malformed, or revoked.
    #[error("invalid authentication session")]
    InvalidSession,
    /// The session credential exceeded its absolute or idle lifetime.
    #[error("expired authentication session")]
    ExpiredSession,
    /// A session-state problem, not a login failure.
    ///
    /// The user behind a session no longer satisfies authentication
    /// requirements (deleted, deactivated, or credential-mismatched), or a
    /// required session is absent/invalid in a context that is not a login
    /// attempt. Login credential rejections use [`AuthError::InvalidCredentials`].
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
