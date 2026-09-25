//! Server authentication errors and their HTTP mapping.

use crate::error::AuthError;

/// Errors produced by the server authentication context.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServerError {
    /// No engine is configured for the current request or process.
    #[error("no server auth configuration available for this request")]
    MissingContext,
    /// [`server_init`](super::registry::server_init) was called twice.
    #[error("server auth configuration already initialized")]
    AlreadyInitialized,
    /// The request did not resolve to an authenticated session.
    #[error("the request did not carry an authenticated session")]
    MissingSession,
    /// The session cookie value is not a valid header value.
    #[error("invalid session cookie header value")]
    InvalidCookieValue,
    /// The underlying auth engine failed.
    #[error("auth engine error: {0}")]
    Engine(#[from] AuthError),
}

impl ServerError {
    /// The HTTP status code the error should be served with.
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        return match self {
            Self::MissingSession => 401,
            Self::Engine(error) => auth_error_status(error),
            Self::MissingContext | Self::AlreadyInitialized | Self::InvalidCookieValue => 500,
        };
    }
}

/// The HTTP status code for an engine failure.
///
/// Shared by [`ServerError::status_code`] and the `ServerFnError` conversion
/// so the two mappings cannot diverge.
#[must_use]
pub const fn auth_error_status(error: &AuthError) -> u16 {
    return match error {
        AuthError::InvalidCredentials | AuthError::PasswordHashError => 401,
        AuthError::RateLimited => 429,
        AuthError::Csrf => 403,
        AuthError::Internal(_) => 500,
    };
}
