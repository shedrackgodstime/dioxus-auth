use thiserror::Error;

pub type AuthResult<T> = Result<T, AuthError>;

#[derive(Clone, Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum AuthError {
    #[error("missing authentication session")]
    MissingSession,
    #[error("invalid authentication session")]
    InvalidSession,
    #[error("expired authentication session")]
    ExpiredSession,
    #[error("user is not authenticated")]
    Unauthenticated,
    #[error("cross-site request forgery attempt detected")]
    Csrf,
    #[error("authentication store error: {0}")]
    Store(String),
}
