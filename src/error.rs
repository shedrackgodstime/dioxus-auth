use std::fmt;

pub type AuthResult<T> = Result<T, AuthError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthError {
    MissingSession,
    InvalidSession,
    ExpiredSession,
    Unauthenticated,
    Store(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSession => f.write_str("missing authentication session"),
            Self::InvalidSession => f.write_str("invalid authentication session"),
            Self::ExpiredSession => f.write_str("expired authentication session"),
            Self::Unauthenticated => f.write_str("user is not authenticated"),
            Self::Store(message) => write!(f, "authentication store error: {message}"),
        }
    }
}

impl std::error::Error for AuthError {}
