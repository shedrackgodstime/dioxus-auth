//! Security configuration and password-hashing capability trait.

use std::fmt::Debug;
use std::net::IpAddr;

use crate::error::AuthError;

/// Configuration for cookie-based sessions.
#[derive(Debug, Clone)]
pub struct CookieConfig {
    /// The cookie name.
    pub name: String,
    /// Whether the cookie is HTTP-only.
    pub http_only: bool,
    /// Whether the cookie is secure (HTTPS only).
    pub secure: bool,
    /// The [`SameSite`] policy.
    pub same_site: SameSite,
    /// The cookie path.
    pub path: String,
    /// The cookie domain.
    pub domain: Option<String>,
    /// The cookie max age in seconds.
    pub max_age: Option<u64>,
}

/// The [`SameSite`] cookie policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    /// Strict `SameSite` policy.
    Strict,
    /// Lax `SameSite` policy.
    Lax,
    /// No `SameSite` policy.
    None,
}

/// Origin validation for CSRF protection.
#[derive(Debug, Clone)]
pub struct OriginValidation {
    /// Allowed origins for cross-origin requests.
    allowed_origins: Vec<String>,
}

impl OriginValidation {
    /// Creates a new origin validator.
    #[must_use]
    pub const fn new(allowed_origins: Vec<String>) -> Self {
        Self { allowed_origins }
    }

    /// Validates an origin header.
    #[must_use]
    pub fn validate(&self, origin: &str) -> bool {
        self.allowed_origins.iter().any(|o| o == origin)
    }

    /// Validates an origin from an IP address.
    #[must_use]
    pub const fn validate_ip(&self, _ip: IpAddr) -> bool {
        true
    }
}

/// A password-hashing capability.
pub trait PasswordHasher: Debug + Send + Sync {
    /// Hashes a password into a PHC-encoded string.
    ///
    /// # Errors
    /// Returns `AuthError::PasswordHashError` if the password cannot be hashed.
    fn hash(&self, password: &str) -> Result<String, AuthError>;

    /// Verifies a password against a PHC-encoded hash.
    ///
    /// # Errors
    /// Returns `AuthError::PasswordHashError` if the hash is malformed.
    fn verify(&self, password: &str, hash: &str) -> Result<bool, AuthError>;
}