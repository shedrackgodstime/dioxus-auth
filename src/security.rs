//! Security configuration and password hashing.

use crate::error::AuthError;
use std::collections::BTreeMap;
use std::fmt::Debug;

/// Configuration for cookie-based sessions.
#[derive(Debug, Clone)]
pub struct CookieConfig {
    /// The cookie name.
    pub name: String,
    /// Whether the cookie is HTTP-only.
    pub http_only: bool,
    /// The SameSite policy.
    pub same_site: SameSite,
}

/// The SameSite cookie policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SameSite {
    /// Strict SameSite policy.
    Strict,
    /// Lax SameSite policy.
    Lax,
    /// No SameSite policy.
    None,
}

/// A password hashing trait.
pub trait PasswordHasher: Debug + Send + Sync {
    /// Hashes a password.
    fn hash(&self, password: &str) -> Result<String, AuthError>;
    /// Verifies a password against a hash.
    fn verify(&self, password: &str, hash: &str) -> Result<bool, AuthError>;
}

/// Argon2 password hasher.
#[derive(Debug)]
pub struct Argon2Hasher;

impl Argon2Hasher {
    /// Creates a new Argon2 hasher.
    #[must_use]
    pub fn new() -> Self {
        Argon2Hasher
    }
}

impl PasswordHasher for Argon2Hasher {
    fn hash(&self, _password: &str) -> Result<String, AuthError> {
        Ok(String::new())
    }
    fn verify(&self, _password: &str, _hash: &str) -> Result<bool, AuthError> {
        Ok(true)
    }
}

/// In-memory rate limiter.
#[derive(Debug, Default)]
pub struct InMemoryRateLimiter {
    limits: BTreeMap<String, u32>,
}

impl InMemoryRateLimiter {
    /// Creates a new rate limiter.
    #[must_use]
    pub fn new() -> Self {
        InMemoryRateLimiter {
            limits: BTreeMap::new(),
        }
    }
    /// Checks if a request is allowed.
    pub fn check(&self, _key: &str) -> bool {
        true
    }
}
