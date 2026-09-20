//! Argon2id password hashing implementation.

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{
    PasswordHash, PasswordHasher as Argon2PasswordHasher, PasswordVerifier, SaltString,
};

use crate::error::AuthError;
use crate::security::PasswordHasher;

/// Argon2id password hasher.
#[derive(Debug, Clone, Default)]
pub struct Argon2Hasher;

impl Argon2Hasher {
    /// Creates a new Argon2 hasher.
    #[must_use]
    pub const fn new() -> Self {
        return Self;
    }
}

impl PasswordHasher for Argon2Hasher {
    fn hash(&self, password: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut OsRng);
        let result = Argon2::default().hash_password(password.as_bytes(), &salt);
        let encoded = match result {
            Ok(encoded) => encoded,
            Err(_) => return Err(AuthError::PasswordHashError),
        };
        return Ok(encoded.to_string());
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, AuthError> {
        let parsed = match PasswordHash::new(hash) {
            Ok(parsed) => parsed,
            Err(_) => return Err(AuthError::PasswordHashError),
        };
        let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
        return Ok(result.is_ok());
    }
}
