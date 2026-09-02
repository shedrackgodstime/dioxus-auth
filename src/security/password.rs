use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::{AuthError, AuthResult};

/// Trait for cryptographic password hashing and verification.
pub trait PasswordHasher: Send + Sync + 'static {
    /// Hash a plaintext password into a secure encoded hash string (including salt and algorithm params).
    fn hash_password(&self, password: &str) -> AuthResult<String>;

    /// Verify a plaintext password against an encoded password hash string.
    ///
    /// Must execute in constant time to prevent side-channel timing attacks.
    fn verify_password(&self, password: &str, password_hash: &str) -> AuthResult<bool>;
}

/// Argon2id password hasher implementing [`PasswordHasher`].
///
/// Uses OWASP-recommended default parameters (Argon2id, 19 MiB memory, 2 iterations, 1 lane).
#[derive(Clone, Debug)]
pub struct Argon2Hasher {
    argon2: Argon2<'static>,
}

impl Default for Argon2Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Argon2Hasher {
    /// Create a new `Argon2Hasher` with OWASP-recommended default parameters.
    pub fn new() -> Self {
        Self {
            argon2: Argon2::default(),
        }
    }

    /// Create a customized `Argon2Hasher` with specific memory (KiB), iterations, and parallelism.
    pub fn with_params(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Result<Self, AuthError> {
        let params = Params::new(m_cost_kib, t_cost, p_cost, None)
            .map_err(|e| AuthError::Store(format!("invalid Argon2 parameters: {e}")))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        Ok(Self { argon2 })
    }
}

impl PasswordHasher for Argon2Hasher {
    fn hash_password(&self, password: &str) -> AuthResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        self.argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| AuthError::Store(format!("password hashing error: {e}")))
    }

    fn verify_password(&self, password: &str, password_hash: &str) -> AuthResult<bool> {
        let parsed_hash = match PasswordHash::new(password_hash) {
            Ok(h) => h,
            Err(_) => return Ok(false),
        };

        Ok(self
            .argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_hashes_and_verifies_correctly() {
        let hasher = Argon2Hasher::new();
        let password = "super_secret_password_123!";

        let hash = hasher.hash_password(password).unwrap();
        assert!(hash.starts_with("$argon2id$"));

        // Correct password matches
        assert!(hasher.verify_password(password, &hash).unwrap());

        // Incorrect password rejected
        assert!(!hasher.verify_password("wrong_password", &hash).unwrap());

        // Malformed hash safely returns false without panic
        assert!(
            !hasher
                .verify_password(password, "not_a_valid_hash")
                .unwrap()
        );
    }
}
