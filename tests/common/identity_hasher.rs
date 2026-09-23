//! Instant password-hasher fixture for hashing-indifferent tests.

// reason: project style requires explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use dioxus_auth::{AuthError, PasswordHasher};

/// A password hasher that treats the stored string as the plaintext.
///
/// Used to make credential verification instant in tests that exercise
/// concurrency or expiry rather than hashing behavior.
#[derive(Debug)]
pub struct IdentityHasher;

impl PasswordHasher for IdentityHasher {
    fn hash(&self, password: &str) -> Result<String, AuthError> {
        return Ok(String::from(password));
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, AuthError> {
        return Ok(password == hash);
    }
}
