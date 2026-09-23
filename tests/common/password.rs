//! Argon2 password fixture shared by hashing-behavior tests.

// reason: project style requires explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use dioxus_auth::{Argon2Hasher, PasswordHasher};

/// Hashes a password with the default Argon2 hasher.
///
/// # Panics
/// Panics if hashing fails; Argon2 hashing cannot fail for a well-formed input.
#[must_use]
pub fn hash_password(password: &str) -> String {
    return Argon2Hasher::new()
        .hash(password)
        .expect("Argon2 hashing cannot fail for valid input");
}
