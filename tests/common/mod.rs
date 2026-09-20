//! Shared test fixtures for the auth-core test suites.
//!
// reason: each test binary uses a subset of these fixtures; the unused ones
// would otherwise trip `dead_code` in that specific binary.

#![allow(dead_code)]

use dioxus_auth::hash::Argon2Hasher;
use dioxus_auth::security::PasswordHasher;
use dioxus_auth::user::AuthUser;

/// A minimal user for exercising the auth core.
#[derive(Debug, Clone)]
pub struct TestUser {
    pub id: u64,
    pub name: String,
}

impl AuthUser for TestUser {
    type Id = u64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn display_name(&self) -> Option<String> {
        Some(self.name.clone())
    }

    fn session_auth_hash(&self) -> Option<&str> {
        None
    }

    fn clone_box(&self) -> Box<dyn AuthUser<Id = Self::Id>> {
        Box::new(self.clone())
    }
}

impl TestUser {
    /// Creates a test user.
    #[must_use]
    pub fn new(id: u64, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
        }
    }
}

/// Hashes a password with the default Argon2 hasher.
///
/// # Panics
/// Panics if hashing fails; Argon2 hashing cannot fail for a well-formed input.
#[must_use]
pub fn hash_password(password: &str) -> String {
    Argon2Hasher::new()
        .hash(password)
        .expect("Argon2 hashing cannot fail for valid input")
}