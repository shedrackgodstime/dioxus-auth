//! Shared test fixtures for the auth-core test suites.
//!
// reason: each test binary uses a subset of these fixtures; the unused ones
// would otherwise trip `dead_code` in that specific binary.

#![allow(dead_code)]
#![allow(clippy::needless_return)]
// reason: RULES 13.5/14.5 require explicit `return`; the reason'd allow mirrors
// the same resolution already applied in src/lib.rs for the lib crate.

use dioxus_auth::prelude::{Argon2Hasher, AuthUser, PasswordHasher};

/// A minimal user for exercising the auth core.
#[derive(Debug, Clone)]
pub struct TestUser {
    pub id: u64,
    pub name: String,
}

impl AuthUser for TestUser {
    type Id = u64;

    fn id(&self) -> Self::Id {
        return self.id;
    }

    fn display_name(&self) -> Option<String> {
        return Some(self.name.clone());
    }

    fn session_auth_hash(&self) -> Option<&str> {
        return None;
    }

    fn clone_box(&self) -> Box<dyn AuthUser<Id = Self::Id>> {
        return Box::new(self.clone());
    }
}

impl TestUser {
    /// Creates a test user.
    #[must_use]
    pub fn new(id: u64, name: impl Into<String>) -> Self {
        return Self {
            id,
            name: name.into(),
        };
    }
}

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
