//! Shared test fixtures for the auth-core test suites.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use dioxus_auth::prelude::AuthUser;

/// A minimal user for exercising the auth core.
///
/// `Serialize`/`Deserialize` make it usable as a server-function return type
/// in the fullstack integration tests.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
