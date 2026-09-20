//! Capability traits for authentication storage.

use crate::error::AuthError;
use crate::status::SessionId;
use crate::status::SessionRecord;
use crate::user::AuthUser;
use std::fmt::Debug;

pub mod memory;
pub mod session;
pub mod user;

/// Stores user data by identifier.
pub trait UserStore: Debug + Send + Sync {
    /// Finds a user by their identifier.
    #[must_use]
    fn find_by_id(&self, id: &str) -> Result<Option<Box<dyn AuthUser>>, AuthError>;
    /// Finds a user by their credentials.
    #[must_use]
    fn find_by_credentials(
        &self,
        identifier: &str,
        password: &str,
    ) -> Result<Option<Box<dyn AuthUser>>, AuthError>;
}

/// Stores and retrieves sessions.
pub trait SessionStore: Debug + Send + Sync {
    /// Creates a new session.
    #[must_use]
    fn create(&self, user_id: &str) -> Result<SessionId, AuthError>;
    /// Retrieves a session by identifier.
    #[must_use]
    fn get(&self, id: &SessionId) -> Result<Option<SessionRecord>, AuthError>;
    /// Deletes a session.
    fn delete(&self, id: &SessionId) -> Result<(), AuthError>;
}

/// Hashes and verifies passwords.
pub trait PasswordHasher: Debug + Send + Sync {
    /// Hashes a password.
    #[must_use]
    fn hash(&self, password: &str) -> Result<String, AuthError>;
    /// Verifies a password against a hash.
    #[must_use]
    fn verify(&self, password: &str, hash: &str) -> Result<bool, AuthError>;
}

/// Stores and retrieves authentication tokens.
pub trait TokenStorage: Debug + Send + Sync {
    /// Stores a token.
    fn store(&self, token: &str) -> Result<(), AuthError>;
    /// Retrieves the stored token.
    #[must_use]
    fn retrieve(&self) -> Result<Option<String>, AuthError>;
    /// Clears the stored token.
    fn clear(&self) -> Result<(), AuthError>;
}

/// The default in-memory store implementation.
pub trait MemoryStore: Debug + Send + Sync {
    /// Stores a value in memory.
    fn put(&mut self, key: &str, value: String) -> Result<(), AuthError>;
    /// Retrieves a value from memory.
    #[must_use]
    fn get(&self, key: &str) -> Result<Option<String>, AuthError>;
}
