//! User storage capability traits.

use std::fmt::Debug;

use crate::error::AuthError;
use crate::user::AuthUser;

/// Stores users by identifier (read-only users of the engine).
pub trait UserStore: Debug + Send + Sync {
    /// The user identifier type.
    type Id: Clone + Eq + Debug + Send + Sync + 'static;
    /// The user type.
    type User: AuthUser<Id = Self::Id>;

    /// Finds a user by their identifier.
    ///
    /// # Errors
    /// Returns an error if the underlying store fails.
    #[must_use = "the store result must be used"]
    fn find_by_id(&self, id: &Self::Id) -> Result<Option<Self::User>, AuthError>;
}

/// Stores users with password credentials.
pub trait PasswordUserStore: UserStore {
    /// Finds a user and their stored password hash by login identifier.
    ///
    /// The engine verifies `password` against the returned hash — the store
    /// never receives plaintext passwords from the login path and never runs
    /// verification itself. Returning the hash lets the engine apply timing
    /// defense on unknown-user logins.
    ///
    /// # Errors
    /// Returns an error if the underlying store fails.
    #[must_use = "the lookup result must be used"]
    fn find_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<(Self::User, String)>, AuthError>;

    /// Updates a user's stored password hash.
    ///
    /// # Errors
    /// Returns an error if the underlying store fails.
    #[must_use = "a failed hash update must be handled"]
    fn update_password(&self, id: &Self::Id, new_hash: &str) -> Result<(), AuthError>;
}
