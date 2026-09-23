//! User storage capability traits.

use std::fmt::Debug;

use crate::error::AuthError;
use crate::user::AuthUser;

/// Stores users by identifier (read-only users of the engine).
///
/// `find_by_id` is the read contract: returns the user row for a known id and
/// `Ok(None)` for a missing one. Insert helpers live on concrete stores
/// (`MemoryStore::insert_user`); capability traits standardize reads and
/// credential writes only.
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
///
/// Identifier matching is exact: the engine normalizes once (trim + lowercase)
/// before every call, so stores compare byte-for-byte and never fold case or
/// whitespace themselves.
pub trait PasswordUserStore: UserStore {
    /// Finds a user and their stored password hash by login identifier.
    ///
    /// The identifier arrives engine-normalized (trimmed, lowercased). Match
    /// it exactly — one canonical row per normalized key. The engine verifies
    /// `password` against the returned hash; the store never receives
    /// plaintext passwords from the login path and never runs verification
    /// itself. Returning the hash lets the engine apply timing defense on
    /// unknown-user logins.
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

    /// Provisions a user and their credential iff the identifier is unused.
    ///
    /// Atomic: when the identifier is already taken, no user or credential row
    /// is written and `Ok(false)` is returned. Implementations must run the
    /// uniqueness check and the write as one indivisible step — a separate
    /// lookup followed by a write leaves a window in which two registrations
    /// both pass the check, and the loser's write overwrites the winner's
    /// credential.
    ///
    /// The identifier arrives engine-normalized (trimmed, lowercased); compare
    /// it byte-for-byte, one canonical row per key. Also rejects when the
    /// `user.id()` row already exists, returning `Ok(false)` with no writes —
    /// two identifiers must never alias one user row.
    ///
    /// # Errors
    /// Returns an error if the underlying store fails.
    #[must_use = "the provisioning result must be checked"]
    fn provision_user_with_password(
        &self,
        user: Self::User,
        identifier: &str,
        password_hash: &str,
    ) -> Result<bool, AuthError>;
}
