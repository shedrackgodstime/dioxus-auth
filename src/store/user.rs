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
    /// Creation input the store builds a [`UserStore::User`] from.
    ///
    /// Stores that persist the input as-is (e.g. [`MemoryStore`](crate::store::MemoryStore))
    /// alias this to their user type. Stores that generate identity or apply
    /// defaults (database ids, timestamps, mapped columns) declare their own
    /// input shape holding only what the caller must supply.
    type NewUser;
    /// Finds a user and their stored password hash by login identifier.
    ///
    /// The identifier arrives engine-normalized (trimmed, lowercased). Match
    /// it exactly for one canonical row per normalized key. The engine verifies
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
    /// Updating an unknown id is a silent no-op `Ok(())`: the engine only
    /// calls this after proving the identifier exists, so the path is
    /// unreachable through credential verbs. Direct store users who need
    /// existence feedback must check first.
    ///
    /// # Errors
    /// Returns an error if the underlying store fails.
    #[must_use = "a failed hash update must be handled"]
    fn update_password(&self, id: &Self::Id, new_hash: &str) -> Result<(), AuthError>;

    /// Attaches a password credential to an existing user.
    ///
    /// The companion to provisioning: provisioning creates the user *and* its
    /// first credential, attaching adds another login to a user that already
    /// exists (imported rows, admin-created users, SSO-linked accounts, a
    /// second identifier on one account). The user id must already exist;
    /// this method never creates users.
    ///
    /// Atomic: when the identifier is already taken (by any user, including
    /// this one), nothing is written and `Ok(false)` is returned. The
    /// existence check and the write must land as one indivisible step, for
    /// the same racing-provisioner reason as
    /// [`provision_user_with_password`](Self::provision_user_with_password).
    ///
    /// The identifier arrives engine-normalized (trimmed, lowercased); compare
    /// it byte-for-byte, one canonical row per key.
    ///
    /// Privileged operation: whoever calls this binds a new login to the
    /// account, so callers must authorize first (a session for this user, or
    /// admin tooling). The store cannot tell a legitimate link from an
    /// attacker binding their own identifier to a victim's account.
    ///
    /// # Errors
    /// Returns `AuthError::InvalidCredentials` when no user with the given id
    /// exists, or a store error if the underlying store fails.
    #[must_use = "the attach result must be checked"]
    fn attach_password_credential(
        &self,
        id: &Self::Id,
        identifier: &str,
        password_hash: &str,
    ) -> Result<bool, AuthError>;

    /// Provisions a user and their credential iff the identifier is unused.
    ///
    /// Builds the stored user from the creation input: the store owns
    /// construction and identity (generated ids, applied defaults, mapped
    /// columns) and hands back exactly what it persisted, so generated values
    /// surface to the caller instead of dying inside the store.
    ///
    /// Atomic: when the identifier is already taken, no user or credential row
    /// is written and `Ok(None)` is returned. Implementations must run the
    /// uniqueness check and the write as one indivisible step. A separate
    /// lookup followed by a write leaves a window in which two registrations
    /// both pass the check, and the loser's write overwrites the winner's
    /// credential.
    ///
    /// The identifier arrives engine-normalized (trimmed, lowercased); compare
    /// it byte-for-byte, one canonical row per key. Also rejects when the
    /// constructed user's id row already exists, returning `Ok(None)` with no
    /// writes. Two identifiers must never alias one user row.
    ///
    /// # Errors
    /// Returns an error if the underlying store fails.
    #[must_use = "the provisioning result must be checked"]
    fn provision_user_with_password(
        &self,
        input: Self::NewUser,
        identifier: &str,
        password_hash: &str,
    ) -> Result<Option<Self::User>, AuthError>;
}
