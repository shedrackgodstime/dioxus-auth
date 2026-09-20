//! User identity trait.

use std::fmt::Debug;
use std::hash::Hash;

/// The user identity trait.
///
/// Applications implement this to provide user data to the authentication system.
/// The crate is generic over this trait, so application domain logic
/// (roles, subscriptions, profile fields) stays entirely on the user type.
pub trait AuthUser: Debug + Send + Sync + 'static {
    /// Stable unique identifier for the user (e.g. `u64`, `Uuid`, `String`).
    type Id: Clone + Eq + Hash + Debug + Send + Sync + 'static;

    /// Returns the user's unique identifier.
    #[must_use]
    fn id(&self) -> Self::Id;

    /// Returns the user's display name.
    #[must_use]
    fn display_name(&self) -> Option<String>;

    /// Opaque value that binds sessions to a known password (or other secret
    /// material) state.
    ///
    /// When a user's password changes, this value changes and every session
    /// bound to the old value is rejected. Return `None` when the application
    /// enforces credential binding through other means (e.g. store-side
    /// checks or token versions).
    #[must_use]
    fn session_auth_hash(&self) -> Option<&str> {
        return None;
    }

    /// Clones this user as a trait object.
    #[must_use]
    fn clone_box(&self) -> Box<dyn AuthUser<Id = Self::Id>>;
}
