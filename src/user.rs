//! User identity trait.

use std::fmt::Debug;
use std::hash::Hash;

/// The user identity trait.
///
/// Applications implement this to provide user data to the authentication system.
/// The crate is generic over this trait, so application domain logic
/// (roles, subscriptions, profile fields) stays entirely on the user type.
///
/// Two methods only: [`AuthUser::id`] is the stable unique identifier
/// (e.g. `u64`, `Uuid`, `String`) and [`AuthUser::email`] is the login
/// identifier. The email is the credential key: `sign_up_email`/
/// `sign_in_email` look the user up by it, and the engine normalizes it once
/// (trim + lowercase) before any store call — stores compare byte-for-byte
/// and never fold case or whitespace themselves. `Clone` replaces the old
/// manual `clone_box`; a display name defaults to the email at the
/// presentation layer.
pub trait AuthUser: Clone + Debug + Send + Sync + 'static {
    /// Stable unique identifier for the user (e.g. `u64`, `Uuid`, `String`).
    type Id: Clone + Eq + Hash + Debug + Send + Sync + 'static;

    /// Returns the user's unique identifier.
    #[must_use]
    fn id(&self) -> Self::Id;

    /// Returns the user's login identifier (the email address).
    #[must_use]
    fn email(&self) -> &str;

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
}
