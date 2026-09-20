//! The `AuthUser` identity contract every host application implements.

use std::hash::Hash;

/// Minimal identity contract a host application's user type must satisfy for
/// `dioxus-auth` to drive sessions for it.
///
/// Implemented manually for your user type. The crate is generic over
/// this trait, so application domain logic (roles, subscriptions,
/// profile fields) stays entirely on the user type.
pub trait AuthUser: Clone + Send + Sync + 'static {
    /// Stable unique identifier for the user (e.g. `u64`, `Uuid`, `String`).
    type Id: Clone + Eq + Hash + Send + Sync + 'static;

    /// Return the user's unique identifier.
    fn id(&self) -> Self::Id;

    /// Opaque value that binds sessions to a known password (or other secret
    /// material) state.
    ///
    /// When a user's password changes, this value changes and every session
    /// bound to the old value is rejected. Return `None` when the application
    /// enforces credential binding through other means (e.g. store-side
    /// checks or token versions).
    fn session_auth_hash(&self) -> Option<&str> {
        None
    }
}
