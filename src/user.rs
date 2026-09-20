//! User identity trait.

use std::fmt::Debug;

/// The user identity trait.
///
/// Applications implement this to provide user data to the authentication system.
pub trait AuthUser: Debug + Send + Sync + 'static {
    /// Returns the unique identifier for this user.
    fn id(&self) -> String;
    /// Returns the user's display name.
    fn display_name(&self) -> Option<String>;
    /// Clones this user as a trait object.
    fn clone_box(&self) -> Box<dyn AuthUser>;
}
