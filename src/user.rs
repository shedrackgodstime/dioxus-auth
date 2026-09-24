//! User identity trait.

use std::fmt::Debug;
use std::hash::Hash;

/// The user identity trait.
///
/// Applications implement this to provide user data to the authentication system.
/// The crate is generic over this trait, so application domain logic
/// (roles, subscriptions, profile fields) stays entirely on the user type.
///
/// This is the session-owner contract, nothing more: [`AuthUser::id`] is the
/// stable unique identifier (e.g. `u64`, `Uuid`, `String`) that sessions point
/// at and that [`UserStore`](crate::store::UserStore) rehydrates through
/// `find_by_id`. Login identifiers travel as separate `&str` arguments on the
/// credential verbs (`sign_up_email`/`sign_in_email`); the engine normalizes
/// them once (trim plus lowercase) before any store call, and stores compare
/// byte-for-byte without folding case or whitespace themselves. The user
/// struct carries every other field (email, name, roles, …) as plain
/// application data the engine never reads. `Clone` lets the engine hand
/// identities to callers.
pub trait AuthUser: Clone + Debug + Send + Sync + 'static {
    /// Stable unique identifier for the user (e.g. `u64`, `Uuid`, `String`).
    type Id: Clone + Eq + Hash + Debug + Send + Sync + 'static;

    /// Returns the user's unique identifier.
    #[must_use]
    fn id(&self) -> Self::Id;

    /// Opaque value that binds sessions to a known password (or other secret
    /// material) state.
    ///
    /// When a user's password changes, this value changes and every session
    /// bound to the old value is rejected on next validation or login.
    /// Implement this when credentials change outside
    /// [`Auth::change_password`](crate::auth::Auth::change_password) (direct
    /// store writes, admin resets, external providers): that verb revokes all
    /// sessions explicitly, but out-of-band changes leave old sessions alive
    /// until TTL expiry unless this binding catches them. Return `None` when
    /// every credential change flows through `change_password` or the
    /// application enforces binding through other means (e.g. store-side
    /// checks or token versions).
    #[must_use]
    fn session_auth_hash(&self) -> Option<&str> {
        return None;
    }
}

/// Row type behind the zero-modeling quickstart.
///
/// This is plumbing, not a model to grow: [`Auth::memory`](crate::auth::Auth::memory)
/// hands these back from signup/sign-in, and graduating means bringing your
/// own user type plus your own store: nothing here renames or migrates.
/// Sessions are opaque and user-type-agnostic; authentication reads only the
/// `id`, and `email`/`name` are plain carried data.
///
/// Memory-backed deployments are non-durable by definition: everything dies
/// with the process. Memory is for prototyping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultUser {
    /// Stable unique identifier.
    pub id: u64,
    /// Application login identifier (mirrors the signup identifier by convention).
    pub email: String,
    /// Display name.
    pub name: String,
}

impl AuthUser for DefaultUser {
    type Id = u64;

    fn id(&self) -> Self::Id {
        return self.id;
    }
}

/// Creation input for the zero-modeling quickstart.
///
/// [`Auth::memory`](crate::auth::Auth::memory) signup takes this instead of a
/// finished [`DefaultUser`]: the developer supplies only the display name,
/// and the default store generates the id and derives the email from the
/// signup identifier. No primary-key thought, no struct completion, no trait
/// to implement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultUserInput {
    /// Display name for the created user.
    pub name: String,
}

impl DefaultUserInput {
    /// Creates quickstart signup input from a display name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        return Self { name: name.into() };
    }
}
