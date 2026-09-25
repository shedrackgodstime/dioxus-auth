//! User identity trait.

use std::fmt::Debug;

/// The application user contract for resolver-backed stores.
///
/// Applications implement this on their user type so resolving stores can
/// persist app rows keyed by [`AuthUser::id`] and hand them back through
/// [`UserStore::resolve`](crate::store::UserStore::resolve). The engine
/// itself never reads this trait: it authenticates subjects and returns
/// application keys, leaving model interpretation to the application
/// (loader closures) or the resolving store. Login identifiers travel as
/// separate `&str` arguments on the credential verbs; the engine
/// normalizes them once (trim plus lowercase) before any store call, and
/// stores compare byte-for-byte without folding case or whitespace
/// themselves. Session binding lives on the subject row as the stored
/// secret itself, so no per-user hook is needed for rotation.
pub trait AuthUser: Clone + Debug + Send + Sync + 'static {
    /// Stable application-row identifier (e.g. `u64`, `Uuid`, `String`).
    type Id: Clone + Eq + Debug + Send + Sync + 'static;

    /// Returns the application-row identifier.
    #[must_use]
    fn id(&self) -> Self::Id;
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
