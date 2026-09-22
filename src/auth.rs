//! Entry facade over the authentication engine.
//!
//! Beginners meet [`Auth`]; the engine underneath stays unchanged. One store
//! serves both the user and session roles here — deployments that split the
//! roles or need custom hashers, limits, or clocks build an engine with the
//! [`AuthEngineBuilder`](crate::builder::AuthEngineBuilder) and wrap it with
//! [`Auth::from_engine`].

use std::fmt;
use std::sync::Arc;

use crate::engine::AuthEngine;
use crate::error::AuthError;
use crate::store::{MemoryStore, SessionStore, UserStore};
use crate::user::AuthUser;

/// Entry point for authentication.
///
/// Wraps a shared [`AuthEngine`](crate::engine::AuthEngine) so application
/// setup names one type instead of three. `Clone` shares the engine through
/// the inner `Arc`; it never clones the stores.
pub struct Auth<D>
where
    D: UserStore + SessionStore<Id = <D as UserStore>::Id>,
{
    pub(crate) engine: Arc<AuthEngine<D, D>>,
}

impl<D> Clone for Auth<D>
where
    D: UserStore + SessionStore<Id = <D as UserStore>::Id>,
{
    fn clone(&self) -> Self {
        return Self {
            engine: Arc::clone(&self.engine),
        };
    }
}

impl<D> fmt::Debug for Auth<D>
where
    D: UserStore + SessionStore<Id = <D as UserStore>::Id>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return f.debug_tuple("Auth").field(&self.engine).finish();
    }
}

impl<D> Auth<D>
where
    D: UserStore + SessionStore<Id = <D as UserStore>::Id>,
{
    /// Accesses the underlying engine.
    #[must_use]
    pub const fn engine(&self) -> &Arc<AuthEngine<D, D>> {
        return &self.engine;
    }

    /// Creates authentication over the given store.
    ///
    /// The store serves both the user and session roles. Uses the default
    /// Argon2id hasher and 7-day session TTL; deployments that need custom
    /// hashers, TTLs, or split roles keep using
    /// [`AuthEngine`](crate::engine::AuthEngine) directly.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::prelude::{Auth, AuthUser, MemoryStore};
    /// # use std::sync::Arc;
    /// # #[derive(Debug, Clone)]
    /// # struct User;
    /// # impl AuthUser for User {
    /// #     type Id = u64;
    /// #     fn id(&self) -> u64 { return 1; }
    /// #     fn display_name(&self) -> Option<String> { return None; }
    /// #     fn clone_box(&self) -> Box<dyn AuthUser<Id = u64>> { return Box::new(Self); }
    /// # }
    /// # fn main() -> Result<(), dioxus_auth::prelude::AuthError> {
    /// let db = Arc::new(MemoryStore::<User>::new());
    /// let auth = Auth::new(db)?;
    /// assert_eq!(auth.engine().session_ttl_secs(), 60 * 60 * 24 * 7);
    /// # return Ok(());
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns `AuthError` if the default hasher cannot pre-compute the
    /// timing-defense dummy hash.
    #[must_use = "the constructed facade must be used"]
    pub fn new(db: Arc<D>) -> Result<Self, AuthError> {
        let engine = match AuthEngine::new(Arc::clone(&db), db) {
            Ok(engine) => engine,
            Err(error) => return Err(error),
        };
        return Ok(Self {
            engine: Arc::new(engine),
        });
    }

    /// Wraps an already-configured engine (the door-3 escape).
    ///
    /// The engine is configured through
    /// [`AuthEngine::builder`](crate::engine::AuthEngine::builder) — custom
    /// hashers, rate limiters, hooks, clocks, split stores — and then handed
    /// here so method verbs work on it unchanged.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::prelude::{Auth, AuthEngine, AuthUser, MemoryStore};
    /// # use std::sync::Arc;
    /// # #[derive(Debug, Clone)]
    /// # struct User;
    /// # impl AuthUser for User {
    /// #     type Id = u64;
    /// #     fn id(&self) -> u64 { return 1; }
    /// #     fn display_name(&self) -> Option<String> { return None; }
    /// #     fn clone_box(&self) -> Box<dyn AuthUser<Id = u64>> { return Box::new(Self); }
    /// # }
    /// # fn main() -> Result<(), dioxus_auth::prelude::AuthError> {
    /// # let db = Arc::new(MemoryStore::<User>::new());
    /// let engine = AuthEngine::builder(Arc::clone(&db), db).build()?;
    /// let auth = Auth::from_engine(engine);
    /// assert_eq!(auth.engine().session_ttl_secs(), 60 * 60 * 24 * 7);
    /// # return Ok(());
    /// # }
    /// ```
    #[must_use = "the constructed facade must be used"]
    pub fn from_engine(engine: AuthEngine<D, D>) -> Self {
        return Self {
            engine: Arc::new(engine),
        };
    }
}

impl<User> Auth<MemoryStore<User>>
where
    User: AuthUser + Clone,
{
    /// Creates in-memory authentication for the given user type.
    ///
    /// Uses [`MemoryStore`] for both roles with the default Argon2id hasher
    /// and 7-day session TTL. Suitable for quickstarts and tests; production
    /// deployments pass a persistent store to [`Auth::new`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::prelude::{Auth, AuthUser, MemoryStore};
    /// # #[derive(Debug, Clone)]
    /// # struct User;
    /// # impl AuthUser for User {
    /// #     type Id = u64;
    /// #     fn id(&self) -> u64 { return 1; }
    /// #     fn display_name(&self) -> Option<String> { return None; }
    /// #     fn clone_box(&self) -> Box<dyn AuthUser<Id = u64>> { return Box::new(Self); }
    /// # }
    /// # fn main() -> Result<(), dioxus_auth::prelude::AuthError> {
    /// let auth = Auth::<MemoryStore<User>>::memory()?;
    /// assert_eq!(auth.engine().session_ttl_secs(), 60 * 60 * 24 * 7);
    /// # return Ok(());
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns `AuthError` if the default hasher cannot pre-compute the
    /// timing-defense dummy hash.
    #[must_use = "the constructed facade must be used"]
    pub fn memory() -> Result<Self, AuthError> {
        let db = Arc::new(MemoryStore::<User>::new());
        return Self::new(db);
    }
}
