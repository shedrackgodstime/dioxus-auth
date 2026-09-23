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
/// Wraps a shared [`AuthEngine`] so application
/// setup names one type instead of three. `Clone` shares the engine through
/// the inner `Arc`; it never clones the stores.
pub struct Auth<D>
where
    D: UserStore + SessionStore<Id = <D as UserStore>::Id>,
{
    pub(crate) engine: Arc<AuthEngine<D, D>>,
    #[cfg(feature = "dioxus")]
    pub(crate) erased_engine: Option<crate::dioxus::AuthEngineHandle<D::User>>,
    #[cfg(feature = "dioxus")]
    pub(crate) token_storage: Option<crate::dioxus::TokenStorageHandle>,
}

impl<D> Clone for Auth<D>
where
    D: UserStore + SessionStore<Id = <D as UserStore>::Id>,
{
    fn clone(&self) -> Self {
        return Self {
            engine: Arc::clone(&self.engine),
            #[cfg(feature = "dioxus")]
            erased_engine: self.erased_engine.clone(),
            #[cfg(feature = "dioxus")]
            token_storage: self.token_storage.clone(),
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

impl<D> PartialEq for Auth<D>
where
    D: UserStore + SessionStore<Id = <D as UserStore>::Id>,
{
    fn eq(&self, other: &Self) -> bool {
        // The facade shares its engine through the inner `Arc`; `Arc` identity
        // is the sound equivalence for prop diffing.
        return Arc::ptr_eq(&self.engine, &other.engine);
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
    /// The store serves both the user and session roles, and is shared
    /// internally — callers pass it by value, never behind an `Arc`. Uses the
    /// default Argon2id hasher and 7-day session TTL; deployments that need
    /// custom hashers, TTLs, or split roles keep using
    /// [`AuthEngine`] directly.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::{Auth, AuthUser, MemoryStore};
    /// # #[derive(Debug, Clone)]
    /// # struct User;
    /// # impl AuthUser for User {
    /// #     type Id = u64;
    /// #     fn id(&self) -> u64 { return 1; }
    /// #     fn email(&self) -> &str { return "user@example.com"; }
    /// # }
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
    /// let auth = Auth::new(MemoryStore::<User>::new())?;
    /// assert_eq!(auth.engine().session_ttl_secs(), 60 * 60 * 24 * 7);
    /// # return Ok(());
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns `AuthError` if the default hasher cannot pre-compute the
    /// timing-defense dummy hash.
    #[must_use = "the constructed facade must be used"]
    pub fn new(db: D) -> Result<Self, AuthError> {
        let db = Arc::new(db);
        let engine = match AuthEngine::new(Arc::clone(&db), db) {
            Ok(engine) => engine,
            Err(error) => return Err(error),
        };
        return Ok(Self {
            engine: Arc::new(engine),
            #[cfg(feature = "dioxus")]
            erased_engine: None,
            #[cfg(feature = "dioxus")]
            token_storage: None,
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
    /// # use dioxus_auth::{Auth, AuthEngine, AuthUser, MemoryStore};
    /// # use std::sync::Arc;
    /// # #[derive(Debug, Clone)]
    /// # struct User;
    /// # impl AuthUser for User {
    /// #     type Id = u64;
    /// #     fn id(&self) -> u64 { return 1; }
    /// #     fn email(&self) -> &str { return "user@example.com"; }
    /// # }
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
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
            #[cfg(feature = "dioxus")]
            erased_engine: None,
            #[cfg(feature = "dioxus")]
            token_storage: None,
        };
    }
}

#[cfg(feature = "dioxus")]
impl<D> Auth<D>
where
    D: UserStore + SessionStore<Id = <D as UserStore>::Id>,
{
    /// Attaches a pre-seeded token storage so [`AuthProvider`](crate::dioxus::AuthProvider) restores from
    /// it instead of a fresh empty one. Tests use this to seed a valid token;
    /// production door-1 code never calls it (the provider defaults to an
    /// empty in-memory storage).
    #[must_use = "the returned facade must be used"]
    pub fn with_token_storage(mut self, storage: crate::dioxus::TokenStorageHandle) -> Self {
        self.token_storage = Some(storage);
        return self;
    }

    /// Wraps an already-erased engine handle so tests and advanced call sites
    /// can mount the provider over a type-erased `AuthOperations`
    /// implementation (failure injection, custom engines) without a concrete
    /// store type.
    ///
    /// Requires `D: Default` only to build the throwaway concrete placeholder
    /// the struct's field type demands; [`AuthProvider`](crate::dioxus::AuthProvider) reads
    /// the `erased_engine` handle first and never touches the placeholder.
    ///
    /// # Errors
    /// Returns `AuthError` if the default hasher cannot pre-compute the
    /// timing-defense dummy hash for the placeholder engine.
    #[must_use = "the constructed facade must be used"]
    pub fn from_erased(handle: crate::dioxus::AuthEngineHandle<D::User>) -> Result<Self, AuthError>
    where
        D: Default,
    {
        let placeholder = match Self::placeholder_engine() {
            Ok(engine) => engine,
            Err(error) => return Err(error),
        };
        return Ok(Self {
            engine: placeholder,
            erased_engine: Some(handle),
            token_storage: None,
        });
    }

    /// Builds a throwaway concrete engine for type-checking only; never
    /// dereferenced when the `erased_engine` handle is `Some`.
    fn placeholder_engine() -> Result<Arc<AuthEngine<D, D>>, AuthError>
    where
        D: Default,
    {
        let store: Arc<D> = Arc::new(D::default());
        return match AuthEngine::new(Arc::clone(&store), store) {
            Ok(engine) => Ok(Arc::new(engine)),
            Err(error) => Err(error),
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
    /// # use dioxus_auth::{Auth, AuthUser, MemoryStore};
    /// # #[derive(Debug, Clone)]
    /// # struct User;
    /// # impl AuthUser for User {
    /// #     type Id = u64;
    /// #     fn id(&self) -> u64 { return 1; }
    /// #     fn email(&self) -> &str { return "user@example.com"; }
    /// # }
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
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
        return Self::new(MemoryStore::<User>::new());
    }
}
