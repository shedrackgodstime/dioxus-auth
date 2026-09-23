//! Interior-mutable token storage handle named in component props.

use std::fmt;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::error::AuthError;
use crate::transport::TokenStorage;

/// Shared token-storage handle for components and context.
///
/// Exposes `&mut self` operations through a shared lock, so both sides share
/// one storage.
///
/// The `Box<dyn TokenStorage>` erasure is load-bearing: component props must
/// name a concrete type.
///
/// `PartialEq` compares the shared `Arc` identity; the stored token contents
/// are deliberately not part of prop diffing.
#[derive(Clone)]
pub struct TokenStorageHandle(pub(crate) Arc<Mutex<Box<dyn TokenStorage>>>);

impl TokenStorageHandle {
    /// Wraps a token storage implementation.
    #[must_use]
    pub fn new(storage: impl TokenStorage + 'static) -> Self {
        return Self(Arc::new(Mutex::new(Box::new(storage))));
    }

    /// Stores a token.
    ///
    /// # Errors
    /// Returns an error if the underlying storage fails.
    #[must_use = "a failed storage write must be handled"]
    pub fn store(&self, token: &str) -> Result<(), AuthError> {
        return self.0.lock().store(token);
    }

    /// Retrieves the stored token.
    ///
    /// # Errors
    /// Returns an error if the underlying storage fails.
    #[must_use = "the stored token must be used"]
    pub fn retrieve(&self) -> Result<Option<String>, AuthError> {
        return self.0.lock().retrieve();
    }

    /// Clears the stored token.
    ///
    /// # Errors
    /// Returns an error if the underlying storage fails.
    #[must_use = "a failed storage clear must be handled"]
    pub fn clear(&self) -> Result<(), AuthError> {
        return self.0.lock().clear();
    }
}

impl fmt::Debug for TokenStorageHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return f.write_str("TokenStorageHandle(..)");
    }
}

impl PartialEq for TokenStorageHandle {
    // reason: the token contents are transient state owned by the storage, not
    // component props; identity equality keeps prop diffing cheap and stable.
    fn eq(&self, other: &Self) -> bool {
        return Arc::ptr_eq(&self.0, &other.0);
    }
}

impl Eq for TokenStorageHandle {}
