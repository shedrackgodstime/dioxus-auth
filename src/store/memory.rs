//! In-memory key-value store.

use crate::error::AuthError;
use crate::store::MemoryStore;
use std::collections::BTreeMap;
use std::fmt::Debug;

/// The default in-memory key-value store.
#[derive(Debug, Default)]
pub struct InMemoryMemoryStore {
    data: BTreeMap<String, String>,
}

impl InMemoryMemoryStore {
    /// Creates a new in-memory store.
    #[must_use]
    pub fn new() -> Self {
        InMemoryMemoryStore {
            data: BTreeMap::new(),
        }
    }
}

impl MemoryStore for InMemoryMemoryStore {
    fn put(&mut self, key: &str, value: String) -> Result<(), AuthError> {
        let _ = self.data.insert(key.to_string(), value);
        Ok(())
    }
    fn get(&self, key: &str) -> Result<Option<String>, AuthError> {
        Ok(self.data.get(key).cloned())
    }
}
