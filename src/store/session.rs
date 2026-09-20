//! In-memory session store.

use crate::error::AuthError;
use crate::status::SessionId;
use crate::status::SessionRecord;
use std::fmt::Debug;

/// In-memory session store implementation.
#[derive(Debug, Default)]
pub struct MemorySessionStore {
    sessions: Vec<SessionRecord>,
}

impl MemorySessionStore {
    /// Creates a new in-memory session store.
    #[must_use]
    pub fn new() -> Self {
        MemorySessionStore {
            sessions: Vec::new(),
        }
    }
}

impl crate::store::SessionStore for MemorySessionStore {
    fn create(&self, _user_id: &str) -> Result<SessionId, AuthError> {
        let id = SessionId::new(String::from("session-id"));
        Ok(id)
    }
    fn get(&self, _id: &SessionId) -> Result<Option<SessionRecord>, AuthError> {
        Ok(None)
    }
    fn delete(&self, _id: &SessionId) -> Result<(), AuthError> {
        Ok(())
    }
}
