//! In-memory user store.

use crate::error::AuthError;
use crate::user::AuthUser;
use std::fmt::Debug;

/// In-memory user store implementation.
#[derive(Debug, Default)]
pub struct MemoryUserStore {
    users: Vec<Box<dyn AuthUser>>,
}

impl MemoryUserStore {
    /// Creates a new in-memory user store.
    #[must_use]
    pub fn new() -> Self {
        MemoryUserStore { users: Vec::new() }
    }
    /// Adds a user to the store.
    pub fn add(&mut self, user: Box<dyn AuthUser>) {
        self.users.push(user);
    }
}

impl crate::store::UserStore for MemoryUserStore {
    fn find_by_id(&self, id: &str) -> Result<Option<Box<dyn AuthUser>>, AuthError> {
        for user in &self.users {
            if user.id() == id {
                return Ok(Some(user.clone_box()));
            }
        }
        Ok(None)
    }
    fn find_by_credentials(
        &self,
        _identifier: &str,
        _password: &str,
    ) -> Result<Option<Box<dyn AuthUser>>, AuthError> {
        Ok(None)
    }
}

/// A concrete in-memory user.
#[derive(Debug)]
pub struct MemoryUser {
    id: String,
    display_name: Option<String>,
}

impl MemoryUser {
    /// Creates a new memory user.
    #[must_use]
    pub fn new(id: String, display_name: Option<String>) -> Self {
        MemoryUser { id, display_name }
    }
}

impl AuthUser for MemoryUser {
    fn id(&self) -> String {
        self.id.clone()
    }
    fn display_name(&self) -> Option<String> {
        self.display_name.clone()
    }
    fn clone_box(&self) -> Box<dyn AuthUser> {
        Box::new(MemoryUser {
            id: self.id.clone(),
            display_name: self.display_name.clone(),
        })
    }
}
