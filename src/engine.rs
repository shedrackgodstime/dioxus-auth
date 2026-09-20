//! Authentication engine and core operations.

pub mod hooks;
pub mod login;
pub mod logout;
pub mod validate;

use crate::error::AuthError;
use crate::status::SessionId;
use std::fmt::Debug;

/// The main authentication engine.
#[derive(Debug)]
pub struct AuthEngine {
    user_store: Option<Box<dyn crate::store::UserStore>>,
    session_store: Option<Box<dyn crate::store::SessionStore>>,
    password_hasher: Option<Box<dyn crate::store::PasswordHasher>>,
}

impl AuthEngine {
    /// Creates a new authentication engine.
    #[must_use]
    pub fn new() -> Self {
        AuthEngine {
            user_store: None,
            session_store: None,
            password_hasher: None,
        }
    }
}
