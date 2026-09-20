//! Login operation.

use crate::error::AuthError;
use crate::store::PasswordHasher;
use crate::store::SessionStore;
use crate::store::UserStore;
use std::fmt::Debug;

/// Performs user login.
pub fn login<U: UserStore, P: PasswordHasher, S: SessionStore>(
    _user_store: &U,
    _password_hasher: &P,
    _session_store: &S,
    _identifier: &str,
    _password: &str,
) -> Result<(), AuthError> {
    Ok(())
}
