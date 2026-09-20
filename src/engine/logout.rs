//! Logout operation.

use crate::error::AuthError;
use crate::store::SessionStore;
use std::fmt::Debug;

/// Performs user logout.
pub fn logout<S: SessionStore>(_session_store: &S, _session_id: &str) -> Result<(), AuthError> {
    Ok(())
}
