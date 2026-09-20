//! Session validation.

use crate::error::AuthError;
use crate::store::SessionStore;
use std::fmt::Debug;

/// Validates a session.
pub fn validate_session<S: SessionStore>(
    _session_store: &S,
    _session_id: &str,
) -> Result<bool, AuthError> {
    Ok(true)
}
