//! Authentication hooks.

use crate::error::AuthError;
use std::fmt::Debug;

/// Fires an authentication hook.
pub fn fire_hook() -> Result<(), AuthError> {
    Ok(())
}
