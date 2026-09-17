//! Free helper functions around [`crate::transport::TokenStorage`] — plain
//! functions (not hooks) that read the storage context from the current
//! component.

use crate::dioxus::hooks::use_token_storage;

/// Persist a raw session token to [`crate::transport::TokenStorage`], if available.
///
/// Silently ignores errors.
pub fn persist_token(raw_token: &str) {
    if let Some(storage) = use_token_storage() {
        let _ = storage.save(raw_token);
    }
}

/// Clear [`crate::transport::TokenStorage`], if available.
///
/// Silently ignores errors.
pub fn clear_persisted_token() {
    if let Some(storage) = use_token_storage() {
        storage.clear();
    }
}
