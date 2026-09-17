//! Access the optional token storage provided by `AuthProvider`.

use std::sync::Arc;

use dioxus::prelude::*;

use crate::transport::TokenStorage;

/// Access the optional [`TokenStorage`] provided by [`crate::dioxus::AuthProvider`].
///
/// Returns `None` if the app did not provide a storage backend.
pub fn use_token_storage() -> Option<Arc<dyn TokenStorage>> {
    use_context::<Option<Arc<dyn TokenStorage>>>()
}
