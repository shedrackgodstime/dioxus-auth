use crate::error::AuthResult;
use crate::transport::token::TokenStorage;

/// `localStorage`-backed [`TokenStorage`] for web clients.
///
/// Stores the raw session token under the given key. Only available when the
/// `dioxus-auth` crate is compiled for `wasm32` because `localStorage` is a
/// browser API.
pub struct WebTokenStorage {
    key: &'static str,
}

impl WebTokenStorage {
    /// The default storage key used by the web demo and by the recommended
    /// application integration.
    pub const DEFAULT_KEY: &'static str = "dioxus_auth_session";

    /// Create a new `WebTokenStorage` with a custom `localStorage` key.
    pub fn new(key: &'static str) -> Self {
        Self { key }
    }
}

impl Default for WebTokenStorage {
    fn default() -> Self {
        Self::new(Self::DEFAULT_KEY)
    }
}

impl TokenStorage for WebTokenStorage {
    fn load(&self) -> Option<String> {
        web_local_storage_get(self.key)
    }

    fn save(&self, token: &str) -> AuthResult<()> {
        web_local_storage_set(self.key, token)
    }

    fn clear(&self) {
        web_local_storage_remove(self.key);
    }
}

fn web_local_storage_get(key: &str) -> Option<String> {
    let window = web_sys::window()?;
    let storage = window.local_storage().ok()??;
    storage.get_item(key).ok().flatten()
}

fn web_local_storage_set(key: &str, value: &str) -> AuthResult<()> {
    let window = web_sys::window()
        .ok_or_else(|| crate::error::AuthError::Store("no window object available".to_string()))?;
    let storage = window
        .local_storage()
        .map_err(|e| crate::error::AuthError::Store(format!("localStorage error: {e:?}")))?
        .ok_or_else(|| crate::error::AuthError::Store("localStorage unavailable".to_string()))?;
    storage
        .set_item(key, value)
        .map_err(|e| crate::error::AuthError::Store(format!("localStorage set error: {e:?}")))?;
    Ok(())
}

fn web_local_storage_remove(key: &str) {
    if let Some(window) = web_sys::window() {
        if let Ok(Some(storage)) = window.local_storage() {
            let _ = storage.remove_item(key);
        }
    }
}
