use std::sync::Mutex;

use crate::error::AuthResult;
use crate::transport::token::TokenStorage;

/// In-memory, thread-safe [`TokenStorage`].
///
/// Useful for tests, ephemeral desktop sessions, and the default fallback. The
/// token does not survive process restart.
#[derive(Debug, Default)]
pub struct MemoryTokenStorage {
    token: Mutex<Option<String>>,
}

impl MemoryTokenStorage {
    /// Create a new empty in-memory token storage.
    pub fn new() -> Self {
        Self {
            token: Mutex::new(None),
        }
    }
}

impl TokenStorage for MemoryTokenStorage {
    fn load(&self) -> Option<String> {
        self.token.lock().ok().and_then(|guard| guard.clone())
    }

    fn save(&self, token: &str) -> AuthResult<()> {
        let mut guard = self
            .token
            .lock()
            .map_err(|e| crate::error::AuthError::Store(e.to_string()))?;
        *guard = Some(token.to_string());
        Ok(())
    }

    fn clear(&self) {
        if let Ok(mut guard) = self.token.lock() {
            *guard = None;
        }
    }
}
