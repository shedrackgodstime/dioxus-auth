use crate::error::AuthResult;

/// Client-side persistence for the raw session token.
///
/// On the web, the browser cookie jar often already provides this; an
/// implementation backed by `localStorage` is provided for SPAs that prefer
/// Bearer-style flows. On desktop and mobile, the token lives in a
/// `FileTokenStorage` (0600) today, and OS keychain implementations may plug in
/// later without changing the trait.
///
/// `TokenStorage` is **client persistence**. [`crate::storage::SessionStore`] is
/// **server persistence**. Do not merge them.
pub trait TokenStorage: Send + Sync + 'static {
    /// Load the previously saved raw session token, if any.
    fn load(&self) -> Option<String>;

    /// Persist the raw session token. The implementation must be safe to call
    /// on the current platform (e.g. `FileTokenStorage` enforces 0600 perms).
    fn save(&self, token: &str) -> AuthResult<()>;

    /// Clear any persisted session token.
    fn clear(&self);
}
