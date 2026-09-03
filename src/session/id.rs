use std::fmt;

/// Opaque, cryptographically secure session identifier.
///
/// On the wire (cookie, bearer header) this is the raw 256-bit CSPRNG token.
/// In storage (DB, memory) the lookup key is `sha256(raw)` — a leaked store
/// cannot be used to hijack active sessions.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SessionId(String);

impl SessionId {
    /// Create a session ID from an existing string (raw wire token).
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Generate a new cryptographically secure random session ID (256-bit CSPRNG hex string).
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(hex::encode(bytes))
    }

    /// Compute the storage form of this session ID: `sha256(raw)` as a lowercase hex string.
    ///
    /// The wire always carries the raw token. The store always keys by the hash.
    /// A leaked store therefore yields no session-hijackable secrets.
    pub fn hash_for_storage(&self) -> SessionId {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(self.0.as_bytes());
        SessionId(hex::encode(digest))
    }

    /// Borrow the session ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert into the underlying `String`.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
