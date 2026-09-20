//! Authentication status and session identifiers.

use std::fmt::{self, Display};

/// The authentication status of a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthStatus<U> {
    /// The user is authenticated.
    Authenticated(U),
    /// The user is a guest with no authenticated identity.
    Guest,
    /// The user is loading their authentication state.
    Loading,
}

/// Opaque session identifier.
///
/// On the wire (cookie, bearer header) this is the raw 256-bit token.
/// In storage the lookup key is `sha256(raw)`. A leaked store therefore
/// cannot be used to hijack active sessions.
///
/// `Debug` and `Display` are **redacted**: they never render the raw token,
/// so accidentally logging a session id cannot leak a hijackable credential.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SessionId(String);

impl SessionId {
    /// Creates a session ID from an existing string (raw wire token).
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Whether `token` has the exact shape [`SessionId::generate`] mints:
    /// 64 lowercase hex characters (a 256-bit CSPRNG value).
    ///
    /// Applied to wire input (bearer/cookie extraction) before any hashing or
    /// lookup, so oversized or malformed inputs are cheap rejections.
    #[must_use]
    pub fn is_valid_wire_format(token: &str) -> bool {
        token.len() == 64
            && token
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }

    /// Generates a new cryptographically secure random session ID
    /// (256-bit CSPRNG hex string).
    #[must_use]
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};

        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(hex::encode(bytes))
    }

    /// Computes the storage form: `sha256(raw)` as a lowercase hex string.
    #[must_use]
    pub fn hash_for_storage(&self) -> Self {
        use sha2::{Digest, Sha256};

        let digest = Sha256::digest(self.0.as_bytes());
        Self(hex::encode(digest))
    }

    /// Borrows the session ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Converts into the underlying string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionId(***)")
    }
}