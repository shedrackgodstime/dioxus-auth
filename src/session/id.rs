use std::fmt;

/// Opaque session identifier.
///
/// On the wire (cookie, bearer header) this is the raw 256-bit token.
/// In storage the lookup key is `sha256(raw)`. A leaked store therefore
/// cannot be used to hijack active sessions.
///
/// `Debug` and `Display` are **redacted**: they never render the raw token,
/// so accidentally logging a session id cannot leak a hijackable credential.
/// Use [`SessionId::as_str`] / [`SessionId::into_string`] at the (rare)
/// points where the wire value is genuinely needed.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SessionId(String);

impl SessionId {
    /// Create a session ID from an existing string (raw wire token).
    ///
    /// Infallible by design (storage layer, tests). Wire input is validated
    /// separately — see [`SessionId::is_valid_wire_format`].
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Whether `token` has the exact shape [`SessionId::generate`] mints:
    /// 64 lowercase hex characters (a 256-bit CSPRNG value).
    ///
    /// Applied to **wire** input (bearer/cookie extraction) before any
    /// hashing or lookup, so oversized or malformed cookie values are cheap
    /// rejections instead of unbounded `sha256` work.
    pub fn is_valid_wire_format(token: &str) -> bool {
        token.len() == 64
            && token
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }

    /// Generate a new cryptographically secure random session ID (256-bit CSPRNG hex string).
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(hex::encode(bytes))
    }

    /// Compute the storage form: `sha256(raw)` as a lowercase hex string.
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
        // Redacted: the raw token must never reach a log line (F9 / C-F4).
        f.write_str("***")
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionId(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_do_not_leak_the_raw_token() {
        let id = SessionId::generate();
        let raw = id.as_str().to_string();
        assert!(!raw.is_empty());
        assert!(!format!("{id:?}").contains(&raw));
        assert!(!format!("{id}").contains(&raw));
        assert_eq!(format!("{id}"), "***");
        assert_eq!(format!("{id:?}"), "SessionId(***)");
    }

    #[test]
    fn wire_format_validation() {
        assert!(SessionId::is_valid_wire_format(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        // Wrong length, non-hex, uppercase, empty — all invalid.
        assert!(!SessionId::is_valid_wire_format("abc"));
        assert!(!SessionId::is_valid_wire_format(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"
        ));
        assert!(!SessionId::is_valid_wire_format(
            "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(!SessionId::is_valid_wire_format(""));
    }
}
