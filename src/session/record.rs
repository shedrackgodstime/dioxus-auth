use crate::session::id::SessionId;

/// Server-side session record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session<UserId> {
    id: SessionId,
    user_id: UserId,
    created_at_unix: u64,
    expires_at_unix: u64,
    auth_hash: Option<String>,
}

impl<UserId> Session<UserId> {
    /// Create a new session record.
    pub fn new(id: SessionId, user_id: UserId, created_at_unix: u64, expires_at_unix: u64) -> Self {
        Self {
            id,
            user_id,
            created_at_unix,
            expires_at_unix,
            auth_hash: None,
        }
    }

    /// Attach a security hash (e.g. password hash or token version) for automatic revocation upon password change.
    pub fn with_auth_hash(mut self, auth_hash: impl Into<String>) -> Self {
        self.auth_hash = Some(auth_hash.into());
        self
    }

    /// Access the unique session identifier.
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// Access the associated user identifier.
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Unix timestamp (seconds) when the session was created.
    pub fn created_at_unix(&self) -> u64 {
        self.created_at_unix
    }

    /// Unix timestamp (seconds) when the session expires.
    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    /// Access the optional session authentication hash.
    pub fn auth_hash(&self) -> Option<&str> {
        self.auth_hash.as_deref()
    }

    /// Check if the session is expired relative to a given unix timestamp.
    pub fn is_expired_at(&self, unix_timestamp: u64) -> bool {
        unix_timestamp >= self.expires_at_unix
    }
}
