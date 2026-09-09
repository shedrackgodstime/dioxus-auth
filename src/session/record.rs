use crate::session::id::SessionId;

/// Server-side session record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session<UserId> {
    id: SessionId,
    user_id: UserId,
    created_at_unix: u64,
    expires_at_unix: u64,
    last_active_at_unix: Option<u64>,
    auth_hash: Option<String>,
    ip_address: Option<String>,
    user_agent: Option<String>,
}

impl<UserId> Session<UserId> {
    /// Create a new session record.
    pub fn new(id: SessionId, user_id: UserId, created_at_unix: u64, expires_at_unix: u64) -> Self {
        Self {
            id,
            user_id,
            created_at_unix,
            expires_at_unix,
            last_active_at_unix: None,
            auth_hash: None,
            ip_address: None,
            user_agent: None,
        }
    }

    /// Set the last-active timestamp (seconds since UNIX epoch).
    ///
    /// Used by the engine to track idle timeouts. `None` means "not yet active
    /// since creation" — the first validation sets it.
    pub fn with_last_active(mut self, at: u64) -> Self {
        self.last_active_at_unix = Some(at);
        self
    }

    /// Last validation/activity timestamp (seconds since UNIX epoch), if any.
    pub fn last_active_at_unix(&self) -> Option<u64> {
        self.last_active_at_unix
    }

    /// Attach a hash used to invalidate this session when credentials change.
    pub fn with_auth_hash(mut self, auth_hash: impl Into<String>) -> Self {
        self.auth_hash = Some(auth_hash.into());
        self
    }

    /// Attach the client IP address.
    pub fn with_ip_address(mut self, ip_address: impl Into<String>) -> Self {
        self.ip_address = Some(ip_address.into());
        self
    }

    /// Attach the client user agent.
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Session identifier.
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// User identifier.
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Creation timestamp (seconds).
    pub fn created_at_unix(&self) -> u64 {
        self.created_at_unix
    }

    /// Expiry timestamp (seconds).
    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    /// Session authentication hash.
    pub fn auth_hash(&self) -> Option<&str> {
        self.auth_hash.as_deref()
    }

    /// Client IP address.
    pub fn ip_address(&self) -> Option<&str> {
        self.ip_address.as_deref()
    }

    /// Client user agent.
    pub fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }

    /// Whether the session is expired at `unix_timestamp`.
    pub fn is_expired_at(&self, unix_timestamp: u64) -> bool {
        unix_timestamp >= self.expires_at_unix
    }

    /// Extend the session expiry by `ttl_secs` from `now`.
    ///
    /// Used for sliding TTL.
    pub fn extend_expiry(mut self, now: u64, ttl_secs: u64) -> Self {
        self.expires_at_unix = now + ttl_secs;
        self
    }

    /// Set the expiry timestamp (seconds since UNIX epoch).
    pub fn set_expires_at_unix(&mut self, expires_at: u64) {
        self.expires_at_unix = expires_at;
    }

    /// Set the last-active timestamp (seconds since UNIX epoch).
    pub fn set_last_active_at_unix(&mut self, last_active: u64) {
        self.last_active_at_unix = Some(last_active);
    }

    /// Set the expiry and last-active timestamp in one operation.
    ///
    /// Used by [`SessionStore`](crate::storage::SessionStore) `touch_session_if_present`
    /// implementations to conditionally refresh a session without a separate
    /// read-modify-write that could resurrect a revoked session (Spec 16).
    pub fn set_expiry_and_last_active(mut self, new_expiry: u64, last_active: u64) -> Self {
        self.expires_at_unix = new_expiry;
        self.last_active_at_unix = Some(last_active);
        self
    }
}
