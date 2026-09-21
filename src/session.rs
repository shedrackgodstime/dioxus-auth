//! Server-side session record.

use std::fmt;

use crate::status::{REDACTED, SessionId};

/// Server-side session record.
///
/// `Debug` is **manual and redacted**: a derived impl would render the raw
/// session token (`id`) and the session auth hash — logging a session would
/// otherwise dump a hijackable credential plus the user's password hash.
/// Field access stays available through the getters.
#[derive(Clone, Eq, PartialEq)]
pub struct Session<Id> {
    id: SessionId,
    user_id: Id,
    created_at_unix: u64,
    expires_at_unix: u64,
    last_active_at_unix: Option<u64>,
    auth_hash: Option<String>,
    ip_address: Option<String>,
    user_agent: Option<String>,
}

impl<Id: fmt::Debug> fmt::Debug for Session<Id> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return f
            .debug_struct("Session")
            .field("id", &REDACTED)
            .field("user_id", &self.user_id)
            .field("created_at_unix", &self.created_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("last_active_at_unix", &self.last_active_at_unix)
            .field(
                "auth_hash",
                &self.auth_hash.as_ref().map(|_| return REDACTED),
            )
            .field("ip_address", &self.ip_address)
            .field("user_agent", &self.user_agent)
            .finish();
    }
}

impl<Id> Session<Id> {
    /// Creates a new session record.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::prelude::{Session, SessionId};
    /// let session = Session::new(SessionId::generate(), 7u64, 1000, 2000);
    /// assert_eq!(session.user_id(), &7);
    /// assert!(!session.is_expired_at(1999));
    /// assert!(session.is_expired_at(2000));
    /// ```
    #[must_use]
    pub const fn new(
        id: SessionId,
        user_id: Id,
        created_at_unix: u64,
        expires_at_unix: u64,
    ) -> Self {
        return Self {
            id,
            user_id,
            created_at_unix,
            expires_at_unix,
            last_active_at_unix: None,
            auth_hash: None,
            ip_address: None,
            user_agent: None,
        };
    }

    /// Sets the last-active timestamp (seconds since UNIX epoch).
    #[must_use]
    pub const fn with_last_active(mut self, at: u64) -> Self {
        self.last_active_at_unix = Some(at);
        return self;
    }

    /// Attaches a hash used to invalidate this session when credentials change.
    #[must_use]
    pub fn with_auth_hash(mut self, auth_hash: impl Into<String>) -> Self {
        self.auth_hash = Some(auth_hash.into());
        return self;
    }

    /// Attaches the client IP address.
    #[must_use]
    pub fn with_ip_address(mut self, ip_address: impl Into<String>) -> Self {
        self.ip_address = Some(ip_address.into());
        return self;
    }

    /// Attaches the client user agent.
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        return self;
    }

    /// Session identifier.
    #[must_use]
    pub const fn id(&self) -> &SessionId {
        return &self.id;
    }

    /// User identifier.
    #[must_use]
    pub const fn user_id(&self) -> &Id {
        return &self.user_id;
    }

    /// Creation timestamp (seconds since UNIX epoch).
    #[must_use]
    pub const fn created_at_unix(&self) -> u64 {
        return self.created_at_unix;
    }

    /// Expiry timestamp (seconds since UNIX epoch).
    #[must_use]
    pub const fn expires_at_unix(&self) -> u64 {
        return self.expires_at_unix;
    }

    /// Last validation/activity timestamp (seconds since UNIX epoch), if any.
    #[must_use]
    pub const fn last_active_at_unix(&self) -> Option<u64> {
        return self.last_active_at_unix;
    }

    /// Session authentication hash.
    #[must_use]
    pub fn auth_hash(&self) -> Option<&str> {
        return self.auth_hash.as_deref();
    }

    /// Client IP address.
    #[must_use]
    pub fn ip_address(&self) -> Option<&str> {
        return self.ip_address.as_deref();
    }

    /// Client user agent.
    #[must_use]
    pub fn user_agent(&self) -> Option<&str> {
        return self.user_agent.as_deref();
    }

    /// Whether the session is expired at `unix_timestamp`.
    #[must_use]
    pub const fn is_expired_at(&self, unix_timestamp: u64) -> bool {
        return unix_timestamp >= self.expires_at_unix;
    }

    /// Sets the expiry and last-active timestamp in one operation.
    ///
    /// Used by [`SessionStore`](crate::store::SessionStore) `touch_session_if_present`
    /// implementations to conditionally refresh a session without a separate
    /// read-modify-write that could resurrect a revoked session (Spec 16).
    #[must_use]
    pub const fn set_expiry_and_last_active(mut self, new_expiry: u64, last_active: u64) -> Self {
        self.expires_at_unix = new_expiry;
        self.last_active_at_unix = Some(last_active);
        return self;
    }
}
