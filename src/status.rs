//! Authentication status and session types.

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

/// A unique session identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId {
    inner: String,
}

impl SessionId {
    /// Creates a new session identifier.
    #[must_use]
    pub fn new(value: String) -> Self {
        SessionId { inner: value }
    }
    /// Returns the inner string value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.inner
    }
}

/// A session record.
#[derive(Debug, Clone)]
pub struct SessionRecord {
    id: SessionId,
    user_id: String,
    active: bool,
}

impl SessionRecord {
    /// Creates a new session record.
    #[must_use]
    pub fn new(id: SessionId, user_id: String, active: bool) -> Self {
        SessionRecord {
            id,
            user_id,
            active,
        }
    }
    /// Returns the session identifier.
    #[must_use]
    pub fn id(&self) -> &SessionId {
        &self.id
    }
    /// Returns the user identifier.
    #[must_use]
    pub fn user_id(&self) -> &str {
        &self.user_id
    }
    /// Returns whether the session is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }
}
