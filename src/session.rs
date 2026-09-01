#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SessionId(String);

impl SessionId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session<UserId> {
    id: SessionId,
    user_id: UserId,
    created_at_unix: u64,
    expires_at_unix: u64,
    auth_hash: Option<String>,
}

impl<UserId> Session<UserId> {
    pub fn new(id: SessionId, user_id: UserId, created_at_unix: u64, expires_at_unix: u64) -> Self {
        Self {
            id,
            user_id,
            created_at_unix,
            expires_at_unix,
            auth_hash: None,
        }
    }

    pub fn with_auth_hash(mut self, auth_hash: impl Into<String>) -> Self {
        self.auth_hash = Some(auth_hash.into());
        self
    }

    pub fn id(&self) -> &SessionId {
        &self.id
    }

    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    pub fn created_at_unix(&self) -> u64 {
        self.created_at_unix
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    pub fn auth_hash(&self) -> Option<&str> {
        self.auth_hash.as_deref()
    }

    pub fn is_expired_at(&self, unix_timestamp: u64) -> bool {
        unix_timestamp >= self.expires_at_unix
    }
}
