use crate::error::AuthResult;
use crate::user::AuthUser;

/// Storage interface for loading users by unique ID.
pub trait UserStore: Send + Sync + 'static {
    type User: AuthUser;

    /// Retrieve a user by their unique identifier.
    fn find_by_id(
        &self,
        id: &<Self::User as AuthUser>::Id,
    ) -> impl std::future::Future<Output = AuthResult<Option<Self::User>>> + Send;
}

/// Storage interface for finding users and password hashes by login identifier (e.g. email or username).
pub trait PasswordUserStore: UserStore {
    /// Retrieve a user and their hashed password by login identifier.
    fn find_by_identifier(
        &self,
        identifier: &str,
    ) -> impl std::future::Future<Output = AuthResult<Option<(Self::User, String)>>> + Send;
}
