//! Email + password verbs on the [`Auth`](crate::auth::Auth) facade.
//!
//! Inherent impls, one per verb: `sign_up_email`, `sign_in_email`,
//! `sign_out`, and `change_password`. Server routes and client twins call
//! these same verbs. Password reset arrives with the mailer seam, which owns
//! the delivery channel.

use crate::auth::Auth;
use crate::error::AuthError;
use crate::login::normalize_identifier;
use crate::status::SessionId;
use crate::store::{PasswordUserStore, SessionStore, UserStore};
use crate::user::AuthUser;

impl<D> Auth<D>
where
    D: PasswordUserStore + SessionStore<Id = <D as UserStore>::Id>,
{
    /// Changes a password after proving the current one.
    ///
    /// Verifies without minting a session, then revokes every session for the
    /// user and updates the hash. Revocation runs first: if it fails, the
    /// credential is untouched and the change reports the store error with
    /// nothing mutated. Unknown identifiers and wrong passwords share
    /// `InvalidCredentials` with no existence oracle.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::{Auth, AuthUser, MemoryStore};
    /// # #[derive(Debug, Clone)]
    /// # struct User { id: u64, name: String }
    /// # impl AuthUser for User {
    /// #     type Id = u64;
    /// #     fn id(&self) -> u64 { return self.id; }
    /// #     fn email(&self) -> &str { return &self.name; }
    /// # }
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
    /// let auth = Auth::new(MemoryStore::<User>::new())?;
    /// auth.sign_up_email("alice", "old-secret", User { id: 1, name: String::from("alice") })?;
    /// auth.change_password("alice", "old-secret", "new-secret")?;
    /// let (user, _) = auth.sign_in_email("alice", "new-secret")?;
    /// assert_eq!(user.id(), 1);
    /// # return Ok(());
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns `InvalidCredentials` for unknown identifiers or wrong current
    /// passwords, or a store or hasher error.
    #[must_use = "a failed password change must be handled"]
    pub fn change_password(
        &self,
        identifier: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        let user = match self
            .engine
            .verify_password(identifier, current_password, None)
        {
            Ok(user) => user,
            Err(error) => return Err(error),
        };
        let hash = match self.engine.hasher().hash(new_password) {
            Ok(hash) => hash,
            Err(error) => return Err(error),
        };
        match self.engine.revoke_all_user_sessions(&user.id()) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        match self.engine.user_store().update_password(&user.id(), &hash) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        self.engine.record_rate_limit_success(identifier, None);
        return Ok(());
    }

    /// Signs in with an identifier and password.
    ///
    /// This is the email-password verb. The bare `sign_in` name is reserved
    /// for a future method-selection surface, so use this form.
    ///
    /// Returns the user with the raw wire session id on success. Unknown
    /// identifiers and wrong passwords share `InvalidCredentials`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::{Auth, AuthUser, MemoryStore};
    /// # #[derive(Debug, Clone)]
    /// # struct User { id: u64, name: String }
    /// # impl AuthUser for User {
    /// #     type Id = u64;
    /// #     fn id(&self) -> u64 { return self.id; }
    /// #     fn email(&self) -> &str { return &self.name; }
    /// # }
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
    /// let auth = Auth::new(MemoryStore::<User>::new())?;
    /// auth.sign_up_email("alice", "s3cret", User { id: 1, name: String::from("alice") })?;
    /// let (user, _) = auth.sign_in_email("alice", "s3cret")?;
    /// assert_eq!(user.id(), 1);
    /// # return Ok(());
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns `InvalidCredentials` for bad credentials, `RateLimited` when
    /// limited, or a store or hasher error.
    #[must_use = "the authenticated user and session must be used"]
    pub fn sign_in_email(
        &self,
        identifier: &str,
        password: &str,
    ) -> Result<(D::User, SessionId), AuthError> {
        let (user, session) = match self.engine.login(identifier, password) {
            Ok(pair) => pair,
            Err(error) => return Err(error),
        };
        return Ok((user, session.id().clone()));
    }

    /// Signs out by revoking one raw wire session.
    ///
    /// Unknown sessions succeed silently, keeping sign-out idempotent.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::{Auth, AuthUser, MemoryStore};
    /// # #[derive(Debug, Clone)]
    /// # struct User { id: u64, name: String }
    /// # impl AuthUser for User {
    /// #     type Id = u64;
    /// #     fn id(&self) -> u64 { return self.id; }
    /// #     fn email(&self) -> &str { return &self.name; }
    /// # }
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
    /// let auth = Auth::new(MemoryStore::<User>::new())?;
    /// let (_, session) = auth.sign_up_email("alice", "s3cret", User { id: 1, name: String::from("alice") })?;
    /// auth.sign_out(&session)?;
    /// # return Ok(());
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns a store error if the lookup or deletion fails.
    #[must_use = "sign-out must be acknowledged"]
    pub fn sign_out(&self, session_id: &SessionId) -> Result<(), AuthError> {
        return self.engine.logout(session_id);
    }

    /// Signs up by provisioning credentials, then signing in.
    ///
    /// The caller builds the user; the store provisions the credential row.
    /// Taken and free identifiers cost the same and fail with the same
    /// `InvalidCredentials`, so identifier state is not observable. Probing
    /// any identifier counts toward the same rate gate as sign-in. Works over
    /// any [`PasswordUserStore`]: own-DB
    /// deployments get the same verb as the memory quickstart.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::{Auth, AuthUser, MemoryStore};
    /// # #[derive(Debug, Clone)]
    /// # struct User { id: u64, name: String }
    /// # impl AuthUser for User {
    /// #     type Id = u64;
    /// #     fn id(&self) -> u64 { return self.id; }
    /// #     fn email(&self) -> &str { return &self.name; }
    /// # }
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
    /// let auth = Auth::new(MemoryStore::<User>::new())?;
    /// let (user, _) = auth.sign_up_email("alice", "s3cret", User { id: 1, name: String::from("alice") })?;
    /// assert_eq!(user.id(), 1);
    /// # return Ok(());
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns `RateLimited` when the identifier is throttled,
    /// `InvalidCredentials` if the identifier is taken, or a store or hasher
    /// error.
    #[must_use = "the provisioned user and session must be used"]
    pub fn sign_up_email(
        &self,
        identifier: &str,
        password: &str,
        user: D::User,
    ) -> Result<(D::User, SessionId), AuthError> {
        match self.engine.check_rate_limit(identifier, None) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        let hash = match self.engine.hasher().hash(password) {
            Ok(hash) => hash,
            Err(error) => return Err(error),
        };
        let normalized = normalize_identifier(identifier);
        let provisioned =
            match self
                .engine
                .user_store()
                .provision_user_with_password(user, &normalized, &hash)
            {
                Ok(provisioned) => provisioned,
                Err(error) => return Err(error),
            };
        if !provisioned {
            // The identifier or id row is taken. The hash above is the work
            // the free path spends before storage; one dummy verifier pass
            // matches the work the free path spends after it, so user state
            // stays unobservable through timing as well as through the error.
            // The raw identifier goes in: the gate normalizes once internally,
            // so pre-normalizing here would fold case and whitespace twice.
            self.engine.record_rate_limit_failure(identifier, None);
            self.engine.dummy_verify(password);
            return Err(AuthError::InvalidCredentials);
        }
        return self.sign_in_email(identifier, password);
    }
}
