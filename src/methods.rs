//! Email+password method verbs (M1).
//!
//! Inherent [`Auth`](crate::auth::Auth) impls, one per verb. Server routes and
//! client twins consume these same verbs, so the method stays one coherent
//! unit. Slice 1e renames them to their final `sign_*_email` forms; until then
//! they mirror engine vocabulary. The request/reset pair needs a delivery
//! channel, so it rides Gate 2 with `Mailer`, not here.

use crate::auth::Auth;
use crate::error::AuthError;
use crate::status::SessionId;
use crate::store::{MemoryStore, PasswordUserStore, SessionStore, UserStore};
use crate::user::AuthUser;

impl<D> Auth<D>
where
    D: PasswordUserStore + SessionStore<Id = <D as UserStore>::Id>,
{
    /// Changes a password after proving the current one.
    ///
    /// Verifies without minting a session, then updates the hash and revokes
    /// every session for the user. Unknown identifiers and wrong passwords
    /// share `InvalidCredentials` — no existence oracle.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::prelude::{Auth, AuthUser, MemoryStore};
    /// # #[derive(Debug, Clone)]
    /// # struct User { id: u64, name: String }
    /// # impl AuthUser for User {
    /// #     type Id = u64;
    /// #     fn id(&self) -> u64 { return self.id; }
    /// #     fn display_name(&self) -> Option<String> { return Some(self.name.clone()); }
    /// #     fn clone_box(&self) -> Box<dyn AuthUser<Id = u64>> { return Box::new(self.clone()); }
    /// # }
    /// # fn main() -> Result<(), dioxus_auth::prelude::AuthError> {
    /// let auth = Auth::<MemoryStore<User>>::memory()?;
    /// auth.sign_up("alice", "old-secret", User { id: 1, name: String::from("alice") })?;
    /// auth.change_password("alice", "old-secret", "new-secret")?;
    /// let (user, _) = auth.sign_in("alice", "new-secret")?;
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
        let user = match self.engine.verify_password(identifier, current_password) {
            Ok(user) => user,
            Err(error) => return Err(error),
        };
        let hash = match self.engine.hasher().hash(new_password) {
            Ok(hash) => hash,
            Err(error) => return Err(error),
        };
        match self.engine.user_store().update_password(&user.id(), &hash) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        match self.engine.revoke_all_user_sessions(&user.id()) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        if let Some(limiter) = &self.engine.rate_limiter {
            limiter.record_success(&identifier.trim().to_lowercase());
        }
        return Ok(());
    }

    /// Signs in with an identifier and password.
    ///
    /// Returns the user with the raw wire session id on success. Unknown
    /// identifiers and wrong passwords share `InvalidCredentials`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::prelude::{Auth, AuthUser, MemoryStore};
    /// # #[derive(Debug, Clone)]
    /// # struct User { id: u64, name: String }
    /// # impl AuthUser for User {
    /// #     type Id = u64;
    /// #     fn id(&self) -> u64 { return self.id; }
    /// #     fn display_name(&self) -> Option<String> { return Some(self.name.clone()); }
    /// #     fn clone_box(&self) -> Box<dyn AuthUser<Id = u64>> { return Box::new(self.clone()); }
    /// # }
    /// # fn main() -> Result<(), dioxus_auth::prelude::AuthError> {
    /// let auth = Auth::<MemoryStore<User>>::memory()?;
    /// auth.sign_up("alice", "s3cret", User { id: 1, name: String::from("alice") })?;
    /// let (user, _) = auth.sign_in("alice", "s3cret")?;
    /// assert_eq!(user.id(), 1);
    /// # return Ok(());
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns `InvalidCredentials` for bad credentials, `RateLimited` when
    /// limited, or a store or hasher error.
    #[must_use = "the authenticated user and session must be used"]
    pub fn sign_in(
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
    /// Unknown sessions succeed silently — sign-out is idempotent.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::prelude::{Auth, AuthUser, MemoryStore};
    /// # #[derive(Debug, Clone)]
    /// # struct User { id: u64, name: String }
    /// # impl AuthUser for User {
    /// #     type Id = u64;
    /// #     fn id(&self) -> u64 { return self.id; }
    /// #     fn display_name(&self) -> Option<String> { return Some(self.name.clone()); }
    /// #     fn clone_box(&self) -> Box<dyn AuthUser<Id = u64>> { return Box::new(self.clone()); }
    /// # }
    /// # fn main() -> Result<(), dioxus_auth::prelude::AuthError> {
    /// let auth = Auth::<MemoryStore<User>>::memory()?;
    /// let (_, session) = auth.sign_up("alice", "s3cret", User { id: 1, name: String::from("alice") })?;
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
}

impl<User> Auth<MemoryStore<User>>
where
    User: AuthUser + Clone,
{
    /// Signs up by provisioning credentials, then signing in.
    ///
    /// The caller builds the user; the store provisions the credential row.
    /// Taken identifiers and unknown identifiers in [`Auth::sign_in`] return
    /// the identical `InvalidCredentials` after the same throttle-and-burn
    /// sequence — no existence oracle, and probing any identifier counts
    /// toward the same rate gate as login. MemoryStore-only until the 1e
    /// sweep adds the general provision seam.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::prelude::{Auth, AuthUser, MemoryStore};
    /// # #[derive(Debug, Clone)]
    /// # struct User { id: u64, name: String }
    /// # impl AuthUser for User {
    /// #     type Id = u64;
    /// #     fn id(&self) -> u64 { return self.id; }
    /// #     fn display_name(&self) -> Option<String> { return Some(self.name.clone()); }
    /// #     fn clone_box(&self) -> Box<dyn AuthUser<Id = u64>> { return Box::new(self.clone()); }
    /// # }
    /// # fn main() -> Result<(), dioxus_auth::prelude::AuthError> {
    /// let auth = Auth::<MemoryStore<User>>::memory()?;
    /// let (user, _) = auth.sign_up("alice", "s3cret", User { id: 1, name: String::from("alice") })?;
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
    pub fn sign_up(
        &self,
        identifier: &str,
        password: &str,
        user: User,
    ) -> Result<(User, SessionId), AuthError> {
        let limiter_key = identifier.trim().to_lowercase();
        match self.engine.check_rate_limit(&limiter_key) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        let entry = match self.engine.user_store().find_by_identifier(identifier) {
            Ok(entry) => entry,
            Err(error) => return Err(error),
        };
        if entry.is_some() {
            // reason: the taken path mirrors login's miss path exactly — one
            // recorded attempt plus one burned verifier run — so taken and
            // free identifiers are indistinguishable in cost, outcome, and
            // throttle accounting.
            self.engine.record_rate_limit_failure(&limiter_key);
            let _burned = self.engine.hasher().hash(password).is_ok();
            return Err(AuthError::InvalidCredentials);
        }
        let hash = match self.engine.hasher().hash(password) {
            Ok(hash) => hash,
            Err(error) => return Err(error),
        };
        self.engine
            .user_store()
            .insert_user_with_password(user, identifier, hash);
        return self.sign_in(identifier, password);
    }
}
