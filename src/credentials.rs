//! Credential management verbs: session-bound attach and password change.
//!
//! These live on the engine (not only the facade) so network paths can
//! reach them without a second spelling: the runtime layer calls these,
//! the facade delegates to `change_password`, and direct store users keep
//! the explicit-id verbs. Accounting (rate gate, dummy verification,
//! success clearing) matches the facade exactly, so every path costs
//! identically.

use crate::engine::AuthEngine;
use crate::error::AuthError;
use crate::login::normalize_identifier;
use crate::status::SessionId;
use crate::store::session::SessionStore;
use crate::store::user::CredentialStore;

impl<C, S> AuthEngine<C, S>
where
    C: CredentialStore,
    S: SessionStore<AuthId = C::AuthId>,
{
    /// Attaches a credential to the session owner's subject.
    ///
    /// Validates the wire session first (expired or rotated sessions cannot
    /// attach), then binds the new identifier to that same subject. Unknown
    /// sessions, unknown subjects, and taken identifiers share
    /// `InvalidCredentials` with identical hashing work. Privilege comes
    /// from session possession: only the session owner can extend their
    /// own logins.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::{AuthEngine, CredentialStore, DefaultStore, DefaultUserInput, SubjectStore};
    /// # use std::sync::Arc;
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
    /// # let store = Arc::new(DefaultStore::new());
    /// # let engine = AuthEngine::new(Arc::clone(&store), Arc::clone(&store))?;
    /// # let hash = engine.hasher().hash("s3cret")?;
    /// # store.provision_subject(None, DefaultUserInput::new("alice"), "email", "alice", &hash)?;
    /// # let (_, session) = engine.login("alice", "s3cret")?;
    /// engine.attach_current(session.id(), "alice-2", "other-secret")?;
    /// let (_, second) = engine.login("alice-2", "other-secret")?;
    /// assert!(engine.validate_session(second.id())?.is_some());
    /// # return Ok(());
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns `InvalidCredentials` for bad sessions, unknown subjects, or
    /// taken identifiers; `RateLimited` when limited; or a store or hasher
    /// error.
    #[must_use = "credential attachment must be acknowledged"]
    pub fn attach_current(
        &self,
        session_id: &SessionId,
        identifier: &str,
        password: &str,
    ) -> Result<(), AuthError> {
        let subject = match self.validate_session(session_id) {
            Ok(Some(subject)) => subject,
            Ok(None) => return Err(AuthError::InvalidCredentials),
            Err(error) => return Err(error),
        };
        match self.check_rate_limit(identifier, None) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        let hash = match self.hasher().hash(password) {
            Ok(hash) => hash,
            Err(error) => return Err(error),
        };
        let normalized = normalize_identifier(identifier);
        let attached =
            match self
                .store()
                .attach_credential(&subject.auth_id, "email", &normalized, &hash)
            {
                Ok(attached) => attached,
                Err(error) => return Err(error),
            };
        if !attached {
            self.record_rate_limit_failure(identifier, None);
            self.dummy_verify(password);
            return Err(AuthError::InvalidCredentials);
        }
        self.record_rate_limit_success(identifier, None);
        return Ok(());
    }

    /// Changes a password after proving the current one.
    ///
    /// Verifies without minting a session, then revokes every session for
    /// the subject and rotates the secret. Revocation runs first: if it
    /// fails, the credential is untouched and the change reports the store
    /// error with nothing mutated. Unknown identifiers and wrong passwords
    /// share `InvalidCredentials` with no existence oracle.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::{AuthEngine, CredentialStore, DefaultStore, DefaultUserInput, SubjectStore};
    /// # use std::sync::Arc;
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
    /// # let store = Arc::new(DefaultStore::new());
    /// # let engine = AuthEngine::new(Arc::clone(&store), Arc::clone(&store))?;
    /// # let hash = engine.hasher().hash("old-secret")?;
    /// # store.provision_subject(None, DefaultUserInput::new("alice"), "email", "alice", &hash)?;
    /// engine.change_password("alice", "old-secret", "new-secret")?;
    /// let (_, session) = engine.login("alice", "new-secret")?;
    /// assert!(engine.validate_session(session.id())?.is_some());
    /// # return Ok(());
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns `InvalidCredentials` for unknown identifiers or wrong
    /// current passwords, or a store or hasher error.
    #[must_use = "a failed password change must be handled"]
    pub fn change_password(
        &self,
        identifier: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        let subject = match self.verify_password(identifier, current_password, None) {
            Ok(subject) => subject,
            Err(error) => return Err(error),
        };
        let hash = match self.hasher().hash(new_password) {
            Ok(hash) => hash,
            Err(error) => return Err(error),
        };
        match self.revoke_all_subject_sessions(&subject.auth_id) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        match self.store().rotate_secret(&subject.auth_id, &hash) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        self.record_rate_limit_success(identifier, None);
        return Ok(());
    }
}
