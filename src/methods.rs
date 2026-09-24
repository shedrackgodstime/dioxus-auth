//! Email + password verbs on the [`Auth`](crate::auth::Auth) facade.
//!
//! Inherent impls, one per verb: `sign_up_email`, `sign_in_email`,
//! `sign_out`, `change_password`, and `attach_email_credential`. Server
//! routes and client twins call these same verbs. Password reset arrives
//! with the mailer seam, which owns the delivery channel.
//!
//! Verbs returning application users compose an engine call with
//! [`UserStore::resolve`](crate::store::UserStore::resolve): the engine
//! authenticates the subject, the facade resolves its app model. The
//! composition lives here, never in the engine.

use crate::auth::Auth;
use crate::error::AuthError;
use crate::login::normalize_identifier;
use crate::status::SessionId;
use crate::store::session::SessionStore;
use crate::store::user::{AuthSubject, CredentialStore, SubjectStore, UserStore};

/// Provisioned subject paired with its wire session id.
///
/// Keeps the fully qualified subject form (required against the ambiguous
/// `AuthId`) out of signatures without losing meaning.
type SubjectSessionId<D> = (
    AuthSubject<<D as SubjectStore>::AuthId, <D as SubjectStore>::AppRef>,
    SessionId,
);

/// Progressive control for signup.
///
/// The canonical [`sign_up_email`](Auth::sign_up_email) stays the simple
/// path; this carries explicit overrides without growing a verb per
/// combination. Pre-hashed secrets arrive separately (migration work),
/// never through this struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignupOptions<Id, Setup> {
    id_override: Option<Id>,
    input: Setup,
}

impl<Id, Setup> SignupOptions<Id, Setup> {
    /// Packages store-defined signup material with default identity.
    #[must_use = "the configured options must be used"]
    pub const fn new(input: Setup) -> Self {
        return Self {
            id_override: None,
            input,
        };
    }

    /// Adopts an explicit subject id instead of minting one.
    ///
    /// For bringing an external identity strategy or an existing id space;
    /// never a prerequisite, always an override.
    #[must_use = "the configured options must be used"]
    pub fn with_id(mut self, id: Id) -> Self {
        self.id_override = Some(id);
        return self;
    }

    /// The explicit subject id, if any.
    #[must_use]
    pub const fn id_override(&self) -> Option<&Id> {
        return self.id_override.as_ref();
    }

    /// The store-defined signup material.
    #[must_use]
    pub const fn input(&self) -> &Setup {
        return &self.input;
    }
}

impl<D> Auth<D>
where
    D: CredentialStore + SessionStore<AuthId = <D as SubjectStore>::AuthId> + UserStore,
{
    /// Changes a password after proving the current one.
    ///
    /// Verifies without minting a session, then revokes every session for the
    /// subject and rotates the secret. Revocation runs first: if it fails, the
    /// credential is untouched and the change reports the store error with
    /// nothing mutated. Unknown identifiers and wrong passwords share
    /// `InvalidCredentials` with no existence oracle.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::{Auth, DefaultStore, DefaultUserInput};
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
    /// let auth = Auth::new(DefaultStore::new())?;
    /// auth.sign_up_email("alice", "old-secret", DefaultUserInput::new("alice"))?;
    /// auth.change_password("alice", "old-secret", "new-secret")?;
    /// let (user, _) = auth.sign_in_email("alice", "new-secret")?;
    /// assert_eq!(user.id, 1);
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
        let subject = match self
            .engine
            .verify_password(identifier, current_password, None)
        {
            Ok(subject) => subject,
            Err(error) => return Err(error),
        };
        let hash = match self.engine.hasher().hash(new_password) {
            Ok(hash) => hash,
            Err(error) => return Err(error),
        };
        match self.engine.revoke_all_subject_sessions(&subject.auth_id) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        match self.engine.store().rotate_secret(&subject.auth_id, &hash) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        self.engine.record_rate_limit_success(identifier, None);
        return Ok(());
    }

    /// Signs out by revoking one raw wire session.
    ///
    /// Unknown sessions succeed silently, keeping sign-out idempotent.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::{Auth, DefaultStore, DefaultUserInput};
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
    /// let auth = Auth::new(DefaultStore::new())?;
    /// let (_, session) = auth.sign_up_email("alice", "s3cret", DefaultUserInput::new("alice"))?;
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

    /// Attaches an email/password credential to an existing subject.
    ///
    /// The companion to signup: signup creates the subject *and* its first
    /// credential, this adds another login to a subject that already exists
    /// (imported rows, admin-created users, SSO-linked accounts, a second
    /// identifier on one account). Unknown subject ids and taken identifiers
    /// both report `InvalidCredentials` with the same hashing work, so
    /// neither subject existence nor identifier state is observable.
    ///
    /// Privileged operation: binding a new login to an account must be
    /// authorized first (a session for this subject, or admin tooling). The
    /// engine cannot tell a legitimate link from an attacker binding their
    /// own identifier to a victim's subject, so server wiring must enforce
    /// the caller before reaching this verb.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::{Auth, DefaultStore, DefaultUserInput};
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
    /// let auth = Auth::new(DefaultStore::new())?;
    /// let (subject, _) = auth.sign_up_subject("alice", "s3cret", DefaultUserInput::new("alice"))?;
    /// auth.attach_email_credential(&subject.auth_id, "alice-2", "other-secret")?;
    /// let (user, _) = auth.sign_in_email("alice-2", "other-secret")?;
    /// assert_eq!(user.id, 1);
    /// # return Ok(());
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns `InvalidCredentials` for unknown subject ids or taken
    /// identifiers, `RateLimited` when limited, or a store or hasher error.
    #[must_use = "credential attachment must be acknowledged"]
    pub fn attach_email_credential(
        &self,
        auth_id: &<D as SubjectStore>::AuthId,
        identifier: &str,
        password: &str,
    ) -> Result<(), AuthError> {
        match self.engine.check_rate_limit(identifier, None) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        let hash = match self.engine.hasher().hash(password) {
            Ok(hash) => hash,
            Err(error) => return Err(error),
        };
        let normalized = normalize_identifier(identifier);
        let attached =
            match self
                .engine
                .store()
                .attach_credential(auth_id, "email", &normalized, &hash)
            {
                Ok(attached) => attached,
                Err(error) => return Err(error),
            };
        if !attached {
            self.engine.record_rate_limit_failure(identifier, None);
            self.engine.dummy_verify(password);
            return Err(AuthError::InvalidCredentials);
        }
        self.engine.record_rate_limit_success(identifier, None);
        return Ok(());
    }

    /// Signs up by provisioning a subject and credentials, then signing in.
    ///
    /// The caller supplies store-defined signup material; the store mints
    /// the subject (or adopts an overridden id), links the app side, and
    /// hands back exactly what it persisted. Taken and free identifiers
    /// cost the same and fail with the same `InvalidCredentials`, so
    /// identifier state is not observable. Probing any identifier counts
    /// toward the same rate gate as sign-in.
    ///
    /// Returns the resolved application user with the raw wire session id.
    /// Unresolvable subjects (association removed mid-flight) fail closed
    /// with `InvalidCredentials`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::{Auth, DefaultStore, DefaultUserInput};
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
    /// let auth = Auth::new(DefaultStore::new())?;
    /// let (user, _) = auth.sign_up_email("alice", "s3cret", DefaultUserInput::new("alice"))?;
    /// assert_eq!(user.id, 1);
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
        input: D::AppSetup,
    ) -> Result<(D::User, SessionId), AuthError> {
        return self.sign_up_inner(identifier, password, input, None);
    }

    /// Signs up with explicit control over identity.
    ///
    /// Same claim as [`sign_up_email`](Self::sign_up_email), but the
    /// subject id is adopted from [`SignupOptions`] instead of minted.
    /// Taken identifiers and taken overridden ids share one
    /// `InvalidCredentials` with identical hashing work, so neither
    /// identifier state nor id-space state is observable. This is the only
    /// second signup verb by design: simple path plus options-carrying
    /// path, never one verb per combination.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::{Auth, DefaultStore, DefaultUserInput, SignupOptions};
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
    /// let auth = Auth::new(DefaultStore::new())?;
    /// let options = SignupOptions::new(DefaultUserInput::new("alice")).with_id(77u64);
    /// let (user, _) = auth.sign_up_email_with_options("alice", "s3cret", options)?;
    /// assert_eq!(user.id, 1);
    /// let subject = auth.engine().validate_session(
    ///     &auth.sign_in_email("alice", "s3cret")?.1,
    /// )?.expect("session must validate");
    /// assert_eq!(subject.auth_id, 77);
    /// # return Ok(());
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns `RateLimited` when the identifier is throttled,
    /// `InvalidCredentials` if the identifier or id is taken, or a store
    /// or hasher error.
    #[must_use = "the provisioned user and session must be used"]
    pub fn sign_up_email_with_options(
        &self,
        identifier: &str,
        password: &str,
        options: SignupOptions<<D as SubjectStore>::AuthId, D::AppSetup>,
    ) -> Result<(D::User, SessionId), AuthError> {
        let SignupOptions { id_override, input } = options;
        return self.sign_up_inner(identifier, password, input, id_override);
    }

    /// Runs the signup claim with an optional id override.
    fn sign_up_inner(
        &self,
        identifier: &str,
        password: &str,
        input: D::AppSetup,
        id_override: Option<<D as SubjectStore>::AuthId>,
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
        let provisioned = match self.engine.store().provision_subject(
            id_override,
            input,
            "email",
            &normalized,
            &hash,
        ) {
            Ok(provisioned) => provisioned,
            Err(error) => return Err(error),
        };
        let Some(_created) = provisioned else {
            // The identifier or subject id is taken. The hash above is the work
            // the free path spends before storage; one dummy verifier pass
            // matches the work the free path spends after it, so subject state
            // stays unobservable through timing as well as through the error.
            // The raw identifier goes in: the gate normalizes once internally,
            // so pre-normalizing here would fold case and whitespace twice.
            self.engine.record_rate_limit_failure(identifier, None);
            self.engine.dummy_verify(password);
            return Err(AuthError::InvalidCredentials);
        };
        // The created subject is re-read by the sign-in below, so the returned
        // user always comes from the single credential-lookup path.
        return self.sign_in_email(identifier, password);
    }

    /// Signs up subject-first, returning auth-space material.
    ///
    /// Same claim as [`sign_up_email`](Self::sign_up_email) without the
    /// application-model resolution: for callers that work in auth-space
    /// (migrations, admin tooling, attach flows needing the fresh id).
    /// Unknown/taken identifiers behave identically.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::{Auth, DefaultStore, DefaultUserInput};
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
    /// let auth = Auth::new(DefaultStore::new())?;
    /// let (subject, _) = auth.sign_up_subject("alice", "s3cret", DefaultUserInput::new("alice"))?;
    /// assert_eq!(subject.auth_id, 1);
    /// # return Ok(());
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns `RateLimited` when the identifier is throttled,
    /// `InvalidCredentials` if the identifier is taken, or a store or hasher
    /// error.
    #[must_use = "the provisioned subject and session must be used"]
    pub fn sign_up_subject(
        &self,
        identifier: &str,
        password: &str,
        input: D::AppSetup,
    ) -> Result<SubjectSessionId<D>, AuthError> {
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
                .store()
                .provision_subject(None, input, "email", &normalized, &hash)
            {
                Ok(provisioned) => provisioned,
                Err(error) => return Err(error),
            };
        let Some(created) = provisioned else {
            self.engine.record_rate_limit_failure(identifier, None);
            self.engine.dummy_verify(password);
            return Err(AuthError::InvalidCredentials);
        };
        let (_, session) = match self.engine.login(identifier, password) {
            Ok(pair) => pair,
            Err(error) => return Err(error),
        };
        return Ok((created, session.id().clone()));
    }

    /// Imports an email credential from a pre-hashed secret (migration).
    ///
    /// Trust-based by construction: without plaintext nothing can be
    /// verified before acceptance, so this is migration and admin tooling
    /// only, never a user-facing endpoint. Garbage in locks the account
    /// out (logins fail closed); stage imports where the original
    /// password is still known and confirm with a test login. No session
    /// is minted: importing proves nothing about who runs it, so callers
    /// authenticate normally afterwards.
    ///
    /// Shares the signup cost path (rate gate, taken handling with dummy
    /// verification, atomic claim) with one deliberate asymmetry: there is
    /// no plaintext to hash, so the free path cannot match the taken
    /// path's work exactly. The endpoint is privileged, which is where
    /// that residual belongs. Empty hashes are rejected outright.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::{Auth, DefaultStore, DefaultUserInput, SignupOptions};
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
    /// let auth = Auth::new(DefaultStore::new())?;
    /// let hash = auth.engine().hasher().hash("s3cret")?;
    /// let options = SignupOptions::new(DefaultUserInput::new("alice"));
    /// let user = auth.import_email_credential("alice", &hash, options)?;
    /// assert_eq!(user.id, 1);
    /// let (same, _) = auth.sign_in_email("alice", "s3cret")?;
    /// assert_eq!(same.id, user.id);
    /// # return Ok(());
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns `InvalidCredentials` for taken identifiers, empty hashes,
    /// or unresolvable subjects; `RateLimited` when limited; or a store
    /// error. Never mints a session.
    #[must_use = "the imported user must be acknowledged"]
    pub fn import_email_credential(
        &self,
        identifier: &str,
        password_hash: &str,
        options: SignupOptions<<D as SubjectStore>::AuthId, D::AppSetup>,
    ) -> Result<D::User, AuthError> {
        match self.engine.check_rate_limit(identifier, None) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        if password_hash.is_empty() {
            return Err(AuthError::InvalidCredentials);
        }
        let normalized = normalize_identifier(identifier);
        let SignupOptions { id_override, input } = options;
        let provisioned = match self.engine.store().provision_subject(
            id_override,
            input,
            "email",
            &normalized,
            password_hash,
        ) {
            Ok(provisioned) => provisioned,
            Err(error) => return Err(error),
        };
        let Some(created) = provisioned else {
            self.engine.record_rate_limit_failure(identifier, None);
            // The imported hash stands in as the verified value: only the
            // work matters here, and Argon2 verify cost is password-agnostic.
            self.engine.dummy_verify(password_hash);
            return Err(AuthError::InvalidCredentials);
        };
        self.engine.record_rate_limit_success(identifier, None);
        return self.resolve_subject(&created);
    }

    /// Attaches an imported pre-hashed credential to an existing subject.
    ///
    /// Same trust model as [`import_email_credential`](Self::import_email_credential):
    /// migration and admin tooling only, no verification possible, no
    /// session minted. Taken identifiers share `InvalidCredentials` with
    /// dummy verification; empty hashes are rejected outright.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::{Auth, DefaultStore, DefaultUserInput};
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
    /// let auth = Auth::new(DefaultStore::new())?;
    /// let (subject, _) = auth.sign_up_subject("alice", "s3cret", DefaultUserInput::new("alice"))?;
    /// let hash = auth.engine().hasher().hash("other-secret")?;
    /// auth.attach_imported_email_credential(&subject.auth_id, "alice-2", &hash)?;
    /// let (user, _) = auth.sign_in_email("alice-2", "other-secret")?;
    /// assert_eq!(user.id, 1);
    /// # return Ok(());
    /// # }
    /// ```
    ///
    /// # Errors
    /// Returns `InvalidCredentials` for unknown subject ids, taken
    /// identifiers, or empty hashes; `RateLimited` when limited; or a
    /// store error.
    #[must_use = "credential attachment must be acknowledged"]
    pub fn attach_imported_email_credential(
        &self,
        auth_id: &<D as SubjectStore>::AuthId,
        identifier: &str,
        password_hash: &str,
    ) -> Result<(), AuthError> {
        match self.engine.check_rate_limit(identifier, None) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        if password_hash.is_empty() {
            return Err(AuthError::InvalidCredentials);
        }
        let normalized = normalize_identifier(identifier);
        let attached = match self.engine.store().attach_credential(
            auth_id,
            "email",
            &normalized,
            password_hash,
        ) {
            Ok(attached) => attached,
            Err(error) => return Err(error),
        };
        if !attached {
            self.engine.record_rate_limit_failure(identifier, None);
            // Same work-equivalence stand-in as import: cost, not content.
            self.engine.dummy_verify(password_hash);
            return Err(AuthError::InvalidCredentials);
        }
        self.engine.record_rate_limit_success(identifier, None);
        return Ok(());
    }

    /// Signs in with an identifier and password.
    ///
    /// This is the email-password verb. The bare `sign_in` name is reserved
    /// for a future method-selection surface, so use this form.
    ///
    /// Returns the resolved application user with the raw wire session id on
    /// success. Unknown identifiers and wrong passwords share
    /// `InvalidCredentials`; unresolvable subjects fail closed the same way.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::{Auth, DefaultStore, DefaultUserInput};
    /// # fn main() -> Result<(), dioxus_auth::AuthError> {
    /// let auth = Auth::new(DefaultStore::new())?;
    /// auth.sign_up_email("alice", "s3cret", DefaultUserInput::new("alice"))?;
    /// let (user, _) = auth.sign_in_email("alice", "s3cret")?;
    /// assert_eq!(user.id, 1);
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
        let (subject, session) = match self.engine.login(identifier, password) {
            Ok(pair) => pair,
            Err(error) => return Err(error),
        };
        // The engine authenticates the subject; the facade resolves its app
        // model. A subject without resolvable app data fails closed: callers
        // must never receive a session paired with no user. Store outages
        // propagate as-is instead of masquerading as bad credentials.
        let user = match self.resolve_subject(&subject) {
            Ok(user) => user,
            Err(error) => return Err(error),
        };
        return Ok((user, session.id().clone()));
    }

    /// Resolves a subject to its application user.
    fn resolve_subject(
        &self,
        subject: &crate::store::AuthSubject<
            <D as SubjectStore>::AuthId,
            <D as SubjectStore>::AppRef,
        >,
    ) -> Result<D::User, AuthError> {
        let Some(app_ref) = subject.app_ref.as_ref() else {
            return Err(AuthError::InvalidCredentials);
        };
        let user = match self.engine.store().resolve(app_ref) {
            Ok(Some(user)) => user,
            Ok(None) => return Err(AuthError::InvalidCredentials),
            Err(error) => return Err(error),
        };
        return Ok(user);
    }
}
