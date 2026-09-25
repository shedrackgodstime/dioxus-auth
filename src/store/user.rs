//! Subject, credential, and application-resolution storage capabilities.
//!
//! Engine-facing traits ([`SubjectStore`], [`CredentialStore`]) work on the
//! library-owned [`AuthSubject`] and never name the application model. The
//! model enters only through [`UserStore::resolve`], called by outer layers,
//! never the engine.
//!
//! Identifier matching is exact throughout: the engine normalizes once (trim
//! plus lowercase) before every call, so stores compare byte-for-byte and
//! never fold case or whitespace themselves.

use std::fmt::Debug;

use crate::error::AuthError;
use crate::user::AuthUser;

/// Auth-space identity material for one authentication subject.
///
/// Library-owned: sessions point at the [`auth_id`](Self::auth_id),
/// credentials attach to it, and revocation scopes by it. The application
/// model stays behind [`app_ref`](Self::app_ref), resolved app-side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSubject<AuthId, AppRef> {
    /// Stable subject identifier.
    pub auth_id: AuthId,
    /// Opaque application key (`None` until app association established).
    pub app_ref: Option<AppRef>,
    /// Credential-version binding (session invalidation on secret change).
    pub auth_hash: Option<String>,
}

/// Atomic signup claim result.
///
/// The persisted subject, or nothing when the identifier (or overridden id)
/// was already taken.
pub type SubjectClaim<AuthId, AppRef> = Option<AuthSubject<AuthId, AppRef>>;

/// Subject material paired with its stored secret, absent for unknown
/// identifiers.
pub type StoredCredential<AuthId, AppRef> = Option<(AuthSubject<AuthId, AppRef>, String)>;

/// Stores authentication subjects and their app links.
///
/// Subjects are method-agnostic: every current and future credential family
/// attaches to the same subject rows, and the app association hangs off the
/// subject, never off individual credentials.
pub trait SubjectStore: Debug + Send + Sync {
    /// Subject identifier type.
    type AuthId: Clone + Eq + Debug + Send + Sync + 'static;
    /// Opaque application key type.
    type AppRef: Clone + Eq + Debug + Send + Sync + 'static;
    /// Per-store signup material (new fields, existing refs, or nothing).
    type AppSetup;

    /// Atomically provisions subject, first credential, and app link.
    ///
    /// One indivisible claim: the id mint-or-override, the app setup, and
    /// the credential row land together or not at all. A separate lookup
    /// followed by writes would let two racing signups both pass the check
    /// and overwrite each other.
    ///
    /// `id_override` adopts a caller-chosen subject id (explicit control);
    /// `None` mints one (the default). `app` carries store-defined setup:
    /// fields for stores that build app rows, an existing ref for stores
    /// that link, or nothing for pure subject infrastructure. The identifier
    /// arrives engine-normalized; compare it byte-for-byte, one canonical
    /// row per key. Taken identifiers (or taken overridden ids) write
    /// nothing and return `Ok(None)`.
    ///
    /// # Errors
    /// Returns an error if the underlying store fails.
    #[must_use = "the provisioning result must be checked"]
    fn provision_subject(
        &self,
        id_override: Option<Self::AuthId>,
        app: Self::AppSetup,
        provider: &str,
        identifier: &str,
        secret_hash: &str,
    ) -> Result<SubjectClaim<Self::AuthId, Self::AppRef>, AuthError>;

    /// Loads subject material by auth id.
    ///
    /// Returns `Ok(None)` for unknown subjects.
    ///
    /// # Errors
    /// Returns an error if the underlying store fails.
    #[must_use = "the store result must be used"]
    fn find_subject(
        &self,
        auth_id: &Self::AuthId,
    ) -> Result<SubjectClaim<Self::AuthId, Self::AppRef>, AuthError>;

    /// Links an app record to an existing subject (adoption).
    ///
    /// Returns `Ok(true)` when linked (or already linked to the same ref)
    /// and `Ok(false)` when the subject is bound elsewhere; the elsewhere
    /// binding is never overwritten. Adoption that also needs a first
    /// credential composes this with
    /// [`attach_credential`](CredentialStore::attach_credential).
    ///
    /// # Errors
    /// Returns `AuthError::InvalidCredentials` for unknown subjects, or a
    /// store error if the underlying store fails.
    #[must_use = "the link result must be checked"]
    fn set_app_link(
        &self,
        auth_id: &Self::AuthId,
        app_ref: &Self::AppRef,
    ) -> Result<bool, AuthError>;

    /// Translates an app key to its subject id (admin direction).
    ///
    /// Lets app-side lifecycle (admin delete, sign-out-everywhere,
    /// self-deletion, admin attach) reach subject-scoped operations, which
    /// compose safely: every follow-up act degrades benignly when the
    /// subject is already gone. Privileged like attach: authorize first.
    /// Returns `Ok(None)` for unlinked keys.
    ///
    /// # Errors
    /// Returns an error if the underlying store fails.
    #[must_use = "the translation result must be used"]
    fn find_auth_id(&self, app_ref: &Self::AppRef) -> Result<Option<Self::AuthId>, AuthError>;

    /// Deletes a subject with its credentials and sessions.
    ///
    /// The cascade root for auth-side lifecycle. Idempotent: missing
    /// subjects succeed, so app-side cascades never strand on retries.
    /// Application rows are the application's own cascade, not this call's.
    ///
    /// # Errors
    /// Returns an error if the underlying store fails.
    #[must_use = "subject deletion must be acknowledged"]
    fn delete_subject(&self, auth_id: &Self::AuthId) -> Result<(), AuthError>;
}

/// Stores credentials against subjects (v0.1: passwords).
///
/// Method-agnostic structure: each credential names its subject and its
/// provider method (`email` today; `google`, `passkey`, and so on later),
/// so future families attach without schema changes. The v0.1 verbs all
/// pass the email provider; the discriminator is already threaded so the
/// second family never needs a redesign.
pub trait CredentialStore: SubjectStore {
    /// Loads subject material with the stored secret by method and identifier.
    ///
    /// The identifier arrives engine-normalized; match the
    /// provider-plus-identifier pair exactly for one canonical row per key.
    /// Providers are closed lowercase vocabulary (`email` in v0.1). The
    /// engine verifies `secret` against the returned hash; the store never
    /// receives plaintext from the login path and never verifies itself.
    /// Returning the hash lets the engine apply timing defense on
    /// unknown-identifier logins.
    ///
    /// # Errors
    /// Returns an error if the underlying store fails.
    #[must_use = "the lookup result must be used"]
    fn find_credential(
        &self,
        provider: &str,
        identifier: &str,
    ) -> Result<StoredCredential<Self::AuthId, Self::AppRef>, AuthError>;

    /// Attaches a credential to an existing subject.
    ///
    /// The companion to provisioning: provisioning creates the subject
    /// *and* its first credential, attaching adds another login to a
    /// subject that already exists (imports, admin rows, SSO links, second
    /// identifiers, second factors). Never creates subjects.
    ///
    /// Atomic: taken identifiers write nothing and return `Ok(false)`;
    /// the existence check and the write land as one indivisible step.
    /// Privileged: callers authorize first, since anyone reaching this
    /// binds a new login to the account.
    ///
    /// # Errors
    /// Returns `AuthError::InvalidCredentials` for unknown subjects, or a
    /// store error if the underlying store fails.
    #[must_use = "the attach result must be checked"]
    fn attach_credential(
        &self,
        auth_id: &Self::AuthId,
        provider: &str,
        identifier: &str,
        secret_hash: &str,
    ) -> Result<bool, AuthError>;

    /// Rotates a subject's secret and bumps its version binding.
    ///
    /// Rewrites every credential row for the subject, so no stale secret
    /// survives on any identifier. Unknown subjects are a silent no-op
    /// `Ok(())`: the engine only calls this after proving the subject
    /// exists.
    ///
    /// # Errors
    /// Returns an error if the underlying store fails.
    #[must_use = "a failed secret rotation must be handled"]
    fn rotate_secret(&self, auth_id: &Self::AuthId, new_hash: &str) -> Result<(), AuthError>;
}

/// Resolves application models from opaque app keys (app-side only).
///
/// Called by outer layers (facade conveniences, Dioxus hooks, server
/// helpers), never the engine. Stores bundling an app model implement
/// this; pure subject infrastructure leaves resolution to the application.
pub trait UserStore: SubjectStore {
    /// The application user type.
    type User: AuthUser;

    /// Loads one application user by its opaque key.
    ///
    /// Returns `Ok(None)` for unknown keys (including subjects whose app
    /// association was never established).
    ///
    /// # Errors
    /// Returns an error if the underlying store fails.
    #[must_use = "the store result must be used"]
    fn resolve(&self, app_ref: &Self::AppRef) -> Result<Option<Self::User>, AuthError>;
}
