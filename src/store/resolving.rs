//! Loader-backed store adapter: subject infrastructure plus resolution.
//!
//! For split architectures: a subject, credential, and session store that
//! knows nothing about application models, paired with one loader function
//! that does. Every auth-space operation delegates to the inner store; only
//! [`UserStore::resolve`] runs the loader. The loader executes
//! synchronously inside resolve calls (same contract as the engine loader
//! closures); async data layers bridge at their own edge.

use std::fmt::{self, Debug};
use std::sync::Arc;

use crate::error::AuthError;
use crate::session::Session;
use crate::status::SessionId;
use crate::store::session::SessionStore;
use crate::store::user::{
    CredentialStore, StoredCredential, SubjectClaim, SubjectStore, UserStore,
};
use crate::user::AuthUser;

/// Application resolution supplied as shared caller code.
///
/// Kept unexported: callers name the closure at construction (`new`), never
/// the type. Sharing through `Arc` lets handles clone without re-wrapping.
type AppLoader<S, U> =
    Arc<dyn Fn(&<S as SubjectStore>::AppRef) -> Result<Option<U>, AuthError> + Send + Sync>;

/// Subject store with application resolution supplied as a closure.
///
/// Construct once around any subject store and mount the result wherever a
/// resolving store is expected (`Auth::new`, `AuthProvider`). The closure
/// maps application keys to models with no traits and no subject
/// vocabulary; fail-closed and outage semantics match the engine loaders
/// (missing resolves to `None`, errors propagate).
pub struct ResolvingStore<S: SubjectStore, U> {
    inner: S,
    loader: AppLoader<S, U>,
}

impl<S: SubjectStore, U> Debug for ResolvingStore<S, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return f
            .debug_struct("ResolvingStore")
            .field("inner", &self.inner)
            .field("loader", &"<loader>")
            .finish();
    }
}

impl<S: SubjectStore, U> ResolvingStore<S, U> {
    /// Pairs a subject store with an application loader.
    ///
    /// The loader runs on every resolve call for the lifetime of the
    /// adapter; keep it fast and non-blocking like any render-path store
    /// call.
    #[must_use = "the configured adapter must be used"]
    pub fn new(
        inner: S,
        loader: impl Fn(&S::AppRef) -> Result<Option<U>, AuthError> + Send + Sync + 'static,
    ) -> Self {
        return Self {
            inner,
            loader: Arc::new(loader),
        };
    }
}

impl<S: SubjectStore, U> SubjectStore for ResolvingStore<S, U> {
    type AuthId = S::AuthId;
    type AppRef = S::AppRef;
    type AppSetup = S::AppSetup;

    fn provision_subject(
        &self,
        id_override: Option<Self::AuthId>,
        app: Self::AppSetup,
        provider: &str,
        identifier: &str,
        secret_hash: &str,
    ) -> Result<SubjectClaim<Self::AuthId, Self::AppRef>, AuthError> {
        return self
            .inner
            .provision_subject(id_override, app, provider, identifier, secret_hash);
    }

    fn find_subject(
        &self,
        auth_id: &Self::AuthId,
    ) -> Result<SubjectClaim<Self::AuthId, Self::AppRef>, AuthError> {
        return self.inner.find_subject(auth_id);
    }

    fn set_app_link(
        &self,
        auth_id: &Self::AuthId,
        app_ref: &Self::AppRef,
    ) -> Result<bool, AuthError> {
        return self.inner.set_app_link(auth_id, app_ref);
    }

    fn find_auth_id(&self, app_ref: &Self::AppRef) -> Result<Option<Self::AuthId>, AuthError> {
        return self.inner.find_auth_id(app_ref);
    }

    fn delete_subject(&self, auth_id: &Self::AuthId) -> Result<(), AuthError> {
        return self.inner.delete_subject(auth_id);
    }
}

impl<S: CredentialStore, U> CredentialStore for ResolvingStore<S, U> {
    fn find_credential(
        &self,
        provider: &str,
        identifier: &str,
    ) -> Result<StoredCredential<Self::AuthId, Self::AppRef>, AuthError> {
        return self.inner.find_credential(provider, identifier);
    }

    fn attach_credential(
        &self,
        auth_id: &Self::AuthId,
        provider: &str,
        identifier: &str,
        secret_hash: &str,
    ) -> Result<bool, AuthError> {
        return self
            .inner
            .attach_credential(auth_id, provider, identifier, secret_hash);
    }

    fn rotate_secret(&self, auth_id: &Self::AuthId, new_hash: &str) -> Result<(), AuthError> {
        return self.inner.rotate_secret(auth_id, new_hash);
    }
}

impl<S, U> SessionStore for ResolvingStore<S, U>
where
    S: CredentialStore + SessionStore<AuthId = <S as SubjectStore>::AuthId>,
{
    type AuthId = <S as SubjectStore>::AuthId;

    fn save_session(&self, session: Session<Self::AuthId>) -> Result<(), AuthError> {
        return self.inner.save_session(session);
    }

    fn find_session(&self, id: &SessionId) -> Result<Option<Session<Self::AuthId>>, AuthError> {
        return self.inner.find_session(id);
    }

    fn delete_session(&self, id: &SessionId) -> Result<(), AuthError> {
        return self.inner.delete_session(id);
    }

    fn touch_session_if_present(
        &self,
        id: &SessionId,
        new_expiry: u64,
        last_active: u64,
    ) -> Result<(), AuthError> {
        return self
            .inner
            .touch_session_if_present(id, new_expiry, last_active);
    }

    fn delete_subject_sessions(&self, auth_id: &Self::AuthId) -> Result<(), AuthError> {
        return self.inner.delete_subject_sessions(auth_id);
    }

    fn list_subject_sessions(
        &self,
        auth_id: &Self::AuthId,
    ) -> Result<Vec<Session<Self::AuthId>>, AuthError> {
        return self.inner.list_subject_sessions(auth_id);
    }
}

impl<S: SubjectStore, U: AuthUser> UserStore for ResolvingStore<S, U> {
    type User = U;

    fn resolve(&self, app_ref: &Self::AppRef) -> Result<Option<Self::User>, AuthError> {
        return (self.loader)(app_ref);
    }
}
