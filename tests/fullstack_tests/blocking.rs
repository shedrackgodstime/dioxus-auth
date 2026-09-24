//! Blocking-boundary tests: engine calls leave the async worker.

// reason: project style requires explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::sync::Arc;
use std::thread::ThreadId;

use dioxus_auth::{
    AuthEngine, AuthEngineHandle, AuthError, AuthSubject, CookieConfig, CredentialStore,
    MemoryStore, ServerAuthConfig, SessionId, SubjectStore, UserStore,
};
use parking_lot::Mutex;

use super::common::TestUser;
use super::fullstack_shared::{
    IDENTIFIER, PASSWORD, USER_ID, request_parts, response_token, run_login,
};
use super::harness::COOKIE;
use super::identity_hasher::IdentityHasher;

/// A user store that records which thread ran its credential lookup.
///
/// The test task is polled on a multi-thread runtime worker; a lookup that
/// ran inline shares that worker's [`ThreadId`], while a lookup dispatched
/// through `spawn_blocking` lands on a blocking-pool thread with a different
/// id. Delegates everything to a [`MemoryStore`].
#[derive(Debug)]
struct ProbingUserStore {
    inner: Arc<MemoryStore<TestUser>>,
    lookup_thread: Mutex<Option<ThreadId>>,
}

impl ProbingUserStore {
    /// Wraps the inner store with an empty lookup record.
    const fn new(inner: Arc<MemoryStore<TestUser>>) -> Self {
        return Self {
            inner,
            lookup_thread: Mutex::new(None),
        };
    }

    /// Records the calling thread as the latest lookup thread.
    fn record_lookup_thread(&self) {
        let mut slot = self.lookup_thread.lock();
        *slot = Some(std::thread::current().id());
    }

    /// Returns the thread that ran the latest lookup, if any.
    fn ran_on(&self) -> Option<ThreadId> {
        return *self.lookup_thread.lock();
    }
}

impl SubjectStore for ProbingUserStore {
    type AuthId = u64;
    type AppRef = u64;
    type AppSetup = TestUser;

    fn provision_subject(
        &self,
        id_override: Option<Self::AuthId>,
        app: Self::AppSetup,
        provider: &str,
        identifier: &str,
        secret_hash: &str,
    ) -> Result<Option<AuthSubject<Self::AuthId, Self::AppRef>>, AuthError> {
        return self
            .inner
            .provision_subject(id_override, app, provider, identifier, secret_hash);
    }

    fn find_subject(
        &self,
        auth_id: &Self::AuthId,
    ) -> Result<Option<AuthSubject<Self::AuthId, Self::AppRef>>, AuthError> {
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

impl CredentialStore for ProbingUserStore {
    fn find_credential(
        &self,
        provider: &str,
        identifier: &str,
    ) -> Result<Option<(AuthSubject<Self::AuthId, Self::AppRef>, String)>, AuthError> {
        self.record_lookup_thread();
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

impl UserStore for ProbingUserStore {
    type User = TestUser;

    fn resolve(&self, app_ref: &Self::AppRef) -> Result<Option<TestUser>, AuthError> {
        self.record_lookup_thread();
        return self.inner.resolve(app_ref);
    }
}

/// Credential lookups during login must not run on the async worker polling
/// the request: the blocking boundary dispatches engine calls to the blocking
/// pool, observable as a lookup thread different from the test task's own
/// worker thread.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_credential_lookup_runs_off_the_async_worker() {
    let users = Arc::new(MemoryStore::<TestUser>::new());
    users.insert_user_with_password(TestUser::new(USER_ID, IDENTIFIER), IDENTIFIER, PASSWORD);
    let probing = Arc::new(ProbingUserStore::new(Arc::clone(&users)));
    let engine = Arc::new(
        AuthEngine::builder(Arc::clone(&probing), Arc::clone(&users))
            .hasher(IdentityHasher)
            .build()
            .expect("engine construction must succeed"),
    );
    let config = ServerAuthConfig::new(
        AuthEngineHandle::from(engine),
        CookieConfig::new().with_name(String::from(COOKIE)),
    );

    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (result, headers) = run_login(parts, IDENTIFIER, PASSWORD).await;
    result.expect("login must succeed");
    assert!(SessionId::is_valid_wire_format(&response_token(
        &headers, COOKIE
    )));

    let worker_thread = std::thread::current().id();
    let lookup_thread = probing
        .ran_on()
        .expect("the credential lookup must have run");
    assert_ne!(
        lookup_thread, worker_thread,
        "the credential lookup must not run inline on the async worker"
    );
}
