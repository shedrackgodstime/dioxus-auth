//! Blocking-boundary tests: engine calls leave the async worker.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::sync::Arc;
use std::thread::ThreadId;

use dioxus_auth::{
    AuthEngine, AuthEngineHandle, AuthError, CookieConfig, MemoryStore, PasswordUserStore,
    ServerAuthConfig, SessionId, UserStore,
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

impl UserStore for ProbingUserStore {
    type Id = u64;
    type User = TestUser;

    fn find_by_id(&self, id: &u64) -> Result<Option<TestUser>, AuthError> {
        self.record_lookup_thread();
        return self.inner.find_by_id(id);
    }
}

impl PasswordUserStore for ProbingUserStore {
    fn find_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<(TestUser, String)>, AuthError> {
        self.record_lookup_thread();
        return self.inner.find_by_identifier(identifier);
    }

    fn update_password(&self, id: &u64, new_hash: &str) -> Result<(), AuthError> {
        return self.inner.update_password(id, new_hash);
    }

    fn provision_user_with_password(
        &self,
        user: TestUser,
        identifier: &str,
        password_hash: &str,
    ) -> Result<bool, AuthError> {
        return self
            .inner
            .provision_user_with_password(user, identifier, password_hash);
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
