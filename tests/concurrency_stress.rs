//! Spec-16 concurrency and expiry tests.
//!
//! The race tests use a `SessionStore` wrapper that lets the test deterministically
//! force the logout/rotate window to interleave with a concurrent `validate_session`,
//! then assert the session was never resurrected.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

mod common;
#[path = "common/identity_hasher.rs"]
mod identity_hasher;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use common::TestUser;
use dioxus_auth::prelude::{AuthEngine, AuthError, MemoryStore, Session, SessionId, SessionStore};
use identity_hasher::IdentityHasher;
use parking_lot::Mutex;

const FIVE_SECONDS: Duration = Duration::from_secs(60);

/// A `SessionStore` decorator that lets a test park in the middle of the engine's
/// read→touch window and deterministically finish the logout/rotate delete first.
#[derive(Debug)]
struct ChoreographedStore {
    inner: MemoryStore<TestUser>,
    found_tx: std::sync::mpsc::Sender<()>,
    found_rx: Mutex<std::sync::mpsc::Receiver<()>>,
    deleted_tx: std::sync::mpsc::Sender<()>,
    deleted_rx: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl ChoreographedStore {
    /// Creates a store with empty handshake channels.
    #[must_use]
    pub fn new() -> Self {
        let (found_tx, found_rx) = std::sync::mpsc::channel();
        let (deleted_tx, deleted_rx) = std::sync::mpsc::channel();
        return Self {
            inner: MemoryStore::new(),
            found_tx,
            found_rx: Mutex::new(found_rx),
            deleted_tx,
            deleted_rx: Mutex::new(deleted_rx),
        };
    }

    /// Waits until a session lookup observed the target session.
    pub fn await_found(&self) -> Result<(), ()> {
        let received = self.found_rx.lock().recv_timeout(FIVE_SECONDS);
        return match received {
            Ok(()) => Ok(()),
            Err(_) => Err(()),
        };
    }

    /// Releases a concurrent touch so it observes the delete that already happened.
    pub fn signal_deleted(&self) {
        debug_assert!(self.deleted_tx.send(()).is_ok());
    }
}

impl Default for ChoreographedStore {
    fn default() -> Self {
        return Self::new();
    }
}

impl SessionStore for ChoreographedStore {
    type Id = u64;

    fn save_session(&self, session: Session<u64>) -> Result<(), AuthError> {
        return self.inner.save_session(session);
    }

    fn find_session(&self, id: &SessionId) -> Result<Option<Session<u64>>, AuthError> {
        let found = match self.inner.find_session(id) {
            Ok(found) => found,
            Err(error) => return Err(error),
        };
        if found.is_some() {
            self.found_tx.send(()).unwrap();
        }
        return Ok(found);
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
        self.deleted_rx.lock().recv_timeout(FIVE_SECONDS).unwrap();
        return self
            .inner
            .touch_session_if_present(id, new_expiry, last_active);
    }

    fn delete_user_sessions(&self, user_id: &u64) -> Result<(), AuthError> {
        return self.inner.delete_user_sessions(user_id);
    }

    fn list_user_sessions(&self, user_id: &u64) -> Result<Vec<Session<u64>>, AuthError> {
        return self.inner.list_user_sessions(user_id);
    }
}

/// Builds an engine over a user store + choreographed session store.
#[must_use]
fn choreographed_engine(
    clock: &Arc<AtomicU64>,
    single_active: bool,
) -> AuthEngine<MemoryStore<TestUser>, ChoreographedStore> {
    let users = Arc::new(MemoryStore::<TestUser>::new());
    users.insert_user_with_password(TestUser::new(1, "alice"), "alice", "pw");
    let sessions = Arc::new(ChoreographedStore::new());
    let clock_t = Arc::clone(clock);
    return AuthEngine::builder(Arc::clone(&users), Arc::clone(&sessions))
        .hasher(IdentityHasher)
        .idle_timeout_secs(3_600)
        .single_active_session(single_active)
        .with_clock(move || return clock_t.load(Ordering::SeqCst))
        .build()
        .expect("engine construction must succeed");
}

/// Builds a plain-engine over an in-memory store with a controllable clock.
#[must_use]
fn clocked_engine(
    clock: &Arc<AtomicU64>,
    session_ttl_secs: u64,
    idle_timeout_secs: Option<u64>,
) -> AuthEngine<MemoryStore<TestUser>, MemoryStore<TestUser>> {
    let store = Arc::new(MemoryStore::<TestUser>::new());
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", "pw");
    let clock_t = Arc::clone(clock);
    let mut builder = AuthEngine::builder(Arc::clone(&store), store)
        .hasher(IdentityHasher)
        .session_ttl_secs(session_ttl_secs);
    if let Some(idle) = idle_timeout_secs {
        builder = builder.idle_timeout_secs(idle);
    }
    return builder
        .with_clock(move || return clock_t.load(Ordering::SeqCst))
        .build()
        .expect("engine construction must succeed");
}

#[test]
fn logout_concurrent_with_validate_does_not_resurrect() {
    let clock = Arc::new(AtomicU64::new(1_000));
    let engine = Arc::new(choreographed_engine(&clock, false));
    let (_, session) = engine.login("alice", "pw").unwrap();
    let storage_id = session.id().hash_for_storage();

    let validate_engine = Arc::clone(&engine);
    let validate_id = session.id().clone();
    let handle = std::thread::spawn(move || {
        return validate_engine.validate_session(&validate_id);
    });

    engine.session_store().await_found().unwrap();
    engine.logout(session.id()).unwrap();
    engine.session_store().signal_deleted();

    let validated = handle.join().expect("validate thread must not panic");
    assert!(validated.unwrap().is_some());
    assert!(
        engine
            .session_store()
            .find_session(&storage_id)
            .unwrap()
            .is_none()
    );
    assert!(engine.validate_session(session.id()).unwrap().is_none());
}

#[test]
fn rotate_concurrent_with_validate_keeps_old_session_dead() {
    let clock = Arc::new(AtomicU64::new(1_000));
    let engine = Arc::new(choreographed_engine(&clock, true));
    let (_, old_session) = engine.login("alice", "pw").unwrap();
    let old_storage_id = old_session.id().hash_for_storage();

    let validate_engine = Arc::clone(&engine);
    let old_id = old_session.id().clone();
    let handle = std::thread::spawn(move || {
        return validate_engine.validate_session(&old_id);
    });

    engine.session_store().await_found().unwrap();
    let (user, new_session) = engine.login("alice", "pw").unwrap();
    assert_eq!(user.id, 1);
    engine.session_store().signal_deleted();

    let validated = handle.join().expect("validate thread must not panic");
    assert!(validated.unwrap().is_some());
    assert!(
        engine
            .session_store()
            .find_session(&old_storage_id)
            .unwrap()
            .is_none()
    );
    assert!(engine.validate_session(old_session.id()).unwrap().is_none());
    let new_storage_id = new_session.id().hash_for_storage();
    assert!(
        engine
            .session_store()
            .find_session(&new_storage_id)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        engine.session_store().list_user_sessions(&1).unwrap().len(),
        1
    );
}

#[test]
fn idle_timeout_expires_the_session_after_inactivity() {
    let clock = Arc::new(AtomicU64::new(10_000));
    let engine = clocked_engine(&clock, 3_600, Some(30));
    let (_, session) = engine.login("alice", "pw").unwrap();

    clock.store(10_020, Ordering::SeqCst);
    assert!(engine.validate_session(session.id()).unwrap().is_some());

    clock.store(10_050, Ordering::SeqCst);
    assert!(engine.validate_session(session.id()).unwrap().is_none());

    let storage_id = session.id().hash_for_storage();
    assert!(
        engine
            .session_store()
            .find_session(&storage_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn active_session_never_outlives_the_absolute_ttl() {
    let clock = Arc::new(AtomicU64::new(10_000));
    let engine = clocked_engine(&clock, 60, None);
    let (_, session) = engine.login("alice", "pw").unwrap();
    assert_eq!(session.expires_at_unix(), 10_060);

    clock.store(10_059, Ordering::SeqCst);
    assert!(engine.validate_session(session.id()).unwrap().is_some());

    clock.store(10_060, Ordering::SeqCst);
    assert!(engine.validate_session(session.id()).unwrap().is_none());
    assert!(engine.validate_session(session.id()).unwrap().is_none());
}

#[test]
fn validation_without_idle_timeout_does_not_rewrite_the_session() {
    let clock = Arc::new(AtomicU64::new(1_000));
    let engine = clocked_engine(&clock, 200, None);
    let (_, session) = engine.login("alice", "pw").unwrap();
    let storage_id = session.id().hash_for_storage();

    clock.store(1_050, Ordering::SeqCst);
    assert!(engine.validate_session(session.id()).unwrap().is_some());

    let stored = engine
        .session_store()
        .find_session(&storage_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.last_active_at_unix(), Some(1_000));
    assert_eq!(stored.expires_at_unix(), 1_200);
}
