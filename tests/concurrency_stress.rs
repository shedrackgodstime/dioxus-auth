//! Concurrency and expiry tests.
//!
//! The race tests use a `SessionStore` wrapper that lets the test deterministically
//! force the logout/rotate window to interleave with a concurrent `validate_session`,
//! then assert the session was never resurrected.

// reason: project style requires explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

mod common;
#[path = "common/identity_hasher.rs"]
mod identity_hasher;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use common::TestUser;
use dioxus_auth::{
    Auth, AuthEngine, AuthError, AuthSubject, CredentialStore, ErrorCode, MemoryStore, Session,
    SessionId, SessionStore,
};
use identity_hasher::IdentityHasher;
use parking_lot::Mutex;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

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
        let received = self.found_rx.lock().recv_timeout(HANDSHAKE_TIMEOUT);
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
    type AuthId = u64;

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
        self.deleted_rx
            .lock()
            .recv_timeout(HANDSHAKE_TIMEOUT)
            .unwrap();
        return self
            .inner
            .touch_session_if_present(id, new_expiry, last_active);
    }

    fn delete_subject_sessions(&self, auth_id: &u64) -> Result<(), AuthError> {
        return self.inner.delete_subject_sessions(auth_id);
    }

    fn list_subject_sessions(&self, auth_id: &u64) -> Result<Vec<Session<u64>>, AuthError> {
        return self.inner.list_subject_sessions(auth_id);
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

/// Runs `disrupt` while a validation parks in the read→touch window, then
/// returns the parked validation's outcome.
fn parked_validation_outcome(
    engine: &Arc<AuthEngine<MemoryStore<TestUser>, ChoreographedStore>>,
    session_id: &SessionId,
    disrupt: impl FnOnce(),
) -> Option<AuthSubject<u64, u64>> {
    let validate_engine = Arc::clone(engine);
    let validate_id = session_id.clone();
    let handle = std::thread::spawn(move || {
        return validate_engine.validate_session(&validate_id);
    });

    let store = engine.session_store();
    store
        .await_found()
        .expect("validate must park in the read window");
    disrupt();
    store.signal_deleted();

    let validated = handle.join().expect("validate thread must not panic");
    return validated.expect("parked validation must not error");
}

#[test]
fn logout_concurrent_with_validate_does_not_resurrect() {
    let clock = Arc::new(AtomicU64::new(1_000));
    let engine = Arc::new(choreographed_engine(&clock, false));
    let (_, session) = engine.login("alice", "pw").unwrap();
    let storage_id = session.id().hash_for_storage();

    let store = engine.session_store();
    let validated = parked_validation_outcome(&engine, session.id(), || {
        return engine.logout(session.id()).unwrap();
    });
    assert!(validated.is_some());
    assert!(store.find_session(&storage_id).unwrap().is_none());
    assert!(engine.validate_session(session.id()).unwrap().is_none());
}

#[test]
fn rotate_concurrent_with_validate_keeps_old_session_dead() {
    let clock = Arc::new(AtomicU64::new(1_000));
    let engine = Arc::new(choreographed_engine(&clock, true));
    let (_, old_session) = engine.login("alice", "pw").unwrap();
    let old_storage_id = old_session.id().hash_for_storage();

    let validated = parked_validation_outcome(&engine, old_session.id(), || {
        let (user, _new_session) = engine.login("alice", "pw").unwrap();
        assert_eq!(user.auth_id, 1);
    });
    assert!(validated.is_some());
    let store = engine.session_store();
    assert!(store.find_session(&old_storage_id).unwrap().is_none());
    assert!(engine.validate_session(old_session.id()).unwrap().is_none());
    let new_storage_id = store
        .list_subject_sessions(&1)
        .unwrap()
        .first()
        .expect("the rotated session must exist")
        .id()
        .clone();
    assert!(store.find_session(&new_storage_id).unwrap().is_some());
    assert_eq!(store.list_subject_sessions(&1).unwrap().len(), 1);
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

/// Concurrent logins under single-active enforcement must leave exactly one
/// session: rotation and save serialize through the engine's login lock, so
/// no two racers can both survive the window.
#[test]
fn concurrent_logins_under_single_active_leave_exactly_one_session() {
    const RACERS: usize = 8;

    let store = Arc::new(MemoryStore::<TestUser>::new());
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", "pw");
    let engine = Arc::new(
        AuthEngine::builder(Arc::clone(&store), store)
            .hasher(IdentityHasher)
            .single_active_session(true)
            .build()
            .expect("engine construction must succeed"),
    );
    let barrier = Arc::new(std::sync::Barrier::new(RACERS));
    let mut handles = Vec::new();
    for _ in 0..RACERS {
        let engine = Arc::clone(&engine);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            return engine
                .login("alice", "pw")
                .map(|(_, session)| return session.id().clone());
        }));
    }

    let mut wires = Vec::new();
    for handle in handles {
        wires.push(
            handle
                .join()
                .expect("racer must not panic")
                .expect("login must succeed"),
        );
    }
    assert_eq!(wires.len(), RACERS);

    let survivors = engine
        .session_store()
        .list_subject_sessions(&1)
        .expect("listing must not fail");
    assert_eq!(
        survivors.len(),
        1,
        "single-active logins must serialize rotate+save"
    );
    let live = wires
        .iter()
        .filter(|id| {
            return engine
                .validate_session(id)
                .expect("validation must not fail")
                .is_some();
        })
        .count();
    assert_eq!(live, 1, "exactly one wire token may still validate");
}

/// Concurrent sign-ups for one identifier must produce exactly one account:
/// the atomic claim in the store, not a lookup-then-write in the facade, is
/// what decides the winner.
#[test]
fn concurrent_sign_ups_claim_one_identifier_once() {
    const RACERS: usize = 8;
    const IDENTIFIER: &str = "race@example.com";

    let auth = Arc::new(Auth::new(MemoryStore::<TestUser>::new()).expect("facade must construct"));
    let barrier = Arc::new(std::sync::Barrier::new(RACERS));
    let mut handles = Vec::new();
    for index in 0..RACERS {
        let id = index as u64 + 1;
        let auth = Arc::clone(&auth);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            return auth.sign_up_email(IDENTIFIER, "s3cret", TestUser::new(id, "racer"));
        }));
    }

    let mut winners = Vec::new();
    let mut losers = Vec::new();
    for handle in handles {
        match handle.join().expect("racer must not panic") {
            Ok(entry) => winners.push(entry),
            Err(error) => losers.push(error),
        }
    }

    assert_eq!(
        winners.len(),
        1,
        "exactly one sign-up may claim the identifier"
    );
    assert_eq!(losers.len(), RACERS - 1);
    for error in &losers {
        assert_eq!(error.code(), ErrorCode::InvalidCredentials);
    }

    let stored = auth
        .engine()
        .store()
        .find_credential(IDENTIFIER)
        .expect("lookup must not fail")
        .expect("the winner must be stored");
    assert_eq!(
        stored.0.app_ref,
        Some(winners[0].0.id),
        "the stored account must be the winner's"
    );
    return;
}
