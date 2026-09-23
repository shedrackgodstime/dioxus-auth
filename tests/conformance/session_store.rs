//! Conformance tests: `MemoryStore` as a `SessionStore`.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

#[path = "../common/mod.rs"]
mod common;

use common::TestUser;
use dioxus_auth::{MemoryStore, Session, SessionId, SessionStore};

fn storage_session(user_id: u64, created_at: u64, expires_at: u64) -> Session<u64> {
    let storage_id = SessionId::generate().hash_for_storage();
    return Session::new(storage_id, user_id, created_at, expires_at);
}

#[test]
fn save_then_find_roundtrip() {
    let store = MemoryStore::<TestUser>::new();
    let session = storage_session(5, 1000, 2000);
    let id = session.id().clone();
    store.save_session(session).unwrap();

    let found = store.find_session(&id).unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().user_id(), &5);
}

#[test]
fn find_missing_session_is_none() {
    let store = MemoryStore::<TestUser>::new();

    let found = store.find_session(&SessionId::generate()).unwrap();
    assert!(found.is_none());
}

#[test]
fn delete_session_removes_it() {
    let store = MemoryStore::<TestUser>::new();
    let session = storage_session(5, 1000, 2000);
    let id = session.id().clone();
    store.save_session(session).unwrap();

    store.delete_session(&id).unwrap();

    let found = store.find_session(&id).unwrap();
    assert!(found.is_none());
}

#[test]
fn delete_user_sessions_removes_only_that_user() {
    let store = MemoryStore::<TestUser>::new();
    let alice = TestUser::new(1, "alice");
    let bob = TestUser::new(2, "bob");
    let alice_session = storage_session(alice.id, 1000, 2000);
    let bob_session = storage_session(bob.id, 1000, 2000);
    store.save_session(alice_session).unwrap();
    store.save_session(bob_session).unwrap();

    store.delete_user_sessions(&alice.id).unwrap();

    assert_eq!(store.list_user_sessions(&alice.id).unwrap().len(), 0);
    let bob_sessions = store.list_user_sessions(&bob.id).unwrap();
    assert_eq!(bob_sessions.len(), 1);
    assert_eq!(bob_sessions[0].user_id(), &bob.id);
}

#[test]
fn list_user_sessions_returns_matching_sessions_only() {
    let store = MemoryStore::<TestUser>::new();
    let alice = TestUser::new(1, "alice");
    let bob = TestUser::new(2, "bob");
    store
        .save_session(storage_session(alice.id, 1000, 1200))
        .unwrap();
    store
        .save_session(storage_session(alice.id, 1300, 1500))
        .unwrap();
    store
        .save_session(storage_session(bob.id, 1000, 1200))
        .unwrap();

    let alice_sessions = store.list_user_sessions(&alice.id).unwrap();
    assert_eq!(alice_sessions.len(), 2);
}

#[test]
fn touch_session_if_present_extends_expiry_and_last_active() {
    let store = MemoryStore::<TestUser>::new();
    let session = storage_session(5, 1000, 2000);
    let id = session.id().clone();
    store.save_session(session).unwrap();

    store.touch_session_if_present(&id, 9000, 8000).unwrap();

    let found = store.find_session(&id).unwrap().unwrap();
    assert_eq!(found.expires_at_unix(), 9000);
    assert_eq!(found.last_active_at_unix(), Some(8000));
}

#[test]
fn touch_session_if_present_is_no_op_for_missing() {
    let store = MemoryStore::<TestUser>::new();

    let result = store.touch_session_if_present(&SessionId::generate(), 9000, 8000);
    assert!(result.is_ok());
}
