//! Conformance tests: `MemoryStore` as a `UserStore`.

#[path = "../common/mod.rs"]
mod common;

use common::TestUser;
use dioxus_auth::{MemoryStore, UserStore};

#[test]
fn insert_then_find_by_id() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user(TestUser::new(7, "alice"));

    let found = store.find_by_id(&7).unwrap();
    assert_eq!(found.unwrap().id, 7);
}

#[test]
fn find_missing_user_is_none() {
    let store = MemoryStore::<TestUser>::new();

    let found = store.find_by_id(&404).unwrap();
    assert!(found.is_none());
}

#[test]
fn insert_replaces_existing_user_by_id() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user(TestUser::new(1, "alice"));
    store.insert_user(TestUser::new(1, "alice-renamed"));

    let found = store.find_by_id(&1).unwrap().unwrap();
    assert_eq!(found.name, "alice-renamed");
}

#[test]
fn users_do_not_collide_across_ids() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user(TestUser::new(1, "alice"));
    store.insert_user(TestUser::new(2, "bob"));

    assert_eq!(store.find_by_id(&1).unwrap().unwrap().name, "alice");
    assert_eq!(store.find_by_id(&2).unwrap().unwrap().name, "bob");
}
