//! Conformance tests: `MemoryStore` as a `PasswordUserStore`.

#[path = "../common/mod.rs"]
mod common;

use common::{TestUser, hash_password};
use dioxus_auth::prelude::{MemoryStore, PasswordUserStore};

#[test]
fn find_by_identifier_returns_user_and_stored_hash() {
    let store = MemoryStore::<TestUser>::new();
    let hash = hash_password("correct horse battery staple");
    store.insert_user_with_password(TestUser::new(3, "bob"), "bob@example.com", hash.clone());

    let found = store
        .find_by_identifier("bob@example.com")
        .unwrap()
        .unwrap();
    assert_eq!(found.0.id, 3);
    assert_eq!(found.1, hash);
}

#[test]
fn find_by_identifier_unknown_is_none() {
    let store = MemoryStore::<TestUser>::new();

    let found = store.find_by_identifier("ghost@example.com").unwrap();
    assert!(found.is_none());
}

#[test]
fn update_password_replaces_the_stored_hash() {
    let store = MemoryStore::<TestUser>::new();
    let old_hash = hash_password("old-secret");
    store.insert_user_with_password(TestUser::new(3, "bob"), "bob", old_hash);

    let new_hash = hash_password("new-secret");
    store.update_password(&3, &new_hash).unwrap();

    let found = store.find_by_identifier("bob").unwrap().unwrap();
    assert_eq!(found.1, new_hash);
}

#[test]
fn insert_with_password_replaces_identifier_credentials() {
    let store = MemoryStore::<TestUser>::new();
    let first_hash = hash_password("first");
    let second_hash = hash_password("second");
    store.insert_user_with_password(TestUser::new(3, "bob"), "bob", first_hash);
    store.insert_user_with_password(TestUser::new(3, "bob"), "bob", second_hash.clone());

    let found = store.find_by_identifier("bob").unwrap().unwrap();
    assert_eq!(found.0.id, 3);
    assert_eq!(found.1, second_hash);
}

#[test]
fn password_hash_is_not_material_for_lookup() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(9, "carol"), "carol", "not-an-argon2-hash");

    let found = store.find_by_identifier("carol").unwrap().unwrap();
    assert_eq!(found.0.id, 9);
}
