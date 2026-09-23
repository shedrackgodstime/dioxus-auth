//! Conformance tests: `MemoryStore` as a `PasswordUserStore`.

#[path = "../common/mod.rs"]
mod common;
#[path = "../common/password.rs"]
mod password;

use common::TestUser;
use dioxus_auth::{AuthUser, MemoryStore, PasswordUserStore, UserStore};
use password::hash_password;

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

#[test]
fn provision_claims_a_free_identifier() {
    let store = MemoryStore::<TestUser>::new();
    let hash = hash_password("first");

    let claimed = store
        .provision_user_with_password(TestUser::new(3, "bob"), "bob", &hash)
        .unwrap();
    assert!(claimed);

    let found = store.find_by_identifier("bob").unwrap().unwrap();
    assert_eq!(found.0.id, 3);
    assert_eq!(found.1, hash);
    let user = store.find_by_id(&3).unwrap().unwrap();
    assert_eq!(user.email(), "bob");
}

#[test]
fn provision_rejects_a_taken_identifier_without_state_change() {
    let store = MemoryStore::<TestUser>::new();
    let winner_hash = hash_password("winner");
    let loser_hash = hash_password("loser");
    store
        .provision_user_with_password(TestUser::new(3, "bob"), "bob", &winner_hash)
        .unwrap();

    let claimed = store
        .provision_user_with_password(TestUser::new(4, "mallory"), "bob", &loser_hash)
        .unwrap();
    assert!(!claimed, "a taken identifier must not be claimed twice");

    let found = store.find_by_identifier("bob").unwrap().unwrap();
    assert_eq!(found.0.id, 3, "the winner's user row must survive");
    assert_eq!(found.1, winner_hash, "the winner's credential must survive");
    assert!(
        store.find_by_id(&4).unwrap().is_none(),
        "the losing user row must not be written"
    );
}

#[test]
fn provision_rejects_a_duplicate_user_id_without_state_change() {
    let store = MemoryStore::<TestUser>::new();
    let hash = hash_password("winner");
    store
        .provision_user_with_password(TestUser::new(3, "bob"), "bob", &hash)
        .unwrap();

    let claimed = store
        .provision_user_with_password(TestUser::new(3, "cloned-row"), "cloned-row", &hash)
        .unwrap();
    assert!(!claimed, "a duplicate user id must not be claimed twice");

    assert!(
        store.find_by_identifier("cloned-row").unwrap().is_none(),
        "the losing credential row must not be written"
    );
    let survivor = store.find_by_identifier("bob").unwrap().unwrap();
    assert_eq!(survivor.0.id, 3, "the winner's user row must survive");
    assert_eq!(survivor.1, hash, "the winner's credential must survive");
}

/// Updating a password rewrites every credential row for the user id, so a
/// user with several identifiers keeps no stale hash behind (parity with the
/// reference SQL store, which updates by `user_id`).
#[test]
fn update_password_rewrites_all_rows_for_the_user() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(3, "bob"), "bob@example.com", "old");
    store.insert_user_with_password(TestUser::new(3, "bob"), "bobby@example.com", "old");
    store
        .update_password(&3, "new")
        .expect("password update must succeed");

    for identifier in ["bob@example.com", "bobby@example.com"] {
        let found = store
            .find_by_identifier(identifier)
            .expect("lookup must succeed")
            .expect("row must exist");
        assert_eq!(found.1, "new", "no stale hash may survive on any row");
    }
}
