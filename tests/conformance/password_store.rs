//! Conformance tests: `MemoryStore` as a `CredentialStore`.

#[path = "../common/mod.rs"]
mod common;
#[path = "../common/password.rs"]
mod password;

use common::TestUser;
use dioxus_auth::{AuthError, CredentialStore, MemoryStore, SubjectStore, UserStore};
use password::hash_password;

#[test]
fn find_credential_returns_subject_and_stored_hash() {
    let store = MemoryStore::<TestUser>::new();
    let hash = hash_password("correct horse battery staple");
    store.insert_user_with_password(TestUser::new(3, "bob"), "bob@example.com", hash.clone());

    let found = store
        .find_credential("email", "bob@example.com")
        .unwrap()
        .unwrap();
    assert_eq!(found.0.app_ref, Some(3));
    assert_eq!(found.1, hash);
}

#[test]
fn find_credential_unknown_is_none() {
    let store = MemoryStore::<TestUser>::new();

    let found = store.find_credential("email", "ghost@example.com").unwrap();
    assert!(found.is_none());
}

#[test]
fn rotate_secret_replaces_the_stored_hash() {
    let store = MemoryStore::<TestUser>::new();
    let old_hash = hash_password("old-secret");
    store.insert_user_with_password(TestUser::new(3, "bob"), "bob", old_hash);
    let created = store.find_credential("email", "bob").unwrap().unwrap();

    let new_hash = hash_password("new-secret");
    store.rotate_secret(&created.0.auth_id, &new_hash).unwrap();

    let found = store.find_credential("email", "bob").unwrap().unwrap();
    assert_eq!(found.1, new_hash);
}

#[test]
fn rotate_secret_rebinds_subject_sessions_to_the_new_secret() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(3, "bob"), "bob", hash_password("old"));
    let created = store.find_credential("email", "bob").unwrap().unwrap();

    let new_hash = hash_password("new-secret");
    store.rotate_secret(&created.0.auth_id, &new_hash).unwrap();

    let rebound = store.find_subject(&created.0.auth_id).unwrap().unwrap();
    assert_eq!(rebound.auth_hash, Some(new_hash));
}

#[test]
fn insert_with_password_replaces_identifier_credentials() {
    let store = MemoryStore::<TestUser>::new();
    let first_hash = hash_password("first");
    let second_hash = hash_password("second");
    store.insert_user_with_password(TestUser::new(3, "bob"), "bob", first_hash);
    store.insert_user_with_password(TestUser::new(3, "bob"), "bob", second_hash.clone());

    let found = store.find_credential("email", "bob").unwrap().unwrap();
    assert_eq!(found.0.app_ref, Some(3));
    assert_eq!(found.1, second_hash);
}

#[test]
fn password_hash_is_not_material_for_lookup() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(9, "carol"), "carol", "not-an-argon2-hash");

    let found = store.find_credential("email", "carol").unwrap().unwrap();
    assert_eq!(found.0.app_ref, Some(9));
}

#[test]
fn provision_claims_a_free_identifier() {
    let store = MemoryStore::<TestUser>::new();
    let hash = hash_password("first");

    let created = store
        .provision_subject(None, TestUser::new(3, "bob"), "email", "bob", &hash)
        .unwrap()
        .expect("free identifier must provision");
    assert_eq!(created.auth_id, 1);
    assert_eq!(created.app_ref, Some(3));
    assert_eq!(created.auth_hash, Some(hash.clone()));

    let found = store.find_credential("email", "bob").unwrap().unwrap();
    assert_eq!(found.0.auth_id, created.auth_id);
    assert_eq!(found.1, hash);
    let user = store.resolve(&3).unwrap().unwrap();
    assert_eq!(user.name, "bob");
}

#[test]
fn provision_rejects_a_taken_identifier_without_state_change() {
    let store = MemoryStore::<TestUser>::new();
    let winner_hash = hash_password("winner");
    let loser_hash = hash_password("loser");
    let winner = store
        .provision_subject(None, TestUser::new(3, "bob"), "email", "bob", &winner_hash)
        .unwrap()
        .expect("first claim must succeed");

    let taken = store
        .provision_subject(
            None,
            TestUser::new(4, "mallory"),
            "email",
            "bob",
            &loser_hash,
        )
        .unwrap();
    assert!(
        taken.is_none(),
        "a taken identifier must not be claimed twice"
    );

    let found = store.find_credential("email", "bob").unwrap().unwrap();
    assert_eq!(found.0.auth_id, winner.auth_id);
    assert_eq!(found.1, winner_hash);
    assert!(
        store.resolve(&4).unwrap().is_none(),
        "the losing app row must not be written"
    );
}

#[test]
fn provision_rejects_a_duplicate_app_id_without_state_change() {
    let store = MemoryStore::<TestUser>::new();
    let hash = hash_password("winner");
    store
        .provision_subject(None, TestUser::new(3, "bob"), "email", "bob", &hash)
        .unwrap();

    let taken = store
        .provision_subject(
            None,
            TestUser::new(3, "cloned-row"),
            "email",
            "cloned-row",
            &hash,
        )
        .unwrap();
    assert!(
        taken.is_none(),
        "a duplicate app id must not be claimed twice"
    );

    assert!(
        store
            .find_credential("email", "cloned-row")
            .unwrap()
            .is_none(),
        "the losing credential row must not be written"
    );
    let survivor = store.find_credential("email", "bob").unwrap().unwrap();
    assert_eq!(survivor.0.app_ref, Some(3));
    assert_eq!(survivor.1, hash);
}

#[test]
fn attach_adds_a_second_identifier_to_an_existing_subject() {
    let store = MemoryStore::<TestUser>::new();
    let first_hash = hash_password("first");
    let second_hash = hash_password("second");
    let created = store
        .provision_subject(None, TestUser::new(3, "bob"), "email", "bob", &first_hash)
        .unwrap()
        .expect("claim must succeed");

    let attached = store
        .attach_credential(&created.auth_id, "email", "bobby", &second_hash)
        .unwrap();
    assert!(attached);

    let added = store.find_credential("email", "bobby").unwrap().unwrap();
    assert_eq!(added.0.auth_id, created.auth_id);
    assert_eq!(added.1, second_hash);
    let original = store.find_credential("email", "bob").unwrap().unwrap();
    assert_eq!(original.1, first_hash);
}

#[test]
fn attach_rejects_a_taken_identifier_without_state_change() {
    let store = MemoryStore::<TestUser>::new();
    let winner_hash = hash_password("winner");
    let created = store
        .provision_subject(None, TestUser::new(3, "bob"), "email", "bob", &winner_hash)
        .unwrap()
        .expect("claim must succeed");

    let attached = store
        .attach_credential(&created.auth_id, "email", "bob", &hash_password("loser"))
        .unwrap();
    assert!(!attached, "a taken identifier must not be attached twice");

    let survivor = store.find_credential("email", "bob").unwrap().unwrap();
    assert_eq!(survivor.0.auth_id, created.auth_id);
    assert_eq!(survivor.1, winner_hash);
}

#[test]
fn attach_rejects_an_unknown_subject() {
    let store = MemoryStore::<TestUser>::new();

    let result = store.attach_credential(&404, "email", "ghost", &hash_password("pw"));
    assert_eq!(
        result.unwrap_err(),
        AuthError::InvalidCredentials,
        "attaching to a missing subject must fail without writing"
    );
    assert!(store.find_credential("email", "ghost").unwrap().is_none());
}

/// Rotating a secret rewrites every credential row for the subject, so a
/// subject with several identifiers keeps no stale hash behind (parity with
/// the reference SQL store, which updates by `auth_id`).
#[test]
fn rotate_secret_rewrites_all_rows_for_the_subject() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(3, "bob"), "bob@example.com", "old");
    store.insert_user_with_password(TestUser::new(3, "bob"), "bobby@example.com", "old");
    let created = store
        .find_credential("email", "bob@example.com")
        .unwrap()
        .unwrap();
    store
        .rotate_secret(&created.0.auth_id, "new")
        .expect("secret rotation must succeed");

    for identifier in ["bob@example.com", "bobby@example.com"] {
        let found = store
            .find_credential("email", identifier)
            .expect("lookup must succeed")
            .expect("row must exist");
        assert_eq!(found.1, "new", "no stale hash may survive on any row");
    }
}
