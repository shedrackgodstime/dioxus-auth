//! Conformance tests: `MemoryStore` as a subject store and app resolver.

#[path = "../common/mod.rs"]
mod common;

use common::TestUser;
use dioxus_auth::{AuthError, AuthSubject, CredentialStore, MemoryStore, SubjectStore, UserStore};

#[test]
fn provision_then_find_subject_roundtrip() {
    let store = MemoryStore::<TestUser>::new();
    let created = store
        .provision_subject(None, TestUser::new(3, "bob"), "bob", "hash")
        .unwrap()
        .expect("free identifier must provision");
    assert_eq!(created.auth_id, 1);

    let found = store.find_subject(&created.auth_id).unwrap();
    assert_eq!(found, Some(created));
}

#[test]
fn find_missing_subject_is_none() {
    let store = MemoryStore::<TestUser>::new();

    let found = store.find_subject(&404).unwrap();
    assert!(found.is_none());
}

#[test]
fn provision_mints_sequential_subject_ids() {
    let store = MemoryStore::<TestUser>::new();
    let first = store
        .provision_subject(None, TestUser::new(3, "bob"), "bob", "hash")
        .unwrap()
        .expect("first claim must succeed");
    let second = store
        .provision_subject(None, TestUser::new(4, "carol"), "carol", "hash")
        .unwrap()
        .expect("second claim must succeed");
    assert_eq!((first.auth_id, second.auth_id), (1, 2));
}

#[test]
fn provision_honors_an_explicit_subject_id_override() {
    let store = MemoryStore::<TestUser>::new();
    let created = store
        .provision_subject(Some(77), TestUser::new(3, "bob"), "bob", "hash")
        .unwrap()
        .expect("override claim must succeed");
    assert_eq!(created.auth_id, 77);
    assert_eq!(
        store.find_subject(&77).unwrap().unwrap().auth_id,
        77,
        "the overridden subject must be retrievable"
    );
}

#[test]
fn provision_rejects_a_taken_subject_id_override() {
    let store = MemoryStore::<TestUser>::new();
    store
        .provision_subject(Some(77), TestUser::new(3, "bob"), "bob", "hash")
        .unwrap();

    let taken = store
        .provision_subject(Some(77), TestUser::new(4, "carol"), "carol", "hash")
        .unwrap();
    assert!(
        taken.is_none(),
        "a taken subject id must be rejected without writes"
    );
    assert!(
        store.find_subject(&77).unwrap().unwrap().app_ref == Some(3),
        "the winner's link must survive"
    );
}

#[test]
fn set_app_link_to_the_same_ref_is_a_no_op_success() {
    // Passthrough stores link at creation, so fresh linking has no v0.1
    // path (it awaits guest-style subject creation); the contract pins the
    // reachable arms: same-ref re-link succeeds without writing.
    let store = MemoryStore::<TestUser>::new();
    let created = store
        .provision_subject(None, TestUser::new(3, "bob"), "bob", "hash")
        .unwrap()
        .expect("claim must succeed");

    let linked = store.set_app_link(&created.auth_id, &3).unwrap();
    assert!(linked);
    assert_eq!(
        store.find_subject(&created.auth_id).unwrap().unwrap().app_ref,
        Some(3)
    );
}

#[test]
fn set_app_link_rejects_a_subject_bound_elsewhere() {
    let store = MemoryStore::<TestUser>::new();
    let created = store
        .provision_subject(None, TestUser::new(3, "bob"), "bob", "hash")
        .unwrap()
        .expect("claim must succeed");

    let linked = store.set_app_link(&created.auth_id, &9).unwrap();
    assert!(
        !linked,
        "re-linking elsewhere must fail without touching the binding"
    );
    assert_eq!(
        store
            .find_subject(&created.auth_id)
            .unwrap()
            .unwrap()
            .app_ref,
        Some(3)
    );
}

#[test]
fn set_app_link_rejects_an_unknown_subject() {
    let store = MemoryStore::<TestUser>::new();
    let result = store.set_app_link(&404, &3);
    assert_eq!(
        result.unwrap_err(),
        AuthError::InvalidCredentials,
        "linking a missing subject must fail"
    );
}

#[test]
fn find_auth_id_translates_an_app_key_to_its_subject() {
    let store = MemoryStore::<TestUser>::new();
    let created = store
        .provision_subject(None, TestUser::new(3, "bob"), "bob", "hash")
        .unwrap()
        .expect("claim must succeed");

    assert_eq!(store.find_auth_id(&3).unwrap(), Some(created.auth_id));
    assert_eq!(store.find_auth_id(&404).unwrap(), None);
}

#[test]
fn delete_subject_removes_auth_rows_but_keeps_app_rows() {
    let store = MemoryStore::<TestUser>::new();
    let created = store
        .provision_subject(None, TestUser::new(3, "bob"), "bob", "hash")
        .unwrap()
        .expect("claim must succeed");
    store
        .attach_credential(&created.auth_id, "bobby", "hash")
        .unwrap();

    store.delete_subject(&created.auth_id).unwrap();

    assert!(store.find_subject(&created.auth_id).unwrap().is_none());
    assert!(store.find_credential("bob").unwrap().is_none());
    assert!(store.find_credential("bobby").unwrap().is_none());
    assert!(store.find_auth_id(&3).unwrap().is_none());
    assert!(
        store.resolve(&3).unwrap().is_some(),
        "application rows are the application's own cascade, not the subject's"
    );
}

#[test]
fn resolve_returns_the_linked_application_user() {
    let store = MemoryStore::<TestUser>::new();
    store
        .provision_subject(None, TestUser::new(3, "bob"), "bob", "hash")
        .unwrap();

    let user = store.resolve(&3).unwrap().expect("linked row must resolve");
    assert_eq!(user, TestUser::new(3, "bob"));
    assert!(store.resolve(&404).unwrap().is_none());
}

#[test]
fn subject_material_reports_its_binding() {
    let store = MemoryStore::<TestUser>::new();
    let created = store
        .provision_subject(None, TestUser::new(3, "bob"), "bob", "hash")
        .unwrap()
        .expect("claim must succeed");
    assert_eq!(
        created,
        AuthSubject {
            auth_id: created.auth_id,
            app_ref: Some(3),
            auth_hash: Some(String::from("hash")),
        }
    );
}
