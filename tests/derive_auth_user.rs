use dioxus_auth::{Argon2Hasher, AuthEngine, AuthUser, MemoryStore, PasswordHasher};
use std::sync::Arc;
use std::time::Duration;

#[derive(dioxus_auth_derive::AuthUser, Clone, PartialEq, Eq, Debug)]
#[auth_user(id = "id")]
struct DerivedUser {
    id: u64,
    name: String,
}

#[derive(dioxus_auth_derive::AuthUser, Clone, PartialEq, Eq, Debug)]
#[auth_user(id = "id", session_auth_hash = "password_hash")]
struct DerivedHashUser {
    id: u64,
    email: String,
    password_hash: String,
}

#[tokio::test(flavor = "current_thread")]
async fn derive_auth_user_generates_id() {
    let user = DerivedUser {
        id: 42,
        name: "Derived".into(),
    };
    assert_eq!(user.id(), 42);
    assert_eq!(user.session_auth_hash(), None);
}

#[tokio::test(flavor = "current_thread")]
async fn derive_auth_user_generates_session_auth_hash() {
    let user = DerivedHashUser {
        id: 7,
        email: "hash@example.com".into(),
        password_hash: "abc123".into(),
    };
    assert_eq!(user.id(), 7);
    assert_eq!(user.session_auth_hash(), Some("abc123"));
}

#[tokio::test(flavor = "current_thread")]
async fn derive_auth_user_works_with_auth_engine() {
    let store = Arc::new(MemoryStore::<DerivedHashUser>::new());
    let hasher = Argon2Hasher::new();
    let password = "derive_engine_pw";
    let password_hash = hasher.hash_password(password).unwrap();

    let user = DerivedHashUser {
        id: 901,
        email: "derive@example.com".into(),
        password_hash: password_hash.clone(),
    };
    store.insert_user_with_password(user.clone(), "derive@example.com", &password_hash);

    let engine = AuthEngine::builder(store.clone(), store.clone())
        .session_ttl(Duration::from_secs(3600))
        .build();

    let found = engine
        .identifier_exists("derive@example.com")
        .await
        .unwrap();
    assert!(found);

    let result = engine.login("derive@example.com", password).await;
    assert!(result.is_ok());
}
