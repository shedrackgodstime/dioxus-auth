//! Debug-redaction tests: store secrets must never render.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use dioxus_auth::prelude::{MemoryStore, MemoryTokenStorage, TokenStorage};

use crate::common::TestUser;

#[test]
fn memory_token_storage_debug_redacts_the_wire_token() {
    let mut storage = MemoryTokenStorage::new();
    storage
        .store("sekret-token")
        .expect("in-memory store writes");
    let rendered = format!("{storage:?}");
    assert!(!rendered.contains("sekret-token"));
    assert!(rendered.contains("***"));
}

#[test]
fn memory_store_debug_redacts_hashes_and_identifiers() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(
        TestUser::new(1, "alice@example.com"),
        "alice@example.com",
        "argon2id$hash$sekret",
    );
    let rendered = format!("{store:?}");
    assert!(!rendered.contains("argon2id$hash$sekret"));
    assert!(!rendered.contains("alice@example.com"));
}
