//! End-to-end tests for the auth-engine lifecycle (login → validate → logout).

// reason: project style requires explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

#[path = "../common/mod.rs"]
mod common;
#[path = "../common/password.rs"]
mod password;

mod faults;
mod hooks;
mod lifecycle;
mod policies;

use std::sync::Arc;

use common::TestUser;
use dioxus_auth::{AuthEngine, MemoryStore};
use password::hash_password;

fn seeded_engine() -> AuthEngine<MemoryStore<TestUser>, MemoryStore<TestUser>> {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", hash_password("s3cret"));
    let store = Arc::new(store);
    return AuthEngine::builder(Arc::clone(&store), store)
        .build()
        .expect("engine construction must succeed");
}
