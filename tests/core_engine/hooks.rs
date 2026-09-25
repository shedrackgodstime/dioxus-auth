//! Hook tests: sign-in/out/validation callbacks and panic propagation.

// reason: project style requires explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::common::TestUser;
use super::password::hash_password;
use dioxus_auth::{AuthEngine, AuthEngineBuilder, AuthError, MemoryStore};

/// Builds an engine with a hook configuration applied.
fn hook_engine(
    configure: impl FnOnce(
        AuthEngineBuilder<MemoryStore<TestUser>, MemoryStore<TestUser>>,
    ) -> AuthEngineBuilder<MemoryStore<TestUser>, MemoryStore<TestUser>>,
) -> AuthEngine<MemoryStore<TestUser>, MemoryStore<TestUser>> {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", hash_password("pw"));
    let store = Arc::new(store);
    let builder = AuthEngine::builder(Arc::clone(&store), store);
    return configure(builder)
        .build()
        .expect("engine construction must succeed");
}

#[test]
fn sign_in_hook_is_fired_on_successful_login() {
    let fired = Arc::new(AtomicBool::new(false));
    let fired_flag = Arc::clone(&fired);
    let engine = hook_engine(|builder| {
        return builder.on_sign_in(move |subject| {
            assert_eq!(subject.auth_id, 1);
            fired_flag.store(true, Ordering::SeqCst);
        });
    });

    engine.login("alice", "pw").unwrap();

    assert!(fired.load(Ordering::SeqCst));
}

#[test]
fn sign_out_hook_is_fired_on_logout() {
    let fired = Arc::new(AtomicBool::new(false));
    let fired_flag = Arc::clone(&fired);
    let engine = hook_engine(|builder| {
        return builder.on_sign_out(move |_user| {
            fired_flag.store(true, Ordering::SeqCst);
        });
    });

    let (_, session) = engine.login("alice", "pw").unwrap();
    engine.logout(session.id()).unwrap();

    assert!(fired.load(Ordering::SeqCst));
}

#[test]
fn on_session_validated_hook_is_fired_per_validation() {
    let count = Arc::new(AtomicBool::new(false));
    let count_flag = Arc::clone(&count);
    let engine = hook_engine(|builder| {
        return builder.on_session_validated(move |_user| {
            count_flag.store(true, Ordering::SeqCst);
        });
    });

    let (_, session) = engine.login("alice", "pw").unwrap();
    engine.validate_session(session.id()).unwrap();

    assert!(count.load(Ordering::SeqCst));
    assert_eq!(
        engine.login("alice", "wrong").unwrap_err(),
        AuthError::InvalidCredentials
    );
}

#[test]
#[should_panic(expected = "boom")]
fn panicking_sign_in_hook_stops_the_program() {
    let engine = hook_engine(|builder| {
        return builder.on_sign_in(move |_user| {
            panic!("boom");
        });
    });

    engine
        .login("alice", "pw")
        .expect("unreachable: the hook panics first");
}
