//! Route-guard tests: redirects and subtree gating.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::cell::Cell;
use std::sync::Arc;

use dioxus_auth::{AuthEngineHandle, AuthStatus, MemoryTokenStorage, TokenStorageHandle};

use super::common::TestUser;
use super::harness::{
    PROBE_MOUNTED, UnknownEngine, context, current_route, erased_router_dom, mount, pump,
    router_dom, seed_valid_token, seeded_engine,
};

#[test]
fn require_auth_redirects_guests_and_gates_the_subtree() {
    PROBE_MOUNTED.with(|flag| {
        flag.set(false);
    });
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let mut vdom = router_dom(&engine, storage, "/");
    mount(&mut vdom);

    assert_eq!(current_route(), "/login");
    assert!(!PROBE_MOUNTED.with(Cell::get));
    let auth = context();
    assert_eq!(auth.status(), AuthStatus::Guest);

    let login = auth.login("alice", "pw");
    assert!(login.is_ok());
    pump(&mut vdom);

    assert_eq!(
        auth.status(),
        AuthStatus::Authenticated(TestUser::new(1, "alice"))
    );
    assert!(PROBE_MOUNTED.with(Cell::get));
    assert_eq!(current_route(), "/");
}

#[test]
fn redirect_if_authed_bounces_authenticated_users_off_login() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let _ = seed_valid_token(&storage, &engine);
    let mut vdom = router_dom(&engine, storage, "/login");
    mount(&mut vdom);

    assert_eq!(current_route(), "/");
    assert!(PROBE_MOUNTED.with(Cell::get));
    let auth = context();
    assert_eq!(
        auth.status(),
        AuthStatus::Authenticated(TestUser::new(1, "alice"))
    );
}

#[test]
fn redirect_if_authed_renders_nothing_and_skips_navigation_while_loading() {
    let engine = AuthEngineHandle::from_erased(Arc::new(UnknownEngine));
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    storage
        .store(&"a".repeat(64))
        .expect("storing a well-formed token must succeed");
    let mut vdom = erased_router_dom(engine, storage, "/login");
    mount(&mut vdom);

    // The restore question is still open: no redirect may fire and the guest
    // subtree must not flash before the first settle.
    let auth = context();
    assert!(auth.is_loading());
    assert_eq!(current_route(), "/login");
    assert!(!PROBE_MOUNTED.with(Cell::get));
}
