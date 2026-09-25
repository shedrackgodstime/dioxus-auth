//! Tests for `on_auth_state_change`: transitions carry the previous and
//! current session states across real context mutations, and stable state
//! fires nothing.

// reason: project style requires explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::cell::RefCell;
use std::sync::Arc;

use dioxus::prelude::{Element, Props, rsx};
use dioxus_auth::{
    Auth, AuthContext, AuthEngine, MemoryTokenStorage, SessionState, TokenStorageHandle,
    on_auth_state_change, use_auth,
};
use dioxus_core::VirtualDom;

use super::common::TestUser;
use super::harness::{CONTEXT_SLOT, SeededStore, mount, pump, seed_valid_token, seeded_engine};

thread_local! {
    static EVENTS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn record(event: &str) {
    EVENTS.with(|slot| {
        slot.borrow_mut().push(String::from(event));
    });
}

fn recorded() -> Vec<String> {
    return EVENTS.with(|slot| {
        return slot.borrow().clone();
    });
}

fn clear() {
    EVENTS.with(|slot| slot.borrow_mut().clear());
}

fn label(state: &SessionState<TestUser>) -> String {
    return match state {
        SessionState::SignedIn(_) => String::from("signed-in"),
        SessionState::Guest => String::from("guest"),
        SessionState::Pending => String::from("pending"),
        SessionState::Unavailable(_) => String::from("unavailable"),
    };
}

/// Root: the provider with the observing child below it.
#[derive(Clone, PartialEq, Props)]
pub struct ObserverRootProps {
    pub auth: Auth<SeededStore>,
}

// reason: Dioxus components are PascalCase fns by framework convention.
#[expect(non_snake_case)]
pub fn ObserverRoot(props: ObserverRootProps) -> Element {
    return rsx! {
        dioxus_auth::AuthProvider {
            auth: props.auth,
            ObserverChild {}
        }
    };
}

#[derive(Clone, PartialEq, Eq, Props)]
struct ChildProps {
    #[props(default)]
    marker: u8,
}

// reason: Dioxus components are PascalCase fns by framework convention.
#[expect(non_snake_case)]
fn ObserverChild(_: ChildProps) -> Element {
    let auth = use_auth::<TestUser>();
    CONTEXT_SLOT.with(|slot| *slot.borrow_mut() = Some(auth.clone()));
    on_auth_state_change::<TestUser, _>(|event| {
        record(&format!(
            "{} -> {}",
            label(&event.previous),
            label(&event.current)
        ));
    });
    return rsx! {
        "observer"
    };
}

fn events_dom(
    engine: &Arc<AuthEngine<SeededStore, SeededStore>>,
    storage: TokenStorageHandle,
) -> VirtualDom {
    let auth = Auth::from_engine((**engine).clone()).with_token_storage(storage);
    return VirtualDom::new_with_props(ObserverRoot, ObserverRootProps { auth });
}

fn context() -> AuthContext<TestUser> {
    return CONTEXT_SLOT
        .with(|slot| {
            return slot.borrow().clone();
        })
        .expect("an AuthProvider must have mounted the observer");
}

#[test]
fn login_and_logout_fire_transitions() {
    clear();
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let mut vdom: VirtualDom = events_dom(&engine, storage);
    mount(&mut vdom);
    let auth = context();

    // The initial settle is recorded without firing: nothing transitioned
    // between two observed states yet.
    assert!(
        recorded().is_empty(),
        "the initial settle must not fire, got: {:?}",
        recorded()
    );

    let _ = auth.login("alice", "pw");
    pump(&mut vdom);

    let events = recorded();
    assert_eq!(events, vec![String::from("guest -> signed-in")]);

    let _ = auth.logout();
    pump(&mut vdom);

    let events = recorded();
    assert_eq!(
        events,
        vec![
            String::from("guest -> signed-in"),
            String::from("signed-in -> guest")
        ]
    );
}

#[test]
fn stable_states_fire_nothing_but_logout_fires_once() {
    clear();
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let _wire = seed_valid_token(&storage, &engine);
    let mut vdom: VirtualDom = events_dom(&engine, storage);
    mount(&mut vdom);
    let auth = context();

    // A stable authenticated identity across extra render passes and a
    // re-login of the same identity must not fire: no state changed.
    pump(&mut vdom);
    let _ = auth.login("alice", "pw");
    pump(&mut vdom);
    assert!(
        recorded().is_empty(),
        "stable state must not fire, got: {:?}",
        recorded()
    );

    let _ = auth.logout();
    pump(&mut vdom);
    assert_eq!(recorded(), vec![String::from("signed-in -> guest")]);
}
