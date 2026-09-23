//! Virtual-DOM harness shared by the runtime suites.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;

use dioxus_auth::prelude::{
    Auth, AuthContext, AuthEngine, AuthEngineHandle, AuthError, AuthOperations, MemoryStore,
    SessionId, TokenStorageHandle,
};
use dioxus_core::VirtualDom;
use dioxus_history::{History, MemoryHistory};

use super::common::TestUser;
use super::components::{RouterRoot, RouterRootProps, StateRoot, StateRootProps};
use super::identity_hasher::IdentityHasher;

thread_local! {
    pub static CONTEXT_SLOT: RefCell<Option<AuthContext<TestUser>>> =
        const { RefCell::new(None) };
}

thread_local! {
    static HISTORY_SLOT: RefCell<Option<Rc<MemoryHistory>>> = const { RefCell::new(None) };
}

thread_local! {
    pub static PROBE_MOUNTED: Cell<bool> = const { Cell::new(false) };
}

/// A user store seeded with one identity: `alice` / ``pw``.
pub type SeededStore = MemoryStore<TestUser>;

pub fn seeded_engine() -> Arc<AuthEngine<SeededStore, SeededStore>> {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(1, "alice"), "alice", "pw");
    let store = Arc::new(store);
    return Arc::new(
        AuthEngine::builder(Arc::clone(&store), store)
            .hasher(IdentityHasher)
            .build()
            .expect("engine construction must succeed"),
    );
}

/// Performs the initial rebuild, then runs render passes until the virtual DOM
/// settles (no more mutations).
pub fn mount(vdom: &mut VirtualDom) {
    vdom.rebuild_to_vec();
    pump(vdom);
}

/// Runs render passes until the virtual DOM settles.
///
/// Effects are the scheduler's lowest-priority work: `render_immediate`
/// skips task polling whenever dirty scopes exist at entry, and a rerun can
/// produce zero edits while effects are still pending. The pump therefore
/// runs a fixed number of passes instead of breaking on the first
/// edit-free pass, so queued effects always drain.
pub fn pump(vdom: &mut VirtualDom) {
    for _ in 0..8 {
        let _ = vdom.render_immediate_to_vec();
    }
}

/// Loads the auth context captured by the last [`Probe`](super::components::Probe) mount.
pub fn context() -> AuthContext<TestUser> {
    return CONTEXT_SLOT
        .with(|slot| {
            return slot.borrow().clone();
        })
        .expect("an AuthProvider must have mounted the probe");
}

pub fn state_dom(
    engine: &Arc<AuthEngine<SeededStore, SeededStore>>,
    storage: TokenStorageHandle,
) -> VirtualDom {
    let auth = Auth::from_engine((**engine).clone()).with_token_storage(storage);
    let props = StateRootProps { auth };
    return VirtualDom::new_with_props(StateRoot, props);
}

/// Builds the state tree over a type-erased engine, for tests that substitute
/// their own `AuthOperations` implementation (failure injection, fakes).
pub fn erased_state_dom(
    engine: AuthEngineHandle<TestUser>,
    storage: TokenStorageHandle,
) -> VirtualDom {
    let auth = Auth::from_erased(engine)
        .expect("erased facade constructs")
        .with_token_storage(storage);
    let props = StateRootProps { auth };
    return VirtualDom::new_with_props(StateRoot, props);
}

/// Builds the guard tree over a type-erased engine, for tests that need a
/// router above a failure-injecting engine.
pub fn erased_router_dom(
    engine: AuthEngineHandle<TestUser>,
    storage: TokenStorageHandle,
    initial_route: &'static str,
) -> VirtualDom {
    let history = Rc::new(MemoryHistory::with_initial_path(initial_route));
    HISTORY_SLOT.with(|slot| *slot.borrow_mut() = Some(history.clone()));
    let auth = Auth::from_erased(engine)
        .expect("erased facade constructs")
        .with_token_storage(storage);
    let props = RouterRootProps { history, auth };
    return VirtualDom::new_with_props(RouterRoot, props);
}

/// An erased engine whose validation never produces an answer, simulating a
/// transport failure between the client runtime and a remote engine.
#[derive(Debug)]
pub struct UnknownEngine;

impl AuthOperations<TestUser> for UnknownEngine {
    fn login(
        &self,
        _identifier: &str,
        _password: &str,
    ) -> Result<(TestUser, SessionId), AuthError> {
        return Err(AuthError::Internal(String::from("transport down")));
    }

    fn logout(&self, _session_id: &SessionId) -> Result<(), AuthError> {
        return Err(AuthError::Internal(String::from("transport down")));
    }

    fn validate(&self, _session_id: &SessionId) -> Result<Option<TestUser>, AuthError> {
        return Err(AuthError::Internal(String::from("transport down")));
    }
}

/// An erased engine that definitively rejects every token it is asked about.
#[derive(Debug)]
pub struct RejectedEngine;

impl AuthOperations<TestUser> for RejectedEngine {
    fn login(
        &self,
        _identifier: &str,
        _password: &str,
    ) -> Result<(TestUser, SessionId), AuthError> {
        return Err(AuthError::InvalidCredentials);
    }

    fn logout(&self, _session_id: &SessionId) -> Result<(), AuthError> {
        return Err(AuthError::InvalidCredentials);
    }

    fn validate(&self, _session_id: &SessionId) -> Result<Option<TestUser>, AuthError> {
        return Err(AuthError::InvalidCredentials);
    }
}

pub fn router_dom(
    engine: &Arc<AuthEngine<SeededStore, SeededStore>>,
    storage: TokenStorageHandle,
    initial_route: &'static str,
) -> VirtualDom {
    let history = Rc::new(MemoryHistory::with_initial_path(initial_route));
    HISTORY_SLOT.with(|slot| *slot.borrow_mut() = Some(history.clone()));
    let auth = Auth::from_engine((**engine).clone()).with_token_storage(storage);
    let props = RouterRootProps { history, auth };
    return VirtualDom::new_with_props(RouterRoot, props);
}

pub fn current_route() -> String {
    return HISTORY_SLOT.with(|slot| {
        return slot
            .borrow()
            .as_ref()
            .expect("a router test must register its history")
            .current_route();
    });
}

pub fn seed_valid_token(
    storage: &TokenStorageHandle,
    engine: &AuthEngine<SeededStore, SeededStore>,
) -> SessionId {
    let (_user, session) = engine
        .login("alice", "pw")
        .expect("seed login must succeed");
    storage
        .store(session.id().as_str())
        .expect("seed token storage must succeed");
    return session.id().clone();
}
