//! End-to-end tests for the Dioxus runtime layer: provider restore, context
//! state transitions and route-guard behavior.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

mod common;

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;

use common::{IdentityHasher, TestUser};
use dioxus::prelude::{Callback, Element, Props, VNode, rsx};
use dioxus_auth::prelude::{
    AuthContext, AuthEngine, AuthEngineHandle, AuthProvider, AuthStatus, MemoryStore,
    MemoryTokenStorage, RedirectIfAuthed, RequireAuth, SessionId, TokenStorageHandle, use_auth,
};
use dioxus_core::VirtualDom;
use dioxus_history::{History, MemoryHistory};
use dioxus_router::{
    Routable,
    components::{HistoryProvider, Router},
};

thread_local! {
    static CONTEXT_SLOT: RefCell<Option<AuthContext<TestUser>>> = const { RefCell::new(None) };
}

thread_local! {
    static HISTORY_SLOT: RefCell<Option<Rc<MemoryHistory>>> = const { RefCell::new(None) };
}

thread_local! {
    static PROBE_MOUNTED: Cell<bool> = const { Cell::new(false) };
}

/// A user store seeded with one identity: `alice` / ``pw``.
type SeededStore = MemoryStore<TestUser>;

fn seeded_engine() -> Arc<AuthEngine<SeededStore, SeededStore>> {
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

/// Probes the provided auth context into [`CONTEXT_SLOT`] and records its
/// mount in [`PROBE_MOUNTED`].
#[derive(Clone, PartialEq, Props)]
struct ProbeProps {
    #[props(default)]
    marker: u8,
}

#[allow(non_snake_case)]
fn Probe(_: ProbeProps) -> Element {
    let auth = use_auth::<TestUser>();
    CONTEXT_SLOT.with(|slot| *slot.borrow_mut() = Some(auth));
    PROBE_MOUNTED.with(|flag| {
        flag.set(true);
    });
    return rsx! {
        "probe"
    };
}

/// Captures the provided auth context into [`CONTEXT_SLOT`] regardless of the
/// auth state, so tests can drive the context while the gated probe is absent.
#[derive(Clone, PartialEq, Props)]
struct ContextCaptureProps {
    #[props(default)]
    marker: u8,
}

#[allow(non_snake_case)]
fn ContextCapture(_: ContextCaptureProps) -> Element {
    let auth = use_auth::<TestUser>();
    CONTEXT_SLOT.with(|slot| *slot.borrow_mut() = Some(auth));
    return rsx! {
        "captured"
    };
}

/// The routes exercised by the guard tests.
#[derive(Clone, Routable, PartialEq)]
enum Route {
    #[route("/")]
    Home {},
    #[route("/login")]
    Login {},
}

#[derive(Clone, PartialEq, Props)]
struct HomeProps {
    #[props(default)]
    marker: u8,
}

#[allow(non_snake_case)]
fn Home(_: HomeProps) -> Element {
    return rsx! {
        RequireAuth::<TestUser> {
            redirect_to: "/login",
            Probe {}
        }
    };
}

#[derive(Clone, PartialEq, Props)]
struct LoginProps {
    #[props(default)]
    marker: u8,
}

#[allow(non_snake_case)]
fn Login(_: LoginProps) -> Element {
    return rsx! {
        RedirectIfAuthed::<TestUser> {
            redirect_to: "/",
            "login form"
        }
    };
}

/// Root for the state-only tests: provider plus a probe, no router.
#[derive(Clone)]
struct StateRootProps {
    engine: AuthEngineHandle<TestUser>,
    token_storage: TokenStorageHandle,
}

#[allow(non_snake_case)]
fn StateRoot(props: StateRootProps) -> Element {
    return rsx! {
        AuthProvider::<TestUser> {
            engine: props.engine,
            token_storage: props.token_storage,
            Probe {}
        }
    };
}

/// Root for the guard tests: history, router, then the provider so route
/// components can consume both contexts.
#[derive(Clone)]
struct RouterRootProps {
    history: Rc<dyn History>,
    engine: AuthEngineHandle<TestUser>,
    token_storage: TokenStorageHandle,
}

#[allow(non_snake_case)]
fn RouterRoot(props: RouterRootProps) -> Element {
    let history = props.history;
    let history_callback = Callback::new(move |()| {
        return history.clone();
    });
    return rsx! {
        HistoryProvider {
            history: history_callback,
            AuthProvider::<TestUser> {
                engine: props.engine,
                token_storage: props.token_storage,
                ContextCapture {},
                Router::<Route> {}
            }
        }
    };
}

/// Performs the initial rebuild, then runs render passes until the virtual DOM
/// settles (no more mutations).
fn mount(vdom: &mut VirtualDom) {
    vdom.rebuild_to_vec();
    pump(vdom);
}

/// Runs render passes until the virtual DOM settles (no more mutations).
fn pump(vdom: &mut VirtualDom) {
    for _ in 0..32 {
        if vdom.render_immediate_to_vec().edits.is_empty() {
            return;
        }
    }
}

/// Loads the auth context captured by the last [`Probe`] mount.
fn context() -> AuthContext<TestUser> {
    return CONTEXT_SLOT
        .with(|slot| {
            return slot.borrow().clone();
        })
        .expect("an AuthProvider must have mounted the probe");
}

fn state_dom(
    engine: Arc<AuthEngine<SeededStore, SeededStore>>,
    storage: TokenStorageHandle,
) -> VirtualDom {
    let handle = AuthEngineHandle::from(engine);
    let props = StateRootProps {
        engine: handle,
        token_storage: storage,
    };
    return VirtualDom::new_with_props(StateRoot, props);
}

fn router_dom(
    engine: Arc<AuthEngine<SeededStore, SeededStore>>,
    storage: TokenStorageHandle,
    initial_route: &'static str,
) -> VirtualDom {
    let history = Rc::new(MemoryHistory::with_initial_path(initial_route));
    HISTORY_SLOT.with(|slot| *slot.borrow_mut() = Some(history.clone()));
    let handle = AuthEngineHandle::from(engine);
    let props = RouterRootProps {
        history,
        engine: handle,
        token_storage: storage,
    };
    return VirtualDom::new_with_props(RouterRoot, props);
}

fn current_route() -> String {
    return HISTORY_SLOT.with(|slot| {
        return slot
            .borrow()
            .as_ref()
            .expect("a router test must register its history")
            .current_route();
    });
}

fn seed_valid_token(
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

#[test]
fn provider_restores_guest_from_empty_storage() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let mut vdom = state_dom(engine, storage);
    mount(&mut vdom);

    let auth = context();
    assert!(!auth.is_loading());
    assert!(!auth.is_authenticated());
    assert_eq!(auth.status(), AuthStatus::Guest);
    assert!(auth.user().is_none());
    assert!(auth.token().is_none());
    assert!(!auth.token_persisted());
}

#[test]
fn provider_restores_authenticated_user_from_stored_token() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let wire = seed_valid_token(&storage, &engine);
    let mut vdom = state_dom(engine, storage);
    mount(&mut vdom);

    let auth = context();
    assert!(!auth.is_loading());
    assert!(auth.is_authenticated());
    assert_eq!(
        auth.status(),
        AuthStatus::Authenticated(TestUser::new(1, "alice"))
    );
    assert_eq!(auth.user().expect("a restored user must be present").id, 1);
    assert_eq!(
        auth.token().as_ref().map(SessionId::as_str),
        Some(wire.as_str())
    );
    assert!(auth.token_persisted());
}

#[test]
fn login_roundtrip_persists_token_and_sets_status() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let mut vdom = state_dom(engine, storage.clone());
    mount(&mut vdom);
    let auth = context();

    let result = auth.login("alice", "pw");
    assert!(result.is_ok());
    mount(&mut vdom);

    assert_eq!(
        auth.status(),
        AuthStatus::Authenticated(TestUser::new(1, "alice"))
    );
    assert!(auth.token_persisted());
    let stored = storage.retrieve().expect("storage must be readable");
    assert_eq!(
        stored.as_deref(),
        Some(auth.token().expect("a token must be set").as_str())
    );
}

#[test]
fn login_rejects_wrong_password_and_leaves_guest_state() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let mut vdom = state_dom(engine, storage.clone());
    mount(&mut vdom);
    let auth = context();

    let result = auth.login("alice", "nope");
    assert!(result.is_err());
    mount(&mut vdom);

    assert_eq!(auth.status(), AuthStatus::Guest);
    assert!(!auth.token_persisted());
    assert!(
        storage
            .retrieve()
            .expect("storage must be readable")
            .is_none()
    );
}

#[test]
fn logout_clears_guest_and_revokes_the_session() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let mut vdom = state_dom(engine, storage.clone());
    mount(&mut vdom);
    let auth = context();
    assert!(auth.login("alice", "pw").is_ok());

    let result = auth.logout();
    assert!(result.is_ok());
    mount(&mut vdom);

    assert_eq!(auth.status(), AuthStatus::Guest);
    assert!(auth.token().is_none());
    assert!(!auth.token_persisted());
    assert!(
        storage
            .retrieve()
            .expect("storage must be readable")
            .is_none()
    );

    let validated = auth.validate();
    assert!(
        validated
            .expect("validation of a revoked session must not error")
            .is_none()
    );
}

#[test]
fn validate_reports_guest_when_the_token_is_revoked() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let wire = seed_valid_token(&storage, &engine);
    let mut vdom = state_dom(engine, storage);
    mount(&mut vdom);
    let auth = context();
    assert!(auth.is_authenticated());

    let revoked = auth.logout();
    assert!(revoked.is_ok());
    let _ = wire;

    let validated = auth.validate();
    assert!(validated.expect("validation must not error").is_none());
    assert_eq!(auth.status(), AuthStatus::Guest);
}

#[test]
fn restore_demotes_stale_tokens_to_guest_but_keeps_storage() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let stale = format!("ab{}", "c".repeat(62));
    storage
        .store(&stale)
        .expect("storing a stale token must succeed");
    let mut vdom = state_dom(engine, storage.clone());
    mount(&mut vdom);

    let auth = context();
    assert!(!auth.is_loading());
    assert_eq!(auth.status(), AuthStatus::Guest);
    let retained = storage.retrieve().expect("storage must be readable");
    assert_eq!(retained.as_deref(), Some(stale.as_str()));
}

#[test]
fn restore_demotes_malformed_tokens_to_guest() {
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    storage
        .store("not-a-wire-token")
        .expect("storing must succeed");
    let mut vdom = state_dom(engine, storage);
    mount(&mut vdom);

    let auth = context();
    assert!(!auth.is_loading());
    assert_eq!(auth.status(), AuthStatus::Guest);
}

#[test]
fn require_auth_redirects_guests_and_gates_the_subtree() {
    PROBE_MOUNTED.with(|flag| {
        flag.set(false);
    });
    let engine = seeded_engine();
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    let mut vdom = router_dom(engine, storage, "/");
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
    let _wire = seed_valid_token(&storage, &engine);
    let mut vdom = router_dom(engine, storage, "/login");
    mount(&mut vdom);

    assert_eq!(current_route(), "/");
    assert!(PROBE_MOUNTED.with(Cell::get));
    let auth = context();
    assert_eq!(
        auth.status(),
        AuthStatus::Authenticated(TestUser::new(1, "alice"))
    );
}
