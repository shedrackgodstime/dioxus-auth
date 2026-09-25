//! Render tests for the quickstart tree: guest sees the login form, a seeded
//! session renders the dashboard, guards redirect exactly once per period.
//! Rendered with `dioxus-ssr`, so no browser or display server is needed.

use std::rc::Rc;

use dioxus::prelude::*;
use dioxus_auth::{Auth, DefaultUserInput, MemoryTokenStorage, TokenStorageHandle};
use dioxus_history::{History, MemoryHistory};
use dioxus_router::components::HistoryProvider;
use quickstart::App;

/// Test root: memory history above the app so guards can navigate.
#[derive(Clone)]
struct TestRootProps {
    history: Rc<dyn History>,
    auth: Auth<dioxus_auth::DefaultStore>,
}

// reason: test components are PascalCase fns by Dioxus convention.
#[expect(non_snake_case)]
fn TestRoot(props: TestRootProps) -> Element {
    let callback = Callback::new(move |()| props.history.clone());
    rsx! {
        HistoryProvider { history: callback, App { auth: props.auth } }
    }
}

fn render(
    history: Rc<MemoryHistory>,
    auth: Auth<dioxus_auth::DefaultStore>,
) -> (String, Rc<MemoryHistory>) {
    let props = TestRootProps {
        history: history.clone() as Rc<dyn History>,
        auth,
    };
    let mut vdom = VirtualDom::new_with_props(TestRoot, props);
    vdom.rebuild_in_place();
    (dioxus_ssr::render(&vdom), history)
}

fn seeded_auth() -> (Auth<dioxus_auth::DefaultStore>, TokenStorageHandle) {
    let auth = Auth::memory().expect("quickstart must construct");
    let (_, session) = auth
        .sign_up_email(
            "alice@example.com",
            "password",
            DefaultUserInput::new("alice"),
        )
        .expect("seed signup must succeed");
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    storage
        .store(session.as_str())
        .expect("seed token must store");
    (auth, storage)
}

#[test]
fn guest_at_login_sees_the_form_and_stays() {
    let history = Rc::new(MemoryHistory::with_initial_path("/login"));
    let auth = Auth::memory().expect("quickstart must construct");
    let (html, history) = render(history, auth);
    assert!(html.contains("email"), "guest must see the login form");
    assert!(html.contains("Sign in"), "guest must see the submit");
    assert_eq!(history.current_route(), "/login");
}

#[test]
fn seeded_session_renders_the_dashboard_at_home() {
    let history = Rc::new(MemoryHistory::with_initial_path("/"));
    let (auth, storage) = seeded_auth();
    let auth = auth.with_token_storage(storage);
    let (html, history) = render(history, auth);
    assert!(
        html.contains("Hello, alice"),
        "restored session must render"
    );
    assert!(html.contains("Sign out"), "dashboard must offer sign-out");
    assert_eq!(history.current_route(), "/");
}

#[test]
fn guest_at_home_redirects_to_login() {
    let history = Rc::new(MemoryHistory::with_initial_path("/"));
    let auth = Auth::memory().expect("quickstart must construct");
    let (_, history) = render(history, auth);
    assert_eq!(history.current_route(), "/login");
}

#[test]
fn signed_in_visitor_bounces_off_the_login_page() {
    let history = Rc::new(MemoryHistory::with_initial_path("/login"));
    let (auth, storage) = seeded_auth();
    let auth = auth.with_token_storage(storage);
    let (_, history) = render(history, auth);
    assert_eq!(history.current_route(), "/");
}
