use dioxus::prelude::*;
use dioxus_auth::{
    AuthProvider, AuthStatus, AuthUser, MemoryStore, RouteGate, redirect_if_authed, require_auth,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct AppUser {
    id: u64,
    username: String,
}

impl AuthUser for AppUser {
    type Id = u64;

    fn id(&self) -> Self::Id {
        self.id
    }
}

#[derive(Routable, Clone, PartialEq, Debug)]
enum Route {
    #[route("/")]
    Home {},
    #[route("/login")]
    Login {},
    #[layout(ProtectedLayout)]
    #[route("/dashboard")]
    Dashboard {},
}

fn main() {
    let mut vdom = VirtualDom::new(App);
    vdom.rebuild_in_place();
    println!("Dioxus Auth application VirtualDom initialized successfully!");
}

#[component]
fn App() -> Element {
    let store = MemoryStore::<AppUser>::new();
    store.insert_user(AppUser {
        id: 1,
        username: "admin".into(),
    });

    rsx! {
        AuthProvider::<AppUser> {
            initial_status: AuthStatus::Unauthenticated,
            Router::<Route> {}
        }
    }
}

#[component]
fn Home() -> Element {
    let auth = dioxus_auth::use_auth::<AppUser>();

    rsx! {
        div {
            h1 { "Home Page" }
            if auth.is_authenticated() {
                p { "Logged in as: {auth.user().unwrap().username}" }
                Link { to: Route::Dashboard {}, "Go to Dashboard" }
            } else {
                Link { to: Route::Login {}, "Login" }
            }
        }
    }
}

#[component]
fn Login() -> Element {
    let mut auth = dioxus_auth::use_auth::<AppUser>();
    let outcome = redirect_if_authed(&auth.status(), Route::Dashboard {});

    if outcome.is_redirect() {
        return rsx! {
            RouteGate { outcome: outcome }
        };
    }

    rsx! {
        div {
            h1 { "Login Page" }
            button {
                onclick: move |_| {
                    auth.set_user(AppUser {
                        id: 1,
                        username: "admin".into(),
                    });
                },
                "Log In as Admin"
            }
        }
    }
}

#[component]
fn ProtectedLayout() -> Element {
    let auth = dioxus_auth::use_auth::<AppUser>();
    let outcome = require_auth(&auth.status(), Route::Login {});

    rsx! {
        RouteGate {
            outcome: outcome,
            fallback: rsx! { div { "Verifying session..." } },
        }
    }
}

#[component]
fn Dashboard() -> Element {
    let mut auth = dioxus_auth::use_auth::<AppUser>();
    let user = auth.user().unwrap();

    rsx! {
        div {
            h1 { "Secret Dashboard" }
            p { "Welcome to the protected area, {user.username}!" }
            button {
                onclick: move |_| {
                    auth.logout();
                },
                "Log Out"
            }
        }
    }
}
