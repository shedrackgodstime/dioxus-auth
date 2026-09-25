//! Minimal Dioxus client on `dioxus-auth`: signup, login form, guarded route.
//!
//! Zero traits: [`DefaultUser`] plus the built-in memory store. The whole
//! app is four components and a route table. Tests render it with
//! `dioxus-ssr` (no browser needed): guests see the login form, a seeded
//! session renders the dashboard.

use dioxus::prelude::*;
use dioxus_auth::{
    Auth, AuthProvider, DefaultStore, DefaultUser, DefaultUserInput, RedirectIfAuthed, RequireAuth,
    SessionState, use_auth, use_session,
};
use dioxus_router::{Routable, Router};

/// Routes for the quickstart app.
#[derive(Clone, Routable, PartialEq)]
pub enum Route {
    #[route("/")]
    Home {},
    #[route("/login")]
    Login {},
}

/// Application root: auth state above the router so guards can navigate.
///
/// Two contexts, two jobs: `AuthProvider` serves the reactive session state
/// (`use_auth`), while the bare `Auth` facade is provided alongside for
/// one-time verbs like signup that need store-specific input the erased
/// context cannot name.
#[component]
pub fn App(auth: Auth<DefaultStore>) -> Element {
    use_context_provider(|| auth.clone());
    rsx! {
        AuthProvider { auth: auth, Router::<Route> {} }
    }
}

/// Landing page: guests see the dashboard only through the guard.
#[component]
pub fn Home() -> Element {
    rsx! {
        RequireAuth::<DefaultUser> {
            redirect_to: "/login".to_string(),
            Dashboard {}
        }
    }
}

/// Login page: bounces signed-in visitors home.
#[component]
pub fn Login() -> Element {
    rsx! {
        RedirectIfAuthed::<DefaultUser> {
            redirect_to: "/".to_string(),
            LoginForm {}
        }
    }
}

/// Email plus password form. Reads nothing reactive itself; the auth handle
/// performs the login and the tree re-renders from the new state.
#[component]
pub fn LoginForm() -> Element {
    let auth = use_auth::<DefaultUser>();
    let mut email = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    rsx! {
        form {
            onsubmit: move |event| {
                event.prevent_default();
                let email = email.read().clone();
                let password = password.read().clone();
                match auth.login(&email, &password) {
                    Ok(()) => error.set(None),
                    Err(_) => error.set(Some(String::from("Email or password is incorrect."))),
                }
            },
            input {
                placeholder: "email",
                value: "{email}",
                oninput: move |event| email.set(event.value()),
            }
            input {
                placeholder: "password",
                r#type: "password",
                value: "{password}",
                oninput: move |event| password.set(event.value()),
            }
            button { r#type: "submit", "Sign in" }
            if error().is_some() {
                p { "Email or password is incorrect." }
            }
        }
    }
}

/// Name plus credentials form. Signup needs store-specific input, so this
/// form reads the provided facade directly instead of the erased context.
#[component]
pub fn SignupForm() -> Element {
    let auth = use_context::<Auth<DefaultStore>>();
    let mut name = use_signal(String::new);
    let mut email = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    rsx! {
        form {
            onsubmit: move |event| {
                event.prevent_default();
                let input = DefaultUserInput::new(name.read().clone());
                let email = email.read().clone();
                let password = password.read().clone();
                match auth.sign_up_email(&email, &password, input) {
                    Ok((_, _)) => error.set(None),
                    Err(_) => error.set(Some(String::from("Could not create the account."))),
                }
            },
            input {
                placeholder: "name",
                value: "{name}",
                oninput: move |event| name.set(event.value()),
            }
            input {
                placeholder: "email",
                value: "{email}",
                oninput: move |event| email.set(event.value()),
            }
            input {
                placeholder: "password",
                r#type: "password",
                value: "{password}",
                oninput: move |event| password.set(event.value()),
            }
            button { r#type: "submit", "Sign up" }
            if error().is_some() {
                p { "Could not create the account." }
            }
        }
    }
}

/// Signed-in landing: reactive read plus sign-out.
#[component]
pub fn Dashboard() -> Element {
    let auth = use_auth::<DefaultUser>();
    match use_session::<DefaultUser>() {
        SessionState::SignedIn(user) => rsx! {
            p { "Hello, {user.name}" }
            button {
                onclick: move |_| {
                    let _ = auth.logout();
                },
                "Sign out"
            }
        },
        SessionState::Guest => rsx! { LoginForm {} },
        SessionState::Pending => rsx! { "Loading..." },
        SessionState::Unavailable(_) => rsx! { "Retry" },
    }
}
