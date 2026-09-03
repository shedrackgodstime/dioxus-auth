use dioxus::prelude::*;
use dioxus_auth::{
    require_auth, use_auth, use_auth_restore, AuthProvider, AuthUser, RouteGate, ServerAuthContext,
    SignedIn, SignedOut,
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "server")]
use {
    dioxus::fullstack::FullstackContext,
    dioxus_auth::{Argon2Hasher, AuthEngine, CookieConfig, MemoryStore, PasswordHasher},
    std::sync::{Arc, LazyLock},
    std::time::Duration,
};

/// The shared application user model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppUser {
    pub id: u64,
    pub email: String,
    pub name: String,
}

impl AuthUser for AppUser {
    type Id = u64;

    fn id(&self) -> Self::Id {
        self.id
    }
}

// ---------------------------------------------------------------------------
// Server-Side Authentication Engine & Database
// ---------------------------------------------------------------------------

#[cfg(feature = "server")]
type DemoEngine = AuthEngine<MemoryStore<AppUser>, MemoryStore<AppUser>>;

#[cfg(feature = "server")]
static SERVER_STATE: LazyLock<(Arc<MemoryStore<AppUser>>, DemoEngine, CookieConfig)> =
    LazyLock::new(|| {
    let store = Arc::new(MemoryStore::<AppUser>::new());
    let hasher = Argon2Hasher::new();

    // Seed default demo user: admin@example.com / password123
    let hashed = hasher.hash_password("password123").unwrap();
    let demo_user = AppUser {
        id: 1,
        email: "admin@example.com".into(),
        name: "Admin User".into(),
    };
    store.insert_user_with_password(demo_user, "admin@example.com", hashed);

    let engine = AuthEngine::builder(store.clone(), store.clone())
        .session_ttl(Duration::from_secs(60 * 60 * 24 * 7)) // 7 days
        .build();

    let cookie_config = CookieConfig::default();

    (store, engine, cookie_config)
});

// ---------------------------------------------------------------------------
// Dioxus Server Functions (#[server])
// ---------------------------------------------------------------------------

/// Extract the raw `Cookie` header string from the current fullstack request, if any.
#[cfg(feature = "server")]
fn read_cookie_header() -> Option<String> {
    let ctx = FullstackContext::current()?;
    let parts = ctx.parts_mut();
    parts
        .headers
        .get(http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Server-side login: verifies credentials with Argon2id, mints a session,
/// and emits a `Set-Cookie` header for the client.
#[server]
pub async fn login_server(
    email: String,
    password: String,
) -> Result<AppUser, ServerFnError> {
    #[cfg(feature = "server")]
    {
        let (_, engine, cookie_config) = &*SERVER_STATE;
        let server_ctx = ServerAuthContext::new(engine, cookie_config);

        match server_ctx.login(&email, &password).await {
            Ok((user, set_cookie)) => {
                if let Some(ctx) = FullstackContext::current() {
                    let value = http::HeaderValue::from_str(&set_cookie)
                        .map_err(|e| ServerFnError::new(format!("cookie error: {e}")))?;
                    ctx.add_response_header(http::header::SET_COOKIE, value);
                }
                Ok(user)
            }
            Err(err) => Err(ServerFnError::new(format!("login failed: {err}"))),
        }
    }
    #[cfg(not(feature = "server"))]
    {
        let _ = (email, password);
        Err(ServerFnError::new("Server only"))
    }
}

/// Server-side logout: revokes the active session and emits a delete-cookie header.
#[server]
pub async fn logout_server() -> Result<(), ServerFnError> {
    #[cfg(feature = "server")]
    {
        let (_, engine, cookie_config) = &*SERVER_STATE;
        let server_ctx = ServerAuthContext::new(engine, cookie_config);

        let cookie_header = read_cookie_header();
        if let Some(session_id) = server_ctx.extract_session_id(cookie_header.as_deref()) {
            let delete_cookie = server_ctx
                .logout(&session_id)
                .await
                .map_err(|e| ServerFnError::new(format!("logout failed: {e}")))?;
            if let Some(ctx) = FullstackContext::current() {
                let value = http::HeaderValue::from_str(&delete_cookie)
                    .map_err(|e| ServerFnError::new(format!("cookie error: {e}")))?;
                ctx.add_response_header(http::header::SET_COOKIE, value);
            }
        }

        Ok(())
    }
    #[cfg(not(feature = "server"))]
    {
        Ok(())
    }
}

/// Server-side restore: reads the session cookie and returns the current user, if any.
#[server]
pub async fn get_current_user() -> Result<Option<AppUser>, ServerFnError> {
    #[cfg(feature = "server")]
    {
        let (_, engine, cookie_config) = &*SERVER_STATE;
        let server_ctx = ServerAuthContext::new(engine, cookie_config);

        let cookie_header = read_cookie_header();
        server_ctx
            .current_user(cookie_header.as_deref())
            .await
            .map_err(|e| ServerFnError::new(format!("restore failed: {e}")))
    }
    #[cfg(not(feature = "server"))]
    {
        Ok(None)
    }
}

/// Server-side protected data endpoint. Returns 401 (Unauthenticated) without a valid session.
#[server]
pub async fn get_secret_metrics() -> Result<Vec<String>, ServerFnError> {
    #[cfg(feature = "server")]
    {
        let (_, engine, cookie_config) = &*SERVER_STATE;
        let server_ctx = ServerAuthContext::new(engine, cookie_config);

        let cookie_header = read_cookie_header();
        let _user = server_ctx
            .require_user(cookie_header.as_deref())
            .await
            .map_err(|e| ServerFnError::new(format!("unauthorized: {e}")))?;

        Ok(vec![
            "Active Subscribers: 1,420".into(),
            "Monthly Recurring Revenue: $18,500".into(),
            "API Success Rate: 99.98%".into(),
        ])
    }
    #[cfg(not(feature = "server"))]
    {
        Ok(vec![])
    }
}

// ---------------------------------------------------------------------------
// Frontend Router & Pages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[layout(Navbar)]
    #[route("/")]
    Home {},
    #[route("/login")]
    Login {},
    #[layout(ProtectedLayout)]
    #[route("/dashboard")]
    Dashboard {},
}

const FAVICON: Asset = asset!("/assets/favicon.ico");
const MAIN_CSS: Asset = asset!("/assets/main.css");

fn main() {
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    rsx! {
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: MAIN_CSS }
        AuthProvider::<AppUser> {
            AuthRestore {}
            Router::<Route> {}
        }
    }
}

/// Child of `AuthProvider` that drives the 3-state from a `get_current_user` resource.
///
/// Starts in `Loading` (the `AuthProvider` default). Once the resource resolves:
/// - `Some(Ok(Some(user)))` → `Authenticated(user)`
/// - `Some(Ok(None))` or `Some(Err(_))` → `Unauthenticated`
///
/// Only mutates while still `Loading`, so a manual login elsewhere is never overwritten.
#[component]
fn AuthRestore() -> Element {
    let whoami = use_resource(get_current_user);
    use_auth_restore(whoami.read().clone());
    rsx! {}
}

/// Navigation Bar with SignedIn / SignedOut conditional rendering.
#[component]
fn Navbar() -> Element {
    let auth = use_auth::<AppUser>();
    let nav = use_navigator();

    rsx! {
        header {
            style: "display: flex; justify-content: space-between; align-items: center; padding: 1rem 2rem; background: #1a1a24; color: #fff; border-bottom: 1px solid #333;",
            div {
                style: "font-weight: bold; font-size: 1.25rem;",
                Link { to: Route::Home {}, "⚡ Dioxus Auth Demo" }
            }
            nav {
                style: "display: flex; gap: 1.5rem; align-items: center;",
                Link { to: Route::Home {}, "Home" }
                Link { to: Route::Dashboard {}, "Dashboard (Protected)" }

                SignedIn::<AppUser> {
                    span {
                        style: "color: #4ade80;",
                        "👤 {auth.user().map(|u| u.name).unwrap_or_default()}"
                    }
                    button {
                        style: "background: #ef4444; color: white; border: none; padding: 0.4rem 0.8rem; border-radius: 4px; cursor: pointer;",
                        onclick: move |_| {
                            let mut auth = auth;
                            let nav = nav;
                            spawn(async move {
                                logout_server().await.ok();
                                auth.logout();
                                nav.push(Route::Home {});
                            });
                        },
                        "Log Out"
                    }
                }

                SignedOut::<AppUser> {
                    Link {
                        to: Route::Login {},
                        style: "background: #3b82f6; color: white; padding: 0.4rem 0.8rem; border-radius: 4px; text-decoration: none;",
                        "Sign In"
                    }
                }
            }
        }

        main {
            style: "max-width: 900px; margin: 2rem auto; padding: 0 1rem; font-family: system-ui, -apple-system, sans-serif;",
            Outlet::<Route> {}
        }
    }
}

/// Public Home Page.
#[component]
fn Home() -> Element {
    rsx! {
        div {
            style: "text-align: center; padding: 3rem 0;",
            h1 { "Production-Ready Dioxus Authentication" }
            p {
                style: "font-size: 1.2rem; color: #666; max-width: 600px; margin: 1rem auto;",
                "Self-hosted, storage-agnostic session authentication built natively for fullstack Dioxus applications."
            }

            div {
                style: "margin-top: 2rem; padding: 1.5rem; background: #f4f4f8; border-radius: 8px; display: inline-block; text-align: left;",
                h3 { "Demo Credentials" }
                p { "Email: ", strong { "admin@example.com" } }
                p { "Password: ", strong { "password123" } }
            }
        }
    }
}

/// Interactive Login Form.
#[component]
fn Login() -> Element {
    let auth = use_auth::<AppUser>();
    let nav = use_navigator();

    let mut email = use_signal(|| "admin@example.com".to_string());
    let mut password = use_signal(|| "password123".to_string());
    let mut error_msg = use_signal(|| Option::<String>::None);
    let mut is_submitting = use_signal(|| false);

    let execute_login = move || {
        let mut auth = auth;
        let nav = nav;
        let em = email();
        let pw = password();

        spawn(async move {
            is_submitting.set(true);
            error_msg.set(None);

            match login_server(em, pw).await {
                Ok(user) => {
                    auth.set_user(user);
                    nav.push(Route::Dashboard {});
                }
                Err(err) => {
                    error_msg.set(Some(format!("{err}")));
                }
            }
            is_submitting.set(false);
        });
    };

    rsx! {
        div {
            style: "max-width: 420px; margin: 3rem auto; padding: 2rem; border: 1px solid #e2e8f0; border-radius: 10px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);",
            h2 { style: "text-align: center; margin-bottom: 1.5rem;", "Sign In to Your Account" }

            if let Some(err) = error_msg() {
                div {
                    style: "background: #fee2e2; color: #991b1b; padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem;",
                    "⚠️ {err}"
                }
            }

            form {
                onsubmit: move |evt: FormEvent| {
                    evt.prevent_default();
                    execute_login();
                },
                div {
                    style: "margin-bottom: 1rem;",
                    label { style: "display: block; font-weight: 500; margin-bottom: 0.3rem;", "Email Address" }
                    input {
                        r#type: "email",
                        style: "width: 100%; padding: 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px;",
                        value: "{email}",
                        oninput: move |e| email.set(e.value())
                    }
                }
                div {
                    style: "margin-bottom: 1.5rem;",
                    label { style: "display: block; font-weight: 500; margin-bottom: 0.3rem;", "Password" }
                    input {
                        r#type: "password",
                        style: "width: 100%; padding: 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px;",
                        value: "{password}",
                        oninput: move |e| password.set(e.value())
                    }
                }
                button {
                    r#type: "submit",
                    disabled: is_submitting(),
                    style: "width: 100%; background: #2563eb; color: white; padding: 0.75rem; border: none; border-radius: 6px; font-weight: bold; cursor: pointer;",
                    if is_submitting() { "Signing in..." } else { "Sign In" }
                }
            }
        }
    }
}

/// Protected Route Gate Layout: enforces authentication before rendering dashboard.
#[component]
fn ProtectedLayout() -> Element {
    let auth = use_auth::<AppUser>();
    let outcome = require_auth(&auth.status(), Route::Login {});

    rsx! {
        RouteGate {
            outcome: outcome,
            fallback: rsx! {
                div {
                    style: "text-align: center; padding: 4rem;",
                    h3 { "Checking Authentication..." }
                    p { "Please wait while your session is verified." }
                }
            }
        }
    }
}

/// Protected Member Dashboard.
#[component]
fn Dashboard() -> Element {
    let auth = use_auth::<AppUser>();
    let user = auth.user().unwrap();
    let metrics = use_resource(get_secret_metrics);

    rsx! {
        div {
            h1 { "Protected Executive Dashboard" }
            p { "Authenticated as: ", strong { "{user.name} ({user.email})" } }

            div {
                style: "margin-top: 2rem;",
                h3 { "Confidential Server Metrics" }
                match &*metrics.read() {
                    Some(Ok(data)) => rsx! {
                        ul {
                            for item in data {
                                li { style: "padding: 0.5rem 0; font-size: 1.1rem;", "{item}" }
                            }
                        }
                    },
                    Some(Err(err)) => rsx! {
                        p { style: "color: red;", "Failed to load metrics: {err}" }
                    },
                    None => rsx! {
                        p { "Loading live metrics from server function..." }
                    }
                }
            }
        }
    }
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_login_server_credentials() {
        let res = login_server("admin@example.com".into(), "password123".into()).await;
        assert!(res.is_ok(), "login_server failed: {:?}", res.err());
        let user = res.unwrap();
        assert_eq!(user.email, "admin@example.com");
    }
}
