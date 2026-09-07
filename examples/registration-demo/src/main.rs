use std::sync::Arc;
use std::time::Duration;

use dioxus::prelude::*;
use dioxus_auth::{
    AuthEngine, AuthProvider, AuthUser, CookieConfig, MemoryStore, PasswordHasher,
    PasswordUserStore, ServerAuthContext, UserStore,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const EMAIL_VERIFY_TTL_SECS: u64 = 60 * 60; // 1 hour
const PASSWORD_RESET_TTL_SECS: u64 = 60 * 60; // 1 hour

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppUser {
    pub id: u64,
    pub email: String,
    pub name: String,
    pub password_hash: String,
    pub email_verified: bool,
}

impl AuthUser for AppUser {
    type Id = u64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> Option<&str> {
        Some(&self.password_hash)
    }
}

#[derive(Clone)]
struct VerificationStore {
    email_tokens: Arc<tokio::sync::RwLock<Vec<(String, u64, u64, bool)>>>,
    reset_tokens: Arc<tokio::sync::RwLock<Vec<(String, u64, u64, String)>>>,
}

impl VerificationStore {
    fn new() -> Self {
        Self {
            email_tokens: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            reset_tokens: Arc::new(tokio::sync::RwLock::new(Vec::new())),
        }
    }

    async fn insert_email_token(&self, token: String, user_id: u64, expires_at_unix: u64) {
        self.email_tokens
            .write()
            .await
            .push((token, user_id, expires_at_unix, false));
    }

    async fn verify_email_token(&self, token: &str) -> Option<u64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut tokens = self.email_tokens.write().await;
        if let Some(pos) = tokens.iter().position(|(t, _, exp, _)| t == token && *exp > now) {
            let (_, user_id, _, _) = tokens.remove(pos);
            return Some(user_id);
        }
        None
    }

    async fn insert_reset_token(&self, token: String, user_id: u64, expires_at_unix: u64) {
        self.reset_tokens
            .write()
            .await
            .push((token, user_id, expires_at_unix, String::new()));
    }

    async fn consume_reset_token(&self, token: &str) -> Option<(u64, String)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut tokens = self.reset_tokens.write().await;
        if let Some(pos) = tokens.iter().position(|(t, _, exp, _)| t == token && *exp > now) {
            let (_, user_id, _, new_hash) = tokens.remove(pos);
            return Some((user_id, new_hash));
        }
        None
    }
}

#[cfg(feature = "server")]
type DemoEngine = AuthEngine<MemoryStore<AppUser>, MemoryStore<AppUser>>;

#[cfg(feature = "server")]
static SERVER_STATE: tokio::sync::OnceCell<(
    Arc<MemoryStore<AppUser>>,
    DemoEngine,
    CookieConfig,
    Arc<VerificationStore>,
)> = tokio::sync::OnceCell::const_new();

    #[cfg(feature = "server")]
    async fn init_server_state() -> &'static (
        Arc<MemoryStore<AppUser>>,
        DemoEngine,
        CookieConfig,
        Arc<VerificationStore>,
    ) {
        SERVER_STATE
            .get_or_init(|| async {
                let users = Arc::new(MemoryStore::<AppUser>::new());
                let hasher = dioxus_auth::Argon2Hasher::new();
                let password = hasher.hash_password("password123").expect("hash");

                users.insert_user(AppUser {
                    id: 1,
                    email: "admin@example.com".into(),
                    name: "Admin".into(),
                    password_hash: password.clone(),
                    email_verified: true,
                });

                let engine = AuthEngine::builder(users.clone(), users.clone())
                    .session_ttl(Duration::from_secs(60 * 60 * 24 * 7))
                    .build();

                let cookie_config = CookieConfig::default();
                let verification = Arc::new(VerificationStore::new());
                (users, engine, cookie_config, verification)
            })
            .await
    }

#[server]
async fn register_server(
    email: String,
    name: String,
    password: String,
) -> Result<String, ServerFnError> {
    #[cfg(feature = "server")]
    {
        let (users, _engine, _cookie_config, verification) = init_server_state().await;

        if users
            .find_by_identifier(&email)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?
            .is_some()
        {
            return Err(ServerFnError::new("email already registered"));
        }

        let hasher = dioxus_auth::Argon2Hasher::new();
        let password_hash = hasher.hash_password(&password).map_err(|e| ServerFnError::new(e.to_string()))?;

        let user = AppUser {
            id: rand::random(),
            email: email.clone(),
            name,
            password_hash,
            email_verified: false,
        };

        users.insert_user(user.clone());

        let token = Uuid::new_v4().to_string();
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + EMAIL_VERIFY_TTL_SECS;

        verification.insert_email_token(token.clone(), user.id, expires_at).await;

        Ok(format!("Verification email sent to {email}. Token: {token}"))
    }
    #[cfg(not(feature = "server"))]
    {
        let _ = (email, name, password);
        Err(ServerFnError::new("Server only"))
    }
}

#[server]
async fn verify_email_server(token: String) -> Result<String, ServerFnError> {
    #[cfg(feature = "server")]
    {
        let (users, _engine, _cookie_config, verification) = init_server_state().await;

        let user_id = verification
            .verify_email_token(&token)
            .await
            .ok_or_else(|| ServerFnError::new("invalid or expired token"))?;

        let mut user = users
            .find_by_id(&user_id)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?
            .ok_or_else(|| ServerFnError::new("user not found"))?;

        user.email_verified = true;
        users.insert_user(user);

        Ok("Email verified successfully".into())
    }
    #[cfg(not(feature = "server"))]
    {
        let _ = token;
        Err(ServerFnError::new("Server only"))
    }
}

#[server]
async fn request_password_reset_server(email: String) -> Result<String, ServerFnError> {
    #[cfg(feature = "server")]
    {
        let (users, _engine, _cookie_config, verification) = init_server_state().await;

        let user = users
            .find_by_identifier(&email)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?
            .map(|(u, _)| u);

        if user.is_none() {
            return Ok("If that email exists, a reset link was sent".into());
        }

        let user = user.unwrap();
        let token = Uuid::new_v4().to_string();
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + PASSWORD_RESET_TTL_SECS;

        verification
            .insert_reset_token(token.clone(), user.id, expires_at)
            .await;

        Ok(format!("Reset link sent to {email}. Token: {token}"))
    }
    #[cfg(not(feature = "server"))]
    {
        let _ = email;
        Err(ServerFnError::new("Server only"))
    }
}

#[server]
async fn reset_password_server(
    token: String,
    new_password: String,
) -> Result<String, ServerFnError> {
    #[cfg(feature = "server")]
    {
        let (users, _engine, _cookie_config, verification) = init_server_state().await;

        let (user_id, _) = verification
            .consume_reset_token(&token)
            .await
            .ok_or_else(|| ServerFnError::new("invalid or expired token"))?;

        let hasher = dioxus_auth::Argon2Hasher::new();
        let new_hash = hasher.hash_password(&new_password).map_err(|e| ServerFnError::new(e.to_string()))?;

        let mut user = users
            .find_by_id(&user_id)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?
            .ok_or_else(|| ServerFnError::new("user not found"))?;

        user.password_hash = new_hash;
        users.insert_user(user);

        engine.revoke_all_user_sessions(&user_id).await.map_err(|e| ServerFnError::new(e.to_string()))?;

        Ok("Password reset successfully".into())
    }
    #[cfg(not(feature = "server"))]
    {
        let _ = (token, new_password);
        Err(ServerFnError::new("Server only"))
    }
}

#[derive(Routable, Clone, PartialEq)]
enum Route {
    #[layout(NavBar)]
    #[route("/")]
    Home {},
    #[route("/login")]
    Login {},
    #[route("/register")]
    Register {},
    #[route("/verify")]
    Verify {},
    #[route("/forgot-password")]
    ForgotPassword {},
    #[route("/reset-password")]
    ResetPassword {},
    #[route("/dashboard")]
    Dashboard {},
}

#[component]
fn NavBar() -> Element {
    let mut auth = dioxus_auth::use_auth::<AppUser>();
    let nav = use_navigator();

    rsx! {
        nav { style: "padding: 1rem; background: #f8fafc; border-bottom: 1px solid #e2e8f0;",
            div { style: "max-width: 800px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center;",
                Link { to: Route::Home {}, "Home" }
                Link { to: Route::Dashboard {}, "Dashboard" }
                match auth.status() {
                    dioxus_auth::AuthStatus::Authenticated(_) => {
                        rsx! {
                            button {
                                style: "background: #ef4444; color: white; border: none; padding: 0.4rem 0.8rem; border-radius: 4px; cursor: pointer;",
                                onclick: move |_| {
                                    spawn(async move {
                                        let _ = logout_server().await;
                                        auth.logout();
                                        nav.push(Route::Home {});
                                    });
                                },
                                "Log Out"
                            }
                        }
                    }
                    _ => {
                        rsx! {
                            Link { to: Route::Login {}, "Log In" }
                        }
                    }
                }
            }
        }
        Outlet::<Route> {}
    }
}

#[component]
fn Home() -> Element {
    rsx! {
        div { style: "max-width: 800px; margin: 0 auto; padding: 2rem;",
            h1 { "dioxus-auth Registration Demo" }
            p { "This demo shows registration, email verification, and password reset flows." }
            p { "Features: register with email verification, login, password reset." }
        }
    }
}

#[component]
fn Register() -> Element {
    let mut email = use_signal(|| String::new());
    let mut name = use_signal(|| String::new());
    let mut password = use_signal(|| String::new());
    let mut message = use_signal(|| Option::<String>::None);
    let nav = use_navigator();

    rsx! {
        div { style: "max-width: 400px; margin: 2rem auto; padding: 2rem; border: 1px solid #e2e8f0; border-radius: 8px;",
            h2 { "Register" }
            form {
                onsubmit: move |evt| {
                    evt.prevent_default();
                    let em = email();
                    let nm = name();
                    let pw = password();
                    if em.is_empty() || nm.is_empty() || pw.is_empty() {
                        message.set(Some("All fields are required".to_string()));
                        return;
                    }
                    let nav = nav;
                    spawn(async move {
                        match register_server(em, nm, pw).await {
                            Ok(msg) => {
                                message.set(Some(msg));
                                nav.push(Route::Verify {});
                            }
                            Err(err) => message.set(Some(format!("{err}"))),
                        }
                    });
                },
                div { style: "margin-bottom: 1rem;",
                    label { style: "display: block; font-weight: 500; margin-bottom: 0.3rem;", "Email" }
                    input {
                        r#type: "email",
                        style: "width: 100%; padding: 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px;",
                        value: "{email}",
                        oninput: move |e| email.set(e.value())
                    }
                }
                div { style: "margin-bottom: 1rem;",
                    label { style: "display: block; font-weight: 500; margin-bottom: 0.3rem;", "Name" }
                    input {
                        r#type: "text",
                        style: "width: 100%; padding: 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px;",
                        value: "{name}",
                        oninput: move |e| name.set(e.value())
                    }
                }
                div { style: "margin-bottom: 1.5rem;",
                    label { style: "display: block; font-weight: 500; margin-bottom: 0.3rem;", "Password" }
                    input {
                        r#type: "password",
                        style: "width: 100%; padding: 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px;",
                        value: "{password}",
                        oninput: move |e| password.set(e.value())
                    }
                }
                if let Some(msg) = message() {
                    p { style: "color: #ef4444; margin-bottom: 1rem;", "{msg}" }
                }
                button {
                    r#type: "submit",
                    style: "width: 100%; background: #2563eb; color: white; padding: 0.75rem; border: none; border-radius: 6px; font-weight: bold; cursor: pointer;",
                    "Register"
                }
            }
        }
    }
}

#[component]
fn Verify() -> Element {
    let mut token = use_signal(|| String::new());
    let mut message = use_signal(|| Option::<String>::None);

    rsx! {
        div { style: "max-width: 400px; margin: 2rem auto; padding: 2rem; border: 1px solid #e2e8f0; border-radius: 8px;",
            h2 { "Verify Email" }
            p { "Enter the verification token from the registration response." }
            form {
                onsubmit: move |evt| {
                    evt.prevent_default();
                    let t = token();
                    if t.is_empty() {
                        message.set(Some("Token is required".to_string()));
                        return;
                    }
                    spawn(async move {
                        match verify_email_server(t).await {
                            Ok(msg) => message.set(Some(msg)),
                            Err(err) => message.set(Some(format!("{err}"))),
                        }
                    });
                },
                div { style: "margin-bottom: 1.5rem;",
                    label { style: "display: block; font-weight: 500; margin-bottom: 0.3rem;", "Token" }
                    input {
                        r#type: "text",
                        style: "width: 100%; padding: 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px;",
                        value: "{token}",
                        oninput: move |e| token.set(e.value())
                    }
                }
                if let Some(msg) = message() {
                    p { style: "color: #22c55e; margin-bottom: 1rem;", "{msg}" }
                }
                button {
                    r#type: "submit",
                    style: "width: 100%; background: #2563eb; color: white; padding: 0.75rem; border: none; border-radius: 6px; font-weight: bold; cursor: pointer;",
                    "Verify Email"
                }
            }
        }
    }
}

#[component]
fn Login() -> Element {
    let mut email = use_signal(|| String::new());
    let mut password = use_signal(|| String::new());
    let mut error_msg = use_signal(|| Option::<String>::None);
    let nav = use_navigator();

    rsx! {
        div { style: "max-width: 400px; margin: 2rem auto; padding: 2rem; border: 1px solid #e2e8f0; border-radius: 8px;",
            h2 { "Sign In" }
            form {
                onsubmit: move |evt| {
                    evt.prevent_default();
                    let em = email();
                    let pw = password();
                    if em.is_empty() || pw.is_empty() {
                        error_msg.set(Some("Email and password are required".to_string()));
                        return;
                    }
                    let mut auth = dioxus_auth::use_auth::<AppUser>();
                    let nav = nav;
                    spawn(async move {
                        match login_server(em, pw).await {
                            Ok((user, _)) => {
                                auth.set_user(user);
                                nav.push(Route::Dashboard {});
                            }
                            Err(err) => error_msg.set(Some(format!("{err}"))),
                        }
                    });
                },
                div { style: "margin-bottom: 1rem;",
                    label { style: "display: block; font-weight: 500; margin-bottom: 0.3rem;", "Email" }
                    input {
                        r#type: "email",
                        style: "width: 100%; padding: 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px;",
                        value: "{email}",
                        oninput: move |e| email.set(e.value())
                    }
                }
                div { style: "margin-bottom: 1.5rem;",
                    label { style: "display: block; font-weight: 500; margin-bottom: 0.3rem;", "Password" }
                    input {
                        r#type: "password",
                        style: "width: 100%; padding: 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px;",
                        value: "{password}",
                        oninput: move |e| password.set(e.value())
                    }
                }
                if let Some(err) = error_msg() {
                    p { style: "color: #ef4444; margin-bottom: 1rem;", "{err}" }
                }
                button {
                    r#type: "submit",
                    style: "width: 100%; background: #2563eb; color: white; padding: 0.75rem; border: none; border-radius: 6px; font-weight: bold; cursor: pointer;",
                    "Sign In"
                }
            }
        }
    }
}

#[component]
fn ForgotPassword() -> Element {
    let mut email = use_signal(|| String::new());
    let mut message = use_signal(|| Option::<String>::None);

    rsx! {
        div { style: "max-width: 400px; margin: 2rem auto; padding: 2rem; border: 1px solid #e2e8f0; border-radius: 8px;",
            h2 { "Reset Password" }
            form {
                onsubmit: move |evt| {
                    evt.prevent_default();
                    let em = email();
                    if em.is_empty() {
                        message.set(Some("Email is required".to_string()));
                        return;
                    }
                    spawn(async move {
                        match request_password_reset_server(em).await {
                            Ok(msg) => message.set(Some(msg)),
                            Err(err) => message.set(Some(format!("{err}"))),
                        }
                    });
                },
                div { style: "margin-bottom: 1.5rem;",
                    label { style: "display: block; font-weight: 500; margin-bottom: 0.3rem;", "Email" }
                    input {
                        r#type: "email",
                        style: "width: 100%; padding: 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px;",
                        value: "{email}",
                        oninput: move |e| email.set(e.value())
                    }
                }
                if let Some(msg) = message() {
                    p { style: "color: #22c55e; margin-bottom: 1rem;", "{msg}" }
                }
                button {
                    r#type: "submit",
                    style: "width: 100%; background: #2563eb; color: white; padding: 0.75rem; border: none; border-radius: 6px; font-weight: bold; cursor: pointer;",
                    "Send Reset Link"
                }
            }
        }
    }
}

#[component]
fn ResetPassword() -> Element {
    let mut token = use_signal(|| String::new());
    let mut password = use_signal(|| String::new());
    let mut message = use_signal(|| Option::<String>::None);

    rsx! {
        div { style: "max-width: 400px; margin: 2rem auto; padding: 2rem; border: 1px solid #e2e8f0; border-radius: 8px;",
            h2 { "Set New Password" }
            form {
                onsubmit: move |evt| {
                    evt.prevent_default();
                    let t = token();
                    let pw = password();
                    if t.is_empty() || pw.is_empty() {
                        message.set(Some("Token and password are required".to_string()));
                        return;
                    }
                    spawn(async move {
                        match reset_password_server(t, pw).await {
                            Ok(msg) => message.set(Some(msg)),
                            Err(err) => message.set(Some(format!("{err}"))),
                        }
                    });
                },
                div { style: "margin-bottom: 1rem;",
                    label { style: "display: block; font-weight: 500; margin-bottom: 0.3rem;", "Reset Token" }
                    input {
                        r#type: "text",
                        style: "width: 100%; padding: 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px;",
                        value: "{token}",
                        oninput: move |e| token.set(e.value())
                    }
                }
                div { style: "margin-bottom: 1.5rem;",
                    label { style: "display: block; font-weight: 500; margin-bottom: 0.3rem;", "New Password" }
                    input {
                        r#type: "password",
                        style: "width: 100%; padding: 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px;",
                        value: "{password}",
                        oninput: move |e| password.set(e.value())
                    }
                }
                if let Some(msg) = message() {
                    p { style: "color: #22c55e; margin-bottom: 1rem;", "{msg}" }
                }
                button {
                    r#type: "submit",
                    style: "width: 100%; background: #2563eb; color: white; padding: 0.75rem; border: none; border-radius: 6px; font-weight: bold; cursor: pointer;",
                    "Reset Password"
                }
            }
        }
    }
}

#[component]
fn Dashboard() -> Element {
    let auth = dioxus_auth::use_auth::<AppUser>();
    let user = auth.user().unwrap();

    rsx! {
        div { style: "max-width: 800px; margin: 0 auto; padding: 2rem;",
            h1 { "Protected Dashboard" }
            p { "Authenticated as: ", strong { "{user.name} ({user.email})" } }
            p { "Email verified: {user.email_verified}" }
        }
    }
}

#[component]
fn App() -> Element {
    rsx! {
        AuthProvider::<AppUser> {
            initial_status: None,
            token_storage: dioxus_auth::TokenStorageRef::new(std::sync::Arc::new(dioxus_auth::MemoryTokenStorage::default())),
            AuthRestore {}
            Router::<Route> {}
        }
    }
}

#[component]
fn AuthRestore() -> Element {
    let whoami = use_resource(get_current_user);
    dioxus_auth::use_auth_restore(whoami.read().clone());
    rsx! {}
}

#[server]
async fn login_server(
    email: String,
    password: String,
) -> Result<(AppUser, String), ServerFnError> {
    #[cfg(feature = "server")]
    {
        let (_, engine, cookie_config, _) = init_server_state().await;
        let ctx = ServerAuthContext::from_request(engine, cookie_config)
            .ok_or_else(|| ServerFnError::new("not in a request context"))?;
        ctx.login_and_set_cookie(&email, &password)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))
    }
    #[cfg(not(feature = "server"))]
    {
        let _ = (email, password);
        Err(ServerFnError::new("Server only"))
    }
}

#[server]
async fn logout_server() -> Result<(), ServerFnError> {
    #[cfg(feature = "server")]
    {
        let (_, engine, cookie_config, _) = init_server_state().await;
        let ctx = ServerAuthContext::from_request(engine, cookie_config)
            .ok_or_else(|| ServerFnError::new("not in a request context"))?;
        if let Some(session_id) = ctx.session_id() {
            ctx.logout_and_clear_cookie(&session_id)
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?;
        }
        Ok(())
    }
    #[cfg(not(feature = "server"))]
    {
        Ok(())
    }
}

#[server]
async fn get_current_user() -> Result<Option<AppUser>, ServerFnError> {
    #[cfg(feature = "server")]
    {
        let (_, engine, cookie_config, _) = init_server_state().await;
        let ctx = ServerAuthContext::from_request(engine, cookie_config)
            .ok_or_else(|| ServerFnError::new("not in a request context"))?;
        ctx.current_user_from_request()
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))
    }
    #[cfg(not(feature = "server"))]
    {
        Ok(None)
    }
}

fn main() {
    dioxus::launch(App);
}
