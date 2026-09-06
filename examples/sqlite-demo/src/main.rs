use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use dioxus::prelude::*;
use dioxus_auth::{
    require_auth, use_auth, use_auth_restore, use_token_storage, AuthProvider, AuthUser,
    AuthEngine, Argon2Hasher, CookieConfig, MemoryStore, PasswordHasher, RouteGate,
    ServerAuthContext, SessionStore, TokenStorageRef, UserStore,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type for the demo app
// ---------------------------------------------------------------------------

#[derive(Error, Debug, Clone)]
enum DemoError {
    #[error("authentication error: {0}")]
    Auth(#[from] dioxus_auth::AuthError),
    #[error("store error: {0}")]
    Store(String),
}

// ---------------------------------------------------------------------------
// Application User model
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppUser {
    pub id: u64,
    pub email: String,
    pub name: String,
    pub password_hash: String,
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

// ---------------------------------------------------------------------------
// SQLite Storage Adapter
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct SqliteStore {
    conn: Arc<Mutex<rusqlite::Connection>>,
}

impl SqliteStore {
    fn new_in_memory() -> Result<Self, DemoError> {
        let conn = rusqlite::Connection::open_in_memory()
            .map_err(|e| DemoError::Store(e.to_string()))?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.create_tables()?;
        Ok(store)
    }

    fn create_tables(&self) -> Result<(), DemoError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at_unix INTEGER NOT NULL,
                expires_at_unix INTEGER NOT NULL,
                auth_hash TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            ",
        )
        .map_err(|e| DemoError::Store(e.to_string()))?;
        Ok(())
    }

    fn create_user(
        &self,
        email: &str,
        name: &str,
        password_hash: &str,
    ) -> Result<AppUser, DemoError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO users (email, name, password_hash) VALUES (?1, ?2, ?3)",
            rusqlite::params![email, name, password_hash],
        )
        .map_err(|e| DemoError::Store(e.to_string()))?;
        let id = conn.last_insert_rowid() as u64;
        Ok(AppUser {
            id,
            email: email.to_string(),
            name: name.to_string(),
            password_hash: password_hash.to_string(),
        })
    }
}

impl UserStore for SqliteStore {
    type User = AppUser;

    async fn find_by_id(&self, id: &u64) -> dioxus_auth::AuthResult<Option<AppUser>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| dioxus_auth::AuthError::Store(e.to_string()))?;
        let user = conn
            .query_row(
                "SELECT id, email, name, password_hash FROM users WHERE id = ?1",
                rusqlite::params![id],
                |row| {
                    Ok(AppUser {
                        id: row.get(0)?,
                        email: row.get(1)?,
                        name: row.get(2)?,
                        password_hash: row.get(3)?,
                    })
                },
            )
            .map(|x| Some(x))
            .map_err(|e| dioxus_auth::AuthError::Store(e.to_string()))?;

        Ok(user)
    }
}

impl dioxus_auth::PasswordUserStore for SqliteStore {
    async fn find_by_identifier(
        &self,
        identifier: &str,
    ) -> dioxus_auth::AuthResult<Option<(AppUser, String)>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| dioxus_auth::AuthError::Store(e.to_string()))?;
        let result = conn
            .query_row(
                "SELECT id, email, name, password_hash FROM users WHERE email = ?1",
                rusqlite::params![identifier],
                |row| {
                    let hash: String = row.get(3)?;
                    let user = AppUser {
                        id: row.get(0)?,
                        email: row.get(1)?,
                        name: row.get(2)?,
                        password_hash: hash.clone(),
                    };
                    Ok((user, hash))
                },
            )
            .map(|x| Some(x))
            .map_err(|e| dioxus_auth::AuthError::Store(e.to_string()))?;
        Ok(result)
    }
}

impl SessionStore<u64> for SqliteStore {
    async fn save_session(&self, session: dioxus_auth::Session<u64>) -> dioxus_auth::AuthResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| dioxus_auth::AuthError::Store(e.to_string()))?;
        conn.execute(
            "
            INSERT INTO sessions (id, user_id, created_at_unix, expires_at_unix, auth_hash)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(id) DO UPDATE SET
                expires_at_unix = excluded.expires_at_unix,
                auth_hash = excluded.auth_hash
            ",
            rusqlite::params![
                session.id().as_str(),
                session.user_id(),
                session.created_at_unix(),
                session.expires_at_unix(),
                session.auth_hash(),
            ],
        )
        .map_err(|e| dioxus_auth::AuthError::Store(e.to_string()))?;
        Ok(())
    }

    async fn find_session(
        &self,
        id: &dioxus_auth::SessionId,
    ) -> dioxus_auth::AuthResult<Option<dioxus_auth::Session<u64>>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| dioxus_auth::AuthError::Store(e.to_string()))?;
        let session = conn
            .query_row(
                "SELECT id, user_id, created_at_unix, expires_at_unix, auth_hash FROM sessions WHERE id = ?1",
                rusqlite::params![id.as_str()],
                |row| {
                    let sess_id = dioxus_auth::SessionId::new(row.get::<_, String>(0)?);
                    let user_id = row.get::<_, u64>(1)?;
                    let created_at = row.get::<_, u64>(2)?;
                    let expires_at = row.get::<_, u64>(3)?;
                    let auth_hash = row.get::<_, Option<String>>(4)?;
                    let mut s = dioxus_auth::Session::new(sess_id, user_id, created_at, expires_at);
                    if let Some(hash) = auth_hash {
                        s = s.with_auth_hash(hash);
                    }
                    Ok(s)
                },
            )
            .map(|x| Some(x))
            .map_err(|e| dioxus_auth::AuthError::Store(e.to_string()))?;
        Ok(session)
    }

    async fn delete_session(&self, id: &dioxus_auth::SessionId) -> dioxus_auth::AuthResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| dioxus_auth::AuthError::Store(e.to_string()))?;
        conn.execute("DELETE FROM sessions WHERE id = ?1", rusqlite::params![id.as_str()])
            .map_err(|e| dioxus_auth::AuthError::Store(e.to_string()))?;
        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: &u64) -> dioxus_auth::AuthResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| dioxus_auth::AuthError::Store(e.to_string()))?;
        conn.execute("DELETE FROM sessions WHERE user_id = ?1", rusqlite::params![user_id])
            .map_err(|e| dioxus_auth::AuthError::Store(e.to_string()))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Server state
// ---------------------------------------------------------------------------

#[cfg(feature = "server")]
type DemoEngine = AuthEngine<SqliteStore, SqliteStore>;

#[cfg(feature = "server")]
static SERVER_STATE: LazyLock<(Arc<SqliteStore>, DemoEngine, CookieConfig)> =
    LazyLock::new(|| {
        let store = Arc::new(SqliteStore::new_in_memory().expect("sqlite"));
        let hasher = Argon2Hasher::new();
        let password = hasher.hash_password("password123").expect("hash");
        store
            .create_user("admin@example.com", "Admin User", &password)
            .expect("seed user");

        let engine = AuthEngine::builder(store.clone(), store.clone())
            .session_ttl(Duration::from_secs(60 * 60 * 24 * 7))
            .build();

        let cookie_config = CookieConfig::default();
        (store, engine, cookie_config)
    });

// ---------------------------------------------------------------------------
// Server Functions
// ---------------------------------------------------------------------------

#[server]
async fn login_server(
    email: String,
    password: String,
) -> Result<(AppUser, String), ServerFnError> {
    #[cfg(feature = "server")]
    {
        let (_, engine, cookie_config) = &*SERVER_STATE;
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
        let (_, engine, cookie_config) = &*SERVER_STATE;
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
        let (_, engine, cookie_config) = &*SERVER_STATE;
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

#[server]
async fn get_secret_metrics() -> Result<Vec<String>, ServerFnError> {
    #[cfg(feature = "server")]
    {
        let (_, engine, cookie_config) = &*SERVER_STATE;
        let ctx = ServerAuthContext::from_request(engine, cookie_config)
            .ok_or_else(|| ServerFnError::new("not in a request context"))?;
        let _user = ctx
            .require_user_from_request()
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        Ok(vec![
            "SQLite-backed metrics".into(),
            "Active users: 42".into(),
            "Revenue: $12,500".into(),
        ])
    }
    #[cfg(not(feature = "server"))]
    {
        Ok(vec![])
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

#[derive(Routable, Clone, PartialEq)]
enum Route {
    #[layout(NavBar)]
    #[route("/")]
    Home {},
    #[route("/login")]
    Login {},
    #[route("/dashboard")]
    Dashboard {},
}

#[component]
fn NavBar() -> Element {
    let mut auth = use_auth::<AppUser>();
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
                                        logout_server().await.ok();
                                        if let Some(storage) = use_token_storage() {
                                            storage.clear();
                                        }
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

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

#[component]
fn Home() -> Element {
    rsx! {
        div { style: "max-width: 800px; margin: 0 auto; padding: 2rem;",
            h1 { "dioxus-auth SQLite Demo" }
            p { "This demo shows dioxus-auth with a real SQLite backend." }
            p { "Features: login/logout, session validation, route protection, token persistence." }
        }
    }
}

#[component]
fn Login() -> Element {
    let mut email = use_signal(|| String::new());
    let mut password = use_signal(|| String::new());
    let mut error_msg = use_signal(|| Option::<String>::None);
    let mut is_submitting = use_signal(|| false);
    let nav = use_navigator();

    rsx! {
        div { style: "max-width: 400px; margin: 2rem auto; padding: 2rem; border: 1px solid #e2e8f0; border-radius: 8px;",
            h2 { "Sign In" }
            p { style: "color: #64748b; margin-bottom: 1.5rem;",
                "Demo user: admin@example.com / password123"
            }
            form {
                onsubmit: move |evt| {
                    evt.prevent_default();
                    let em = email();
                    let pw = password();
                    if em.is_empty() || pw.is_empty() {
                        error_msg.set(Some("Email and password are required".to_string()));
                        return;
                    }
                    let mut auth = use_auth::<AppUser>();
                    let nav = nav;
                    spawn(async move {
                        is_submitting.set(true);
                        error_msg.set(None);
                        match login_server(em, pw).await {
                            Ok((user, raw_token)) => {
                                if let Some(storage) = use_token_storage() {
                                    let _ = storage.save(&raw_token);
                                }
                                auth.set_user(user);
                                nav.push(Route::Dashboard {});
                            }
                            Err(err) => {
                                error_msg.set(Some(format!("{err}")));
                            }
                        }
                        is_submitting.set(false);
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
                    disabled: is_submitting(),
                    style: "width: 100%; background: #2563eb; color: white; padding: 0.75rem; border: none; border-radius: 6px; font-weight: bold; cursor: pointer;",
                    if is_submitting() { "Signing in..." } else { "Sign In" }
                }
            }
        }
    }
}

#[component]
fn Dashboard() -> Element {
    let mut auth = use_auth::<AppUser>();
    let metrics = use_resource(get_secret_metrics);

    let outcome = require_auth(&auth.status(), Route::Login {});

    rsx! {
        RouteGate {
            outcome: outcome,
            fallback: rsx! {
                div { style: "text-align: center; padding: 4rem;",
                    h3 { "Checking Authentication..." }
                    p { "Please wait while your session is verified." }
                }
            },
        }
        div { style: "max-width: 800px; margin: 0 auto; padding: 2rem;",
            h1 { "Protected Dashboard" }
            p { "Authenticated as: ", strong { "{auth.user().unwrap().name} ({auth.user().unwrap().email})" } }
            div { style: "margin-top: 2rem;",
                h3 { "Confidential Metrics (SQLite-backed)" }
                match &*metrics.read() {
                    Some(Ok(data)) => rsx! {
                        ul {
                            for item in data {
                                li { style: "padding: 0.5rem 0; font-size: 1.1rem;", "{item}" }
                            }
                        }
                    },
                    Some(Err(err)) => rsx! {
                        p { style: "color: #ef4444;", "Failed to load metrics: {err}" }
                    },
                    None => rsx! {
                        p { "Loading live metrics from server function..." }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

#[component]
fn App() -> Element {
    rsx! {
        AuthProvider::<AppUser> {
            initial_status: None,
            token_storage: TokenStorageRef::new(std::sync::Arc::new(dioxus_auth::MemoryTokenStorage::default())),
            AuthRestore {}
            Router::<Route> {}
        }
    }
}

#[component]
fn AuthRestore() -> Element {
    let whoami = use_resource(get_current_user);
    use_auth_restore(whoami.read().clone());
    rsx! {}
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    dioxus::launch(App);
}
