use std::sync::Arc;
use std::time::Duration;

use dioxus::prelude::*;
use dioxus_auth::{
    AuthProvider, AuthUser, use_auth,
};
#[cfg(feature = "server")]
use dioxus_auth::{
    Argon2Hasher, AuthEngine, CookieConfig, PasswordHasher, ServerAuthContext, SessionStore, UserStore,
};
use sqlx::{FromRow, Row, SqlitePool};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, FromRow)]
pub struct AppUser {
    pub id: i64,
    pub email: String,
    pub name: String,
    pub password_hash: String,
}

impl AuthUser for AppUser {
    type Id = u64;

    fn id(&self) -> Self::Id {
        self.id as u64
    }

    fn session_auth_hash(&self) -> Option<&str> {
        Some(&self.password_hash)
    }
}

#[derive(Clone)]
#[cfg(feature = "server")]
struct SqliteStore {
    pool: Arc<SqlitePool>,
}

#[cfg(feature = "server")]
impl SqliteStore {
    async fn new_in_memory() -> Result<Self, sqlx::Error> {
        let pool = SqlitePool::connect("sqlite::memory:").await?;
        let store = Self {
            pool: Arc::new(pool),
        };
        store.create_tables().await?;
        Ok(store)
    }

    async fn create_tables(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL
            )",
        )
        .execute(&*self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at_unix INTEGER NOT NULL,
                expires_at_unix INTEGER NOT NULL,
                auth_hash TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )",
        )
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    async fn create_user(
        &self,
        email: &str,
        name: &str,
        password_hash: &str,
    ) -> Result<AppUser, sqlx::Error> {
        let result = sqlx::query(
            "INSERT INTO users (email, name, password_hash) VALUES (?1, ?2, ?3)",
        )
        .bind(email)
        .bind(name)
        .bind(password_hash)
        .execute(&*self.pool)
        .await?;

        let id = result.last_insert_rowid();
        Ok(AppUser {
            id,
            email: email.to_string(),
            name: name.to_string(),
            password_hash: password_hash.to_string(),
        })
    }
}

#[cfg(feature = "server")]
impl UserStore for SqliteStore {
    type User = AppUser;

    async fn find_by_id(&self, id: &u64) -> dioxus_auth::AuthResult<Option<AppUser>> {
        let row = sqlx::query(
            "SELECT id, email, name, password_hash FROM users WHERE id = ?1",
        )
        .bind(*id as i64)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| dioxus_auth::AuthError::Store(e.to_string()))?;

        let user = row.map(|r| AppUser {
            id: r.get(0),
            email: r.get(1),
            name: r.get(2),
            password_hash: r.get(3),
        });

        Ok(user)
    }
}

#[cfg(feature = "server")]
impl dioxus_auth::PasswordUserStore for SqliteStore {
    async fn find_by_identifier(
        &self,
        identifier: &str,
    ) -> dioxus_auth::AuthResult<Option<(AppUser, String)>> {
        let row = sqlx::query(
            "SELECT id, email, name, password_hash FROM users WHERE email = ?1",
        )
        .bind(identifier)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| dioxus_auth::AuthError::Store(e.to_string()))?;

        let result = row.map(|r| {
            let password_hash: String = r.get(3);
            (
                AppUser {
                    id: r.get(0),
                    email: r.get(1),
                    name: r.get(2),
                    password_hash: password_hash.clone(),
                },
                password_hash,
            )
        });

        Ok(result)
    }
}

#[cfg(feature = "server")]
impl SessionStore<u64> for SqliteStore {
    async fn save_session(&self, session: dioxus_auth::Session<u64>) -> dioxus_auth::AuthResult<()> {
        sqlx::query(
            "
            INSERT INTO sessions (id, user_id, created_at_unix, expires_at_unix, auth_hash)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(id) DO UPDATE SET
                expires_at_unix = excluded.expires_at_unix,
                auth_hash = excluded.auth_hash
            ",
        )
        .bind(session.id().as_str())
        .bind(*session.user_id() as i64)
        .bind(session.created_at_unix() as i64)
        .bind(session.expires_at_unix() as i64)
        .bind(session.auth_hash())
        .execute(&*self.pool)
        .await
        .map_err(|e| dioxus_auth::AuthError::Store(e.to_string()))?;

        Ok(())
    }

    async fn find_session(
        &self,
        id: &dioxus_auth::SessionId,
    ) -> dioxus_auth::AuthResult<Option<dioxus_auth::Session<u64>>> {
        let row = sqlx::query_as::<_, (String, i64, i64, i64, Option<String>)>(
            "SELECT id, user_id, created_at_unix, expires_at_unix, auth_hash FROM sessions WHERE id = ?1",
        )
        .bind(id.as_str())
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| dioxus_auth::AuthError::Store(e.to_string()))?;

        let session = row.map(|(id, user_id, created_at, expires_at, auth_hash)| {
            let mut s = dioxus_auth::Session::new(
                dioxus_auth::SessionId::new(id),
                user_id as u64,
                created_at as u64,
                expires_at as u64,
            );
            if let Some(hash) = auth_hash {
                s = s.with_auth_hash(hash);
            }
            s
        });

        Ok(session)
    }

    async fn delete_session(&self, id: &dioxus_auth::SessionId) -> dioxus_auth::AuthResult<()> {
        sqlx::query("DELETE FROM sessions WHERE id = ?1")
            .bind(id.as_str())
            .execute(&*self.pool)
            .await
            .map_err(|e| dioxus_auth::AuthError::Store(e.to_string()))?;

        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: &u64) -> dioxus_auth::AuthResult<()> {
        sqlx::query("DELETE FROM sessions WHERE user_id = ?1")
            .bind(*user_id as i64)
            .execute(&*self.pool)
            .await
            .map_err(|e| dioxus_auth::AuthError::Store(e.to_string()))?;

        Ok(())
    }

    async fn list_user_sessions(
        &self,
        user_id: &u64,
    ) -> dioxus_auth::AuthResult<Vec<dioxus_auth::Session<u64>>> {
        let rows = sqlx::query_as::<_, (String, i64, i64, i64, Option<String>)>(
            "SELECT id, user_id, created_at_unix, expires_at_unix, auth_hash FROM sessions WHERE user_id = ?1",
        )
        .bind(*user_id as i64)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| dioxus_auth::AuthError::Store(e.to_string()))?;

        let sessions = rows
            .into_iter()
            .map(|(id, user_id, created_at, expires_at, auth_hash)| {
                let mut s = dioxus_auth::Session::new(
                    dioxus_auth::SessionId::new(id),
                    user_id as u64,
                    created_at as u64,
                    expires_at as u64,
                );
                if let Some(hash) = auth_hash {
                    s = s.with_auth_hash(hash);
                }
                s
            })
            .collect();

        Ok(sessions)
    }
}

#[cfg(feature = "server")]
type DemoEngine = AuthEngine<SqliteStore, SqliteStore>;

#[cfg(feature = "server")]
static SERVER_STATE: std::sync::OnceLock<(
    Arc<SqliteStore>,
    DemoEngine,
    CookieConfig,
)> = std::sync::OnceLock::new();

#[cfg(feature = "server")]
fn get_server_state(
) -> &'static (Arc<SqliteStore>, DemoEngine, CookieConfig) {
    SERVER_STATE.get_or_init(|| {
        let store = Arc::new(
            tokio::runtime::Handle::current()
                .block_on(SqliteStore::new_in_memory())
                .expect("sqlite"),
        );
        let hasher = Argon2Hasher::new();
        let password = hasher.hash_password("password123").expect("hash");
        let store_clone = store.clone();
        let _user = tokio::runtime::Handle::current()
            .block_on(store_clone.create_user("admin@example.com", "Admin User", &password))
            .expect("seed user");

        let engine = AuthEngine::builder(store.clone(), store.clone())
            .session_ttl(Duration::from_secs(60 * 60 * 24 * 7))
            .build();

        let cookie_config = CookieConfig::default();
        (store, engine, cookie_config)
    })
}

#[server]
    async fn login_server(
        email: String,
        password: String,
    ) -> Result<AppUser, ServerFnError> {
        #[cfg(feature = "server")]
        {
            let (_, engine, cookie_config) = get_server_state();
            let ctx = ServerAuthContext::from_request(engine, cookie_config)
                .ok_or_else(|| ServerFnError::new("not in a request context"))?;
            ctx.login_cookie(&email, &password)
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
        let (_, engine, cookie_config) = get_server_state();
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
        let (_, engine, cookie_config) = get_server_state();
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
                                        if let Some(storage) = dioxus_auth::use_token_storage() {
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

#[component]
fn Home() -> Element {
    rsx! {
        div { style: "max-width: 800px; margin: 0 auto; padding: 2rem;",
            h1 { "dioxus-auth SQLx SQLite Demo" }
            p { "This demo shows dioxus-auth with a SQLx-backed SQLite store using connection pooling." }
            p { "Features: async session store, login/logout, route protection, token persistence." }
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
    let auth = use_auth::<AppUser>();
    let metrics = use_resource(get_secret_metrics);

    let outcome = dioxus_auth::require_auth(&auth.status(), Route::Login {});

    rsx! {
        dioxus_auth::RouteGate {
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
                h3 { "Confidential Metrics (SQLx-backed)" }
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
async fn get_secret_metrics() -> Result<Vec<String>, ServerFnError> {
    #[cfg(feature = "server")]
    {
        let (_, engine, cookie_config) = get_server_state();
        let ctx = ServerAuthContext::from_request(engine, cookie_config)
            .ok_or_else(|| ServerFnError::new("not in a request context"))?;
        let _user = ctx
            .require_user_from_request()
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        Ok(vec![
            "SQLx-backed metrics".into(),
            "Active users: 42".into(),
            "Revenue: $12,500".into(),
        ])
    }
    #[cfg(not(feature = "server"))]
    {
        Ok(vec![])
    }
}

fn main() {
    dioxus::launch(App);
}
