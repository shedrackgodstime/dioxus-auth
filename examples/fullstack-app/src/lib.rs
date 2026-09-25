//! Minimal fullstack app on `dioxus-auth`: login, session, logout over
//! cookie server functions, plus axum middleware in front of a probe route.
//!
//! The whole app is one config constructor, one router, and the generated
//! server functions. Tests drive real HTTP semantics (cookies, statuses)
//! through `tower` without binding a port.

use std::sync::Arc;

use dioxus_auth::{
    Auth, AuthEngine, AuthEngineHandle, CookieConfig, MemoryStore, RequireAuthLayer,
    ServerAuthConfig,
};
use dioxus_fullstack::axum::Router;
use dioxus_fullstack::axum::extract::Extension;
use dioxus_fullstack::axum::http::StatusCode;
use dioxus_fullstack::axum::response::IntoResponse;
use dioxus_fullstack::axum::routing::get;

dioxus_auth::fullstack_server_fns!(AppUser);

/// Application user for the fullstack demo.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AppUser {
    /// Stable row id.
    pub id: u64,
    /// Login identifier.
    pub email: String,
}

impl dioxus_auth::AuthUser for AppUser {
    type Id = u64;

    fn id(&self) -> Self::Id {
        self.id
    }
}

/// Builds the seeded server configuration every test and `main` share.
///
/// # Panics
/// Panics if the engine, seed signup, or config construction fails. Test and
/// example setup only; production builds fallible configuration instead.
#[must_use]
pub fn app_config() -> ServerAuthConfig<AppUser> {
    let store = Arc::new(MemoryStore::<AppUser>::new());
    let engine = AuthEngine::builder(Arc::clone(&store), Arc::clone(&store))
        .build()
        .expect("engine must build");
    let auth = Auth::from_engine(engine);
    auth.sign_up_email(
        "alice@example.com",
        "password",
        AppUser {
            id: 1,
            email: String::from("alice@example.com"),
        },
    )
    .expect("seed signup must succeed");
    let cookie = CookieConfig::new().with_name(String::from("session"));
    ServerAuthConfig::new(AuthEngineHandle::from(Arc::clone(auth.engine())), cookie)
}

/// Router with the engine attached and the probe behind the requiring
/// layer: guests get 401 without reaching the handler.
pub fn app_router(config: ServerAuthConfig<AppUser>) -> Router {
    Router::new()
        .route("/probe", get(probe).post(probe))
        .layer(RequireAuthLayer::new(config))
}

/// Probe handler: only reachable with a valid session.
async fn probe(Extension(_config): Extension<Arc<ServerAuthConfig<AppUser>>>) -> impl IntoResponse {
    (StatusCode::OK, String::from("authed"))
}
