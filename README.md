# dioxus-auth

**Authentication and session management for Dioxus.**

`dioxus-auth` is a composable authentication system for Dioxus fullstack applications. It handles the authentication lifecycle while allowing applications to keep control of their own data, storage, infrastructure, and UI.

### Features

* Argon2id password hashing with constant-time timing defense
* Opaque session tokens hashed at rest (`sha256(raw)`)
* Automatic session revocation on password change
* Dioxus-native auth state (`AuthProvider`, `use_auth`, `RouteGate`, `SignedIn`/`SignedOut`)
* Server-side extraction (`ServerAuthContext`) — auto-extracts cookies, origin, and bearer tokens
* `fullstack_server_fns!` macro — generates `\[server\]` login, logout, restore, and require functions
* Token persistence (`TokenStorage` trait with `WebTokenStorage` and `FileTokenStorage`)
* Event hooks (`on_sign_in`, `on_sign_out`, `on_session_validated`)
* Sliding TTL and token rotation
* Hardened cookies — `__Host-` prefix, `HttpOnly`, `SameSite`, CSRF/Origin validation
* Axum middleware (`auth_middleware`)
* Pluggable storage — implement `UserStore`, `PasswordUserStore`, and `SessionStore` against any backend

### Quick Start

#### 1. Define your `User`

```rust
use dioxus_auth::AuthUser;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub id: u64,
    pub email: String,
    pub password_hash: String,
}

impl AuthUser for User {
    type Id = u64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> Option<&str> {
        Some(&self.password_hash)
    }
}
```

#### 2. Build the server engine

```rust,ignore
use std::sync::Arc;
use std::time::Duration;
use dioxus_auth::{AuthEngine, MemoryStore};

let store = Arc::new(MemoryStore::<User>::new());

let engine = AuthEngine::builder(store.clone(), store.clone())
    .session_ttl(Duration::from_secs(60 * 60 * 24 * 7)) // 7 days
    .build();
```

#### 3. Wire the client lifecycle

```rust,ignore
use dioxus::prelude::*;
use dioxus_auth::{AuthProvider, AuthStatus, use_auth, use_auth_restore};

fn App() -> Element {
    rsx! {
        AuthProvider::<User> {
            initial_status: AuthStatus::Loading,
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
```

#### 4. Protect routes

```rust,ignore
use dioxus_auth::{use_auth, require_auth, RouteGate};

#[component]
fn ProtectedLayout() -> Element {
    let auth = use_auth::<User>();
    let outcome = require_auth(&auth.status(), Route::Login);

    rsx! {
        RouteGate {
            outcome: outcome,
            fallback: rsx! { div { "Verifying session..." } },
        }
    }
}
```

#### 5. Conditional rendering

```rust,ignore
use dioxus_auth::{use_auth, SignedIn, SignedOut};

#[component]
fn Navbar() -> Element {
    let auth = use_auth::<User>();

    rsx! {
        SignedIn::<User> {
            span { "Welcome, {auth.user().unwrap().email}!" }
            button { onclick: move |_| auth.logout(), "Log Out" }
        }
        SignedOut::<User> {
            Link { to: Route::Login, "Log In" }
        }
    }
}
```

#### 6. Server-side extraction

```rust,ignore
use dioxus_auth::{ServerAuthContext, AuthEngine, CookieConfig};

#[server]
async fn get_current_user() -> Result<Option<User>, ServerFnError> {
    let (engine, cookie_config) = /* ... */;
    let ctx = ServerAuthContext::from_request(&engine, &cookie_config)
        .ok_or_else(|| ServerFnError::new("not in a request context"))?;
    ctx.current_user_from_request()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}
```

#### 7. Full server-side setup (end-to-end)

For a complete fullstack app, you need three pieces: a shared engine/store, `\[server\]` functions, and client-side restore.

```rust,ignore
// 1. Shared server state (usually a LazyLock)
#[cfg(feature = "server")]
static SERVER_STATE: LazyLock<(Arc<MemoryStore<AppUser>>, AuthEngine<MemoryStore<AppUser>, MemoryStore<AppUser>>, CookieConfig)> =
    LazyLock::new(|| {
        let store = Arc::new(MemoryStore::<AppUser>::new());
        let hasher = Argon2Hasher::new();
        let hash = hasher.hash_password("password123").unwrap();
        store.insert_user_with_password(
            AppUser { id: 1, email: "admin@example.com".into(), name: "Admin".into() },
            "admin@example.com",
            &hash,
        );
        let engine = AuthEngine::builder(store.clone(), store.clone())
            .session_ttl(Duration::from_secs(60 * 60 * 24 * 7))
            .build();
        let cookie_config = CookieConfig::default();
        (store, engine, cookie_config)
    });

// 2. Ready-made server functions via macro
fullstack_server_fns! {
    AppUser,
    &SERVER_STATE.1,
    &SERVER_STATE.2,
}

// 3. Client-side restore
#[component]
fn AuthRestore() -> Element {
    let whoami = use_resource(get_current_user);
    use_auth_restore(whoami.read().clone());
    rsx! {}
}
```

The `fullstack_server_fns!` macro generates four `\[server\]` functions:
- `login_server(identifier: String, password: String) -> Result<User, ServerFnError>`
- `logout_server() -> Result<(), ServerFnError>`
- `get_current_user() -> Result<Option<User>, ServerFnError>`
- `require_user() -> Result<User, ServerFnError>`

`login_server` is **cookie-only** — it sets an `HttpOnly` session cookie on the response and returns the authenticated user. The raw session token never reaches JavaScript. `logout_server` revokes the current session (cookie or bearer) and clears the cookie if a cookie session was active.

#### 8. Bearer token support

`ServerAuthContext` supports both cookies and `Authorization: Bearer` headers. Bearer tokens take precedence. Bearer is for **native / API clients** (desktop, mobile, scripts); the web flow is cookie-only.

For native clients, use `login_bearer` instead of `login_cookie`:

```rust,ignore
#[server]
async fn login_bearer(
    identifier: String,
    password: String,
) -> Result<(User, String), ServerFnError> {
    let (engine, cookie_config) = /* ... */;
    let ctx = ServerAuthContext::new(&engine, &cookie_config);
    ctx.login_bearer(&identifier, &password)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}
```

`login_bearer` returns the raw session token for the client to persist via `TokenStorage` (file, keychain, in-memory). It does **not** set a cookie.

```rust,ignore
#[server]
async fn api_get_user(
    auth_header: Option<String>,
) -> Result<Option<User>, ServerFnError> {
    let (engine, cookie_config) = /* ... */;
    let ctx = ServerAuthContext::new(&engine, &cookie_config);
    ctx.current_user(None, None, auth_header.as_deref())
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}
```

#### 9. Axum middleware

For raw Axum routes, use `auth_middleware` to validate sessions and insert the user into request extensions:

```rust,ignore
use std::sync::Arc;
use dioxus_auth::{axum::auth_middleware, AuthEngine, CookieConfig, MemoryStore};

let engine = Arc::new(AuthEngine::builder(store.clone(), store.clone()).build());
let cookie_config = CookieConfig::default();

let app = Router::new()
    .route("/protected", get(handler))
    .layer(Extension(engine))
    .layer(Extension(cookie_config))
    .layer(middleware::from_fn(auth_middleware::<AppUser, MemoryStore<AppUser>>));
```

The middleware inserts `AuthenticatedUser(user)` into request extensions. Handlers can extract it with `Extension(AuthenticatedUser(user))`.

```rust,ignore
use dioxus_auth::{ServerAuthContext, AuthEngine, CookieConfig};

#[server]
async fn login(email: String, password: String) -> Result<User, ServerFnError> {
    let (engine, cookie_config) = /* ... */;
    let ctx = ServerAuthContext::from_request(&engine, &cookie_config)
        .ok_or_else(|| ServerFnError::new("not in a request context"))?;
    ctx.login_cookie(&email, &password)
        .map_err(|e| ServerFnError::new(e.to_string()))
}
```

#### 10. Logout

`logout_server` revokes the current session (cookie or bearer) and clears the cookie if a cookie session was active. On the client, call `logout_server()` then `auth.logout()` to reset local state:

```rust,ignore
spawn(async move {
    logout_server().await.ok();
    auth.logout();
});
```

#### 10. Logout

`logout_server` revokes the current session (cookie or bearer) and clears the cookie if a cookie session was active. On the client, call `logout_server()` then `auth.logout()` to reset local state:

```rust,ignore
spawn(async move {
    logout_server().await.ok();
    auth.logout();
});
```

```rust,ignore
#[server]
async fn logout() -> Result<(), ServerFnError> {
    let (engine, cookie_config) = /* ... */;
    let ctx = ServerAuthContext::from_request(&engine, &cookie_config)
        .ok_or_else(|| ServerFnError::new("not in a request context"))?;
    if let Some(session_id) = ctx.session_id() {
        ctx.logout_and_clear_cookie(&session_id)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
    }
    Ok(())
}
```

#### 10. Event hooks

```rust,ignore
use std::sync::Arc;
use dioxus_auth::{AuthEngine, MemoryStore};

let store = Arc::new(MemoryStore::<User>::new());
let engine = AuthEngine::builder(store.clone(), store.clone())
    .session_ttl(Duration::from_secs(60 * 60 * 24 * 7))
    .on_sign_in(|user| {
        // audit log, analytics, cache invalidation
        tracing::info!("user {} signed in", user.id());
    })
    .on_sign_out(|user| {
        tracing::info!("user {} signed out", user.id());
    })
    .on_session_validated(|user| {
        // track active sessions
    })
    .build();
```

#### 11. SQLite-backed demo (rusqlite)

A complete working example with a real `rusqlite` store is in [`examples/sqlite-demo/`](examples/sqlite-demo/). It demonstrates:

- `SqliteStore` implementing `UserStore`, `PasswordUserStore`, and `SessionStore`
- Full Dioxus fullstack wiring: login, logout, restore, route protection
- `ServerAuthContext::login_cookie` / `logout_current`
- `AuthProvider` with `AuthRestore`

Run it with:

```sh
cargo run --example dioxus-auth-sqlite-demo --features server
```

#### 12. SQLite-backed demo (SQLx)

A production-pattern example using `sqlx` with `SqlitePool` is in [`examples/sqlx-sqlite/`](examples/sqlx-sqlite/). It demonstrates:

- Async `SqliteStore` with connection pooling
- `UserStore`, `PasswordUserStore`, and `SessionStore` implementations
- Type-safe queries with `sqlx::query_as`
- Full Dioxus fullstack wiring

Run it with:

```sh
cargo run -p dioxus-auth-sqlx-sqlite --features server
```

#### 13. Store test suite

The crate ships a `dioxus_auth::tests` module with conformance tests for `UserStore`, `PasswordUserStore`, and `SessionStore` implementations. Use them to verify your custom store works with `AuthEngine`:

```rust,ignore
use std::sync::Arc;
use dioxus_auth::{tests::*, AuthEngine, Argon2Hasher, MemoryStore};

#[tokio::test]
async fn my_store_follows_contract() {
    let store = Arc::new(MyStore::new_in_memory());
    let hasher = Argon2Hasher::new();
    let (user, hash) = seeded_test_user(1, "alice@example.com", "password123");
    store.create_user_for_testing(user, &hash).await.unwrap();

    run_user_store_tests(store.clone()).await;
    run_password_user_store_tests(store.clone(), &hasher).await;
    run_session_store_tests(store.clone()).await;
    run_engine_lifecycle_tests(store.clone(), store.clone()).await;
}
```

See [`src/storage/tests.rs`](src/storage/tests.rs) for the full list of test helpers.

### Minimal setup

The smallest working setup requires four trait implementations and an engine:

```rust
use std::sync::Arc;
use dioxus_auth::{
    AuthEngine, AuthUser, PasswordUserStore, Session, SessionId, SessionStore, UserStore,
};

// 1. Your user model
#[derive(Clone, Debug, PartialEq, Eq)]
struct User {
    id: u64,
    email: String,
    password_hash: String,
}

impl AuthUser for User {
    type Id = u64;
    fn id(&self) -> Self::Id { self.id }
    fn session_auth_hash(&self) -> Option<&str> { Some(&self.password_hash) }
}

// 2. Minimal in-memory store (replace with your database)
struct MyStore {
    users: std::collections::HashMap<u64, User>,
    credentials: std::collections::HashMap<String, (u64, String)>,
    sessions: std::collections::HashMap<SessionId, Session<u64>>,
}

impl UserStore for MyStore {
    type User = User;
    async fn find_by_id(&self, id: &u64) -> dioxus_auth::AuthResult<Option<User>> {
        Ok(self.users.get(id).cloned())
    }
}

impl PasswordUserStore for MyStore {
    async fn find_by_identifier(
        &self,
        identifier: &str,
    ) -> dioxus_auth::AuthResult<Option<(User, String)>> {
        Ok(self.credentials
            .get(identifier)
            .and_then(|(id, hash)| self.users.get(id).map(|u| (u.clone(), hash.clone())))
        )
    }
}

impl SessionStore<u64> for MyStore {
    async fn save_session(&self, session: Session<u64>) -> dioxus_auth::AuthResult<()> { Ok(()) }
    async fn find_session(&self, id: &SessionId) -> dioxus_auth::AuthResult<Option<Session<u64>>> {
        Ok(self.sessions.get(id).cloned())
    }
    async fn delete_session(&self, id: &SessionId) -> dioxus_auth::AuthResult<()> { Ok(()) }
    async fn delete_user_sessions(&self, user_id: &u64) -> dioxus_auth::AuthResult<()> { Ok(()) }
    async fn list_user_sessions(&self, user_id: &u64) -> dioxus_auth::AuthResult<Vec<Session<u64>>> {
        Ok(self.sessions.values().filter(|s| s.user_id() == user_id).cloned().collect())
    }
    // Default `touch_session_if_present` is a best-effort find-then-save;
    // override it with a conditional update to close resurrection races.
}

// 3. Wire the engine
fn main() {
    let store = Arc::new(MyStore {
        users: std::collections::HashMap::new(),
        credentials: std::collections::HashMap::new(),
        sessions: std::collections::HashMap::new(),
    });
    let engine = AuthEngine::builder(store.clone(), store)
        .session_ttl(std::time::Duration::from_secs(3600))
        .build();

    // Now use engine.login(), engine.validate_session(), engine.logout()
}
```

Replace `MyStore` with your actual database (SQLite, PostgreSQL, etc.). See [`examples/sqlite-demo/`](examples/sqlite-demo/) for a `rusqlite` implementation or [`examples/sqlx-sqlite/`](examples/sqlx-sqlite/) for an async `sqlx` implementation with connection pooling.

### Philosophy

> **Your application owns the data and infrastructure. `dioxus-auth` owns the authentication lifecycle.**

The goal is to make authentication feel like a natural part of a Dioxus application without forcing developers into a particular database, ORM, provider, or UI.

### Status

🚧 **Early development**

The API is still evolving. Expect breaking changes while the core architecture is being established.

### License

Licensed under the MIT License.
