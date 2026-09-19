# dioxus-auth

**Authentication and session management for Dioxus.**

`dioxus-auth` is a composable authentication system for Dioxus fullstack applications. It handles the authentication lifecycle while allowing applications to keep control of their own data, storage, infrastructure, and UI.

## Authentication in Dioxus

`dioxus-auth` follows three principles:

1. **Authentication state is reactive.** One `Signal<AuthStatus<User>>` drives every component. Sign out anywhere and the whole UI updates — no manual invalidation.
2. **The server is the security authority.** Client state drives *rendering* only. Every protected operation re-validates the session server-side; a component can be wrong safely, an endpoint cannot.
3. **Sessions are transport-independent.** The engine neither knows nor cares whether the credential arrived as an `HttpOnly` cookie (web) or a bearer token (native/API). Same `SessionStore`, same lifecycle.

The whole client model fits in one diagram — `use_auth()` hides all of it:

```text
            Dioxus Application
                   │
            use_auth::<User>()
                   │
        Signal<AuthStatus<User>>
         /         |          \
    Loading   Authenticated   Unauthenticated
                  (User)
                   │  (sign in / sign out / restore)
         [server fn — cookie or bearer]
                   │
           ServerAuthContext → AuthEngine
                   │
              SessionStore
```

If you already know Dioxus, the API is predictable:

| If you want… | Dioxus way | dioxus-auth way |
|---|---|---|
| Authentication state | reactive signal | `use_auth::<User>()` → `auth.status()` (`AuthStatus`) |
| Current user | `.read()` | `auth.user()` → `Option<User>` |
| Sign in | server function | `login_server(identifier, password)` (sets `HttpOnly` cookie) |
| Sign out | server function | `logout_server()` + `auth.logout()` |
| Session restore on mount | `use_resource` | `use_auth_restore` |
| Auth provider | context | `AuthProvider::<User> { .. }` |
| Protected UI | router guard | `require_auth(&status, route)` + `RouteGate { .. }`, or `SignedIn::<User>` / `SignedOut::<User>` |
| Return-to after login | — | automatic with `RouteGate` (`preserve_intent` default) + `consume_return_to()` at login |
| Protected server operation | `#[server]` fn | `require_user().await?` (or `ServerAuthContext::require_user`) |
| Native / API clients | — | `login_bearer` + `TokenStorage` |

### Features

* Argon2id password hashing with user-enumeration timing mitigation (dummy-hash verification on unknown identifiers; lookup is variable-time, not constant-time)
* Opaque session tokens hashed at rest (`sha256(raw)`)
* Automatic session revocation on password change
* Dioxus-native auth state (`AuthProvider`, `use_auth`, `RouteGate`, `SignedIn`/`SignedOut`)
* Server-side extraction (`ServerAuthContext`) — auto-extracts cookies, origin, and bearer tokens
* `fullstack_server_fns!` macro — generates `\[server\]` login, logout, restore, and require functions
* Token persistence (`TokenStorage` trait with `WebTokenStorage` and `FileTokenStorage`)
* Event hooks (`on_sign_in`, `on_sign_out`, `on_session_validated`)
* Absolute session TTL + optional idle timeout; optional single-active-session
* Hardened cookies — `__Host-` prefix, `HttpOnly`, `SameSite`, CSRF/Origin validation
* Axum middleware (`auth_middleware`)
* Pluggable storage — implement `UserStore`, `PasswordUserStore`, and `SessionStore` against any backend

### Quick Start

#### 1. Define your users

Two types: one for the wire, one for the server. The engine authenticates
`UserRecord` (server-side only); clients only ever see `UserView`.

```rust
use dioxus_auth::AuthUser;
use serde::{Deserialize, Serialize};

/// The type that crosses the wire and lives in client auth state.
/// Public fields only — `#[server]` functions serialize what they return.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserView {
    pub id: u64,
    pub email: String,
    pub name: String,
}

/// The server-side row. The password hash NEVER leaves the server.
#[derive(Clone)]
struct UserRecord {
    id: u64,
    email: String,
    password_hash: String,
}

impl AuthUser for UserRecord {
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

let store = Arc::new(MemoryStore::<UserRecord>::new());

let engine = AuthEngine::builder(store.clone(), store.clone())
    .session_ttl(Duration::from_secs(60 * 60 * 24 * 7)) // 7 days
    .build();
```

#### 3. Wire the client lifecycle

Restore is **cookie-first and network-aware**: the probe rides the `HttpOnly`
session cookie, and its error is classified — a definitive server rejection
(401/403) signs the user out, but a network failure (DNS down, Wi-Fi blip,
timeout) leaves the app in `Loading` so nobody gets logged out by a bad
connection. Retry the probe on window focus while loading:

```rust,ignore
let whoami = use_resource(current_user);
use_effect(move || {
    let w = window();
    // restart the probe when the tab regains focus and still Loading
});
```

```rust,ignore
use dioxus::prelude::*;
use dioxus_auth::{AuthProvider, AuthStatus, use_auth, use_auth_restore};

fn App() -> Element {
    rsx! {
        AuthProvider::<UserView> {
            initial_status: AuthStatus::Loading,
            AuthRestore {}
            Router::<Route> {}
        }
    }
}

#[component]
fn AuthRestore() -> Element {
    let whoami = use_resource(current_user);
    use_auth_restore(whoami.read().clone());
    rsx! {}
}
```

#### 4. Protect routes

```rust,ignore
use dioxus_auth::{use_auth, require_auth, RouteGate};

#[component]
fn ProtectedLayout() -> Element {
    let auth = use_auth::<UserView>();
    let outcome = require_auth(&auth.status(), Route::Login);

    rsx! {
        RouteGate {
            outcome: outcome,
            fallback: rsx! { div { "Verifying session..." } },
        }
    }
}
```

By default, `RouteGate` **preserves intent**: when it bounces an unauthenticated visitor, the URL they were heading for is parked (browser `localStorage`, open-redirect-filtered). Pop it after a successful login to land them back on their original destination:

```rust,ignore
// in the login component, after login succeeds:
auth.set_user(user);
if let Some(dest) = consume_return_to() {
    // dest is a safe relative path like "/app/exam/cbt"
    navigator.push(dest);
} else {
    navigator.push(Route::Dashboard {});
}
```

`capture_return_to` / `clear_return_to` / `is_safe_return_to` are exported for custom guard flows; off-browser targets are no-ops.

#### 5. Cross-tab sync

Sign in on one tab, stay in sync on the rest. Mount the receiver near the root, emit from your login/logout flows:

```rust,ignore
rsx! {
    AuthProvider::<UserView> {
        CrossTabSync::<UserView> {}          // receive: applies other tabs' changes
        Router::<Route> {}
    }
}

// in the login flow, after auth.set_user(user):
let broadcaster = use_auth_broadcaster::<UserView>();
broadcaster.login(&user);                // other tabs sign in too

// in the logout flow:
broadcaster.logout();
```

Messages ride a `BroadcastChannel` (`dioxus-auth-sync` by default; override via `CrossTabSync`'s `channel_name` prop — the broadcaster picks it up automatically). Off-browser targets are no-ops.

#### 6. Conditional rendering

```rust,ignore
use dioxus_auth::{use_auth, SignedIn, SignedOut};

#[component]
fn Navbar() -> Element {
    let auth = use_auth::<UserView>();

    rsx! {
        SignedIn::<UserView> {
            span { "Welcome, {auth.user().unwrap().email}!" }
            button { onclick: move |_| auth.logout(), "Log Out" }
        }
        SignedOut::<UserView> {
            Link { to: Route::Login, "Log In" }
        }
    }
}
```

#### 7. Server-side extraction

```rust,ignore
use dioxus_auth::{ServerAuthContext, AuthEngine, CookieConfig};

#[server]
async fn current_user() -> Result<Option<UserView>, ServerFnError> {
    let (engine, cookie_config) = /* ... */;
    let ctx = ServerAuthContext::from_request(&engine, &cookie_config)
        .ok_or_else(|| ServerFnError::new("not in a request context"))?;
    ctx.current_user_from_request()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}
```

#### 8. Full server-side setup (end-to-end)

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
    let whoami = use_resource(current_user);
    use_auth_restore(whoami.read().clone());
    rsx! {}
}
```

The `fullstack_server_fns!` macro generates four `\[server\]` functions:
- `login_server(identifier: String, password: String) -> Result<UserView, ServerFnError>`
- `logout_server() -> Result<(), ServerFnError>`
- `current_user() -> Result<Option<UserView>, ServerFnError>`
- `require_user() -> Result<UserView, ServerFnError>`

`login_server` is **cookie-only** — it sets an `HttpOnly` session cookie on the response and returns the authenticated user. The raw session token never reaches JavaScript. `logout_server` revokes the current session (cookie or bearer) and clears the cookie if a cookie session was active.

#### 9. Bearer token support

`ServerAuthContext` supports both cookies and `Authorization: Bearer` headers. Bearer tokens take precedence. Bearer is for **native / API clients** (desktop, mobile, scripts); the web flow is cookie-only.

> On web, prefer the cookie flow: `HttpOnly` cookies are invisible to JavaScript, while a bearer token persisted via `WebTokenStorage` (`localStorage`) is readable by any XSS. See the warning on the type and the "Secure configuration" notes below.

For native clients, use `login_bearer` instead of `login_cookie`:

```rust,ignore
#[server]
async fn login_bearer(
    identifier: String,
    password: String,
) -> Result<(UserView, String), ServerFnError> {
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
) -> Result<Option<UserView>, ServerFnError> {
    let (engine, cookie_config) = /* ... */;
    let ctx = ServerAuthContext::new(&engine, &cookie_config);
    ctx.current_user(None, None, auth_header.as_deref())
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}
```

#### 10. Axum middleware

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
async fn login(email: String, password: String) -> Result<UserView, ServerFnError> {
    let (engine, cookie_config) = /* ... */;
    let ctx = ServerAuthContext::from_request(&engine, &cookie_config)
        .ok_or_else(|| ServerFnError::new("not in a request context"))?;
    ctx.login_cookie(&email, &password)
        .map_err(|e| ServerFnError::new(e.to_string()))
}
```

#### 11. Logout

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

#### 12. Event hooks

```rust,ignore
use std::sync::Arc;
use dioxus_auth::{AuthEngine, MemoryStore};

let store = Arc::new(MemoryStore::<UserRecord>::new());
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

#### 13. SQLite-backed demo (rusqlite)

A complete working example with a real `rusqlite` store is in [`examples/sqlite-demo/`](examples/sqlite-demo/). It demonstrates:

- `SqliteStore` implementing `UserStore`, `PasswordUserStore`, and `SessionStore`
- Full Dioxus fullstack wiring: login, logout, restore, route protection
- `ServerAuthContext::login_cookie` / `logout_current`
- `AuthProvider` with `AuthRestore`

Run it with:

```sh
cargo run --example dioxus-auth-sqlite-demo --features server
```

#### 14. SQLite-backed demo (SQLx)

A production-pattern example using `sqlx` with `SqlitePool` is in [`examples/sqlx-sqlite/`](examples/sqlx-sqlite/). It demonstrates:

- Async `SqliteStore` with connection pooling
- `UserStore`, `PasswordUserStore`, and `SessionStore` implementations
- Type-safe queries with `sqlx::query_as`
- Full Dioxus fullstack wiring

Run it with:

```sh
cargo run -p dioxus-auth-sqlx-sqlite --features server
```

#### 15. Store test suite

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

See [`src/storage/conformance.rs`](src/storage/conformance.rs) for the full list of test helpers.

> **Warning: keep secrets out of the wire user.** `#[server]` functions serialize
> their return value to the client. Your `AuthUser` type — or anything containing
> `password_hash` / `session_auth_hash` — must **not** be returned from a server
> function. Return a public user view instead (id, email, name, roles) and keep
> the hash row server-side only. The examples use hash-free public types for
> exactly this reason.

### Minimal setup

The smallest working setup requires four trait implementations and an engine:

```rust
use std::sync::Arc;
use dioxus_auth::{
    AuthEngine, AuthUser, PasswordUserStore, Session, SessionId, SessionStore, UserStore,
};

// 1. Your server-side user record (the password hash never crosses the
// wire; return a hash-free public view from #[server] functions).
#[derive(Clone, Debug, PartialEq, Eq)]
struct UserRecord {
    id: u64,
    email: String,
    password_hash: String,
}

impl AuthUser for UserRecord {
    type Id = u64;
    fn id(&self) -> Self::Id { self.id }
    fn session_auth_hash(&self) -> Option<&str> { Some(&self.password_hash) }
}

// 2. Minimal in-memory store (replace with your database)
struct MyStore {
    users: std::collections::HashMap<u64, UserRecord>,
    credentials: std::collections::HashMap<String, (u64, String)>,
    sessions: std::collections::HashMap<SessionId, Session<u64>>,
}

impl UserStore for MyStore {
    type User = UserRecord;
    async fn find_by_id(&self, id: &u64) -> dioxus_auth::AuthResult<Option<UserRecord>> {
        Ok(self.users.get(id).cloned())
    }
}

impl PasswordUserStore for MyStore {
    async fn find_by_identifier(
        &self,
        identifier: &str,
    ) -> dioxus_auth::AuthResult<Option<(UserRecord, String)>> {
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

### Secure configuration

These settings interact and must be considered together before you ship:

| Setting | Guidance |
|---|---|
| `host_only` | Prefer `true` in production: forces `Path=/`, forbids `Domain`, enforces `Secure`, and (Spec 15) the server **rejects** the bare unprefixed cookie name on read. Requires HTTPS. |
| `same_site` | Keep `Lax` (default) unless you genuinely need cross-site cookies. |
| **`same_site = None`** | **Mandatory** `expected_origins`. With `SameSite=None` a cross-site request can carry the ambient session cookie, so `expected_origins` becomes the **only** real CSRF defense on cookie state-changing ops (`login`, `logout`). If you set `None`, you must set `expected_origins` to your exact origin(s). |
| `expected_origins` | Origin/CSRF checks apply **only to cookie credentials** (Bearer never needs Origin). Set this to your production origin(s) (`https://app.example.com`). Default `None` disables it — fine for a vanilla `SameSite=Lax` same-origin app, unsafe with `SameSite=None`. |
| `secure` | Emitted automatically with `host_only`; default `true` in release builds. Do not set the cookie over plain HTTP. |
| **rate limiter** | **Opt-in — off until you call `.with_rate_limiter(...)` on the builder.** Without it, login brute force is unthrottled (S1's defense only exists if configured). The built-in `InMemoryRateLimiter` is a per-process sliding window; multi-instance deployments should implement `RateLimiter` against a shared store (Redis, Memcached). |
| **login CSRF** | Set `expected_origins` in production **even with `SameSite=Lax`** — login CSRF does not need the victim's cookie: an attacker cross-site POSTs *their own* credentials and the response `Set-Cookie` binds your visitor's browser to the attacker's account. Lax cannot stop that; the Origin check can. |
| `Session` / `SessionId` logging | Never log a `Session` or `SessionId`: `Debug`/`Display` print the **raw wire token** — a log line is a session leak. (Redaction is planned post-0.1.) |

> The sliding-window rate limiter is a **per-process approximation**. For a
> multi-instance deployment, implement `RateLimiter` against a shared store
> (Redis, Memcached). It counts attempts per normalized identifier and is not a
> lockout policy. Remember it is **off by default** — see the table row above.
>
> `AuthEngine::identifier_exists` is a public existence check intended for
> registration flows. Do **not** call it from an unauthenticated
> "is this email taken?" probe on the login page — login's own error channel
> collapses unknown-user and wrong-password precisely to prevent enumeration.
>
> `WebTokenStorage` keeps the raw session token in `localStorage`. The cookie
> flow (`HttpOnly`, never readable by JavaScript) is the XSS-resistant default
> on web; prefer it. Use bearer + `WebTokenStorage` only for apps that accept
> the token-theft-on-XSS trade-off, or on native targets where
> `FileTokenStorage` applies.

### Philosophy

> **Your application owns the data and infrastructure. `dioxus-auth` owns the authentication lifecycle.**

The goal is to make authentication feel like a natural part of a Dioxus application without forcing developers into a particular database, ORM, provider, or UI.

### Status

**Pre-1.0, under active development.** The core auth kernel (engine, sessions,
cookies, password hashing) and the Dioxus client lifecycle are stable in
shape and covered by the security review in `docs/`; the API may still break
between minor releases while the crate approaches 1.0. See
[`CHANGELOG.md`](CHANGELOG.md) for what changed and what is planned.

### License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-Apache) at your option.
