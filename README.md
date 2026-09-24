# dioxus-auth

Authentication and session management for [Dioxus](https://dioxuslabs.com).

You own the database, users, and data. **dioxus-auth** provides the authentication and session layer around them.

## Quickstart

Add `dioxus-auth`:

```bash
cargo add dioxus-auth
```

Zero modeling. A built-in user, verbs that just work:

```rust
use dioxus_auth::{Auth, DefaultUserInput};

fn main() -> Result<(), dioxus_auth::AuthError> {
    let auth = Auth::memory()?;

    auth.sign_up_email(
        "alice@example.com",
        "password",
        DefaultUserInput::new("alice"),
    )?;

    let (user, session) = auth.sign_in_email("alice@example.com", "password")?;
    assert_eq!(user.name, "alice");

    auth.sign_out(&session)?;
    Ok(())
}
```

Memory dies with the process, so prototype with it. Unknown
identifiers and wrong passwords share one `InvalidCredentials` error:
identifier state is never observable.

## Graduating (memory → your database)

1. Define your own `AppUser` with your fields (nothing renames or
   migrates; the quickstart types stay behind).
2. Swap `Auth::memory()` for `Auth::new(your_store)` (for example
   `examples/sqlite-reference`) and implement `AuthUser` (one method:
   `id`).
3. Nothing else changes: same verbs, same sessions, same error codes.
   Sessions are opaque and user-type-agnostic, so zero migration.

Your data lives in four tables. Column sketch below; the exact DDL ships
in `examples/sqlite-reference`, which also implements the store. Apply it
with any SQL tool, then point a store at it:

```sql
users(id, email, name, ...)  -- your AppUser rows
accounts(provider, identifier, user_id, password_hash)  -- credentials
sessions(id, user_id, expiry, activity, metadata)  -- opaque server sessions
verifications(id, identifier, token, expiry)  -- reserved for future flows
```

```rust
use dioxus_auth::{Auth, AuthUser, MemoryStore};

#[derive(Debug, Clone)]
struct AppUser {
    id: u64,
    email: String,
}

impl AuthUser for AppUser {
    type Id = u64;

    fn id(&self) -> u64 {
        self.id
    }
}

fn main() -> Result<(), dioxus_auth::AuthError> {
    let auth = Auth::new(MemoryStore::<AppUser>::new())?;

    auth.sign_up_email(
        "alice@example.com",
        "password",
        AppUser { id: 1, email: String::from("alice@example.com") },
    )?;
    Ok(())
}
```

## Client (Dioxus)

Mount one provider, read state anywhere, guard routes with plain components:

```rust,ignore
rsx! {
    AuthProvider { auth,
        RequireAuth { redirect_to: "/login", Dashboard {} }
    }
}
```

```rust,ignore
let s = use_session::<AppUser>();
match s {
    SessionState::SignedIn(user) => rsx! { "Hello, {user.email}" },
    SessionState::Pending => rsx! { "Loading..." },
    SessionState::Unavailable(_) => rsx! { "Retry" },
    SessionState::Guest => rsx! { LoginForm {} },
}
```

## Server (fullstack)

Generate the cookie-driven endpoints once, and resolve the caller per call.
The server re-validates every time; guards are UX only:

```rust,ignore
dioxus_auth::fullstack_server_fns!(AppUser);
```

```rust,ignore
let user = dioxus_auth::require_user::<AppUser>().await?;
```

## Hardening

Rate limiting is opt-in. Turn it on for any credential endpoint facing the
network:

```rust
use std::sync::Arc;
use std::time::Duration;
use dioxus_auth::{AuthEngine, AuthUser, InMemoryRateLimiter, MemoryStore};

#[derive(Debug, Clone)]
struct AppUser {
    id: u64,
    email: String,
}

impl AuthUser for AppUser {
    type Id = u64;

    fn id(&self) -> u64 {
        self.id
    }
}

fn main() -> Result<(), dioxus_auth::AuthError> {
    let limiter = InMemoryRateLimiter::new(5, Duration::from_secs(60));
    let store = Arc::new(MemoryStore::<AppUser>::new());
    let _auth = AuthEngine::builder(store.clone(), store)
        .rate_limiter(limiter)
        .build()?;
    Ok(())
}
```

Production preset: 100 attempts per 60-second window
(`InMemoryRateLimiter::prod()`), with tighter per-verb rules on sensitive
endpoints.

## Secure configuration

Cookie and origin defaults, and when to tighten them:

| Setting | Default | Tighten when |
|---|---|---|
| `HttpOnly`, `Secure` | on | never turn off in production |
| `SameSite` | `Lax` | cross-site embeds need `None` (which forces `Secure`, and origins below become mandatory) |
| Cookie lifetime | session cookie (dies with the browser) | persistent login: `with_max_age` sized to the engine TTL (7 days by default) |
| `expected_origins` | none (no origin enforcement) | always for `SameSite=None`; recommended even with `Lax` |
| `host_only` | off | multi-app hosts, to bind the cookie with the `__Host-` prefix |
| Rate limiting | opt-in | any credential endpoint facing the network |

`SameSite=Lax` alone does not stop login CSRF: an attacker can POST their own
credentials to your origin and bind the victim's browser to the attacker's
account. Set `expected_origins` so state-changing operations (login, logout)
require a present, matching `Origin`. Mismatches fail with 403. `SameSite=None`
deployments must set it: `None` sends cookies on cross-site requests, leaving
the origin gate as the CSRF backstop. Session reads never require an origin,
and the axum middleware skips the gate for safe methods (`GET`/`HEAD`/`OPTIONS`).

Host-only mode emits `__Host-<name>` with a forced `Path=/`, no `Domain`, and
`Secure`, and accepts only that exact name back. A sibling-app cookie shadow
cannot displace the session.

Two reads, never confused: `use_session()` is the local render read;
`require_user()` is the verified network truth. Server code must never trust
the local read.

## Status

v0.1.0 is the email+password vertical: `Auth::new` over your store, mirrored
verbs, single-prop provider, `use_session`, documented schema with a
copy-paste SQLite reference (`examples/sqlite-reference`). Additive methods
(magic link, OAuth, passkeys) arrive as new verbs on the same entry point.
Never a second auth system. Expect breaking changes before release; nothing
is published yet.

## License

MIT OR Apache-2.0
