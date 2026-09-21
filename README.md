# dioxus-auth

Authentication and session management for [Dioxus](https://dioxuslabs.com).

You own the database, users, and data. **dioxus-auth** provides the authentication and session layer around them.

## Features

- Session management (rotation, idle timeout, optional single active session)
- Password authentication (Argon2id, timing-attack mitigated)
- Custom user and session stores
- Secure defaults
- Origin/CSRF enforcement and `__Host-` cookie support for fullstack apps

## Usage

Add `dioxus-auth`:

```bash
cargo add dioxus-auth
```

Every plain (`rust`) snippet below is mirrored verbatim in
[`tests/readme_snippets.rs`](tests/readme_snippets.rs) and compile-checked by
CI against the real API. Snippets that need a Dioxus component tree or a
fullstack server are marked `rust,ignore` and are exercised end-to-end by the
crate's test-suite instead.

### Define your user

You own the user type; the crate is generic over it:

```rust
use dioxus_auth::prelude::AuthUser;

#[derive(Debug, Clone)]
struct AppUser {
    id: u64,
    name: String,
}

impl AuthUser for AppUser {
    type Id = u64;

    fn id(&self) -> Self::Id {
        return self.id;
    }

    fn display_name(&self) -> Option<String> {
        return Some(self.name.clone());
    }

    fn clone_box(&self) -> Box<dyn AuthUser<Id = Self::Id>> {
        return Box::new(self.clone());
    }
}
```

### Build the engine

Connect your stores (any `UserStore` / `SessionStore` implementation — the
bundled `MemoryStore` is shown here) and build the engine. Registration is
yours: create users in your store however your application does.

```rust
use std::sync::Arc;

use dioxus_auth::prelude::{Argon2Hasher, AuthEngine, MemoryStore, PasswordHasher};

let store = Arc::new(MemoryStore::<AppUser>::new());

let auth = AuthEngine::builder(Arc::clone(&store), Arc::clone(&store))
    .session_ttl_secs(60 * 60 * 24 * 7)
    .build()
    .expect("engine construction succeeds");

// You own user registration: hash the password yourself (the store must
// never see plaintext) and provision your store however your app does.
// MemoryStore offers a convenience helper that takes an already-hashed
// password.
let hasher = Argon2Hasher::new();
let hash = hasher.hash("password").expect("hashing succeeds");
store.insert_user_with_password(
    AppUser {
        id: 1,
        name: String::from("alice"),
    },
    "alice",
    hash,
);
```

### Log in and validate sessions

The engine is synchronous. `login` returns the authenticated user plus the
raw wire session (the store only ever sees its hash):

```rust
let (user, session) = auth.login("alice", "password").expect("valid credentials");
assert_eq!(user.id(), 1);

let current = auth.validate_session(session.id()).expect("validation must not error");
assert!(current.is_some());

auth.logout(session.id()).expect("revocation must not error");
```

### Wire the Dioxus runtime (`dioxus` feature)

Mount the provider above your tree with an engine handle and a token storage;
read the state in any descendant through `use_auth`:

```rust,ignore
rsx! {
    AuthProvider {
        engine,
        token_storage,
        LoginPage { }
    }
}
```

```rust,ignore
let auth = use_auth::<AppUser>();

let user = auth.user();
if auth.is_authenticated() {
    // render the signed-in UI
}
```

Route guards are components:

```rust,ignore
rsx! {
    RequireAuth::<AppUser> {
        redirect_to: "/login",
        Dashboard { }
    }
}
```

Restore is network-aware: a stored token the server definitively rejects
demotes to guest, but a failure that never answered the session question
(storage failure, rate limit, transport error) leaves the context in
`Loading` so a network blip never silently signs the user out. See
`RestoreVerdict` and the `dioxus` feature docs.

### Fullstack server functions (`dioxus-fullstack` feature)

The macro generates the login/logout/session server functions and their
client callers:

```rust,ignore
dioxus_auth::fullstack_server_fns!(AppUser);
```

Inside your own server functions or middleware, resolve the caller:

```rust,ignore
let user = require_user::<AppUser>().await?;
```

### Hardening

Rate limiting is opt-in; turn it on for any password endpoint facing the
network:

```rust
use std::time::Duration;

use dioxus_auth::prelude::InMemoryRateLimiter;

let limiter = InMemoryRateLimiter::new(5, Duration::from_secs(60));

let auth = AuthEngine::builder(Arc::clone(&store), Arc::clone(&store))
    .rate_limiter(limiter)
    .build()
    .expect("engine construction succeeds");
```

Your application owns the database, users, and data.

For advanced configuration, custom stores, sessions, and authentication providers, see the [API documentation](https://docs.rs/dioxus-auth) (docs.rs), or check out the full [guides](./docs/README.md).

## Secure configuration

Cookie and origin defaults, and when to tighten them:

| Setting | Default | Tighten when |
|---|---|---|
| `HttpOnly`, `Secure` | on | never turn off in production |
| `SameSite` | `Lax` | cross-site embeds need `None` (see below) |
| Cookie lifetime | session cookie (dies with the browser) | persistent login: `with_max_age` sized to the engine TTL (7 days by default) |
| `expected_origins` | none (no origin enforcement) | always for `SameSite=None`; recommended even with `Lax` |
| `host_only` | off | multi-app hosts, to bind the cookie with the `__Host-` prefix |
| Rate limiting | opt-in via the builder | any password endpoint facing the network |

`SameSite=Lax` alone does not stop login CSRF: an attacker can POST their own
credentials to your origin and bind the victim's browser to the attacker's
account. Set `expected_origins` so state-changing operations (login, logout)
require a present, matching `Origin` — mismatches fail with 403. `SameSite=None`
deployments must set it: `None` sends cookies on cross-site requests, leaving
the origin gate as the CSRF backstop. Session reads never require an origin,
and the axum middleware skips the gate for safe methods (`GET`/`HEAD`/`OPTIONS`).

Host-only mode emits `__Host-<name>` with a forced `Path=/`, no `Domain`, and
`Secure`, and accepts only that exact name back — a sibling-app cookie shadow
cannot displace the session.

## Status

Early development. Expect breaking changes.

## License

MIT OR Apache-2.0
