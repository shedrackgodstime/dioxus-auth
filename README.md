# dioxus-auth

Authentication and session management for [Dioxus](https://dioxuslabs.com).

Secure password authentication and session management for [Dioxus](https://dioxuslabs.com) applications.

You own the database, users, and data. **dioxus-auth** provides the authentication and session layer around them.

## Features

- Session management
- Password authentication (Argon2id, timing-attack mitigated)
- Custom user and session stores
- Secure defaults

## Usage

Add `dioxus-auth`:

```bash
cargo add dioxus-auth
```

### Setup

Enable authentication and connect your stores:

```rust
let auth = AuthEngine::builder(user_store, session_store)
    .password_auth(true)
    .build()?;
```

### Password authentication

```rust
auth.register("alice", "password")?;

let user = auth.login("alice", "password").await?;
```

### Logout

```rust
auth.logout().await?;
```

### Current user

```rust
let auth = use_auth::<AppUser>();

let user = auth.user();
```

### Protected routes

```rust
require_auth();
```

### Server authorization

```rust
let user = require_user().await?;
```

### Custom stores

```rust
let auth = AuthEngine::builder(user_store, session_store)
    .build()?;
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
