# dioxus-auth

Authentication and session management for [Dioxus](https://dioxuslabs.com).

You own the database, users, and data. **dioxus-auth** provides the authentication and session layer around them.

> ## DX contract — pinned, do not regress
>
> This README describes the **future target API** the crate is converging on.
> The implementation is not there yet (see Status). Until it is, do not rewrite
> this file back to the old engine-first quickstart — that shape is frozen
> reference only, not the direction.
>
> Three doors, no CLI needed to start:
>
> 1. **Quick start** — `Auth::memory().with_email_password()`, built-in
>    `DefaultUser`, guarded route in <10 min, ≤3 concepts, 0 traits.
> 2. **Own DB** — `Auth::new(my_db)` with the same verbs; documented schema you
>    apply yourself; hardening without rewriting.
> 3. **Full control** — explicit stores, hashers, limits, audit hooks, `__Host-`,
>    per-request authority, conformance proofs.
>
> Laws: methods are additive (absence = disabled — never a `without_*` flag);
> verbs are mirrored server = client = HTTP path and return `{ data, error }`
> with stable `error.code`; sessions/guards stay method-agnostic; no hosted
> backend, no billing, no black-box sign-in UI (the form is always yours).

## Features

- Session management (TTL, idle timeout, single active session, scoped sign-out)
- Email+password authentication (Argon2id, timing-attack mitigated, no-enumeration errors)
- Magic link / passwordless email (planned, same session model)
- `use_session()` reactive state (`{ data, pending, error, refetch }`) + route guards
- Custom user and session stores (you own the schema; guides ship copy-paste SQL)
- Secure defaults: `HttpOnly` + `Secure` cookies, `SameSite=Lax`, origin enforcement
- Origin/CSRF enforcement and `__Host-` cookie support for fullstack apps
- Opt-in rate limiting with per-verb rules

## Usage (future target DX — converging, see Status)

Add `dioxus-auth`:

```bash
cargo add dioxus-auth
```

> Snippets below marked `FUTURE` show the pinned future shape (`rust,ignore`,
> not yet compile-checked). The crate is being rebuilt toward them.

### Door 1 — quick start (FUTURE)

Zero modeling. A built-in `DefaultUser`; hashing, stores, and tokens pre-wired:

```rust,ignore
// FUTURE target shape
let auth = Auth::memory().with_email_password();
auth.sign_up_email(SignUpEmail { email: "alice@example.com", password: "password", name: "alice" })?;

rsx! {
    AuthProvider { auth,
        RequireAuth { redirect_to: "/login", Dashboard {} }
    }
}
```

### Door 2 — own DB, same verbs (FUTURE)

Your user type, your database, the same verbs. No scaffolding — apply the
documented schema yourself:

```rust,ignore
// FUTURE target shape
struct AppUser { id: Uuid, email: String, name: String }

let auth = Auth::new(my_db).with_email_password();
auth.sign_in_email(SignInEmail { email: "alice@example.com", password: "password" })?;
```

```rust,ignore
// FUTURE target shape — read state anywhere, reactive
let s = use_session();
match &s.data {
    Some(user) => rsx! { "Hello, {user.name}" },
    None if s.is_pending => rsx! { "Loading..." },
    None => rsx! { LoginForm {} },
}
```

Route guards stay plain components, usable anywhere:

```rust,ignore
rsx! {
    RequireAuth { redirect_to: "/login", Dashboard {} }
}
```

### Door 3 — full control (explicit everything)

Custom stores, hashers, rate limiters, audit hooks, and cookie policy — the
current engine surface survives here, under new names. Server remains the
security authority: resolve the caller per call:

```rust,ignore
let user = require_user().await?;
```

Rate limiting is opt-in; turn it on for any credential endpoint facing the
network (prod defaults: 60 s window / 100 max, tighter per-verb rules):

```rust,ignore
// FUTURE target shape — limits live on the method, not a god object
let auth = Auth::new(my_db)
    .with_email_password()
    .with_rate_limit(RateLimit::prod());
```

Your application owns the database, users, and data.

For the full method list (password → magic link → OTP → OAuth → passkeys/TOTP)
and budgets, see the Features list above — the future direction is additive
methods on one entry point, never a second auth system.

## Secure configuration

Cookie and origin defaults, and when to tighten them:

| Setting | Default | Tighten when |
|---|---|---|
| `HttpOnly`, `Secure` | on | never turn off in production |
| `SameSite` | `Lax` | cross-site embeds need `None` (see below) |
| Cookie lifetime | session cookie (dies with the browser) | persistent login: `with_max_age` sized to the engine TTL (7 days by default) |
| `expected_origins` | none (no origin enforcement) | always for `SameSite=None`; recommended even with `Lax` |
| `host_only` | off | multi-app hosts, to bind the cookie with the `__Host-` prefix |
| Rate limiting | opt-in | any credential endpoint facing the network |

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

Two reads, never confused: `session()` is the local render read; `authenticate()`
is the verified network truth. Server code must never trust the local read.

## Status

Rebuilding toward the future DX contract above: the `Auth::new` / `Auth::memory`
facade, mirrored verbs, `use_session`, mailer seam, and documented schema, in
that order. The current code still exposes the old engine-first API as frozen
reference. Expect breaking changes — nothing is published yet.

## License

MIT OR Apache-2.0
