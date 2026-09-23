# dioxus-auth — Guides

Deeper guides for `dioxus-auth`. The crate is converging on the future DX
contract in the root README (three doors, additive methods, mirrored verbs) —
guides below follow that direction. Entries marked `FUTURE` are planned and not
yet written; unmarked entries exist.

> Do not document the old engine-first quickstart as the happy path. The future
> entry point is `Auth::memory()` / `Auth::new(db)` with `.with_*` methods, read
> through `use_session()`, guarded by `RequireAuth`. That shape is frozen as the
> direction until the implementation lands.

## Getting started

- **Installation** — features (`dioxus`, `dioxus-fullstack`, `server`), MSRV,
  wasm target notes, what each feature pulls in. (FUTURE)
- **Hello, guarded route (Door 1)** — `Auth::memory().with_email_password()` to
  a protected page in <10 min, ≤3 concepts, 0 traits. The copy-paste `LoginForm`
  snippet lives here (the crate never ships a black-box sign-in screen). (FUTURE)
- **Your user, your database (Door 2)** — own `AppUser` + own store with the
  same verbs; the documented 4-table shape (`user` / `session` / `account` /
  `verification`) as copy-paste SQL you apply yourself. No scaffolding required.
  Reference implementation with guide: `examples/sqlite-reference` (schema,
  store, and engine-flow tests; the guide asserts its SQL stays byte-identical
  to the DDL). (The `.with_*` builder surface it points at is still FUTURE.)
- **Full control (Door 3)** — custom stores, hashers, rate limiters, audit
  hooks, `__Host-`, per-request authority, conformance proofs. (FUTURE)

## Core concepts

- **Three doors, one family** — how quick start, own DB, and full control share
  one entry point and one verb set; what each door owns vs the crate owns. (FUTURE)
- **Sessions** — opaque server-side sessions; TTL, idle timeout, single-active
  and multi-session list/revoke; scoped sign-out (`local` default, `global`
  opt-in); the two reads you must never confuse: `session()` (local render) vs
  `authenticate()` (verified network truth). (FUTURE)
- **Tokens & storage** — memory (quickstart/tests), file, web, and custom
  `TokenStorage`; cookies on web vs secure storage on native; why `clear()`
  returns `Result`. (FUTURE)
- **Users & identities** — your `AppUser`, the built-in `DefaultUser`, linking
  multiple identities to one user, admin-managed users. (FUTURE)
- **Passwords** — Argon2id defaults, timing-attack mitigation, identical
  unknown-user/wrong-secret errors, change + reset flows. (FUTURE)
- **Errors** — stable `error.code` values for every verb; `{ data, error }`
  values; branch on code, never on message text. (FUTURE)

## Auth methods (additive — absence = disabled)

- **Email + password** — `sign_up_email` / `sign_in_email` / `sign_out`;
  per-method options (`disable_sign_up`, `require_email_verification`,
  `auto_sign_in`, `should_create_user`). (FUTURE)
- **Magic link & email OTP** — `request_magic_link` (always succeeds, no
  enumeration) / `consume_magic_link`; the single mailer seam (core owns token +
  TTL + store, you own transport; never await the send inside the request). (FUTURE)
- **Username** — addon to email+password, availability check. (FUTURE)
- **OAuth / OIDC providers** — `sign_in_oauth({ provider })`, redirect flow,
  PKCE confirm route (`token_hash` + `type` + `next`); implicit fragment flow is
  refused server-side. (FUTURE)
- **Passkeys & TOTP two-factor** — on top of a first factor, never standalone
  login; assurance levels (`aal1`/`aal2`) as claims. (FUTURE)
- **Anonymous & guest upgrade** — try-before-sign-up with account linking. (FUTURE)
- **API keys & bearer tokens** — long-lived keys for native/CLI clients with a
  revocation list. (FUTURE)
- **Admin, roles & organizations** — role checks, user management, teams. (FUTURE)

## Client (Dioxus)

- **Provider & `use_session()`** — single-prop `AuthProvider { auth }`,
  `use_session()` → `{ data, pending, error, refetch }`,
  `on_auth_state_change` subscriptions, cross-tab sync. (FUTURE)
- **Route guards** — `RequireAuth` / `RedirectIfAuthed` as plain components,
  usable anywhere; redirect-once semantics, router requirements. (FUTURE)
- **Network-aware restore** — definitive reject demotes to guest; storage /
  transport / rate-limit failures stay in `Loading` so a blip never signs the
  user out. (FUTURE)
- **SSR & hydration** — first-paint behavior, no silent sign-out, no hydration
  flash. (FUTURE)
- **Desktop & mobile targets** — bearer transport, secure storage, no cookie
  jar. (FUTURE)

## Server (fullstack)

- **Wire functions & config doors** — generated functions once; `AuthLayer` for
  apps vs `server_init` for tests (one door per page, same config). (FUTURE)
- **Resolving the caller** — `require_user` / `current_user` per call; the
  server re-validates every time, guards are UX only. (FUTURE)
- **Cookies** — `HttpOnly` + `Secure`, `SameSite=Lax` default, expected origins,
  `max-age` sized to TTL, `__Host-` prefix mode; safe methods skip the origin
  gate, state-changing ops enforce it. (FUTURE)
- **Middleware composition** — `RequireAuthLayer`, per-request context. (FUTURE)
- **Email delivery (SMTP)** — custom sender setup, templates, quotas; built-in
  sending is for development only. (FUTURE)
- **Hooks** — audit (`on_sign_in` / `on_sign_out` / `on_session_validated`) and
  single-branch `before` / `after(path)` middleware. (FUTURE)

## Shipping & operating

- **Hardening checklist** — origins, `__Host-`, persistent tokens, rate limits
  (prod 60 s / 100 with tighter per-verb rules, `429` + `X-Retry-After`),
  CAPTCHA hooks, secret hygiene. (FUTURE)
- **Rate limits** — per-verb rules, atomic single-use consume, storage backends. (FUTURE)
- **Audit logs** — what to log per event (`sign-in`, `sign-out`, `token
  refreshed`, `challenge created`) and where to ship it. (FUTURE)
- **Testing your auth** — injected clocks for expiry, the conformance suite for
  your stores, stress tests, IP/user-agent attribution. (FUTURE)
- **Troubleshooting** — error-code lookup, common misconfigurations (origins,
  clock skew, cookie flags), debug checklist. (FUTURE)
- **Security review notes** — threat model, what the crate guarantees vs what
  your app must enforce. (FUTURE)

## Examples

- **Minimal fullstack app** — the hello example, also the compile gate. (FUTURE)
- **Own-DB app (SQLite)** — file-backed persistence without scaffolding. (FUTURE)
- **Hardened production app** — origins, limits, persistent tokens, hooks. (FUTURE)
- **Native token-storage app** — desktop/mobile bearer flow. (FUTURE)
