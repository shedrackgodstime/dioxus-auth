# Changelog

All notable changes to `dioxus-auth` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Logout Origin bypass via junk `Authorization` (F7).** `ServerAuthContext::logout_current`
  and the registry's `logout_with_headers` extracted credentials by passing
  the cookie into the bearer extractor; a present-but-non-Bearer header
  (`Basic …`, `Bearer ` with no token, unknown schemes) fell through to the
  session cookie, was misclassified as bearer credentials, and skipped
  `validate_cookie_origin` — letting a cross-site request revoke the cookie
  session with no Origin check. Both sites now extract bearer with
  `cookie = None` (mirroring `current_user`): junk headers fall through to
  the cookie path, where the Origin check runs before revocation. Guarded by
  `junk_authorization_header_cannot_bypass_logout_origin_check`.
- `CookieConfig::build_delete_cookie_header` now forces `Path=/` when
  `host_only` is enabled, mirroring `build_set_cookie_header` (RFC 6265bis §5).
  Previously the delete header used the configured `path` unforced, so with
  `host_only: true` and a custom `path` the clear-cookie header could not
  match the cookie the set header wrote — logout appeared to succeed while
  the session cookie survived in the browser. Latent until now (the default
  config is `host_only: false`); guarded by a set/delete symmetry test.

### Security

- Registry one-liner `logout_current` now enforces Origin/CSRF validation on
  cookie-credential logouts (spec 15): previously the registry's logout path
  dropped the `Origin` header, so a cross-site request could revoke a
  cookie-session despite `expected_origins` being configured. Rejection leaves
  the session alive; bearer logouts skip Origin per the credential-specific
  rule; no-credential logouts stay idempotent. Plan + tests:
  `scratch/plans/0a-cookie-transport-completion.md`.

### Changed

- **BREAKING:** `use_auth_restore` now requires the error type to implement
  the new `RestoreClassify` trait (one method: `restore_verdict() ->
  RestoreVerdict`). The hook no longer treats every restore error as logout:
  a definitive server rejection (`RestoreVerdict::Unauthenticated`, i.e. an
  HTTP 401/403-class answer) signs the user out, but a network failure
  (`RestoreVerdict::Unknown` — DNS, timeout, offline, 5xx) **stays in
  `Loading`** instead of rendering a guest session (research 23 §2.1).
  `dioxus_auth::RestoreClassify` is implemented for `ServerFnError`
  (`dioxus-fullstack` feature); for custom whoami errors, implement the one
  method:

  ```rust
  impl dioxus_auth::RestoreClassify for MyError {
      fn restore_verdict(&self) -> dioxus_auth::RestoreVerdict {
          dioxus_auth::RestoreVerdict::Unknown
      }
  }
  ```

  Migration: if your error type previously relied on `Err(_) → logout`, return
  `RestoreVerdict::Unauthenticated` for your definitive-rejection shapes.

### Security

- `AuthError::into_server_fn_error()` (new) maps auth failures to HTTP status
  codes (`401` rejections, `403` CSRF, `429` rate-limited) instead of
  `format!`-flattening, so clients can distinguish "rejected" from "server
  error"; the `fullstack_server_fns!` generated functions now use it
  (research 23 §3.2).

### Added

- **Cross-tab emit half** — `use_auth_broadcaster::<User>()` returns an
  `AuthBroadcaster` with `login(&user)` / `logout()` / `broadcast(&msg)`;
  each emit opens a short-lived `BroadcastChannel` (default channel
  `dioxus-auth-sync`, exposed as `DEFAULT_CROSS_TAB_CHANNEL`). Channel parity
  with a mounted `CrossTabSync` is automatic, even for custom channel names.
  Emit needs `User: Serialize` only. `CrossTabSync` is no longer
  wasm32-gated at the module level (it was already a documented no-op
  off-browser) and its stale "broadcasts" doc is corrected. Wire format is
  unchanged and now pinned by tests (`{"Login":{"user":…}}` / `"Logout"`).
- Cross-tab sync (`CrossTabSyncHost`) now logs a console warning when a
  received broadcast message is malformed (typically deploy skew between tabs
  with different `User` serializations) instead of dropping it silently, and
  documents the deliberate `Closure::forget` lifetime.
- **Return-to navigation** (spec 17 §3): `RouteGate` gains
  `preserve_intent: bool` (default `true`) — when it redirects an
  unauthenticated visitor, the target URL is parked in `localStorage`
  (`dioxus_auth_intent`) and the login flow can pop it with
  `consume_return_to()` (single read, open-redirect-filtered). Also exported:
  `capture_return_to`, `clear_return_to`, `is_safe_return_to`,
  `AUTH_INTENT_KEY`. Storage is browser-only; SSR/native are no-ops.
  Deviation from the spec sketch: consumption is free functions, not a method
  on `Auth` — `Auth` stays a pure `Copy` signal handle (spec 13 rule 2).
- `try_use_auth::<User>() -> Option<Auth<User>>` — non-panicking variant of
  `use_auth`, following dioxus's `try_use_context`/`use_context` pairing
  convention. Returns `None` outside an `AuthProvider` tree (embeds, test
  shells, SSR probes) instead of panicking. Hooks and `Auth` query methods
  also gained dioxus-standard hygiene: `#[must_use]`, `#[track_caller]` on
  panicking hooks, rules-of-hooks doc sections, `#[doc(alias)]` entries, and
  `AuthProvider` now provisions contexts via `use_context_provider`.
- Server registry + one-liner helpers (requires `dioxus-fullstack`):
  `server_init(engine, cookie_config)` called once at boot, then
  `require_user::<AppUser>().await?`, `current_user::<AppUser>().await`, and
  `logout_current().await` inside any `#[server]` function — no per-endpoint
  wiring. State is stored type-erased (dioxus-context pattern) and downcast at
  the call site; app code stays fully typed. Panics are documented for the
  three misuse cases (not initialized, no request context, wrong user type).
  Login stays on `ServerAuthContext` (needs `LoginOptions` + wire tokens).
- `AuthError::InvalidCredentials` — returned when a login's identifier/password
  pair is rejected. Covers both an unknown identifier and a wrong password;
  the two are deliberately indistinguishable so the error channel cannot be
  used to enumerate registered accounts.

### Changed

- **BREAKING:** `AuthEngine::login`/`login_with_options` now return
  `AuthError::InvalidCredentials` on rejected credentials instead of
  `AuthError::Unauthenticated`. `Unauthenticated` now means session-state
  problems only (absent/invalid session, user behind a session no longer
  eligible). Match on `InvalidCredentials` for inline form errors and on
  `Unauthenticated` for redirects:

  ```rust
  // before
  Err(AuthError::Unauthenticated) => /* form error or redirect? */
  // after
  Err(AuthError::InvalidCredentials) => /* inline "wrong email or password" */,
  Err(AuthError::Unauthenticated)    => /* session-state problem */
  ```

<!-- The entries below were previously mislabeled "[0.2.0]" (a version that
     was never released — its tag existed only locally and no crates.io
     publish accompanied it). They are part of the upcoming real 0.1.0. -->

### Added

- `fullstack_server_fns!` macro — generates ready-made `#[server]` login, logout, restore, and require functions
- `ServerAuthContext::login_cookie` (cookie-only web flow) and `login_bearer` (native/API flow returning the raw token) — Spec 14
- `login_with_options` — login with optional IP address and user agent metadata
- Axum middleware (`auth_middleware`, `require_auth_middleware`, `permission_middleware`) — all read the request's `Origin` header (Spec 15)
- Event hooks (`on_sign_in`, `on_sign_out`, `on_session_validated`) on `AuthEngineBuilder`
- Idle timeout (`idle_timeout` / `idle_timeout_secs`) — session expiry advances on validated activity; absolute TTL remains `created_at + session_ttl` (Spec 16)
- Single-active-session policy (`single_active_session`) — re-login revokes the user's other sessions (Spec 16)
- `SessionStore::touch_session_if_present` — conditional expiry/activity update that closes logout/rotate resurrection races; documented store contract (Spec 16)
- `Session::last_active_at_unix` + setters
- Rate limiting — `RateLimiter` trait, `InMemoryRateLimiter` (sliding window), `with_rate_limiter` on the builder; attempts are keyed on a normalized (trim + lowercase) identifier so case/whitespace variants share one budget
- `__Host-` cookie prefix support with enforced constraints on **write and read** (Spec 15)
- Origin/CSRF validation for cookie credentials — state-changing cookie ops (`login`, `logout`) require a matching `Origin` when `expected_origins` is configured; bearer is never Origin-checked
- `extract_session_token` — dual-extract helper preferring `Authorization: Bearer`, falling back to `Cookie`
- `use_token_storage()` and `TokenStorageRef` for client-side token persistence
- SQLite-backed demos (`examples/sqlite-demo/`, `examples/sqlx-sqlite/`) with `SqliteStore`
- Store test suite helpers in `dioxus_auth::tests`
- Standing security review (`docs/20-security-review.md`)

### Changed (breaking)

- **`fullstack_server_fns!`**: `login_server` now returns `Result<User, _>` — cookie-only, the raw session token never reaches JavaScript. Use a separate `login_bearer` server fn for native clients.
- **Builder renames**: `sliding_window` → `idle_timeout` (semantics changed — see Spec 16; the old sliding window stopped extending once `now - created >= window`), `rotate_tokens` → `single_active_session`.
- **`extract_session_token`** gained a `host_only: bool` parameter — strict cookie-name matching (`__Host-<name>` when true, bare `<name>` when false; the other form is rejected either way).
- **`CookieConfig`**: `host_only` now forces `Path=/` on write and rejects the unprefixed name on read (cookie-name confusion closed).
- **`auth_middleware`** now returns `403 Forbidden` on `AuthError::Csrf` instead of treating it as anonymous (parity with `require_auth_middleware`/`permission_middleware`).
- Simplified and tightened all doc comments across the crate
- Extracted shared login logic in `AuthEngine` to reduce duplication
- Consolidated hook firing into a single helper
- `AuthEngine::dummy_hash` is now private with `pub(crate)` getter for tests

### Security

- Bearer tokens bypass CSRF/Origin checks (not susceptible to cross-site request forgery)
- File-backed `FileTokenStorage` enforces 0600 permissions on Unix
- Session tokens are hashed at rest with SHA-256
- Timing defense corrected in docs: the dummy-hash verification on unknown identifiers mitigates user enumeration, but the lookup is **variable-time, not constant-time** (the earlier "constant-time" wording was an overclaim)
- `SameSite=None` now documented as **requiring** `expected_origins` (see README "Secure configuration") — with `SameSite=None` the Origin check is the only real CSRF defense on cookie state-changing ops
- Rate limiter documented as a per-process approximation (multi-instance deployments need a distributed `RateLimiter`)
- `RUSTSEC-2026-0009` (`time <0.3.47`) accepted and documented in `.cargo/audit.toml` — the fix requires Rust ≥1.88, above this crate's 1.85 MSRV floor; `time` is transitive-only (dioxus-fullstack → reqwest → cookie_store)

## [0.0.1] - 2026-09-01

> **Historical relabel (2026-09-18):** this content shipped to crates.io as
> **`0.0.1`** — the only version ever published there. It was previously
> mislabeled `[0.1.0]` here; the GitHub `v0.1.0` tag of the same era was a
> phantom (no crates.io release ever accompanied it) and has been deleted.
> Semver counts published versions, so the next release is the real `0.1.0`.

### Added

- Core authentication engine (`AuthEngine`) with login, validate, logout, and revoke-all
- `UserStore`, `PasswordUserStore`, and `SessionStore` traits for pluggable storage
- `MemoryStore` — in-memory implementation for testing and prototyping
- Argon2id password hashing with OWASP-recommended defaults
- Constant-time dummy verification on unknown-user login to prevent timing attacks
- Session tokens hashed at rest with SHA-256 (`sha256(raw)` in store, raw on wire)
- `session_auth_hash` automatic revocation on password change
- `AuthProvider`, `use_auth()`, `use_auth_restore()` for Dioxus reactive auth state
- `AuthStatus` 3-state model: `Loading`, `Authenticated`, `Unauthenticated`
- `RouteGate`, `RequireAuth`, `RedirectIfAuthed` for declarative route protection
- `SignedIn` and `SignedOut` convenience components
- `ServerAuthContext` for `#[server]` functions — reads cookies, emits `Set-Cookie`
- Dual transport extraction: `Authorization: Bearer` first, then `Cookie`
- `TokenStorage` trait with `MemoryTokenStorage`, `FileTokenStorage` (0600), and `WebTokenStorage` (localStorage)
- `__Host-` cookie prefix support with enforced constraints (no Domain, Secure, Path=/)
- CSRF/Origin validation for cookie-based authentication
- Sliding TTL — session expiry extends on validation within configured window
- Token rotation — re-login invalidates existing sessions
- Prelude module for ergonomic imports
- `thiserror`-based error handling with `Csrf` variant

### Changed

- `CookieConfig::build_set_cookie_header` and `build_delete_cookie_header` support `host_only` mode
- `ServerAuthContext::current_user` and `require_user` accept optional `Origin` header for CSRF checks

### Security

- All pre-commit checks pass: fmt, clippy (`-D warnings`), 43 tests
- Concurrency stress test: 1000 tasks across 100 sessions, no corruption
- Dummy Argon2 verification proves real constant-time defense (≥5ms, miss/hit within 10x)
