# Changelog

All notable changes to `dioxus-auth` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-06

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

## [0.1.0] - 2026-09-04

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
