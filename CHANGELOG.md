# Changelog

All notable changes to `dioxus-auth` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
