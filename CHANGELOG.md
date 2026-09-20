# Changelog

All notable changes to `dioxus-auth` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/).


## [0.1.0](https://github.com/shedrackgodstime/dioxus-auth/releases/tag/v0.1.0) - [Unreleased]

First functional release.

`dioxus-auth` offers authentication features for Dioxus applications, including
server-side sessions, browser and native authentication flows, route protection,
and configurable security settings.

### Added

- Authentication engine with login, session validation, logout, and revocation.
- Pluggable user and session storage.
- Argon2id password hashing.
- Hashed session tokens with automatic invalidation on password changes.
- Reactive Dioxus authentication state and restoration.
- Declarative route protection with `RouteGate`, `RequireAuth`, and `RedirectIfAuthed`.
- Cookie and bearer-token authentication.
- Secure cookie configuration, including `__Host-` cookies.
- CSRF/Origin protection for cookie-based state-changing operations.
- Session idle timeout, absolute lifetime, token rotation, and single-active-session support.
- Configurable rate limiting.
- Axum middleware and Dioxus Fullstack server helpers.
- Cross-tab authentication synchronization.
- Return-to navigation after authentication redirects.
- Memory, file, and browser token storage.
- SQLite storage examples and store conformance tests.
- Security review and secure-configuration documentation.

### Security

- Authentication credentials are redacted from `Debug` output.
- Wire tokens are validated before hashing or storage lookup.
- Invalid credentials are indistinguishable between unknown users and incorrect passwords.
- Transient restore failures no longer incorrectly sign users out.
- Authentication errors preserve HTTP status semantics for clients.
- Cookie logout consistently enforces Origin validation.
- Published packages are guarded against accidental inclusion of private files.

### Documentation

- Reworked the quickstart around a hash-free client `UserView` and server-side user record.
- Documented authentication boundaries, token-storage choices, CSRF requirements, and bearer-token/XSS trade-offs.
- Added architecture, specification, and security-review documentation.
- Corrected security documentation around password verification timing and session handling.
