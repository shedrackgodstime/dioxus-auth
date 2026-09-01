# dioxus-auth

[![Crates.io](https://img.shields.io/crates/v/dioxus-auth.svg)](https://crates.io/crates/dioxus-auth)
[![Documentation](https://docs.rs/dioxus-auth/badge.svg)](https://docs.rs/dioxus-auth)
[![License](https://img.shields.io/crates/l/dioxus-auth.svg)](#license)

`dioxus-auth` is a Dioxus-native authentication and session-management crate for fullstack Dioxus applications.

The library orchestrates the authentication lifecycle while keeping storage completely pluggable and database-agnostic.

## Goals

- Feel native inside Dioxus apps.
- Keep the server as the source of truth.
- Use opaque, server-side sessions by default.
- Expose explicit, hydration-safe auth state with `Loading`, `Authenticated`, and `Unauthenticated`.
- Stay storage-agnostic via capability traits (`UserStore`, `SessionStore`).
- Integrate cleanly with Dioxus fullstack and Axum.

## Non-Goals For The First Release

- OAuth / OIDC
- Passkeys / WebAuthn
- Multi-factor authentication (MFA)
- Complex RBAC / permissions
- Password reset token flows
- Email verification flows
- Production database adapters (SQLx, Diesel, etc.)

## Current Status

Core types, storage traits, in-memory store, and Dioxus runtime hooks are implemented.

Implemented:

- `AuthStatus` (3-state hydration-safe enum)
- `AuthUser` trait
- `Session` & `SessionId`
- `AuthError` & `AuthResult`
- `UserStore` & `SessionStore` storage traits
- `MemoryStore` (thread-safe, zero-dependency in-memory store for testing & prototyping)
- `AuthProvider` component & `use_auth()` hook (feature-gated behind `dioxus`)

Next:

1. Add route protection guard components (`RouteGate`, `RequireAuth`).
2. Implement Axum/Dioxus Fullstack server function session helpers.
3. Build a minimal fullstack runnable example.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT license
