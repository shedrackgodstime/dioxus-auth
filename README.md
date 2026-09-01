# dioxus-auth

[![Crates.io](https://img.shields.io/crates/v/dioxus-auth.svg)](https://crates.io/crates/dioxus-auth)
[![Documentation](https://docs.rs/dioxus-auth/badge.svg)](https://docs.rs/dioxus-auth)
[![License](https://img.shields.io/crates/l/dioxus-auth.svg)](#license)

`dioxus-auth` is a planned Dioxus-native authentication and session-management crate for fullstack Dioxus applications.

The project is at the start stage. The current code defines the first core types only; Dioxus hooks, Axum integration, server functions, and examples are the next implementation milestones.

## Goals

- Feel native inside Dioxus apps.
- Keep the server as the source of truth.
- Use opaque, server-side sessions by default.
- Expose explicit auth state with `Loading`, `Authenticated`, and `Unauthenticated`.
- Stay storage-agnostic.
- Integrate cleanly with Dioxus fullstack and Axum.

## Non-Goals For The First Release

- OAuth
- passkeys
- MFA
- RBAC/permissions
- password reset
- email verification
- JWT/bearer auth
- production database adapters
- hosted-provider integrations

## Current Status

Started.

Implemented:

- `AuthStatus`
- `AuthUser`
- `Session`
- `SessionId`
- `AuthError`

Next:

1. Design `UserStore` and `SessionStore`.
2. Implement an in-memory store.
3. Add Dioxus feature flags.
4. Prototype `AuthProvider` and `use_auth()`.
5. Build a minimal fullstack example.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT license
