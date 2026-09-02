# dioxus-auth

[![Crates.io](https://img.shields.io/crates/v/dioxus-auth.svg)](https://crates.io/crates/dioxus-auth)
[![Documentation](https://docs.rs/dioxus-auth/badge.svg)](https://docs.rs/dioxus-auth)
[![License](https://img.shields.io/crates/l/dioxus-auth.svg)](#license)
[![CI](https://github.com/shedrackgodstime/dioxus-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/shedrackgodstime/dioxus-auth/actions)

`dioxus-auth` is a Dioxus-native authentication and session-management library for fullstack Dioxus applications.

It provides a clean, reactive frontend API (`AuthProvider`, `use_auth()`, `RouteGate`, `SignedIn`, `SignedOut`) coupled with a secure, server-authoritative backend engine (`AuthEngine`, `ServerAuthContext`) while keeping storage **100% pluggable and database-agnostic**.

---

## Key Features

- **🌐 Dioxus-Native & SSR-Safe**: Hydration-safe 3-state lifecycle (`Loading`, `Authenticated`, `Unauthenticated`) prevents premature redirects and visual layout flashes during SSR.
- **🛡️ Storage-Agnostic Capability Model**: Zero database dependencies in the core crate. Connect any database (SQLite, Turso / libSQL, PostgreSQL, MongoDB, or REST APIs) by implementing [`UserStore`] and [`SessionStore`].
- **🔒 Enterprise-Grade Security Defaults**:
  - OWASP-recommended **Argon2id** password hashing.
  - **Constant-time dummy verification** against side-channel timing attacks and account enumeration.
  - **256-bit CSPRNG** opaque session identifiers.
  - **Automatic password-rotation revocation** via `session_auth_hash` verification.
  - Hardened cookie defaults: `HttpOnly`, `SameSite=Lax`, and `Secure`.
- **🚦 Declarative Route Protection**: Layout-level route gating with [`RouteGate`], [`RequireAuth`], and [`RedirectIfAuthed`].
- **⚡ Ergonomic UI Components**: Expressive conditional rendering with [`SignedIn`] and [`SignedOut`].
- **🚀 Server Function Integration**: [`ServerAuthContext`] simplifies reading session cookies and attaching `Set-Cookie` headers inside `#[server]` functions.

---

## Architecture: The 3-Layer Capability Model

> **The developer owns domain models and database infrastructure. `dioxus-auth` owns the authentication processes and Dioxus reactive state.**

```text
┌─────────────────────────────────────────────────────────────┐
│ 1. Dioxus Runtime Layer (Client & SSR Ergonomics)           │
│    - AuthProvider & use_auth()                              │
│    - Signal<AuthStatus<User>> (Hydration-Safe 3-State Model)│
│    - RouteGate, RequireAuth, RedirectIfAuthed               │
│    - SignedIn & SignedOut Convenience Components            │
│    - ServerAuthContext for #[server] functions              │
├─────────────────────────────────────────────────────────────┤
│ 2. Auth Flow Orchestrator (Core Business Logic)             │
│    - AuthEngine (login, validate_session, logout)           │
│    - Timing Attack Defense (constant-time dummy checks)     │
│    - Session Lifecycle (create, expire, revoke, rotate)     │
│    - Password Hashing (Argon2id default)                    │
├─────────────────────────────────────────────────────────────┤
│ 3. Capability Storage Layer (Pluggable Application Traits)  │
│    - UserStore<User> & PasswordUserStore                    │
│    - SessionStore<UserId>                                   │
│    - MemoryStore (built-in testing & prototyping store)     │
└─────────────────────────────────────────────────────────────┘
```

---

## Installation

Add `dioxus-auth` to your `Cargo.toml`:

```toml
[dependencies]
dioxus-auth = "0.1"
```

---

## Quickstart

### 1. Define Your User Model

```rust
use dioxus_auth::AuthUser;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub id: u64,
    pub email: String,
    pub password_hash: String,
}

impl AuthUser for User {
    type Id = u64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> Option<&str> {
        Some(&self.password_hash)
    }
}
```

### 2. Initialize the Server Engine

```rust
use std::sync::Arc;
use std::time::Duration;
use dioxus_auth::{AuthEngine, MemoryStore};

// Use an in-memory store for testing, or your custom SQLite/Turso store
let store = Arc::new(MemoryStore::<User>::new());

let engine = AuthEngine::builder(store.clone(), store.clone())
    .session_ttl(Duration::from_secs(60 * 60 * 24 * 7)) // 7 days
    .build();
```

### 3. Mount `AuthProvider` in Your Dioxus App

```rust
use dioxus::prelude::*;
use dioxus_auth::{AuthProvider, AuthStatus};

fn App() -> Element {
    rsx! {
        AuthProvider::<User> {
            initial_status: AuthStatus::Loading,
            Router::<Route> {}
        }
    }
}
```

### 4. Protect Routes with `RouteGate`

```rust
use dioxus::prelude::*;
use dioxus_auth::{use_auth, require_auth, RouteGate};

#[component]
fn ProtectedLayout() -> Element {
    let auth = use_auth::<User>();
    let outcome = require_auth(&auth.status(), Route::Login {});

    rsx! {
        RouteGate {
            outcome: outcome,
            fallback: rsx! { div { "Verifying session..." } },
        }
    }
}
```

### 5. Use Auth in Components

```rust
use dioxus::prelude::*;
use dioxus_auth::{use_auth, SignedIn, SignedOut};

#[component]
fn Navbar() -> Element {
    let mut auth = use_auth::<User>();

    rsx! {
        nav {
            SignedIn::<User> {
                span { "Welcome, {auth.user().unwrap().email}!" }
                button { onclick: move |_| auth.logout(), "Log Out" }
            }
            SignedOut::<User> {
                Link { to: Route::Login {}, "Log In" }
            }
        }
    }
}
```

---

## Examples

Runnable examples are located in [`examples/`](./examples):

- **[`examples/basic_auth.rs`](./examples/basic_auth.rs)**: In-memory Dioxus VirtualDom application demonstrating routes, login, logout, and route guarding.
- **[`examples/sqlite_adapter.rs`](./examples/sqlite_adapter.rs)**: Complete real-world SQLite / Turso storage adapter integrating `rusqlite`, `AuthEngine`, Argon2id, and `AuthProvider`.

Run an example:

```bash
cargo run --example sqlite_adapter
```

---

## Testing

Run the full automated test suite:

```bash
cargo test --all-targets
```

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE))
- MIT license ([LICENSE-MIT](./LICENSE-MIT))
