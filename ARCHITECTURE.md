# dioxus-auth — Architecture

## Core Thesis

> **`dioxus-auth` orchestrates secure authentication workflows and provides Dioxus-native ergonomics. The application provides domain models and storage capabilities via traits.**

The crate is a single publishable crate. Internal organization separates concerns by module, not by crate.

---

## Three Layers

```
┌─────────────────────────────────────────────────────┐
│ 1. DIOXUS RUNTIME LAYER (client & SSR ergonomics) │
│    AuthProvider, use_auth(), Signal<AuthStatus<U>> │
│    RouteGate, RequireAuth, RedirectIfAuthed        │
│    Server function context extraction               │
├─────────────────────────────────────────────────────┤
│ 2. AUTH ENGINE (core business logic)              │
│    Login / Logout / Validate                       │
│    Session lifecycle                               │
│    Argon2id password hashing                       │
│    Timing-attack mitigation                        │
├─────────────────────────────────────────────────────┤
│ 3. CAPABILITY LAYER (pluggable application traits) │
│    UserStore, SessionStore, PasswordHasher         │
│    TokenStorage (Cookie / Bearer)                  │
│    MemoryStore (default)                           │
└─────────────────────────────────────────────────────┘
```

Each layer has a clear boundary. The core engine (Layer 2) has **zero Dioxus dependency**. The Dioxus runtime (Layer 1) depends on the engine. The capability traits (Layer 3) are implemented by the application.

---

## Module Layout

```
src/
├── lib.rs                      # <50 lines: attributes + re-exports
├── error.rs                    # AuthError, AuthResult
├── user.rs                     # AuthUser trait
├── status.rs                   # AuthStatus, SessionId, SessionRecord
├── session.rs                  # Session, SessionStore traits
├── engine.rs                   # AuthEngine struct
├── builder.rs                  # AuthEngineBuilder (Clone)
├── login.rs                    # login() method
├── logout.rs                   # logout() method
├── validate.rs                 # validate_session() method
├── hooks.rs                    # fire_hook(), callbacks
├── security.rs                 # CookieConfig, SameSite, PasswordHasher trait
├── hash.rs                     # Argon2Hasher implementation
├── rate_limit.rs               # InMemoryRateLimiter (RwLock)
├── store/                      # capability traits + memory impl
│   ├── mod.rs
│   ├── user.rs                 # UserStore, PasswordUserStore
│   ├── session.rs              # SessionStore
│   └── memory.rs               # MemoryStore
├── transport.rs                # TokenStorage trait + implementations
├── cookie.rs                   # Cookie building, validation
├── token.rs                    # FileTokenStorage, WebTokenStorage, MemoryTokenStorage
└── dioxus/                     # feature-gated
    ├── mod.rs                  # client/server dispatcher
    ├── client/                 # any Dioxus target (no dioxus-fullstack needed)
    │   ├── mod.rs
    │   ├── context.rs          # Auth struct
    │   ├── provider.rs         # AuthProvider, TokenStorageRef
    │   ├── guards.rs           # RouteGate, RequireAuth, RedirectIfAuthed
    │   ├── return_to.rs        # capture_return_to, consume_return_to
    │   ├── sync.rs             # CrossTabSync, AuthBroadcaster
    │   ├── helpers.rs          # persist_token, clear_persisted_token
    │   ├── components/
    │   │   ├── mod.rs
    │   │   ├── route_gate.rs
    │   │   └── signed_in_out.rs
    │   └── hooks/
    │       ├── mod.rs
    │       ├── use_auth.rs
    │       ├── use_auth_restore.rs
    │       └── use_token_storage.rs
    └── server/                 # requires dioxus-fullstack
        ├── mod.rs
        ├── server_fn.rs        # ServerAuthContext (≤200 lines)
        ├── fullstack.rs        # fullstack_server_fns! macro
        ├── registry.rs         # server_init, current_user, require_user (≤200 lines)
        └── axum.rs             # auth_middleware, require_auth_middleware
```

### Key structural decisions

- **`dioxus/mod.rs`** dispatches to `client/` and `server/`. The boundary is explicit at the module level, not hidden in `#[cfg]` attributes on individual files.
- **`client/`** works with any Dioxus target (no `dioxus-fullstack` needed).
- **`server/`** requires `dioxus-fullstack` and is gated at the module boundary.
- **`engine.rs`** contains `AuthEngine` struct and all methods. Each method's implementation is extracted into `login.rs`, `logout.rs`, `validate.rs`, `hooks.rs`. The engine file itself stays ≤200 lines by re-exporting the split logic.
- **`store/`** contains all capability traits and the default `MemoryStore` implementation.
- **`transport.rs`** contains the `TokenStorage` trait and all three implementations (`MemoryTokenStorage`, `FileTokenStorage`, `WebTokenStorage`).

---

## Feature Model

```toml
[features]
default = []
dioxus = ["dep:dioxus"]
dioxus-fullstack = ["dioxus", "dioxus/fullstack", "dep:http"]
axum = ["dep:axum", "dep:tower", "dep:http"]
```

- No default features — users explicitly opt in.
- `dioxus-auth` alone provides the core engine, no Dioxus dependency.
- `dioxus` feature adds the client-side runtime.
- `dioxus-fullstack` adds server functions and Axum middleware.
- `axum` adds middleware only.

---

## Public API Surface

Only what's in `prelude` is intended for public use:

```rust
pub mod prelude {
    #[doc(inline)] pub use crate::error::{AuthError, AuthResult};
    #[doc(inline)] pub use crate::security::{Argon2Hasher, CookieConfig, PasswordHasher, SameSite};
    #[doc(inline)] pub use crate::status::{AuthStatus, SessionId};
    #[doc(inline)] pub use crate::store::{MemoryStore, PasswordUserStore, SessionStore, UserStore};
    #[doc(inline)] pub use crate::transport::{MemoryTokenStorage, TokenStorage, extract_session_token};
    #[doc(inline)] pub use crate::user::AuthUser;
    #[cfg(feature = "dioxus")] #[doc(inline)] pub use crate::dioxus::*;
}
```

All other items are `pub(crate)` or private. There is a single import path — `crate::prelude::*`. No duplicate re-exports at `crate::*`.

---

## Test Organization

All tests live in `tests/`. No `#[cfg(test)]` modules in source files.

```
tests/
├── auth_lifecycle_integration.rs
├── concurrency_stress.rs
├── sqlite_integration.rs
├── transport_extract.rs
├── conformance/
│   ├── user_store.rs
│   ├── session_store.rs
│   └── password_store.rs
├── core_engine.rs
├── dioxus_runtime.rs           # requires dioxus feature
└── fullstack_tests.rs          # requires dioxus-fullstack feature
```

---

## Enforcement

| Mechanism | Config |
|-----------|--------|
| `unsafe_code` | `#![forbid(unsafe_code)]` |
| Missing docs | `#![warn(missing_docs)]` |
| Formatting | `rustfmt.toml` at root, `cargo fmt --check` in CI |
| Clippy | `clippy.toml` at root, `--pedantic` in CI |
| Audit | `cargo audit`, `cargo deny` in CI |
| Packaging | `scripts/check-packaging.sh` |
| Coverage | Minimum threshold in CI |

---

## Dependency Boundaries

```
application code
    │
    ├── depends on → dioxus-auth (prelude)
    │                     │
    │                     ├── core engine (no Dioxus dep)
    │                     │     ├── AuthEngine
    │                     │     ├── Argon2Hasher
    │                     │     ├── CookieConfig
    │                     │     ├── UserStore, SessionStore traits
    │                     │     └── MemoryStore
    │                     │
    │                     ├── dioxus runtime (requires dioxus feature)
    │                     │     ├── AuthProvider, use_auth()
    │                     │     ├── RouteGate, RequireAuth
    │                     │     └── hooks, components
    │                     │
    │                     └── fullstack (requires dioxus-fullstack feature)
    │                           ├── ServerAuthContext
    │                           ├── fullstack_server_fns! macro
    │                           └── Axum middleware
    │
    └── implements → UserStore, SessionStore, PasswordHasher
```

The application owns the domain data, user schema, and persistence infrastructure. `dioxus-auth` owns the authentication workflows and Dioxus reactive state.

---

## Design Principles (Non-Negotiable)

1. **Server is the security authority** — Client state is for rendering only. Every server function re-validates the session.
2. **Reactive by default** — `Signal<AuthStatus<User>>` drives the entire UI.
3. **Opaque, server-side sessions by default** — Random session tokens, hashed at rest. Bearer tokens for native platforms.
4. **Storage- and transport-agnostic** — Traits for everything. Web uses HttpOnly cookies; native uses secure storage.
5. **Dioxus-native ergonomics** — `AuthProvider`, `use_auth()`, `RouteGate`, `require_auth`.
6. **Security over convenience** — Argon2id, timing-attack mitigation, strict cookie flags, CSRF, rate-limiting hooks.
7. **No unsafe code** — `#![forbid(unsafe_code)]`.
8. **Strict panic model** — Panics stop the program. No silent continuation.
9. **Strict error handling** — No `let _ =`. All errors propagated or logged.
10. **Single import path** — `use dioxus_auth::prelude::*` and you have everything.

---

## What's Explicitly Deferred (v0.2+)

- OAuth / OIDC providers
- Passkeys / WebAuthn
- TOTP Multi-factor authentication
- Email verification & password reset token flows
- `EmailSender` capability trait
- Role-based authorization
- Standalone database adapter crates (`dioxus-auth-turso`, `dioxus-auth-sqlx`)
- `#[derive(AuthUser)]` proc macro

---

## Compliance Notes

This architecture is designed to comply with:

- **M-SINGLE-ITEM-PATH** — Single import path via `prelude`
- **M-PANIC-CONTINUATION** — No silent panic swallowing
- **M-PANIC-IS-STOP** — Consistent panic behavior
- **M-CANONICAL-DOCS** — All `# Errors`, `# Panics`, `# Examples` sections
- **M-DOC-INLINE** — `#[doc(inline)]` on all `pub use`
- **M-UNSAFE** — `#![forbid(unsafe_code)]`
- **M-EXAMPLE-OVER-PROC** — `fullstack_server_fns!` is `macro_rules!`
- **M-FIRST-DOC-SENTENCE** — All doc comments have ≤15-word first sentences
- **M-MODULE-DOCS** — Comprehensive module-level documentation
- **M-NO-META-DESIGN** — No meta narratives in user-facing docs

Based on 38 research documents (01–39) and the Microsoft Pragmatic Rust Guidelines audit.
