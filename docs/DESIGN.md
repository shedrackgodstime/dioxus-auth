# dioxus-auth — Design

## Goal

`dioxus-auth` is an authentication and session-management library designed specifically for Dioxus applications.

It should feel like a natural extension of Dioxus rather than a generic authentication library adapted to Dioxus.

## Design Principles

* **Dioxus-native** — use Dioxus concepts such as hooks, context, reactive state, components, and server functions.
* **Secure by default** — sensible cookie, session, and authentication defaults.
* **Simple API** — hide unnecessary HTTP, cookie, and session plumbing.
* **Composable** — integrate with existing Dioxus and Axum applications without imposing a database or architecture.
* **Server-authoritative** — client authentication state is for UI; security decisions happen on the server.
* **Rust-native** — use traits, strong types, `Result`, and explicit errors rather than magic.

## Core Concepts

```text
Auth
 ├── User
 ├── Session
 ├── AuthState
 ├── UserStore
 └── SessionStore
```

### Client

```rust
let auth = use_auth();

auth.status();
auth.user();
auth.login(...);
auth.logout();
```

### Server

```rust
let auth = Auth::current().await?;

let user = auth.require_user().await?;
```

## Session Model

The default web authentication model is:

```text
Browser
   ↓
HttpOnly session cookie
   ↓
Opaque session ID
   ↓
Server-side SessionStore
   ↓
User
```

The server remains the source of truth.

## Storage

The core crate should not require a specific database.

Storage should be abstracted through traits:

```rust
trait UserStore { ... }

trait SessionStore { ... }
```

Database and external-service integrations can be added separately.

## Initial Scope

### `0.1`

* Authentication state
* User identity
* Server-side sessions
* Login/logout
* Current user
* Session expiration/revocation
* Secure cookies
* Dioxus hooks/context
* Dioxus/Axum integration
* Pluggable user/session storage

### Out of Scope for `0.1`

* OAuth
* Passkeys
* MFA
* RBAC/permissions
* Password reset
* Email verification
* JWT/bearer authentication
* Database-specific implementations

These can be added later without compromising the core design.

## North Star

The ideal Dioxus application should be able to use authentication with minimal ceremony:

```rust
fn App() -> Element {
    rsx! {
        AuthProvider {
            Router::<Route> {}
        }
    }
}
```

And access authentication naturally:

```rust
let auth = use_auth();
```

The complexity of authentication should remain inside the library while the developer interacts with a small, predictable, Dioxus-native API.
