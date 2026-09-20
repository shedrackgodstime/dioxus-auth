# dioxus-auth

Authentication and session management for Dioxus.

Secure, reactive authentication for Dioxus fullstack applications.

You own the database, users, and data. **dioxus-auth** provides the authentication and session layer around them.

## Features

- Reactive auth state
- Session management
- Password & social authentication
- Route protection
- Server-side authorization
- Custom user and session stores
- Secure defaults

## Usage

```toml
dioxus-auth = "0.x"
```

### Core engine

`AppUser` implements `AuthUser` (with `Id = u64`). Point the engine at any
pair of stores that implement the capability traits; `MemoryStore` is the
default in-process store:

```rust
use dioxus_auth::prelude::*;
use std::sync::Arc;

let store = Arc::new(MemoryStore::<AppUser>::new());

let engine = AuthEngine::builder(Arc::clone(&store), Arc::clone(&store))
    .session_ttl_secs(7 * 24 * 60 * 60) // absolute session lifetime
    .idle_timeout_secs(30 * 60)         // slide expiry on activity
    .single_active_session(true)        // rotate previous sessions on login
    .build()?;
```

### Register a user

```rust
let hash = Argon2Hasher::new().hash("s3cret")?;
store.insert_user_with_password(AppUser::new(1, "alice"), "alice", hash);
```

### Sign in and validate on every request

```rust
let (user, session) = engine.login("alice", "s3cret")?;
assert_eq!(user.id(), 1);

// Pass the raw session token with each request and validate it:
if let Some(user) = engine.validate_session(session.id())? {
    // authorize this request for `user`
}
```

Pass `LoginOptions` to record client metadata on the session:

```rust
let (user, session) = engine.login_with_options(
    "alice",
    "s3cret",
    LoginOptions::default()
        .with_ip_address(Some("203.0.113.7"))
        .with_user_agent(Some("dioxus/0.x")),
)?;
```

### Sign out

```rust
engine.logout(session.id())?;              // invalidate the session
engine.revoke_session(session.id())?;      // Ok(false) if it was already gone
```

### The Dioxus runtime binds the same engine to the UI:

```rust
let auth = use_auth::<AppUser>();

auth.login(...).await?;
auth.logout().await?;
```

Protect routes and server operations with the same auth state.

```rust
require_auth();

let user = require_user().await?;
```

## Design

**dioxus-auth** manages authentication and sessions.

Your application owns the data.

```text
Your Database
     │
     ▼
  dioxus-auth
     │
     ├── Authentication
     ├── Sessions
     └── Authorization
            │
            ▼
       Dioxus App
```

## Status

Early development. API may change before "1.0".

## License

MIT