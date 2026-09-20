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

```rust
use dioxus_auth::prelude::*;
use std::sync::Arc;

let store = Arc::new(MemoryStore::<AppUser>::new());

let auth = AuthEngine::builder(Arc::clone(&store), Arc::clone(&store))
    .idle_timeout_secs(30 * 60) // little config: idle sessions expire
    .single_active_session(true)
    .build()?;

// Password auth — register a user, then sign in.
let hash = Argon2Hasher::new().hash("s3cret")?;
store.insert_user_with_password(AppUser::new(1, "alice"), "alice", hash);

let (user, session) = auth.login("alice", "s3cret")?;
auth.validate_session(session.id())?;
auth.logout(session.id())?;
```

Then:

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