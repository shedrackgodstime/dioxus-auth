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

let auth = AuthEngine::builder(user_store, session_store).build()?;
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