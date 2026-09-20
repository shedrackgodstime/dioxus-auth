# dioxus-auth

Authentication and session management for [Dioxus](https://dioxuslabs.com).

Secure password authentication and session management for [Dioxus](https://dioxuslabs.com) applications.

You own the database, users, and data. **dioxus-auth** provides the authentication and session layer around them.

## Features

- Session management
- Password authentication (Argon2id, timing-attack mitigated)
- Custom user and session stores
- Secure defaults

## Usage

Add `dioxus-auth`:

```bash
cargo add dioxus-auth
```

### Setup

Enable authentication and connect your stores:

```rust
let auth = AuthEngine::builder(user_store, session_store)
    .password_auth(true)
    .build()?;
```

### Password authentication

```rust
auth.register("alice", "password")?;

let user = auth.login("alice", "password").await?;
```

### Logout

```rust
auth.logout().await?;
```

### Current user

```rust
let auth = use_auth::<AppUser>();

let user = auth.user();
```

### Protected routes

```rust
require_auth();
```

### Server authorization

```rust
let user = require_user().await?;
```

### Custom stores

```rust
let auth = AuthEngine::builder(user_store, session_store)
    .build()?;
```

Your application owns the database, users, and data.

For advanced configuration, custom stores, sessions, and authentication providers, see the [API documentation](https://docs.rs/dioxus-auth) (docs.rs), or check out the full [guides](./docs/README.md).

## Status

Early development. Expect breaking changes.

## License

MIT OR Apache-2.0
