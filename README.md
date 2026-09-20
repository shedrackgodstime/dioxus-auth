# dioxus-auth

Authentication and session management for Dioxus.

Secure password authentication and session management for Dioxus applications.

You own the database, users, and data. **dioxus-auth** provides the authentication and session layer around them.

## Features

- Session management
- Password authentication (Argon2id, timing-attack mitigated)
- Custom user and session stores
- Secure defaults

## Usage

Add "dioxus-auth" to your Dioxus application:

```bash
cargo add dioxus-auth
```

1. Enable authentication

Configure "dioxus-auth" with your application's user and session stores. Password authentication is built in — no extra toggle needed:

```rust
use dioxus_auth::prelude::*;
use std::sync::Arc;

let store = Arc::new(MemoryStore::<AppUser>::new());

let auth = AuthEngine::builder(Arc::clone(&store), Arc::clone(&store))
    .idle_timeout_secs(30 * 60)
    .build()?;
```

Your application owns the database and decides how users and sessions are stored.

2. Register and log in

Create a user with a password:

```rust
let hash = Argon2Hasher::new().hash("s3cret")?;
store.insert_user_with_password(AppUser::new(1, "alice"), "alice", hash);
```

Then log in -- the session is created automatically and returned with the user:

```rust
let (user, session) = auth.login("alice", "s3cret")?;
```

3. Log out

```rust
auth.logout(session.id())?;
```

4. Use authentication in your app

Reactive authentication state (`use_auth`, `AuthStatus`) ships with the Dioxus runtime layer, which is the next milestone and not available yet.

5. Protect routes

Route protection (`require_auth`, `RouteGate`) ships with the Dioxus runtime layer, which is the next milestone and not available yet.

6. Protect server operations

Server-side checks (`require_user`) ship with the Dioxus runtime layer, which is the next milestone and not available yet.

7. Custom database

"dioxus-auth" does not own your database.

Bring your own user and session stores:

```rust
let user_store = Arc::new(MyUserStore::new(db.clone()));
let session_store = Arc::new(MySessionStore::new(db));

let auth = AuthEngine::builder(user_store, session_store).build()?;
```

Your existing database remains the source of truth for your application's users and data.

Other authentication methods

Password authentication is the supported method today. Social authentication is planned but not implemented yet.

## Status

Early development. API may change before "1.0".

## License

MIT OR Apache-2.0