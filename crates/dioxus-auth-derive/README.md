# dioxus-auth-derive

Derive macro for [`dioxus_auth::AuthUser`](https://docs.rs/dioxus-auth).

```rust
use dioxus_auth_derive::AuthUser;

#[derive(AuthUser)]
#[auth_user(id = "id", session_auth_hash = "password_hash")]
struct User {
    id: String,
    password_hash: String,
}
```

- `id` (required) — field used as the stable unique identifier.
- `session_auth_hash` (optional) — field whose value binds sessions to a known
  credential state; sessions die automatically when it changes. Omit to return
  `None` and enforce credential binding in your store instead.

Part of the [`dioxus-auth`](https://github.com/shedrackgodstime/dioxus-auth) workspace.
