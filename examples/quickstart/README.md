# Quickstart app: Dioxus client on `dioxus-auth`

The minimal login form plus guarded route, using only `DefaultUser` and the
built-in memory store. `cargo run -p quickstart` exercises the auth flow
headlessly; `cargo test -p quickstart` renders the whole tree with
`dioxus-ssr` (guest form, both redirect directions, restored dashboard).

## Honest DX notes (measured building this)

- `dioxus-router` has no `prelude` module: `use dioxus_router::{Routable,
  Router}` sits beside `use dioxus::prelude::*`. Two import styles to learn.
- Guards need an explicit `::<User>` turbofish (generics cannot be inferred
  from context). The provider does not: `AuthProvider { auth }` infers.
- Signup reads the `Auth` facade from a provided context because the erased
  runtime context cannot name store-specific signup input. Session verbs
  (`login`, `logout`) live on `use_auth()`; one-time verbs live on the
  provided facade. Two handles, each doing one job.
