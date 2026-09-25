# Fullstack demo app on `dioxus-auth`

One config constructor, one axum router, generated cookie server functions.
`cargo test -p fullstack-app` drives login → cookie → guarded probe →
logout over real HTTP semantics through `tower`, without binding a port.

## Honest DX notes (measured building this)

- The generated server fns key their server half off a `server` cargo
  feature in the *downstream* crate. Without it, calls compile to HTTP
  client stubs that fail against a fake URL. This app enables it by
  default; shared crates should follow the split-feature convention
  instead (declare it, let dependents opt in).
- `RequireAuthLayer` alone both attaches the config and enforces it;
  `AuthLayer` is the lenient variant for mixed routes. One layer per
  route group, no ordering puzzles.
- Server-function tests need a `FullstackContext` scope per call. It is
  three lines of setup, but it is three lines the docs should show once
  (this crate is that showing).
