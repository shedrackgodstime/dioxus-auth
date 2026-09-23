# Changelog

All notable changes to `dioxus-auth` are recorded here. Nothing is published
yet; pre-1.0 entries may describe breaking changes without deprecation.

## [0.1.0] (unreleased, v2 branch)

Gate 1 (M1 vertical) on the 1e surface:

- `Auth` facade: `new(store)` by value, zero-modeling `memory()` over
  `DefaultUser`, `from_engine` escape.
- Email+password verbs (`sign_up_email`, `sign_in_email`, `sign_out`,
  `change_password`) with no-enumeration errors and stable `ErrorCode`s.
- Sessions: opaque 256-bit tokens stored as `sha256`, 7-day TTL, idle timeout,
  single-active enforcement, scoped sign-out, lazy expiry.
- Dioxus runtime: single-prop `AuthProvider`, `use_session` →
  `SessionState`, `use_auth`, `on_auth_state_change`, `RequireAuth` /
  `RedirectIfAuthed` guards, network-aware restore verdicts.
- Fullstack: generated cookie server fns, `require_user` / `current_user`,
  `AuthLayer` / `RequireAuthLayer`, `__Host-` + origin enforcement, blocking
  boundary for sync engine calls.
- Hardening: opt-in sliding-window rate limiting (`InMemoryRateLimiter::prod`
  preset), Argon2id with timing-defense dummy verification.
- Crate-root imports (no `prelude`); door-3 modules (`engine`, `builder`,
  `store`, `security`, …) stay importable.
- SQLite reference store + guide (`examples/sqlite-reference`).
