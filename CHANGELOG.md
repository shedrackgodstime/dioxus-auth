# Changelog

All notable changes to `dioxus-auth` are recorded here. Nothing is published
yet; pre-1.0 entries may describe breaking changes without deprecation.

## [0.1.0] (unreleased, v2 branch)

Breaking (pre-1.0, AuthUser boundary decision): removed `AuthUser::email()`.
The trait is the session-owner contract (`id()` plus optional
`session_auth_hash()`); login identifiers travel as verb arguments and app
fields stay plain struct data. Every `AuthUser` impl drops one method; no
engine behavior changes.

Breaking (pre-1.0, store-owned creation decision): `provision_user_with_password`
takes `Self::NewUser` creation input and returns `Result<Option<Self::User>>`
(`None` when the identifier or id row is taken) instead of taking a finished
user and returning `bool`. `Auth::sign_up_email` takes the store's `NewUser`
and returns the persisted user with the session. `MemoryStore` and the SQLite
reference alias `NewUser` to their user type (passthrough); stores that
generate identity declare their own input shape.

Breaking (pre-1.0, create-vs-attach decision): split credential attachment
into its own capability. `PasswordUserStore::attach_password_credential`
adds a login to an existing user id (`false` when the identifier is taken,
`InvalidCredentials` for unknown ids); `Auth::attach_email_credential` is
the facade verb with the same enumeration defense as signup. Privileged by
design: callers must authorize (session for the user, or admin) before
binding a new login to an account.

Breaking (pre-1.0, ID-free quickstart): `Auth::memory()` now runs over the
new `DefaultStore`, which generates `u64` user ids from an atomic counter.
Signup on the memory path takes `DefaultUserInput::new(name)` instead of a
finished `DefaultUser`; the store derives the email from the signup
identifier and returns the persisted row. Beginners never construct an id.
`MemoryStore<DefaultUser>` still works with caller-built users for anyone
already on it.

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
