# Handoff: dioxus-auth v2 branch, full arc to date

For PC pull, test, and verification. Push back to `v2` when done for
last review before publishing.

## 1. Branch state

Branch `v2`, pushed clean. `git status` on handoff day shows only two
untracked-or-modified stragglers, both yours-or-junk, neither code:

- `prompt.md` (modified, your brief files, left untouched deliberately)
- `kb.1` (untracked man page for the `kb` CLI that landed in root by
  accident; safe to delete, never committed)

Everything else is committed and pushed through `9ec190a`.

## 2. Commit arc (what changed, in order)

- `5ec4fb7`, cut `AuthUser::email`, provision takes creation input and
  returns the created user instead of `bool`.
- `d7796dc`, ID-free memory quickstart (`DefaultStore` with atomic
  counters, `DefaultUserInput::new(name)`, no invented IDs).
- `d7187b6`, filed working design docs under `docs/` (investigations,
  decisions, vision, inconclusion notes).
- `f8d38ef`, retired `DefaultUser::new`, reframed `DefaultUser` as
  store plumbing, not a model to grow.
- `066132f`, dropped `CHANGELOG.md` until the first release settles;
  packaging whitelist and script references updated with it.
- `0c6cf5b` + `f3e12a4`, checkpoint of the subject remodel
  (intermediate, pre-R1; second entry is a duplicate push, ignore it).
- `3a02214`, R1 reference migration: SQLite reference dropped its
  subjects table; credentials and sessions key off the application key
  with cascading deletes; binding derived from the current secret.
- `546401f`, key-returning reads (`login_key`, `validate_key`),
  caller-loader composition (`login_user`, `validate_user`), signup
  options with id override (`SignupOptions`,
  `sign_up_email_with_options`), trust-based hash import
  (`import_email_credential`, `attach_imported_email_credential`,
  tx-side `claim_hash`).
- `cd52eea`, provider-keyed credentials (`find`/`attach`/`provision`
  all take provider; credentials keyed by provider-plus-identifier),
  idempotent DDL (`IF NOT EXISTS`, reopen-safe files), `session_auth_hash`
  hook removal.
- `b3b2908`, straggler test updates from the provider pass.
- `c58ed28`, settings network parity (`attach_current` +
  `change_password` engine verbs, operations, context, five-endpoint
  macro with additive arm, redacted inputs), AuthUser `Hash` trim,
  `ResolvingStore` (subject store plus loader closure).
- `9ec190a`, `docs/README.md` rewritten as one complete guides file.

## 3. Architecture decisions (all in `docs/`)

- `docs/architecture-conclusion.md`, authoritative. Direction D
  (dev-owned transaction + tx-scoped claim), R1, key-returning reads,
  loader-as-convenience, options channel, hash import, two-tier Dioxus
  experience, tiered escape hatches, north star. Read this first.
- `docs/dioxus-auth-user-creation-decisions.md`, decision log with
  IMPLEMENTED/DECIDED markers per item.
- `docs/signup-storage-investigation.md`,
  `docs/user-creation-developer-control.md`, early research, frozen.
- `docs/picturing.md`, `docs/inconclusion.md`, vision and synthesis
  notes that drove the final direction.
- `docs/prompt.md`, `docs/prompt-00.txt`, `docs/prompt.txt`, the
  investigation briefs, kept for provenance.

## 4. What is implemented (v0.1 email/password vertical)

Core: auth-pure engine (login, validate, logout, revoke, rotation,
idle timeout, single-active, rate gates, dummy-verified
no-enumeration), Argon2id hashing, opaque 256-bit sessions stored as
`sha256`, redacted Debug everywhere. Facade verbs: signup, signin,
signout, change-password, attach, import, options-override signup,
auth-space signup. Engine key reads plus loader composition.
SQLite reference: R1 tables, tx-scoped `EmailClaims`
(claim/claim_hash/signup_with) plus `ConfiguredSignup`, idempotent
DDL, FK cascades with adoption/rotation/cascade flow tests. Dioxus:
provider, hooks, guards, network-aware restore. Fullstack: five
generated server functions with redacted inputs, origin gating,
blocking dispatch, middleware layers. Conformance suites pinning the
trait contracts.

## 5. Deliberately NOT built

Custom method families and verify dispatch (structure ready via
provider params; no second verifier). Loader configuration object
(per-call composition covers it). Generic ID framework (counters work;
`i64` reference scope documented). `ensure_schema` policy beyond
idempotent DDL. Adapters beyond bundled stores. `UserData`
orchestration beyond `signup_with`/`ConfiguredSignup`. Release
mechanics (no tag, no publish, no changelog). Extra auth methods
(OAuth, passkeys, magic links, OTP, API keys).

## 6. How to verify on PC

Full gate is `bash scripts/verify.sh` (fmt, clippy x3, tests x3
feature combos, doctests, docs build, packaging, doc invariants,
SSOT). On slow machines it exceeds shell timeouts; run the documented
chunks instead, in this order:

```bash
cargo fmt -- --check
cargo clippy --workspace --all-targets -- -D warnings -W clippy::pedantic
cargo test --workspace --all-targets
cargo test --workspace --all-targets --features dioxus
cargo test --workspace --all-targets --features dioxus-fullstack,server
cargo test --workspace --doc
cargo clippy --workspace --all-targets --features dioxus -- -D warnings -W clippy::pedantic
cargo clippy --workspace --all-targets --features dioxus-fullstack,server -- -D warnings -W clippy::pedantic
RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links" cargo doc --no-deps --features dioxus-fullstack
bash scripts/check-packaging.sh
bash scripts/check-docs.sh
bash scripts/check-ssot.sh
```

Argon2 makes suites slow everywhere (minutes, not seconds); that is
normal. MSRV (1.85 for the core library) and wasm/audit/coverage jobs
are CI-only.

## 7. Known quirks (read before triaging failures)

- **Timing flake:** `policies::failed_attempts_are_rate_limited` fails
  when a full-suite run stretches past its 60-second rate window on
  slow hardware. Passes in isolation and on fast runners. Environmental,
  not a code defect; do not "fix" by loosening the test.
- **Em-dash ban:** `scripts/check-docs.sh` fails the build on U+2014
  anywhere in `src/`, `tests/`, `README.md`, `docs/`, `CHANGELOG.md`,
  `CONTRIBUTING.md`, or `scripts/`. Reword with commas, colons, or
  periods. This bites documentation edits most often.
- **Byte-identical schema:** `examples/sqlite-reference/README.md` must
  contain `SCHEMA_SQL` verbatim (test-enforced). Edit the constant and
  the README together or neither.
- **Temp-file tests:** file-backed SQLite tests use unique temp paths
  with best-effort cleanup; leftovers in the system temp dir are harmless.
- **`CONTRIBUTING.md` vanished from disk twice**, uncommanded, and was
  restored byte-identical from git both times. Cause unknown. If it
  happens on PC, check filesystem/sync tooling before suspecting the repo.
- **Packaging whitelist:** `Cargo.toml` `include` plus
  `scripts/check-packaging.sh` must agree; new `src/` files match
  automatically via `/src/**`, new top-level or `docs/` files do not
  ship unless whitelisted.

## 8. Review-before-publish checklist status

- Sim-0 budget: quickstart at 15 meaningful lines, zero traits, zero
  infra, non-durability stated. Still owed: copy-paste `LoginForm`
  snippet, timed 10-minute run.
- Graduation parity tests green on both boundaries.
- `src/error.rs` untouched since early v2: no silent error-code drift.
- CONTRIBUTING's release checklist references a deleted `CHANGELOG.md`
  and a scratch `plan/` path; repoint both before tagging.
- `docs/README.md` was just rewritten; flagged by its author as needing
  a proper editorial pass (structure is complete, prose is first-draft).

## 9. How to pull back

Work on `v2`, push to `v2` when done. Keep commits in the established
style (`v2: <imperative summary>`), one concern per commit, gate green
per commit. Do not force-push shared history. Leave `kb.1` alone or
delete it; either way do not commit it.
