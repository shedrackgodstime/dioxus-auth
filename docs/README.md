# dioxus-auth guides

Authentication and session management for [Dioxus](https://dioxuslabs.com).

You own the database, users, and data. **dioxus-auth** provides the
authentication and session layer around them: credentials, sessions,
and the link between a login and your application identity. It never
scaffolds, migrates, or touches your database, and it never owns your
User model.

Status: v0.1 covers email and password. Every other method (OAuth,
passkeys, magic links, OTP, API keys) is future scope; the architecture
is built so they arrive as new verbs on the same entry point, never a
second auth system. Pre-1.0: expect breaking changes, nothing is
published yet.

## 1. Quickstart: authentication in minutes

Add the crate:

```bash
cargo add dioxus-auth
```

No modeling. The bundled memory store mints identities, so signup takes
a display name and nothing else:

```rust
use dioxus_auth::{Auth, DefaultUserInput};

fn main() -> Result<(), dioxus_auth::AuthError> {
    let auth = Auth::memory()?;

    auth.sign_up_email(
        "alice@example.com",
        "password",
        DefaultUserInput::new("alice"),
    )?;

    let (user, session) = auth.sign_in_email("alice@example.com", "password")?;
    assert_eq!(user.name, "alice");

    auth.sign_out(&session)?;
    Ok(())
}
```

Memory dies with the process: prototype with it, graduate before
anything matters. Unknown identifiers and wrong passwords share one
`InvalidCredentials` error, so identifier state is never observable,
through messages or timing.

## 2. Your User, your database

Graduation has three shapes. Pick the one that matches how much you
want to own.

### 2a. Prototype resolver: your model, memory storage

Define your own `AppUser`, implement one method, point the generic
memory store at it. Same verbs, same sessions:

```rust
use dioxus_auth::{Auth, AuthUser, MemoryStore};

#[derive(Debug, Clone)]
struct AppUser {
    id: u64,
    email: String,
}

impl AuthUser for AppUser {
    type Id = u64;

    fn id(&self) -> u64 {
        self.id
    }
}

fn main() -> Result<(), dioxus_auth::AuthError> {
    let auth = Auth::new(MemoryStore::<AppUser>::new())?;

    auth.sign_up_email(
        "alice@example.com",
        "password",
        AppUser { id: 1, email: String::from("alice@example.com") },
    )?;
    Ok(())
}
```

`AuthUser` is the whole contract: a stable application-row identifier.
The engine never reads your fields; it authenticates subjects and
returns keys, and the facade resolves them to your model.

### 2b. SQLite reference: file-backed persistence

`examples/sqlite-reference` is a copy-paste store plus the DDL you apply
yourself with any SQL tool. Your application table carries zero auth
columns; credentials and sessions key off your key and cascade with
your rows:

```sql
users(id, email, name, ...)       -- your rows, untouched by auth
accounts(provider, identifier, app_key, password_hash)
sessions(id, app_key, expiry, activity, metadata)
```

Signup takes creation material your store understands. Adopting an
existing row (imports, admin-created users, SSO links) passes the
existing key instead of a new row:

```rust
SqliteAppSetup::New(AppUser { ... })  // persist a new row with the claim
SqliteAppSetup::Existing(1)           // link the claim to row 1, rewrite nothing
```

### 2c. Your transaction: the Direction D flow

When your application owns its transaction, authentication attaches
inside it. You insert your row with your own SQL, claim the credential
for your own key, and commit once. Both land together or neither does:

```rust,ignore
let tx = conn.transaction()?;
tx.execute("INSERT INTO users (...) VALUES (...)", ...)?;
claims.claim(&tx, "alice@example.com", "password", app_id)?;
tx.commit()?;
```

`EmailClaims` holds the hasher, the timing-defense dummy, and an
optional rate limiter shared with login; it executes statements only
and never commits, begins, or rolls back. Taken identifiers, unknown
keys, and mismatches fail indistinguishably with identical hashing
work; re-claiming the same identifier for the same key succeeds so
retries self-heal. Pre-hashed migration credentials go through
`claim_hash` under the same contract. To stop repeating the row writer,
configure it once with `ConfiguredSignup::new(claims, insert_fn)` and
call `sign_up` with application data; arbitrary custom columns flow
through your SQL untouched.

## 3. Core concepts

**Two layers, one engine.** `Auth` is the application-facing facade
(one store, both roles). `AuthEngine` is the configurable core: custom
hashers, session TTL (7 days by default), idle timeout, single-active
sessions, audit hooks, rate limiters, and injectable clocks, all via
`AuthEngine::builder`, wrapped back with `Auth::from_engine`.

**Sessions are opaque server records.** Each login mints a 256-bit
token; the wire token travels to the client while storage keeps only
its `sha256`. Sessions expire by absolute TTL, optionally by idle
timeout, optionally enforce single-active, and revoke in scopes
(one session, or all of a subject). Expiry is lazy (dropped on use),
so deployments with hard revocation deadlines add background sweeping.
Debug output redacts tokens and hashes everywhere.

**Identifiers are normalized once** (trim plus lowercase) before any
store call; stores compare byte-for-byte. There is deliberately no
email canonicalization beyond display folding.

**Credentials are Argon2id hashes** with a timing-defense dummy
verification on every miss path, so unknown identifiers cost exactly
what wrong passwords cost.

**Errors are codes, not messages.** Branch on `AuthError::code()`,
never on text:

| Code | Meaning |
|---|---|
| `invalid_credentials` | Unknown identifier, wrong secret, or taken identifier on signup. One error for all three, always. |
| `password_hash_error` | Malformed stored hash (surfaced outside the login oracle path only). |
| `rate_limited` | Throttled; opt-in per deployment. |
| `csrf_validation_failed` | State-changing cookie op without a present, matching origin. |
| `internal_error` | Store, hasher, or configuration failure. |

## 4. Auth methods (email + password)

| Verb | Does |
|---|---|
| `sign_up_email` | Provision subject + first credential, then sign in. |
| `sign_up_email_with_options` | Same claim with explicit control (`SignupOptions`: subject-ID override today; pre-hashed secrets stay separate by design). |
| `sign_up_subject` | Same claim returning auth-space material (attach and migration flows). |
| `sign_in_email` | Verify and mint a session. |
| `sign_out` | Revoke one session, idempotently. |
| `change_password` | Prove current, revoke all sessions, rotate. |
| `attach_email_credential` | Bind another login to an existing subject (privileged: authorize first). |
| `import_email_credential` / `attach_imported_email_credential` | Trust-based migration from pre-hashed secrets. No verification possible, no session minted, admin and migration tooling only. |

Rate limiting is opt-in per deployment (`InMemoryRateLimiter`, with a
`prod()` preset around 100 attempts per 60-second window). Turn it on
for any credential endpoint facing the network.

## 5. Reading identity: keys first, models second

Two reads, never confused. The engine resolves sessions to an
application **key** (`login_key`, `validate_key`): no model, no app
tables, fail-closed. Resolving the key to your `User` is a separate
step, done three ways:

- **Bundled stores** resolve inside the facade (`sign_in_email`
  returns your `User` directly).
- **Caller loaders** compose per call (`login_user`,
  `validate_user`): a plain `Fn`, any return type, unresolvable keys
  fail closed, outages propagate, dead links are swept on validate.
- **Split architectures** mount a `ResolvingStore`: any subject store
  plus one loader closure becomes a complete store for the facade,
  provider, and guards.

Server code must never trust the local render read; `require_user()`
is the verified network truth (see §7).

## 6. Client: Dioxus runtime (`dioxus` feature)

Mount one provider, read state anywhere, guard routes with plain
components:

```rust,ignore
rsx! {
    AuthProvider { auth,
        RequireAuth { redirect_to: "/login", Dashboard {} }
    }
}
```

```rust,ignore
let s = use_session::<AppUser>();
match s {
    SessionState::SignedIn(user) => rsx! { "Hello, {user.email}" },
    SessionState::Pending => rsx! { "Loading..." },
    SessionState::Unavailable(_) => rsx! { "Retry" },
    SessionState::Guest => rsx! { LoginForm {} },
}
```

`SessionState` has four variants: `SignedIn(user)`,
`Pending` (restore still open), `Unavailable(code)` (could not ask;
retry, never a silent sign-out), `Guest` (definitive no). A definitive
rejection demotes to guest; storage, transport, and rate-limit failures
stay out of the guest path so a blip never signs the user out.
`RedirectIfAuthed` mirrors the guard for signed-in users, and
`on_auth_state_change` subscribes to transitions.

## 7. Server: fullstack (`dioxus-fullstack` feature)

Generate the cookie-driven endpoints once:

```rust,ignore
dioxus_auth::fullstack_server_fns!(AppUser);
```

This expands `POST /api/auth/login`, `/logout`, `/session`,
`/attach`, and `/change-password` (custom paths supported), all
cookie-only with redacted wire inputs (`LoginRequest`,
`AttachRequest`, `ChangePasswordRequest`). Resolve the caller per call;
the server re-validates every time and guards are UX only:

```rust,ignore
let user = dioxus_auth::require_user::<AppUser>().await?;
```

Configure with `server_init` (tests and simple apps) or `AuthLayer`
/ `RequireAuthLayer` (middleware composition). The sync engine runs
off the async worker through a blocking boundary.

Cookies default to `HttpOnly` plus `Secure` with `SameSite=Lax` and a
session lifetime; size `max_age` to the engine TTL for persistent
login. Set `expected_origins` for every `SameSite=None` deployment
(mandatory there) and preferably always: `Lax` alone does not stop
login CSRF, and the origin gate is the backstop that does. Safe methods
(`GET`/`HEAD`/`OPTIONS`) skip the gate; state-changing operations
enforce it with 403s. `host_only` mode binds the `__Host-` prefixed
cookie against sibling-app shadowing.

## 8. Storage: capability traits and the escape hatch

| Trait | Owns |
|---|---|
| `SubjectStore` | Subjects: atomic provision, lookup, app linking, key translation, cascade delete. |
| `CredentialStore` | Credentials per subject and provider: lookup, attach, rotation. |
| `SessionStore` | Sessions keyed by storage id: save, find, delete, conditional touch, per-subject list and revoke. |
| `UserStore` | Application models: `resolve` from app key. Called by outer layers, never the engine. |

Bundled implementations: `DefaultStore` (memory quickstart with
generated identities), `MemoryStore` (prototype resolver over your
model), the SQLite reference (file-backed R1). `ResolvingStore` adapts
any subject store plus a loader closure. Anything further out:
implement the traits directly against any backend; they are sync by
design. The crate never creates tables or runs migrations; the
reference DDL is idempotent, so reopening a file database preserves
data. Single-table and merged-column layouts are permitted wherever
they can honor the same method contracts.

## 9. Shipping checklist

Enforce origins (required for `SameSite=None`, recommended always);
never disable `HttpOnly`/`Secure` in production; size persistent
cookies to the engine TTL; rate-limit every network-facing credential
endpoint; sweep expired sessions in the background if revocation has
deadlines; never log tokens or hashes (the crate redacts them, keep it
that way); branch on error codes, not messages; keep credential
management (attach, import, rotation) behind authorization.

## 10. Status and direction

v0.1 is the email-plus-password vertical over this architecture. The
preserved direction: the same entry point gains additive methods
(magic link, OAuth, passkeys) as new verbs, and the configured
high-level path keeps approaching one-call signup over developer-owned
models (`sign_up_email` with application data) without ever taking
ownership of the model. No second auth system, at any tier.

## License

MIT OR Apache-2.0. See the root `LICENSE`, `LICENSE-MIT`, and
`LICENSE-APACHE`.
