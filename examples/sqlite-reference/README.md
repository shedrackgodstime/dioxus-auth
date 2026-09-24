# SQLite reference store (1d)

Copy-paste SQLite persistence for `dioxus-auth`. **You own this file:**
copy `src/lib.rs` into your app, rename the tables, add columns, swap the
user type. The crate never scaffolds, migrates, or touches your database.
The schema below is documentation you apply yourself, and `src/lib.rs` is
one honest implementation of it.

```rust
use std::sync::Arc;

let store = Arc::new(SqliteStore::open("app.db")?);
let auth = Auth::new(store)?; // same verbs as the memory quickstart
auth.sign_up_email("alice@example.com", "password", SqliteAppSetup::New(AppUser { ... }))?;
```

## Transaction-joined signup (Direction D)

When the application owns its transaction, authentication attaches
inside it instead of the other way around. The application inserts its
User row with its own SQL, claims the credential for its own key, and
commits once; both land together or neither does:

```rust
let tx = conn.transaction()?;
tx.execute("INSERT INTO users (...) VALUES (...)", ...)?;
claims.claim(&tx, "alice@example.com", "password", app_id)?;
tx.commit()?;
```

Ownership on this path: the application owns its model, table, rows,
transaction, and commit. Auth owns credentials, sessions, hashing, and
the link. Auth never writes application columns; the developer never
manages an auth ID and implements no storage traits. `EmailClaims`
holds the hasher, the timing-defense dummy, and an optional rate
limiter shared with the login gate; it executes statements only and
never commits. Taken identifiers, unknown keys, and mismatches fail
indistinguishably with identical hashing work; re-claiming the same
identifier for the same key succeeds so retries self-heal.

## Schema: apply this yourself

`users` (application rows, zero auth columns) · `accounts` (credentials,
one row per login method, keyed by the application key) · `sessions`
(opaque server-side sessions, keyed by `sha256(raw token)`, owned by the
application key) · `verifications` (reserved for future magic-link
flows; created now so the shape is complete, unused by email+password
verbs). There is no subjects table: the application key serves as the
subject key.

```sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL,
    email_verified_at INTEGER,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
CREATE TABLE IF NOT EXISTS accounts (
    provider TEXT NOT NULL DEFAULT 'email',
    provider_account_id TEXT NOT NULL PRIMARY KEY,
    app_key INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS accounts_app_key ON accounts (app_key);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT NOT NULL PRIMARY KEY,
    app_key INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_active_at INTEGER,
    auth_hash TEXT,
    ip TEXT,
    user_agent TEXT
);
CREATE INDEX IF NOT EXISTS sessions_app_key ON sessions (app_key);
CREATE TABLE IF NOT EXISTS verifications (
    id TEXT NOT NULL PRIMARY KEY,
    identifier TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
);
```

A test (`schema_doc_matches_const`) asserts this block is byte-identical to
the `SCHEMA_SQL` constant the store executes. The copy-paste SQL cannot rot
away from the DDL. One documented deviation: the guide's 4-table shape omits
`sessions.created_at`, but the engine needs it persisted for absolute-TTL
math, so the column stays.

## Notes for owners

- **Sync driver on purpose.** The engine's store traits are synchronous; an
  async driver would need `block_on` plumbing that panics inside the server's
  blocking pool. `rusqlite` keeps every path panic-free, including server
  functions.
- **One connection behind a lock.** `rusqlite` connections are `Send` but not
  `Sync`; the mutex is what makes the store shareable. Provisioning runs in
  an immediate transaction, so the identifier claim is atomic even under
  threads.
- **Identifiers are engine-normalized** (trim + lowercase) before any store
  call; the store compares byte-for-byte.
- **Timestamps are `INTEGER` UNIX seconds.** Out-of-range values fail loudly
  (`Internal`) instead of wrapping.
- **Foreign keys are enforced** (`PRAGMA foreign_keys = ON` per connection).
