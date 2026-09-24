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

## Schema: apply this yourself

`subjects` (auth identities with the app link) · `users` (application
rows, zero auth columns) · `accounts` (credentials, one row per login
method, pointing at the subject) · `sessions` (opaque server-side
sessions, keyed by `sha256(raw token)`) · `verifications` (reserved for
future magic-link flows; created now so the shape is complete, unused by
email+password verbs).

```sql
CREATE TABLE subjects (
    auth_id INTEGER PRIMARY KEY,
    app_ref INTEGER UNIQUE,
    auth_hash TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL,
    email_verified_at INTEGER,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
CREATE TABLE accounts (
    provider TEXT NOT NULL DEFAULT 'email',
    provider_account_id TEXT NOT NULL PRIMARY KEY,
    auth_id INTEGER NOT NULL REFERENCES subjects (auth_id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL
);
CREATE TABLE sessions (
    id TEXT NOT NULL PRIMARY KEY,
    auth_id INTEGER NOT NULL REFERENCES subjects (auth_id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_active_at INTEGER,
    auth_hash TEXT,
    ip TEXT,
    user_agent TEXT
);
CREATE TABLE verifications (
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
