# dioxus-auth, Signup & Storage Architecture Investigation

> No code modified. Facts below trace to actual files. I separate **Fact** (code-observed), **Implication** (architectural consequence), and **Opinion** (design judgment) where it matters.

---

## 1. Executive findings

1. **The caller-supplied ID is a trait-shape consequence, not a domain requirement.** `Auth::sign_up_email` (`src/methods.rs:188-224`) takes a fully-formed `D::User` by value and hands it to `PasswordUserStore::provision_user_with_password(user, identifier, hash)` (`src/store/user.rs:80-85`). The engine never generates, sets, or fills in an ID. It only reads `user.id()` inside the store for duplicate-check + persistence (`src/store/memory.rs:207-211`, `examples/sqlite-reference/src/lib.rs:302-304`). The library *cannot* construct an `AppUser` today, there is no factory bound, and *cannot* mutate one, `AuthUser` exposes only `&self` getters (`src/user.rs:19-42`).
2. **`AuthUser::email()` is dead weight in v0.1.0.** Repo-wide search: `.email()` is called in zero `src/` files. Only the trait definition (`src/user.rs:28-29`) and two test assertions (`tests/auth_facade.rs:349`, `tests/conformance/password_store.rs:83`) reference it. The engine's only real needs from a user are: a stable session-owner key (`id()`), rehydration by that key (`find_by_id`), and optional credential binding (`session_auth_hash()`). The login identifier travels as a separate `&str` argument, never via the user object.
3. **The library requires almost no physical schema. The 4-table shape is reference-only.** `AuthEngine` assumes only the six `SessionStore` methods (`src/store/session.rs`), three `PasswordUserStore` methods + one `UserStore` method (`src/store/user.rs`), a `PasswordHasher`, and sync execution. No SQL, no table count, no `users/accounts/sessions/verifications` names appear in `src/`. A one-table / one-struct / document / KV / external-service store is permitted *if* it can implement those methods with their documented atomicity. `MemoryStore` already proves this: three `Vec`s in one struct, zero tables (`src/store/memory.rs:29-33`).
4. **`verifications` is untouched by current functionality.** Zero hits for `verification` in `src/`. In the SQLite reference, `verifications` is never read/written by any engine path; `users` + `accounts` + `sessions` are the only tables exercised by signup/signin/signout. `email_verified_at` is likewise future-only.
5. **There are two entry points with different flexibility.** `Auth<D>` forces one store to play both user and session roles (`src/auth.rs:22-27`). `AuthEngine<U,S>` allows split stores (`src/engine.rs:92-96`). Advanced deployments (separate user/session persistence, custom hasher/limiter/clock/hooks) must use `AuthEngine::builder(...)` + `Auth::from_engine`, the `Auth::new` happy path hides that.
6. **The current signup signature duplicates information without checking it.** Caller passes `identifier: &str` *and* `user: D::User` (which itself contains an email field). Nothing verifies they match. Tests prove the divergence is tolerated: `TestUser{ name: "bob" }` provisioned under identifier `"bob@example.com"` succeeds (`tests/conformance/password_store.rs:70-84`).
7. **Beginner friction is conceptual, not just verbose.** To call signup the beginner must: invent a primary-key strategy, pick an ID value, understand `DefaultUser` vs `AppUser`, supply the email twice, put the password outside the user for non-obvious reasons, and implement (later) a 2-method trait + 7-method store surface just to graduate. None of this is needed for the engine's actual work.

---

## 2. Current architecture

### 2.1 Layer map

```
Auth<D>  (src/auth.rs, facade, single dual-role store D)
  └─ Arc<AuthEngine<D,D>>
AuthEngine<U,S>  (src/engine.rs, U: PasswordUserStore, S: SessionStore<Id=U::Id>)
  ├─ login / do_login / authenticate_user  (src/login.rs)
  ├─ logout / revoke_*                     (src/logout.rs)
  ├─ validate_session                      (src/validate.rs)
  ├─ hooks (fire_on_*)                     (src/hooks.rs)
  └─ builder (TTL, idle, single-active, hasher, limiter, clock, hooks) (src/builder.rs)
Stores (src/store/)
  ├─ UserStore: find_by_id
  ├─ PasswordUserStore: find_by_identifier, update_password, provision_user_with_password
  └─ SessionStore: save/find/delete/touch_if_present/delete_user_sessions/list_user_sessions
  └─ MemoryStore<User> implements all three (src/store/memory.rs)
Dioxus runtime (src/dioxus/, feature-gated): AuthProvider, use_session, guards, erased AuthOperations
Fullstack server (src/dioxus/server/): generated fns, require_user/current_user, cookie+origin policy
```

### 2.2 Signup call-flow (exact names)

```
Auth::sign_up_email(identifier, password, user)          [src/methods.rs:188]
  ├─ engine.check_rate_limit(identifier, None)           [src/login.rs:128]
  ├─ engine.hasher().hash(password)                     [Argon2Hasher default, src/builder.rs:240-246]
  ├─ normalize_identifier(identifier) → trim+lowercase  [src/login.rs:28]
  ├─ user_store.provision_user_with_password(           [src/store/user.rs:80]
  │     user, &normalized, &hash)
  │     MemoryStore: write-lock credentials→check ident, [src/store/memory.rs:199-214]
  │       write-lock users→check user.id(), push both
  │     SqliteStore: IMMEDIATE tx, INSERT users then     [examples/sqlite-reference/src/lib.rs:294-325]
  │       INSERT accounts; conflict → Ok(false), rollback by drop
  ├─ on Ok(false):
  │     record_rate_limit_failure + dummy_verify(password) [src/methods.rs:219-220]
  │     → Err(InvalidCredentials)  // taken == free, same error + extra hash work
  └─ on Ok(true):
        Auth::sign_in_email(identifier, password)       [src/methods.rs:113]
          └─ engine.login → do_login                    [src/login.rs:73,191]
                ├─ verify_password → check_rate_limit + authenticate_user
                │     └─ users.find_by_identifier(&normalized) [src/login.rs:269]
                │     └─ hasher.verify(password, stored_hash); miss → dummy_verify + InvalidCredentials
                ├─ SessionId::generate() (256-bit CSPRNG hex) [src/status.rs:83]
                ├─ storage_id = raw.hash_for_storage() (sha256) [src/status.rs:91]
                ├─ Session::new(storage_id, user.id(), now, now+ttl) + auth_hash/ip/UA [src/login.rs:204-219]
                ├─ login_lock { save_session + rotate_stale_sessions } [src/login.rs:220-236]
                ├─ rebuild wire Session with raw id
                ├─ fire_on_sign_in, record_rate_limit_success
                └─ return (U::User, Session<Id>) → facade returns (D::User, SessionId) [src/methods.rs:118-122]
```

Error points: rate-limit (`RateLimited`), hasher failure, store failure (`Internal` via SQLite mapping, passthrough in memory), taken identifier/id (`InvalidCredentials` by design).

### 2.3 Trait relationships

* `UserStore` (`src/store/user.rs:14-26`): `type Id`, `type User: AuthUser<Id=Self::Id>`, `find_by_id`.
* `PasswordUserStore: UserStore` (+ `find_by_identifier`, `update_password`, `provision_user_with_password`). Identifier arrives pre-normalized; store compares byte-for-byte, enforces atomic claim-or-`false`, rejects duplicate `user.id()` with no writes.
* `SessionStore` (`src/store/session.rs:15-68`): keyed by **storage form** `sha256(raw)`; engine hashes before every call. Six methods listed above.
* `AuthUser` (`src/user.rs:19-42`): `Clone+Debug+Send+Sync+'static`, `type Id: Clone+Eq+Hash+Debug+Send+Sync+'static`, `id()`, `email()`, default `session_auth_hash() → None`.
* `AuthOperations<T>` (`src/dioxus/operations.rs:26-47`): erased login/logout/validate over `T: AuthUser`, hiding store generics from components.

---

## 3. User creation and ID ownership

| # | Question | Answer + proof |
|---|---|---|
| 1 | Where is `AuthUser::Id` defined? | `src/user.rs:21`, re-bound as `UserStore::Id` / `User::AuthUser<Id=Self::Id>` (`src/store/user.rs:16-18`), threaded into `SessionStore<Id=U::Id>` and `Session<Id>`. |
| 2 | Who generates it? | **The application, always.** Caller constructs `AppUser{id,...}` before signup. Engine has no ID-generation code path; `SessionId::generate` is the only generator and it mints *session* tokens, not user IDs. |
| 3 | Does the store know the concrete user type? | Yes: `type User: AuthUser` is concrete per impl (`MemoryStore<User>`, `SqliteStore::User=AppUser`). |
| 4 | Can the engine construct the concrete type? | **No.** No `Default`, `From<_>`, or factory bound exists. The engine only receives an owned `User` and clones/returns it. |
| 5 | Can the library create an `AppUser` today? | No, for the above reason. |
| 6 | Can the library set `AppUser.id`? | No. `AuthUser` has no `set_id` / `&mut` method; implementations expose public fields by convention, not by trait. |
| 7 | Can the store generate the ID? | Not through the current signature: it receives `user: Self::User` by value, so the ID slot is already filled. A store *could* ignore `user.id()` and substitute its own internally, but it cannot hand a corrected user back (`provision_*` returns `bool`, not `User`), and the facade returns the caller-built object, so caller and row would disagree. |
| 8 | Can the store return a newly created user? | No channel for it: `provision_user_with_password → Result<bool>`. `Ok(true)` means "your object was stored"; there is no "here is the stored object". |
| 9 | Deliberate or accidental? | **Implication: consequence of trait design.** The doc comment "The caller builds the user; the store provisions the credential row" (`src/methods.rs:157`) describes the mechanism faithfully, but no design record in-tree justifies *why* construction lives caller-side. The signature made caller-side IDs inevitable; nothing else in the engine needs it. |

**Fact:** both stores treat `user.id()` as an opaque duplicate-check + foreign key (`memory.rs:208`, sqlite `INSERT users(id,...)` + `accounts.user_id`). The ID type itself is fully generic (`u64` in tests, `i64` in SQLite, `Uuid`/`String` permitted by bounds).

---

## 4. Storage ownership: what the library requires vs what the reference chooses

| Responsibility | Current owner | Could library own it? | Could store own it? | Why |
|---|---|---|---|---|
| User ID generation | App | Yes (optional default) | Yes | Nothing in engine generates user IDs; both are greenfield. Current `provision(user,...)->bool` shape blocks both, needs signature change. |
| User construction | App | Only with new input/factory trait | Yes | Engine never constructs `User`; store receives it pre-built. |
| Email normalization | Library (engine) | Already does | No (forbidden) | `normalize_identifier` (`login.rs:28`) runs once per verb; stores must compare byte-for-byte (`store/user.rs:30-32`). Clean boundary, keep. |
| Password hashing | Library (hasher trait, Argon2 default) | Already does | No (login path) | Store never sees plaintext on login (`store/user.rs:36-41`); signup hashes before `provision`. Custom hashers via builder. |
| Credential persistence | Store | No | Already does | Engine only passes `(normalized_ident, hash)`; physical layout is store-private. |
| Session generation | Library | Already does | No | `SessionId::generate` + `hash_for_storage` in engine (`login.rs:212-213`). Store sees only hashes. |
| Session persistence/lifecycle | Store (via 6-method contract) | No | Already does | Engine dictates semantics, store picks medium. |
| Custom user fields | App | No (must stay opaque) | Pass-through | Engine touches only `id()` + `session_auth_hash()`; `MemoryStore` clones whole struct; SQLite reference persists only `id/email/name`, extra fields need reference edits. |
| Database schema | App (owns DB) | No | Reference chooses 4 tables | Zero schema names in `src/`; `SCHEMA_SQL` lives in the example (`examples/sqlite-reference/src/lib.rs:38-68`). |

**One-table question (Fact):** yes, permitted. One struct can implement all three traits over one `HashMap`/table/JSONB column provided it honors: atomic `provision` (identifier+id claim indivisible), `touch_session_if_present` as no-op-if-deleted (anti-resurrection, `store/session.rs:40-53`), `list/delete_user_sessions` by owner, hashed session keys, and lazy-expiry semantics. Whether one-table is *wise* (indexability, revocation cost, row bloat) is a separate performance judgment the traits do not make.

**Physical-vs-logical leak (Implication):** the *code* does not leak schema (traits are storage-agnostic). The *docs/mental model* partially do: README's "four tables" sketch, `provider/provider_account_id` columns anticipating OAuth, and `AuthUser::email()` implying every user has an email. A username-only, phone-OTP, or external-IdP deployment would find `email()` and the accounts-table shape misleading even though the engine never calls `email()`.

### Reference schema categorization

* `users` + `accounts` + `sessions`: **required for current email/password**, all touched by signup/signin/signout paths.
* `verifications`: **future/extensibility**, zero engine references in v0.1.0.
* `email_verified_at` (users col): **future**, never read/written by engine.
* `sessions.created_at`: **engine-required** (absolute TTL `created_at + ttl` in `validate.rs:79`), the reference README notes this as a documented deviation from the guide sketch.

---

## 5. Current API friction (beginner lens)

For `Auth::memory()?` + `sign_up_email(email, pw, DefaultUser{id,email,name})`:

1. **"Why do I need an ID?"** Nothing in the flow explains that the ID is the session-owner key + store primary key. The beginner must invent a PK strategy (counter? UUID? DB autoincrement, but there is no DB?) before first signup.
2. **"Who generates it?"** Unspecified. `1` in the quickstart looks like a placeholder; collisions return `InvalidCredentials` (deliberately indistinguishable from taken-email), so a guessing beginner gets a confusing error.
3. **"Why is the email in two places?"** `identifier` arg *and* `user.email` field, with no equality check and different roles (lookup key vs display/persisted field). Divergence silently persists.
4. **"Why is the password outside the user?"** Correct security-wise (plaintext never stored in the user row; hash lives in the credential map/table), but unexplained. A beginner naturally models `User{email, password}` and must unlearn it.
5. **"What is `DefaultUser`?"** Minimal `{id,email,name}` that must later be renamed to `AppUser` + trait impl + store swap. The graduation story is documented but still a rewrite of every call site's third argument.
6. **"Which fields are auth's vs mine?"** Auth needs only the ID (+ optional auth-hash); `name` is pure application data that the engine blindly carries. The signature does not distinguish them, so everything looks equally mandatory.
7. **"Why does the library need my whole user to register me?"** It doesn't, functionally, it needs an ID, a lookup key, and a hash. The whole-object requirement is the friction.

---

## 6. Design constraints (any future API must satisfy)

1. **No-enumeration preserved:** taken/free identifiers share error + comparable hash work (`methods.rs:212-223`, `login.rs:274-280`). Any new signup path must keep the dummy-verify on the reject path.
2. **Atomic provision:** identifier-claim + user-write indivisible (`store/user.rs:63-75`; memory guard order `memory.rs:199-214`; SQLite immediate tx). DB-generated IDs must still close the check-then-insert race (unique constraint + conflict→`false` is the established pattern).
3. **Session security invariants:** 256-bit CSPRNG wire tokens, storage as `sha256(raw)`, wire-shape pre-check, hashed-only store access (`status.rs`, `login.rs:212`, `validate.rs:38-44`).
4. **Session lifecycle semantics:** lazy expiry + eager drop-on-use, idle-timeout gating of touches (`validate.rs:74-86`), `touch_if_present` no-resurrection, `login_lock` save-then-rotate window (`login.rs:220-236`), single-active exactness process-local / transactional distributed (`builder.rs:149-160`, `engine.rs:116-125`), credential-version rotation via `session_auth_hash`.
5. **Sync stores:** engine traits are sync; async drivers need blocking plumbing (SQLite reference documents why it chose `rusqlite`, `examples/sqlite-reference/src/lib.rs:8-14`).
6. **Normalization single-homing:** engine normalizes once; stores never fold (`login.rs:18-30`). Any ID/identifier generator must decide where it sits relative to this.
7. **Generic `Id` preserved:** `u64`/`i64`/UUID/String/DB keys must all keep working; `find_by_id`/`Session<Id>`/`delete/list_user_sessions` key everything off it.
8. **Custom fields stay opaque to the engine:** engine must never need to know `name/avatar/role/org/...`.
9. **Unpublished freedom:** pre-1.0, breaking trait/method changes are allowed; do not contort a design to preserve the current signature.

---

## 7. Possible architectural directions (no selection)

**Option A, Current model** (`sign_up_email(email, pw, full User)`).
*Trait changes:* none. *Ownership:* app builds + IDs everything. *Beginner DX:* poor (see §5). *Advanced control:* full. *Compat:* baseline. *Complexity/risks:* atomicity already handled; risk is conceptual, email twice, ID invention, `email()` dead contract.

**Option B, Metadata/input model** (`sign_up_email(email, pw, NewUser{...})` where `NewUser` ≠ stored `User`).
*Trait changes:* needs a creation-input associated type or second generic (e.g. `UserStore::NewUser` / `ProvisionInput`), plus a create returning the stored `User`. Breaks every `UserStore`/`PasswordUserStore` impl, `MemoryStore`, SQLite reference, conformance tests, docs. *Ownership:* app defines input shape; store maps input→row. *DX:* good, no ID at call site, no duplicated email, small input struct. *Advanced:* excellent, input can carry org/role/avatar; store applies DB defaults/constraints. *IDs:* store or DB can generate (INTEGER AUTOINCREMENT, UUID, app-supplied, all expressible). *Risks:* biggest trait churn; two user-related types to document; migration of all stores/tests/examples.

**Option C, Library-generated ID** (same call shape as B, library mints the ID).
*Trait changes:* needs an ID-generator bound (e.g. `Id: Generate` or builder-supplied closure) + construction channel (same as B). Additionally constrains `Id` types to generatable ones unless generator is injectable per-type. *DX:* best for beginners (nothing to invent). *Advanced:* must stay overridable or it dictates PK strategy, the exact thing "you own your data" forbids. *Risks:* library in the identity business; UUID-vs-integer wars; DB-autoincrement conflicts with pre-minting. Likely needs Option E's configurability to be acceptable.

**Option D, Store-generated user** (`sign_up_email(email, pw, NewUser)` where store owns creation + identity).
*Trait changes:* same family as B (input type + returning `User`), but ownership explicitly store-side; engine passes input through untouched. *DX:* good; works with existing-users tables (store can look up-or-create, map columns freely). *Advanced:* maximal, custom schema, DB-generated IDs, external identity systems (store can call out), multi-row writes (users+accounts) hidden inside `provision`. *Compat:* same breakage as B. *Risks:* engine must trust store's atomicity + uniqueness; per-store behavior variance grows; conformance suite must pin semantics harder.

**Option E, Configurable identity generation** (`Auth::builder(store).user_id_generator(...)` or per-store strategy).
*Trait changes:* smallest if additive, optional builder hook / defaulted trait method rather than associated-type overhaul. Can layer over A *or* B/D. *DX:* neutral alone (still need input model to remove ID from call site). *Advanced:* best preserves "bring your PK": app closure, DB default, UUID v7, Snowflake, external IdP subject. *Risks:* ordering questions (generator vs normalization vs rate-limit vs tx), testability, and the temptation to make the default strategy magic.

*Cross-cutting notes (Fact):* `MemoryStore` can support B/D trivially (construct struct from input in-process); SQL stores can support B/D via `INSERT ... RETURNING` / `last_insert_rowid` / UUID functions, all hidden behind the trait. UUID/integer/DB-generated/app-generated/external IDs are all compatible with B/D/E, incompatible with pure-C (library-minted) unless E is added. Arbitrary custom fields are preserved by B/D (input carries them), awkward under A (whole object required) and C (library must forward unknown fields it doesn't understand).

### Persona check

* **Beginner** ("auth without designing identity"): A fails (must invent PK + understand stores); B/C/D pass with generated identity; E alone insufficient.
* **Normal app dev** (existing `AppUser{Uuid,...}` + DB): A works but dictates call shape; B/D integrate (store maps input→existing rows/columns); C threatens PK ownership unless E-overridable.
* **Advanced** (custom IDs/schema/sessions/credentials): permitted today only via `AuthEngine` split + custom hasher/limiter/hooks (`builder.rs`, `from_engine`); B/D/E preserve or extend that; any direction must keep split-store, custom `PasswordHasher`, `SessionStore`, and sync-trait escape hatches.

---

## 8. Open questions (codebase cannot answer, product decisions needed)

1. Is `email` the canonical login identifier forever, or should the identifier be opaque (`login_id`) with email as one possible value? (`email()` dead today suggests the abstraction already wants generality.)
2. Should signup return the stored user, the input echo, or nothing-but-session? (Determines whether store-generated IDs/fields are visible.)
3. Who owns uniqueness scope, per-normalized-identifier globally, per-provider, per-org? Current provision assumes global identifier + global id uniqueness.
4. Are multi-identifier-per-user (email+username→same row) in or out? `update_password`-by-`user_id` assumes possible; provision docs discourage aliasing. Contradiction needs a ruling.
5. Should `DefaultUser`/memory path gain an ID-free convenience without changing the generic path (two APIs, one engine)?
6. DB-generated IDs: does the engine need to know the ID *before* hashing/rate-accounting, or only after `provision` returns the row?
7. External identity (OIDC subject, existing users table with pre-existing PKs): is "adopt, don't create" a first-class signup mode?
8. Session store physical minimum: is JSONB-embedded sessions acceptable if single-active + touch-atomicity hold, or do we bless separate session rows as the only supported pattern?
9. `verifications`/`email_verified_at`: activate now, defer, or drop from the reference until the magic-link/OTP vertical lands?

---

## 9. Recommended next investigations (not a design)

1. **Prototype-signature spike (no commit):** sketch B/D trait deltas (`NewUser` associated type vs generic param vs separate `UserFactory` trait) and count every impl/test/doc touch, the breakage inventory decides whether B/D ships pre-1.0 or behind an additive method.
2. **DB-generated-ID walkthrough:** trace an AUTOINCREMENT-UUID store through atomic-provision + rate-limit + dummy-verify to find where the generated ID must surface.
3. **Adoption-mode walkthrough:** trace "user row already exists, attach credential" (SSO-link, admin-created users, imports), currently impossible via `provision` (`false` on duplicate id); determine required new verb.
4. **`email()` removal impact:** confirm no downstream (dioxus layer, server fns, examples) reads `email()` semantically, then decide: remove, repurpose as `login_label`, or keep as display hint.
5. **Conformance-suite hardening:** before any redesign, pin single-table stores, multi-identifier behavior, and touch-resurrection in tests so B/D/E alternatives are verifiable, not aspirational.
6. **Persona walkthrough scripts:** write the three 10-minute scripts (beginner memory-only, normal existing-DB, advanced split-store + custom hasher/limiter) against each candidate API and compare concept count, not line count.
