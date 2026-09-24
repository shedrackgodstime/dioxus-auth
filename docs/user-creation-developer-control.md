# Deep Investigation: User Creation & Developer Control

## A. What we know for certain

* `sign_up_email(id, pw, user)` takes a fully-built `D::User` (`src/methods.rs:188`). Engine only hashes pw, normalizes identifier (`src/login.rs:28`), calls `provision_user_with_password(user, normalized, hash)` (`src/store/user.rs:80`).
* Engine never generates/mutates user IDs. It only reads `user.id()` inside stores for dup-check + FK (`src/store/memory.rs:207`, `examples/sqlite-reference/src/lib.rs:302`).
* `AuthUser` has no factory/setter, only `id()`, `email()`, `session_auth_hash()` (`src/user.rs:19`). Library cannot construct `AppUser`.
* `provision → bool`, not `User`. Store can only accept/reject, never return a created user. Facade returns the caller-built object.
* `.email()` has zero callers in `src/`. Identifier travels as separate `&str`; the two emails are never compared (proven by `TestUser{name:"bob"}` + identifier `"bob@example.com"` test).
* Engine needs from `User`: `id()` for `Session.user_id` (`src/login.rs:204`), `find_by_id` on validate/logout, `session_auth_hash()` for rotation. Nothing else.
* `Auth<D>` forces one dual-role store (`src/auth.rs:22`); `AuthEngine<U,S>` allows split stores. No SQL/table names in `src/`, 4-table shape is example-only.

## B. The actual architectural seam

The forcing function is one signature:

`provision_user_with_password(user: Self::User, ...) -> bool`

Because input is a complete `User` and output is `bool`, construction + ID choice must happen caller-side. Store can't mint IDs (no return channel), library can't build users (no factory bound). Change that signature and the whole ownership question reopens; keep it and Models B–D are impossible.

## C. What the library actually needs

* Signup: normalized lookup key + hash + a storable owner key. Not a full `User`.
* Signin/validate/ownership: `Id` → `find_by_id → User` + optional `auth_hash`.
* Conclusion: complete `AppUser` is a persistence/application object passed *through* auth, not an auth input. `name/avatar/role/org` are opaque payload the engine clones/carries.

## D. Possible ownership models

1. **App owns User+ID:** status quo. Best control, worst beginner DX. Works with existing DB/IDs trivially.
2. **Library owns User+ID by default:** best beginner DX, but library enters PK business (UUID vs int vs DB key) and must understand custom fields to construct `AppUser`, breaks "you own data" unless narrowly scoped to `DefaultUser`/memory path.
3. **Store owns creation+ID:** cleanest separation, engine orchestrates, store maps `NewUser→User`. Handles DB-generated IDs, existing tables, external IdPs. Costs a new input associated type + breaks all stores/tests.
4. **Default path owns creation, custom stores own theirs:** same as 3, but beginner path (memory/default store) gets ID-free convenience while custom stores keep full control. One engine, two construction policies. Most aligned with "same system, different control levels", most trait surface to design.

## E. API shapes worth exploring

1. Current: `sign_up(email, pw, AppUser{id,email,..})`, baseline.
2. Input type: `sign_up(email, pw, NewUser{name,..}) -> (User, session)`, store builds `User`, returns it.
3. Adopt mode: `attach_credential(existing_user_id, email, pw)`, separates "create user" from "add login", needed for imports/SSO/admin-created rows (currently impossible: dup id → `false`).
4. ID-strategy hook: `builder().id_generator(...)` layered over 2/3, preserves UUID/int/DB-key/external choice.
5. Minimal default: `Auth::memory().sign_up_default(email, pw, name)`, ID-free quickstart without touching generic path.

## F. Questions before choosing

* `NewUser` vs `User`: new associated type, generic param, or separate factory trait? Who defines it per-app?
* Does `provision` return `User` (store-generated IDs visible) or `bool`?
* Is `email()` removed, made optional, or replaced by opaque identifier? Who owns uniqueness scope (global/per-provider/per-org)?
* Multi-identifier-per-user allowed or not? (Today: `update_password` assumes yes, provision docs say no.)
* Create-user vs attach-credential: one verb or two?
* Must app-supplied IDs still work alongside generated ones?

## G. Observations (inference, not fact)

* `DefaultUser` looks like compensation for "library can't create users" rather than a permanent concept, a genuinely minimal path wouldn't ask for `id: 1`.
* The duplicated-email is the sharpest smell: two sources of truth for one identifier with no check implies neither layer truly owns it yet.
* Create-vs-attach conflation is the hidden blocker for existing-DB adoption, bigger than ID generation alone.
