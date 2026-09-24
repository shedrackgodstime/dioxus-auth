# dioxus-auth, User Creation & Developer Control

## The vision in one paragraph

Signup requires email + password:

```text
auth.sign_up_email("alice@example.com", "password");
```

Conceptually the library does: create auth subject → generate `auth_id` →
hash password → attach credential to subject → optionally establish the
application association → create session. That `auth_id` is not an
email-specific ID, it belongs to the universal authentication subject
(§2). Everything beyond email + password arrives through one options
channel, never a second auth system and never a matrix of verbs (§7).

## Core philosophy

- simple by default → flexible when needed → no duplicated signup APIs →
  no unnecessary auth-model ceremony.
- The library owns authentication identity and credentials by default. It
  generates what the developer does not care about, accepts what the
  developer explicitly wants to control, and provides a clean mechanism
  for associating application-owned data without owning the application's
  user model.

The developer should feel: *"I only need email and password, so I only
provide email and password"*, and later *"I need my own auth ID / my
app data / my hashes"* without changing authentication models.

## Finalized Decisions

### 1. The auth subject exists independently of the method

The same subject model serves every current and future method:

```text
email/password ─┐
magic link ─────┤
OTP ────────────┤
OAuth ──────────┤
OIDC ───────────┤
passkey ────────┤
API key ────────┤
anonymous ──────┘
                 ↓
            Auth Subject
               auth_id
```

The method is a credential attached to the subject, not the identity
itself. Therefore: one subject may hold many credentials; password +
Google can belong to the same subject; credentials attach/rotate/revoke
independently; an anonymous subject can exist before it has credentials;
future methods reuse the model; the auth ID is universal across all of
them. Developer-controlled IDs are subject-level control, not an
email-signup feature, the same override must stay conceptually available
whether the subject is created through email, OAuth, migration, or any
later method.

### 2. The library owns the auth identity by default

Normally signup means the library generates the subject ID; the developer
provides none. Control is an explicit override (`SignupOptions`-style
`id: Some(…)`, exact syntax open). Rule: *library-generated auth identity
is the default; developer-controlled identity is an override.* Custom IDs
must never become a prerequisite for normal signup. This flips the
earlier "store owns ID generation" direction: store/database/app
strategies hang off the same verb as overrides, they are not the source.

### 3. Application data is separate from authentication

Signup commonly carries app-owned data (name, avatar, username,
organization, metadata, an existing app user/customer reference). The
developer expresses it naturally (e.g. alongside a `UserData` value);
the library provides the *mechanism* for establishing the association
without understanding or interpreting the model. Rule: *email/password
are authentication concerns; application data belongs to the
application.*

### 4. The two relationships stay separate

```text
Auth Subject
    │
    ├────────────── credentials (many → one, auth concern)
    │              email / Google / passkey / API key / …
    │
    └────────────── application association (one → one, boundary concern)
                   app_ref → application-owned data
```

`app_ref` lives on the subject's association, never duplicated onto
credential rows, per-credential copies could disagree and make identity
method-dependent, contradicting §1. Credential rows carry `auth_id` plus
method material only.

### 5. The auth layer must not own the application's User model

The layer deals in auth-space information:

```text
AuthSubject { auth_id, app_ref, auth-related state }
```

and the application resolves the reference however its domain demands
(`app_ref → User / Customer / Account / Member / …`), keeping its
queries, caching, and model evolution. The engine consumes only
auth-space material (owner key, credential binding); it never reads the
model. The physical storage representation of the association stays open.

### 6. One verb, progressive control, no matrix

Forbidden: `sign_up_email_with_id`, `sign_up_email_with_data`,
`sign_up_email_with_id_and_hash`, …, the matrix is how simplicity dies.
The intended progression, one primary operation with one
options/extension mechanism (struct, builder, or another Rust-native
form, shape still open):

```text
email + password
  → + application data
  → + custom auth ID
  → + pre-hashed credential
  → future controls
```

### 7. Custom password hashes are an advanced override

Normal signup always hashes; the developer never sees the hash. Migration
and import may supply `password_hash: Some(existing)` instead of
plaintext, same subject/credential model, not a separate system.

### 8. v0.1.0 scope: email/password now, method-agnostic underneath

v0.1.0 implements email/password signup only. The identity/session
architecture is nevertheless built around the universal subject, not
around email: email is the first credential type, not the definition of
the user. Future methods are out of scope for this release, and not
every future method must live in the core library. The design leaves
room for adapters and developer-defined flows that establish or
authenticate a subject and then reuse the same
session/association machinery.

## Where the implemented work stands

- `AuthUser::email()` cut: stands, needed under any variant.
- Create/attach split (`provision` + `attach`, `sign_up_email` +
  `attach_email_credential`): stands, adoption, second logins, SSO-link,
  and the migration target from §7.
- Subject remodel: IMPLEMENTED (uncommitted, full gate green on all
  feature combos). Engine is auth-pure over `AuthSubject`; `UserStore`
  survives as the app-side resolver called by facade and runtime layers
  only; `Session.user_id` is now `auth_id`; `update_password` is now
  `rotate_secret`; `MemoryStore` keeps its prototype-resolver role;
  new facade verb `sign_up_subject` returns auth-space material for
  attach/migration flows. `NewUser` evolved into link-aware `AppSetup`.

## Open investigations (downstream, in order)

1. Store mapping of auth identity ↔ application identity: RATIFIED
   as R1 and implemented in the reference adapter (app key serves as
   subject key; no subjects table; credentials and sessions keyed by
   app key with cascading deletes; binding derived from the current
   secret; proven by adoption, cascade, and lazy-binding flow tests).
   The association is the equality itself, so per-credential copies
   (method-dependent identity) and session-carried mappings (lost at
   expiry) never arise; auth-id app columns stay a documented
   single-table alternative. Precedent: better-auth's
   `account.userId`/`session.userId` FKs with cascade and no link table
   (their user row doubles as app container; ours keeps app rows
   auth-column-free). The subjects-table variant (P1) is superseded as
   the reference and kept only as the documented evolution path, with
   explicit triggers (guest auth, merge flows). Residual resolved: the
   app→auth direction is a single translation query composed with the
   existing idempotent deletes: no new atomicity class, no
   per-operation sprawl. The composition is safe because every act degrades benignly
   if the subject vanishes mid-flight (unknown-session logout,
   missing-session delete, and revoke-missing all succeed quietly;
   attach/change-password report `InvalidCredentials`). Admin delete,
   sign-out-everywhere, self-deletion, and admin-side attach all flow
   through translate-then-act; like attach, translation is privileged
   (authorize first). The `app_ref` carrier type (string vs generic)
   stays open with items 4 and 5.
2. Bidirectional lifecycle queries (subject deletion cascades, session
   revocation from the app side).
3. Exact trait signatures: IMPLEMENTED (uncommitted, gate green).
   As recorded, plus: `NewUser` became link-aware `AppSetup` (per-store
   signup material); new aliases `SubjectClaim`, `StoredCredential`,
   `AuthenticatedPair` carry the long auth-space types; `MemoryStore`
   keeps its prototype-resolver role (passthrough `AppSetup = User`,
   aliased seed subjects); new facade verb `sign_up_subject` returns
   auth-space material for attach/migration flows; resolve failures
   fail closed (`InvalidCredentials`) while store outages propagate.
   Method tag deferred past v0.1.
4. `AuthUser` fate: KEEP as the resolver-backed UI model marker. Verified:
   the engine never reads it (any `U` works with loaders), Dioxus and
   server layers hold it nominally (no method calls, no `Id`
   projections), and exactly one consumer needs the accessor (generic
   resolving stores keying app rows). Dissolving would scatter the same
   bounds unnamed across every use site. Trimmed as part of the verdict:
   dead `session_auth_hash` hook removed, unused `Hash` bound dropped
   from all four identifier types.
5. Auth-ID type and generation (counter vs random vs UUID).
6. Options-channel shape: IMPLEMENTED as one struct (`SignupOptions`
   with explicit id override; canonical verb unchanged beside
   `sign_up_email_with_options`; hash import stays a separate future
   so the struct never becomes a grab-bag).
7. Hash-import semantics: IMPLEMENTED as trust-based import
   (`import_email_credential` + `attach_imported_email_credential` +
   tx-side `claim_hash`; no verification possible without plaintext,
   so migration/admin-only with staged test-logins; no session minted;
   empty hashes rejected; pre-hashed secrets deliberately excluded
   from `SignupOptions`).
8. Adapter surface for developer-defined auth flows (what core exposes
   so custom methods reuse subject/session machinery).

## Current Design Principle

> **`dioxus-auth` owns the authentication identity and credentials by
> default. It generates what the developer does not care about, accepts
> what the developer explicitly wants to control, and provides a clean
> mechanism for associating application-owned data without owning the
> application's user model.**
