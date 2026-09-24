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
- Create/attach split (`provision` + `attach_password_credential`,
  `sign_up_email` + `attach_email_credential`): stands, adoption,
  second logins, SSO-link, and the migration target from §7.
- `provision → NewUser → Option<User>` + `DefaultStore`: the mechanism
  stands, repositioned as one override path (custom stores that
  mint/adopt identity), not the model. Build nothing further on it until
  the mapping investigation lands.

## Open investigations (downstream, in order)

1. Store mapping of auth identity ↔ application identity (physical home,
   atomicity, existing-DB adoption patterns).
2. Bidirectional lifecycle queries (subject deletion cascades, session
   revocation from the app side).
3. Exact trait signatures for the subject/credential/association surface.
4. `AuthUser` fate (loader contract in outer layers vs dissolve into
   `app_ref` + app helpers).
5. Auth-ID type and generation (counter vs random vs UUID).
6. Options-channel shape (struct vs builder, extension without breakage).
7. Hash-import semantics (verify-before-accept, session handling,
   privilege requirements).
8. Adapter surface for developer-defined auth flows (what core exposes
   so custom methods reuse subject/session machinery).

## Current Design Principle

> **`dioxus-auth` owns the authentication identity and credentials by
> default. It generates what the developer does not care about, accepts
> what the developer explicitly wants to control, and provides a clean
> mechanism for associating application-owned data without owning the
> application's user model.**
