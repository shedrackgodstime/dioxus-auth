# dioxus-auth: architectural conclusion

## 1. Core model

`dioxus-auth` separates application identity/data from authentication:

```text
Application identity/data
        │
        ▼
      User
        ▲
        │ application key
        │
Authentication credentials
        │
        ├── email/password
        ├── OAuth/OIDC
        ├── passkey
        ├── magic link / OTP
        └── future methods
```

Authentication methods are credentials attached to an application identity.
They are not separate application users.

Internally, the library may represent authenticated identity as an auth
subject, because that abstraction serves the authentication and session
machinery. That is an internal architectural concept, not the
developer-facing model. A developer using the high-level API must not
have to understand `AuthSubject`, `SubjectStore`, credential-storage
internals, authentication IDs, or a mandatory subjects table.

The physical database representation is an implementation concern. A
subjects table is therefore NOT an architectural requirement.

## 2. Ownership is settled

The application owns its `User` model, User table, application data,
primary keys, database, application transactions, and application queries.

`dioxus-auth` owns authentication credentials, credential verification,
credential lifecycle, sessions, authentication security, and the
association between credentials and application identities.

Auth must not become the owner of arbitrary application User fields. This
is a fundamental architectural boundary. But application ownership does
not mean the developer must manually perform every persistence operation
forever: a future high-level adapter layer may coordinate
application-owned User creation once the developer has supplied enough
schema and model information for the library to do so safely. The
ownership boundary is about who owns the model and data, not about who
mechanically executes every SQL statement. Do not conflate ownership
with orchestration.

## 3. Direction D is the ownership-preserving primitive, not the final UX

The transaction-scoped authentication claim is the key architectural
discovery:

```text
let tx = conn.transaction()?;
tx.execute("INSERT INTO users (...) VALUES (...)", ...)?;
auth.<claim-operation>(&tx, identifier, secret, user.id)?;
tx.commit()?;
```

The exact public method name is not finalized. The application starts the
transaction, creates its User with its own persistence logic, obtains its
own primary key, asks auth to attach authentication to that identity, and
commits. Auth never begins, commits, or rolls back; never creates the
application User in this primitive; never writes application columns;
never requires an auth-owned identity table. This yields atomic
application-user plus credential creation while preserving application
ownership.

Critical clarification: this primitive is the foundation, not the final
custom-database signup UX. It proves the architecture preserves ownership
without forcing developers into the internal subject and storage model.
It does NOT mean the intended high-level API is permanently manual
INSERT plus manual claim.

## 4. The high-level signup goal is preserved

For a developer who owns their User model and database, the eventual
high-level experience must be able to approach:

```rust
auth.sign_up_email(
    "alice@example.com",
    "password",
    UserData {
        name: "Alice",
    },
)?;
```

after the developer has supplied whatever minimal schema and database
configuration is actually necessary. Conceptually: "here is my database,
here is my User model, here is how it is identified," after which
dioxus-auth orchestrates authentication around that application-owned
model, internally performing the equivalent of application-User creation
plus credential creation plus association plus transaction atomicity,
without changing ownership of the model. The exact adapter mechanism is
not finalized. `UserData` is not claimed as implemented for arbitrary
databases. Classify this as a preserved high-level DX requirement and
future API and adapter work, built on the Direction D foundation. This
requirement must not be lost from the architectural record.

## 5. Ownership and orchestration stay separate

Ownership (User, schema, data, database, model): the application.
Orchestration (User creation, credential creation, association,
transaction boundaries): providable by a higher-level dioxus-auth
integration without transferring ownership. Direction D is the
lower-level ownership-preserving primitive; the future high-level API
builds above it. Because auth orchestrates an operation, auth does not
own the data.

## 6. The application key is the relationship

The developer's mental model is: "this is my User's ID." Not: "this is
my auth ID." The application key may be `i64`, `Uuid`, or another
application-defined key type; the rest of the User model (`email`,
`name`, `avatar_url`, `organization_id`, and so on) is completely
outside auth, which must not care about those fields. Even where an
implementation internally reuses the same value for its subject key,
that equality is an implementation property, never the public contract,
so a future representation can introduce a separate subject identity
without disturbing developers.

## 7. Key-returning primitives are fundamental

The underlying authentication API operates in terms of the application
identity: authenticate yields the application key, session validation
yields the application key. The library must not require knowledge of
the application's `User` model merely to authenticate or validate. A
higher-level convenience may resolve session to key to `User`, but that
convenience must not replace the key-returning primitives. Both layers
remain possible.

## 8. The optional loader is convenience, not architecture

A configured User loader (login and session restore yield key, loader
yields `User`) can remove repetitive resolution from application code.
But it must not make auth own the User, make the model part of auth's
core, eliminate key-returning APIs, or turn persistence into an auth
concern. Its exact shape, including sync and async behavior, remains API
refinement, which is not architectural uncertainty.

## 9. Two Dioxus experience levels

There are two legitimate levels, and both must stay documented. The
foundation-level custom flow (request, application transaction, create
User, auth claim, commit) is the ownership-preserving primitive and is
valid before any higher-level orchestration exists. The target
high-level flow (`sign_up_email` with `UserData` over configured
application persistence, one atomic operation) is a real project goal,
not an optional convenience, with its exact API still open. Do not lose
either.

## 10. Protected-request lifecycle

Protected request to session cookie or token, to session validation, to
application key, to application User resolution, to Dioxus UI. The
developer works at key level or `User` level depending on the surface
chosen.

## 11. Multiple methods preserve the model

User 42 may hold email/password, Google, passkey, and further
credentials. Adding a method must not require another application User
or expose the internal subject model. Future methods build on the same
identity relationship. Nothing beyond email/password is implemented now;
the requirement is only that the architecture not need redesigning when
methods arrive.

## 12. Low-level traits remain the advanced escape hatch

The subject, credential, and session storage machinery already
implemented is not thrown away. The intended experience is tiered:
bundled simple usage; own User plus own DB with a high-level configured
experience built on Direction D primitives; raw and custom storage
machinery for complete control. The low-level traits must not become
the normal graduation path for a developer who simply wants
authentication on an existing User model. Hide complexity through a
better integration layer; keep the lower-level capability.

## 13. What the architecture does NOT require

No developer must: create a subjects table; expose `AuthSubject`;
create an auth-specific User model; generate authentication IDs;
implement storage traits merely to use their own User table; give auth
ownership of application data; maintain separate signup APIs per User
customization; or understand credential-storage internals. Likewise,
manual INSERT plus manual claim is the current foundation primitive,
not the final UX: the eventual high-level API may abstract that
orchestration without violating ownership.

## 14. Implementation status, grounded in the repository

Implemented (compiles, full gate green on all feature combos;
subject-remodel work currently uncommitted, pending review):
library-owned `AuthSubject` with `SubjectStore`, `CredentialStore`,
re-keyed `SessionStore`, and `UserStore` repurposed as the app-side
resolver; engine auth-pure with enumeration defense and session
semantics intact; facade verbs including `sign_up_email`,
`sign_in_email`, `attach_email_credential`, `change_password`, plus
auth-space `sign_up_subject`; narrowed `AuthUser` (no `email`);
`DefaultStore` and `MemoryStore` covering memory paths; Dioxus runtime
and fullstack layers; conformance suites pinning the new traits.

Honest gaps against this document: the SQLite reference is still
physically R2-shaped (it has a subjects table); the R1 reference shape
is decided but not yet migrated. No tx-scoped claim operation exists
yet; provisioning still runs in store-owned transactions. Reads resolve
through `UserStore`; key-returning primitives are specified, not yet
exposed. No loader, no options type, no hash import, no `ensure_schema`,
no adapters beyond the bundled stores.

Architecturally decided (settled, implementation pending or in flight):
R1 as the reference physical representation; dev-owned-transaction
claim primitive with the stated contract; key-returning reads as the
primitive with resolver conveniences beside them; options-channel shape
for progressive control; physical DDL details.

API refinement (direction settled, exact Rust API open): claim method
name and signature; high-level configured persistence API; loader API
including sync and async shape; ergonomic signup surface.

Future scope (not implementation requirements): additional methods
(OAuth/OIDC, passkeys, magic links, OTP, API keys, custom methods).

## 15. North star

Simple by default, flexible when needed, no duplicated signup API
matrix, application ownership preserved. The ideal remains
`sign_up_email(email, password, UserData { ... })` for developers who
want high-level convenience, with complete control available from the
lower-level primitives. The project does not choose between simple and
flexible. The architecture supports both through layers.

## 16. Architecture statement

`dioxus-auth` is an authentication and session layer around an
application-owned identity. The application owns its User model,
database, data, and identity keys. Authentication credentials and
sessions belong to dioxus-auth. Internally, the library may represent
authenticated identity as an auth subject, but that abstraction does
not define the developer-facing model or require a particular physical
schema.

Direction D provides the ownership-preserving transaction primitive:
the application can create its User and have dioxus-auth attach
authentication to that identity atomically within the application's
transaction.

Above that primitive, the project continues toward a higher-level
configured experience where a developer can provide their database and
User schema once and use simple operations such as
`sign_up_email(..., UserData)` without manually orchestrating User
creation and credential attachment for every operation.

The lower-level primitives remain available for complete control. The
goal is therefore not to choose between simplicity and flexibility,
but to provide both as layers over the same architecture.
