dioxus-auth — post-checkpoint implementation directive

The architecture checkpoint is accepted.

The current implementation is converging correctly. Do not reopen the architecture, redesign the subject model, or restart the investigation.

The architectural conclusion remains authoritative.

1. What is now settled

The following are architectural decisions, not questions for further investigation:

- Application identity/data is owned by the application.
- dioxus-auth owns credentials, authentication security, and sessions.
- AuthSubject is an internal authentication abstraction, not the developer-facing identity model.
- A subjects table is not architecturally required.
- R1 is the reference physical representation.
- Credentials and sessions can bind directly to the application's identity key.
- The application key is the developer-facing relationship.
- The application may use "i64", "Uuid", or another appropriate key type.
- The application owns its database and transaction.
- The transaction-scoped authentication-association primitive operates inside the application's transaction and never begins, commits, or rolls it back.
- Key-returning authentication/session primitives are fundamental.
- User resolution is a convenience layer.
- Low-level storage traits remain available as an advanced escape hatch.
- The normal custom-DB path must not require developers to implement a large storage-trait surface.
- The eventual high-level custom-DB experience must be able to approach:

auth.sign_up_email(
    "alice@example.com",
    "password",
    UserData {
        name: "Alice",
    },
)?;

after the developer has supplied the necessary application persistence/model configuration.

That last point is important:

manual INSERT + authentication association is the foundation primitive, not the final custom-database signup UX.

The eventual high-level layer may orchestrate application User creation, credential creation, association, and transaction atomicity without taking ownership of the application's User model or data.

Do not lose or weaken this requirement.

---

2. Current implementation reality

The checkpoint established:

Already working

- R1-shaped SQLite reference.
- No subjects table in the reference representation.
- Credentials/sessions keyed by application identity.
- Caller-owned transaction claim implementation in the reference.
- Key-returning login/validation primitives.
- Existing authentication/session security semantics.
- "attach_current".
- "change_password".
- Runtime/server/macro integration for those operations.
- Conformance and wire-level tests.
- Enumeration defenses.
- Fail-closed application-user resolution.
- Session-based privilege for authenticated operations.
- Database-independent core.

Known boundary cleanup

The checkpoint found:

- "claim", "claim_hash", and "signup_with" became public names in the reference crate even though "claim" was originally only a working architectural term.
- Some engine-level APIs still expose "AuthSubject".
- "i64" is currently threaded through the reference implementation.
- MemoryStore intentionally retains R2-shaped subject machinery for trait/conformance purposes.

These are not architecture failures.

Do not let them trigger another redesign.

---

3. Immediate priority: build the D spine

The next implementation phase should focus on the developer-experience spine.

The intended progression is:

R1 representation
      ↓
transaction-scoped auth association
      ↓
key-returning authentication/session primitives
      ↓
configured application persistence
      ↓
high-level signup orchestration
      ↓
loader/convenience

The goal is to make the lower-level architecture capable of supporting the simple high-level experience, rather than stopping at the lower-level primitive.

---

4. First priority: high-level application persistence / UserData path

This is the most important remaining product-level requirement.

We need to move from:

INSERT User
claim authentication
commit

toward a configured high-level experience conceptually equivalent to:

auth.sign_up_email(
    email,
    password,
    UserData { ... },
)?;

The exact Rust API is still open.

Do not invent a final API merely to satisfy the example.

Instead:

1. Inspect the current implementation.
2. Determine what information a developer must configure once for dioxus-auth to understand their application User persistence.
3. Determine how that configuration can remain application-owned.
4. Determine how the high-level operation can orchestrate:
   - application User creation;
   - credential creation;
   - application-key association;
   - atomic transaction behavior.
5. Preserve the lower-level transaction primitive underneath.
6. Avoid requiring the developer to repeat raw INSERT + claim for every signup.
7. Avoid creating a matrix of separate signup APIs for different User shapes.
8. Avoid forcing "AuthSubject", "SubjectStore", credential-storage internals, or an auth-specific User model into the normal path.

The resulting mechanism should remain thin.

Do not turn this into a generic ORM or application-data framework.

dioxus-auth only needs enough integration to coordinate authentication around the application's User identity.

---

5. Do not overbuild future authentication methods

The checkpoint classified custom method families + verify dispatch as part of the architectural spine.

Re-evaluate that classification before implementing substantial new machinery.

Separate these three things:

A. Architecture requirement

The identity model must allow:

User 42
 ├── email/password
 ├── OAuth/OIDC
 ├── passkey
 ├── magic link
 └── future credentials

without creating another application User.

This is already settled.

B. Reusable internal infrastructure

It is reasonable to prepare infrastructure that makes future authentication methods fit the same credential model.

Only build this if it directly supports the current architecture and does not complicate the current API.

C. Actual future authentication methods

Do NOT implement OAuth/OIDC, passkeys, magic links, OTP, API keys, or other method families now unless explicitly requested.

They remain future scope.

Do not allow "future extensibility" to become a reason for unnecessary abstractions in v0.1.

---

6. API naming discipline

The architectural operation is settled:

«attach authentication credentials to an existing application identity inside a caller-owned transaction.»

The public name is NOT architecturally settled.

"claim" was a working term and has accidentally become a reference-crate API name.

Before stabilizing/releasing this surface:

- do not treat "claim" as sacred;
- evaluate whether the terminology communicates the operation clearly;
- do not create aliases or a naming matrix merely to preserve every experimental name;
- keep the ability to rename pre-1.0.

The same applies to "claim_hash" and "signup_with".

The important thing is the semantics, not the current spelling.

---

7. AuthSubject boundary

Do not redesign the internal subject model.

However, maintain the intended boundary:

Normal developer-facing code should not need to understand:

- "AuthSubject";
- "SubjectStore";
- auth IDs;
- subject minting;
- subject translation;
- credential-storage internals.

Key-returning APIs should remain the normal primitive.

If engine-level return types can be cleaned up without architectural disruption, prefer application-key-oriented results.

But do not perform a broad refactor solely to eliminate every internal "AuthSubject" occurrence.

Advanced APIs may expose lower-level concepts where deliberate.

---

8. Database independence

Keep the architecture database-independent.

SQLite/rusqlite is currently the reference implementation only.

Do not:

- move rusqlite into core;
- make SQLite semantics part of the public architectural contract;
- assume every backend has the same transaction API;
- design the whole library around rusqlite types.

Backend-specific transaction adapters are acceptable.

The core contract remains:

application-owned database
        ↓
application-owned transaction
        ↓
auth operates within that transaction
        ↓
application controls commit/rollback

Future PostgreSQL, MySQL, or other adapters must remain possible without changing the ownership model.

Do not build those adapters now unless explicitly requested.

---

9. ID type

Do not prematurely redesign the entire system around generic IDs.

The current "i64" reference is acceptable as a reference implementation while the architecture is being exercised.

However:

- do not describe "i64" as an architectural requirement;
- do not make the developer-facing architecture depend conceptually on "i64";
- do not introduce a complicated generic-ID framework merely because future IDs may be "Uuid".

ID-type selection remains API refinement/future implementation work.

---

10. Loader

A loader remains a convenience layer.

Conceptually:

session
  ↓
application key
  ↓
configured User loader
  ↓
User

It must not:

- make User part of auth's core;
- replace key-returning primitives;
- make the application database an auth-owned concern.

Do not implement a complicated loader abstraction before the high-level persistence path is understood.

Sync/async shape remains API refinement.

---

11. Options

Keep the options channel progressive.

Do not create a large configuration/options matrix just to anticipate every future authentication method.

The beginner path should remain small.

Advanced control can be added through options without multiplying public methods.

---

12. Storage traits

Keep:

- SubjectStore;
- CredentialStore;
- SessionStore;
- related low-level storage interfaces

as advanced/custom machinery where they are useful.

But preserve this graduation path:

Simple bundled usage
        ↓
Own User + own DB
        ↓
High-level configured integration
        ↓
Raw storage/custom control when actually needed

Do NOT turn:

own User + own DB

into:

implement 10–14 storage methods

That was one of the problems this architecture was explicitly intended to eliminate.

---

13. Testing requirements

Every implementation step must preserve the architectural invariants.

In particular test:

Ownership

Auth does not create arbitrary application fields.

Atomicity

Application User creation + authentication association can succeed or fail atomically through the caller-owned transaction.

Identity

Credentials attach to the application's identity rather than creating separate application Users.

Security

Existing:

- password hashing;
- normalization;
- enumeration defense;
- dummy verification;
- session rotation;
- expiry;
- fail-closed resolution;
- origin protection;
- redacted request/debug output

must remain intact.

Backend boundary

The core must not acquire SQLite-specific dependencies.

DX

The high-level custom-DB path must not require knowledge of:

- AuthSubject;
- SubjectStore;
- authentication IDs;
- credential-storage internals.

---

14. What NOT to do now

Do not:

- reopen R1 vs R2;
- restore a mandatory subjects table;
- redesign AuthSubject;
- build a generic ORM;
- build all future authentication methods;
- add PostgreSQL/MySQL implementations now;
- create a generic ID framework prematurely;
- create multiple signup APIs for different User models;
- make manual INSERT + claim the declared final UX;
- require storage-trait implementations for ordinary custom-DB users;
- expand the API merely because an abstraction might be useful someday;
- perform release mechanics yet.

---

15. Definition of success for this phase

The phase is successful when the architecture can support both:

Foundation-level control

application transaction
      ↓
application creates User
      ↓
auth attaches credential
      ↓
application commits

and the eventual high-level experience:

configured application persistence
      ↓
auth.sign_up_email(... UserData)
      ↓
atomic User + credential creation

with both paths using the same underlying identity/authentication architecture.

The second path must be an abstraction over the first, not a competing authentication architecture.

---

16. Working method

Before changing code for each substantial step:

1. Inspect the relevant existing implementation.
2. State what architectural invariant the change is satisfying.
3. Make the smallest implementation change that advances the spine.
4. Run the relevant tests and full feature gate.
5. Inspect the resulting public API.
6. Check that no internal concept has leaked into the beginner path.
7. Update the relevant documentation in the same pass.

Do not accumulate another large speculative refactor.

Prefer small, verifiable increments.

---

17. Immediate next action

Start with the high-level application persistence / signup orchestration investigation and implementation boundary, using the existing R1 transaction primitive as the foundation.

Do not begin by designing a large adapter framework.

First determine the smallest configuration surface required for:

auth.sign_up_email(
    email,
    password,
    UserData { ... },
)?;

to be possible while preserving:

- application ownership;
- arbitrary application User fields;
- application-defined identity keys;
- atomicity;
- database independence;
- the lower-level transaction primitive;
- the simple beginner experience.

If the existing implementation already contains useful pieces for this, reuse them.

If something is genuinely unresolved at the API level, keep the mechanism internal/experimental rather than prematurely freezing a public abstraction.

After implementing the smallest coherent increment:

- run the full gate;
- report exactly what changed;
- report which architectural invariants were verified;
- report any remaining API decisions.

Do not ask to reopen the architecture unless an actual contradiction with the accepted architectural conclusion is discovered.

The architecture is settled.

Now build the spine.
