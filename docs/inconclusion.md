Yes. Before folding the investigation into the decisions document, I want the entire original signup/API vision carried forward, not just the storage/identity conclusions.

The identity investigation exists to support the developer experience we started with. The final design should connect both.

---

1. Signup should fundamentally be simple

Signup primarily needs:

- email
- password

That is the common case.

The canonical developer experience should therefore be:

auth.sign_up_email("alice@example.com", "password");

The developer should not have to think about IDs, password hashing, authentication records, sessions, or internal auth structures just to create an account.

Conceptually, the library does:

email + password
       ↓
create auth subject
       ↓
generate auth_id
       ↓
hash password
       ↓
attach credential to subject
       ↓
optionally establish application association
       ↓
create session

The important correction from our later investigation is that this "auth_id" is not an email-specific ID.

It belongs to the universal authentication subject.

---

2. The auth subject exists independently of the authentication method

The same underlying subject model must work for every authentication method we support now or later:

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

The authentication method is a credential attached to the subject, not the identity itself.

Therefore:

- one subject may have multiple credentials;
- password + Google can belong to the same subject;
- a credential can be added/revoked/rotated independently;
- an anonymous subject can exist before it has credentials;
- future authentication methods use the same subject model;
- the auth ID is universal across all of them.

This also means developer-controlled IDs are not an email-signup feature.

The developer is controlling the auth subject's ID.

The same control must remain conceptually available regardless of whether the subject is created through email, OAuth, passkey, migration, or another supported method.

---

3. The library owns the auth identity by default

Normally:

auth.sign_up_email("alice@example.com", "password");

means the library generates the auth subject ID.

The developer does not need to provide one.

But if the application already has an ID strategy or is adopting an existing identity, the developer should be able to take control:

SignupOptions {
    id: Some(user_id),
    ...
}

The exact Rust syntax is still open.

The important rule is:

«Library-generated auth identity is the default. Developer-controlled identity is an explicit override.»

Custom IDs must not become a prerequisite for normal signup.

---

4. Application data is separate from authentication

The developer will often want to create/attach application-specific information during signup:

- name
- avatar
- username
- display name
- organization ID
- application metadata
- an existing application user/account/customer reference

The developer should be able to express that naturally without making "dioxus-auth" understand every possible application model.

Conceptually:

auth.sign_up_email(
    "alice@example.com",
    "password",
    UserData {
        name: "alice",
        avatar: Some("image.png"),
    },
);

Or another ergonomic form if the eventual Rust API supports it.

The exact syntax is not decided.

The architectural rule is:

«Email/password are authentication concerns. Application data belongs to the application.»

"dioxus-auth" should provide the mechanism for establishing the association, but should not become the owner/interpreter of the application's "User" model.

---

5. The two relationships must remain separate

The investigation established that there are two different relationships:

Auth Subject
    │
    ├────────────── credentials
    │              email
    │              Google
    │              passkey
    │              API key
    │              ...
    │
    └────────────── application association
                   app_ref
                       ↓
               application-owned data

Credential → Auth Subject

Many credentials can belong to one auth subject.

This is an authentication concern.

Auth Subject → Application Data

One auth subject has its application association.

This is an application boundary concern.

Therefore "app_ref" should not be duplicated onto every credential row.

The application association belongs to the subject, not to the individual authentication method.

---

6. The auth layer must not own the application's User model

The library should not turn:

auth_id → application User

into an internal assumption that every application has a particular "User" type.

Instead, the authentication layer deals with auth-space information:

AuthSubject {
    auth_id,
    app_ref,
    auth-related state,
}

The application decides what "app_ref" means and how it resolves it:

app_ref → User
app_ref → Customer
app_ref → Account
app_ref → Member
...

The application's queries, caching, model structure, and domain logic remain application-owned.

The physical storage representation of this relationship remains open.

---

7. Additional data should not force an API matrix

The API should not evolve into:

sign_up_email()
sign_up_email_with_id()
sign_up_email_with_data()
sign_up_email_with_hash()
sign_up_email_with_id_and_data()
sign_up_email_with_id_and_hash()
...

That defeats the entire purpose of the API.

The intended progression is:

Simple
  ↓
email + password
  ↓
email + password + application data
  ↓
custom auth ID
  ↓
pre-hashed credential
  ↓
other advanced controls

All through one primary operation with one options/extension mechanism.

The exact shape, options struct, builder, or another Rust-native mechanism, remains an API investigation.

But one verb + progressive control is the design constraint.

---

8. Custom password hashes are an advanced override

Normally:

auth.sign_up_email("alice@example.com", "password");

means the library handles password hashing.

The normal developer should never need to know or provide the hash.

But migration/import scenarios may already have a valid password hash:

SignupOptions {
    password_hash: Some(existing_hash),
    ...
}

That should be an advanced override, not a separate authentication system.

The same underlying subject/credential model remains in use.

---

9. The final developer experience should feel progressive

The developer should be able to start here:

auth.sign_up_email("alice@example.com", "password");

and stop there.

If they need application data:

auth.sign_up_email(
    "alice@example.com",
    "password",
    UserData { ... },
);

If they need a specific auth identity:

SignupOptions {
    id: Some(existing_id),
    ...
}

If they are migrating an existing credential:

SignupOptions {
    password_hash: Some(existing_hash),
    ...
}

And if they eventually need a more advanced provider or custom store, they should still be working with the same authentication subject/credential model, not switching to another conceptual auth system.

---

10. The complete architectural picture

The mental model I want the project to preserve is:

                         AUTH SYSTEM
                              │
                         Auth Subject
                           auth_id
                              │
              ┌───────────────┴────────────────┐
              │                                │
        Credentials                      App Association
        many → one                          one → one
              │                                │
    email/password                         app_ref
    OAuth                                    │
    OIDC                                     ↓
    passkey                          Application-owned
    API key                         User / Account / etc.
    future methods

With the developer experience layered on top:

                     SIMPLE
                       │
          email + password
                       │
                       ↓
              library defaults
              auth_id + hashing
                       │
             ┌─────────┴─────────┐
             ↓                   ↓
      application data       custom auth ID
             │                   │
             └─────────┬─────────┘
                       ↓
                advanced options
                       │
                 hash import
                 provider data
                 future controls

Core principle

«"dioxus-auth" owns the authentication identity and credentials by default. It generates what the developer does not care about, accepts what the developer explicitly wants to control, and provides a clean mechanism for associating application-owned data without owning the application's user model.»

The developer should be able to think:

«"I only need email and password, so I only provide email and password."»

And later:

«"I need my own auth ID."»

or:

«"I need to attach my application's user data."»

or:

«"I'm migrating an existing password hash."»

without changing authentication models or learning a completely different API.

---

So when you fold this into the decisions document, please preserve both sides of the design:

1. The developer-facing vision: simple signup → progressive control → one API, no matrix.
2. The architectural foundation: universal auth subject → many credentials → separate application association → application-owned user model.

The second exists to make the first possible without creating the identity/model coupling we had before.

Keep physical schema decisions, exact trait signatures, "AuthUser" fate, auth-ID type/generation, options API shape, and hash-import semantics as downstream investigations.




v0.1.0 only implements email/password signup. Future authentication methods are planned, but are intentionally out of scope for this release. The architecture must nevertheless model authentication around a universal auth subject with credentials attached to it, rather than making email the identity itself.
The public DX should remain as simple as sign_up_email(email, password), with the same extension mechanism available for application data and advanced controls. We should not create separate APIs for every combination of options.
At the same time, don't assume that every future authentication method must be implemented by the core library. The design should leave room for adapters or developer-defined/custom authentication flows that can establish or authenticate an auth subject and then use the same session/application-association machinery.
In other words: implement only email/password now, but make the underlying identity/session architecture method-agnostic. Email is the first credential type, not the definition of the user.
