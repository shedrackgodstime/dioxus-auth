Signup API, Design Intent

Signup should fundamentally require only two pieces of information:

- email
- password

That is all a normal application should have to provide.

The user ID is owned by "dioxus-auth" by default. If the developer does not provide one, the library generates it automatically.

So the normal signup should be as simple as:

auth.sign_up_email("alice@example.com", "password");

The developer should not have to manually create an ID, construct an auth user model, hash the password, or understand internal authentication fields just to create an account.

---

But the API should remain flexible

The important part is that the simple API should not become a limitation.

A developer may want to attach application-specific data during signup:

auth.sign_up_email(
    "alice@example.com",
    "password",
    UserData {
        name: "alice",
        avatar: Some("image.png"),
    },
);

Or conceptually:

auth.sign_up_email(
    "alice@example.com",
    "password",
    name: "alice",
    avatar: "image.png",
);

The exact Rust syntax is still open for investigation. The important design requirement is:

«The developer should be able to provide additional application-owned data without having to manually create or manipulate the authentication user.»

"dioxus-auth" owns the authentication identity. The application owns additional user/profile/domain data.

---

Custom ID should be an optional override

Normally:

auth.sign_up_email("alice@example.com", "password");

means:

generate user ID
→ hash password
→ create authentication identity
→ create/attach application user data

But if the application already has its own ID strategy, it should be possible to provide the ID explicitly:

auth.sign_up_email(
    id: user_id,
    email: "alice@example.com",
    password: "password",
);

The developer should not need a completely different conceptual signup system just because they want to control the ID.

The default remains library-generated IDs; explicit IDs are simply an override.

---

Custom password hash should also be an override

The same principle applies to password hashing.

Normal signup:

auth.sign_up_email(
    "alice@example.com",
    "password",
);

The library owns the hashing process.

But an advanced use case such as migrating an existing authentication system may already have a password hash:

auth.sign_up_email(
    id: user_id,
    email: "alice@example.com",
    password_hash: existing_hash,
);

In that case, the library should be able to accept the already-hashed credential instead of requiring the developer to provide the plaintext password and hash it again.

This is primarily an advanced/migration capability, not something that should complicate the normal signup experience.

---

One API, progressively more control

The mental model should be:

                         ┌─ application data
                         │
email + password ────────┼─ custom user ID
                         │
                         └─ custom password hash

The simplest possible call:

auth.sign_up_email("alice@example.com", "password");

should remain the canonical path.

Then developers can progressively take control when necessary:

auth.sign_up_email(
    "alice@example.com",
    "password",
    UserData { ... },
);

or:

auth.sign_up_email(
    id: user_id,
    email: "alice@example.com",
    password: "password",
);

or for an advanced migration:

auth.sign_up_email(
    id: user_id,
    email: "alice@example.com",
    password_hash: existing_hash,
);

The exact syntax can change during API design. The important thing is the API philosophy, not these exact examples.

---

Avoid API duplication

Do not solve every combination by creating a separate function:

sign_up_email()
sign_up_email_with_id()
sign_up_email_with_data()
sign_up_email_with_id_and_data()
sign_up_email_with_hash()
sign_up_email_with_id_and_hash()
sign_up_email_with_hash_and_data()
...

That quickly becomes an API matrix.

Instead, there should be one obvious signup operation with a clean mechanism for optional/advanced inputs.

The API should make the common path extremely simple while allowing the developer to progressively opt into more control.

The developer should feel:

«"I only need email and password, so I only provide email and password."»

And later:

«"I need my own ID."»

or:

«"I need to attach my application's user data."»

or:

«"I'm migrating existing password hashes."»

None of those requirements should force them into a completely different authentication model.

Core principle

"dioxus-auth" owns authentication by default, but does not own the application's user model.

It should generate what the developer does not care about, accept what the developer explicitly wants to control, and provide a clean extension point for everything that belongs to the application.

The API should therefore optimize for:

simple by default → flexible when needed → no duplicated signup APIs → no unnecessary auth-model ceremony.
