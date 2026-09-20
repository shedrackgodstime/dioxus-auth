# dioxus-auth

Authentication and session management for Dioxus.

Secure, reactive authentication for Dioxus fullstack applications.

You own the database, users, and data. **dioxus-auth** provides the authentication and session layer around them.

## Features

- Reactive auth state
- Session management
- Password & social authentication
- Route protection
- Server-side authorization
- Custom user and session stores
- Secure defaults

## Usage

Add "dioxus-auth" to your Dioxus application:

cargo add dioxus-auth

1. Enable authentication

Configure "dioxus-auth" with your application's user and session stores.

let auth = AuthEngine::builder(user_store, session_store)
    .password_auth(true)
    .build()?;

Your application owns the database and decides how users and sessions are stored.

2. Register and log in

Create a user with a password:

auth.register("alice", "s3cret")?;

Then log in:

let user = auth.login("alice", "s3cret").await?;

The session is created automatically after a successful login.

3. Log out

auth.logout().await?;

4. Use authentication in your app

Access the reactive authentication state from any component:

let auth = use_auth::<AppUser>();

if let Some(user) = auth.user() {
    rsx! {
        p { "Welcome, {user.username}" }
    }
}

Authentication state updates reactively when the user logs in or out.

5. Protect routes

Require authentication for protected routes:

require_auth();

rsx! {
    Dashboard {}
}

Unauthenticated users can be redirected to your login page.

6. Protect server operations

Authentication can also be checked on the server:

let user = require_user().await?;

Use the returned user for authorization and application logic:

let user = require_user().await?;

get_private_data(user.id).await?;

The same authentication state is used for both your UI and server-side operations.

7. Custom database

"dioxus-auth" does not own your database.

Bring your own user and session stores:

let user_store = MyUserStore::new(db.clone());
let session_store = MySessionStore::new(db);

let auth = AuthEngine::builder(user_store, session_store)
    .password_auth(true)
    .build()?;

Your existing database remains the source of truth for your application's users and data.

Other authentication methods

Password authentication is only one option. Social authentication can be added when needed.

See the documentation for configuring social providers and advanced authentication flows.

## Status

Early development. API may change before "1.0".

## License

MIT
