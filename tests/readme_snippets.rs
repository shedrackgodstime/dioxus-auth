//! Compile-checked mirrors of the README quickstart snippets.
//!
//! Each function body is copied verbatim from a ```` ```rust ```` block in
//! `README.md`. When the README changes, this file changes with it; when the
//! API changes, CI fails here instead of letting the README drift into
//! teaching an API that does not exist (review finding N9).
//!
//! Snippets marked ```` ```rust,ignore ```` in the README (component trees,
//! fullstack server wiring) are excluded per their own annotation; their
//! symbols are pinned by `symbol_drift_guards` below and exercised end-to-end
//! by the `dioxus_runtime` and fullstack test suites.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::sync::Arc;

use dioxus_auth::prelude::{
    Argon2Hasher, AuthEngine, AuthUser, InMemoryRateLimiter, MemoryStore, PasswordHasher,
};

/// A minimal user mirroring the README's `AppUser`. The serde derives exist
/// so the fullstack drift pins below can expand the server-fn macro against
/// it, exactly as the README teaches.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AppUser {
    id: u64,
    name: String,
}

impl AuthUser for AppUser {
    type Id = u64;

    fn id(&self) -> Self::Id {
        return self.id;
    }

    fn display_name(&self) -> Option<String> {
        return Some(self.name.clone());
    }

    fn clone_box(&self) -> Box<dyn AuthUser<Id = Self::Id>> {
        return Box::new(self.clone());
    }
}

/// Mirror of the README's "Build the engine" snippet.
#[test]
fn readme_build_the_engine() {
    let store = Arc::new(MemoryStore::<AppUser>::new());

    let auth = AuthEngine::builder(Arc::clone(&store), Arc::clone(&store))
        .session_ttl_secs(60 * 60 * 24 * 7)
        .build()
        .expect("engine construction succeeds");

    // You own user registration: hash the password yourself (the store must
    // never see plaintext) and provision your store however your app does.
    // MemoryStore offers a convenience helper that takes an already-hashed
    // password.
    let hasher = Argon2Hasher::new();
    let hash = hasher.hash("password").expect("hashing succeeds");
    store.insert_user_with_password(
        AppUser {
            id: 1,
            name: String::from("alice"),
        },
        "alice",
        hash,
    );

    // The engine must be usable after the mirrored setup.
    let _ = auth.session_ttl_secs();
}

/// Mirror of the README's "Log in and validate sessions" snippet, using an
/// engine built exactly as the README builds one.
#[test]
fn readme_login_and_validate_sessions() {
    let store = Arc::new(MemoryStore::<AppUser>::new());
    let auth = AuthEngine::builder(Arc::clone(&store), Arc::clone(&store))
        .build()
        .expect("engine construction succeeds");
    store.insert_user_with_password(
        AppUser {
            id: 1,
            name: String::from("alice"),
        },
        "alice",
        Argon2Hasher::new()
            .hash("password")
            .expect("hashing succeeds"),
    );

    let (user, session) = auth.login("alice", "password").expect("valid credentials");
    assert_eq!(user.id(), 1);

    let current = auth
        .validate_session(session.id())
        .expect("validation must not error");
    assert!(current.is_some());

    auth.logout(session.id())
        .expect("revocation must not error");
}

/// Mirror of the README's "Hardening" snippet.
#[test]
fn readme_hardening_rate_limiter() {
    use std::time::Duration;

    let store = Arc::new(MemoryStore::<AppUser>::new());

    let limiter = InMemoryRateLimiter::new(5, Duration::from_secs(60));

    let auth = AuthEngine::builder(Arc::clone(&store), Arc::clone(&store))
        .rate_limiter(limiter)
        .build()
        .expect("engine construction succeeds");

    let _ = auth;
}

/// The `rust,ignore` README snippets are excluded from compilation per their
/// own annotation, but the symbols they teach must keep existing — otherwise
/// the README would silently rot. Each pin mirrors one snippet's surface.
/// Gated on the features that export the named items.
#[cfg(feature = "dioxus")]
#[test]
fn symbol_drift_guards_for_ignored_snippets() {
    use std::marker::PhantomData;

    use dioxus::prelude::Element;
    use dioxus_auth::prelude::{
        AuthEngineHandle, AuthProvider, AuthProviderProps, RedirectIfAuthed, RedirectIfAuthedProps,
        RequireAuth, RequireAuthProps, RestoreVerdict, TokenStorageHandle, use_auth,
    };

    // "Wire the Dioxus runtime": the provider component and its props.
    fn provider_surface(
        engine: AuthEngineHandle<AppUser>,
        token_storage: TokenStorageHandle,
        children: Element,
    ) {
        let _: fn(AuthProviderProps<AppUser>) -> Element = AuthProvider::<AppUser>;
        let _ = AuthProviderProps::<AppUser> {
            engine,
            token_storage,
            children,
        };
    }

    // "Current user": the hook and the state accessors it teaches.
    fn hook_surface() -> bool {
        let auth = use_auth::<AppUser>();
        let _user = auth.user();
        return auth.is_authenticated();
    }

    // "Protected routes": the guard components and their props shape.
    fn guard_surface(redirect_to: String, children: Element) {
        let _: fn(RequireAuthProps<AppUser>) -> Element = RequireAuth::<AppUser>;
        let _: fn(RedirectIfAuthedProps<AppUser>) -> Element = RedirectIfAuthed::<AppUser>;
        let _ = RequireAuthProps::<AppUser> {
            redirect_to,
            children,
            generic: PhantomData,
        };
    }

    // Restore classification is part of the documented client behavior.
    let _ = RestoreVerdict::Unknown;

    let _ = provider_surface;
    let _ = hook_surface;
    let _ = guard_surface;
}

/// The fullstack snippet pins, gated on the fullstack feature. Mirrors the
/// README's `dioxus_auth::fullstack_server_fns!(AppUser);` invocation and the
/// `require_user` resolver, following the proven pattern of
/// `tests/fullstack_global_tests.rs`.
#[cfg(feature = "dioxus-fullstack")]
mod fullstack_snippet_pins {
    use super::AppUser;

    dioxus_auth::fullstack_server_fns!(AppUser);

    #[test]
    fn require_user_is_resolvable() {
        let _ = dioxus_auth::prelude::require_user::<AppUser>;
    }
}
