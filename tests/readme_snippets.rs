//! Compile-checked mirrors of the README snippets.
//!
//! Each function body follows a ```` ```rust ```` block in `README.md`. When
//! the README changes, this file changes with it; when the API changes, CI
//! fails here instead of letting the README drift into teaching an API that
//! does not exist.
//!
//! Snippets marked ```` ```rust,ignore ```` in the README (component trees,
//! fullstack server wiring) are excluded per their own annotation; their
//! symbols are pinned by `symbol_drift_guards` below and exercised end-to-end
//! by the `dioxus_runtime` and fullstack test suites.

// reason: project style requires explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::sync::Arc;

use dioxus_auth::{Auth, AuthEngine, AuthUser, DefaultUser, InMemoryRateLimiter, MemoryStore};

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

    fn email(&self) -> &str {
        return &self.name;
    }
}

/// Mirror of the README's quickstart snippet: zero modeling, zero traits.
#[test]
fn readme_quickstart() {
    let auth = Auth::memory().expect("quickstart must construct");

    auth.sign_up_email(
        "alice@example.com",
        "password",
        DefaultUser {
            id: 1,
            email: String::from("alice@example.com"),
            name: String::from("alice"),
        },
    )
    .expect("sign-up must succeed");

    let (user, session) = auth
        .sign_in_email("alice@example.com", "password")
        .expect("sign-in must succeed");
    assert_eq!(user.id, 1);

    auth.sign_out(&session).expect("sign-out must succeed");
    return;
}

/// Mirror of the README's graduation snippet: own user type, same verbs.
#[test]
fn readme_graduation() {
    let auth = Auth::new(MemoryStore::<AppUser>::new()).expect("facade must construct");

    auth.sign_up_email(
        "alice@example.com",
        "password",
        AppUser {
            id: 1,
            name: String::from("alice@example.com"),
        },
    )
    .expect("sign-up must succeed");
    return;
}

/// Graduation preserves verb behavior: the quickstart flow and the own-DB
/// flow answer identically, including error codes.
#[test]
fn graduation_preserves_verb_behavior() {
    use dioxus_auth::AuthError;

    let quick = Auth::memory().expect("quickstart must construct");
    quick
        .sign_up_email(
            "alice@example.com",
            "password",
            DefaultUser {
                id: 1,
                email: String::from("alice@example.com"),
                name: String::from("alice"),
            },
        )
        .expect("sign-up must succeed");

    let owned = Auth::new(MemoryStore::<AppUser>::new()).expect("facade must construct");
    owned
        .sign_up_email(
            "alice@example.com",
            "password",
            AppUser {
                id: 1,
                name: String::from("alice@example.com"),
            },
        )
        .expect("sign-up must succeed");

    // Same verbs, same answers on both sides of graduation (written out:
    // the two facades have different store types, so the parity is literal).
    assert_eq!(
        quick
            .sign_in_email("alice@example.com", "wrong")
            .expect_err("wrong password must fail"),
        AuthError::InvalidCredentials
    );
    assert_eq!(
        quick
            .sign_in_email("nobody@example.com", "password")
            .expect_err("unknown identifier must fail"),
        AuthError::InvalidCredentials
    );
    assert_eq!(
        owned
            .sign_in_email("alice@example.com", "wrong")
            .expect_err("wrong password must fail"),
        AuthError::InvalidCredentials
    );
    assert_eq!(
        owned
            .sign_in_email("nobody@example.com", "password")
            .expect_err("unknown identifier must fail"),
        AuthError::InvalidCredentials
    );

    let (_, quick_session) = quick
        .sign_in_email("alice@example.com", "password")
        .expect("sign-in must succeed");
    let (_, owned_session) = owned
        .sign_in_email("alice@example.com", "password")
        .expect("sign-in must succeed");
    quick
        .sign_out(&quick_session)
        .expect("sign-out must succeed");
    owned
        .sign_out(&owned_session)
        .expect("sign-out must succeed");
    return;
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
    return;
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
    use dioxus_auth::{
        Auth, AuthProvider, AuthProviderProps, MemoryStore, RedirectIfAuthed,
        RedirectIfAuthedProps, RequireAuth, RequireAuthProps, RestoreVerdict, use_auth,
    };

    // "Wire the Dioxus runtime": the provider component and its props.
    fn provider_surface(auth: Auth<MemoryStore<AppUser>>, children: Element) {
        let _: fn(AuthProviderProps<MemoryStore<AppUser>>) -> Element =
            AuthProvider::<MemoryStore<AppUser>>;
        let _ = AuthProviderProps::<MemoryStore<AppUser>> { auth, children };
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
        let _ = dioxus_auth::require_user::<AppUser>;
    }
}
