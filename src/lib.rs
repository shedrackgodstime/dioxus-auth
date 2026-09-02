#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

//! Core types, traits, cryptographic hashing, and Dioxus runtime components for `dioxus-auth`.

pub mod engine;
pub mod error;
pub mod security;
pub mod session;
pub mod storage;
pub mod user;

#[cfg(feature = "dioxus")]
pub mod dioxus;

// Top-level re-exports
pub use engine::{AuthEngine, AuthEngineBuilder};
pub use error::{AuthError, AuthResult};
pub use security::{Argon2Hasher, CookieConfig, PasswordHasher, SameSite};
pub use session::{AuthStatus, Session, SessionId};
pub use storage::{MemoryStore, PasswordUserStore, SessionStore, UserStore};
pub use user::AuthUser;

#[cfg(feature = "dioxus")]
pub use dioxus::{
    Auth, AuthProvider, GuardOutcome, RedirectIfAuthed, RequireAuth, RouteGate, RouteGuard,
    ServerAuthContext, SignedIn, SignedOut, redirect_if_authed, require_auth, use_auth,
};

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TestUser {
        id: u64,
        name: String,
        auth_hash: Option<String>,
    }

    impl AuthUser for TestUser {
        type Id = u64;

        fn id(&self) -> Self::Id {
            self.id
        }

        fn session_auth_hash(&self) -> Option<&str> {
            self.auth_hash.as_deref()
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum MockRoute {
        Login,
        Dashboard,
        Home,
    }

    #[test]
    fn authenticated_status_exposes_user() {
        let user = TestUser {
            id: 7,
            name: "Alice".into(),
            auth_hash: None,
        };
        let status = AuthStatus::Authenticated(user.clone());

        assert!(status.is_authenticated());
        assert_eq!(status.user(), Some(&user));
    }

    #[test]
    fn session_expiration_is_explicit() {
        let session = Session::new(SessionId::new("session-1"), 7, 100, 200);

        assert!(!session.is_expired_at(199));
        assert!(session.is_expired_at(200));
    }

    #[test]
    fn session_id_generates_random_hex_strings() {
        let id1 = SessionId::generate();
        let id2 = SessionId::generate();
        assert_eq!(id1.as_str().len(), 64);
        assert_eq!(id2.as_str().len(), 64);
        assert_ne!(id1, id2);
    }

    #[test]
    fn cookie_header_generation_and_extraction() {
        let config = CookieConfig {
            name: "auth_token".into(),
            path: "/".into(),
            domain: None,
            secure: true,
            http_only: true,
            same_site: SameSite::Lax,
            max_age_secs: Some(3600),
        };

        let session_id = SessionId::new("test-token-123");
        let header = config.build_set_cookie_header(&session_id);
        assert!(header.contains("auth_token=test-token-123"));
        assert!(header.contains("Path=/"));
        assert!(header.contains("Max-Age=3600"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("Secure"));
        assert!(header.contains("SameSite=Lax"));

        let delete_header = config.build_delete_cookie_header();
        assert!(delete_header.contains("auth_token="));
        assert!(delete_header.contains("Max-Age=0"));

        let cookie_header_val = "foo=bar; auth_token=test-token-123; other=val";
        assert_eq!(
            config.extract_session_id(cookie_header_val),
            Some(SessionId::new("test-token-123"))
        );
        assert_eq!(config.extract_session_id("foo=bar; baz=qux"), None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn memory_store_user_and_session_lifecycle() {
        let store = MemoryStore::<TestUser>::new();
        let user = TestUser {
            id: 42,
            name: "Bob".into(),
            auth_hash: None,
        };

        // Insert & find user
        store.insert_user(user.clone());
        let found_user = store.find_by_id(&42).await.unwrap();
        assert_eq!(found_user, Some(user));

        // Unknown user
        let missing = store.find_by_id(&999).await.unwrap();
        assert_eq!(missing, None);

        // Save session
        let session_id = SessionId::new("sess-abc");
        let session = Session::new(session_id.clone(), 42, 1000, 2000);
        store.save_session(session.clone()).await.unwrap();

        // Find session
        let found_session = store.find_session(&session_id).await.unwrap();
        assert_eq!(found_session, Some(session));

        // Delete session
        store.delete_session(&session_id).await.unwrap();
        assert_eq!(store.find_session(&session_id).await.unwrap(), None);

        // Multiple sessions for user deletion
        let s1 = Session::new(SessionId::new("s1"), 42, 100, 200);
        let s2 = Session::new(SessionId::new("s2"), 42, 100, 200);
        let s3 = Session::new(SessionId::new("s3"), 99, 100, 200);
        store.save_session(s1).await.unwrap();
        store.save_session(s2).await.unwrap();
        store.save_session(s3).await.unwrap();

        store.delete_user_sessions(&42).await.unwrap();
        assert_eq!(
            store.find_session(&SessionId::new("s1")).await.unwrap(),
            None
        );
        assert_eq!(
            store.find_session(&SessionId::new("s2")).await.unwrap(),
            None
        );
        assert!(
            store
                .find_session(&SessionId::new("s3"))
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn auth_engine_login_logout_and_validation_lifecycle() {
        let store = std::sync::Arc::new(MemoryStore::<TestUser>::new());
        let hasher = Argon2Hasher::new();
        let password = "my_secure_password_999";
        let password_hash = hasher.hash_password(password).unwrap();

        let user = TestUser {
            id: 101,
            name: "Evelyn".into(),
            auth_hash: Some(password_hash.clone()),
        };

        // Insert user with password hash into store
        store.insert_user_with_password(user.clone(), "evelyn@example.com", &password_hash);

        // Build the AuthEngine
        let engine = AuthEngine::builder(store.clone(), store.clone())
            .session_ttl(Duration::from_secs(3600))
            .build();

        // 1. Failed login: wrong password
        let err = engine.login("evelyn@example.com", "wrong_pass").await;
        assert_eq!(err.unwrap_err(), AuthError::Unauthenticated);

        // 2. Failed login: unknown user (runs constant-time dummy verification)
        let err = engine
            .login("nonexistent@example.com", "any_password")
            .await;
        assert_eq!(err.unwrap_err(), AuthError::Unauthenticated);

        // 3. Successful login: valid credentials
        let (authed_user, session) = engine
            .login("evelyn@example.com", password)
            .await
            .expect("Login failed");
        assert_eq!(authed_user, user);
        assert_eq!(session.user_id(), &101);
        assert!(!session.is_expired_at(session.created_at_unix()));

        // 4. Validate active session
        let validated = engine
            .validate_session(session.id())
            .await
            .unwrap()
            .expect("Session should be valid");
        assert_eq!(validated, user);

        // 5. Logout and confirm invalidation
        engine.logout(session.id()).await.unwrap();
        let post_logout = engine.validate_session(session.id()).await.unwrap();
        assert_eq!(post_logout, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn auth_engine_invalidates_session_on_password_change() {
        let store = std::sync::Arc::new(MemoryStore::<TestUser>::new());
        let hasher = Argon2Hasher::new();
        let old_hash = hasher.hash_password("old_password").unwrap();

        let user_v1 = TestUser {
            id: 202,
            name: "Frank".into(),
            auth_hash: Some(old_hash.clone()),
        };
        store.insert_user_with_password(user_v1.clone(), "frank@example.com", &old_hash);

        let engine = AuthEngine::builder(store.clone(), store.clone()).build();

        // Frank logs in with old password
        let (_, session) = engine
            .login("frank@example.com", "old_password")
            .await
            .unwrap();
        assert!(
            engine
                .validate_session(session.id())
                .await
                .unwrap()
                .is_some()
        );

        // Frank changes password -> user record in store gets updated auth_hash
        let new_hash = hasher.hash_password("new_password").unwrap();
        let user_v2 = TestUser {
            id: 202,
            name: "Frank".into(),
            auth_hash: Some(new_hash.clone()),
        };
        store.insert_user_with_password(user_v2, "frank@example.com", &new_hash);

        // Old session is now automatically invalidated because auth_hash doesn't match!
        let result = engine.validate_session(session.id()).await.unwrap();
        assert_eq!(result, None);
    }

    #[cfg(feature = "dioxus")]
    #[test]
    fn dioxus_auth_handle_manipulates_status() {
        use ::dioxus::prelude::*;

        let mut vdom = VirtualDom::new(|| {
            let user = TestUser {
                id: 1,
                name: "Carol".into(),
                auth_hash: None,
            };
            let auth_signal = use_signal(|| AuthStatus::Loading);
            let mut auth = Auth::new(auth_signal);

            assert!(auth.is_loading());
            assert_eq!(auth.user(), None);

            auth.set_user(user.clone());
            assert!(auth.is_authenticated());
            assert_eq!(auth.user(), Some(user));

            auth.logout();
            assert!(auth.is_unauthenticated());
            assert_eq!(auth.user(), None);

            rsx! { div {} }
        });

        vdom.rebuild_in_place();
    }

    #[cfg(feature = "dioxus")]
    #[test]
    fn route_guards_evaluate_outcomes_correctly() {
        let user = TestUser {
            id: 1,
            name: "Dan".into(),
            auth_hash: None,
        };
        let loading_status = AuthStatus::<TestUser>::Loading;
        let authed_status = AuthStatus::Authenticated(user);
        let unauthed_status = AuthStatus::<TestUser>::Unauthenticated;

        // require_auth
        assert_eq!(
            require_auth(&loading_status, MockRoute::Login),
            GuardOutcome::Pending
        );
        assert_eq!(
            require_auth(&authed_status, MockRoute::Login),
            GuardOutcome::Allow
        );
        assert_eq!(
            require_auth(&unauthed_status, MockRoute::Login),
            GuardOutcome::Redirect(MockRoute::Login)
        );

        // redirect_if_authed
        assert_eq!(
            redirect_if_authed(&loading_status, MockRoute::Dashboard),
            GuardOutcome::Pending
        );
        assert_eq!(
            redirect_if_authed(&authed_status, MockRoute::Dashboard),
            GuardOutcome::Redirect(MockRoute::Dashboard)
        );
        assert_eq!(
            redirect_if_authed(&unauthed_status, MockRoute::Dashboard),
            GuardOutcome::Allow
        );

        // Declarative trait wrappers
        let req_guard = RequireAuth(MockRoute::Login);
        assert_eq!(req_guard.evaluate(&authed_status), GuardOutcome::Allow);
        assert_eq!(
            req_guard.evaluate(&unauthed_status),
            GuardOutcome::Redirect(MockRoute::Login)
        );

        let redir_guard = RedirectIfAuthed(MockRoute::Home);
        assert_eq!(
            redir_guard.evaluate(&authed_status),
            GuardOutcome::Redirect(MockRoute::Home)
        );
        assert_eq!(redir_guard.evaluate(&unauthed_status), GuardOutcome::Allow);
    }

    #[cfg(feature = "dioxus")]
    #[test]
    fn signed_in_and_signed_out_components_render_conditionally() {
        use ::dioxus::prelude::*;

        let user = TestUser {
            id: 88,
            name: "Grace".into(),
            auth_hash: None,
        };

        // Case 1: Authenticated
        let mut vdom_authed = VirtualDom::new_with_props(
            |props: (Option<AuthStatus<TestUser>>,)| {
                rsx! {
                    AuthProvider::<TestUser> {
                        initial_status: props.0,
                        SignedIn::<TestUser> {
                            div { id: "welcome-box", "Welcome, member!" }
                        }
                        SignedOut::<TestUser> {
                            div { id: "login-box", "Please sign in" }
                        }
                    }
                }
            },
            (Some(AuthStatus::Authenticated(user.clone())),),
        );
        vdom_authed.rebuild_in_place();

        // Case 2: Unauthenticated
        let mut vdom_unauthed = VirtualDom::new_with_props(
            |props: (Option<AuthStatus<TestUser>>,)| {
                rsx! {
                    AuthProvider::<TestUser> {
                        initial_status: props.0,
                        SignedIn::<TestUser> {
                            div { id: "welcome-box", "Welcome, member!" }
                        }
                        SignedOut::<TestUser> {
                            div { id: "login-box", "Please sign in" }
                        }
                    }
                }
            },
            (Some(AuthStatus::Unauthenticated),),
        );
        vdom_unauthed.rebuild_in_place();
    }
}
