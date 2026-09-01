#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

//! Core types, traits, and Dioxus runtime components for `dioxus-auth`.

mod cookie;
mod error;
mod session;
mod status;
mod store;
mod user;

#[cfg(feature = "dioxus")]
mod dioxus_integration;
#[cfg(feature = "dioxus")]
mod guards;

pub use cookie::{CookieConfig, SameSite};
pub use error::{AuthError, AuthResult};
pub use session::{Session, SessionId};
pub use status::AuthStatus;
pub use store::{MemoryStore, SessionStore, UserStore};
pub use user::AuthUser;

#[cfg(feature = "dioxus")]
pub use dioxus_integration::{use_auth, Auth, AuthProvider};
#[cfg(feature = "dioxus")]
pub use guards::{
    redirect_if_authed, require_auth, GuardOutcome, RedirectIfAuthed, RequireAuth, RouteGate,
    RouteGuard,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TestUser {
        id: u64,
        name: String,
    }

    impl AuthUser for TestUser {
        type Id = u64;

        fn id(&self) -> Self::Id {
            self.id
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
        assert_eq!(store.find_session(&SessionId::new("s1")).await.unwrap(), None);
        assert_eq!(store.find_session(&SessionId::new("s2")).await.unwrap(), None);
        assert!(store.find_session(&SessionId::new("s3")).await.unwrap().is_some());
    }

    #[cfg(feature = "dioxus")]
    #[test]
    fn dioxus_auth_handle_manipulates_status() {
        use dioxus::prelude::*;

        let mut vdom = VirtualDom::new(|| {
            let user = TestUser {
                id: 1,
                name: "Carol".into(),
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
        assert_eq!(
            req_guard.evaluate(&authed_status),
            GuardOutcome::Allow
        );
        assert_eq!(
            req_guard.evaluate(&unauthed_status),
            GuardOutcome::Redirect(MockRoute::Login)
        );

        let redir_guard = RedirectIfAuthed(MockRoute::Home);
        assert_eq!(
            redir_guard.evaluate(&authed_status),
            GuardOutcome::Redirect(MockRoute::Home)
        );
        assert_eq!(
            redir_guard.evaluate(&unauthed_status),
            GuardOutcome::Allow
        );
    }
}
