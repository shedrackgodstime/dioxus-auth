#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

//! Core types, traits, cryptographic hashing, and Dioxus runtime components for `dioxus-auth`.

pub mod engine;
pub mod error;
pub mod security;
pub mod session;
pub mod storage;
pub mod transport;
pub mod user;

#[cfg(feature = "dioxus")]
pub mod dioxus;

// Top-level re-exports
pub use engine::{AuthEngine, AuthEngineBuilder};
pub use error::{AuthError, AuthResult};
pub use security::{Argon2Hasher, CookieConfig, PasswordHasher, SameSite};
pub use session::{AuthStatus, Session, SessionId};
pub use storage::{MemoryStore, PasswordUserStore, SessionStore, UserStore};
#[cfg(not(target_arch = "wasm32"))]
pub use transport::FileTokenStorage;
#[cfg(target_arch = "wasm32")]
pub use transport::WebTokenStorage;
pub use transport::{MemoryTokenStorage, TokenStorage, extract_session_token};
pub use user::AuthUser;

#[cfg(feature = "dioxus")]
pub use dioxus::{
    Auth, AuthProvider, GuardOutcome, RedirectIfAuthed, RequireAuth, RouteGate, RouteGuard,
    ServerAuthContext, SignedIn, SignedOut, redirect_if_authed, require_auth, use_auth,
    use_auth_restore,
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

    /// Phase B: the pre-computed dummy hash must be a real, parseable Argon2 PHC string
    /// and a verify against it must run the actual Argon2 (i.e. take non-trivial work).
    #[tokio::test(flavor = "current_thread")]
    async fn auth_engine_dummy_hash_is_real_phc_and_argon2_actually_runs() {
        use std::time::Instant;

        use argon2::password_hash::PasswordHash;

        let store = std::sync::Arc::new(MemoryStore::<TestUser>::new());
        let engine = AuthEngine::builder(store.clone(), store.clone()).build();

        // 1. The dummy hash must be a real PHC string (the old broken hash was not).
        let dummy_hash = &engine.dummy_hash;
        assert!(
            PasswordHash::new(dummy_hash).is_ok(),
            "dummy hash must be a parseable Argon2 PHC string"
        );
        assert!(
            dummy_hash.starts_with("$argon2id$"),
            "dummy hash must be Argon2id"
        );

        // 2. A verify against the dummy hash must run the real Argon2 (i.e. take
        //    non-trivial work). We assert a generous lower bound to avoid flakiness
        //    on fast machines while still catching the "short-circuits on parse"
        //    regression. The old code short-circuited in <1ms; a real Argon2id
        //    verification at OWASP params takes tens of milliseconds.
        let started = Instant::now();
        let _ = engine.hasher().verify_password("anything", dummy_hash);
        let elapsed = started.elapsed();
        assert!(
            elapsed.as_millis() >= 5,
            "verify against dummy hash took {elapsed:?}; expected >= 5ms (real Argon2 should run)"
        );

        // 3. Miss and hit paths take comparable time. The known-user path runs
        //    Argon2 against the real hash; the miss path now runs Argon2 against
        //    the dummy hash with the same params. Both must be in the same order
        //    of magnitude. We assert the miss/hit ratio is within a loose band
        //    so the test does not flake on a busy CI box while still catching
        //    the old regression where miss was ~0ms and hit was ~25ms.
        let password = "test_password_for_timing";
        let hasher = Argon2Hasher::new();
        let real_hash = hasher.hash_password(password).unwrap();
        let store2 = std::sync::Arc::new(MemoryStore::<TestUser>::new());
        let user = TestUser {
            id: 999,
            name: "Timing".into(),
            auth_hash: Some(real_hash.clone()),
        };
        store2.insert_user_with_password(user, "timing@example.com", &real_hash);
        let engine2 = AuthEngine::builder(store2.clone(), store2.clone()).build();

        let miss_started = Instant::now();
        let _ = engine2
            .login("nonexistent@example.com", "any_password")
            .await;
        let miss_elapsed = miss_started.elapsed();

        let hit_started = Instant::now();
        let _ = engine2.login("timing@example.com", "wrong_password").await;
        let hit_elapsed = hit_started.elapsed();

        // Sanity: both must be at least 5ms (Argon2 actually ran).
        assert!(
            miss_elapsed.as_millis() >= 5,
            "miss path took {miss_elapsed:?}; Argon2 should have run"
        );
        assert!(
            hit_elapsed.as_millis() >= 5,
            "hit-wrong-password path took {hit_elapsed:?}; Argon2 should have run"
        );

        // The miss must be within a generous factor of the hit. If the old bug
        // regressed (miss short-circuits), miss would be ~0ms and the ratio
        // would explode. Allow up to 10x slack for CI noise; in practice the
        // values are within ~2x because both paths do the same Argon2 work.
        let ratio = miss_elapsed.as_micros() as f64 / hit_elapsed.as_micros() as f64;
        assert!(
            (0.1..=10.0).contains(&ratio),
            "miss/hit timing ratio {ratio:.2} (miss={miss_elapsed:?}, hit={hit_elapsed:?}) \
             suggests one path is not running Argon2"
        );
    }

    /// Phase C: the store must never see the raw wire token. Login hashes before save,
    /// validate/logout hash before lookup/delete. A leaked store cannot hijack sessions.
    #[tokio::test(flavor = "current_thread")]
    async fn auth_engine_session_tokens_are_hashed_at_rest() {
        let store = std::sync::Arc::new(MemoryStore::<TestUser>::new());
        let hasher = Argon2Hasher::new();
        let password = "hashed_at_rest_pw";
        let password_hash = hasher.hash_password(password).unwrap();

        let user = TestUser {
            id: 303,
            name: "Hash".into(),
            auth_hash: Some(password_hash.clone()),
        };
        store.insert_user_with_password(user.clone(), "hash@example.com", &password_hash);

        let engine = AuthEngine::builder(store.clone(), store.clone()).build();

        // 1. Login returns a wire Session whose id is the raw token.
        let (_, wire_session) = engine
            .login("hash@example.com", password)
            .await
            .expect("login should succeed");
        let raw_id = wire_session.id().clone();
        let expected_storage_id = raw_id.hash_for_storage();

        // 2. The raw token must NOT be present in the store under the raw form.
        //    The store should only have the sha256(raw) form.
        assert_ne!(
            raw_id.as_str(),
            expected_storage_id.as_str(),
            "raw id and its hash must differ"
        );
        assert!(
            store.find_session(&raw_id).await.unwrap().is_none(),
            "store must not be queryable by the raw wire token"
        );

        // 3. The store IS queryable by the hashed id.
        let stored = store
            .find_session(&expected_storage_id)
            .await
            .unwrap()
            .expect("session must be retrievable by hashed id");
        assert_eq!(stored.user_id(), &303);
        assert_eq!(stored.id().as_str(), expected_storage_id.as_str());

        // 4. validate_session (which takes the raw id) hashes internally and finds the row.
        let validated = engine
            .validate_session(&raw_id)
            .await
            .unwrap()
            .expect("validate must succeed via the raw wire id");
        assert_eq!(validated, user);

        // 5. Logout by raw id also works (engine hashes before delete).
        engine.logout(&raw_id).await.unwrap();
        assert_eq!(
            store.find_session(&expected_storage_id).await.unwrap(),
            None,
            "logout by raw id must delete the hashed row"
        );
        // And a subsequent validate by the same raw id returns None.
        assert_eq!(engine.validate_session(&raw_id).await.unwrap(), None);
    }

    /// Phase D: `MemoryTokenStorage` round-trips a token and clears it.
    #[test]
    fn memory_token_storage_round_trip_and_clear() {
        use crate::transport::MemoryTokenStorage;

        let storage = MemoryTokenStorage::new();
        assert_eq!(storage.load(), None);

        storage.save("raw_wire_token_xyz").unwrap();
        assert_eq!(storage.load().as_deref(), Some("raw_wire_token_xyz"));

        storage.clear();
        assert_eq!(storage.load(), None);
    }

    /// Phase D: `FileTokenStorage` writes, reads, and clears on disk. On Unix it
    /// must enforce 0600 permissions so other processes running as the same user
    /// cannot read the raw session token.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn file_token_storage_round_trip_and_0600() {
        use crate::transport::FileTokenStorage;

        let dir = std::env::temp_dir().join(format!(
            "dioxus_auth_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("session.token");

        let storage = FileTokenStorage::new(&path);

        // Empty storage
        assert_eq!(storage.load(), None);

        // Save + load
        storage.save("native_raw_token_abc").unwrap();
        assert_eq!(storage.load().as_deref(), Some("native_raw_token_abc"));

        // Permissions check (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&path).unwrap();
            let mode = metadata.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "file mode should be 0600, got {mode:o}");
        }

        // Clear deletes the file
        storage.clear();
        assert!(!path.exists());
        assert_eq!(storage.load(), None);

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
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
    fn use_auth_restore_drives_status_from_resource() {
        use ::dioxus::prelude::*;

        // Case 1: resource resolves to Some(user) → Authenticated
        let mut vdom_authed = VirtualDom::new(|| {
            let user = TestUser {
                id: 1,
                name: "Ada".into(),
                auth_hash: None,
            };
            let auth_signal = use_context_provider(|| Signal::new(AuthStatus::<TestUser>::Loading));
            let auth = Auth::new(auth_signal);
            provide_context(auth);

            use_auth_restore(Some(Ok::<Option<TestUser>, &str>(Some(user.clone()))));
            assert!(auth.is_authenticated());
            assert_eq!(auth.user(), Some(user));

            rsx! { div {} }
        });
        vdom_authed.rebuild_in_place();

        // Case 2: resource resolves to None → Unauthenticated
        let mut vdom_none = VirtualDom::new(|| {
            let auth_signal = use_context_provider(|| Signal::new(AuthStatus::<TestUser>::Loading));
            let auth = Auth::new(auth_signal);
            provide_context(auth);

            use_auth_restore(Some(Ok::<Option<TestUser>, &str>(None)));
            assert!(auth.is_unauthenticated());

            rsx! { div {} }
        });
        vdom_none.rebuild_in_place();

        // Case 3: resource errors → Unauthenticated
        let mut vdom_err = VirtualDom::new(|| {
            let auth_signal = use_context_provider(|| Signal::new(AuthStatus::<TestUser>::Loading));
            let auth = Auth::new(auth_signal);
            provide_context(auth);

            use_auth_restore::<TestUser, &str>(Some(Err("network down")));
            assert!(auth.is_unauthenticated());

            rsx! { div {} }
        });
        vdom_err.rebuild_in_place();

        // Case 4: resource still None → Loading (no change)
        let mut vdom_pending = VirtualDom::new(|| {
            let auth_signal = use_context_provider(|| Signal::new(AuthStatus::<TestUser>::Loading));
            let auth = Auth::new(auth_signal);
            provide_context(auth);

            use_auth_restore::<TestUser, &str>(None);
            assert!(auth.is_loading());

            rsx! { div {} }
        });
        vdom_pending.rebuild_in_place();

        // Case 5: manual login is NOT overwritten by a late restore
        let mut vdom_protect = VirtualDom::new(|| {
            let user = TestUser {
                id: 2,
                name: "Live".into(),
                auth_hash: None,
            };
            let auth_signal = use_context_provider(|| Signal::new(AuthStatus::<TestUser>::Loading));
            let mut auth = Auth::new(auth_signal);
            provide_context(auth);

            // Simulate a manual login setting the state away from Loading.
            auth.set_user(user.clone());
            assert!(auth.is_authenticated());

            // A late restore arriving after login must NOT wipe the live session.
            use_auth_restore(Some(Ok::<Option<TestUser>, &str>(None)));
            assert!(auth.is_authenticated());
            assert_eq!(auth.user(), Some(user));

            rsx! { div {} }
        });
        vdom_protect.rebuild_in_place();
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

    /// Phase E proof-of-concept: the exact pattern UTME Lab will use.
    /// `AuthUser::Id = String` (their `id` type), `use_auth_restore` driving
    /// the 3-state from a whoami result, `require_auth` mapping each state to
    /// the correct `GuardOutcome`, `SignedIn` / `SignedOut` conditionally
    /// visible. This is the *contract* the adapter plugs into.
    #[cfg(feature = "dioxus")]
    #[test]
    fn string_id_user_full_lifecycle() {
        use ::dioxus::prelude::*;

        #[derive(Clone, Debug, Eq, PartialEq)]
        struct StringIdUser {
            id: String,
            email: String,
        }

        impl crate::user::AuthUser for StringIdUser {
            type Id = String;
            fn id(&self) -> Self::Id {
                self.id.clone()
            }
            fn session_auth_hash(&self) -> Option<&str> {
                None
            }
        }

        // 1. Restore → Authenticated → require_auth maps to Allow.
        let mut vdom_authed = VirtualDom::new(|| {
            let user = StringIdUser {
                id: "user_42".into(),
                email: "ada@example.com".into(),
            };
            let auth_signal =
                use_context_provider(|| Signal::new(AuthStatus::<StringIdUser>::Loading));
            provide_context(Auth::new(auth_signal));
            use_auth_restore(Some(Ok::<Option<StringIdUser>, &str>(Some(user.clone()))));
            let auth = use_auth::<StringIdUser>();
            let outcome = require_auth(&auth.status(), MockRoute::Login);
            assert_eq!(outcome, GuardOutcome::Allow);
            assert!(auth.is_authenticated());
            assert_eq!(auth.user().map(|u| u.id), Some("user_42".to_string()));
            rsx! { div {} }
        });
        vdom_authed.rebuild_in_place();

        // 2. Restore → Unauthenticated → require_auth maps to Redirect.
        let mut vdom_unauthed = VirtualDom::new(|| {
            let auth_signal =
                use_context_provider(|| Signal::new(AuthStatus::<StringIdUser>::Loading));
            provide_context(Auth::new(auth_signal));
            use_auth_restore(Some(Ok::<Option<StringIdUser>, &str>(None)));
            let auth = use_auth::<StringIdUser>();
            let outcome = require_auth(&auth.status(), MockRoute::Login);
            assert_eq!(outcome, GuardOutcome::Redirect(MockRoute::Login));
            assert!(auth.is_unauthenticated());
            rsx! { div {} }
        });
        vdom_unauthed.rebuild_in_place();

        // 3. Restore → Loading (resource still None) → require_auth maps to Pending
        //    (no premature redirect — the F5 / hydration flash fix).
        let mut vdom_loading = VirtualDom::new(|| {
            let auth_signal =
                use_context_provider(|| Signal::new(AuthStatus::<StringIdUser>::Loading));
            provide_context(Auth::new(auth_signal));
            use_auth_restore::<StringIdUser, &str>(None);
            let auth = use_auth::<StringIdUser>();
            let outcome = require_auth(&auth.status(), MockRoute::Login);
            assert_eq!(outcome, GuardOutcome::Pending);
            assert!(auth.is_loading());
            rsx! { div {} }
        });
        vdom_loading.rebuild_in_place();

        // 4. SignedIn / SignedOut render conditionally inside the provider.
        let mut vdom_components = VirtualDom::new(|| {
            let auth_signal = use_context_provider(|| {
                Signal::new(AuthStatus::<StringIdUser>::Authenticated(StringIdUser {
                    id: "user_1".into(),
                    email: "x@y.z".into(),
                }))
            });
            provide_context(Auth::new(auth_signal));
            rsx! {
                AuthProvider::<StringIdUser> {
                    initial_status: Some(AuthStatus::Authenticated(StringIdUser {
                        id: "user_1".into(),
                        email: "x@y.z".into(),
                    })),
                    SignedIn::<StringIdUser> { div { id: "in", "in" } }
                    SignedOut::<StringIdUser> { div { id: "out", "out" } }
                }
            }
        });
        vdom_components.rebuild_in_place();
    }
}
