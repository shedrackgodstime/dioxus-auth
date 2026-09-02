use std::sync::Arc;
use std::time::Duration;

use dioxus_auth::{
    Argon2Hasher, AuthEngine, AuthError, AuthUser, CookieConfig, MemoryStore, PasswordHasher,
    ServerAuthContext,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct CustomerUser {
    id: u32,
    email: String,
    password_hash: String,
}

impl AuthUser for CustomerUser {
    type Id = u32;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> Option<&str> {
        Some(&self.password_hash)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn full_auth_lifecycle_external_test() {
    let store = Arc::new(MemoryStore::<CustomerUser>::new());
    let hasher = Argon2Hasher::new();
    let raw_pass = "P@ssw0rd_integration_test!";
    let hashed = hasher.hash_password(raw_pass).unwrap();

    let user = CustomerUser {
        id: 100,
        email: "enterprise@corp.com".into(),
        password_hash: hashed.clone(),
    };
    store.insert_user_with_password(user.clone(), "enterprise@corp.com", &hashed);

    let engine = AuthEngine::builder(store.clone(), store.clone())
        .session_ttl(Duration::from_secs(1800)) // 30 minutes
        .build();

    // 1. Invalid login attempt
    let err = engine.login("enterprise@corp.com", "incorrect_pwd").await;
    assert_eq!(err.unwrap_err(), AuthError::Unauthenticated);

    // 2. Successful login
    let (authed_user, session1) = engine
        .login("enterprise@corp.com", raw_pass)
        .await
        .expect("Valid login must succeed");
    assert_eq!(authed_user, user);

    // 3. Validate active session
    let validated = engine
        .validate_session(session1.id())
        .await
        .unwrap()
        .expect("Session must be active");
    assert_eq!(validated, user);

    // 4. Second session for same user (multi-device)
    let (_, session2) = engine
        .login("enterprise@corp.com", raw_pass)
        .await
        .expect("Second login must succeed");
    assert_ne!(session1.id(), session2.id());

    // Both sessions are valid
    assert!(
        engine
            .validate_session(session1.id())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        engine
            .validate_session(session2.id())
            .await
            .unwrap()
            .is_some()
    );

    // 5. Total revocation (logout all devices)
    engine.revoke_all_user_sessions(&user.id).await.unwrap();
    assert_eq!(engine.validate_session(session1.id()).await.unwrap(), None);
    assert_eq!(engine.validate_session(session2.id()).await.unwrap(), None);
}

#[tokio::test(flavor = "current_thread")]
async fn server_auth_context_flow_external_test() {
    let store = Arc::new(MemoryStore::<CustomerUser>::new());
    let hasher = Argon2Hasher::new();
    let password = "valid_password_456";
    let hash = hasher.hash_password(password).unwrap();

    let user = CustomerUser {
        id: 200,
        email: "alice@acme.org".into(),
        password_hash: hash.clone(),
    };
    store.insert_user_with_password(user.clone(), "alice@acme.org", &hash);

    let engine = AuthEngine::builder(store.clone(), store.clone())
        .session_ttl(Duration::from_secs(3600))
        .build();

    let cookie_config = CookieConfig {
        name: "custom_app_session".into(),
        path: "/app".into(),
        secure: true,
        http_only: true,
        ..Default::default()
    };

    let server = ServerAuthContext::new(&engine, &cookie_config);

    // 1. Perform server-side login
    let (authed_user, set_cookie) = server.login("alice@acme.org", password).await.unwrap();
    assert_eq!(authed_user, user);
    assert!(set_cookie.contains("custom_app_session="));
    assert!(set_cookie.contains("Path=/app"));

    // 2. Validate request with cookie header
    let cookie_header = format!("other_cookie=123; {set_cookie}");
    let current_user = server.current_user(Some(&cookie_header)).await.unwrap();
    assert_eq!(current_user, Some(user.clone()));

    // 3. Require user
    let required = server.require_user(Some(&cookie_header)).await.unwrap();
    assert_eq!(required, user);

    // 4. Logout via server context
    let session_id = server.extract_session_id(Some(&cookie_header)).unwrap();
    let clear_cookie = server.logout(&session_id).await.unwrap();
    assert!(clear_cookie.contains("Max-Age=0"));

    // 5. Subsequent request is unauthenticated
    let after_logout = server.current_user(Some(&cookie_header)).await.unwrap();
    assert_eq!(after_logout, None);
}
