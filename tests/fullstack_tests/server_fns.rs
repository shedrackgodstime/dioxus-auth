//! Tests for the generated login, logout, and session server functions.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::sync::Arc;

use dioxus_auth::prelude::{
    AuthEngine, AuthEngineHandle, AuthError, CookieConfig, MemoryStore, SameSite, ServerAuthConfig,
    ServerAuthContext, ServerError, ServerFnError, SessionId, current_user, write_session_cookie,
};
use dioxus_fullstack::FullstackContext;
use dioxus_fullstack::http;

use super::common::TestUser;
use super::dioxus_auth_session;
use super::fullstack_shared::{
    IDENTIFIER, PASSWORD, USER_ID, error_code, request_parts, response_token, run_login,
    run_logout, run_session,
};
use super::harness::{COOKIE, assert_cleared_cookie, config};
use super::identity_hasher::IdentityHasher;

#[tokio::test]
async fn login_sets_a_valid_session_cookie() {
    let config = config();
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (result, headers) = run_login(parts, IDENTIFIER, PASSWORD).await;

    let user = result.expect("login must succeed");
    assert_eq!(user.id, USER_ID);

    let token = response_token(&headers, COOKIE);
    assert!(
        SessionId::is_valid_wire_format(&token),
        "cookie token must be a valid session id"
    );
    let parts = request_parts(Some(&config), COOKIE, Some(&token), "/api/auth/session");
    let session = run_session(parts).await;
    let resolved = session.expect("the session must resolve");
    assert_eq!(resolved.id, USER_ID);
}

#[tokio::test]
async fn login_rejects_wrong_password_with_401() {
    let config = config();
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (result, _) = run_login(parts, IDENTIFIER, "not the password").await;
    assert_eq!(error_code(&result), 401);
}

#[tokio::test]
async fn session_returns_401_for_guests() {
    let config = config();
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/session");
    let result = run_session(parts).await;
    assert_eq!(error_code(&result), 401);
}

#[tokio::test]
async fn session_returns_401_for_malformed_tokens() {
    let config = config();
    let parts = request_parts(
        Some(&config),
        COOKIE,
        Some("not-a-valid-session-token"),
        "/api/auth/session",
    );
    let result = run_session(parts).await;
    assert_eq!(error_code(&result), 401);
}

#[tokio::test]
async fn session_resolves_the_authenticated_user() {
    let config = config();
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (login, headers) = run_login(parts, IDENTIFIER, PASSWORD).await;
    assert!(login.is_ok());

    let token = response_token(&headers, COOKIE);
    let parts = request_parts(Some(&config), COOKIE, Some(&token), "/api/auth/session");
    let user = run_session(parts).await.expect("session must resolve");
    assert_eq!(user.id, USER_ID);
}

#[tokio::test]
async fn logout_clears_the_cookie_and_revokes_the_session() {
    let config = config();
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (_login, headers) = run_login(parts, IDENTIFIER, PASSWORD).await;
    let token = response_token(&headers, COOKIE);

    let parts = request_parts(Some(&config), COOKIE, Some(&token), "/api/auth/logout");
    let (result, headers) = run_logout(parts).await;
    result.expect("logout must succeed");
    assert_cleared_cookie(&headers);

    let parts = request_parts(Some(&config), COOKIE, Some(&token), "/api/auth/session");
    let session = run_session(parts).await;
    assert_eq!(error_code(&session), 401, "the session must be revoked");
}

#[tokio::test]
async fn logout_clears_the_cookie_for_guests() {
    let config = config();
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/logout");
    let (result, headers) = run_logout(parts).await;
    result.expect("guest logout must succeed");
    assert_cleared_cookie(&headers);
}

#[tokio::test]
async fn current_user_guest_defaults_to_none() {
    let config = config();
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/session");
    let context = FullstackContext::new(parts);
    let resolved = context
        .scope(async move {
            return current_user::<TestUser>().await;
        })
        .await;
    let user = resolved.expect("guest lookup must succeed");
    assert!(user.is_none(), "guests must resolve to no user");
}

#[tokio::test]
async fn current_user_resolves_the_authenticated_user() {
    let config = config();
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (_login, headers) = run_login(parts, IDENTIFIER, PASSWORD).await;
    let token = response_token(&headers, COOKIE);

    let parts = request_parts(Some(&config), COOKIE, Some(&token), "/api/auth/session");
    let context = FullstackContext::new(parts);
    let resolved = context
        .scope(async move {
            return current_user::<TestUser>().await;
        })
        .await;
    let user = resolved
        .expect("session lookup must succeed")
        .expect("an authenticated user must resolve");
    assert_eq!(user.id, USER_ID);
}

#[tokio::test]
async fn missing_configuration_errors_instead_of_panicking() {
    // No extension and no process-global registration (that state lives in
    // tests/fullstack_global_tests.rs, a separate process).
    let bare = http::Request::builder()
        .method(http::Method::POST)
        .uri("/api/auth/session")
        .body(())
        .expect("request construction must succeed")
        .into_parts()
        .0;
    let context = FullstackContext::new(bare);
    let result = context
        .scope(async move { return dioxus_auth_session().await })
        .await;
    match result {
        Err(ServerFnError::ServerError { code: 500, .. }) => {}
        other => panic!("expected 500, got {other:?}"),
    }
}

#[tokio::test]
async fn context_reports_authentication_state() {
    let config = config();
    let guest = FullstackContext::new(request_parts(
        Some(&config),
        COOKIE,
        None,
        "/api/auth/session",
    ));
    let guest_authenticated = guest
        .scope(async move {
            let context = ServerAuthContext::<TestUser>::from_request()
                .await
                .expect("guest context must resolve");
            return context.is_authenticated();
        })
        .await;
    assert!(!guest_authenticated);

    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (_login, headers) = run_login(parts, IDENTIFIER, PASSWORD).await;
    let token = response_token(&headers, COOKIE);
    let authed = FullstackContext::new(request_parts(
        Some(&config),
        COOKIE,
        Some(&token),
        "/api/auth/session",
    ));
    let authed_authenticated = authed
        .scope(async move {
            let context = ServerAuthContext::<TestUser>::from_request()
                .await
                .expect("session context must resolve");
            return context.is_authenticated();
        })
        .await;
    assert!(authed_authenticated);
}

#[tokio::test]
async fn login_cookie_honors_the_configured_samesite_policy() {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(USER_ID, IDENTIFIER), IDENTIFIER, PASSWORD);
    let store = Arc::new(store);
    let engine = Arc::new(
        AuthEngine::builder(Arc::clone(&store), store)
            .hasher(IdentityHasher)
            .build()
            .expect("engine construction must succeed"),
    );
    let cookie = CookieConfig::new()
        .with_name(String::from(COOKIE))
        .with_same_site(SameSite::None);
    let config = ServerAuthConfig::new(AuthEngineHandle::from(engine), cookie);

    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (result, headers) = run_login(parts, IDENTIFIER, PASSWORD).await;
    result.expect("login must succeed");
    let set_cookie = headers
        .get(http::header::SET_COOKIE)
        .expect("login must set a response cookie")
        .to_str()
        .expect("the Set-Cookie header must be valid");
    assert!(
        set_cookie.contains("SameSite=None"),
        "the cookie must carry the configured policy"
    );
}

#[tokio::test]
async fn cookie_write_outside_a_request_errors() {
    let config = config();
    let result = write_session_cookie(config.cookie(), Some("token"));
    assert!(matches!(result, Err(ServerError::MissingContext)));
}

#[test]
fn auth_errors_map_to_status_codes() {
    let cases = [
        (AuthError::InvalidCredentials, 401),
        (AuthError::PasswordHashError, 401),
        (AuthError::RateLimited, 429),
        (AuthError::Internal(String::from("boom")), 500),
    ];
    for (error, expected) in cases {
        let message = error.to_string();
        let converted: ServerFnError = error.into();
        let (code, text) = match converted {
            ServerFnError::ServerError { code, message, .. } => (code, message),
            _ => panic!("expected a server error for {message}"),
        };
        assert_eq!(code, expected);
        assert_eq!(text, message);
    }
}
