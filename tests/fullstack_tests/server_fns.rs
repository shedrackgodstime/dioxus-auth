//! Tests for the generated login, logout, and session server functions.

// reason: project style requires explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::sync::Arc;

use dioxus_auth::{
    AttachRequest, AuthEngine, AuthEngineHandle, AuthError, ChangePasswordRequest, CookieConfig,
    MemoryStore, SameSite, ServerAuthConfig, ServerAuthContext, ServerError, SessionId,
    current_user, require_user, write_session_cookie,
};
use dioxus_fullstack::http;
use dioxus_fullstack::{FullstackContext, ServerFnError};

/// Runs the generated attach server function in a fullstack scope.
pub async fn run_attach(
    parts: http::request::Parts,
    identifier: &str,
    password: &str,
) -> Result<(), ServerFnError> {
    let request = AttachRequest {
        identifier: String::from(identifier),
        password: String::from(password),
    };
    let context = FullstackContext::new(parts);
    return context
        .scope(async move { return super::dioxus_auth_attach(request).await })
        .await;
}

/// Runs the generated change-password server function in a fullstack scope.
pub async fn run_change_password(
    parts: http::request::Parts,
    identifier: &str,
    current_password: &str,
    new_password: &str,
) -> Result<(), ServerFnError> {
    let request = ChangePasswordRequest {
        identifier: String::from(identifier),
        current_password: String::from(current_password),
        new_password: String::from(new_password),
    };
    let context = FullstackContext::new(parts);
    return context
        .scope(async move { return super::dioxus_auth_change_password(request).await })
        .await;
}

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
async fn attach_adds_a_login_for_the_session_owner() {
    let config = config();
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (_login, headers) = run_login(parts, IDENTIFIER, PASSWORD).await;
    let token = response_token(&headers, COOKIE);

    let parts = request_parts(Some(&config), COOKIE, Some(&token), "/api/auth/attach");
    run_attach(parts, "ada-2", PASSWORD)
        .await
        .expect("attach must succeed");

    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (login, _) = run_login(parts, "ada-2", PASSWORD).await;
    let user = login.expect("attached login must work");
    assert_eq!(user.id, USER_ID);
}

#[tokio::test]
async fn attach_rejects_guests_with_401() {
    let config = config();
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/attach");
    let result = run_attach(parts, "ada-2", PASSWORD).await;
    assert_eq!(error_code(&result), 401);
}

#[tokio::test]
async fn attach_rejects_taken_identifiers() {
    let config = config();
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (_login, headers) = run_login(parts, IDENTIFIER, PASSWORD).await;
    let token = response_token(&headers, COOKIE);

    let parts = request_parts(Some(&config), COOKIE, Some(&token), "/api/auth/attach");
    let result = run_attach(parts, IDENTIFIER, PASSWORD).await;
    assert_eq!(error_code(&result), 401);
}

#[tokio::test]
async fn change_password_rotates_the_credential_over_the_wire() {
    let config = config();
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (_login, headers) = run_login(parts, IDENTIFIER, PASSWORD).await;
    let token = response_token(&headers, COOKIE);

    let parts = request_parts(
        Some(&config),
        COOKIE,
        Some(&token),
        "/api/auth/change-password",
    );
    run_change_password(parts, IDENTIFIER, PASSWORD, "rotated")
        .await
        .expect("change must succeed");

    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (stale, _) = run_login(parts, IDENTIFIER, PASSWORD).await;
    assert_eq!(error_code(&stale), 401);
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (fresh, _) = run_login(parts, IDENTIFIER, "rotated").await;
    assert!(fresh.is_ok());
}

#[tokio::test]
async fn change_password_rejects_wrong_current_password() {
    let config = config();
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (_login, headers) = run_login(parts, IDENTIFIER, PASSWORD).await;
    let token = response_token(&headers, COOKIE);

    let parts = request_parts(
        Some(&config),
        COOKIE,
        Some(&token),
        "/api/auth/change-password",
    );
    let result = run_change_password(parts, IDENTIFIER, "wrong", "rotated").await;
    assert_eq!(error_code(&result), 401);
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
    assert!(
        matches!(result, Err(ServerFnError::ServerError { code: 500, .. })),
        "expected a 500 server error, got {result:?}"
    );
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
        (AuthError::Csrf, 403),
        (AuthError::Internal(String::from("boom")), 500),
    ];
    for (error, expected) in cases {
        let converted: ServerFnError = error.into();
        let code = match converted {
            ServerFnError::ServerError { code, .. } => code,
            _ => panic!("expected a server error"),
        };
        assert_eq!(code, expected);
    }
    // Internal details never reach the wire: the code carries the signal.
    let converted: ServerFnError = AuthError::Internal(String::from("boom")).into();
    let text = match converted {
        ServerFnError::ServerError { message, .. } => message,
        _ => panic!("expected a server error"),
    };
    assert_eq!(text, "internal error");
    assert!(!text.contains("boom"));
}

/// Async entry points stay `Send`: futures holding the context, config, or
/// engine across an `.await` must not trap callers on a single thread.
#[test]
fn server_futures_are_send() {
    fn assert_send<T: Send>(_: T) {}
    assert_send(ServerAuthContext::<TestUser>::from_request());
    assert_send(current_user::<TestUser>());
    assert_send(require_user::<TestUser>());
}
