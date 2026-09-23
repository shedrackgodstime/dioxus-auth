//! Origin-enforcement tests for state-changing server functions.

// reason: project style requires explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use super::fullstack_shared::{
    IDENTIFIER, PASSWORD, USER_ID, error_code, request_parts, response_token, run_login,
    run_logout, run_session,
};
use super::harness::{COOKIE, ORIGIN, origin_parts, origins_config};

#[tokio::test]
async fn login_accepts_a_matching_origin() {
    let config = origins_config();
    let parts = origin_parts(&config, None, "/api/auth/login", Some(ORIGIN));
    let (result, _) = run_login(parts, IDENTIFIER, PASSWORD).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn login_rejects_a_mismatched_origin_with_403() {
    let config = origins_config();
    let parts = origin_parts(
        &config,
        None,
        "/api/auth/login",
        Some("https://evil.example.com"),
    );
    let (result, _) = run_login(parts, IDENTIFIER, PASSWORD).await;
    assert_eq!(error_code(&result), 403);
}

#[tokio::test]
async fn login_rejects_a_missing_origin_with_403() {
    let config = origins_config();
    let parts = origin_parts(&config, None, "/api/auth/login", None);
    let (result, _) = run_login(parts, IDENTIFIER, PASSWORD).await;
    assert_eq!(error_code(&result), 403);
}

#[tokio::test]
async fn logout_rejects_a_mismatched_origin_with_403() {
    let config = origins_config();
    let login_parts = origin_parts(&config, None, "/api/auth/login", Some(ORIGIN));
    let (login, headers) = run_login(login_parts, IDENTIFIER, PASSWORD).await;
    assert!(login.is_ok());
    let token = response_token(&headers, COOKIE);

    let parts = origin_parts(
        &config,
        Some(&token),
        "/api/auth/logout",
        Some("https://evil.example.com"),
    );
    let (result, _) = run_logout(parts).await;
    assert_eq!(error_code(&result), 403);

    let parts = request_parts(Some(&config), COOKIE, Some(&token), "/api/auth/session");
    let user = run_session(parts).await.expect("no logout must have run");
    assert_eq!(user.id, USER_ID);
}

#[tokio::test]
async fn logout_rejects_a_missing_origin_with_403() {
    let config = origins_config();
    let login_parts = origin_parts(&config, None, "/api/auth/login", Some(ORIGIN));
    let (login, headers) = run_login(login_parts, IDENTIFIER, PASSWORD).await;
    assert!(login.is_ok());
    let token = response_token(&headers, COOKIE);

    let parts = origin_parts(&config, Some(&token), "/api/auth/logout", None);
    let (result, _) = run_logout(parts).await;
    assert_eq!(error_code(&result), 403);
}

#[tokio::test]
async fn session_resolution_ignores_origin() {
    let config = origins_config();
    let login_parts = origin_parts(&config, None, "/api/auth/login", Some(ORIGIN));
    let (login, headers) = run_login(login_parts, IDENTIFIER, PASSWORD).await;
    assert!(login.is_ok());
    let token = response_token(&headers, COOKIE);

    let parts = request_parts(Some(&config), COOKIE, Some(&token), "/api/auth/session");
    let user = run_session(parts)
        .await
        .expect("reads must not require an origin");
    assert_eq!(user.id, USER_ID);
}
