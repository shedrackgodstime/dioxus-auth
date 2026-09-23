//! Cookie render/extract symmetry tests for host-only configurations.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use dioxus_auth::{CookieConfig, SameSite, ServerAuthConfig};
use dioxus_fullstack::http;

use super::common::TestUser;
use super::fullstack_shared::{
    IDENTIFIER, PASSWORD, USER_ID, build_config, error_code, request_parts, response_token,
    run_login, run_session,
};
use super::harness::{COOKIE, config};

/// A host-only configuration over the shared seeded engine spine.
fn host_only_config() -> ServerAuthConfig<TestUser> {
    let base = build_config(COOKIE);
    let cookie = CookieConfig::new()
        .with_name(String::from(COOKIE))
        .with_path(String::from("/app"))
        .with_domain(Some(String::from("example.com")))
        .with_host_only(true);
    return ServerAuthConfig::new(base.engine().clone(), cookie);
}

/// The emitted `Set-Cookie` name for a host-only configuration.
fn prefixed_name() -> String {
    return format!("__Host-{COOKIE}");
}

#[tokio::test]
async fn host_only_login_emits_a_prefixed_secure_cookie() {
    let config = host_only_config();
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (result, headers) = run_login(parts, IDENTIFIER, PASSWORD).await;
    result.expect("login must succeed");

    let set_cookie = headers
        .get(http::header::SET_COOKIE)
        .expect("login must set a response cookie")
        .to_str()
        .expect("the Set-Cookie header must be valid");
    let prefixed = prefixed_name();
    assert!(
        set_cookie.starts_with(&format!("{prefixed}=")),
        "the cookie name must carry the __Host- prefix"
    );
    assert!(
        set_cookie.contains("Path=/;") || set_cookie.contains("Path=/ "),
        "host-only cookies must force Path=/"
    );
    assert!(
        !set_cookie.contains("/app"),
        "the configured path must not leak into host-only cookies"
    );
    assert!(
        !set_cookie.contains("Domain="),
        "host-only cookies must omit Domain"
    );
    assert!(
        set_cookie.contains("Secure"),
        "host-only cookies must be Secure"
    );
}

#[tokio::test]
async fn host_only_session_resolves_through_the_prefixed_cookie() {
    let config = host_only_config();
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (result, headers) = run_login(parts, IDENTIFIER, PASSWORD).await;
    result.expect("login must succeed");

    let token = response_token(&headers, &prefixed_name());
    assert!(!token.is_empty());
    let parts = request_parts(
        Some(&config),
        &prefixed_name(),
        Some(&token),
        "/api/auth/session",
    );
    let user = run_session(parts).await.expect("session must resolve");
    assert_eq!(user.id, USER_ID);
}

#[tokio::test]
async fn host_only_rejects_the_bare_cookie_name() {
    let config = host_only_config();
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (result, headers) = run_login(parts, IDENTIFIER, PASSWORD).await;
    result.expect("login must succeed");
    let token = response_token(&headers, &prefixed_name());

    let parts = request_parts(Some(&config), COOKIE, Some(&token), "/api/auth/session");
    let result = run_session(parts).await;
    assert_eq!(error_code(&result), 401);
}

#[tokio::test]
async fn default_config_rejects_the_prefixed_cookie_name() {
    let config = config();
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (result, headers) = run_login(parts, IDENTIFIER, PASSWORD).await;
    result.expect("login must succeed");
    let token = response_token(&headers, COOKIE);

    let parts = request_parts(
        Some(&config),
        &prefixed_name(),
        Some(&token),
        "/api/auth/session",
    );
    let result = run_session(parts).await;
    assert_eq!(error_code(&result), 401);
}

#[tokio::test]
async fn same_site_none_forces_secure_even_when_disabled() {
    let base = build_config(COOKIE);
    let cookie = CookieConfig::new()
        .with_name(String::from(COOKIE))
        .with_secure(false)
        .with_same_site(SameSite::None);
    let config = ServerAuthConfig::new(base.engine().clone(), cookie);
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
        "the configured policy must render"
    );
    assert!(
        set_cookie.contains("Secure"),
        "SameSite=None without Secure is rejected by browsers; the crate must force it"
    );
}
