//! Cookie render/extract symmetry tests for host-only configurations.

// reason: project style requires explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::sync::Arc;

use dioxus_auth::{CookieConfig, SameSite, ServerAuthConfig};
use dioxus_fullstack::http;

use super::common::TestUser;
use super::fullstack_shared::{
    IDENTIFIER, PASSWORD, USER_ID, build_config, error_code, request_parts, response_token,
    run_login, run_session,
};
use super::harness::{COOKIE, ORIGIN, config, origin_parts, origins_config};

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

/// Builds session-request parts carrying several `Cookie` headers verbatim.
fn parts_with_cookies(
    config: &ServerAuthConfig<TestUser>,
    cookies: &[String],
) -> http::request::Parts {
    let mut request = http::Request::builder()
        .method(http::Method::POST)
        .uri("/api/auth/session")
        .extension(Arc::new(config.clone()));
    for cookie in cookies {
        request = request.header(http::header::COOKIE, cookie);
    }
    return request
        .body(())
        .expect("request construction must succeed")
        .into_parts()
        .0;
}

/// Duplicate cookie names resolve deterministically: the last occurrence
/// wins, and either order terminates (never hangs, never panics).
#[tokio::test]
async fn duplicate_cookie_names_resolve_last_wins() {
    let config = config();
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (result, headers) = run_login(parts, IDENTIFIER, PASSWORD).await;
    result.expect("login must succeed");
    let token = response_token(&headers, COOKIE);

    let valid_first = parts_with_cookies(
        &config,
        &[
            format!("{COOKIE}={token}"),
            String::from("dioxus_auth_test_session=garbage"),
        ],
    );
    assert_eq!(error_code(&run_session(valid_first).await), 401);

    let valid_last = parts_with_cookies(
        &config,
        &[
            String::from("dioxus_auth_test_session=garbage"),
            format!("{COOKIE}={token}"),
        ],
    );
    run_session(valid_last).await.expect("last cookie must win");
}

/// Hostile cookie values — empty, missing `=`, oversized, `=`-laden — are
/// cheap rejections, never panics.
#[tokio::test]
async fn hostile_cookie_values_are_rejected() {
    let config = config();
    let hostile = [
        String::new(),
        String::from("just-a-value"),
        String::from("="),
        format!("{COOKIE}="),
        format!("{COOKIE}=short"),
        format!("{COOKIE}={}", "a".repeat(10_000)),
        format!("{COOKIE}=a=b=c"),
        format!("{COOKIE}=GARBAGE-UPPERCASE-0123456789abcdef0123456789abcdef0123456789abcd"),
    ];
    for value in hostile {
        let parts = parts_with_cookies(&config, &[value]);
        assert_eq!(
            error_code(&run_session(parts).await),
            401,
            "hostile cookie values must not resolve"
        );
    }
}

/// Origin matching is exact: a trailing slash or a case change is a different
/// origin and fails state-changing operations.
#[tokio::test]
async fn origin_matching_is_exact() {
    let config = origins_config();
    for forged in [
        format!("{ORIGIN}/"),
        String::from("HTTPS://APP.EXAMPLE.COM"),
        String::from("https://app.example.com:443"),
    ] {
        let parts = origin_parts(&config, None, "/api/auth/login", Some(&forged));
        let (result, _) = run_login(parts, IDENTIFIER, PASSWORD).await;
        assert_eq!(
            error_code(&result),
            403,
            "near-miss origins must fail closed: {forged}"
        );
    }
}
