//! Fixtures for the extension-driven fullstack tests.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::sync::Arc;

use dioxus_auth::prelude::{CookieConfig, ServerAuthConfig};
use dioxus_fullstack::axum::extract::Extension;
use dioxus_fullstack::http::{self, HeaderMap, StatusCode};

use super::common::TestUser;
use super::fullstack_shared::{build_config, request_parts, response_token};

/// Session cookie name for the extension-driven suite.
pub const COOKIE: &str = "dioxus_auth_test_session";

/// Origin accepted by the origins-configured suite.
pub const ORIGIN: &str = "https://app.example.com";

/// A server auth configuration with one seeded identity.
pub fn config() -> ServerAuthConfig<TestUser> {
    return build_config(COOKIE);
}

/// A server auth configuration that enforces request origins.
pub fn origins_config() -> ServerAuthConfig<TestUser> {
    let base = build_config(COOKIE);
    let cookie = CookieConfig::new()
        .with_name(String::from(COOKIE))
        .with_expected_origins(vec![String::from(ORIGIN)]);
    return ServerAuthConfig::new(base.engine().clone(), cookie);
}

/// Builds request parts with an optional `Origin` header.
pub fn origin_parts(
    config: &ServerAuthConfig<TestUser>,
    token: Option<&str>,
    uri: &str,
    origin: Option<&str>,
) -> http::request::Parts {
    let mut parts = request_parts(Some(config), COOKIE, token, uri);
    if let Some(origin) = origin {
        parts.headers.insert(
            http::header::ORIGIN,
            origin.parse().expect("origins must be valid header values"),
        );
    }
    return parts;
}

/// A probe handler that only runs when the config extension is attached.
// reason: axum requires handlers to be async; the body performs no awaits.
#[allow(clippy::unused_async)]
pub async fn probe(Extension(_config): Extension<Arc<ServerAuthConfig<TestUser>>>) -> StatusCode {
    return StatusCode::OK;
}

/// Asserts a response carries an emptied session cookie with `Max-Age=0`.
pub fn assert_cleared_cookie(headers: &HeaderMap) {
    let set_cookie = headers
        .get(http::header::SET_COOKIE)
        .expect("logout must set a response cookie")
        .to_str()
        .expect("the Set-Cookie header must be valid");
    assert!(
        set_cookie.contains("Max-Age=0"),
        "logout must emit a clearing cookie"
    );
    assert!(
        response_token(headers, COOKIE).is_empty(),
        "logout must clear the cookie value"
    );
}
