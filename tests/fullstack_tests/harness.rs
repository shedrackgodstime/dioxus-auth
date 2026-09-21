//! Fixtures for the extension-driven fullstack tests.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::sync::Arc;

use dioxus_auth::prelude::ServerAuthConfig;
use dioxus_fullstack::axum::extract::Extension;
use dioxus_fullstack::http::{self, HeaderMap, StatusCode};

use super::common::TestUser;
use super::fullstack_shared::{build_config, response_token};

/// Session cookie name for the extension-driven suite.
pub const COOKIE: &str = "dioxus_auth_test_session";

/// A server auth configuration with one seeded identity.
pub fn config() -> ServerAuthConfig<TestUser> {
    return build_config(COOKIE);
}

/// A probe handler that only runs when the config extension is attached.
#[allow(clippy::unused_async)]
// reason: axum requires handlers to be async; the body performs no awaits.
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
