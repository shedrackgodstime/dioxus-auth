//! Tests for the process-global server configuration registry, exercised by
//! [`server_init`](dioxus_auth::prelude::server_init).
//!
//! The registry is process-wide, so these tests live in their own binary to
//! keep `tests/fullstack_tests.rs` deterministic. Every test either registers
//! the global configuration or tolerates an already-registered one, and the
//! seeded identity is identical across tests, so ordering never matters.
//!
//! `cargo test --features dioxus-fullstack,server --test fullstack_global_tests`.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

mod common;
#[path = "common/fullstack_shared.rs"]
mod fullstack_shared;
#[path = "common/identity_hasher.rs"]
mod identity_hasher;

use dioxus_auth::prelude::{ServerAuthConfig, ServerError, SessionId, server_init};
use dioxus_fullstack::http;

use common::TestUser;
use fullstack_shared::{
    IDENTIFIER, PASSWORD, USER_ID, build_config, error_code, request_parts, response_token,
    run_login, run_logout, run_session,
};

dioxus_auth::fullstack_server_fns!(TestUser);

const COOKIE: &str = "dioxus_auth_global_test_session";

/// Builds a fresh engine + config with the shared seeded identity.
fn fresh_config() -> ServerAuthConfig<TestUser> {
    let config = build_config(COOKIE);
    match server_init(config.clone()) {
        Ok(()) | Err(ServerError::AlreadyInitialized) => return config,
        Err(other) => panic!("unexpected init error: {other:?}"),
    }
}

/// Builds login parts with no request extension, so the process-global
/// registry is the only way the configuration can resolve.
fn login_parts() -> http::request::Parts {
    return request_parts(None, COOKIE, None, "/api/auth/login");
}

/// Builds session parts with no request extension, so the process-global
/// registry is the only way the configuration can resolve.
fn session_parts(token: Option<&str>) -> http::request::Parts {
    return request_parts(None, COOKIE, token, "/api/auth/session");
}

/// Builds logout parts with no request extension, so the process-global
/// registry is the only way the configuration can resolve.
fn logout_parts(token: &str) -> http::request::Parts {
    return request_parts(None, COOKIE, Some(token), "/api/auth/logout");
}

#[tokio::test]
async fn guest_requests_resolve_via_the_process_global_config() {
    let _config = fresh_config();
    let result = run_session(session_parts(None)).await;
    assert_eq!(
        error_code(&result),
        401,
        "a guest session must report 401, not 500"
    );
}

#[tokio::test]
async fn authenticated_sessions_resolve_via_the_process_global_config() {
    let _config = fresh_config();
    let (_login, headers) = run_login(login_parts(), IDENTIFIER, PASSWORD).await;
    let token = response_token(&headers, COOKIE);
    assert!(SessionId::is_valid_wire_format(&token));

    let user = run_session(session_parts(Some(&token)))
        .await
        .expect("the session must resolve against the global config");
    assert_eq!(user.id, USER_ID);
}

#[tokio::test]
async fn logout_revokes_the_global_session() {
    let _config = fresh_config();
    let (_login, headers) = run_login(login_parts(), IDENTIFIER, PASSWORD).await;
    let token = response_token(&headers, COOKIE);

    let (result, _) = run_logout(logout_parts(&token)).await;
    result.expect("logout must succeed");

    let session = run_session(session_parts(Some(&token))).await;
    assert_eq!(error_code(&session), 401, "the session must be revoked");
}

#[tokio::test]
async fn second_initialization_is_rejected() {
    let config = fresh_config();
    let result = server_init(config);
    assert!(
        matches!(result, Err(ServerError::AlreadyInitialized)),
        "expected AlreadyInitialized, got {result:?}"
    );
}
