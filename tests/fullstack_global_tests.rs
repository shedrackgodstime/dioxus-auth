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

use std::sync::Arc;

use common::{IdentityHasher, TestUser};
use dioxus_auth::prelude::{
    AuthEngine, AuthEngineHandle, CookieConfig, LoginRequest, MemoryStore, ServerAuthConfig,
    ServerError, ServerFnError, SessionId, server_init,
};
use dioxus_fullstack::FullstackContext;
use dioxus_fullstack::http::{self, HeaderMap};

dioxus_auth::fullstack_server_fns!(TestUser);

const COOKIE: &str = "dioxus_auth_global_test_session";
const IDENTIFIER: &str = "ada";
const PASSWORD: &str = "loves auth";
const USER_ID: u64 = 7;

/// Builds a fresh engine + config with the shared seeded identity.
fn fresh_config() -> ServerAuthConfig<TestUser> {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(USER_ID, IDENTIFIER), IDENTIFIER, PASSWORD);
    let store = Arc::new(store);
    let engine = Arc::new(
        AuthEngine::builder(Arc::clone(&store), store)
            .hasher(IdentityHasher)
            .build()
            .expect("engine construction must succeed"),
    );
    let config = ServerAuthConfig::new(
        AuthEngineHandle::from(engine),
        CookieConfig::new().with_name(String::from(COOKIE)),
    );
    match server_init(config.clone()) {
        Ok(()) | Err(ServerError::AlreadyInitialized) => return config,
        Err(other) => panic!("unexpected init error: {other:?}"),
    }
}

/// Builds request parts with no request extension, so the process-global
/// registry is the only way the configuration can resolve.
fn parts(token: Option<&str>, uri: &str) -> http::request::Parts {
    let mut request = http::Request::builder().method(http::Method::POST).uri(uri);
    if let Some(token) = token {
        request = request.header(http::header::COOKIE, format!("{COOKIE}={token}"));
    }
    let request = request.body(()).expect("request construction must succeed");
    return request.into_parts().0;
}

/// Extracts the session token from a `Set-Cookie` response header.
fn response_token(headers: &HeaderMap) -> String {
    let value = headers
        .get(http::header::SET_COOKIE)
        .expect("a Set-Cookie header must be present")
        .to_str()
        .expect("the Set-Cookie header must be valid");
    let prefix = format!("{COOKIE}=");
    let token = value
        .strip_prefix(&prefix)
        .expect("the cookie name must match");
    return token
        .split(';')
        .next()
        .expect("a cookie value must be present")
        .trim()
        .to_owned();
}

async fn run_login_global(
    identifier: &str,
    password: &str,
) -> (Result<TestUser, ServerFnError>, HeaderMap) {
    let context = FullstackContext::new(parts(None, "/api/auth/login"));
    let probe = context.clone();
    let result = context
        .scope(async move {
            return dioxus_auth_login(LoginRequest {
                identifier: String::from(identifier),
                password: String::from(password),
            })
            .await;
        })
        .await;
    return (
        result,
        probe
            .take_response_headers()
            .expect("response headers must exist"),
    );
}

async fn run_session_global(cookie: Option<&str>) -> Result<TestUser, ServerFnError> {
    let context = FullstackContext::new(parts(cookie, "/api/auth/session"));
    return context
        .scope(async move { return dioxus_auth_session().await })
        .await;
}

fn error_code(result: &Result<TestUser, ServerFnError>) -> u16 {
    return match result {
        Err(ServerFnError::ServerError { code, .. }) => *code,
        Err(other) => panic!("unexpected server fn error shape: {other:?}"),
        Ok(_) => panic!("expected an error, got {result:?}"),
    };
}

#[tokio::test]
async fn guest_requests_resolve_via_the_process_global_config() {
    let _config = fresh_config();
    let result = run_session_global(None).await;
    assert_eq!(
        error_code(&result),
        401,
        "a guest session must report 401, not 500"
    );
}

#[tokio::test]
async fn authenticated_sessions_resolve_via_the_process_global_config() {
    let _config = fresh_config();
    let (_login, headers) = run_login_global(IDENTIFIER, PASSWORD).await;
    let token = response_token(&headers);
    assert!(SessionId::is_valid_wire_format(&token));

    let user = run_session_global(Some(&token))
        .await
        .expect("the session must resolve against the global config");
    assert_eq!(user.id, USER_ID);
}

#[tokio::test]
async fn second_initialization_is_rejected() {
    let config = fresh_config();
    match server_init(config) {
        Err(ServerError::AlreadyInitialized) => {}
        other => panic!("expected AlreadyInitialized, got {other:?}"),
    }
}
