//! Shared harness for the fullstack server-function suites.
//!
//! Included by both `fullstack_tests` (request-extension configs) and
//! `fullstack_global_tests` (process-global registry). Every item here is
//! used by both binaries; binary-specific fixtures stay in the binaries. The
//! generated server functions are invoked once per binary at its root; the
//! runners below call them through `super`.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::sync::Arc;

use dioxus_auth::prelude::{
    AuthEngine, AuthEngineHandle, CookieConfig, LoginRequest, MemoryStore, ServerAuthConfig,
    ServerFnError,
};
use dioxus_fullstack::FullstackContext;
use dioxus_fullstack::http::{self, HeaderMap};

use super::common::TestUser;
use super::identity_hasher::IdentityHasher;

/// Seeded login identifier shared by the fullstack suites.
pub const IDENTIFIER: &str = "ada";
/// Seeded login password shared by the fullstack suites.
pub const PASSWORD: &str = "loves auth";
/// Seeded user id shared by the fullstack suites.
pub const USER_ID: u64 = 7;

/// Builds a server auth configuration with one seeded identity.
pub fn build_config(cookie_name: &str) -> ServerAuthConfig<TestUser> {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(USER_ID, IDENTIFIER), IDENTIFIER, PASSWORD);
    let store = Arc::new(store);
    let engine = Arc::new(
        AuthEngine::builder(Arc::clone(&store), store)
            .hasher(IdentityHasher)
            .build()
            .expect("engine construction must succeed"),
    );
    return ServerAuthConfig::new(
        AuthEngineHandle::from(engine),
        CookieConfig::new().with_name(String::from(cookie_name)),
    );
}

/// Builds request parts for a server-function call.
///
/// Attaches the config extension exactly as the axum middleware would install
/// it; `None` leaves extension resolution to the process-global registry.
pub fn request_parts(
    config: Option<&ServerAuthConfig<TestUser>>,
    cookie_name: &str,
    token: Option<&str>,
    uri: &str,
) -> http::request::Parts {
    let mut request = http::Request::builder().method(http::Method::POST).uri(uri);
    if let Some(config) = config {
        request = request.extension(Arc::new(config.clone()));
    }
    if let Some(token) = token {
        request = request.header(http::header::COOKIE, format!("{cookie_name}={token}"));
    }
    let request = request.body(()).expect("request construction must succeed");
    return request.into_parts().0;
}

/// Reads the session token from a `Set-Cookie` response header.
pub fn response_token(headers: &HeaderMap, cookie_name: &str) -> String {
    let value = headers
        .get(http::header::SET_COOKIE)
        .expect("a Set-Cookie header must be present");
    let value = value.to_str().expect("the Set-Cookie header must be valid");
    let prefix = format!("{cookie_name}=");
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

/// Extracts the `ServerFnError::ServerError` code from a result.
pub fn error_code<T: std::fmt::Debug>(result: &Result<T, ServerFnError>) -> u16 {
    return match result {
        Err(ServerFnError::ServerError { code, .. }) => *code,
        Err(other) => panic!("unexpected server fn error shape: {other:?}"),
        Ok(_) => panic!("expected an error, got {result:?}"),
    };
}

/// Runs the generated login server function in a fullstack scope.
pub async fn run_login(
    parts: http::request::Parts,
    identifier: &str,
    password: &str,
) -> (Result<TestUser, ServerFnError>, HeaderMap) {
    let identifier = String::from(identifier);
    let password = String::from(password);
    let context = FullstackContext::new(parts);
    let probe = context.clone();
    let result = context
        .scope(async move {
            return super::dioxus_auth_login(LoginRequest {
                identifier,
                password,
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

/// Runs the generated session server function in a fullstack scope.
pub async fn run_session(parts: http::request::Parts) -> Result<TestUser, ServerFnError> {
    let context = FullstackContext::new(parts);
    return context
        .scope(async move { return super::dioxus_auth_session().await })
        .await;
}

/// Runs the generated logout server function in a fullstack scope.
pub async fn run_logout(parts: http::request::Parts) -> (Result<(), ServerFnError>, HeaderMap) {
    let context = FullstackContext::new(parts);
    let probe = context.clone();
    let result = context
        .scope(async move { return super::dioxus_auth_logout().await })
        .await;
    return (
        result,
        probe
            .take_response_headers()
            .expect("response headers must exist"),
    );
}
