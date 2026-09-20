//! End-to-end tests for the fullstack server slice: the generated server
//! functions, cookie handling, and the filets middleware.
//!
//! Runs natively with both the `dioxus-fullstack` and `server` features:
//! `cargo test --features dioxus-fullstack,server --test fullstack_tests`.
//!
//! Every test scopes its request with the configuration attached as a request
//! extension, so the process-global registry (exercised by
//! `tests/fullstack_global_tests.rs`) never leaks into these results.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]
// reason: the middleware closures intentionally yield `async` blocks whose
// `Send`-safety is checked by the layer conversion, not in the test body.
#![allow(clippy::unused_async)]

mod common;

use std::sync::Arc;

use common::{IdentityHasher, TestUser};
use dioxus_auth::prelude::{
    AuthEngine, AuthEngineHandle, AuthLayer, CookieConfig, LoginRequest, MemoryStore,
    RequireAuthLayer, ServerAuthConfig, ServerError, ServerFnError, SessionId, require_user,
};
use dioxus_fullstack::FullstackContext;
use dioxus_fullstack::axum::{
    Router,
    body::Body,
    extract::{Extension, Request},
    routing::get,
};
use dioxus_fullstack::http::{self, HeaderMap, StatusCode};
use tower::ServiceExt;

dioxus_auth::fullstack_server_fns!(TestUser);

const COOKIE: &str = "dioxus_auth_test_session";
const IDENTIFIER: &str = "ada";
const PASSWORD: &str = "loves auth";

/// A server auth configuration with one seeded identity: `ada` / `loves auth`.
fn config() -> ServerAuthConfig<TestUser> {
    let store = MemoryStore::<TestUser>::new();
    store.insert_user_with_password(TestUser::new(7, "ada"), IDENTIFIER, PASSWORD);
    let store = Arc::new(store);
    let engine = Arc::new(
        AuthEngine::builder(Arc::clone(&store), store)
            .hasher(IdentityHasher)
            .build()
            .expect("engine construction must succeed"),
    );
    return ServerAuthConfig::new(
        AuthEngineHandle::from(engine),
        CookieConfig::new().with_name(String::from(COOKIE)),
    );
}

/// Builds request parts for a server-function call: the config rides along in
/// the request extensions exactly as [`auth_middleware`] would install it.
fn parts(config: &ServerAuthConfig<TestUser>, token: Option<&str>) -> http::request::Parts {
    let mut request = http::Request::builder()
        .method(http::Method::POST)
        .uri("/api/auth/session")
        .extension(Arc::new(config.clone()));
    if let Some(token) = token {
        request = request.header(http::header::COOKIE, format!("{COOKIE}={token}"));
    }
    let request = request.body(()).expect("request construction must succeed");
    return request.into_parts().0;
}

/// Reads the session token from a `Set-Cookie` response header.
fn response_token(headers: &HeaderMap) -> String {
    let value = headers
        .get(http::header::SET_COOKIE)
        .expect("a Set-Cookie header must be present");
    let value = value.to_str().expect("the Set-Cookie header must be valid");
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

/// Runs the generated login server function in a fullstack scope.
async fn run_login(
    config: &ServerAuthConfig<TestUser>,
    cookie: Option<&str>,
) -> (Result<TestUser, ServerFnError>, HeaderMap) {
    let context = FullstackContext::new(parts(config, cookie));
    let probe = context.clone();
    let result = context
        .scope(async move {
            return dioxus_auth_login(LoginRequest {
                identifier: String::from(IDENTIFIER),
                password: String::from(PASSWORD),
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
async fn run_session(
    config: &ServerAuthConfig<TestUser>,
    cookie: Option<&str>,
) -> Result<TestUser, ServerFnError> {
    let context = FullstackContext::new(parts(config, cookie));
    return context
        .scope(async move { return dioxus_auth_session().await })
        .await;
}

/// Runs the generated logout server function in a fullstack scope.
async fn run_logout(
    config: &ServerAuthConfig<TestUser>,
    cookie: Option<&str>,
) -> (Result<(), ServerFnError>, HeaderMap) {
    let context = FullstackContext::new(parts(config, cookie));
    let probe = context.clone();
    let result = context
        .scope(async move { return dioxus_auth_logout().await })
        .await;
    return (
        result,
        probe
            .take_response_headers()
            .expect("response headers must exist"),
    );
}

/// Extracts the `ServerFnError::ServerError` code from a result.
fn error_code(result: &Result<TestUser, ServerFnError>) -> u16 {
    return match result {
        Err(ServerFnError::ServerError { code, .. }) => *code,
        Err(other) => panic!("unexpected server fn error shape: {other:?}"),
        Ok(_) => panic!("expected an error, got {result:?}"),
    };
}

#[tokio::test]
async fn login_sets_a_valid_session_cookie() {
    let config = config();
    let (result, headers) = run_login(&config, None).await;

    let user = result.expect("login must succeed");
    assert_eq!(user.id, 7);

    let token = response_token(&headers);
    assert!(
        SessionId::is_valid_wire_format(&token),
        "cookie token must be a valid session id"
    );
    let session = run_session(&config, Some(&token)).await;
    let resolved = session.expect("the session must resolve");
    assert_eq!(resolved.id, 7);
}

#[tokio::test]
async fn login_rejects_wrong_password_with_401() {
    let config = config();
    let context = FullstackContext::new(parts(&config, None));
    let result = context
        .scope(async move {
            return dioxus_auth_login(LoginRequest {
                identifier: String::from(IDENTIFIER),
                password: String::from("not the password"),
            })
            .await;
        })
        .await;
    assert_eq!(error_code(&result), 401);
}

#[tokio::test]
async fn session_returns_401_for_guests() {
    let config = config();
    let result = run_session(&config, None).await;
    assert_eq!(error_code(&result), 401);
}

#[tokio::test]
async fn session_returns_401_for_malformed_tokens() {
    let config = config();
    let result = run_session(&config, Some("not-a-valid-session-token")).await;
    assert_eq!(error_code(&result), 401);
}

#[tokio::test]
async fn session_resolves_the_authenticated_user() {
    let config = config();
    let (login, _) = run_login(&config, None).await;
    assert!(login.is_ok());

    let token = run_login(&config, None).await.1;
    let token = response_token(&token);
    let user = run_session(&config, Some(&token))
        .await
        .expect("session must resolve");
    assert_eq!(user.id, 7);
}

#[tokio::test]
async fn logout_clears_the_cookie_and_revokes_the_session() {
    let config = config();
    let (_login, headers) = run_login(&config, None).await;
    let token = response_token(&headers);

    let (result, headers) = run_logout(&config, Some(&token)).await;
    result.expect("logout must succeed");

    let set_cookie = headers
        .get(http::header::SET_COOKIE)
        .expect("logout must set a response cookie")
        .to_str()
        .expect("the Set-Cookie header must be valid");
    assert!(
        set_cookie.contains("Max-Age=0"),
        "logout must emit a clearing cookie"
    );

    let session = run_session(&config, Some(&token)).await;
    assert_eq!(error_code(&session), 401, "the session must be revoked");
}

#[tokio::test]
async fn current_user_guest_defaults_to_none() {
    let config = config();
    let context = FullstackContext::new(parts(&config, None));
    let resolved = context
        .scope(async move { return require_user::<TestUser>().err() })
        .await;
    assert!(matches!(resolved, Some(ServerError::MissingSession)));
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

/// A probe handler that only runs when the config extension is attached.
async fn probe(Extension(_config): Extension<Arc<ServerAuthConfig<TestUser>>>) -> StatusCode {
    return StatusCode::OK;
}

#[tokio::test]
async fn auth_middleware_attaches_the_config_to_every_request() {
    let config = config();
    let app = Router::new()
        .route("/", get(probe))
        .layer(AuthLayer::new(config));

    let request = Request::builder()
        .uri("/")
        .body(Body::empty())
        .expect("request construction must succeed");
    let response = app.oneshot(request).await.expect("the router must respond");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn require_auth_middleware_rejects_guests_and_accepts_valid_sessions() {
    let config = config();
    let (_login, headers) = run_login(&config, None).await;
    let token = response_token(&headers);
    let app = Router::new()
        .route("/", get(probe))
        .layer(RequireAuthLayer::for_config(config));

    let guest = Request::builder()
        .uri("/")
        .body(Body::empty())
        .expect("request construction must succeed");
    let response = app
        .clone()
        .oneshot(guest)
        .await
        .expect("the router must respond");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let cookie = format!("{COOKIE}={token}");
    let authed = Request::builder()
        .uri("/")
        .header(http::header::COOKIE, cookie)
        .body(Body::empty())
        .expect("request construction must succeed");
    let response = app.oneshot(authed).await.expect("the router must respond");
    assert_eq!(response.status(), StatusCode::OK);
}
