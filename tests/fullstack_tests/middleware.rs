//! Router-level tests for the axum middleware layers.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use std::sync::Arc;

use dioxus_auth::prelude::{
    AuthEngine, AuthEngineHandle, AuthError, AuthLayer, CookieConfig, MemoryStore,
    RequireAuthLayer, ServerAuthConfig, Session, SessionId, SessionStore,
};
use dioxus_fullstack::axum::{Router, body::Body, extract::Request, routing::get};
use dioxus_fullstack::http::{self, StatusCode};
use tower::ServiceExt;

use super::common::TestUser;
use super::fullstack_shared::{
    IDENTIFIER, PASSWORD, USER_ID, request_parts, response_token, run_login,
};
use super::harness::{COOKIE, config, probe};
use super::identity_hasher::IdentityHasher;

#[tokio::test]
async fn auth_layer_attaches_the_config_to_every_request() {
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
async fn require_auth_layer_rejects_guests_and_accepts_valid_sessions() {
    let config = config();
    let parts = request_parts(Some(&config), COOKIE, None, "/api/auth/login");
    let (_login, headers) = run_login(parts, IDENTIFIER, PASSWORD).await;
    let token = response_token(&headers, COOKIE);
    let app = Router::new()
        .route("/", get(probe))
        .layer(RequireAuthLayer::new(config));

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

/// A session store that always fails, to exercise the middleware's 500 path.
#[derive(Debug)]
struct FailingSessionStore;

impl SessionStore for FailingSessionStore {
    type Id = u64;

    fn save_session(&self, _session: Session<u64>) -> Result<(), AuthError> {
        return Err(AuthError::Internal(String::from("store unavailable")));
    }

    fn find_session(&self, _id: &SessionId) -> Result<Option<Session<u64>>, AuthError> {
        return Err(AuthError::Internal(String::from("store unavailable")));
    }

    fn delete_session(&self, _id: &SessionId) -> Result<(), AuthError> {
        return Err(AuthError::Internal(String::from("store unavailable")));
    }

    fn touch_session_if_present(
        &self,
        _id: &SessionId,
        _new_expiry: u64,
        _last_active: u64,
    ) -> Result<(), AuthError> {
        return Err(AuthError::Internal(String::from("store unavailable")));
    }

    fn delete_user_sessions(&self, _user_id: &u64) -> Result<(), AuthError> {
        return Err(AuthError::Internal(String::from("store unavailable")));
    }

    fn list_user_sessions(&self, _user_id: &u64) -> Result<Vec<Session<u64>>, AuthError> {
        return Err(AuthError::Internal(String::from("store unavailable")));
    }
}

#[tokio::test]
async fn require_auth_layer_reports_store_failures_as_500() {
    let users = Arc::new(MemoryStore::<TestUser>::new());
    users.insert_user_with_password(TestUser::new(USER_ID, IDENTIFIER), IDENTIFIER, PASSWORD);
    let engine = Arc::new(
        AuthEngine::builder(Arc::clone(&users), Arc::new(FailingSessionStore))
            .hasher(IdentityHasher)
            .build()
            .expect("engine construction must succeed"),
    );
    let config = ServerAuthConfig::new(
        AuthEngineHandle::from(engine),
        CookieConfig::new().with_name(String::from(COOKIE)),
    );
    let app = Router::new()
        .route("/", get(probe))
        .layer(RequireAuthLayer::new(config));

    let token = SessionId::generate();
    let cookie = format!("{COOKIE}={}", token.as_str());
    let request = Request::builder()
        .uri("/")
        .header(http::header::COOKIE, cookie)
        .body(Body::empty())
        .expect("request construction must succeed");
    let response = app.oneshot(request).await.expect("the router must respond");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
