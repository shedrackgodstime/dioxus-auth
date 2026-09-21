//! Router-level tests for the axum middleware layers.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use dioxus_auth::prelude::{AuthLayer, RequireAuthLayer};
use dioxus_fullstack::axum::{Router, body::Body, extract::Request, routing::get};
use dioxus_fullstack::http::{self, StatusCode};
use tower::ServiceExt;

use super::fullstack_shared::{IDENTIFIER, PASSWORD, request_parts, response_token, run_login};
use super::harness::{COOKIE, config, probe};

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
