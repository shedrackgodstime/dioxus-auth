//! HTTP-level tests for the demo app: login mints a cookie, the cookie
//! opens the guarded probe, guests get 401, logout clears the cookie.
//! Everything runs through `tower` without binding a port.

use std::sync::Arc;

use dioxus_fullstack::axum::body::Body;
use dioxus_fullstack::axum::http::{self, StatusCode};
use fullstack_app::{AppUser, app_config, app_router};
use tower::ServiceExt;

dioxus_auth::fullstack_server_fns!(AppUser);

fn cookie_value(headers: &http::HeaderMap, name: &str) -> String {
    let value = headers
        .get(http::header::SET_COOKIE)
        .expect("response must set a cookie")
        .to_str()
        .expect("cookie must be valid");
    let token = value
        .strip_prefix(&format!("{name}="))
        .expect("cookie name must match");
    token
        .split(';')
        .next()
        .expect("cookie value must exist")
        .to_string()
}

#[tokio::test]
async fn login_cookie_opens_the_probe_and_logout_closes_it() {
    let config = app_config();
    let login_parts = http::Request::builder()
        .method(http::Method::POST)
        .uri("/api/auth/login")
        .extension(Arc::new(config.clone()))
        .body(())
        .expect("request must build")
        .into_parts()
        .0;
    let context = dioxus_fullstack::FullstackContext::new(login_parts);
    let probe = context.clone();
    let result = context
        .scope(async move {
            dioxus_auth_login(dioxus_auth::LoginRequest {
                identifier: String::from("alice@example.com"),
                password: String::from("password"),
            })
            .await
        })
        .await;
    let user = result.expect("login must succeed");
    let headers = probe
        .take_response_headers()
        .expect("response headers must exist");
    assert_eq!(user.id, 1);
    let token = cookie_value(&headers, "session");
    assert!(!token.is_empty());

    let app = app_router(config);
    let authed = http::Request::builder()
        .uri("/probe")
        .header(http::header::COOKIE, format!("session={token}"))
        .body(Body::empty())
        .expect("request must build");
    let response = app
        .clone()
        .oneshot(authed)
        .await
        .expect("router must respond");
    assert_eq!(response.status(), StatusCode::OK);

    let guest = http::Request::builder()
        .uri("/probe")
        .body(Body::empty())
        .expect("request must build");
    let response = app.oneshot(guest).await.expect("router must respond");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
