//! Axum middleware that publishes the engine to fullstack requests.
//!
//! The middleware inserts the configuration into each request's extensions,
//! so it resolves in both SSR renders and server functions.

use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::extract::Request;
use axum::http::{self, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::Route;
use tower::Layer;
use tower::Service;

use crate::dioxus::server::ServerAuthConfig;
use crate::dioxus::server::blocking::run_blocking;
use crate::dioxus::server::server_fn::{ServerError, authenticate_headers};
use crate::error::AuthError;
use crate::user::AuthUser;

type BoxFuture = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send + 'static>>;

const fn service_ready() -> std::task::Poll<Result<(), Infallible>> {
    return std::task::Poll::Ready(Ok(()));
}

fn forward(mut inner: Route, request: Request) -> BoxFuture {
    return Box::pin(async move {
        return match inner.call(request).await {
            Ok(response) => Ok(response),
            Err(infallible) => match infallible {},
        };
    });
}

/// Server auth middleware that makes the engine available to every request.
///
/// [`ServerAuthConfig`] is inserted into the request extensions so that
/// [`ServerAuthContext::from_request`](super::server_fn::ServerAuthContext::from_request)
/// resolves everywhere — initial SSR renders and server functions alike.
///
/// Guests are served normally; combine with [`RequireAuthLayer`] to
/// reject them.
#[derive(Clone, Debug)]
pub struct AuthLayer<U: AuthUser> {
    config: Arc<ServerAuthConfig<U>>,
}

impl<U: AuthUser> AuthLayer<U> {
    /// Builds the middleware from a server auth configuration.
    #[must_use]
    pub fn new(config: ServerAuthConfig<U>) -> Self {
        return Self {
            config: Arc::new(config),
        };
    }
}

impl<U: AuthUser> Layer<Route> for AuthLayer<U> {
    type Service = AuthService<U>;

    fn layer(&self, inner: Route) -> Self::Service {
        return AuthService {
            config: Arc::clone(&self.config),
            inner,
        };
    }
}

/// The layered service produced by [`AuthLayer`].
#[derive(Clone)]
pub struct AuthService<U: AuthUser> {
    config: Arc<ServerAuthConfig<U>>,
    inner: Route,
}

impl<U: AuthUser> Service<Request> for AuthService<U> {
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        return service_ready();
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let config = Arc::clone(&self.config);
        let inner = self.inner.clone();
        let mut request = request;
        request.extensions_mut().insert(config);
        return forward(inner, request);
    }
}

/// Server auth middleware that resolves the session and rejects guests.
///
/// Validates the session cookie with the same helper as
/// [`ServerAuthContext::from_request`](super::server_fn::ServerAuthContext::from_request);
/// unauthenticated or invalid requests receive `401 Unauthorized` without
/// reaching the handler. Authenticated requests continue with the engine in
/// the request extensions.
#[derive(Clone, Debug)]
pub struct RequireAuthLayer<U: AuthUser> {
    config: Arc<ServerAuthConfig<U>>,
}

impl<U: AuthUser> RequireAuthLayer<U> {
    /// Builds the requiring middleware from a server auth configuration.
    #[must_use]
    pub fn new(config: ServerAuthConfig<U>) -> Self {
        return Self {
            config: Arc::new(config),
        };
    }
}

impl<U: AuthUser> Layer<Route> for RequireAuthLayer<U> {
    type Service = RequireAuthService<U>;

    fn layer(&self, inner: Route) -> Self::Service {
        return RequireAuthService {
            config: Arc::clone(&self.config),
            inner,
        };
    }
}

/// The layered service produced by [`RequireAuthLayer`].
#[derive(Clone)]
pub struct RequireAuthService<U: AuthUser> {
    config: Arc<ServerAuthConfig<U>>,
    inner: Route,
}

impl<U: AuthUser> Service<Request> for RequireAuthService<U> {
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        return service_ready();
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let config = Arc::clone(&self.config);
        let inner = self.inner.clone();
        return Box::pin(async move {
            let mut request = request;
            request.extensions_mut().insert(Arc::clone(&config));
            // reason: state-changing requests run the origin gate before any
            // session work, so a forged cross-site request fails closed even
            // when it carries no session; safe methods keep working without
            // an Origin, which browsers omit on same-origin navigations.
            if !is_safe_method(request.method()) {
                let origin = request
                    .headers()
                    .get(http::header::ORIGIN)
                    .and_then(|header| return header.to_str().ok());
                match config.cookie().check_origin(origin) {
                    Ok(()) => {}
                    Err(_) => return Ok(forbidden()),
                }
            }
            // reason: validation does store lookups under locks; running it
            // on the worker would stall the request loop, so the headers are
            // cloned once and the check goes to the blocking pool.
            let headers = request.headers().clone();
            let validation = run_blocking({
                let config = Arc::clone(&config);
                move || return authenticate_headers(&config, &headers)
            })
            .await;
            let outcome = match validation {
                Ok(outcome) => outcome,
                Err(_) => return Ok(server_error()),
            };
            let authenticated = match outcome {
                Ok((_, Some(_))) => true,
                Err(ServerError::Engine(AuthError::Internal(_))) => {
                    return Ok(server_error());
                }
                Ok((_, None)) | Err(_) => false,
            };
            if !authenticated {
                return Ok(unauthorized());
            }
            return forward(inner, request).await;
        });
    }
}

fn unauthorized() -> Response {
    return (StatusCode::UNAUTHORIZED, String::from("unauthorized")).into_response();
}

fn forbidden() -> Response {
    return (StatusCode::FORBIDDEN, String::from("forbidden")).into_response();
}

/// Whether the request method never changes state, so ambient credentials
/// need no origin backstop.
const fn is_safe_method(method: &Method) -> bool {
    return matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS);
}

fn server_error() -> Response {
    return (
        StatusCode::INTERNAL_SERVER_ERROR,
        String::from("internal server error"),
    )
        .into_response();
}

/// Redacted debug: the inner route carries handler state not worth rendering.
impl<U: AuthUser> fmt::Debug for AuthService<U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return f.write_str("AuthService(..)");
    }
}

/// Redacted debug: the inner route carries handler state not worth rendering.
impl<U: AuthUser> fmt::Debug for RequireAuthService<U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return f.write_str("RequireAuthService(..)");
    }
}
