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
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::Route;
use tower::Layer;
use tower::Service;

use crate::dioxus::server::ServerAuthConfig;
use crate::dioxus::server::blocking::run_blocking;
use crate::dioxus::server::server_fn::authenticate_headers;
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
            // Validation (store lookups under locks) runs on the blocking
            // pool so the worker executing this request stays responsive.
            let headers = request.headers().clone();
            let validation = run_blocking({
                let config = Arc::clone(&config);
                move || return authenticate_headers(&config, &headers)
            })
            .await;
            let authenticated = match validation {
                Ok((_, user)) => user.is_some(),
                Err(_) => false,
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
