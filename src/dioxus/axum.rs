//! Axum/Tower integration for [`dioxus-auth`].
//!
//! Provides middleware that validates sessions and inserts the authenticated user
//! into request extensions.
//!
//! Requires the `axum` feature:
//!
//! ```toml
//! dioxus-auth = { version = "0.1", features = ["dioxus", "axum"] }
//! ```

use std::sync::Arc;

use crate::dioxus::ServerAuthContext;
use crate::engine::AuthEngine;
use crate::error::AuthError;
use crate::security::CookieConfig;
use crate::storage::{PasswordUserStore, SessionStore, UserStore};
use crate::user::AuthUser;

use axum::{
    Extension,
    body::Body,
    http::{self, Request, StatusCode},
    middleware::Next,
    response::Response,
};

/// Request extension key for the authenticated user.
///
/// Inserted by [`auth_middleware`] as `Option<User>`.
#[derive(Clone)]
pub struct AuthenticatedUser<User>(pub Option<User>);

/// Axum middleware that validates the incoming session and inserts the
/// authenticated user into request extensions.
///
/// # How it works
///
/// 1. Extracts `Cookie` and `Authorization` headers from the request.
/// 2. Validates the session via [`ServerAuthContext`].
/// 3. Inserts `AuthenticatedUser(user)` into request extensions.
/// 4. Calls the next middleware/handler.
///
/// # Requirements
///
/// - The `axum` feature must be enabled.
/// - `User` must implement [`crate::user::AuthUser`] and be `Clone + Send + Sync + 'static`.
/// - The `AuthEngine` and `CookieConfig` must be provided as Axum `Extension`s.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use dioxus_auth::{axum::auth_middleware, AuthEngine, CookieConfig, MemoryStore};
///
/// let engine = Arc::new(AuthEngine::builder(store.clone(), store.clone()).build());
/// let cookie_config = CookieConfig::default();
///
/// let app = Router::new()
///     .route("/protected", get(handler))
///     .layer(Extension(engine))
///     .layer(Extension(cookie_config))
///     .layer(middleware::from_fn(auth_middleware::<AppUser, MemoryStore<AppUser>>));
/// ```
pub async fn auth_middleware<U, S>(
    Extension(engine): Extension<Arc<AuthEngine<U, S>>>,
    Extension(cookie_config): Extension<CookieConfig>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode>
where
    U: UserStore + PasswordUserStore + 'static,
    U::User: AuthUser + Clone + Send + Sync + 'static,
    S: SessionStore<<U::User as AuthUser>::Id> + 'static,
{
    let cookie_header = req
        .headers()
        .get(http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let origin_header = req
        .headers()
        .get(http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let authorization_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let ctx = ServerAuthContext::new(&engine, &cookie_config);
    let user = ctx
        .current_user(
            cookie_header.as_deref(),
            origin_header.as_deref(),
            authorization_header.as_deref(),
        )
        .await
        .ok()
        .flatten();

    req.extensions_mut().insert(AuthenticatedUser(user));

    Ok(next.run(req).await)
}

/// Request extension key for a guaranteed authenticated user.
///
/// Inserted by [`require_auth_middleware`] and [`permission_middleware`].
#[derive(Clone)]
pub struct RequireAuthUser<User>(pub User);

/// Axum middleware that requires authentication and returns 401 if not authenticated.
///
/// Unlike [`auth_middleware`], this middleware returns `StatusCode::UNAUTHORIZED`
/// instead of inserting `None` when no valid session is found.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use dioxus_auth::{axum::require_auth_middleware, AuthEngine, CookieConfig, MemoryStore};
///
/// let app = Router::new()
///     .route("/api/me", get(handler))
///     .layer(Extension(engine))
///     .layer(Extension(cookie_config))
///     .layer(middleware::from_fn(require_auth_middleware::<AppUser, MemoryStore<AppUser>>));
/// ```
pub async fn require_auth_middleware<U, S>(
    Extension(engine): Extension<Arc<AuthEngine<U, S>>>,
    Extension(cookie_config): Extension<CookieConfig>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode>
where
    U: UserStore + PasswordUserStore + 'static,
    U::User: AuthUser + Clone + Send + Sync + 'static,
    S: SessionStore<<U::User as AuthUser>::Id> + 'static,
{
    let cookie_header = req
        .headers()
        .get(http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let origin_header = req
        .headers()
        .get(http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let authorization_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let ctx = ServerAuthContext::new(&engine, &cookie_config);
    let user = match ctx
        .current_user(
            cookie_header.as_deref(),
            origin_header.as_deref(),
            authorization_header.as_deref(),
        )
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return Err(StatusCode::UNAUTHORIZED),
        Err(AuthError::Csrf) => return Err(StatusCode::FORBIDDEN),
        Err(_) => return Err(StatusCode::UNAUTHORIZED),
    };

    let mut req = Request::new(Body::empty());
    *req.headers_mut() = req.headers().clone();
    req.extensions_mut().insert(RequireAuthUser(user.clone()));
    req.extensions_mut().insert(AuthenticatedUser(Some(user)));

    Ok(next.run(req).await)
}

/// Axum middleware that requires a permission check and returns 403 if the check fails.
///
/// This middleware first requires authentication (returns 401 if not authenticated),
/// then runs the provided permission check. Returns `StatusCode::FORBIDDEN` if the
/// permission check fails.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use dioxus_auth::{axum::permission_middleware, AuthEngine, CookieConfig, MemoryStore};
///
/// let app = Router::new()
///     .route("/admin", get(admin_handler))
///     .layer(Extension(engine))
///     .layer(Extension(cookie_config))
///     .layer(middleware::from_fn(permission_middleware::<AppUser, MemoryStore<AppUser>, _>(|user| user.is_admin)));
/// ```
pub async fn permission_middleware<U, S, F>(
    Extension(engine): Extension<Arc<AuthEngine<U, S>>>,
    Extension(cookie_config): Extension<CookieConfig>,
    req: Request<Body>,
    next: Next,
    check: F,
) -> Result<Response, StatusCode>
where
    U: UserStore + PasswordUserStore + 'static,
    U::User: AuthUser + Clone + Send + Sync + 'static,
    S: SessionStore<<U::User as AuthUser>::Id> + 'static,
    F: Fn(&U::User) -> bool + Send + Sync + 'static,
{
    let cookie_header = req
        .headers()
        .get(http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let origin_header = req
        .headers()
        .get(http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let authorization_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let ctx = ServerAuthContext::new(&engine, &cookie_config);
    let user = match ctx
        .current_user(
            cookie_header.as_deref(),
            origin_header.as_deref(),
            authorization_header.as_deref(),
        )
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return Err(StatusCode::UNAUTHORIZED),
        Err(AuthError::Csrf) => return Err(StatusCode::FORBIDDEN),
        Err(_) => return Err(StatusCode::UNAUTHORIZED),
    };

    if !check(&user) {
        return Err(StatusCode::FORBIDDEN);
    }

    let mut req = Request::new(Body::empty());
    *req.headers_mut() = req.headers().clone();
    req.extensions_mut().insert(RequireAuthUser(user.clone()));
    req.extensions_mut().insert(AuthenticatedUser(Some(user)));

    Ok(next.run(req).await)
}
