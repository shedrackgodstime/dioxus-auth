//! Request-scoped server authentication context.

use std::sync::Arc;

use dioxus_fullstack::{FullstackContext, http};

use crate::dioxus::operations::AuthEngineHandle;
use crate::dioxus::server::blocking::run_blocking;
use crate::dioxus::server::cookies::{request_cookie_token, request_origin_header};
use crate::dioxus::server::error::ServerError;
use crate::dioxus::server::registry::current_config;
use crate::error::AuthError;
use crate::security::CookieConfig;
use crate::status::SessionId;
use crate::user::AuthUser;

/// Engine + cookie configuration for the server slice.
///
/// Placed into axum request extensions by
/// [`AuthLayer`](super::axum::AuthLayer) (or registered
/// process-wide with [`server_init`](super::registry::server_init)) so that
/// every server function and SSR render can resolve the current session.
#[derive(Debug)]
pub struct ServerAuthConfig<U: AuthUser> {
    engine: AuthEngineHandle<U>,
    cookie: CookieConfig,
}

impl<U: AuthUser> Clone for ServerAuthConfig<U> {
    fn clone(&self) -> Self {
        return Self {
            engine: self.engine.clone(),
            cookie: self.cookie.clone(),
        };
    }
}

impl<U: AuthUser> ServerAuthConfig<U> {
    /// Creates a server auth configuration.
    #[must_use]
    pub const fn new(engine: AuthEngineHandle<U>, cookie: CookieConfig) -> Self {
        return Self { engine, cookie };
    }

    /// The engine used to login, logout, and validate sessions.
    #[must_use]
    pub const fn engine(&self) -> &AuthEngineHandle<U> {
        return &self.engine;
    }

    /// The cookie the session token travels in.
    #[must_use]
    pub const fn cookie(&self) -> &CookieConfig {
        return &self.cookie;
    }
}

/// The resolved authentication state of the current request.
///
/// Guests resolve normally too: a missing or stale token simply yields
/// [`user`](Self::user) = `None`. Only a missing engine configuration is an
/// error.
#[derive(Debug, Clone)]
pub struct ServerAuthContext<U: AuthUser> {
    config: ServerAuthConfig<U>,
    token: Option<SessionId>,
    user: Option<U>,
}

impl<U: AuthUser + Clone> ServerAuthContext<U> {
    /// Resolves the request's session: cookie token, then engine validation.
    ///
    /// The engine's validation (store lookups, and user hydration through
    /// app-supplied stores) runs off the async worker via the blocking
    /// boundary; see the `blocking` module.
    ///
    /// # Errors
    /// Returns `ServerError::MissingContext` when no engine is configured for
    /// this request, or the engine's validation error verbatim.
    #[must_use = "the resolved context must be used"]
    pub async fn from_request() -> Result<Self, ServerError> {
        let config = match current_config::<U>() {
            Ok(config) => config,
            Err(error) => return Err(error),
        };
        let session = match FullstackContext::current() {
            Some(ctx) => {
                // reason: the parts guard borrows request state that must be
                // released before the await below; holding it across the
                // blocking dispatch would needlessly extend the borrow.
                let headers = {
                    let parts = ctx.parts_mut();
                    parts.headers.clone()
                };
                match run_blocking({
                    let config = config.clone();
                    move || return authenticate_headers(&config, &headers)
                })
                .await
                {
                    Ok(Ok(session)) => session,
                    Ok(Err(error)) => return Err(error),
                    Err(_) => return Err(blocking_cancelled()),
                }
            }
            None => (None, None),
        };
        let (token, user) = session;
        return Ok(Self {
            config,
            token,
            user,
        });
    }

    /// The configuration the context was resolved against.
    #[must_use]
    pub const fn config(&self) -> &ServerAuthConfig<U> {
        return &self.config;
    }

    /// The engine the context is bound to.
    #[must_use]
    pub const fn engine(&self) -> &AuthEngineHandle<U> {
        return &self.config.engine;
    }

    /// The raw wire session token carried by the cookie, if one was present
    /// and well-formed.
    #[must_use]
    pub const fn token(&self) -> Option<&SessionId> {
        return self.token.as_ref();
    }

    /// The validated user, or `None` for a guest request.
    #[must_use]
    pub const fn user(&self) -> Option<&U> {
        return self.user.as_ref();
    }

    /// Whether the request resolved to an authenticated user.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        return self.user.is_some() && self.token.is_some();
    }

    /// Authenticates the credentials and returns the user with the fresh wire
    /// session token.
    ///
    /// The engine call (Argon2 verification, credential lookups) runs off the
    /// async worker via the blocking boundary; see
    /// the `blocking` module.
    ///
    /// When the configuration sets expected origins, the request must carry
    /// a present, matching `Origin` header: login is state-changing.
    ///
    /// # Errors
    /// Returns the engine's login error verbatim, or `ServerError::Engine`
    /// wrapping `AuthError::Csrf` for a missing or mismatched origin.
    #[must_use = "the authenticated user and session must be used"]
    pub async fn login(
        &self,
        identifier: &str,
        password: &str,
    ) -> Result<(U, SessionId), ServerError> {
        match check_state_changing_origin(self.config.cookie()) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        let engine = Arc::clone(self.engine().engine());
        let identifier = String::from(identifier);
        let password = String::from(password);
        let outcome = run_blocking(move || {
            return engine.login(&identifier, &password);
        })
        .await;
        let (user, token) = match outcome {
            Ok(Ok(pair)) => pair,
            Ok(Err(error)) => return Err(ServerError::from(error)),
            Err(_) => return Err(blocking_cancelled()),
        };
        return Ok((user, token));
    }

    /// Revokes the given session on the engine.
    ///
    /// The engine call (a store scan under the session lock) runs off the
    /// async worker via the blocking boundary; see
    /// the `blocking` module.
    ///
    /// When the configuration sets expected origins, the request must carry
    /// a present, matching `Origin` header: logout is state-changing.
    ///
    /// # Errors
    /// Returns the engine's logout error verbatim, or `ServerError::Engine`
    /// wrapping `AuthError::Csrf` for a missing or mismatched origin.
    #[must_use = "session revocation errors must be handled"]
    pub async fn logout(&self, token: &SessionId) -> Result<(), ServerError> {
        match check_state_changing_origin(self.config.cookie()) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        let engine = Arc::clone(self.engine().engine());
        let token = token.clone();
        let outcome = run_blocking(move || return engine.logout(&token)).await;
        match outcome {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => return Err(ServerError::from(error)),
            Err(_) => return Err(blocking_cancelled()),
        }
    }
}

/// Maps a blocking task lost to runtime shutdown to an internal error.
fn blocking_cancelled() -> ServerError {
    return ServerError::Engine(AuthError::Internal(String::from(
        "the blocking task was cancelled",
    )));
}

/// Enforces the origin gate for a state-changing cookie operation.
///
/// Login and logout share this one spelling so the two verbs cannot disagree
/// on what counts as a present, matching origin.
fn check_state_changing_origin(cookie: &CookieConfig) -> Result<(), ServerError> {
    return match cookie.check_origin(request_origin().as_deref()) {
        Ok(()) => Ok(()),
        Err(error) => Err(ServerError::Engine(error)),
    };
}

/// Reads the request's `Origin` header, if the current request carries one.
fn request_origin() -> Option<String> {
    let ctx = match FullstackContext::current() {
        Some(ctx) => ctx,
        None => return None,
    };
    let parts = ctx.parts_mut();
    let origin = request_origin_header(&parts.headers).map(String::from);
    drop(parts);
    return origin;
}

/// Validates the session cookie carried by request headers.
///
/// Returns the well-formed wire token and validated user. A missing or
/// malformed token yields `(None, None)`; engine failures are returned.
///
/// Blocking: runs the engine's validation synchronously. Async callers reach
/// it through [`ServerAuthContext::from_request`] or the axum layers, which
/// dispatch it via the blocking boundary.
#[must_use = "the validated session must be used"]
pub fn authenticate_headers<U: AuthUser>(
    config: &ServerAuthConfig<U>,
    headers: &http::HeaderMap,
) -> Result<(Option<SessionId>, Option<U>), ServerError> {
    let token = match request_cookie_token(headers, config.cookie()) {
        Some(token) => token,
        None => return Ok((None, None)),
    };
    if !SessionId::is_valid_wire_format(&token) {
        return Ok((None, None));
    }
    let token = SessionId::new(token);
    let engine = config.engine.engine();
    return match engine.validate(&token) {
        Ok(user) => Ok((Some(token), user)),
        Err(error) => Err(ServerError::Engine(error)),
    };
}
