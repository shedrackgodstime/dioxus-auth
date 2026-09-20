//! Request-scoped server authentication context.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use dioxus_fullstack::FullstackContext;
use parking_lot::Mutex;

use crate::dioxus::operations::AuthEngineHandle;
use crate::dioxus::server::cookies::request_cookie_token;
use crate::error::AuthError;
use crate::security::CookieConfig;
use crate::status::SessionId;
use crate::user::AuthUser;

/// Errors produced by the server authentication context.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServerError {
    /// No engine is configured for the current request or process.
    #[error("no server auth configuration available for this request")]
    MissingContext,
    /// [`server_init`](super::registry::server_init) was called twice.
    #[error("server auth configuration already initialized")]
    AlreadyInitialized,
    /// The request did not resolve to an authenticated session.
    #[error("the request did not carry an authenticated session")]
    MissingSession,
    /// The session cookie value is not a valid header value.
    #[error("invalid session cookie header value")]
    InvalidCookieValue,
    /// The underlying auth engine failed.
    #[error("auth engine error: {0}")]
    Engine(#[from] AuthError),
}

impl ServerError {
    /// The HTTP status code the error should be served with.
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        return match self {
            Self::MissingSession
            | Self::Engine(AuthError::InvalidCredentials | AuthError::PasswordHashError) => 401,
            Self::Engine(AuthError::RateLimited) => 429,
            Self::Engine(AuthError::Internal(_))
            | Self::MissingContext
            | Self::AlreadyInitialized
            | Self::InvalidCookieValue => 500,
        };
    }
}

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
    /// # Errors
    /// Returns `ServerError::MissingContext` when no engine is configured for
    /// this request, or the engine's validation error verbatim.
    #[must_use = "the resolved context must be used"]
    pub fn from_request() -> Result<Self, ServerError> {
        let config = match current_config::<U>() {
            Ok(config) => config,
            Err(error) => return Err(error),
        };
        let token = cookie_token(&config);
        let user = match token {
            Some(ref token) => {
                let engine = config.engine.engine();
                match engine.validate(token) {
                    Ok(user) => user,
                    Err(error) => return Err(ServerError::Engine(error)),
                }
            }
            None => None,
        };
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
}

/// Reads the session cookie token (if any) from the current request.
fn cookie_token<U: AuthUser>(config: &ServerAuthConfig<U>) -> Option<SessionId> {
    let Some(ctx) = FullstackContext::current() else {
        return None;
    };
    let parts = ctx.parts_mut();
    let token = request_cookie_token(&parts.headers, config.cookie().name());
    drop(parts);
    return token.and_then(|token| {
        if SessionId::is_valid_wire_format(&token) {
            return Some(SessionId::new(token));
        }
        return None;
    });
}

type BoxedConfig = Arc<dyn Any + Send + Sync>;
static GLOBAL: OnceLock<Mutex<HashMap<TypeId, BoxedConfig>>> = OnceLock::new();

/// Locates the engine configuration for this request or process.
fn current_config<U: AuthUser>() -> Result<ServerAuthConfig<U>, ServerError> {
    if let Some(ctx) = FullstackContext::current() {
        if let Some(config) = ctx.extension::<Arc<ServerAuthConfig<U>>>() {
            let config = Arc::clone(&config).as_ref().clone();
            return Ok(config);
        }
    }

    let lock = GLOBAL
        .get_or_init(|| return Mutex::new(HashMap::new()))
        .lock();
    return lock.get(&TypeId::of::<ServerAuthConfig<U>>()).map_or_else(
        || return Err(ServerError::MissingContext),
        |config| {
            let config = Arc::clone(config);
            let config = match config.downcast::<ServerAuthConfig<U>>() {
                Ok(config) => config,
                Err(_) => return Err(ServerError::MissingContext),
            };
            return Ok(Arc::unwrap_or_clone(config));
        },
    );
}

/// Registers the process-wide server auth configuration.
///
/// # Errors
/// Returns `ServerError::AlreadyInitialized` if a configuration for this user
/// type is already registered.
pub fn register_global<U: AuthUser>(config: ServerAuthConfig<U>) -> Result<(), ServerError> {
    let mut lock = GLOBAL
        .get_or_init(|| return Mutex::new(HashMap::new()))
        .lock();
    let key = TypeId::of::<ServerAuthConfig<U>>();
    if lock.contains_key(&key) {
        return Err(ServerError::AlreadyInitialized);
    }
    lock.insert(key, Arc::new(config));
    drop(lock);
    return Ok(());
}
