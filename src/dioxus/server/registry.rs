//! Application-level server helpers: initialization and one-step guards.
//!
//! This module owns the process-wide configuration registry (the `GLOBAL`
//! typemap behind [`server_init`]) alongside the thin helpers built on it, so
//! registry state and registry API cannot drift across files.

use std::any::{Any, TypeId};
use std::sync::{Arc, OnceLock};

use dioxus_fullstack::FullstackContext;
use parking_lot::Mutex;
use rustc_hash::FxHashMap;

use crate::dioxus::server::error::ServerError;
use crate::dioxus::server::server_fn::{ServerAuthConfig, ServerAuthContext};
use crate::user::AuthUser;

type BoxedConfig = Arc<dyn Any + Send + Sync>;
static GLOBAL: OnceLock<Mutex<FxHashMap<TypeId, BoxedConfig>>> = OnceLock::new();

fn global_registry() -> &'static Mutex<FxHashMap<TypeId, BoxedConfig>> {
    return GLOBAL.get_or_init(|| return Mutex::new(FxHashMap::default()));
}

/// Locates the engine configuration for this request or process.
pub(super) fn current_config<U: AuthUser>() -> Result<ServerAuthConfig<U>, ServerError> {
    if let Some(ctx) = FullstackContext::current() {
        if let Some(config) = ctx.extension::<Arc<ServerAuthConfig<U>>>() {
            return Ok((*config).clone());
        }
    }

    let lock = global_registry().lock();
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
/// Storage primitive behind [`server_init`]; not re-exported through the
/// prelude, so application code has exactly one registration path.
fn register_global<U: AuthUser>(config: ServerAuthConfig<U>) -> Result<(), ServerError> {
    let mut lock = global_registry().lock();
    let key = TypeId::of::<ServerAuthConfig<U>>();
    if lock.contains_key(&key) {
        return Err(ServerError::AlreadyInitialized);
    }
    lock.insert(key, Arc::new(config));
    drop(lock);
    return Ok(());
}

/// Registers the process-wide server auth configuration.
///
/// This is the single canonical registration path: the only registration
/// function re-exported through the crate prelude. It applies when no
/// per-request middleware is present (background tasks, tests,
/// or routers that do not attach [`AuthLayer`](super::axum::AuthLayer)).
///
/// # Errors
/// Returns `ServerError::AlreadyInitialized` if a configuration for this user
/// type was already registered.
#[must_use = "initialization errors must be handled"]
pub fn server_init<U: AuthUser>(config: ServerAuthConfig<U>) -> Result<(), ServerError> {
    return register_global(config);
}

/// Resolves the current request's user, or `None` for a guest request.
///
/// Mirrors [`ServerAuthContext::from_request`] with a convenient return type.
/// The engine's validation runs off the async worker via the blocking
/// boundary; see the `blocking` module.
///
/// # Errors
/// Returns `ServerError::MissingContext` when no engine is configured for the
/// request, or the engine's validation error verbatim.
#[must_use = "the session user must be used"]
pub async fn current_user<U: AuthUser + Clone>() -> Result<Option<U>, ServerError> {
    let context = match ServerAuthContext::<U>::from_request().await {
        Ok(context) => context,
        Err(error) => return Err(error),
    };
    return Ok(context.user().cloned());
}

/// Requires an authenticated session, rejecting guests.
///
/// The one-step guard for server functions: validates the session cookie and
/// returns the authenticated user, or `ServerError::MissingSession`. The
/// engine's validation runs off the async worker via the blocking boundary;
/// see the `blocking` module.
///
/// # Errors
/// Returns `ServerError::MissingSession` for a guest request, or
/// `ServerError::MissingContext` when no engine is configured.
#[must_use = "the required user must be used"]
pub async fn require_user<U: AuthUser + Clone>() -> Result<U, ServerError> {
    let context = match ServerAuthContext::<U>::from_request().await {
        Ok(context) => context,
        Err(error) => return Err(error),
    };
    return context.user().map_or_else(
        || return Err(ServerError::MissingSession),
        |user| return Ok(user.clone()),
    );
}
