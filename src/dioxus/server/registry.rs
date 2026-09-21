//! Application-level server helpers: initialization and one-step guards.

use crate::dioxus::server::server_fn::{ServerAuthConfig, ServerAuthContext, ServerError};
use crate::user::AuthUser;

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
pub fn server_init<U: AuthUser>(config: ServerAuthConfig<U>) -> Result<(), ServerError> {
    return super::server_fn::register_global(config);
}

/// Resolves the current request's user, or `None` for a guest request.
///
/// Mirrors [`ServerAuthContext::from_request`] with a convenient return type.
///
/// # Errors
/// Returns `ServerError::MissingContext` when no engine is configured for the
/// request, or the engine's validation error verbatim.
#[must_use = "the session user must be used"]
pub fn current_user<U: AuthUser + Clone>() -> Result<Option<U>, ServerError> {
    let context = match ServerAuthContext::<U>::from_request() {
        Ok(context) => context,
        Err(error) => return Err(error),
    };
    return Ok(context.user().cloned());
}

/// Requires an authenticated session, rejecting guests.
///
/// The one-step guard for server functions: validates the session cookie and
/// returns the authenticated user, or `ServerError::MissingSession`.
///
/// # Errors
/// Returns `ServerError::MissingSession` for a guest request, or
/// `ServerError::MissingContext` when no engine is configured.
#[must_use = "the required user must be used"]
pub fn require_user<U: AuthUser + Clone>() -> Result<U, ServerError> {
    let context = match ServerAuthContext::<U>::from_request() {
        Ok(context) => context,
        Err(error) => return Err(error),
    };
    return context.user().map_or_else(
        || return Err(ServerError::MissingSession),
        |user| return Ok(user.clone()),
    );
}
