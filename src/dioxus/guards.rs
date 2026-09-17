//! Pure routing-guard logic: outcome evaluation and declarative guard rules.
//! The rendering component lives in [`crate::dioxus::components::RouteGate`].

use crate::session::AuthStatus;

/// The outcome of evaluating route access permissions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardOutcome<R> {
    /// Access granted; render the child route.
    Allow,
    /// Authentication state is still loading (e.g. session restore in progress).
    /// Renders the fallback view without triggering a premature redirect.
    Pending,
    /// Access denied; redirect the user to the target route.
    Redirect(R),
}

impl<R> GuardOutcome<R> {
    /// Returns `true` when access is granted and the child route should render.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns `true` while authentication state is still loading.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Returns `true` when access is denied and a redirect was produced.
    #[must_use]
    pub fn is_redirect(&self) -> bool {
        matches!(self, Self::Redirect(_))
    }
}

/// Evaluates whether the current user is authenticated, otherwise redirects.
///
/// `AuthStatus::Loading` maps to [`GuardOutcome::Pending`] so guards never
/// redirect during session restore (no login flash, no false bounce).
#[must_use]
pub fn require_auth<R: Clone, User>(status: &AuthStatus<User>, redirect_to: R) -> GuardOutcome<R> {
    match status {
        AuthStatus::Loading => GuardOutcome::Pending,
        AuthStatus::Authenticated(_) => GuardOutcome::Allow,
        AuthStatus::Unauthenticated => GuardOutcome::Redirect(redirect_to),
    }
}

/// Evaluates whether the user is already authenticated (e.g. on `/login` or `/register`),
/// redirecting them to a dashboard if signed in.
#[must_use]
pub fn redirect_if_authed<R: Clone, User>(
    status: &AuthStatus<User>,
    redirect_to: R,
) -> GuardOutcome<R> {
    match status {
        AuthStatus::Loading => GuardOutcome::Pending,
        AuthStatus::Authenticated(_) => GuardOutcome::Redirect(redirect_to),
        AuthStatus::Unauthenticated => GuardOutcome::Allow,
    }
}

/// Trait for custom declarative route protection rules.
///
/// Implement this to encode domain authorization (roles, subscriptions) on top
/// of the built-in [`RequireAuth`] / [`RedirectIfAuthed`] guards.
pub trait RouteGuard<R, User>: Send + Sync + 'static {
    /// Evaluate the current auth status into a routing outcome.
    fn evaluate(&self, status: &AuthStatus<User>) -> GuardOutcome<R>;
}

/// Declarative route guard requiring an active authenticated session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequireAuth<R>(pub R);

impl<R: Clone + Send + Sync + 'static, User: 'static> RouteGuard<R, User> for RequireAuth<R> {
    fn evaluate(&self, status: &AuthStatus<User>) -> GuardOutcome<R> {
        require_auth(status, self.0.clone())
    }
}

/// Declarative route guard redirecting authenticated users away from guest pages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectIfAuthed<R>(pub R);

impl<R: Clone + Send + Sync + 'static, User: 'static> RouteGuard<R, User> for RedirectIfAuthed<R> {
    fn evaluate(&self, status: &AuthStatus<User>) -> GuardOutcome<R> {
        redirect_if_authed(status, self.0.clone())
    }
}
