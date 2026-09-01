use dioxus::prelude::*;

use crate::status::AuthStatus;

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
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    pub fn is_redirect(&self) -> bool {
        matches!(self, Self::Redirect(_))
    }
}

/// Evaluates whether the current user is authenticated, otherwise redirects.
pub fn require_auth<R: Clone, User>(status: &AuthStatus<User>, redirect_to: R) -> GuardOutcome<R> {
    match status {
        AuthStatus::Loading => GuardOutcome::Pending,
        AuthStatus::Authenticated(_) => GuardOutcome::Allow,
        AuthStatus::Unauthenticated => GuardOutcome::Redirect(redirect_to),
    }
}

/// Evaluates whether the user is already authenticated (e.g. on `/login` or `/register`),
/// redirecting them to a dashboard if signed in.
pub fn redirect_if_authed<R: Clone, User>(status: &AuthStatus<User>, redirect_to: R) -> GuardOutcome<R> {
    match status {
        AuthStatus::Loading => GuardOutcome::Pending,
        AuthStatus::Authenticated(_) => GuardOutcome::Redirect(redirect_to),
        AuthStatus::Unauthenticated => GuardOutcome::Allow,
    }
}

/// Trait for custom declarative route protection rules.
pub trait RouteGuard<R, User>: Send + Sync + 'static {
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

/// Component that gates access to child routes based on a [`GuardOutcome`].
///
/// If allowed, renders `Outlet::<R> {}`.
/// If pending, renders the optional `fallback` element (or a default loading indicator).
/// If redirect, navigates to the target route using [`use_navigator`].
#[component]
pub fn RouteGate<R: Routable + Clone + PartialEq + 'static>(
    outcome: GuardOutcome<R>,
    #[props(default)]
    fallback: Option<Element>,
) -> Element {
    let nav = use_navigator();

    match outcome {
        GuardOutcome::Allow => rsx! {
            Outlet::<R> {}
        },
        GuardOutcome::Pending => {
            if let Some(fb) = fallback {
                rsx! { {fb} }
            } else {
                rsx! {
                    div { class: "dioxus-auth-pending", "Loading session..." }
                }
            }
        }
        GuardOutcome::Redirect(target) => {
            use_effect(move || {
                nav.replace(target.clone());
            });
            rsx! {}
        }
    }
}
