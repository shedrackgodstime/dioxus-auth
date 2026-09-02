use dioxus::prelude::*;

use crate::session::AuthStatus;

/// Handle to the reactive authentication state in the Dioxus component tree.
#[derive(Clone, Copy, PartialEq)]
pub struct Auth<User: 'static> {
    status: Signal<AuthStatus<User>>,
}

impl<User: Clone + 'static> Auth<User> {
    /// Wrap a reactive status signal into an [`Auth`] handle.
    pub fn new(status: Signal<AuthStatus<User>>) -> Self {
        Self { status }
    }

    /// Read the current [`AuthStatus`].
    pub fn status(&self) -> AuthStatus<User> {
        (self.status)()
    }

    /// Returns `true` if authentication is currently resolving (e.g. restoring session).
    pub fn is_loading(&self) -> bool {
        self.status().is_loading()
    }

    /// Returns `true` if there is an active authenticated user.
    pub fn is_authenticated(&self) -> bool {
        self.status().is_authenticated()
    }

    /// Returns `true` if the user is explicitly unauthenticated / signed out.
    pub fn is_unauthenticated(&self) -> bool {
        self.status().is_unauthenticated()
    }

    /// Return a clone of the current authenticated user if signed in.
    pub fn user(&self) -> Option<User> {
        self.status().into_user()
    }

    /// Set the authentication status directly.
    pub fn set_status(&mut self, status: AuthStatus<User>) {
        self.status.set(status);
    }

    /// Mark the state as authenticated with the given user.
    pub fn set_user(&mut self, user: User) {
        self.status.set(AuthStatus::Authenticated(user));
    }

    /// Reset authentication state to unauthenticated.
    pub fn logout(&mut self) {
        self.status.set(AuthStatus::Unauthenticated);
    }

    /// Access the underlying `Signal<AuthStatus<User>>`.
    pub fn signal(&self) -> Signal<AuthStatus<User>> {
        self.status
    }
}

/// Hook to consume the current [`Auth`] context from any Dioxus component.
///
/// # Panics
/// Panics if called outside an [`crate::dioxus::AuthProvider`] tree for type `User`.
pub fn use_auth<User: Clone + 'static>() -> Auth<User> {
    use_context::<Auth<User>>()
}
