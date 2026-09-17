use dioxus::prelude::*;

use crate::session::AuthStatus;

/// Handle to the reactive authentication state in the component tree.
///
/// Obtained via [`crate::dioxus::use_auth`] inside an
/// [`crate::dioxus::AuthProvider`] tree. Cheap to copy; every consumer reads
/// the same underlying signal, so `logout()` re-renders all of them.
pub struct Auth<User: 'static> {
    status: Signal<AuthStatus<User>>,
}

impl<User: 'static> Clone for Auth<User> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<User: 'static> Copy for Auth<User> {}

impl<User: 'static> PartialEq for Auth<User> {
    fn eq(&self, other: &Self) -> bool {
        self.status == other.status
    }
}

impl<User: Clone + 'static> Auth<User> {
    /// Wrap a reactive status signal into an [`Auth`] handle.
    pub fn new(status: Signal<AuthStatus<User>>) -> Self {
        Self { status }
    }

    /// Current [`AuthStatus`].
    pub fn status(&self) -> AuthStatus<User> {
        (self.status)()
    }

    /// Whether authentication is resolving.
    pub fn is_loading(&self) -> bool {
        self.status().is_loading()
    }

    /// Whether the user is authenticated.
    pub fn is_authenticated(&self) -> bool {
        self.status().is_authenticated()
    }

    /// Whether the user is unauthenticated.
    pub fn is_unauthenticated(&self) -> bool {
        self.status().is_unauthenticated()
    }

    /// Authenticated user, if signed in.
    pub fn user(&self) -> Option<User> {
        self.status().into_user()
    }

    /// Set the authentication status directly.
    pub fn set_status(&mut self, status: AuthStatus<User>) {
        self.status.set(status);
    }

    /// Set the authenticated user.
    pub fn set_user(&mut self, user: User) {
        self.status.set(AuthStatus::Authenticated(user));
    }

    /// Reset to unauthenticated.
    pub fn logout(&mut self) {
        self.status.set(AuthStatus::Unauthenticated);
    }

    /// Underlying `Signal<AuthStatus<User>>`.
    pub fn signal(&self) -> Signal<AuthStatus<User>> {
        self.status
    }
}
