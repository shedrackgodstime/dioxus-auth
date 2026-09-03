use dioxus::prelude::*;

use crate::session::AuthStatus;

/// Handle to the reactive authentication state in the Dioxus component tree.
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

/// Drive the reactive auth status from a restore result.
///
/// Intended to be paired with `use_resource` or `use_server_future` inside a child
/// component of [`AuthProvider`]. The hook only mutates auth state while it is still
/// `Loading`, so a manual login/logout elsewhere is never overwritten by a late or
/// failed restore.
///
/// # Arguments
/// * `restored` - The current value of the restore resource:
///   - `None` → still resolving, do nothing.
///   - `Some(Ok(Some(user)))` → transition to `Authenticated`.
///   - `Some(Ok(None))` or `Some(Err(_))` → transition to `Unauthenticated`.
pub fn use_auth_restore<User, E>(restored: Option<Result<Option<User>, E>>)
where
    User: Clone + 'static,
{
    let mut auth = use_auth::<User>();
    if !auth.is_loading() {
        return;
    }

    match restored {
        None => {}
        Some(Ok(Some(user))) => auth.set_user(user),
        Some(Ok(None)) | Some(Err(_)) => auth.set_status(AuthStatus::Unauthenticated),
    }
}
