use std::sync::Arc;

use dioxus::prelude::*;

use crate::session::AuthStatus;

use crate::transport::TokenStorage;

/// Handle to the reactive authentication state in the component tree.
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

/// Consume the current [`Auth`] context from any component.
///
/// # Panics
/// Panics if called outside an [`AuthProvider`] tree.
pub fn use_auth<User: Clone + 'static>() -> Auth<User> {
    use_context::<Auth<User>>()
}

/// Drive auth status from a restore result.
///
/// Only mutates while still `Loading`, so a manual login/logout is never
/// overwritten by a late or failed restore.
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

/// Access the optional [`TokenStorage`] provided by [`AuthProvider`].
///
/// Returns `None` if the app did not provide a storage backend.
pub fn use_token_storage() -> Option<Arc<dyn TokenStorage>> {
    use_context::<Option<Arc<dyn TokenStorage>>>()
}

/// Persist a raw session token to [`TokenStorage`], if available.
///
/// Silently ignores errors.
pub fn persist_token(raw_token: &str) {
    if let Some(storage) = use_token_storage() {
        let _ = storage.save(raw_token);
    }
}

/// Clear [`TokenStorage`], if available.
///
/// Silently ignores errors.
pub fn clear_persisted_token() {
    if let Some(storage) = use_token_storage() {
        storage.clear();
    }
}
