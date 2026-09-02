/// Explicit 3-state authentication status for UI and hydration lifecycle.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum AuthStatus<User> {
    /// Authentication is still resolving (e.g. restoring session on client mount).
    /// Used by route guards and SSR to prevent premature redirect flashes.
    #[default]
    Loading,
    /// Active authenticated session holding the application's user model.
    Authenticated(User),
    /// Unauthenticated guest.
    Unauthenticated,
}

impl<User> AuthStatus<User> {
    /// Returns `true` if the status is [`AuthStatus::Loading`].
    pub fn is_loading(&self) -> bool {
        matches!(self, Self::Loading)
    }

    /// Returns `true` if the status is [`AuthStatus::Authenticated`].
    pub fn is_authenticated(&self) -> bool {
        matches!(self, Self::Authenticated(_))
    }

    /// Returns `true` if the status is [`AuthStatus::Unauthenticated`].
    pub fn is_unauthenticated(&self) -> bool {
        matches!(self, Self::Unauthenticated)
    }

    /// Borrow the authenticated user if present.
    pub fn user(&self) -> Option<&User> {
        match self {
            Self::Authenticated(user) => Some(user),
            Self::Loading | Self::Unauthenticated => None,
        }
    }

    /// Extract the authenticated user if present.
    pub fn into_user(self) -> Option<User> {
        match self {
            Self::Authenticated(user) => Some(user),
            Self::Loading | Self::Unauthenticated => None,
        }
    }
}
