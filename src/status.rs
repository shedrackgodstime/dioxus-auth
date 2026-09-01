#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum AuthStatus<User> {
    #[default]
    Loading,
    Authenticated(User),
    Unauthenticated,
}

impl<User> AuthStatus<User> {
    pub fn is_loading(&self) -> bool {
        matches!(self, Self::Loading)
    }

    pub fn is_authenticated(&self) -> bool {
        matches!(self, Self::Authenticated(_))
    }

    pub fn is_unauthenticated(&self) -> bool {
        matches!(self, Self::Unauthenticated)
    }

    pub fn user(&self) -> Option<&User> {
        match self {
            Self::Authenticated(user) => Some(user),
            Self::Loading | Self::Unauthenticated => None,
        }
    }

    pub fn into_user(self) -> Option<User> {
        match self {
            Self::Authenticated(user) => Some(user),
            Self::Loading | Self::Unauthenticated => None,
        }
    }
}
