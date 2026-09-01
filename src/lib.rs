#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

//! Initial core types for `dioxus-auth`.

mod error;
mod session;
mod status;
mod user;

pub use error::{AuthError, AuthResult};
pub use session::{Session, SessionId};
pub use status::AuthStatus;
pub use user::AuthUser;

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TestUser {
        id: u64,
    }

    impl AuthUser for TestUser {
        type Id = u64;

        fn id(&self) -> Self::Id {
            self.id
        }
    }

    #[test]
    fn authenticated_status_exposes_user() {
        let user = TestUser { id: 7 };
        let status = AuthStatus::Authenticated(user.clone());

        assert!(status.is_authenticated());
        assert_eq!(status.user(), Some(&user));
    }

    #[test]
    fn session_expiration_is_explicit() {
        let session = Session::new(SessionId::new("session-1"), 7, 100, 200);

        assert!(!session.is_expired_at(199));
        assert!(session.is_expired_at(200));
    }
}
