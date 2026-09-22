//! Typed client-side session read state.
//!
//! The reactive read is an exhaustive enum, not a struct of option fields:
//! invalid combinations (a user and an error at the same time, or a guest
//! that is also pending) are unrepresentable. This is the AM3 result-shape
//! contract in type form; wire responses keep the `{ data, error }` field
//! set and map into these variants at the client boundary.

use crate::error::ErrorCode;
use crate::status::AuthStatus;
use crate::user::AuthUser;

/// The settled-or-in-flight session state a component renders from.
///
/// Branch exhaustively: [`SessionState::SignedIn`] renders the identity,
/// [`SessionState::Guest`] renders signed-out UI, [`SessionState::Pending`]
/// means the restore question is still open (initial mount, or an async
/// client engine in flight), and [`SessionState::Unavailable`] means the
/// question could not be asked (rate limit, transport failure) — retryable,
/// and it never demotes a live session to guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState<T: AuthUser> {
    /// An authenticated identity is present.
    SignedIn(T),
    /// No session: the restore question was answered with a definitive no.
    Guest,
    /// The restore question is still open; nothing has answered yet.
    Pending,
    /// The restore question could not be asked — retryable, never a sign-out.
    Unavailable(ErrorCode),
}

impl<T: AuthUser + Clone> SessionState<T> {
    /// Maps the reactive status plus the last unknown-class restore failure
    /// into the read state.
    ///
    /// A `Loading` status with no recorded failure is [`SessionState::Pending`];
    /// with one, it is [`SessionState::Unavailable`]. Only the loading state
    /// consults the failure — settled statuses already carry their answer.
    pub(crate) fn from_parts(status: &AuthStatus<T>, unavailable: Option<ErrorCode>) -> Self {
        return match status {
            AuthStatus::Authenticated(user) => Self::SignedIn(user.clone()),
            AuthStatus::Guest => Self::Guest,
            AuthStatus::Loading => unavailable.map_or_else(
                || return Self::Pending,
                |code| return Self::Unavailable(code),
            ),
        };
    }
}
