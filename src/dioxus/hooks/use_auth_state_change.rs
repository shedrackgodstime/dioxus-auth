//! Hook for observing auth state transitions.

use std::cell::RefCell;
use std::rc::Rc;

use ::dioxus::prelude::{use_context, use_effect, use_hook};

use crate::dioxus::context::AuthContext;
use crate::dioxus::state::SessionState;
use crate::user::AuthUser;

/// An authentication state transition: the session state before and after a
/// change.
///
/// The previous state is the last state observed by this subscription, and
/// the current state the one it just changed into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthStateEvent<T: AuthUser> {
    /// The session state observed immediately before the change.
    pub previous: SessionState<T>,
    /// The session state observed immediately after the change.
    pub current: SessionState<T>,
}

/// Runs `handler` whenever the session state changes.
///
/// The read half of the runtime is reactive; this hook is the observe half —
/// analytics, logging, cross-tab sync through an application-owned channel.
/// The first settled state is recorded without firing, so a handler sees
/// changes between two observed states only (login, logout, refresh); read
/// the initial state with [`use_session`](crate::prelude::use_session).
/// The subscription lives as long as the calling component stays mounted.
///
/// # Examples
///
/// ```no_run
/// use dioxus::prelude::*;
/// use dioxus_auth::prelude::{SessionState, on_auth_state_change, AuthUser};
///
/// # #[derive(Debug, Clone, PartialEq)]
/// # struct User { id: u64, name: String }
/// # impl AuthUser for User {
/// #     type Id = u64;
/// #     fn id(&self) -> u64 { return self.id; }
/// #     fn email(&self) -> &str { return &self.name; }
/// # }
/// # fn main() {
/// on_auth_state_change::<User, _>(|event| {
///     if let SessionState::SignedIn(user) = &event.current {
///         println!("signed in as {}", user.email());
///     }
/// });
/// # }
/// ```
///
/// # Panics
/// Panics when no enclosing [`AuthProvider`](crate::dioxus::AuthProvider) has
/// been mounted above the calling component.
pub fn on_auth_state_change<T, F>(mut handler: F)
where
    T: AuthUser + Clone + PartialEq + 'static,
    F: FnMut(&AuthStateEvent<T>) + 'static,
{
    let context = use_context::<AuthContext<T>>();
    let previous = use_hook(|| {
        return Rc::new(RefCell::new(None::<SessionState<T>>));
    });
    use_effect(move || {
        let current = context.session_state();
        let last = previous.borrow().clone();
        if let Some(last) = last {
            if last != current {
                handler(&AuthStateEvent {
                    previous: last,
                    current: current.clone(),
                });
            }
        }
        *previous.borrow_mut() = Some(current);
    });
}
