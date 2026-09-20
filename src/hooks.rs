//! Authentication hook firing.

use crate::engine::{AuthEngine, UserCallback};
use crate::store::{PasswordUserStore, SessionStore};

impl<U, S> AuthEngine<U, S>
where
    U: PasswordUserStore,
    S: SessionStore<Id = U::Id>,
{
    pub(crate) fn fire_on_sign_in(&self, user: &U::User) {
        fire_hook(self.on_sign_in.as_ref(), user);
    }

    pub(crate) fn fire_on_sign_out(&self, user: &U::User) {
        fire_hook(self.on_sign_out.as_ref(), user);
    }

    pub(crate) fn fire_on_session_validated(&self, user: &U::User) {
        fire_hook(self.on_session_validated.as_ref(), user);
    }
}

/// Fires a hook.
///
/// Per RULES §8.5 a panicking hook indicates a programming error: it is
/// intentionally not caught. The panic stops the program.
pub fn fire_hook<U>(hook: Option<&UserCallback<U>>, user: &U) {
    if let Some(hook) = hook {
        hook(user);
    }
}
