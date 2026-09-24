//! Authentication hook firing.

use crate::engine::{AuthEngine, SubjectCallback};
use crate::store::session::SessionStore;
use crate::store::user::{AuthSubject, CredentialStore};

impl<C, S> AuthEngine<C, S>
where
    C: CredentialStore,
    S: SessionStore<AuthId = C::AuthId>,
{
    pub(crate) fn fire_on_sign_in(&self, subject: &AuthSubject<C::AuthId, C::AppRef>) {
        fire_hook(self.on_sign_in.as_ref(), subject);
    }

    pub(crate) fn fire_on_sign_out(&self, subject: &AuthSubject<C::AuthId, C::AppRef>) {
        fire_hook(self.on_sign_out.as_ref(), subject);
    }

    pub(crate) fn fire_on_session_validated(&self, subject: &AuthSubject<C::AuthId, C::AppRef>) {
        fire_hook(self.on_session_validated.as_ref(), subject);
    }
}

/// Fires a hook.
///
/// A panicking hook indicates a programming error: it is intentionally not
/// caught. The panic stops the program.
///
/// Visibility lives on the module (`pub(crate) mod hooks`): plain `pub` here
/// is already crate-internal, and `pub(crate)` would trip
/// `redundant_pub_crate`.
///
/// # Panics
/// Propagates any panic raised by `hook`; panics in hooks are programming
/// errors and must stop the program rather than be caught.
pub fn fire_hook<AuthId, AppRef>(
    hook: Option<&SubjectCallback<AuthId, AppRef>>,
    subject: &AuthSubject<AuthId, AppRef>,
) {
    if let Some(hook) = hook {
        hook(subject);
    }
}
