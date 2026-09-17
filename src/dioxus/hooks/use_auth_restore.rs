//! Restore authentication status from an async source (session probe, token
//! refresh, network whoami).

use dioxus::prelude::*;

use crate::dioxus::hooks::use_auth::use_auth;
use crate::session::AuthStatus;

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
