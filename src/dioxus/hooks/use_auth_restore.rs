//! Restore authentication status from an async source (session probe, token
//! refresh, network whoami).
//!
//! The probe's error is **classified**, not flattened (research 23 §2.1): a
//! definitive server rejection demotes the user to a guest, but a network
//! failure ("we don't know") leaves the status at `Loading` — a Wi-Fi/DNS
//! blip at boot no longer logs anyone out. See [`crate::dioxus::restore`].

use dioxus::prelude::*;

use crate::dioxus::hooks::use_auth::use_auth;
use crate::dioxus::restore::{RestoreClassify, RestoreVerdict};
use crate::session::AuthStatus;

/// Drive auth status from a restore result.
///
/// Decision table (research 23 §2.1):
///
/// | Probe result | Client status |
/// |---|---|
/// | `Ok(Some(user))` | `Authenticated` |
/// | `Ok(None)` | `Unauthenticated` (server said no session) |
/// | `Err(e)` where `e.restore_verdict()` is `Unauthenticated` | `Unauthenticated` (definitive rejection) |
/// | `Err(e)` where `e.restore_verdict()` is `Unknown` | **stay `Loading`** — we learned nothing |
/// | `None` | stay `Loading` |
///
/// Only mutates while still `Loading`, so a manual login/logout is never
/// overwritten by a late or failed restore.
///
/// # Rules of hooks
/// Must be called unconditionally at the top level of a component (it reads
/// context internally). It is intentionally *not* reactive to its argument:
/// pass the current resource value each render (`whoami.read().clone()`), and
/// the hook applies it only while the status is still `Loading`.
///
/// `Unknown` verdicts should be **retried**, not rendered as a guest state —
/// restart the probe on window focus / `visibilitychange`
/// (`whoami.restart()`) while the status is `Loading`.
///
/// A probe that never resolves keeps the app `Loading` forever (guards stay
/// `Pending`, `SignedIn`/`SignedOut` render nothing) — retrying is not
/// optional. See [`crate::AuthProvider`]'s Loading-forever note.
#[doc(alias = "use_session_restore")]
pub fn use_auth_restore<User, E>(restored: Option<Result<Option<User>, E>>)
where
    User: Clone + 'static,
    E: RestoreClassify,
{
    let mut auth = use_auth::<User>();
    if !auth.is_loading() {
        return;
    }

    match restored {
        None => {}
        Some(Ok(Some(user))) => auth.set_user(user),
        Some(Ok(None)) => auth.set_status(AuthStatus::Unauthenticated),
        // The research 23 §2.1 fix: only a *definitive* server rejection may
        // demote to guest. Network/transport unknowns keep the pending state.
        Some(Err(e)) if e.restore_verdict() == RestoreVerdict::Unauthenticated => {
            auth.set_status(AuthStatus::Unauthenticated);
        }
        // Unknown verdict (network/transport): leave the status untouched —
        // we learned nothing, so we must not log anyone out.
        Some(Err(_)) => {}
    }
}
