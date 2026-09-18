//! Return-to (`auth_intent`) navigation — park the destination a signed-out
//! visitor was heading for, pop it after login.
//!
//! Spec 17 §3 / research 23 §2.10. The loop:
//!
//! 1. `RouteGate` (with `preserve_intent` on, the default) bounces an
//!    unauthenticated visitor and **captures** the target URL.
//! 2. The login page consumes it after a successful sign-in:
//!
//! ```ignore
//! let nav = use_navigator();
//! spawn(async move {
//!     if let Ok(user) = login_server(email(), password()).await {
//!         auth.set_user(user);
//!         let dest = consume_return_to(); // pop-once, validated
//!         // navigate `dest` or your default; parse with Route::from_str
//!     }
//! });
//! ```
//!
//! Deviation from spec 17 §3.2's sketch: consumption is these free functions,
//! not a method on [`crate::Auth`] — `Auth` stays a pure `Copy` signal handle
//! (spec 13 rule 2); browser-storage concerns live here.
//!
//! Open-redirect defense (research 23 §2.10): only relative paths starting
//! with a single `/` are ever stored or returned; anything else is rejected
//! on the way in **and** on the way out.
//!
//! Storage is browser `localStorage` under wasm32; other targets (SSR server,
//! native) are no-ops, so calling these from shared components is safe.

/// `localStorage` key for the parked destination (spec 17 §3.2).
pub const AUTH_INTENT_KEY: &str = "dioxus_auth_intent";

// ---------------------------------------------------------------------------
// storage seam — real localStorage on wasm, no-op elsewhere
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
mod intent_store {
    use super::AUTH_INTENT_KEY;

    fn storage() -> Option<web_sys::Storage> {
        web_sys::window()?.local_storage().ok().flatten()
    }

    pub(crate) fn set(value: &str) {
        if let Some(s) = storage() {
            let _ = s.set_item(AUTH_INTENT_KEY, value);
        }
    }

    pub(crate) fn get() -> Option<String> {
        storage()?.get_item(AUTH_INTENT_KEY).ok().flatten()
    }

    pub(crate) fn remove() {
        if let Some(s) = storage() {
            let _ = s.remove_item(AUTH_INTENT_KEY);
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod intent_store {
    pub(crate) fn set(_value: &str) {}
    pub(crate) fn get() -> Option<String> {
        None
    }
    pub(crate) fn remove() {}
}

// ---------------------------------------------------------------------------
// public API
// ---------------------------------------------------------------------------

/// Whether `path` is a safe return-to destination.
///
/// Accepts **relative paths only**: must start with `/`, must not start with
/// `//` (protocol-relative), must contain no scheme separator, whitespace, or
/// control characters. This is the open-redirect filter from research 23
/// §2.10 — an attacker-crafted `?next=https://evil.com` can never survive it.
#[must_use]
pub fn is_safe_return_to(path: &str) -> bool {
    if path.is_empty() || !path.starts_with('/') {
        return false;
    }
    if path.starts_with("//") {
        return false;
    }
    // Any `scheme:` prefix (`javascript:`, `data:`, …) is a different
    // URL-space; a relative path never needs one.
    if path.contains(':') {
        return false;
    }
    // Whitespace/control chars: parsers and redirects disagree about them.
    if path.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    true
}

/// Park the destination a signed-out visitor was heading for.
///
/// Called by [`crate::RouteGate`] when `preserve_intent` is on; can also be
/// called manually for custom guard flows. No-op unless `path` passes
/// [`is_safe_return_to`], and a no-op off-wasm.
pub fn capture_return_to(path: &str) {
    if !is_safe_return_to(path) {
        return;
    }
    intent_store::set(path);
}

/// Pop the parked destination — single read, then gone (a stale intent can
/// never hijack a later manual login).
///
/// Re-validated with [`is_safe_return_to`] on the way out; returns `None`
/// when absent, when this is not a browser, or when the stored value is not
/// a safe relative path.
#[must_use]
pub fn consume_return_to() -> Option<String> {
    let value = intent_store::get()?;
    intent_store::remove();
    if is_safe_return_to(&value) {
        Some(value)
    } else {
        None
    }
}

/// Drop any parked destination without consuming it.
///
/// Call when the user navigates somewhere other than the parked destination,
/// so a stale bounce can't hijack a later login.
pub fn clear_return_to() {
    intent_store::remove();
}

#[cfg(test)]
mod tests {
    use super::*;

    // Host-testable matrix for the open-redirect filter.
    #[test]
    fn safe_paths_are_accepted() {
        assert!(is_safe_return_to("/"));
        assert!(is_safe_return_to("/app/exam/cbt"));
        assert!(is_safe_return_to("/app/x?next=1#frag"));
        assert!(is_safe_return_to("/a-b_c.d/e"));
    }

    #[test]
    fn unsafe_paths_are_rejected() {
        assert!(!is_safe_return_to(""));
        assert!(!is_safe_return_to("app/exam"), "must be rooted");
        assert!(!is_safe_return_to("//evil.com"), "protocol-relative");
        assert!(!is_safe_return_to("///evil.com"));
        assert!(!is_safe_return_to("https://evil.com"));
        assert!(!is_safe_return_to("javascript:alert(1)"));
        assert!(!is_safe_return_to("data:text/html,x"));
        assert!(!is_safe_return_to(" /x"), "leading space");
        assert!(!is_safe_return_to("/x\n"));
        assert!(!is_safe_return_to("/x\ty"));
        assert!(!is_safe_return_to("/a b"));
    }

    // Off-wasm behavior: storage seam is a no-op, so capture/consume are
    // safe to call from shared code and consume is always None.
    #[test]
    fn off_wasm_capture_and_consume_are_no_ops() {
        capture_return_to("/app/exam");
        assert_eq!(consume_return_to(), None);
        clear_return_to(); // must not panic
    }
}
