//! Phase D: `extract_session_token` contract.
//!
//! Bearer wins over cookie. Missing both → None. Malformed bearer falls through
//! to cookie. Empty values are ignored. Cookie name is exact match.
//! Spec 15: host_only enforces strict cookie-name matching.
//! C-F7: values that are not well-formed wire tokens (64 lowercase hex, the
//! shape `SessionId::generate` mints) are rejected on every transport.

use dioxus_auth::extract_session_token;

/// A well-formed 256-bit hex token, as `SessionId::generate` mints.
fn hex_token(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}

#[test]
fn bearer_wins_over_cookie() {
    let bearer_tok = hex_token(0xab);
    let cookie_tok = hex_token(0xcd);
    let token = extract_session_token(
        Some(&format!("Bearer {bearer_tok}")),
        Some(&format!("dioxus_session={cookie_tok}")),
        "dioxus_session",
        false,
    );
    assert_eq!(token.as_deref(), Some(bearer_tok.as_str()));
}

#[test]
fn cookie_used_when_no_bearer() {
    let cookie_tok = hex_token(0xcd);
    let token = extract_session_token(
        None,
        Some(&format!("foo=bar; dioxus_session={cookie_tok}; baz=qux")),
        "dioxus_session",
        false,
    );
    assert_eq!(token.as_deref(), Some(cookie_tok.as_str()));
}

#[test]
fn cookie_used_when_bearer_malformed() {
    // "Basic ..." is not Bearer; should fall through to cookie.
    let cookie_tok = hex_token(0xcd);
    let token = extract_session_token(
        Some("Basic dXNlcjpwYXNz"),
        Some(&format!("dioxus_session={cookie_tok}")),
        "dioxus_session",
        false,
    );
    assert_eq!(token.as_deref(), Some(cookie_tok.as_str()));
}

#[test]
fn missing_both_returns_none() {
    let token = extract_session_token(None, Some("foo=bar; baz=qux"), "dioxus_session", false);
    assert_eq!(token, None);
}

#[test]
fn empty_cookie_value_ignored() {
    let token = extract_session_token(
        None,
        Some("dioxus_session=; foo=bar"),
        "dioxus_session",
        false,
    );
    assert_eq!(token, None);
}

#[test]
fn empty_bearer_value_falls_through() {
    let cookie_tok = hex_token(0xcd);
    let token = extract_session_token(
        Some("Bearer "),
        Some(&format!("dioxus_session={cookie_tok}")),
        "dioxus_session",
        false,
    );
    assert_eq!(token.as_deref(), Some(cookie_tok.as_str()));
}

#[test]
fn cookie_name_is_exact_match() {
    let cookie_tok = hex_token(0xcd);
    let token = extract_session_token(
        None,
        Some(&format!("session=other; dioxus_session={cookie_tok}")),
        "dioxus_session",
        false,
    );
    assert_eq!(token.as_deref(), Some(cookie_tok.as_str()));
}

#[test]
fn custom_cookie_name() {
    let tok = hex_token(0x11);
    let token = extract_session_token(
        None,
        Some(&format!("app_session={tok}")),
        "app_session",
        false,
    );
    assert_eq!(token.as_deref(), Some(tok.as_str()));
}

#[test]
fn bearer_with_lowercase_scheme() {
    let tok = hex_token(0x22);
    let token = extract_session_token(
        Some(&format!("bearer {tok}")),
        None,
        "dioxus_session",
        false,
    );
    assert_eq!(token.as_deref(), Some(tok.as_str()));
}

#[test]
fn host_only_rejects_bare_cookie_name() {
    // Spec 15: when host_only=true, bare name is rejected — even for a
    // well-formed value, so this isolates the NAME rule.
    let tok = hex_token(0xab);
    let token = extract_session_token(
        None,
        Some(&format!("dioxus_session={tok}")),
        "dioxus_session",
        true,
    );
    assert_eq!(token, None);
}

#[test]
fn host_only_accepts_prefixed_cookie_name() {
    // Spec 15: when host_only=true, __Host- prefixed form is accepted.
    let tok = hex_token(0xab);
    let token = extract_session_token(
        None,
        Some(&format!("__Host-dioxus_session={tok}")),
        "dioxus_session",
        true,
    );
    assert_eq!(token.as_deref(), Some(tok.as_str()));
}

#[test]
fn non_host_only_rejects_prefixed_cookie_name() {
    // Spec 15: when host_only=false, __Host- prefixed form is rejected.
    let tok = hex_token(0xab);
    let token = extract_session_token(
        None,
        Some(&format!("__Host-dioxus_session={tok}")),
        "dioxus_session",
        false,
    );
    assert_eq!(token, None);
}

/// C-F7: the wire format gate. Values that do not match the engine-minted
/// shape (64 lowercase hex chars) are rejected on both transports.
#[test]
fn malformed_wire_tokens_are_rejected() {
    let legit = hex_token(0x0f);

    // Oversized bearer (65 chars) — rejected before any hashing.
    assert_eq!(
        extract_session_token(
            Some(&format!("Bearer {}", "a".repeat(65))),
            None,
            "s",
            false
        ),
        None
    );
    // Non-hex 64-char value — rejected.
    assert_eq!(
        extract_session_token(
            Some(&format!("Bearer {}", "z".repeat(64))),
            None,
            "s",
            false
        ),
        None
    );
    // Uppercase hex — rejected (wire tokens are lowercase).
    let upper = "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef";
    assert_eq!(
        extract_session_token(Some(&format!("Bearer {upper}")), None, "s", false),
        None
    );
    // Cookie value with the same malformed shapes — rejected too.
    assert_eq!(
        extract_session_token(None, Some(&format!("s={}", "a".repeat(65))), "s", false),
        None
    );
    assert_eq!(
        extract_session_token(None, Some(&format!("s={}", "z".repeat(64))), "s", false),
        None
    );
    // The well-formed token is accepted on both transports.
    assert_eq!(
        extract_session_token(Some(&format!("Bearer {legit}")), None, "s", false).as_deref(),
        Some(legit.as_str())
    );
    assert_eq!(
        extract_session_token(None, Some(&format!("s={legit}")), "s", false).as_deref(),
        Some(legit.as_str())
    );
}
