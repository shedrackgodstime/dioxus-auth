//! Phase D: `extract_session_token` contract.
//!
//! Bearer wins over cookie. Missing both → None. Malformed bearer falls through
//! to cookie. Empty values are ignored. Cookie name is exact match.

use dioxus_auth::extract_session_token;

#[test]
fn bearer_wins_over_cookie() {
    let token = extract_session_token(
        Some("Bearer bearer_token_xyz"),
        Some("dioxus_session=cookie_token_abc"),
        "dioxus_session",
    );
    assert_eq!(token.as_deref(), Some("bearer_token_xyz"));
}

#[test]
fn cookie_used_when_no_bearer() {
    let token = extract_session_token(
        None,
        Some("foo=bar; dioxus_session=cookie_token_abc; baz=qux"),
        "dioxus_session",
    );
    assert_eq!(token.as_deref(), Some("cookie_token_abc"));
}

#[test]
fn cookie_used_when_bearer_malformed() {
    let token = extract_session_token(
        Some("Basic dXNlcjpwYXNz"),
        Some("dioxus_session=cookie_token_abc"),
        "dioxus_session",
    );
    assert_eq!(token.as_deref(), Some("cookie_token_abc"));
}

#[test]
fn missing_both_returns_none() {
    let token = extract_session_token(None, Some("foo=bar; baz=qux"), "dioxus_session");
    assert_eq!(token, None);
}

#[test]
fn empty_cookie_value_ignored() {
    let token = extract_session_token(None, Some("dioxus_session=; foo=bar"), "dioxus_session");
    assert_eq!(token, None);
}

#[test]
fn empty_bearer_value_falls_through() {
    let token = extract_session_token(
        Some("Bearer "),
        Some("dioxus_session=cookie_token_abc"),
        "dioxus_session",
    );
    assert_eq!(token.as_deref(), Some("cookie_token_abc"));
}

#[test]
fn cookie_name_is_exact_match() {
    let token = extract_session_token(
        None,
        Some("session=other; dioxus_session=mine"),
        "dioxus_session",
    );
    assert_eq!(token.as_deref(), Some("mine"));
}

#[test]
fn custom_cookie_name() {
    let token = extract_session_token(None, Some("app_session=my_app_token"), "app_session");
    assert_eq!(token.as_deref(), Some("my_app_token"));
}

#[test]
fn bearer_with_lowercase_scheme() {
    let token = extract_session_token(Some("bearer lower_bearer_token"), None, "dioxus_session");
    assert_eq!(token.as_deref(), Some("lower_bearer_token"));
}
