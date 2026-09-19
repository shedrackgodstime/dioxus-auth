/// Extract a session token from request headers, preferring `Authorization: Bearer`
/// and falling back to a `Cookie` header.
///
/// Bearer takes precedence over cookies. If both are present, Bearer wins.
///
/// When `host_only` is `true`, only the `__Host-<cookie_name>` form is accepted;
/// when `false`, only the bare `<cookie_name>` is accepted (Spec 15).
pub fn extract_session_token(
    authorization: Option<&str>,
    cookie: Option<&str>,
    cookie_name: &str,
    host_only: bool,
) -> Option<String> {
    if let Some(raw) = authorization {
        if let Some(token) = bearer_token(raw) {
            return valid_wire_token(token).map(str::to_string);
        }
    }
    if let Some(raw) = cookie {
        if let Some(token) = cookie_value(raw, cookie_name, host_only) {
            return valid_wire_token(token).map(str::to_string);
        }
    }
    None
}

/// Wire tokens must have the exact shape the engine mints (256-bit CSPRNG
/// hex, 64 chars). Anything else is a cheap rejection before any hashing —
/// an oversized or malformed cookie/bearer value cannot force unbounded
/// `sha256` work or reach the store (C-F7).
fn valid_wire_token(token: &str) -> Option<&str> {
    if crate::session::SessionId::is_valid_wire_format(token) {
        Some(token)
    } else {
        None
    }
}

/// Extract the bearer token from an `Authorization` header value.
///
/// Accepts `Bearer <token>` and `bearer <token>`.
fn bearer_token(authorization: &str) -> Option<&str> {
    let trimmed = authorization.trim();
    let mut parts = trimmed.splitn(2, ' ');
    let scheme = parts.next()?.trim();
    let value = parts.next()?.trim();
    if !scheme.eq_ignore_ascii_case("bearer") || value.is_empty() {
        return None;
    }
    Some(value)
}

/// Extract a named cookie value from a `Cookie` header string.
///
/// When `host_only` is `true`, only matches the `__Host-<name>` form.
/// When `false`, only matches the bare `<name>` form (Spec 15).
fn cookie_value<'a>(cookie_header: &'a str, name: &str, host_only: bool) -> Option<&'a str> {
    let expected_name = if host_only {
        format!("__Host-{name}")
    } else {
        name.to_string()
    };
    for pair in cookie_header.split(';') {
        let mut parts = pair.trim().splitn(2, '=');
        if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            let k = k.trim();
            if k == expected_name {
                let v = v.trim();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed 256-bit hex token, as `SessionId::generate` mints.
    fn hex_token(seed: u8) -> String {
        let pair = format!("{seed:02x}");
        pair.repeat(32)
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
    fn host_prefixed_cookie_found_when_host_only() {
        // host_only=true: __Host- prefixed form is accepted
        let cookie_tok = hex_token(0xab);
        let token = extract_session_token(
            None,
            Some(&format!("__Host-dioxus_session={cookie_tok}")),
            "dioxus_session",
            true,
        );
        assert_eq!(token.as_deref(), Some(cookie_tok.as_str()));
    }

    #[test]
    fn bare_cookie_rejected_when_host_only() {
        // host_only=true: bare name is rejected even when the value is a
        // perfectly formed token — the NAME rule is what fails here.
        let cookie_tok = hex_token(0xab);
        let token = extract_session_token(
            None,
            Some(&format!("dioxus_session={cookie_tok}")),
            "dioxus_session",
            true,
        );
        assert_eq!(token, None);
    }

    #[test]
    fn malformed_wire_tokens_are_rejected() {
        let legit = "a".repeat(64);
        // Oversized token: rejected regardless of transport.
        assert_eq!(
            extract_session_token(
                Some(&format!("Bearer {}", "a".repeat(65))),
                None,
                "s",
                false
            ),
            None
        );
        // Non-hex characters.
        assert_eq!(
            extract_session_token(
                Some(&format!("Bearer {}", "z".repeat(64))),
                None,
                "s",
                false
            ),
            None
        );
        // Valid 64-hex bearer is accepted.
        assert_eq!(
            extract_session_token(Some(&format!("Bearer {legit}")), None, "s", false).as_deref(),
            Some(legit.as_str())
        );
    }

    #[test]
    fn host_prefixed_cookie_rejected_when_not_host_only() {
        // host_only=false: __Host- prefixed form is rejected even when the
        // value is well formed — again the NAME rule, not the value shape.
        let cookie_tok = hex_token(0xab);
        let token = extract_session_token(
            None,
            Some(&format!("__Host-dioxus_session={cookie_tok}")),
            "dioxus_session",
            false,
        );
        assert_eq!(token, None);
    }
}
