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
            return Some(token.to_string());
        }
    }
    if let Some(raw) = cookie {
        if let Some(token) = cookie_value(raw, cookie_name, host_only) {
            return Some(token.to_string());
        }
    }
    None
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

    #[test]
    fn bearer_wins_over_cookie() {
        let token = extract_session_token(
            Some("Bearer bearer_token_xyz"),
            Some("dioxus_session=cookie_token_abc"),
            "dioxus_session",
            false,
        );
        assert_eq!(token.as_deref(), Some("bearer_token_xyz"));
    }

    #[test]
    fn cookie_used_when_no_bearer() {
        let token = extract_session_token(
            None,
            Some("foo=bar; dioxus_session=cookie_token_abc; baz=qux"),
            "dioxus_session",
            false,
        );
        assert_eq!(token.as_deref(), Some("cookie_token_abc"));
    }

    #[test]
    fn cookie_used_when_bearer_malformed() {
        // "Basic ..." is not Bearer; should fall through to cookie.
        let token = extract_session_token(
            Some("Basic dXNlcjpwYXNz"),
            Some("dioxus_session=cookie_token_abc"),
            "dioxus_session",
            false,
        );
        assert_eq!(token.as_deref(), Some("cookie_token_abc"));
    }

    #[test]
    fn missing_both_returns_none() {
        let token = extract_session_token(None, Some("foo=bar; baz=qux"), "dioxus_session", false);
        assert_eq!(token, None);
    }

    #[test]
    fn empty_cookie_value_ignored() {
        let token = extract_session_token(None, Some("dioxus_session=; foo=bar"), "dioxus_session", false);
        assert_eq!(token, None);
    }

    #[test]
    fn empty_bearer_value_falls_through() {
        let token = extract_session_token(
            Some("Bearer "),
            Some("dioxus_session=cookie_token_abc"),
            "dioxus_session",
            false,
        );
        assert_eq!(token.as_deref(), Some("cookie_token_abc"));
    }

    #[test]
    fn cookie_name_is_exact_match() {
        let token = extract_session_token(
            None,
            Some("session=other; dioxus_session=mine"),
            "dioxus_session",
            false,
        );
        assert_eq!(token.as_deref(), Some("mine"));
    }

    #[test]
    fn host_prefixed_cookie_found_when_host_only() {
        // host_only=true: __Host- prefixed form is accepted
        let token = extract_session_token(
            None,
            Some("__Host-dioxus_session=host_token_abc"),
            "dioxus_session",
            true,
        );
        assert_eq!(token.as_deref(), Some("host_token_abc"));
    }

    #[test]
    fn bare_cookie_rejected_when_host_only() {
        // host_only=true: bare name is rejected
        let token = extract_session_token(
            None,
            Some("dioxus_session=bare_token_abc"),
            "dioxus_session",
            true,
        );
        assert_eq!(token, None);
    }

    #[test]
    fn host_prefixed_cookie_rejected_when_not_host_only() {
        // host_only=false: __Host- prefixed form is rejected
        let token = extract_session_token(
            None,
            Some("__Host-dioxus_session=host_token_abc"),
            "dioxus_session",
            false,
        );
        assert_eq!(token, None);
    }
}
