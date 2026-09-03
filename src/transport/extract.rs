/// Extract a session token from request headers, preferring `Authorization: Bearer`
/// and falling back to a `Cookie` header.
///
/// This is the v0.1 dual-transport contract. On web, the browser usually attaches
/// the cookie; on desktop and mobile, the client usually attaches a bearer token
/// from a `TokenStorage`. If both are present, Bearer wins (mobile clients often
/// have no `Origin` header, so CSRF defenses are skipped for bearer credentials —
/// see spec/11 §5).
///
/// # Arguments
/// * `authorization` - the raw `Authorization` header value, if any
///   (e.g. `"Bearer abc123"`).
/// * `cookie` - the raw `Cookie` header value, if any
///   (e.g. `"dioxus_session=abc123; foo=bar"`).
/// * `cookie_name` - the session cookie name to look for in the `Cookie` header.
///
/// # Returns
/// The raw session token string, or `None` if neither header carries one.
pub fn extract_session_token(
    authorization: Option<&str>,
    cookie: Option<&str>,
    cookie_name: &str,
) -> Option<String> {
    if let Some(raw) = authorization {
        if let Some(token) = bearer_token(raw) {
            return Some(token.to_string());
        }
    }
    if let Some(raw) = cookie {
        if let Some(token) = cookie_value(raw, cookie_name) {
            return Some(token.to_string());
        }
    }
    None
}

/// Extract the bearer token from an `Authorization` header value.
///
/// Accepts `Bearer <token>` and `bearer <token>`. Returns `None` for any other
/// scheme (Basic, Digest, missing scheme, empty token).
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
/// Returns `None` if the cookie is not present or has an empty value.
fn cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for pair in cookie_header.split(';') {
        let mut parts = pair.trim().splitn(2, '=');
        if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            if k.trim() == name {
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
        // "Basic ..." is not Bearer; should fall through to cookie.
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
}
