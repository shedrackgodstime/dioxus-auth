use crate::error::{AuthError, AuthResult};
use crate::session::SessionId;

/// SameSite policy for session cookies.
///
/// Maps to the `SameSite` cookie attribute; see [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)
/// for browser behavior details.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum SameSite {
    /// Send the cookie on same-site requests and top-level cross-site navigation (default).
    #[default]
    Lax,
    /// Send the cookie only on same-site requests.
    Strict,
    /// Send the cookie on cross-site requests; requires the `Secure` flag.
    None,
}

impl SameSite {
    /// Canonical `SameSite` attribute string for `Set-Cookie` headers.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Lax => "Lax",
            Self::Strict => "Strict",
            Self::None => "None",
        }
    }
}

/// Result of origin validation.
///
/// `Mismatch` carries both sides of the comparison so the caller can log the
/// event without the validator itself performing I/O.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OriginValidation {
    /// Origin is valid (matches expected origin or origin is not required).
    Valid,
    /// Origin is present but does not match expected origins.
    Mismatch {
        /// The origin(s) the server was configured to accept.
        expected: String,
        /// The `Origin` header value the client actually sent.
        received: String,
    },
}

/// Configuration for session cookie issuance and validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CookieConfig {
    /// Name of the session cookie. Default is `"dioxus_session"`.
    pub name: String,
    /// Path scope for the cookie. Default is `"/"`.
    pub path: String,
    /// Optional domain scope.
    pub domain: Option<String>,
    /// Whether the cookie requires HTTPS. Default is `true` in release builds.
    pub secure: bool,
    /// Whether the cookie is forbidden from client-side JavaScript access. Default is `true`.
    pub http_only: bool,
    /// SameSite policy. Default is [`SameSite::Lax`].
    pub same_site: SameSite,
    /// Session cookie time-to-live in seconds. Default is 7 days.
    pub max_age_secs: Option<u64>,
    /// Use `__Host-` prefix for the cookie name, enforcing host-only scope.
    ///
    /// When enabled, the cookie name is prefixed with `__Host-` and the
    /// `Domain` attribute is omitted. The `Secure` flag is enforced.
    /// The `Path` is forced to `/`.
    pub host_only: bool,
    /// Expected Origins for CSRF protection with cookie-based auth.
    ///
    /// When set, requests using cookie credentials must include an `Origin` header
    /// that matches one of these values. Matches against the scheme, host, and port.
    /// A `None` value means origin validation is disabled (default for backward compatibility).
    pub expected_origins: Option<Vec<String>>,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            name: "dioxus_session".to_string(),
            path: "/".to_string(),
            domain: None,
            secure: !cfg!(debug_assertions),
            http_only: true,
            same_site: SameSite::Lax,
            max_age_secs: Some(60 * 60 * 24 * 7), // 7 days
            host_only: false,
            expected_origins: None,
        }
    }
}

impl CookieConfig {
    /// Format a `Set-Cookie` HTTP header value for establishing an active session.
    #[must_use = "the header value must be attached to the HTTP response"]
    pub fn build_set_cookie_header(&self, session_id: &SessionId) -> String {
        let cookie_name = if self.host_only {
            format!("__Host-{}", self.name)
        } else {
            self.name.clone()
        };

        // __Host- cookies MUST use Path=/ (RFC 6265bis §5)
        let path = if self.host_only { "/" } else { &self.path };

        let mut header = format!("{}={}; Path={}", cookie_name, session_id.as_str(), path);

        // __Host- cookies forbid Domain attribute
        if !self.host_only {
            if let Some(domain) = &self.domain {
                header.push_str(&format!("; Domain={domain}"));
            }
        }
        if let Some(max_age) = self.max_age_secs {
            header.push_str(&format!("; Max-Age={max_age}"));
        }
        if self.http_only {
            header.push_str("; HttpOnly");
        }
        // __Host- cookies enforce Secure
        if self.secure || self.host_only {
            header.push_str("; Secure");
        }
        header.push_str(&format!("; SameSite={}", self.same_site.as_str()));

        header
    }

    /// Format a `Set-Cookie` HTTP header value to immediately invalidate and delete the cookie.
    #[must_use = "the header value must be attached to the HTTP response"]
    pub fn build_delete_cookie_header(&self) -> String {
        let cookie_name = if self.host_only {
            format!("__Host-{}", self.name)
        } else {
            self.name.clone()
        };

        // Mirrors build_set_cookie_header: a delete header only clears a
        // cookie with the same Path, and __Host- cookies are always written
        // with Path=/ (RFC 6265bis §5) — emit nothing else or logout
        // silently fails to clear the session cookie.
        let path = if self.host_only { "/" } else { &self.path };
        let mut header = format!("{}=; Path={}; Max-Age=0", cookie_name, path);

        // __Host- cookies forbid Domain attribute
        if !self.host_only {
            if let Some(domain) = &self.domain {
                header.push_str(&format!("; Domain={domain}"));
            }
        }
        if self.http_only {
            header.push_str("; HttpOnly");
        }
        // __Host- cookies enforce Secure
        if self.secure || self.host_only {
            header.push_str("; Secure");
        }
        header.push_str(&format!("; SameSite={}", self.same_site.as_str()));

        header
    }

    /// Extract the session ID from an incoming HTTP `Cookie` header string.
    ///
    /// When `host_only` is `true`, only the `__Host-<name>` form is accepted —
    /// the bare `<name>` is rejected (Spec 15). When `host_only` is `false`,
    /// only the bare `<name>` is accepted — the `__Host-` prefixed form is
    /// rejected. This prevents cookie-name confusion attacks.
    pub fn extract_session_id(&self, cookie_header: &str) -> Option<SessionId> {
        let expected_name = if self.host_only {
            format!("__Host-{}", self.name)
        } else {
            self.name.clone()
        };
        for pair in cookie_header.split(';') {
            let mut parts = pair.trim().splitn(2, '=');
            if let (Some(name), Some(val)) = (parts.next(), parts.next()) {
                let val = val.trim();
                if val.is_empty() {
                    continue;
                }
                if name.trim() == expected_name {
                    return Some(SessionId::new(val));
                }
            }
        }
        None
    }

    /// Validate the request `Origin` header against the configured expected origins.
    ///
    /// Returns [`OriginValidation::Valid`] if no origins are configured (validation disabled),
    /// if no Origin header is present (browsers may omit it for same-origin GET requests), or
    /// if the Origin matches one of the expected values.
    ///
    /// Returns [`OriginValidation::Mismatch`] if the Origin is present but does not match.
    ///
    /// This is used for **safe** requests (GET/HEAD/OPTIONS) where Origin may be absent.
    /// For state-changing cookie operations, use [`CookieConfig::validate_cookie_origin`]
    /// which requires Origin to be present when `expected_origins` is configured.
    pub fn validate_origin(&self, origin: Option<&str>) -> OriginValidation {
        let Some(expected) = &self.expected_origins else {
            return OriginValidation::Valid;
        };
        let Some(received) = origin else {
            return OriginValidation::Valid;
        };
        for exp in expected {
            if exp == received {
                return OriginValidation::Valid;
            }
        }
        OriginValidation::Mismatch {
            expected: expected.join(", "),
            received: received.to_string(),
        }
    }

    /// Validate Origin for state-changing cookie operations (login, logout).
    ///
    /// When `expected_origins` is configured, the Origin header **must** be present
    /// and match one of the expected values. Returns `Err(AuthError::Csrf)` on
    /// mismatch or absence. When `expected_origins` is `None`, all origins are allowed.
    ///
    /// Bearer credentials never need Origin validation — this is only for cookie ops.
    pub fn validate_cookie_origin(&self, origin: Option<&str>) -> AuthResult<()> {
        let Some(expected) = &self.expected_origins else {
            return Ok(());
        };
        let Some(received) = origin else {
            return Err(AuthError::Csrf);
        };
        for exp in expected {
            if exp == received {
                return Ok(());
            }
        }
        Err(AuthError::Csrf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Extract the `Path=` attribute value from a Set-Cookie header string.
    fn path_of(header: &str) -> &str {
        header
            .split(';')
            .map(str::trim)
            .find_map(|a| a.strip_prefix("Path="))
            .expect("header must carry a Path attribute")
    }

    /// G6 regression: the delete header must target the exact cookie the set
    /// header wrote — same name AND same Path — or logout silently fails.
    #[test]
    fn delete_header_is_symmetric_with_set_header() {
        // The trap config: host_only forces Path=/ on set, so delete must
        // emit Path=/ too — not the configured custom path.
        let cfg = CookieConfig {
            name: "app_sess".into(),
            path: "/app".into(),
            host_only: true,
            ..Default::default()
        };
        let set = cfg.build_set_cookie_header(&SessionId::new("tok"));
        let del = cfg.build_delete_cookie_header();
        assert!(
            set.starts_with("__Host-app_sess="),
            "set uses prefix: {set}"
        );
        assert_eq!(path_of(&set), "/", "host_only set forces Path=/");
        assert!(
            del.starts_with("__Host-app_sess="),
            "delete uses prefix: {del}"
        );
        assert_eq!(
            path_of(&del),
            "/",
            "host_only delete must also force Path=/"
        );
        assert_eq!(
            path_of(&set),
            path_of(&del),
            "delete must match set exactly"
        );

        // Default path with host_only: both sides "/", symmetric.
        let cfg = CookieConfig {
            name: "app_sess".into(),
            host_only: true,
            ..Default::default()
        };
        let set = cfg.build_set_cookie_header(&SessionId::new("tok"));
        let del = cfg.build_delete_cookie_header();
        assert_eq!(path_of(&set), "/");
        assert_eq!(path_of(&set), path_of(&del));

        // Non-host-only custom path: unchanged behavior, still symmetric.
        let cfg = CookieConfig {
            name: "app_sess".into(),
            path: "/app".into(),
            ..Default::default()
        };
        let set = cfg.build_set_cookie_header(&SessionId::new("tok"));
        let del = cfg.build_delete_cookie_header();
        assert!(set.starts_with("app_sess="), "no prefix without host_only");
        assert_eq!(path_of(&set), "/app");
        assert_eq!(path_of(&set), path_of(&del), "custom path stays symmetric");
    }
}
