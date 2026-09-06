use crate::session::SessionId;

/// SameSite policy for session cookies.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum SameSite {
    #[default]
    Lax,
    Strict,
    None,
}

impl SameSite {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Lax => "Lax",
            Self::Strict => "Strict",
            Self::None => "None",
        }
    }
}

/// Result of origin validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OriginValidation {
    /// Origin is valid (matches expected origin or origin is not required).
    Valid,
    /// Origin is present but does not match expected origins.
    Mismatch { expected: String, received: String },
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
    pub fn build_set_cookie_header(&self, session_id: &SessionId) -> String {
        let cookie_name = if self.host_only {
            format!("__Host-{}", self.name)
        } else {
            self.name.clone()
        };

        let mut header = format!(
            "{}={}; Path={}",
            cookie_name,
            session_id.as_str(),
            self.path
        );

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
    pub fn build_delete_cookie_header(&self) -> String {
        let cookie_name = if self.host_only {
            format!("__Host-{}", self.name)
        } else {
            self.name.clone()
        };

        let mut header = format!("{}=; Path={}; Max-Age=0", cookie_name, self.path);

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
    /// When `host_only` is enabled, the cookie name is prefixed with `__Host-`
    /// in `Set-Cookie` headers, so this method also checks for that prefix.
    pub fn extract_session_id(&self, cookie_header: &str) -> Option<SessionId> {
        for pair in cookie_header.split(';') {
            let mut parts = pair.trim().splitn(2, '=');
            if let (Some(name), Some(val)) = (parts.next(), parts.next()) {
                let val = val.trim();
                if val.is_empty() {
                    continue;
                }
                let trimmed_name = name.trim();
                if trimmed_name == self.name || trimmed_name == format!("__Host-{}", self.name) {
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
}
