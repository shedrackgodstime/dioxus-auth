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
        }
    }
}

impl CookieConfig {
    /// Format a `Set-Cookie` HTTP header value for establishing an active session.
    pub fn build_set_cookie_header(&self, session_id: &SessionId) -> String {
        let mut header = format!("{}={}; Path={}", self.name, session_id.as_str(), self.path);

        if let Some(domain) = &self.domain {
            header.push_str(&format!("; Domain={domain}"));
        }
        if let Some(max_age) = self.max_age_secs {
            header.push_str(&format!("; Max-Age={max_age}"));
        }
        if self.http_only {
            header.push_str("; HttpOnly");
        }
        if self.secure {
            header.push_str("; Secure");
        }
        header.push_str(&format!("; SameSite={}", self.same_site.as_str()));

        header
    }

    /// Format a `Set-Cookie` HTTP header value to immediately invalidate and delete the cookie.
    pub fn build_delete_cookie_header(&self) -> String {
        let mut header = format!("{}=; Path={}; Max-Age=0", self.name, self.path);
        if let Some(domain) = &self.domain {
            header.push_str(&format!("; Domain={domain}"));
        }
        if self.http_only {
            header.push_str("; HttpOnly");
        }
        if self.secure {
            header.push_str("; Secure");
        }
        header.push_str(&format!("; SameSite={}", self.same_site.as_str()));
        header
    }

    /// Extract the session ID from an incoming HTTP `Cookie` header string.
    pub fn extract_session_id(&self, cookie_header: &str) -> Option<SessionId> {
        for pair in cookie_header.split(';') {
            let mut parts = pair.trim().splitn(2, '=');
            if let (Some(name), Some(val)) = (parts.next(), parts.next()) {
                if name.trim() == self.name {
                    let val = val.trim();
                    if !val.is_empty() {
                        return Some(SessionId::new(val));
                    }
                }
            }
        }
        None
    }
}
