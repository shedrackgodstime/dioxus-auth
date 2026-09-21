//! Security configuration and password-hashing capability trait.

use std::fmt::Debug;

use crate::error::AuthError;

/// Configuration for cookie-based sessions.
///
/// Fields are private; read or change them through the accessors and the
/// `with_*` setters. Secure defaults are active on [`CookieConfig::new`].
#[derive(Debug, Clone)]
pub struct CookieConfig {
    name: String,
    http_only: bool,
    secure: bool,
    same_site: SameSite,
    path: String,
    domain: Option<String>,
    max_age: Option<u64>,
}

impl CookieConfig {
    /// Creates the default session-cookie configuration.
    ///
    /// Defaults: `name = "session"`, `http_only = true`, `secure = true`,
    /// `same_site = SameSite::Lax`, `path = "/"`, no `domain`, no `max_age`.
    ///
    /// `max_age` defaults to `None` (a session cookie that dies with the
    /// browser session), independent of the engine's session TTL: size
    /// [`with_max_age`](Self::with_max_age) to the engine TTL for persistent
    /// login. Server-side sessions outlive a vanished cookie in that case;
    /// stores drop expired sessions lazily on use, so long-lived deployments
    /// want a store with background cleanup.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dioxus_auth::prelude::{CookieConfig, SameSite};
    /// let config = CookieConfig::new()
    ///     .with_secure(false)
    ///     .with_name(String::from("sid"));
    /// assert_eq!(config.name(), "sid");
    /// assert!(!config.secure());
    /// assert!(config.http_only());
    /// assert_eq!(config.same_site(), SameSite::Lax);
    /// let fresh = CookieConfig::new();
    /// assert_eq!(CookieConfig::default().name(), fresh.name());
    /// assert_eq!(CookieConfig::default().secure(), fresh.secure());
    /// ```
    #[must_use = "the cookie configuration must be used"]
    pub fn new() -> Self {
        return Self {
            name: String::from("session"),
            http_only: true,
            secure: true,
            same_site: SameSite::Lax,
            path: String::from("/"),
            domain: None,
            max_age: None,
        };
    }

    /// The cookie name.
    #[must_use]
    pub fn name(&self) -> &str {
        return &self.name;
    }

    /// Whether the cookie is HTTP-only.
    #[must_use]
    pub const fn http_only(&self) -> bool {
        return self.http_only;
    }

    /// Whether the cookie is secure (HTTPS only).
    #[must_use]
    pub const fn secure(&self) -> bool {
        return self.secure;
    }

    /// The [`SameSite`] policy.
    #[must_use]
    pub const fn same_site(&self) -> SameSite {
        return self.same_site;
    }

    /// The cookie path.
    #[must_use]
    pub fn path(&self) -> &str {
        return &self.path;
    }

    /// The cookie domain.
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        return self.domain.as_deref();
    }

    /// The cookie max age in seconds.
    #[must_use]
    pub const fn max_age(&self) -> Option<u64> {
        return self.max_age;
    }

    /// Sets the cookie name.
    #[must_use = "the returned configuration must be used"]
    pub fn with_name(mut self, name: String) -> Self {
        self.name = name;
        return self;
    }

    /// Sets whether the cookie is HTTP-only.
    #[must_use = "the returned configuration must be used"]
    pub const fn with_http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        return self;
    }

    /// Sets whether the cookie is secure (HTTPS only).
    #[must_use = "the returned configuration must be used"]
    pub const fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        return self;
    }

    /// Sets the [`SameSite`] policy.
    #[must_use = "the returned configuration must be used"]
    pub const fn with_same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        return self;
    }

    /// Sets the cookie path.
    #[must_use = "the returned configuration must be used"]
    pub fn with_path(mut self, path: String) -> Self {
        self.path = path;
        return self;
    }

    /// Sets the cookie domain.
    #[must_use = "the returned configuration must be used"]
    pub fn with_domain(mut self, domain: Option<String>) -> Self {
        self.domain = domain;
        return self;
    }

    /// Sets the cookie max age in seconds.
    #[must_use = "the returned configuration must be used"]
    pub const fn with_max_age(mut self, max_age: Option<u64>) -> Self {
        self.max_age = max_age;
        return self;
    }
}

impl Default for CookieConfig {
    fn default() -> Self {
        return Self::new();
    }
}

/// The [`SameSite`] cookie policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    /// Strict `SameSite` policy.
    Strict,
    /// Lax `SameSite` policy.
    Lax,
    /// No `SameSite` policy.
    None,
}

/// Origin validation for CSRF protection.
#[derive(Debug, Clone)]
pub struct OriginValidation {
    /// Allowed origins for cross-origin requests.
    allowed_origins: Vec<String>,
}

impl OriginValidation {
    /// Creates a new origin validator.
    #[must_use]
    pub const fn new(allowed_origins: Vec<String>) -> Self {
        return Self { allowed_origins };
    }

    /// Validates an origin header.
    #[must_use]
    pub fn validate(&self, origin: &str) -> bool {
        return self.allowed_origins.iter().any(|o| return o == origin);
    }
}

/// A password-hashing capability.
pub trait PasswordHasher: Debug + Send + Sync {
    /// Hashes a password into a PHC-encoded string.
    ///
    /// # Errors
    /// Returns `AuthError::PasswordHashError` if the password cannot be hashed.
    #[must_use = "the encoded hash must be used"]
    fn hash(&self, password: &str) -> Result<String, AuthError>;

    /// Verifies a password against a PHC-encoded hash.
    ///
    /// # Errors
    /// Returns `AuthError::PasswordHashError` if the hash is malformed.
    #[must_use = "the verification result must be used"]
    fn verify(&self, password: &str, hash: &str) -> Result<bool, AuthError>;
}
