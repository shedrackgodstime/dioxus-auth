//! Builder for authentication engine.

use crate::error::AuthError;
use std::fmt::Debug;

/// Builder for authentication configuration.
#[derive(Debug, Default)]
pub struct AuthEngineBuilder {
    cookie_config: Option<CookieConfig>,
}

/// Cookie configuration for the builder.
#[derive(Debug, Clone)]
pub struct CookieConfig {
    /// The cookie name.
    pub name: String,
    /// Whether the cookie is HTTP-only.
    pub http_only: bool,
}

impl AuthEngineBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new() -> Self {
        AuthEngineBuilder {
            cookie_config: None,
        }
    }
    /// Sets the cookie configuration.
    pub fn cookie_config(mut self, config: CookieConfig) -> Self {
        self.cookie_config = Some(config);
        self
    }
    /// Builds the authentication engine.
    pub fn build(self) -> Result<(), AuthError> {
        Ok(())
    }
}
