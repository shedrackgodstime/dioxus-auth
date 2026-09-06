use crate::engine::AuthEngine;
use crate::error::{AuthError, AuthResult};
use crate::security::{CookieConfig, OriginValidation};
use crate::session::SessionId;
use crate::storage::{PasswordUserStore, SessionStore, UserStore};
use crate::user::AuthUser;

/// Server-side authentication helper for `#[server]` functions and Axum handlers.
///
/// Reads session IDs from cookies or bearer tokens, authenticates requests,
/// and produces `Set-Cookie` headers.
pub struct ServerAuthContext<'a, U, S>
where
    U: UserStore,
    S: SessionStore<<U::User as AuthUser>::Id>,
{
    engine: &'a AuthEngine<U, S>,
    cookie_config: &'a CookieConfig,
    cookie_header: Option<String>,
    origin_header: Option<String>,
    authorization_header: Option<String>,
}

impl<'a, U, S> ServerAuthContext<'a, U, S>
where
    U: UserStore,
    S: SessionStore<<U::User as AuthUser>::Id>,
{
    /// Create a new `ServerAuthContext` bound to the given [`AuthEngine`] and [`CookieConfig`].
    pub fn new(engine: &'a AuthEngine<U, S>, cookie_config: &'a CookieConfig) -> Self {
        Self {
            engine,
            cookie_config,
            cookie_header: None,
            origin_header: None,
            authorization_header: None,
        }
    }

    /// Create a `ServerAuthContext` from the current Dioxus fullstack request.
    ///
    /// Automatically extracts `Cookie`, `Origin`, and `Authorization` headers from the incoming
    /// request. Returns `None` if called outside a `#[server]` function context.
    #[cfg(feature = "dioxus-fullstack")]
    pub fn from_request(
        engine: &'a AuthEngine<U, S>,
        cookie_config: &'a CookieConfig,
    ) -> Option<Self> {
        use dioxus::fullstack::FullstackContext;
        let ctx = FullstackContext::current()?;
        let parts = ctx.parts_mut();
        let cookie_header = parts
            .headers
            .get(http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let origin_header = parts
            .headers
            .get(http::header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let authorization_header = parts
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        Some(Self {
            engine,
            cookie_config,
            cookie_header,
            origin_header,
            authorization_header,
        })
    }

    /// Access the underlying [`AuthEngine`].
    pub fn engine(&self) -> &AuthEngine<U, S> {
        self.engine
    }

    /// Access the configured [`CookieConfig`].
    pub fn cookie_config(&self) -> &CookieConfig {
        self.cookie_config
    }

    /// Raw `Cookie` header, if present.
    pub fn cookie_header(&self) -> Option<&str> {
        self.cookie_header.as_deref()
    }

    /// Raw `Origin` header, if present.
    pub fn origin_header(&self) -> Option<&str> {
        self.origin_header.as_deref()
    }

    /// Raw `Authorization` header, if present.
    pub fn authorization_header(&self) -> Option<&str> {
        self.authorization_header.as_deref()
    }

    /// Extract a [`SessionId`] from the stored `Cookie` header.
    pub fn session_id(&self) -> Option<SessionId> {
        self.cookie_header
            .as_deref()
            .and_then(|h| self.cookie_config.extract_session_id(h))
    }

    /// Extract a [`SessionId`] from an HTTP `Cookie` header string.
    pub fn extract_session_id(&self, cookie_header: Option<&str>) -> Option<SessionId> {
        let header = cookie_header.or(self.cookie_header.as_deref())?;
        self.cookie_config.extract_session_id(header)
    }

    /// Authenticate the request from cookie and/or bearer token.
    ///
    /// Bearer takes precedence over cookies. CSRF/Origin checks apply only to
    /// cookie credentials. Falls back to stored request headers when arguments
    /// are `None`.
    #[must_use = "use the authenticated user or handle the error"]
    pub async fn current_user(
        &self,
        cookie_header: Option<&str>,
        origin_header: Option<&str>,
        authorization_header: Option<&str>,
    ) -> AuthResult<Option<U::User>> {
        let cookie_header = cookie_header.or(self.cookie_header.as_deref());
        let origin_header = origin_header.or(self.origin_header.as_deref());
        let authorization_header = authorization_header.or(self.authorization_header.as_deref());

        let session_id = if let Some(auth_header) = authorization_header {
            if let Some(token) = crate::transport::extract_session_token(
                Some(auth_header),
                cookie_header,
                self.cookie_config.name.as_str(),
            ) {
                SessionId::new(token)
            } else {
                return Ok(None);
            }
        } else if let Some(cookie) = cookie_header {
            match self.cookie_config.extract_session_id(cookie) {
                Some(id) => id,
                None => return Ok(None),
            }
        } else {
            return Ok(None);
        };

        let origin_validation = self.cookie_config.validate_origin(origin_header);
        if matches!(origin_validation, OriginValidation::Mismatch { .. }) {
            return Err(AuthError::Csrf);
        }

        self.engine.validate_session(&session_id).await
    }

    /// Authenticate using the headers stored by [`from_request`](Self::from_request).
    ///
    /// Requires the `dioxus-fullstack` feature.
    #[cfg(feature = "dioxus-fullstack")]
    pub async fn current_user_from_request(&self) -> AuthResult<Option<U::User>> {
        self.current_user(
            self.cookie_header.as_deref(),
            self.origin_header.as_deref(),
            self.authorization_header.as_deref(),
        )
        .await
    }

    /// Require an authenticated user from the incoming request.
    ///
    /// Returns `Ok(user)` on success, or `Err(AuthError::Unauthenticated)`
    /// if the session is missing, expired, or invalid.
    ///
    /// Falls back to the stored request headers if the explicit arguments are `None`.
    pub async fn require_user(
        &self,
        cookie_header: Option<&str>,
        origin_header: Option<&str>,
        authorization_header: Option<&str>,
    ) -> AuthResult<U::User> {
        self.current_user(cookie_header, origin_header, authorization_header)
            .await?
            .ok_or(AuthError::Unauthenticated)
    }

    /// Require an authenticated user using the headers stored by [`from_request`](Self::from_request).
    ///
    /// Requires the `dioxus-fullstack` feature.
    #[cfg(feature = "dioxus-fullstack")]
    pub async fn require_user_from_request(&self) -> AuthResult<U::User> {
        self.current_user_from_request()
            .await?
            .ok_or(AuthError::Unauthenticated)
    }

    /// Invalidate the active session (logout) and return the `Set-Cookie` header value to clear the cookie.
    pub async fn logout(&self, session_id: &SessionId) -> AuthResult<String> {
        self.engine.logout(session_id).await?;
        Ok(self.cookie_config.build_delete_cookie_header())
    }

    /// Generate the `Set-Cookie` header value to clear a session cookie.
    pub fn build_delete_cookie_header(&self) -> String {
        self.cookie_config.build_delete_cookie_header()
    }

    /// Generate the `Set-Cookie` header value to establish a session cookie.
    pub fn build_set_cookie_header(&self, session_id: &SessionId) -> String {
        self.cookie_config.build_set_cookie_header(session_id)
    }
}

impl<'a, U, S> ServerAuthContext<'a, U, S>
where
    U: PasswordUserStore,
    S: SessionStore<<U::User as AuthUser>::Id>,
{
    /// Authenticate credentials, create a new session in storage, and return
    /// the authenticated user along with the `Set-Cookie` HTTP header value.
    #[must_use = "the login result must be used to set the session cookie"]
    pub async fn login(&self, identifier: &str, password: &str) -> AuthResult<(U::User, String)> {
        let (user, session) = self.engine.login(identifier, password).await?;
        let set_cookie_header = self.cookie_config.build_set_cookie_header(session.id());
        Ok((user, set_cookie_header))
    }

    /// Authenticate credentials, create a new session, automatically set the session
    /// cookie on the response, and return the authenticated user along with the raw
    /// session token for client-side persistence.
    ///
    /// Requires the `dioxus-fullstack` feature.
    #[cfg(feature = "dioxus-fullstack")]
    pub async fn login_and_set_cookie(
        &self,
        identifier: &str,
        password: &str,
    ) -> AuthResult<(U::User, String)> {
        let (user, session) = self.engine.login(identifier, password).await?;
        let cookie_header = self.cookie_config.build_set_cookie_header(session.id());
        if let Some(ctx) = dioxus::fullstack::FullstackContext::current() {
            let value = http::HeaderValue::from_str(&cookie_header)
                .map_err(|e| AuthError::Store(format!("invalid cookie header: {e}")))?;
            ctx.add_response_header(http::header::SET_COOKIE, value);
        }
        Ok((user, session.id().as_str().to_string()))
    }

    /// Invalidate the active session and automatically clear the session cookie on the response.
    ///
    /// Requires the `dioxus-fullstack` feature.
    #[cfg(feature = "dioxus-fullstack")]
    pub async fn logout_and_clear_cookie(&self, session_id: &SessionId) -> AuthResult<()> {
        self.logout(session_id).await?;
        let cookie_header = self.cookie_config.build_delete_cookie_header();
        if let Some(ctx) = dioxus::fullstack::FullstackContext::current() {
            let value = http::HeaderValue::from_str(&cookie_header)
                .map_err(|e| AuthError::Store(format!("invalid cookie header: {e}")))?;
            ctx.add_response_header(http::header::SET_COOKIE, value);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::security::Argon2Hasher;
    use crate::security::PasswordHasher;
    use crate::storage::MemoryStore;

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct MockUser {
        id: u64,
        email: String,
        auth_hash: Option<String>,
    }

    impl AuthUser for MockUser {
        type Id = u64;
        fn id(&self) -> Self::Id {
            self.id
        }
        fn session_auth_hash(&self) -> Option<&str> {
            self.auth_hash.as_deref()
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn server_auth_context_login_and_cookie_flow() {
        let store = Arc::new(MemoryStore::<MockUser>::new());
        let hasher = Argon2Hasher::new();
        let pass = "hunter2_secure";
        let pass_hash = hasher.hash_password(pass).unwrap();

        let user = MockUser {
            id: 1,
            email: "bob@example.com".into(),
            auth_hash: Some(pass_hash.clone()),
        };
        store.insert_user_with_password(user.clone(), "bob@example.com", &pass_hash);

        let engine = AuthEngine::builder(store.clone(), store.clone())
            .session_ttl(Duration::from_secs(3600))
            .build();

        let cookie_config = CookieConfig {
            name: "test_sess".into(),
            ..Default::default()
        };

        let server_ctx = ServerAuthContext::new(&engine, &cookie_config);

        // 1. Login generates user and Set-Cookie header
        let (authed_user, set_cookie) = server_ctx.login("bob@example.com", pass).await.unwrap();
        assert_eq!(authed_user, user);
        assert!(set_cookie.contains("test_sess="));
        assert!(set_cookie.contains("HttpOnly"));

        // 2. Extract session and authenticate request
        let incoming_cookie_header = format!("foo=bar; {set_cookie}; baz=qux");
        let current = server_ctx
            .current_user(Some(&incoming_cookie_header), None, None)
            .await
            .unwrap();
        assert_eq!(current, Some(user.clone()));

        // 3. Require user succeeds
        let required = server_ctx
            .require_user(Some(&incoming_cookie_header), None, None)
            .await
            .unwrap();
        assert_eq!(required, user);

        // 4. Require user fails on empty/invalid cookie
        let err = server_ctx.require_user(Some("foo=bar"), None, None).await;
        assert_eq!(err.unwrap_err(), AuthError::Unauthenticated);

        // 5. Logout revokes session and generates delete cookie header
        let session_id = server_ctx
            .extract_session_id(Some(&incoming_cookie_header))
            .unwrap();
        let delete_cookie = server_ctx.logout(&session_id).await.unwrap();
        assert!(delete_cookie.contains("Max-Age=0"));

        // 6. Validating now returns None
        let after_logout = server_ctx
            .current_user(Some(&incoming_cookie_header), None, None)
            .await
            .unwrap();
        assert_eq!(after_logout, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn server_auth_context_rejects_mismatched_origin() {
        let store = Arc::new(MemoryStore::<MockUser>::new());
        let hasher = Argon2Hasher::new();
        let pass = "hunter2_secure";
        let pass_hash = hasher.hash_password(pass).unwrap();

        let user = MockUser {
            id: 1,
            email: "bob@example.com".into(),
            auth_hash: Some(pass_hash.clone()),
        };
        store.insert_user_with_password(user.clone(), "bob@example.com", &pass_hash);

        let engine = AuthEngine::builder(store.clone(), store.clone())
            .session_ttl(Duration::from_secs(3600))
            .build();

        let cookie_config = CookieConfig {
            name: "test_sess".into(),
            expected_origins: Some(vec!["https://app.example.com".into()]),
            ..Default::default()
        };

        let server_ctx = ServerAuthContext::new(&engine, &cookie_config);

        // Login to get a valid session
        let (_, set_cookie) = server_ctx.login("bob@example.com", pass).await.unwrap();
        let incoming_cookie_header = format!("foo=bar; {set_cookie}");

        // Mismatched Origin should be rejected with Csrf error
        let err = server_ctx
            .current_user(
                Some(&incoming_cookie_header),
                Some("https://evil.example.com"),
                None,
            )
            .await;
        assert_eq!(err.unwrap_err(), AuthError::Csrf);

        // Missing Origin should be allowed (browsers omit it for same-origin GETs)
        let ok = server_ctx
            .current_user(Some(&incoming_cookie_header), None, None)
            .await
            .unwrap();
        assert_eq!(ok, Some(user.clone()));

        // Matching Origin should be allowed
        let ok2 = server_ctx
            .current_user(
                Some(&incoming_cookie_header),
                Some("https://app.example.com"),
                None,
            )
            .await
            .unwrap();
        assert_eq!(ok2, Some(user));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn server_auth_context_authenticates_bearer_token() {
        let store = Arc::new(MemoryStore::<MockUser>::new());
        let hasher = Argon2Hasher::new();
        let pass = "bearer_test_pass";
        let pass_hash = hasher.hash_password(pass).unwrap();

        let user = MockUser {
            id: 1,
            email: "bearer@example.com".into(),
            auth_hash: Some(pass_hash.clone()),
        };
        store.insert_user_with_password(user.clone(), "bearer@example.com", &pass_hash);

        let engine = AuthEngine::builder(store.clone(), store.clone())
            .session_ttl(Duration::from_secs(3600))
            .build();

        let cookie_config = CookieConfig {
            name: "test_sess".into(),
            ..Default::default()
        };

        let server_ctx = ServerAuthContext::new(&engine, &cookie_config);

        // Login to get a valid session
        let (_, session) = engine.login("bearer@example.com", pass).await.unwrap();
        let raw_token = session.id().as_str();

        // Authenticate via Authorization: Bearer header
        let auth_header = format!("Bearer {raw_token}");
        let current = server_ctx
            .current_user(None, None, Some(&auth_header))
            .await
            .unwrap();
        assert_eq!(current, Some(user.clone()));

        // Bearer wins over cookie when both are present
        let cookie_header = "dioxus_session=wrong_token; other=val".to_string();
        let current_both = server_ctx
            .current_user(Some(&cookie_header), None, Some(&auth_header))
            .await
            .unwrap();
        assert_eq!(current_both, Some(user));

        // Invalid bearer token returns None
        let bad_auth = server_ctx
            .current_user(None, None, Some("Bearer invalid_token"))
            .await
            .unwrap();
        assert_eq!(bad_auth, None);
    }
}
