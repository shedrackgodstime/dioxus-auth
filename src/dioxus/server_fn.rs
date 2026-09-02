use crate::engine::AuthEngine;
use crate::error::{AuthError, AuthResult};
use crate::security::CookieConfig;
use crate::session::SessionId;
use crate::storage::{PasswordUserStore, SessionStore, UserStore};
use crate::user::AuthUser;

/// Server-side authentication helper for Dioxus `#[server]` functions and Axum request handlers.
///
/// Encapsulates reading session IDs from cookies, authenticating incoming requests,
/// and generating `Set-Cookie` headers for session creation and revocation.
pub struct ServerAuthContext<'a, U, S>
where
    U: UserStore,
    S: SessionStore<<U::User as AuthUser>::Id>,
{
    engine: &'a AuthEngine<U, S>,
    cookie_config: &'a CookieConfig,
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
        }
    }

    /// Access the underlying [`AuthEngine`].
    pub fn engine(&self) -> &AuthEngine<U, S> {
        self.engine
    }

    /// Access the configured [`CookieConfig`].
    pub fn cookie_config(&self) -> &CookieConfig {
        self.cookie_config
    }

    /// Extract a [`SessionId`] from an incoming HTTP `Cookie` header string.
    pub fn extract_session_id(&self, cookie_header: Option<&str>) -> Option<SessionId> {
        let header = cookie_header?;
        self.cookie_config.extract_session_id(header)
    }

    /// Authenticate the incoming request by checking its cookie header.
    ///
    /// Returns `Ok(Some(user))` if a valid, unexpired session is present,
    /// or `Ok(None)` if no session cookie exists or the session has expired/been revoked.
    pub async fn current_user(&self, cookie_header: Option<&str>) -> AuthResult<Option<U::User>> {
        let session_id = match self.extract_session_id(cookie_header) {
            Some(id) => id,
            None => return Ok(None),
        };

        self.engine.validate_session(&session_id).await
    }

    /// Require an authenticated user from the incoming request.
    ///
    /// Returns `Ok(user)` on success, or `Err(AuthError::Unauthenticated)`
    /// if the session is missing, expired, or invalid.
    pub async fn require_user(&self, cookie_header: Option<&str>) -> AuthResult<U::User> {
        self.current_user(cookie_header)
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
    pub async fn login(&self, identifier: &str, password: &str) -> AuthResult<(U::User, String)> {
        let (user, session) = self.engine.login(identifier, password).await?;
        let set_cookie_header = self.cookie_config.build_set_cookie_header(session.id());
        Ok((user, set_cookie_header))
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
            .current_user(Some(&incoming_cookie_header))
            .await
            .unwrap();
        assert_eq!(current, Some(user.clone()));

        // 3. Require user succeeds
        let required = server_ctx
            .require_user(Some(&incoming_cookie_header))
            .await
            .unwrap();
        assert_eq!(required, user);

        // 4. Require user fails on empty/invalid cookie
        let err = server_ctx.require_user(Some("foo=bar")).await;
        assert_eq!(err.unwrap_err(), AuthError::Unauthenticated);

        // 5. Logout revokes session and generates delete cookie header
        let session_id = server_ctx
            .extract_session_id(Some(&incoming_cookie_header))
            .unwrap();
        let delete_cookie = server_ctx.logout(&session_id).await.unwrap();
        assert!(delete_cookie.contains("Max-Age=0"));

        // 6. Validating now returns None
        let after_logout = server_ctx
            .current_user(Some(&incoming_cookie_header))
            .await
            .unwrap();
        assert_eq!(after_logout, None);
    }
}
