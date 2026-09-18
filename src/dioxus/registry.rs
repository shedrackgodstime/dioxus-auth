//! Process-wide server registry: one [`server_init`] at boot, then the
//! [`require_user`] one-liner in every `#[server]` function.
//!
//! Dioxus 0.7 provides no app-level state injection into `#[server]`
//! functions, so hand-rolled endpoints otherwise need the engine and cookie
//! config in scope at every call site. The registry closes that gap the same
//! way dioxus's own `use_context` works: state is stored type-erased and
//! downcast at the call site — the cast lives inside the crate, and app code
//! stays fully typed:
//!
//! ```ignore
//! // boot (once, e.g. in main before serving):
//! dioxus_auth::server_init(engine_arc, cookie_config_arc);
//!
//! // any #[server] function:
//! #[server]
//! pub async fn my_scores() -> Result<Vec<Score>, ServerFnError> {
//!     let user = dioxus_auth::require_user::<AppUser>()
//!         .await
//!         .map_err(|e| ServerFnError::new(e.to_string()))?;
//!     // ...
//! }
//! ```
//!
//! Login is deliberately **not** part of the registry: it needs
//! `LoginOptions` (IP/user-agent) and returns wire tokens, so it stays on
//! [`ServerAuthContext`](crate::dioxus::ServerAuthContext) where those
//! concerns are explicit.
//!
//! Requires the `dioxus-fullstack` feature.

use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use crate::engine::AuthEngine;
use crate::error::{AuthError, AuthResult};
use crate::security::CookieConfig;
use crate::storage::{SessionStore, UserStore};
use crate::user::AuthUser;

use super::server_fn::ServerAuthContext;

const REGISTRY_UNINITIALIZED: &str = "dioxus-auth server registry not initialized: call `dioxus_auth::server_init(engine, \
     cookie_config)` once at server startup before `require_user`/`current_user`/`logout_current`";
const REGISTRY_TYPE_MISMATCH: &str = "dioxus-auth registry user type mismatch: the engine registered with `server_init` stores a \
     different user type than the type parameter given to `require_user`/`current_user`";
const REGISTRY_NO_REQUEST: &str =
    "dioxus-auth server helper called outside a `#[server]` function (no request context)";

type ErasedUser = Box<dyn Any + Send + Sync>;

type ExtractFuture = Pin<Box<dyn Future<Output = AuthResult<Option<ErasedUser>>> + Send>>;

type ExtractFn =
    Arc<dyn Fn(Option<String>, Option<String>, Option<String>) -> ExtractFuture + Send + Sync>;

type LogoutFuture = Pin<Box<dyn Future<Output = AuthResult<String>> + Send>>;

type LogoutFn =
    Arc<dyn Fn(Option<String>, Option<String>, Option<String>) -> LogoutFuture + Send + Sync>;

/// The type-erased registry contents (dioxus-context-style).
struct Registry {
    extract: ExtractFn,
    logout: LogoutFn,
}

static REGISTRY: OnceLock<Registry> = OnceLock::new();

/// Initialize the process-wide server auth registry.
///
/// Call **once** at server startup, before serving requests. Subsequent calls
/// panic — the registry exists so endpoints don't need per-call wiring, and a
/// silent re-init would hide boot-order bugs.
///
/// # Panics
///
/// Panics if called more than once in the process.
pub fn server_init<U, S>(engine: Arc<AuthEngine<U, S>>, cookie_config: Arc<CookieConfig>)
where
    U: UserStore + Send + Sync + 'static,
    U::User: AuthUser + Send + Sync + 'static,
    S: SessionStore<<U::User as AuthUser>::Id> + Send + Sync + 'static,
{
    let engine_for_extract = Arc::clone(&engine);
    let cookie_for_extract = Arc::clone(&cookie_config);
    let extract: ExtractFn = Arc::new(move |cookie, origin, authorization| {
        // Clone per call — the closure must stay `Fn`, and the async block owns
        // its handles for the duration of the request.
        let engine = Arc::clone(&engine_for_extract);
        let cookie_config = Arc::clone(&cookie_for_extract);
        Box::pin(async move {
            let ctx = ServerAuthContext::new(&engine, &cookie_config);
            let user = ctx
                .current_user(
                    cookie.as_deref(),
                    origin.as_deref(),
                    authorization.as_deref(),
                )
                .await?;
            Ok(user.map(|u| Box::new(u) as ErasedUser))
        })
    });

    let engine_for_logout = Arc::clone(&engine);
    let cookie_for_logout = Arc::clone(&cookie_config);
    let logout: LogoutFn = Arc::new(move |cookie, origin, authorization| {
        let engine = Arc::clone(&engine_for_logout);
        let cookie_config = Arc::clone(&cookie_for_logout);
        Box::pin(async move {
            logout_with_headers(
                &engine,
                &cookie_config,
                cookie.as_deref(),
                origin.as_deref(),
                authorization.as_deref(),
            )
            .await
        })
    });

    if REGISTRY.set(Registry { extract, logout }).is_err() {
        panic!(
            "dioxus_auth::server_init called twice: the registry must be initialized exactly once"
        );
    }
}

/// Resolve the authenticated user from the incoming request, if any.
///
/// Soft variant: returns `Ok(None)` when no session credential is presented or
/// the credential is invalid/expired. Use [`require_user`] when absence is an
/// error.
///
/// # Panics
///
/// - if [`server_init`] was not called at startup
/// - if called outside a `#[server]` function (no request context)
/// - if the registry was initialized with an engine whose user type differs
///   from `U` — a programmer error caught at the first call
pub async fn current_user<U>() -> AuthResult<Option<U>>
where
    U: AuthUser + Send + Sync + 'static,
{
    let (cookie, origin, authorization) = request_headers();
    current_user_from_headers(
        cookie.as_deref(),
        origin.as_deref(),
        authorization.as_deref(),
    )
    .await
}

/// Require an authenticated user from the incoming request.
///
/// Hard variant of [`current_user`]: maps a missing/invalid session to
/// [`AuthError::Unauthenticated`] (a session-state problem — login rejections
/// use [`AuthError::InvalidCredentials`]).
///
/// # Panics
///
/// - if [`server_init`] was not called at startup
/// - if called outside a `#[server]` function (no request context)
/// - if the registry was initialized with an engine whose user type differs
///   from `U` — a programmer error caught at the first call
pub async fn require_user<U>() -> AuthResult<U>
where
    U: AuthUser + Send + Sync + 'static,
{
    current_user::<U>().await?.ok_or(AuthError::Unauthenticated)
}

/// Revoke the request's session and return the `Set-Cookie` header that
/// clears the browser cookie.
///
/// Idempotent: with no session credential present, returns the clear-cookie
/// header without touching the store.
///
/// # Panics
///
/// - if [`server_init`] was not called at startup
/// - if called outside a `#[server]` function (no request context)
pub async fn logout_current() -> AuthResult<String> {
    let (cookie, origin, authorization) = request_headers();
    logout_from_headers(
        cookie.as_deref(),
        origin.as_deref(),
        authorization.as_deref(),
    )
    .await
}

/// Header-explicit core of [`current_user`] — the unit-testable seam.
async fn current_user_from_headers<U>(
    cookie: Option<&str>,
    origin: Option<&str>,
    authorization: Option<&str>,
) -> AuthResult<Option<U>>
where
    U: AuthUser + Send + Sync + 'static,
{
    let registry = REGISTRY.get().expect(REGISTRY_UNINITIALIZED);
    let erased = (registry.extract)(
        cookie.map(str::to_string),
        origin.map(str::to_string),
        authorization.map(str::to_string),
    )
    .await?;
    Ok(erased.map(|boxed| downcast_user::<U>(boxed)))
}

/// Header-explicit logout used by the registry closure — the unit-testable
/// seam.
///
/// Credential precedence matches validation (spec 14/15): bearer first, then
/// cookie. Origin/CSRF applies ONLY to cookie credentials (spec 15 §1.2), and
/// logout is state-changing — so a cookie logout with a mismatched Origin is
/// rejected and the session stays alive. No credential at all → idempotent
/// clear-cookie header.
async fn logout_with_headers<U, S>(
    engine: &Arc<AuthEngine<U, S>>,
    cookie_config: &Arc<CookieConfig>,
    cookie: Option<&str>,
    origin: Option<&str>,
    authorization: Option<&str>,
) -> AuthResult<String>
where
    U: UserStore + Send + Sync + 'static,
    U::User: AuthUser + Send + Sync + 'static,
    S: SessionStore<<U::User as AuthUser>::Id> + Send + Sync + 'static,
{
    let ctx = ServerAuthContext::new(engine, cookie_config);
    // Bearer wins ONLY when an Authorization header is actually present —
    // identical to `ServerAuthContext::logout_current`. Without this guard the
    // extractor would classify the cookie value itself as a token and skip the
    // Origin check below.
    let bearer = authorization.and_then(|auth| {
        crate::transport::extract_session_token(
            Some(auth),
            cookie,
            cookie_config.name.as_str(),
            cookie_config.host_only,
        )
    });
    if let Some(token) = bearer {
        return ctx.logout(&crate::session::SessionId::new(token)).await;
    }
    let cookie_id = cookie.and_then(|c| cookie_config.extract_session_id(c));
    if let Some(id) = cookie_id {
        cookie_config.validate_cookie_origin(origin)?;
        return ctx.logout(&id).await;
    }
    Ok(ctx.build_delete_cookie_header())
}

/// Header-explicit core of [`logout_current`] — the unit-testable seam.
///
/// Credential precedence matches validation (bearer first), and cookie
/// credentials are Origin/CSRF-checked (spec 15) before the session is
/// revoked; a rejected logout leaves the session alive.
async fn logout_from_headers(
    cookie: Option<&str>,
    origin: Option<&str>,
    authorization: Option<&str>,
) -> AuthResult<String> {
    let registry = REGISTRY.get().expect(REGISTRY_UNINITIALIZED);
    (registry.logout)(
        cookie.map(str::to_string),
        origin.map(str::to_string),
        authorization.map(str::to_string),
    )
    .await
}

/// Downcast with a message that names the mistake instead of the type IDs.
fn downcast_user<U: 'static>(boxed: ErasedUser) -> U {
    let actual = (*boxed).type_id();
    match boxed.downcast::<U>() {
        Ok(user) => *user,
        Err(_) => panic!("{REGISTRY_TYPE_MISMATCH} (actual: {actual:?})"),
    }
}

/// Gather `Cookie` / `Origin` / `Authorization` from the current request.
///
/// # Panics
///
/// Panics when no request context exists (not inside a `#[server]` function).
fn request_headers() -> (Option<String>, Option<String>, Option<String>) {
    use dioxus::fullstack::FullstackContext;

    let ctx = FullstackContext::current().expect(REGISTRY_NO_REQUEST);
    let parts = ctx.parts_mut();
    let header = |name: http::header::HeaderName| {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    (
        header(http::header::COOKIE),
        header(http::header::ORIGIN),
        header(http::header::AUTHORIZATION),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{Argon2Hasher, PasswordHasher};
    use crate::storage::MemoryStore;
    use std::time::Duration;
    use tokio::sync::Mutex as AsyncMutex;

    type RegEngine = AuthEngine<MemoryStore<RegUser>, MemoryStore<RegUser>>;

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct RegUser {
        id: u64,
        email: String,
        auth_hash: Option<String>,
    }

    impl AuthUser for RegUser {
        type Id = u64;

        fn id(&self) -> Self::Id {
            self.id
        }

        fn session_auth_hash(&self) -> Option<&str> {
            self.auth_hash.as_deref()
        }
    }

    /// All registry tests share one process-global `OnceLock`, so they
    /// serialize on this mutex and share one initialization.
    static TEST_LOCK: AsyncMutex<()> = AsyncMutex::const_new(());

    /// One shared store for the whole test process: sessions live in the
    /// store, so logins and registry validation must hit the same instance.
    fn shared_store() -> Arc<MemoryStore<RegUser>> {
        static STORE: OnceLock<Arc<MemoryStore<RegUser>>> = OnceLock::new();
        STORE
            .get_or_init(|| {
                let store = Arc::new(MemoryStore::<RegUser>::new());
                let pass_hash = Argon2Hasher::new().hash_password("registry_pw").unwrap();
                store.insert_user_with_password(
                    RegUser {
                        id: 42,
                        email: "reg@example.com".into(),
                        auth_hash: Some(pass_hash.clone()),
                    },
                    "reg@example.com",
                    &pass_hash,
                );
                store
            })
            .clone()
    }

    fn test_engine_and_cookie() -> (Arc<RegEngine>, Arc<CookieConfig>, Arc<MemoryStore<RegUser>>) {
        let store = shared_store();
        let engine = Arc::new(
            AuthEngine::builder(store.clone(), store.clone())
                .session_ttl(Duration::from_secs(3600))
                .build(),
        );
        let cookie = Arc::new(CookieConfig {
            name: "reg_test_sess".into(),
            ..Default::default()
        });
        (engine, cookie, store)
    }

    /// Initialize the global registry exactly once for the test process.
    fn ensure_registry() {
        static INIT: OnceLock<()> = OnceLock::new();
        INIT.get_or_init(|| {
            let (engine, cookie, _store) = test_engine_and_cookie();
            server_init(engine, cookie);
        });
    }

    /// Log a user in through the normal `ServerAuthContext` flow and return
    /// the raw `Cookie` header value to present on subsequent requests.
    async fn login_cookie_header() -> String {
        let (engine, cookie, _store) = test_engine_and_cookie();
        let ctx = ServerAuthContext::new(&engine, &cookie);
        let (_user, set_cookie) = ctx.login("reg@example.com", "registry_pw").await.unwrap();
        set_cookie
    }

    #[tokio::test(flavor = "current_thread")]
    async fn require_user_resolves_the_typed_user_from_a_cookie() {
        let _guard = TEST_LOCK.lock().await;
        ensure_registry();

        let cookie = login_cookie_header().await;
        let user = current_user_from_headers::<RegUser>(Some(&cookie), None, None)
            .await
            .unwrap()
            .expect("session from login must authenticate");
        assert_eq!(user.id, 42);
        assert_eq!(user.email, "reg@example.com");

        let user2 = current_user_from_headers::<RegUser>(Some(&cookie), None, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user, user2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn missing_session_is_unauthenticated_not_none() {
        let _guard = TEST_LOCK.lock().await;
        ensure_registry();

        let err = current_user_from_headers::<RegUser>(None, None, None)
            .await
            .unwrap();
        assert_eq!(err, None);

        let err = require_user_from_headers_for_test::<RegUser>(None, None, None)
            .await
            .unwrap_err();
        assert_eq!(err, AuthError::Unauthenticated);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn logout_revokes_the_session_and_clears_the_cookie() {
        let _guard = TEST_LOCK.lock().await;
        ensure_registry();

        let cookie = login_cookie_header().await;
        let clear = logout_from_headers(Some(&cookie), None, None)
            .await
            .unwrap();
        assert!(
            clear.contains("reg_test_sess"),
            "must clear the cookie: {clear}"
        );

        let after = current_user_from_headers::<RegUser>(Some(&cookie), None, None)
            .await
            .unwrap();
        assert_eq!(after, None, "session must be revoked");
    }

    // The registry is a process-global OnceLock with one cookie config, so the
    // Origin/CSRF tests below exercise `logout_with_headers` directly with a
    // config that has `expected_origins` set — same code path the closure runs.

    #[tokio::test(flavor = "current_thread")]
    async fn cookie_logout_with_mismatched_origin_is_rejected_and_session_survives() {
        let (_engine, cookie, store) = test_engine_and_cookie();
        let cookie_config = Arc::new(CookieConfig {
            name: "reg_test_sess".into(),
            expected_origins: Some(vec!["https://app.example.com".into()]),
            ..Default::default()
        });

        // Log in through a matching-origin context to get a live session.
        let ctx = ServerAuthContext::new(&_engine, &cookie);
        let (_user, set_cookie) = ctx.login("reg@example.com", "registry_pw").await.unwrap();
        let raw = set_cookie
            .split(';')
            .next()
            .unwrap()
            .split("reg_test_sess=")
            .nth(1)
            .unwrap()
            .to_string();

        // Mismatched Origin → CSRF rejection, session must still authenticate.
        let err = logout_with_headers(
            &_engine,
            &cookie_config,
            Some(&format!("reg_test_sess={raw}")),
            Some("https://evil.example.com"),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(err, AuthError::Csrf);

        let alive = store
            .find_session(&crate::session::SessionId::new(raw.clone()).hash_for_storage())
            .await
            .unwrap();
        assert!(
            alive.is_some(),
            "rejected logout must not revoke the session"
        );

        // Matching Origin → revokes.
        logout_with_headers(
            &_engine,
            &cookie_config,
            Some(&format!("reg_test_sess={raw}")),
            Some("https://app.example.com"),
            None,
        )
        .await
        .unwrap();
        let gone = store
            .find_session(&crate::session::SessionId::new(raw).hash_for_storage())
            .await
            .unwrap();
        assert!(gone.is_none(), "matching-origin logout must revoke");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bearer_logout_skips_origin_validation() {
        let (engine, _cookie, _store) = test_engine_and_cookie();
        let cookie_config = Arc::new(CookieConfig {
            name: "reg_test_sess".into(),
            expected_origins: Some(vec!["https://app.example.com".into()]),
            ..Default::default()
        });

        let ctx = ServerAuthContext::new(&engine, &cookie_config);
        let (_user, token) = ctx
            .login_bearer("reg@example.com", "registry_pw")
            .await
            .unwrap();

        // Arbitrary/absent Origin is irrelevant for bearer credentials.
        logout_with_headers(
            &engine,
            &cookie_config,
            None,
            Some("https://evil.example.com"),
            Some(&format!("Bearer {token}")),
        )
        .await
        .unwrap();

        let (_e, _c, store) = test_engine_and_cookie();
        let gone = store
            .find_session(&crate::session::SessionId::new(token).hash_for_storage())
            .await
            .unwrap();
        assert!(gone.is_none(), "bearer session must be revoked");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn logout_without_credentials_is_idempotent() {
        let (_engine, _cookie, _store) = test_engine_and_cookie();
        let cookie_config = Arc::new(CookieConfig {
            name: "reg_test_sess".into(),
            expected_origins: Some(vec!["https://app.example.com".into()]),
            ..Default::default()
        });

        // No cookie, no bearer: no Origin requirement may apply.
        let clear = logout_with_headers(
            &_engine,
            &cookie_config,
            None,
            Some("https://evil.example.com"),
            None,
        )
        .await
        .unwrap();
        assert!(
            clear.contains("reg_test_sess"),
            "no-credential logout still clears the cookie: {clear}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn double_init_panics_with_a_clear_message() {
        let _guard = TEST_LOCK.lock().await;
        ensure_registry();

        let (engine, cookie, _store) = test_engine_and_cookie();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            server_init(engine, cookie);
        }));
        let err = result.unwrap_err();
        let msg = err
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().copied().map(str::to_string))
            .unwrap_or_default();
        assert!(
            msg.contains("exactly once"),
            "panic message must name the mistake: {msg}"
        );
    }

    #[test]
    fn type_mismatch_downcast_panics_with_a_clear_message() {
        #[derive(Debug)]
        struct OtherUser;
        let boxed: ErasedUser = Box::new(OtherUser);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            downcast_user::<RegUser>(boxed)
        }));
        let err = result.unwrap_err();
        let msg = err
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().copied().map(str::to_string))
            .unwrap_or_default();
        assert!(
            msg.contains("user type mismatch"),
            "panic message must name the mistake: {msg}"
        );
    }

    /// Test-only hard variant over the header-explicit seam, mirroring
    /// [`require_user`] exactly.
    async fn require_user_from_headers_for_test<U>(
        cookie: Option<&str>,
        origin: Option<&str>,
        authorization: Option<&str>,
    ) -> AuthResult<U>
    where
        U: AuthUser + Send + Sync + 'static,
    {
        current_user_from_headers(cookie, origin, authorization)
            .await?
            .ok_or(AuthError::Unauthenticated)
    }
}
