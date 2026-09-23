//! Root auth provider component.

use std::sync::Arc;

use ::dioxus::prelude::{Element, Props, component, rsx, use_context_provider, use_signal};

use crate::auth::Auth;
use crate::error::ErrorCode;
use crate::status::{AuthStatus, SessionId};
use crate::store::{PasswordUserStore, SessionStore, UserStore};
use crate::token::MemoryTokenStorage;

use super::context::{AuthContext, AuthSignals};
use super::operations::AuthEngineHandle;
use super::storage::TokenStorageHandle;

/// Provides authentication state to the subtree.
///
/// Mount once above the router with the single [`Auth`] entry point; storage
/// and restore wiring are the provider's responsibility, so the page-one
/// budget never names a handle. The provider restores the identity from a
/// default in-memory token storage on its first render, and hands a reactive
/// [`AuthContext`] to every descendant. Mount a
/// [`Router`](dioxus_router::Router) outside (or above) it so route guards can
/// navigate.
///
/// # Examples
///
/// ```no_run
/// use dioxus::prelude::*;
/// use dioxus_auth::prelude::{AuthProvider, Auth, MemoryStore};
///
/// # #[derive(Debug, Clone, PartialEq)]
/// # struct User { id: u64, name: String }
/// # impl dioxus_auth::prelude::AuthUser for User {
/// #     type Id = u64;
/// #     fn id(&self) -> u64 { return self.id; }
/// #     fn email(&self) -> &str { return &self.name; }
/// # }
/// # fn App() -> Element {
/// #     let auth = Auth::<MemoryStore<User>>::memory().expect("memory facade constructs");
/// #     let children = rsx! { "signed in" };
/// rsx! {
///     AuthProvider { auth: auth, children: children }
/// }
/// # }
/// ```
///
/// # Panics
/// Panics when the default Argon2id hasher cannot pre-compute the
/// timing-defense dummy hash.
#[component]
pub fn AuthProvider<D>(auth: Auth<D>, children: Element) -> Element
where
    D: PasswordUserStore + SessionStore<Id = <D as UserStore>::Id> + 'static,
{
    let engine: AuthEngineHandle<D::User> = auth
        .erased_engine
        .clone()
        .unwrap_or_else(|| return AuthEngineHandle::from(Arc::clone(auth.engine())));
    let token_storage = auth
        .token_storage
        .take()
        .unwrap_or_else(|| return TokenStorageHandle::new(MemoryTokenStorage::new()));

    let status = use_signal(|| {
        return AuthStatus::<D::User>::Loading;
    });
    let token = use_signal(|| {
        return None::<SessionId>;
    });
    let token_persisted = use_signal(|| {
        return false;
    });
    let restore_unavailable = use_signal(|| {
        return None::<ErrorCode>;
    });
    let context = use_context_provider(|| {
        return AuthContext::new(
            engine,
            token_storage,
            &AuthSignals {
                status,
                token,
                token_persisted,
                restore_unavailable,
            },
        );
    });

    if context.is_loading() {
        // reason: the first render settles the identity from storage; a
        // definitive rejection demotes to guest, while an unknown outcome
        // (storage failure, rate limit, transport error) leaves the tree in
        // Loading with the failure recorded, so `session_state()` reports
        // `Unavailable` and `restart()` can be used to ask again.
        let _verdict = context.restore();
    }

    return rsx! {
        {children}
    };
}
