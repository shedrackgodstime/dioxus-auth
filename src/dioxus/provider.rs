//! Root auth provider component.

use ::dioxus::prelude::{Element, Props, rsx, use_context_provider, use_signal};

use crate::status::{AuthStatus, SessionId};
use crate::user::AuthUser;

use super::context::AuthContext;
use super::operations::AuthEngineHandle;
use super::storage::TokenStorageHandle;

/// Props for [`AuthProvider`].
#[derive(Clone, Props)]
pub struct AuthProviderProps<T: AuthUser + Clone> {
    /// Type-erased authentication engine supplied by the application.
    pub engine: AuthEngineHandle<T>,
    /// Client token storage consumed on mount and on login/logout.
    pub token_storage: TokenStorageHandle,
    /// Application tree rendered below the auth context.
    pub children: Element,
}

impl<T: AuthUser + Clone> PartialEq for AuthProviderProps<T> {
    fn eq(&self, other: &Self) -> bool {
        let engine_agrees = self.engine == other.engine;
        let storage_agrees = self.token_storage == other.token_storage;
        let children_agree = self.children == other.children;
        return engine_agrees && storage_agrees && children_agree;
    }
}

/// Provides authentication state to the subtree.
///
/// The provider restores the identity from the token storage on its first
/// render, and hands a reactive [`AuthContext`] to every descendant. Mount a
/// [`Router`](dioxus_router::Router) outside (or above) it so route guards can
/// navigate.
#[allow(non_snake_case)]
// reason: dioxus components follow PascalCase naming, which the
// `non_snake_case` lint otherwise rejects.
// reason: clippy's `missing_errors_doc` cannot apply to `Element`, which is not
// a `Result`; the attributes the lint inspects are only reachable through the
// component machinery, so it is masked here.
#[allow(clippy::missing_errors_doc)]
pub fn AuthProvider<T>(props: AuthProviderProps<T>) -> Element
where
    T: AuthUser + Clone,
{
    let AuthProviderProps {
        engine,
        token_storage,
        children,
    } = props;

    let status = use_signal(|| {
        return AuthStatus::<T>::Loading;
    });
    let token = use_signal(|| {
        return None::<SessionId>;
    });
    let token_persisted = use_signal(|| {
        return false;
    });
    let context = use_context_provider(|| {
        return AuthContext::new(engine, token_storage, status, token, token_persisted);
    });

    if context.is_loading() {
        // First render: settle the identity from storage. A storage failure is
        // demoted to guest so the rest of the tree always sees a defined state.
        match context.restore() {
            Ok(()) => {}
            Err(_) => context.set_guest(),
        }
    }

    return rsx! {
        {children}
    };
}
