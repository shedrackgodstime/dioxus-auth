use std::sync::Arc;

use dioxus::prelude::*;

use crate::dioxus::context::Auth;
use crate::session::AuthStatus;
use crate::transport::TokenStorage;

/// Opaque reference to a [`TokenStorage`] implementation that can be passed as a
/// Dioxus prop. Equality is pointer-based so components using it do not re-render
/// when the underlying storage has not changed.
#[derive(Clone)]
pub struct TokenStorageRef(Arc<dyn TokenStorage>);

impl PartialEq for TokenStorageRef {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl TokenStorageRef {
    /// Wrap an [`Arc<dyn TokenStorage>`] for use as a Dioxus prop.
    pub fn new(storage: Arc<dyn TokenStorage>) -> Self {
        Self(storage)
    }

    /// Access the inner [`TokenStorage`].
    pub fn into_inner(self) -> Arc<dyn TokenStorage> {
        self.0
    }
}

/// Inject the reactive authentication context into the component tree.
#[component]
pub fn AuthProvider<User: Clone + PartialEq + 'static>(
    #[props(default)] initial_status: Option<AuthStatus<User>>,
    #[props(default)] token_storage: Option<TokenStorageRef>,
    children: Element,
) -> Element {
    let status_signal = use_context_provider(|| Signal::new(initial_status.unwrap_or_default()));
    let auth = Auth::new(status_signal);
    provide_context(auth);
    provide_context(token_storage.map(|r| r.into_inner()));

    rsx! {
        {children}
    }
}
