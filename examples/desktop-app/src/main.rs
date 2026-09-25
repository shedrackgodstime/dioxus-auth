//! Desktop shell on `dioxus-auth`: the same quickstart tree on wry.
//!
//! Check-gated only (`cargo check -p desktop-app`): CI has no display
//! server, so nothing here runs headless. The point this proves is
//! portability — provider, hooks, and components move renderers unchanged.
//! Token storage is in-memory here; native secure storage is future work.

use std::any::Any;
use std::sync::Arc;

use dioxus::prelude::*;
use dioxus_auth::{
    Auth, AuthProvider, DefaultStore, DefaultUserInput, MemoryTokenStorage, TokenStorageHandle,
};
use quickstart::Dashboard;

/// Desktop root: facade arrives as a root context, provider serves state.
// reason: Dioxus components are PascalCase fns by framework convention.
#[expect(non_snake_case)]
fn DesktopRoot() -> Element {
    let auth = use_context::<Auth<DefaultStore>>();
    rsx! {
        AuthProvider { auth: auth, Dashboard {} }
    }
}

fn main() -> Result<(), dioxus_auth::AuthError> {
    let auth = Auth::memory()?;
    let (_, session) = auth.sign_up_email(
        "alice@example.com",
        "password",
        DefaultUserInput::new("alice"),
    )?;
    let storage = TokenStorageHandle::new(MemoryTokenStorage::new());
    storage
        .store(session.as_str())
        .expect("memory storage must write");
    let auth = auth.with_token_storage(storage);

    let provided: Arc<Auth<DefaultStore>> = Arc::new(auth);
    let context = move || {
        let boxed: Box<dyn Any> = Box::new((*provided).clone());
        return boxed;
    };
    dioxus_desktop::launch::launch(
        DesktopRoot,
        vec![Box::new(context) as Box<dyn Fn() -> Box<dyn Any> + Send + Sync>],
        vec![],
    );
}
