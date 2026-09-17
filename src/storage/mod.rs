//! Storage contracts the engine drives (`UserStore`, `PasswordUserStore`,
//! `SessionStore`) plus an in-memory reference implementation for tests and
//! examples.

mod memory;
mod session;
mod user;

pub use memory::MemoryStore;
pub use session::SessionStore;
pub use user::{PasswordUserStore, UserStore};

/// Conformance suite for store authors: replicate these tests against your
/// backend to prove it upholds the [`UserStore`], [`PasswordUserStore`], and
/// [`SessionStore`] contracts.
#[cfg(any(test, doc))]
pub mod conformance;
