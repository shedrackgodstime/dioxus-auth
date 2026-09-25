//! Capability traits for authentication storage and the default memory store.
//!
//! Advanced surface: the traits and [`MemoryStore`] are re-exported here and at
//! the crate root; the implementing modules underneath stay closed so each
//! item keeps one documented path.

pub(crate) mod default;
pub(crate) mod memory;
pub(crate) mod resolving;
pub(crate) mod session;
pub(crate) mod user;

pub use default::DefaultStore;
pub use memory::MemoryStore;
pub use resolving::ResolvingStore;
pub use session::SessionStore;
pub use user::{
    AuthSubject, CredentialStore, StoredCredential, SubjectClaim, SubjectStore, UserStore,
};
