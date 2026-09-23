//! Capability traits for authentication storage and the default memory store.
//!
//! Door-3 surface: the traits and [`MemoryStore`] are re-exported here and at
//! the crate root; the implementing modules underneath stay closed so each
//! item keeps one documented path.

pub(crate) mod memory;
pub(crate) mod session;
pub(crate) mod user;

pub use memory::MemoryStore;
pub use session::SessionStore;
pub use user::{PasswordUserStore, UserStore};
