//! Capability traits for authentication storage and the default memory store.

pub mod memory;
pub mod session;
pub mod user;

pub use memory::MemoryStore;
pub use session::SessionStore;
pub use user::{PasswordUserStore, UserStore};
