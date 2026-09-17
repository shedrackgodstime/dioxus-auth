//! Session domain types: opaque session identifiers, session records, and the
//! client-side authentication status lifecycle.

mod id;
mod record;
mod status;

pub use id::SessionId;
pub use record::Session;
pub use status::AuthStatus;
