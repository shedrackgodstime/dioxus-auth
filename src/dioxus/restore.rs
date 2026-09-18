//! Restore-error classification — did the server say "no session", or did we
//! fail to find out?
//!
//! Research 23 §2.1: treating *any* restore error as logout turns a boot-time
//! Wi-Fi/DNS blip into a guest session. The fix is to classify failures before
//! acting on them:
//!
//! | Probe result | Meaning | Client status |
//! |---|---|---|
//! | `Ok(Some(user))` | session valid | `Authenticated` |
//! | `Ok(None)` | server said no session | `Unauthenticated` |
//! | `Err` → [`RestoreVerdict::Unauthenticated`] | server definitively rejected | `Unauthenticated` |
//! | `Err` → [`RestoreVerdict::Unknown`] | network/transport — we learned nothing | **stay `Loading`** |
//!
//! The crate provides [`RestoreClassify`] for `ServerFnError` (feature
//! `dioxus-fullstack`). Apps with a custom whoami error type implement the
//! one method themselves:
//!
//! ```rust,ignore
//! struct MyError;
//! impl RestoreClassify for MyError {
//!     fn restore_verdict(&self) -> RestoreVerdict {
//!         RestoreVerdict::Unknown // or inspect your own shapes
//!     }
//! }
//! ```
//!
//! Requires the `dioxus-fullstack` feature.

/// What a restore failure *means*.
///
/// The distinction drives the client state machine: only a **definitive**
/// server rejection may demote the user to a guest; anything else must leave
/// the previous status untouched so a network blip can't log anyone out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreVerdict {
    /// The server responded and definitively said "not authenticated"
    /// (an HTTP 401/403-class answer).
    Unauthenticated,
    /// We failed to learn anything (DNS failure, timeout, offline, 5xx,
    /// malformed response, …). The session state is *unknown*, not absent.
    Unknown,
}

/// Classify a restore failure for [`crate::use_auth_restore`].
///
/// Implemented by this crate for `ServerFnError`; implement it for your own
/// whoami error type when you don't use the built-in server functions.
pub trait RestoreClassify {
    /// Did the server definitively reject the session, or did we fail to
    /// find out? See the [module docs](self) for the decision table.
    fn restore_verdict(&self) -> RestoreVerdict;
}

#[cfg(feature = "dioxus-fullstack")]
mod sfe_impl {
    use super::{RestoreClassify, RestoreVerdict};
    use dioxus::fullstack::{RequestError, ServerFnError};

    fn verdict_for_status(code: u16) -> RestoreVerdict {
        // 401/403 = the server *answered* and rejected the credential.
        // Everything else (5xx, 404-ish routing oddities, …) tells us nothing
        // about session validity.
        match code {
            401 | 403 => RestoreVerdict::Unauthenticated,
            _ => RestoreVerdict::Unknown,
        }
    }

    impl RestoreClassify for ServerFnError {
        fn restore_verdict(&self) -> RestoreVerdict {
            match self {
                // The client never reached a valid answer: connect/timeout/
                // send/decode failures are all "unknown"; only an actual
                // rejection status is definitive.
                ServerFnError::Request(RequestError::Status(_, code)) => verdict_for_status(*code),
                // The server fn itself reported a failure — trust its code.
                ServerFnError::ServerError { code, .. } => verdict_for_status(*code),
                // Transport/serialization noise: nothing definitive.
                _ => RestoreVerdict::Unknown,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn classify(err: ServerFnError) -> RestoreVerdict {
            err.restore_verdict()
        }

        #[test]
        fn definitive_rejections_are_unauthenticated() {
            // Client saw a rejection status.
            assert_eq!(
                classify(ServerFnError::Request(RequestError::Status(
                    "unauthorized".into(),
                    401
                ))),
                RestoreVerdict::Unauthenticated
            );
            assert_eq!(
                classify(ServerFnError::Request(RequestError::Status(
                    "forbidden".into(),
                    403
                ))),
                RestoreVerdict::Unauthenticated
            );
            // Server fn reported a rejection code.
            assert_eq!(
                classify(ServerFnError::ServerError {
                    message: "restore failed: unauthenticated".into(),
                    code: 401,
                    details: None,
                }),
                RestoreVerdict::Unauthenticated
            );
        }

        #[test]
        fn network_and_transport_failures_are_unknown() {
            assert_eq!(
                classify(ServerFnError::Request(RequestError::Connect(
                    "dns error: temporary failure in name resolution".into()
                ))),
                RestoreVerdict::Unknown
            );
            assert_eq!(
                classify(ServerFnError::Request(RequestError::Timeout(
                    "request timed out".into()
                ))),
                RestoreVerdict::Unknown
            );
            assert_eq!(
                classify(ServerFnError::Request(RequestError::Decode(
                    "bad body".into()
                ))),
                RestoreVerdict::Unknown
            );
            // A 5xx from the server fn tells us nothing about the session.
            assert_eq!(
                classify(ServerFnError::ServerError {
                    message: "db down".into(),
                    code: 500,
                    details: None,
                }),
                RestoreVerdict::Unknown
            );
            assert_eq!(
                classify(ServerFnError::Deserialization("oops".into())),
                RestoreVerdict::Unknown
            );
        }
    }
}
