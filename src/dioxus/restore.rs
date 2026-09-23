//! Network-aware session restore classification.
//!
//! A restore attempt can fail for reasons that mean fundamentally different
//! things for the user's session: the server may have *definitively* answered
//! "no session for this token", or the attempt may have failed before any
//! answer was learnable (storage read failure, rate limiting, transport
//! errors). Treating both as "signed out" silently demotes live sessions to
//! guest on a mere network blip.
//!
//! [`RestoreVerdict`] and [`RestoreClassify`] carry that distinction so
//! callers (the provider, or an application retry loop) can keep the context
//! in [`AuthStatus::Loading`](crate::status::AuthStatus::Loading) while the
//! outcome is genuinely unknown.

use crate::error::AuthError;

/// Outcome of a session restore attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreVerdict {
    /// A stored token was present and the engine accepted it; the context is
    /// authenticated.
    Restored,
    /// Definitive rejection: the context is a guest.
    ///
    /// No usable token existed, or the server definitively rejected the
    /// stored token.
    Unauthenticated,
    /// The attempt failed before the session question could be answered. The
    /// context is deliberately left in
    /// [`AuthStatus::Loading`](crate::status::AuthStatus::Loading); callers
    /// may retry.
    Unknown,
}

/// Classifies a restore failure as rejection or unknown.
///
/// Did the server definitively say "no session", or did the attempt fail
/// without an answer?
///
/// Implemented for [`AuthError`] in-crate. Applications wrapping remote
/// engines whose transport errors surface through other error types implement
/// this trait for their own error and feed the verdict to
/// [`AuthContext::restore`](crate::dioxus::AuthContext::restore) semantics.
pub trait RestoreClassify {
    /// The restore outcome implied by this failure.
    #[must_use = "the restore verdict must be handled"]
    fn restore_verdict(&self) -> RestoreVerdict;
}

impl RestoreClassify for AuthError {
    fn restore_verdict(&self) -> RestoreVerdict {
        return match self {
            // The engine compared the stored token against session state and
            // answered "no such session" — a definitive rejection.
            Self::InvalidCredentials | Self::PasswordHashError => RestoreVerdict::Unauthenticated,
            // Rate limiting, CSRF rejection and internal errors (the channel
            // transport failures surface through) all mean the token was
            // never judged — the session question is still open.
            Self::RateLimited | Self::Csrf | Self::Internal(_) => RestoreVerdict::Unknown,
        };
    }
}
