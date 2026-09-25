//! Blocking boundary for synchronous engine calls inside async server slices.
//!
//! The core engine is synchronous by design (single crate, zero async core).
//! Its calls are cheap for in-memory stores but not always: Argon2 verification
//! is deliberately CPU-heavy, and SQL-backed stores scan under locks. Running
//! those directly inside async handlers occupies a tokio worker for the whole
//! duration; with few workers this stalls unrelated requests into starvation,
//! and creates a latency cliff on login.
//!
//! [`run_blocking`] dispatches blocking calls to `tokio::task::spawn_blocking`
//! when a tokio runtime context is available and falls back to an inline call
//! otherwise, so the server slice never assumes which executor hosts it.

use std::panic;

use tokio::runtime::Handle;
use tokio::task;

/// Whether the current async context can dispatch to the blocking pool.
///
/// The check is `Handle::try_current()`: without a runtime context (plain
/// `#[test]`s, non-tokio executors) the call runs inline on the current
/// thread instead of failing.
fn runtime_available() -> bool {
    return Handle::try_current().is_ok();
}

/// Runs a fallible-blocking closure off the async worker when possible.
///
/// Inside a tokio runtime the closure moves to the blocking pool; the caller
/// awaits its completion, so the async worker never executes the closure.
/// Without a runtime context the closure runs inline (there is no worker to
/// starve).
///
/// A spawned task that panics unwinds through the awaiting caller, per the
/// crate's panic model. A task lost to runtime shutdown surfaces as `Err`,
/// since no output value exists to return.
#[must_use = "the blocking result must be used"]
pub(super) async fn run_blocking<T, F>(operation: F) -> Result<T, tokio::task::JoinError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    if !runtime_available() {
        return Ok(operation());
    }
    let joined = task::spawn_blocking(operation).await;
    return match joined {
        Ok(value) => Ok(value),
        Err(join_error) => {
            if join_error.is_panic() {
                // reason: engine panics are programming errors; re-raising
                // preserves the crate's panic model instead of converting a
                // crash into a return value.
                panic::resume_unwind(join_error.into_panic());
            }
            return Err(join_error);
        }
    };
}
