//! `AuthError` restore-classification unit tests.
//!
//! Requires the `dioxus` feature for the prelude re-exports.

use dioxus_auth::prelude::{AuthError, RestoreClassify, RestoreVerdict};

#[test]
fn rejections_classify_as_unauthenticated() {
    assert_eq!(
        AuthError::InvalidCredentials.restore_verdict(),
        RestoreVerdict::Unauthenticated
    );
    assert_eq!(
        AuthError::PasswordHashError.restore_verdict(),
        RestoreVerdict::Unauthenticated
    );
}

#[test]
fn non_answers_classify_as_unknown() {
    assert_eq!(
        AuthError::RateLimited.restore_verdict(),
        RestoreVerdict::Unknown
    );
    assert_eq!(AuthError::Csrf.restore_verdict(), RestoreVerdict::Unknown);
    assert_eq!(
        AuthError::Internal(String::from("transport down")).restore_verdict(),
        RestoreVerdict::Unknown
    );
}
