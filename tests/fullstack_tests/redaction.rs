//! Debug-redaction tests for the wire inputs carrying plaintext secrets.

// reason: project style requires explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use dioxus_auth::{AttachRequest, ChangePasswordRequest, LoginRequest};

#[test]
fn login_request_debug_redacts_the_plaintext_password() {
    let request = LoginRequest {
        identifier: String::from("alice@example.com"),
        password: String::from("s3cret-password"),
    };
    let rendered = format!("{request:?}");
    assert!(rendered.contains("alice@example.com"));
    assert!(!rendered.contains("s3cret-password"));
    assert!(rendered.contains("***"));
    return;
}

#[test]
fn attach_request_debug_redacts_the_plaintext_password() {
    let request = AttachRequest {
        identifier: String::from("alice-2@example.com"),
        password: String::from("other-secret"),
    };
    let rendered = format!("{request:?}");
    assert!(rendered.contains("alice-2@example.com"));
    assert!(!rendered.contains("other-secret"));
    assert!(rendered.contains("***"));
    return;
}

#[test]
fn change_password_request_debug_redacts_both_plaintext_passwords() {
    let request = ChangePasswordRequest {
        identifier: String::from("alice@example.com"),
        current_password: String::from("old-secret"),
        new_password: String::from("new-secret"),
    };
    let rendered = format!("{request:?}");
    assert!(rendered.contains("alice@example.com"));
    assert!(!rendered.contains("old-secret"));
    assert!(!rendered.contains("new-secret"));
    assert!(rendered.contains("***"));
    return;
}
