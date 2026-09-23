//! Debug-redaction test for the login wire input.

// reason: project style requires explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use dioxus_auth::LoginRequest;

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
}
