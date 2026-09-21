//! Session id and record unit tests.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use dioxus_auth::prelude::{Session, SessionId};

fn storage_session() -> Session<u64> {
    return Session::new(SessionId::generate(), 1, 1000, 2000);
}

#[test]
fn session_id_generates_valid_128_hex_chars() {
    let id = SessionId::generate();
    let raw = id.as_str();
    assert_eq!(raw.len(), 64);
    assert!(SessionId::is_valid_wire_format(raw));
    let reparsed = id.into_string();
    assert_eq!(reparsed.len(), 64);
}

#[test]
fn session_id_rejects_oversized_and_non_hex_tokens() {
    assert!(!SessionId::is_valid_wire_format("short"));
    assert!(!SessionId::is_valid_wire_format(&"a".repeat(65)));
    assert!(!SessionId::is_valid_wire_format(&"g".repeat(64)));
    assert!(!SessionId::is_valid_wire_format(&"A".repeat(64)));
}

#[test]
fn session_id_storage_form_is_deterministic_sha256() {
    let id = SessionId::new("deadbeef".repeat(8));
    let first = id.hash_for_storage();
    let second = id.hash_for_storage();
    assert_eq!(first.as_str(), second.as_str());
    assert_eq!(first.as_str().len(), 64);
    assert_ne!(first.as_str(), id.as_str());
}

#[test]
fn session_id_debug_and_display_are_redacted() {
    let id = SessionId::new("a".repeat(64));
    assert!(!format!("{id}").contains('a'));
    assert!(!format!("{id:?}").contains('a'));
    assert!(format!("{id:?}").contains("***"));
}

#[test]
fn session_record_accessors_and_expiry() {
    let session = storage_session()
        .with_last_active(1500)
        .with_auth_hash("h")
        .with_ip_address("127.0.0.1")
        .with_user_agent("test-agent");

    assert_eq!(session.user_id(), &1);
    assert_eq!(session.created_at_unix(), 1000);
    assert_eq!(session.expires_at_unix(), 2000);
    assert_eq!(session.last_active_at_unix(), Some(1500));
    assert_eq!(session.auth_hash(), Some("h"));
    assert_eq!(session.ip_address(), Some("127.0.0.1"));
    assert_eq!(session.user_agent(), Some("test-agent"));
    assert!(!session.is_expired_at(1999));
    assert!(session.is_expired_at(2000));
}

#[test]
fn session_set_expiry_and_last_active_updates_both() {
    let session = storage_session().set_expiry_and_last_active(9000, 8000);
    assert_eq!(session.expires_at_unix(), 9000);
    assert_eq!(session.last_active_at_unix(), Some(8000));
}

#[test]
fn session_debug_redacts_id_and_auth_hash() {
    let session = storage_session().with_auth_hash("hunter2");
    let debug = format!("{session:?}");
    assert!(!debug.contains("hunter2"));
    assert!(!debug.contains("session\""));
}
