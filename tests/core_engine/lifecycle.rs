//! Engine lifecycle tests: login, validate, logout, revocation.

// reason: RULES 13.5/14.5 require explicit `return` on tail expressions, so the
// conflicting style lint `needless_return` is allowed with this justification.
#![allow(clippy::needless_return)]

use dioxus_auth::prelude::SessionId;

use super::seeded_engine;

#[test]
fn login_then_validate_roundtrip() {
    let engine = seeded_engine();

    let (user, session) = engine.login("alice", "s3cret").unwrap();
    assert_eq!(user.id, 1);

    let validated = engine.validate_session(session.id()).unwrap().unwrap();
    assert_eq!(validated.id, 1);
}

#[test]
fn login_wrong_password_fails() {
    let engine = seeded_engine();

    let result = engine.login("alice", "wrong");
    assert!(result.is_err());
}

#[test]
fn login_unknown_user_fails() {
    let engine = seeded_engine();

    let result = engine.login("ghost", "whatever");
    assert!(result.is_err());
}

#[test]
fn logout_invalidates_the_session() {
    let engine = seeded_engine();

    let (_, session) = engine.login("alice", "s3cret").unwrap();
    engine.logout(session.id()).unwrap();

    assert!(engine.validate_session(session.id()).unwrap().is_none());
}

#[test]
fn logout_of_unknown_session_is_a_no_op() {
    let engine = seeded_engine();

    let result = engine.logout(&SessionId::generate());
    assert!(result.is_ok());
}

#[test]
fn revoke_known_session_reports_true() {
    let engine = seeded_engine();

    let (_, session) = engine.login("alice", "s3cret").unwrap();
    let revoked = engine.revoke_session(session.id()).unwrap();
    assert!(revoked);
    assert!(engine.validate_session(session.id()).unwrap().is_none());
}

#[test]
fn revoke_unknown_session_reports_false() {
    let engine = seeded_engine();

    let revoked = engine.revoke_session(&SessionId::generate()).unwrap();
    assert!(!revoked);
}

#[test]
fn validate_unknown_token_is_none() {
    let engine = seeded_engine();

    let validated = engine.validate_session(&SessionId::generate()).unwrap();
    assert!(validated.is_none());
}

#[test]
fn login_after_sign_out_revives_the_account() {
    let engine = seeded_engine();
    let (_, session) = engine.login("alice", "s3cret").unwrap();
    engine.logout(session.id()).unwrap();

    let (user, new_session) = engine.login("alice", "s3cret").unwrap();
    assert_eq!(user.id, 1);
    assert_ne!(session.id().as_str(), new_session.id().as_str());
    assert!(engine.validate_session(new_session.id()).unwrap().is_some());
}

#[test]
fn successful_validation_keeps_the_session_active() {
    let engine = seeded_engine();

    let (_, session) = engine.login("alice", "s3cret").unwrap();
    engine.validate_session(session.id()).unwrap();
    engine.validate_session(session.id()).unwrap();
    let validated = engine.validate_session(session.id()).unwrap().unwrap();

    assert_eq!(validated.id, 1);
}
