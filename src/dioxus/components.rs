//! Dioxus components.

use std::fmt::Debug;

/// The guard component.
#[derive(Debug)]
pub struct RouteGate;

/// Requires authentication.
#[derive(Debug)]
pub struct RequireAuth;

/// Redirects if already authenticated.
#[derive(Debug)]
pub struct RedirectIfAuthed;

/// Components for signed-in/out views.
#[derive(Debug)]
pub struct SignedInOut;
