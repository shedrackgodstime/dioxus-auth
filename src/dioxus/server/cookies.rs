//! Session-cookie parsing and writing.

use dioxus_fullstack::{FullstackContext, http};

use crate::dioxus::server::ServerError;
use crate::security::{CookieConfig, SameSite};

/// Extracts the value of the session cookie from the request's `Cookie` header.
///
/// When the configuration is host-only, only the `__Host-`-prefixed name is
/// accepted; otherwise only the bare name is accepted, so a prefixed shadow
/// cannot displace it.
#[must_use]
pub fn request_cookie_token(headers: &http::HeaderMap, cfg: &CookieConfig) -> Option<String> {
    let expected = if cfg.host_only() {
        format!("__Host-{}", cfg.name())
    } else {
        String::from(cfg.name())
    };
    let mut token = None;
    for value in headers.get_all(http::header::COOKIE) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for pair in value.split(';') {
            let mut kv = pair.trim().splitn(2, '=');
            if kv.next() == Some(expected.as_str()) {
                token = kv.next().map(str::to_owned);
            }
        }
    }
    return token;
}

/// Builds the value of a [`Set-Cookie`](http::header::SET_COOKIE) header for
/// the session cookie. `None` emits a clearing cookie.
///
/// A host-only configuration emits the `__Host-`-prefixed name with a forced
/// `Path=/`, no `Domain`, and `Secure`.
#[must_use]
pub fn session_cookie_value(cfg: &CookieConfig, token: Option<&str>) -> String {
    let name = if cfg.host_only() {
        format!("__Host-{}", cfg.name())
    } else {
        String::from(cfg.name())
    };
    let path = if cfg.host_only() { "/" } else { cfg.path() };
    let mut attributes = vec![
        format!("{name}={}", token.unwrap_or("")),
        format!("Path={path}"),
    ];
    if cfg.http_only() {
        attributes.push(String::from("HttpOnly"));
    }
    if cfg.secure() || cfg.host_only() {
        attributes.push(String::from("Secure"));
    }
    attributes.push(format!("SameSite={}", same_site_name(cfg.same_site())));
    if token.is_none() {
        attributes.push(String::from("Max-Age=0"));
    } else if let Some(max_age) = cfg.max_age() {
        attributes.push(format!("Max-Age={max_age}"));
    }
    if !cfg.host_only() {
        if let Some(domain) = cfg.domain() {
            attributes.push(format!("Domain={domain}"));
        }
    }
    return attributes.join("; ");
}

/// Writes the session cookie value into the current response via
/// `FullstackContext`. Safe to call inside any server function.
///
/// # Errors
/// Returns `ServerError::MissingContext` outside a request context, or
/// `ServerError::InvalidCookieValue` if the value cannot be a header.
#[must_use = "cookie write errors must be handled"]
pub fn write_session_cookie(cfg: &CookieConfig, token: Option<&str>) -> Result<(), ServerError> {
    let ctx = match FullstackContext::current() {
        Some(ctx) => ctx,
        None => return Err(ServerError::MissingContext),
    };
    let value = session_cookie_value(cfg, token);
    let value = match http::HeaderValue::from_str(&value) {
        Ok(value) => value,
        Err(_) => return Err(ServerError::InvalidCookieValue),
    };
    ctx.add_response_header(http::header::SET_COOKIE, value);
    return Ok(());
}

const fn same_site_name(policy: SameSite) -> &'static str {
    return match policy {
        SameSite::Strict => "Strict",
        SameSite::Lax => "Lax",
        SameSite::None => "None",
    };
}
