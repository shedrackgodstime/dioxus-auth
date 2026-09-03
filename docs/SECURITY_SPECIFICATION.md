# dioxus-auth: Security & Native Fullstack Architecture Specification

> **Status:** Specification & Architectural Findings (Pre-Implementation)  
> **Author:** Antigravity Team Lead & Pair Programmer  
> **Scope:** Threat Modeling, Cryptographic Standards, Fullstack Axum/Dioxus Integration, and OWASP Compliance.

---

## 1. Executive Summary & Problem Statement

Authentication libraries frequently fail in production not because the hashing algorithm was wrong, but because of **architectural security gaps**:
1. **Database Leaks Leading to Session Hijacking**: Storing raw session IDs in plaintext means any database read-access or leaked backup grants full account takeover.
2. **Denial of Service via Expensive Hashing**: Argon2id is computationally heavy by design. Without rate-limiting *prior* to hashing, an attacker can trivially crash a server by sending 100 login requests/sec.
3. **CSRF on Server Functions**: Cookie-based server functions are vulnerable to cross-site invocation unless origin validation is enforced.
4. **Timing Attacks on Authentication**: Differential latency between "user not found" vs. "invalid password" leaks whether an email exists.
5. **Stale Session Longevity**: If a user changes their password on their phone, an attacker with a stolen session on a laptop remains logged in unless session-hash binding is active.

This document details the exact technical findings and architectural designs to make `dioxus-auth` immune to these attack vectors while keeping the Dioxus API ergonomic and clean.

---

## 2. Threat Modeling & Defense Matrix

| Threat / Attack Vector | Severity | Traditional Failure Mode | `dioxus-auth` Native Defense |
|---|---|---|---|
| **Database Compromise / Read-Only SQLi** | **Critical** | Attacker dumps `sessions` table and uses raw session IDs to impersonate all users. | **Stored Session Hashing (SHA-256)**: Database only stores `sha256(token)`. Browser holds the secret token. Leaked database yields zero hijackable sessions. |
| **CSRF on `#[server]` Functions** | **High** | Malicious site (`evil.com`) triggers cross-site POST to `/api/...`; browser attaches cookie. | **Dual Defense**: `SameSite=Lax` + automatic `Origin`/`Host` header validation in `AuthLayer`. |
| **CPU Starvation / DoS Attack** | **High** | Attacker spams login with fake accounts; server CPU hits 100% running Argon2id. | **Pre-Hash Rate Limiting**: In-memory token bucket throttles failed attempts per IP/identifier *before* invoking Argon2. |
| **User Enumeration / Timing Attacks** | **Medium** | Response latency differs when username does not exist. | **Constant-Time Dummy Verification**: Executes a dummy Argon2 check if user is not found, keeping latency identical (~25ms). |
| **Stolen Active Sessions after Credential Change** | **High** | User resets compromised password; active sessions on attacker's device remain valid. | **`session_auth_hash` Invalidation**: Every session is bound to the user's current password hash. Updating password instantly revokes all existing sessions. |
| **XSS Cookie Theft & Subdomain Spoofing** | **Medium** | Malicious script on page or compromised subdomain reads/overwrites session cookie. | **`__Host-` Prefix & `HttpOnly`**: Hardened cookie flags prevent JS access and forbid subdomain overwrites. |

---

## 3. Deep Dive into Technical Findings

### Finding 1: Stored Session Hashing (The Lucia / OWASP Pattern)

```text
[ Browser ]                                       [ Database ]
     │                                                 │
     │ 1. Set-Cookie: session=s_9f4b12...              │
     │    (Client holds raw 256-bit token)             │
     │                                                 │
     │ 2. GET /dashboard (Cookie: session=s_9f4b12...) │
     │ ──────────────────────────────────────────────> │
     │    Server hashes token:                         │
     │    let key = sha256("s_9f4b12...")              │
     │                                                 │
     │    Query database:                              │
     │    SELECT * FROM sessions WHERE id = key        │
     │    ───────────────────────────────────────────> │
     │    (Database ONLY knows the SHA-256 hash!)      │
```

#### Why this is essential:
- If an attacker gains access to database backups, SQL dumps, or logs, they see a list of SHA-256 hashes: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- SHA-256 is a one-way cryptographic hash. It is mathematically impossible to reverse the hash back into the raw session cookie token.
- **Cost**: A single SHA-256 operation takes less than **0.5 microseconds**, adding virtually zero latency while providing enterprise-grade leak protection.

---

### Finding 2: Zero-Boilerplate CSRF Defense in `AuthLayer`

In Next.js, Server Actions protect against CSRF by checking the `Origin` header against the `Host` header.
In Dioxus, `AuthLayer` will enforce this at the Axum layer:

```text
Incoming Request -> [ AuthLayer ]
                          │
                   Is method POST/PUT/DELETE?
                     ├── NO  -> Proceed (Safe GET/HEAD request)
                     └── YES -> Check Headers:
                                  let origin = request.headers.get("Origin");
                                  let host = request.headers.get("Host");
                                  if origin != host {
                                      return 403 Forbidden ("CSRF Verification Failed")
                                  }
                                  Proceed to Server Function
```

#### Key Rules:
1. **Safe Methods (`GET`, `HEAD`, `OPTIONS`)**: Allowed to proceed without CSRF checks (they must remain idempotent).
2. **State-Changing Methods (`POST`, `PUT`, `DELETE`)**: The `Origin` (or `Referer` fallback) must match the application `Host`.
3. **Cross-Origin APIs**: If a developer intentionally builds a public API endpoint, they can opt-out that route via `.cors_allowed_origins(...)`.

---

### Finding 3: Rate Limiting & CPU Starvation Defense

Argon2id configuration in `dioxus-auth`:
- Memory: **19,456 KiB** (~19 MiB)
- Iterations: **2**
- Parallelism: **1**
- Latency per check: **~20ms - 35ms** (on modern x86_64 CPUs)

While 25ms is imperceptible for a human logging in, **100 requests per second will saturate 4 CPU cores completely**.

#### Design of the Rate Limiter:
```rust
pub trait RateLimiter: Send + Sync + 'static {
    /// Check if the request is permitted. If not, returns retry-after duration.
    async fn check(&self, key: &str) -> Result<(), Duration>;
    
    /// Record a failed authentication attempt.
    async fn record_failure(&self, key: &str);
    
    /// Reset counter upon successful login.
    async fn record_success(&self, key: &str);
}
```

- **Default Implementation**: An in-memory sliding window using an LRU cache with TTL (zero dependencies, zero setup for the developer).
- **Throttling Key**: `format!("{ip}:{identifier}")`
- **Threshold**: 5 failed attempts per 60 seconds.
- **Action**: When threshold is reached, `AuthEngine::login` returns `Err(AuthError::RateLimited { retry_after: 60 })` **immediately without calling Argon2**.

---

### Finding 4: Cookie Hardening Standards

Cookies must follow modern RFC 6265bis specifications:

| Setting | Production Value | Development (`localhost`) Value | Security Rationale |
|---|---|---|---|
| **Cookie Name** | `__Host-dioxus_session` | `dioxus_session` | `__Host-` prefix enforces `Secure=true`, `Path=/`, and forbids subdomain tampering. |
| **`HttpOnly`** | `true` | `true` | Prevents JavaScript (`document.cookie`) and XSS from reading session tokens. |
| **`Secure`** | `true` | `false` (allows HTTP) | Ensures cookies are only transmitted over TLS-encrypted HTTPS connections. |
| **`SameSite`** | `SameSite::Lax` | `SameSite::Lax` | Prevents the browser from sending cookies on cross-origin POST requests (primary CSRF defense). |
| **`Path`** | `/` | `/` | Confines cookie to entire domain. |
| **`Max-Age`** | User-configured (e.g. 7 days) | User-configured | Explicit expiration; automatically deleted on browser expiration. |

---

## 4. The Native Fullstack Developer Experience (DX)

How does all of this look to a developer using `dioxus-auth`?
**The developer writes zero crypto and zero security boilerplate.**

### 1. Server Entrypoint (`dioxus::serve`)
```rust
#[cfg(feature = "server")]
fn main() {
    dioxus::serve(|| async move {
        let engine = Arc::new(AuthEngine::builder(user_store, session_store).build());

        Ok(dioxus::server::router(App)
            .layer(
                AuthLayer::new(engine)
                    .protect_prefix("/dashboard", "/login")
                    .rate_limit(5, Duration::from_secs(60)) // 5 attempts per min
            ))
    });
}
```

### 2. Protected Server Function
```rust
#[server]
pub async fn get_financial_records() -> Result<Records, ServerFnError> {
    let auth = server_auth::<AppUser>()?;
    let user = auth.require_user()?; // 🛡️ Rejects with 401 if unauthenticated!

    Ok(records_service::get(user.id()).await?)
}
```

### 3. Server Login Endpoint
```rust
#[server]
pub async fn login(email: String, password: String) -> Result<AppUser, ServerFnError> {
    let auth = server_auth::<AppUser>()?;
    
    // 🛡️ Handles rate-limiting, timing-defense dummy hash, 
    // SHA-256 session token hashing, and emits hardened __Host- cookie!
    Ok(auth.login(&email, &password).await?)
}
```

### 4. Client SPA / SSR App (`App`)
```rust
#[component]
fn App() -> Element {
    rsx! {
        AuthProvider::<AppUser> {
            // Automatically hydrates session from cookie on mount / F5 refresh!
            Router::<Route> {}
        }
    }
}
```

---

## 5. Summary & Next Steps

This specification bridges the entire auth lifecycle:
1. **Frontend**: Hydration-safe reactive state (`Loading` $\to$ `Authenticated`), route guards, and zero layout flicker.
2. **Transport**: `AuthLayer` providing Next.js-style middleware interception, CSRF validation, and hardened `__Host-` cookies.
3. **Backend**: `AuthEngine` with SHA-256 stored session hashing, pre-hash rate-limiting against DoS, and Argon2id timing mitigation.
