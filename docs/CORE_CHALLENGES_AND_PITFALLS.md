# Dioxus Auth: The Master Catalog of Architectural Challenges & Pitfalls

> **Status:** Definitive Problem Catalog & Threat Analysis  
> **Location:** `docs/CORE_CHALLENGES_AND_PITFALLS.md`  
> **Purpose:** Document and categorize all 11 critical challenges facing `dioxus-auth` before implementing solutions.

---

## The Risk & Priority Matrix

| Priority | Challenge Domain | Risk Level | Primary Failure Mode |
|:---:|---|:---:|---|
| **#1** | **The Abstraction Boundary** | 🔴 **Critical** | Mega-trait coupling; forcing databases or ORMs onto developers. |
| **#2** | **Security Correctness** | 🔴 **Critical** | Vulnerable sessions, timing attacks, CSRF, DB leak hijacking. |
| **#3** | **Dioxus Client / Server / SSR State** | 🔴 **Critical** | Hydration flashes, premature redirects, session loss on F5 refresh. |
| **#4** | **Cookies & Session Transports** | 🟠 **High** | Desktop/Mobile cookie breakage; browser form reload loops. |
| **#5** | **Session Lifecycle & DB Write Amplification** | 🟠 **High** | Updating DB on every request; abandoned sessions bloating storage. |
| **#6** | **User Data Model Freedom** | 🟠 **High** | Forcing `User.id` types; leaking password hashes to WASM bundles. |
| **#7** | **Identity Normalization & Registration DoS** | 🟠 **High** | Case-collision takeover; 10MB password payload CPU starvation. |
| **#8** | **Authorization vs. Authentication Scope Creep** | 🟡 **Medium** | Inventing a rigid RBAC system that doesn't fit domain logic. |
| **#9** | **Rust Async Ergonomics & Type System Bounds** | 🟡 **Medium** | Generic bounds explosion; `Send + Sync + 'static` compiler fights. |
| **#10** | **Error Architecture & Security Boundaries** | 🟡 **Medium** | Leaking DB errors to clients; `Box<dyn Error>` ambiguity. |
| **#11** | **Public API Surface & Semantic Stability** | 🟡 **Medium** | Breaking user apps after publishing to crates.io. |

---

## 1. Challenge #1: Designing the Abstraction Boundary

### The Core Tension
A library must orchestrate the auth lifecycle without knowing what database is running.

```text
       ┌────────────────────────┐
       │     AuthEngine         │
       └───────────┬────────────┘
                   │
    How wide is this boundary?
                   │
    ┌──────────────┴──────────────┐
    ▼                             ▼
[ TOO BROAD ]                 [ TOO WEAK ]
Mega-Storage Trait            Minimal Trait
- 20+ methods                 - Only find_by_id()
- Forced user schemas         - Engine cannot do timing defense
- SQLx/Diesel leakage         - Cannot revoke on password change
```

### The Traps:
1. **The Mega-Trait Trap (Arium's mistake)**:
   Trying to put `create_user()`, `update_user()`, `delete_user()`, `create_session()`, `create_token()`, `create_oauth()`, and `audit_log()` into one giant `trait Storage`. This forces the application to conform to our database schema and locks out simple stores.
2. **The Database Coupling Trap**:
   Hardcoding `sqlx::Pool` or `diesel::Connection` into the library, locking out Turso (`libsql`), rusqlite, MongoDB, and Redis.
3. **The Solution Strategy: Granular Capability Traits**:
   - `UserStore`: Read-only `find_by_id(&id)`.
   - `PasswordUserStore`: Read-only `find_by_identifier(&identifier)`.
   - `SessionStore`: `save_session()`, `find_session()`, `delete_session()`, `delete_user_sessions()`.

---

## 2. Challenge #2: Making Authentication Actually Secure

### The Core Tension
Authentication is not ordinary CRUD. In ordinary CRUD, an edge-case bug returns bad data. In authentication, an edge-case bug exposes every user's private account.

### The Specific Attack Vectors:
1. **Session Hijacking via Database Leaks (Plaintext Tokens)**:
   - *Threat:* Storing raw session IDs in the database means any SQL injection, backup leak, or log dump allows an attacker to hijack all active user sessions.
   - *Requirement:* The database must **only store the SHA-256 hash** of the token. The browser holds the secret raw token.
2. **Timing Attacks on Login (User Enumeration)**:
   - *Threat:* If checking a nonexistent email takes 0.1ms, but verifying an existing user takes 25ms (Argon2id), attackers can measure latency to compile a list of valid registered users.
   - *Requirement:* Constant-time dummy verification when user is not found.
3. **CPU Starvation / Denial of Service via Argon2**:
   - *Threat:* Argon2id is intentionally CPU-heavy (~25ms CPU time, 19 MiB RAM). An attacker sending 100 requests/sec can peg all CPU cores at 100%.
   - *Requirement:* Pre-hash rate limiting that blocks repeated failures before invoking Argon2.
4. **Cross-Site Request Forgery (CSRF) on Server Functions**:
   - *Threat:* Malicious websites can issue background POST requests to Dioxus server functions with browser cookies attached.
   - *Requirement:* `SameSite=Lax` + automatic `Origin == Host` validation in `AuthLayer`.
5. **Stale Sessions on Password Rotation**:
   - *Threat:* When a user changes their compromised password, active sessions on other devices remain logged in.
   - *Requirement:* `session_auth_hash` binding that instantly revokes all existing sessions when credentials change.

---

## 3. Challenge #3: Dioxus ↔ Server State Synchronization

### The Core Tension
In a client-server architecture, state lives on the server, but the UI lives in the browser.

```text
Browser ──> Dioxus UI ──> Server Fn / HTTP ──> AuthEngine ──> Session ──> Store
```

### The Pitfalls:
1. **The Loading State Ambiguity**:
   When the app boots, what is the user's status?
   - If it defaults to `false` (Unauthenticated), protected layouts panic and redirect to `/login`.
   - If it defaults to `true`, unauthorized screens briefly render before booting the user.
   - *Requirement:* Explicit 3-state machine (`Loading`, `Authenticated`, `Unauthenticated`).
2. **The F5 / Page Refresh Wipeout**:
   If login only updates a client-side signal, pressing F5 reloads the browser, wipes client memory, and logs the user out.
   - *Requirement:* Persistent cookie emission + automatic session hydration on mount.

---

## 4. Challenge #4: SSR and Hydration (The Layout Flash)

### The Core Tension
In Dioxus Fullstack, HTML is first rendered on the server (SSR), then hydrated by WebAssembly in the browser.

```text
Request ──> Server SSR (Authenticated) ──> HTML Sent ──> Client WASM Hydration
                                                               │
                                         Does WASM know the user immediately?
                                         ├── NO  ──> UI flashes logged-out / redirects!
                                         └── YES ──> Seamless, zero-flicker render.
```

### The Pitfalls:
1. **The Hydration Flash Trap**:
   Server renders dashboard HTML for authenticated user. Client WASM wakes up with uninitialized status, assumes user is logged out, and immediately triggers `nav.replace("/login")`.
2. **The Solution Strategy**:
   - SSR serializes initial auth status into the root context payload.
   - `<RouteGate>` enters `Pending` mode during `Loading`, rendering a fallback instead of triggering a redirect.

---

## 5. Challenge #5: Cookies, Sessions, & Multi-Platform Transports

### The Core Tension
Next.js is only web (cookies). Dioxus runs on **Web, Desktop (Wry/Tao), and Mobile (iOS/Android)**.

### The Pitfalls:
1. **The Desktop/Mobile Cookie Breakdown**:
   Native webviews on macOS, Windows, Linux, iOS, and Android often have fragile or unshared cookie jars. Desktop apps using HTTP clients (`reqwest`) communicate via `Authorization: Bearer <token>`.
2. **The Dual-Transport Requirement**:
   `AuthLayer` must transparently accept:
   - `Authorization: Bearer <token>` (Native Desktop / Mobile)
   - `Cookie: __Host-dioxus_session=<token>` (Web browsers)
3. **The Browser Form Native Reload Bug**:
   In web forms, clicking `<button type="submit">` triggers a browser page refresh unless `evt.prevent_default()` is explicitly called.

---

## 6. Challenge #6: Session Lifecycle & Database Write Amplification

### The Core Tension
Keeping sessions alive for active users vs. destroying database performance.

```text
Naive Sliding Window:
Request 1  ──> UPDATE sessions SET expires_at = now + 7d;
Request 2  ──> UPDATE sessions SET expires_at = now + 7d;
Request 3  ──> UPDATE sessions SET expires_at = now + 7d; (100 requests = 100 DB writes!)

The 50% Renewal Rule:
Request 1..50 (Lifespan < 50%) ──> READ-ONLY DB query. Zero writes!
Request 51+   (Lifespan > 50%) ──> Extend expiration by 7d. Emits updated cookie.
```

### The Pitfalls:
1. **Database Write Amplification**: Updating session TTL on every HTTP request creates massive write contention.
   - *Solution:* The 50% renewal rule reduces database writes by **>95%**.
2. **Dead Session Bloat**: Abandoned sessions sit in the database forever.
   - *Solution:* Lazy deletion on lookup + optional hourly background sweeper task.
3. **"Remember Me" Configuration**:
   - Transient (Session cookie, cleared on browser exit).
   - Persistent (`Max-Age = 30 days`, survives restart).

---

## 7. Challenge #7: The Application's User Data Model Freedom

### The Core Tension
Every app has a different user model. App A uses `id: Uuid`. App B uses `id: i64`. App C uses `id: String`.

```rust
// App A
struct User { id: Uuid, email: String, tenant_id: Uuid }

// App B
struct Account { id: i64, username: String, role: Role }
```

### The Pitfalls:
1. **Forcing Types onto the Application**:
   Hardcoding `UserId = i64` or `Uuid` alienates half the ecosystem.
   - *Solution:* `trait AuthUser { type Id: Clone + Eq + Hash + Send + Sync + 'static; }`
2. **Leaking Password Hashes to WASM**:
   If the `User` struct contains `password_hash: String`, passing `User` over server functions serializes the password hash into the browser's JavaScript memory!
   - *Solution:* Separate `User` from the hash: `PasswordUserStore::find_by_identifier` returns `(User, String /* hash */)`.

---

## 8. Challenge #8: Identity Normalization & Registration Exploits

### The Core Tension
Handling user input during account creation and login.

### The Pitfalls:
1. **Case-Collision Account Hijacking**:
   If Alice signs up as `Alice@example.com` and an attacker registers `alice@example.com`, case-sensitive databases create duplicate accounts, causing routing and recovery bugs.
   - *Solution:* Canonical lowercasing and trimming on all email identifiers.
2. **Unicode Homoglyph / Confusable Attacks**:
   Attacker uses Cyrillic 'а' (U+0430) instead of Latin 'a' (U+0061) to spoof usernames (`аdmin` vs `admin`).
   - *Solution:* Unicode NFKC normalization.
3. **Password Payload DoS (CPU Starvation)**:
   An attacker submits a **10-megabyte password string**. Computing Argon2 on 10MB locks up CPU and memory.
   - *Solution:* Enforce strict maximum password length of **128 characters**.

---

## 9. Challenge #9: Authorization vs. Authentication Scope Creep

### The Core Tension
- **Authentication (AuthN)**: *Who are you?* (`User`, `Session`)
- **Authorization (AuthZ)**: *What are you allowed to do?* (Permissions, roles, policies)

### The Pitfalls:
1. **The Universal RBAC Fallacy**:
   Trying to build a complex, rigid RBAC/permission engine into `dioxus-auth`.
   - Real apps have domain-specific rules: *"Can user X edit document Y belonging to organization Z on a Tuesday?"*
   - A generic auth library cannot invent an authorization system that fits every domain.
2. **The Solution Strategy**:
   - `dioxus-auth` handles **AuthN completely**.
   - For **AuthZ**, it exposes clean capability extension points: route gates that accept any predicate `fn(&User) -> bool`, and user-defined roles.

---

## 10. Challenge #10: Rust Async Ergonomics & Type System Bounds

### The Core Tension
Rust's strict type system requires `Send + Sync + 'static` for multi-threaded async runtimes (Tokio/Axum), but developers hate boilerplate.

### The Pitfalls:
1. **Generics Explosion**:
   If every component requires `<User, Id, Store, Hasher>`, the API becomes unusable.
   - *Solution:* Type inference in builders, defaulting hasher to `Argon2Hasher`.
2. **`Auth<User>` Lifetime & Closure Ergonomics**:
   In Dioxus, components and event closures (`onclick`, `onsubmit`) require captured variables to be easily movable.
   - *Solution:* Implement `Copy` unconditionally on `Auth<User>` (just like Dioxus's `Signal<T>`).

---

## 11. Challenge #11: Error Architecture & API Stability

### The Core Tension
Errors originate from databases, password hashing, network transport, and user input.

### The Pitfalls:
1. **The `Box<dyn Error>` Anti-Pattern**:
   Hiding errors behind dynamic trait objects prevents programmatic matching.
2. **Leaking Internal Infrastructure**:
   Exposing raw SQL errors to client browsers gives attackers information about database table names.
3. **The Solution Strategy**:
   An explicit `AuthError` enum:
   - `Unauthenticated`
   - `InvalidCredentials`
   - `UserAlreadyExists`
   - `RateLimited { retry_after_secs: u64 }`
   - `Store(String)` (opaque for client, logged on server)
   - `Crypto(String)`
