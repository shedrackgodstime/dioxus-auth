# Dioxus Auth: Cross-Platform, Session Lifecycle, & Identity Specification

> **Status:** Architectural Specification & Findings (Pre-Implementation)  
> **Author:** Antigravity Team Lead & Pair Programmer  
> **Scope:** Cross-Platform Transport (Web vs Desktop vs Mobile), Session Renewal & Pruning, and Secure Identity Normalization.

---

## 1. Overview of the Three Areas

This specification addresses three foundational pillars of real-world application authentication:

1. **Area 1: Cross-Platform Transport**: How `dioxus-auth` bridges Web cookies with Desktop & Mobile Bearer tokens under a single unified API.
2. **Area 2: Session Lifecycle & Cleanup Architecture**: How sessions stay alive for active users without causing database write amplification, how "Remember Me" works, and how expired sessions are pruned.
3. **Area 3: Identity & Registration Specification**: How user accounts are safely created, normalized, and protected against payload DoS attacks.

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ AREA 1: CROSS-PLATFORM TRANSPORT                                            │
│ Web: Cookie: __Host-dioxus_session=<token>                                  │
│ Desktop / Mobile: Authorization: Bearer <token>                             │
│ Server AuthLayer: Transparent dual-extraction (one unified backend API!)    │
├─────────────────────────────────────────────────────────────────────────────┤
│ AREA 2: SESSION LIFECYCLE & CLEANUP                                         │
│ Sliding TTL: The 50% renewal rule (prevents DB write amplification)         │
│ Remember Me: Session cookie (transient) vs Persistent cookie (30 days)      │
│ Pruning: Lazy deletion on access + optional periodic background sweeper     │
├─────────────────────────────────────────────────────────────────────────────┤
│ AREA 3: IDENTITY & REGISTRATION SPECIFICATION                               │
│ Normalization: Email trimming, lowercasing, NFKC Unicode normalization      │
│ Password Constraints: Min 8 chars, Max 128 chars (DoS payload cap)          │
│ Atomic Registration: Validate -> Hash -> UserStore -> SessionStore          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Area 1: Cross-Platform Transport (Web vs. Desktop vs. Mobile)

### The Problem
- Dioxus is a multi-target framework targeting **Web**, **Desktop (Wry/Tao)**, and **Mobile (iOS/Android)**.
- On the **Web**, `HttpOnly`, `SameSite=Lax` cookies are the gold standard because browsers manage them automatically.
- On **Desktop and Mobile**, native webviews (WebKit, WebView2, Android WebView) often have inconsistent cookie persistence across app restarts. Native apps also frequently talk to server functions over HTTP clients (`reqwest`) or WebSockets, where `Authorization: Bearer <token>` is the standard.

### The Solution: The Unified Dual-Transport Architecture

```text
                  Incoming Request
                         │
                         ▼
             [ AuthLayer: Token Resolver ]
                         │
        Does 'Authorization: Bearer <token>' exist?
           ├── YES ──> Use Bearer token
           └── NO  ──> Extract 'Cookie: dioxus_session=<token>'
                         │
                         ▼
             [ Validate against AuthEngine ]
                         │
        (Downstream handlers have NO IDEA which transport was used!)
```

#### 1. Server-Side Extraction (`AuthLayer`)
The server accepts credentials from **either** source:
1. `Authorization: Bearer <token>` (Preferred by Desktop & Mobile).
2. `Cookie: dioxus_session=<token>` (Preferred by Web browsers).

Downstream server functions and route handlers simply receive `AuthSession<User>`. They do not have to write separate endpoints for mobile vs. web!

#### 2. Client-Side Transport Storage
On the frontend, `AuthProvider` uses a pluggable `TokenStorage` trait:
- **Web**: Uses browser cookies (transparent, zero storage code needed).
- **Desktop**: Optional keyring integration (OS Keychain on macOS, Windows Credential Manager, SecretService on Linux).
- **Mobile / Fallback**: Secure storage or in-memory persistence.

---

## 3. Area 2: Session Lifecycle & Cleanup Architecture

### 1. Sliding Window TTL & The 50% Renewal Rule

#### The Naive Sliding Window Problem:
If a session extends its expiration on *every single request*, a user browsing 100 pages generates **100 database update queries** (`UPDATE sessions SET expires_at = ?`). This destroys database performance.

#### The 50% Renewal Rule (The Lucia / OWASP Pattern):
Instead of updating on every request, the server only renews the session if **more than half of its lifespan has passed**:

```text
[ Created: Day 0 ] ─────────────────── [ 50% Mark: Day 3.5 ] ─────────────────── [ Expired: Day 7 ]
        │                                      │                                      │
   Requests here:                        Requests here:                         Requests here:
   READ-ONLY DB lookup.                  TRIGGER RENEWAL:                       Session is expired.
   No DB writes!                         - Update DB: expires_at = now + 7d     Deleted from DB.
                                         - Emit updated Set-Cookie header.
```

- **Impact**: Reduces database writes by **over 95%** while keeping active users logged in indefinitely.

---

### 2. "Remember Me" Toggle

| Mode | Cookie Configuration | Lifetime | Use Case |
|---|---|---|---|
| **Transient Session** (`remember_me: false`) | No `Max-Age` / `Expires` attribute | Cleared when browser window/process closes | Shared computers, cybercafes, sensitive banking apps |
| **Persistent Session** (`remember_me: true`) | `Max-Age = 2592000` (30 days) | Survives browser restarts | Normal SaaS, personal laptops, mobile apps |

---

### 3. Database Garbage Collection & Dead Session Pruning

When users abandon accounts or close browsers, expired sessions sit in the database forever unless pruned.

#### Two-Tier Pruning Strategy:
1. **Tier 1: Lazy Pruning on Access (Always Active)**:
   When `find_session(&id)` is called:
   If `session.is_expired_at(now)`, the server deletes the row from the database immediately and returns `Ok(None)`.
2. **Tier 2: Periodic Sweeper (Optional Background Task)**:
   A lightweight Tokio task running once every hour:
   ```sql
   DELETE FROM sessions WHERE expires_at_unix < strftime('%s', 'now');
   ```
   Ensures the `sessions` table stays small and indexes remain fast.

---

## 4. Area 3: Identity & Registration Specification

### 1. Identifier Normalization & Anti-Spoofing

#### Threat 1: Case Collision
If Alice registers `Alice@example.com` and later an attacker registers `alice@example.com`, systems with case-sensitive lookups create two distinct accounts, causing email collision and password reset confusion.

#### Threat 2: Homoglyph / Confusable Attacks
Using Cyrillic 'а' instead of Latin 'a' to spoof `admin` (`аdmin`).

#### Normalization Standard:
1. **Email Identifiers**:
   - `trim()` whitespace.
   - `to_lowercase()`.
   - Validate basic syntax (`contains('@')` and valid domain dots).
2. **Username Identifiers**:
   - Unicode Normalization: **NFKC** (Normalization Form KC - Compatibility Decomposition followed by Canonical Composition).
   - Trim whitespace.
   - Store canonical lowercase form for uniqueness matching.

---

### 2. Password Constraints & Denial of Service Protection

Argon2id hashing time scales with input size. If an attacker submits a **10-megabyte password string**, hashing it consumes massive CPU and memory.

#### Enforced Constraints:
- **Minimum Password Length**: **8 characters** (OWASP recommendation).
- **Maximum Password Length**: **128 characters** (Strictly enforced payload cap to prevent CPU exhaustion DoS).
- **Entropy Requirement**: Disallow all-whitespace passwords.

---

### 3. Atomic `register()` Flow in `AuthEngine`

```text
register(identifier, raw_password, user_data)
      │
      ├── 1. Normalize identifier (trim, lowercase, NFKC)
      │
      ├── 2. Validate password bounds (8 <= len <= 128)
      │
      ├── 3. Check duplicate: user_store.find_by_identifier(normalized)
      │      └── If exists: return Err(AuthError::UserAlreadyExists)
      │
      ├── 4. Hash password: hasher.hash_password(raw_password) (Argon2id)
      │
      ├── 5. Persist user: user_store.create_user(user, hash)
      │
      ├── 6. Generate session:
      │      - Create 256-bit CSPRNG token
      │      - Hash token via SHA-256 for database storage
      │      - Save session in session_store
      │
      └── 7. Return (User, RawSessionToken)
```

---

## 5. Next Steps

We now have formal specifications for all core domains:
1. **Core Capability Layer**: [`docs/DESIGN.md`](./DESIGN.md)
2. **Native Fullstack & Middleware**: [`docs/NATIVE_FULLSTACK_DESIGN.md`](./NATIVE_FULLSTACK_DESIGN.md)
3. **Security & Threat Model**: [`docs/SECURITY_SPECIFICATION.md`](./SECURITY_SPECIFICATION.md)
4. **Cross-Platform, Lifecycle, & Identity**: This document ([`docs/CROSS_PLATFORM_SESSION_AND_IDENTITY_SPEC.md`](./CROSS_PLATFORM_SESSION_AND_IDENTITY_SPEC.md))

We can now examine and dissect each area one by one.
