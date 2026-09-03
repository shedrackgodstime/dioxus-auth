# Engineering Handoff: `dioxus-auth`

> **Repository:** [`shedrackgodstime/dioxus-auth`](https://github.com/shedrackgodstime/dioxus-auth)  
> **Branch:** `main` (All work pushed and synced to remote)  
> **Status:** Architecture Solidified • Core Engine Verified (15 tests passing) • Live Fullstack Demo Running • Master Problem Catalog Established

---

## 1. Quick Context for the Next AI Agent

You are working on **`dioxus-auth`**, a Dioxus-native, storage-agnostic authentication and session-management crate for fullstack Dioxus applications.

### Core Philosophy:
> **"The application developer owns their database models and infrastructure. `dioxus-auth` owns the authentication process, security math, and Dioxus reactive state."**

---

## 2. Master Documentation Index (`docs/`)

All architectural specifications, findings, and problem catalogs are written down in `docs/`:

1. **[`docs/CORE_CHALLENGES_AND_PITFALLS.md`](./CORE_CHALLENGES_AND_PITFALLS.md)**:
   The master 11-problem catalog and priority ranking (Abstraction boundary, security correctness, SSR hydration flash, write amplification, multi-platform transport).
2. **[`docs/NATIVE_FULLSTACK_DESIGN.md`](./NATIVE_FULLSTACK_DESIGN.md)**:
   How `AuthLayer` acts as the Dioxus equivalent to Next.js `middleware.ts`, how `#[server]` functions access context, and how SSR hydration works.
3. **[`docs/SECURITY_SPECIFICATION.md`](./SECURITY_SPECIFICATION.md)**:
   Threat model, SHA-256 stored session hashing (Lucia pattern), CSRF Origin/Host checks, pre-hash Argon2 DoS rate limiting, and `__Host-` cookies.
4. **[`docs/CROSS_PLATFORM_SESSION_AND_IDENTITY_SPEC.md`](./CROSS_PLATFORM_SESSION_AND_IDENTITY_SPEC.md)**:
   Dual-transport (Web Cookies vs. Desktop/Mobile Bearer tokens), the 50% sliding window renewal rule, and identity normalization (NFKC, 128-char cap).
5. **[`docs/DESIGN.md`](./DESIGN.md)**:
   The 3-layer capability architecture and directory layout.

---

## 3. Current Codebase & File Map

```text
dioxus-auth/
├── Cargo.toml                      # Zero database dependencies in core!
├── README.md                       # Public crate documentation and quickstart
├── docs/                           # Master specifications (read these first!)
│
├── src/                            # 🦀 CRATE SOURCE CODE
│   ├── lib.rs                      # Public prelude & exports
│   ├── error.rs                    # AuthError & AuthResult
│   ├── user.rs                     # AuthUser trait (generic over associated Id type)
│   ├── engine/                     # Layer 2: AuthEngine & AuthEngineBuilder
│   │   └── auth_engine.rs          # login, validate_session, logout, timing defense
│   ├── security/                   # Argon2Hasher, PasswordHasher, CookieConfig
│   ├── session/                    # Session, SessionId (CSPRNG), AuthStatus
│   ├── storage/                    # Layer 3: UserStore, PasswordUserStore, SessionStore, MemoryStore
│   └── dioxus/                     # Layer 1: AuthProvider, use_auth(), RouteGate, SignedIn, SignedOut, ServerAuthContext
│
├── tests/                          # 🧪 STANDALONE INTEGRATION TESTS
│   ├── auth_lifecycle_integration.rs # External crate consumer test (multi-device, revocation)
│   └── sqlite_integration.rs       # External SQLite database adapter test (rusqlite)
│
└── examples/
    ├── basic_auth.rs               # In-memory Dioxus VirtualDom example
    ├── sqlite_adapter.rs           # Real-world SQLite store adapter example
    └── dioxus-fullstack/           # 🚀 LIVE RUNNABLE FULLSTACK WEB APPLICATION
        ├── Cargo.toml              # (name = "dioxus-auth-demo")
        └── src/main.rs             # Fullstack webapp with #[server] functions & live UI
```

---

## 4. Verification & Testing Commands

All code is clean, formatted, and passes with zero warnings:

```bash
# 1. Check formatting
cargo fmt --check

# 2. Run Clippy (Strict: -D warnings)
cargo clippy --all-targets -- -D warnings

# 3. Run all 15 unit and integration tests
cargo test --all-targets

# 4. Run the live fullstack app in the browser (localhost:8080)
cd examples/dioxus-fullstack
dx serve
```

---

## 5. Current State of the Fullstack Demo (`examples/dioxus-fullstack`)

- **What works:**
  - Running `cd examples/dioxus-fullstack && dx serve` compiles and launches on `http://127.0.0.1:8080`.
  - User can log in with demo credentials: `admin@example.com` / `password123`.
  - Terminal prints server diagnostics (`[SERVER] login SUCCEEDED`).
  - Client navigates to `/dashboard` protected by `<RouteGate>`.
  - Navbar dynamically switches between `<SignedIn>` and `<SignedOut>`.
- **The Known Limitation (Next Immediate Task):**
  - Right now, `login_server` only updates client-side memory signal (`auth.set_user(user)`).
  - It does **not** yet emit a real `Set-Cookie` header, and `AuthProvider` does not yet hydrate from cookie on page mount.
  - Therefore, if the user presses **F5 (Refresh)**, the browser resets to `Unauthenticated`.

---

## 6. Immediate Next Tasks for the Next Session

Follow the roadmap in **[`docs/CORE_CHALLENGES_AND_PITFALLS.md`](./CORE_CHALLENGES_AND_PITFALLS.md)**:

1. **Fix the F5 Refresh / Cookie Bridge (Priority #1)**:
   - In `examples/dioxus-fullstack`:
     - Have `login_server` emit the HTTP cookie (`Set-Cookie: dioxus_session=...; HttpOnly; SameSite=Lax; Path=/`).
     - Add `get_current_user()` server function that reads incoming cookie and returns the session user.
     - Have `AuthProvider` automatically call `get_current_user()` on mount so refreshing the page preserves the login!
2. **Implement Stored Session Hashing (Security #1)**:
   - Separate the raw token (sent in the cookie) from the hashed token stored in the database (`sha256(token)`), per [`docs/SECURITY_SPECIFICATION.md`](./SECURITY_SPECIFICATION.md).
3. **Implement Registration (`AuthEngine::register`)**:
   - Add atomic user registration with identifier normalization (NFKC/lowercase) and 128-char password caps.
