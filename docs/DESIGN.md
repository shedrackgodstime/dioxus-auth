# dioxus-auth — Design & Architecture

## 1. Goal

`dioxus-auth` is a Dioxus-native authentication and session-management framework for fullstack Dioxus applications.

It feels like a natural extension of Dioxus while providing complete database independence and enterprise-grade security defaults.

---

## 2. Core Architectural Thesis

> **The developer owns the application's domain data, user schemas, and persistence infrastructure. `dioxus-auth` owns the secure authentication workflows and Dioxus reactive state.**

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Dioxus Runtime Layer (Client & SSR Ergonomics)           │
│    - AuthProvider & use_auth()                              │
│    - Signal<AuthStatus<User>> (Hydration-Safe 3-State Model)│
│    - RouteGate, RequireAuth, RedirectIfAuthed               │
│    - Server Function Context & Cookie Extraction            │
├─────────────────────────────────────────────────────────────┤
│ 2. Auth Flow Orchestrator (Core Business Logic)             │
│    - AuthEngine (login, validate_session, logout)           │
│    - Timing Attack Defense (constant-time verification)     │
│    - Session Lifecycle (create, expire, revoke, rotate)     │
│    - Password Hashing (Argon2id default)                    │
├─────────────────────────────────────────────────────────────┤
│ 3. Capability Storage Layer (Pluggable Application Traits)  │
│    - UserStore<User> & PasswordUserStore                    │
│    - SessionStore<UserId>                                   │
│    - (Future: EmailSender, OAuthProvider, Authorization)    │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Design Principles

* **Dioxus-native** — Native hooks (`use_auth()`), context providers (`AuthProvider`), hydration-safe signals (`AuthStatus`), and router layouts (`RouteGate`).
* **Server-authoritative** — Client state is for responsive UI rendering; all security decisions happen on the server.
* **Storage-agnostic** — Zero database coupling in the core crate. Compatible with SQLite, Turso / libSQL, PostgreSQL, MongoDB, or custom APIs via capability traits.
* **Secure by default** — OWASP Argon2id password hashing, constant-time dummy verification against timing enumeration attacks, CSPRNG session IDs, and `HttpOnly; SameSite=Lax; Secure` cookies.
* **Simple API** — Strong types and associated types instead of generic signature pollution.

---

## 4. Module & Directory Layout

```text
dioxus-auth/
├── Cargo.toml
├── README.md
├── CHANGELOG.md
├── LICENSE
│
├── src/
│   ├── lib.rs                  # Public prelude, top-level exports
│   ├── error.rs                # AuthError and AuthResult
│   │
│   ├── dioxus/                 # 🌐 LAYER 1: DIOXUS RUNTIME (feature = "dioxus")
│   │   ├── mod.rs
│   │   ├── provider.rs         # AuthProvider component & hydration lifecycle
│   │   ├── context.rs          # use_auth() hook & Auth handle
│   │   ├── guards.rs           # RouteGate, RequireAuth, RedirectIfAuthed
│   │   └── server_fn.rs        # Dioxus #[server] cookie/session helpers
│   │
│   ├── engine/                 # ⚙️ LAYER 2: AUTH ENGINE & ORCHESTRATION
│   │   ├── mod.rs
│   │   ├── orchestrator.rs     # AuthEngine (coordinates login, validate, logout)
│   │   ├── builder.rs          # AuthEngineBuilder fluent constructor
│   │   ├── login.rs            # Login workflow & timing attack defense
│   │   ├── logout.rs           # Logout workflow
│   │   └── register.rs         # Registration workflow (v0.2)
│   │
│   ├── session/                # 🎫 SESSION SYSTEM
│   │   ├── mod.rs
│   │   ├── session.rs          # Session struct & AuthStatus
│   │   └── id.rs               # 256-bit CSPRNG SessionId
│   │
│   ├── storage/                # 📦 LAYER 3: CAPABILITY TRAITS & STORES
│   │   ├── mod.rs
│   │   ├── user.rs             # UserStore & PasswordUserStore traits
│   │   ├── session.rs          # SessionStore trait
│   │   └── memory.rs           # MemoryStore (in-memory test implementation)
│   │
│   ├── security/               # 🔒 CRYPTOGRAPHY & SECURITY
│   │   ├── mod.rs
│   │   ├── password.rs         # PasswordHasher trait & Argon2id
│   │   └── cookie.rs           # CookieConfig & SameSite headers
│   │
│   ├── authorization/          # 🛡️ AUTHORIZATION (v0.2)
│   │   ├── mod.rs
│   │   └── policy.rs           # Role & permission evaluation
│   │
│   └── providers/              # 🔌 EXTERNAL PROVIDERS (v0.2)
│       ├── mod.rs
│       ├── email.rs            # EmailSender trait
│       └── oauth.rs            # OAuthProvider trait
│
├── tests/                      # Integration test suite
├── examples/                   # Fullstack, basic, and SQLite examples
└── docs/                       # Technical specs & design documentation
```

---

## 5. Developer Experience

### 5.1 Setting Up the Engine on the Server

```rust
// 1. App implements capability traits for its database (e.g. SQLite, Turso, Postgres)
let users = Arc::new(MySqliteStore::new(pool));
let sessions = Arc::new(MySqliteStore::new(pool));

// 2. Build the AuthEngine
let engine = AuthEngine::builder(users, sessions)
    .session_ttl(Duration::from_secs(60 * 60 * 24 * 7)) // 7 days
    .build();
```

### 5.2 Client Application Entry

```rust
fn App() -> Element {
    rsx! {
        AuthProvider::<User> {
            initial_status: AuthStatus::Loading,
            Router::<Route> {}
        }
    }
}
```

### 5.3 Protected Views & Route Guards

```rust
#[component]
fn ProtectedLayout() -> Element {
    let auth = use_auth::<User>();
    let outcome = require_auth(&auth.status(), Route::Login {});

    rsx! {
        RouteGate {
            outcome: outcome,
            fallback: rsx! { div { "Verifying session..." } },
        }
    }
}
```

### 5.4 Consuming Auth Anywhere in the Component Tree

```rust
#[component]
fn Header() -> Element {
    let mut auth = use_auth::<User>();

    match auth.status() {
        AuthStatus::Loading => rsx! { span { "Loading..." } },
        AuthStatus::Authenticated(user) => rsx! {
            span { "Hello, {user.name}!" }
            button { onclick: move |_| { auth.logout(); }, "Log Out" }
        },
        AuthStatus::Unauthenticated => rsx! {
            Link { to: Route::Login {}, "Log In" }
        },
    }
}
```

---

## 6. Scope & Roadmap

### v0.1 (MVP - Current Focus)
- [x] Core types (`AuthStatus`, `AuthUser`, `Session`, `SessionId`, `AuthError`).
- [x] Pluggable storage traits (`UserStore`, `PasswordUserStore`, `SessionStore`).
- [x] Zero-dependency `MemoryStore` for testing and prototyping.
- [x] `PasswordHasher` trait with OWASP `Argon2id` implementation.
- [x] `AuthEngine` orchestrator with constant-time timing attack protection.
- [x] Dioxus `AuthProvider`, `use_auth()`, and hydration-safe status management.
- [x] Standard `RouteGate`, `RequireAuth`, and `RedirectIfAuthed` guards.
- [x] `CookieConfig` with `SameSite`, `HttpOnly`, and `Secure` header formatting.
- [x] Real-world SQLite/Turso database storage proof-of-concept.

### v0.2+ (Future Extensions)
- [ ] Dioxus Fullstack `#[server]` cookie extractor helpers.
- [ ] `EmailSender` capability trait (SMTP, Resend, AWS SES).
- [ ] Email verification & password reset token workflows.
- [ ] OAuth / OIDC providers (GitHub, Google, Discord).
- [ ] Passkeys / WebAuthn.
- [ ] Role-based authorization (`AuthorizationProvider`).
- [ ] Standalone database adapter crates (`dioxus-auth-turso`, `dioxus-auth-sqlx`).
