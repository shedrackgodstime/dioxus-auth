# The Dioxus-Native Design Doctrine: Making Auth Feel Built-In

> **The North Star Statement:**  
> *"The goal is NOT to build an authentication library that works with Dioxus. The goal is to design an authentication system whose Dioxus integration feels like a natural, inevitable extension of the Dioxus programming model."*

---

## 1. The Core Philosophy: Two Worlds, One Bridge

Authentication inherently spans two entirely different computing environments:
1. **The Server & Database World**: Cryptography (Argon2id), timing-attack defenses, session tables, HTTP cookies, CSRF validation, and database pools.
2. **The Client & UI World**: Virtual DOM, reactive signals, component trees, layouts, routing, and user interactions.

The fatal mistake of "bolted-on" authentication libraries is that **they drag the complexity of the server world into the UI world**. They make frontend components deal with token strings, cookie expirations, HTTP header parsing, and state listeners.

`dioxus-auth` enforces a strict, beautiful architectural division:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. THE FRONTEND UI WORLD (Speaks Pure Dioxus)                               │
│    • `<AuthProvider<User>>` at root                                         │
│    • `use_auth::<User>()` hook                                              │
│    • Unconditionally `Copy` handle (Zero clone tax in event closures!)      │
│    • `<SignedIn>` and `<SignedOut>` declarative components                  │
│    • `<RouteGate>` composing with Dioxus Router layouts and `<Outlet />`    │
│    • 3-State Reactive Signal (`Loading`, `Authenticated`, `Unauthenticated`)│
├─────────────────────────────────────────────────────────────────────────────┤
│ ─── TRANSPARENT RPC BRIDGE (Dioxus #[server] Functions & Axum AuthLayer) ── │
├─────────────────────────────────────────────────────────────────────────────┤
│ 2. THE SERVER & STORAGE WORLD (Speaks Pure Application Rust)                │
│    • `AuthEngine` orchestrating verification and session lifecycles         │
│    • `UserStore` & `SessionStore` capability traits                         │
│    • Zero database lock-in (Turso, SQLite, PostgreSQL, MongoDB, Redis)      │
│    • Argon2id + Constant-time dummy verification + SHA-256 session hashing  │
└─────────────────────────────────────────────────────────────────────────────┘
```

- **A frontend developer** writing Dioxus components never sees SQL, never sees Argon2, and never handles raw cookies.
- **A backend developer** configuring the server never touches virtual DOMs or layout routes.
- **The bridge between them** is Dioxus's native `#[server]` functions and Axum layers.

---

## 2. The 4 Golden Rules of Dioxus-Native Design

Looking into how the Dioxus core team built `dioxus-router`, `dioxus-signals`, and `dioxus-fullstack`, all official Dioxus subsystems obey four immutable principles:

### Rule 1: Speak Dioxus Vocabulary, Don't Invent an "Auth DSL"

In Dioxus, the entire universe is constructed from five primitives:
```text
Provider ──> Context ──> Hook ──> Signals ──> RSX Components
```

If an auth library introduces foreign concepts like *"Event Listeners"*, *"Imperative State Managers"*, *"Session Observers"*, or *"Custom Route Matchers"*, it immediately feels alien and bolted-on.

`dioxus-auth` uses exclusively Dioxus concepts:
- **`AuthProvider`**: A standard Dioxus component that initializes root context.
- **`use_auth()`**: A standard hook that accesses the context.
- **`AuthStatus`**: A 3-state reactive signal (`Loading`, `Authenticated(User)`, `Unauthenticated`).
- **`RouteGate`**: A standard layout component that yields to `Outlet::<Route> {}`.
- **`SignedIn` / `SignedOut`**: Standard declarative components using RSX conditional rendering.

---

### Rule 2: Unconditional `Copy` Handles (The Zero-Clone Tax)

In Dioxus 0.7, every primary handle is **unconditionally `Copy`**:
- `Signal<T>` is `Copy`.
- `Navigator` is `Copy`.
- `Coroutine<T>` is `Copy`.

Why? Because in Rust UI components, you are constantly moving handles into closures (`onclick`, `oninput`, `spawn`):

#### ❌ The Bolted-On Feeling (The Clone Tax Nightmare):
```rust
// An alien library requiring manual cloning:
let auth_clone1 = auth.clone();
let auth_clone2 = auth.clone();
let nav = use_navigator();

rsx! {
    button {
        onclick: move |_| {
            let auth = auth_clone1.clone();
            spawn(async move {
                auth.logout().await;
            });
        },
        "Logout"
    }
}
```

#### ⭐️ The Dioxus-Native Feeling (Zero Clone Tax):
```rust
// dioxus-auth: Auth<User> is unconditionally Copy!
let auth = use_auth::<User>();
let nav = use_navigator();

rsx! {
    button {
        onclick: move |_| async move {
            auth.logout().await;
            nav.push(Route::Home {});
        },
        "Logout"
    }
}
```
`Auth<User>` wraps a Dioxus generational signal copy handle. It can be moved into any closure, async task, or child component without `.clone()`.

---

### Rule 3: Compose With the Router, Never Shadow It

A bolted-on library attempts to reinvent routing by creating custom route macros or wrapping components in artificial auth wrappers:
```rust
// ❌ BOLTED-ON: Reinventing the router with custom wrappers
AuthProtectedRoute {
    path: "/dashboard",
    component: Dashboard
}
```

Dioxus already has a world-class, type-safe router: `#[derive(Routable)]` with nested `#[layout]` support.

A truly native auth library **composes directly with Dioxus layouts and Outlets**:

```rust
#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[layout(Navbar)]
        #[route("/")]
        Home {},
        #[route("/login")]
        Login {},
        #[layout(ProtectedLayout)]
            #[route("/dashboard")]
            Dashboard {},
            #[route("/settings")]
            Settings {},
}

#[component]
fn ProtectedLayout() -> Element {
    let auth = use_auth::<AppUser>();
    let outcome = require_auth(&auth.status(), Route::Login {});

    // RouteGate renders Outlet::<Route> {} on Allow,
    // renders fallback spinner on Loading,
    // and navigates to target on Redirect!
    rsx! { RouteGate { outcome: outcome } }
}
```
The developer does not learn a new routing system. They simply use Dioxus layouts exactly as the Dioxus documentation teaches.

---

### Rule 4: Hydration-Safe 3-State Reactivity (No Flashes, No F5 Logouts)

In naive web libraries, auth is modeled as a simple boolean:
```rust
// ❌ The Naive Boolean Trap
let is_logged_in: bool = false;
```
During SSR or WASM client hydration, `is_logged_in` starts as `false` for 50 milliseconds while the session cookie is checked.
**Result:** The router sees `false`, immediately redirects the user to `/login`, and the screen flashes or logs the user out on every page refresh!

`dioxus-auth` models authentication as a **strict 3-state machine**:

```text
                     ┌──────────────────┐
                     │     Loading      │ ──> RouteGate displays fallback spinner.
                     └────────┬─────────┘     (Zero premature redirects!)
                              │
             Session check completes in background:
                              │
             ┌────────────────┴────────────────┐
             ▼                                 ▼
┌──────────────────────────┐     ┌───────────────────────────┐
│  Authenticated(AppUser)  │     │      Unauthenticated      │
│  RouteGate renders page  │     │  RouteGate replaces route │
└──────────────────────────┘     └───────────────────────────┘
```

On initial mount or F5 refresh:
1. App boots in `Loading`.
2. `<RouteGate>` holds the fallback element (spinner/skeleton) instead of prematurely booting the user to `/login`.
3. Background verification confirms the session cookie.
4. Status transitions to `Authenticated(user)`, and `<RouteGate>` renders the protected page seamlessly.

---

## 3. Side-by-Side Code Walkthrough: What It Feels Like

### 1. In the Navigation Bar: Declarative Visibility
Instead of writing manual `if let Some(user) = ...` checks in every single component:

```rust
#[component]
fn Navbar() -> Element {
    let auth = use_auth::<AppUser>();

    rsx! {
        nav {
            Link { to: Route::Home {}, "Home" }

            // ⭐️ Renders ONLY when authenticated:
            SignedIn::<AppUser> {
                span { "Welcome back, {auth.user().unwrap().name}!" }
                button { onclick: move |_| auth.logout(), "Sign Out" }
            }

            // ⭐️ Renders ONLY when signed out:
            SignedOut::<AppUser> {
                Link { to: Route::Login {}, "Sign In" }
            }
        }
    }
}
```

### 2. In Protected Server Functions: Type-Safe Extraction
Inside a `#[server]` function, the developer extracts the user in one clean line:

```rust
#[server]
pub async fn get_secret_metrics() -> Result<Vec<String>, ServerFnError> {
    // 🛡️ One-line native user extraction from Axum request extensions:
    let auth = server_auth::<AppUser>()?;
    let user = auth.require_user()?; // Fails with 401 Unauthorized if not logged in!

    Ok(database::get_metrics_for(user.id()).await?)
}
```

---

## 4. Summary: The Developer Reaction

When a Dioxus developer installs `dioxus-auth`:

```rust
use dioxus::prelude::*;
use dioxus_auth::prelude::*;
```

They should never have to stop and think: *"Wait, how does this library do things?"*

They should look at the code and say:

> **"This is just Dioxus. It uses my components, my router, my signals, and my server functions. It feels like it was here all along."**
