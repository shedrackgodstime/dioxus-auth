# Dioxus Native Fullstack Auth Architecture Blueprint

> **Design Goal:** Provide a first-class, idiomatic authentication experience that feels as native to Dioxus as NextAuth feels to Next.js or Lucia felt to SvelteKit—leveraging Axum's type-safe Tower layers, Dioxus server functions, and SSR hydration.

---

## 1. The Core Analogy: Next.js vs. Dioxus Fullstack

| Next.js Concept | What Next.js Does | Native Dioxus Equivalent | What Dioxus Does Better |
|---|---|---|---|
| `middleware.ts` | V8 edge function runs before any request; checks cookies and issues `NextResponse.redirect()` | **Axum `AuthLayer` / Tower Service** | Native compiled Rust async; direct database access; zero V8/Node restrictions |
| `getServerSession()` / `auth()` | Server Component helper to inspect session | **`server_auth::<User>()` / Extractor** | Type-safe extractor directly in `#[server]` functions |
| `<SessionProvider>` | React Context wrapping the tree | **`<AuthProvider<User>>`** | Dioxus Signal-driven (`AuthStatus`: `Loading`, `Authenticated`, `Unauthenticated`) |
| Client Guards (`useEffect`) | Client-side redirect if unauthed | **`<RouteGate>` Layout Component** | Hydration-safe: prevents premature redirects and layout flashes |
| Server Actions Set-Cookie | `cookies().set()` inside action | **`auth.login()` in `#[server]`** | Automatically builds RFC 6265 compliant `Set-Cookie` with `HttpOnly`, `SameSite=Lax` |

---

## 2. The 4 Native Pillars of `dioxus-auth`

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. THE SERVER GATE (Axum Tower Layer)                                       │
│    - dioxus::server::router(App).layer(AuthLayer::new(engine))              │
│    - Global cookie parsing & session resolution                             │
│    - Server-side route pre-filtering (redirects before SSR starts!)         │
│    - Injects AuthSession<User> into request extensions                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ 2. THE SERVER FUNCTION CONTEXT (#[server] integration)                      │
│    - server_auth::<User>() accessor                                         │
│    - auth.require_user() -> 401 Unauthorized for APIs                       │
│    - auth.login(email, password) -> validates & queues Set-Cookie           │
│    - auth.logout() -> revokes session & queues Delete-Cookie                │
├─────────────────────────────────────────────────────────────────────────────┤
│ 3. THE HYDRATION BRIDGE (Persistent Sessions across F5 / Refreshes)         │
│    - SSR: Server injects initial session into root HTML context             │
│    - Client Mount: use_server_future restores session from cookie           │
│    - Explicit Loading state prevents flashing                               │
├─────────────────────────────────────────────────────────────────────────────┤
│ 4. REACTIVE CLIENT ERGONOMICS                                               │
│    - use_auth::<User>() (unconditionally Copy handle)                       │
│    - <RouteGate> for layouts                                                │
│    - <SignedIn> and <SignedOut> for declarative UI                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Pillar 1: The Server Gate (`AuthLayer`)

In Next.js, developers put a `middleware.ts` at the root of their project to protect `/dashboard/*`.
In Dioxus, the native equivalent is an **Axum Tower Layer** mounted in `dioxus::serve`:

```rust
#[cfg(feature = "server")]
fn main() {
    dioxus::serve(|| async move {
        // 1. Initialize storage and engine
        let engine = Arc::new(AuthEngine::builder(user_store, session_store).build());

        // 2. Mount native Dioxus router with AuthLayer
        Ok(dioxus::server::router(App)
            .layer(
                AuthLayer::new(engine.clone())
                    // Optional: HTTP-level pre-routing redirect (zero JS/WASM overhead!)
                    .protect_prefix("/dashboard", "/login")
                    .cookie_name("dioxus_session")
            ))
    });
}
```

### How `AuthLayer` Works on Every HTTP Request:
1. **Extract Cookie**: Reads `Cookie: dioxus_session=<session_id>`.
2. **Resolve Session**: Calls `engine.validate_session(&session_id)`.
3. **HTTP-Level Interception**:
   - If the request path begins with `/dashboard` and the session is invalid, the middleware intercepts the request immediately and returns an HTTP `307 Temporary Redirect` to `/login`.
   - **Benefit**: The browser redirects immediately. The protected page HTML is never rendered or downloaded by unauthorized users.
4. **Context Injection**:
   - If the user is authenticated, it inserts `AuthSession<User>` into Axum's request extensions (`request.extensions_mut().insert(...)`).
   - Every downstream server function and SSR component now has instantaneous, zero-cost access to the user!

---

## 4. Pillar 2: Native Server Functions (`#[server]`)

Inside `#[server]` functions, developers should never have to manually parse cookie strings or craft raw HTTP headers.

### Scenario A: Protecting an API / Data Endpoint
```rust
#[server]
pub async fn get_secret_metrics() -> Result<Vec<String>, ServerFnError> {
    // 🛡️ One-line native user extraction:
    let auth = server_auth::<AppUser>()?;
    let user = auth.require_user()?; // Fails with 401 Unauthorized if not logged in!

    // Fetch data belonging to this user:
    Ok(db.get_metrics_for(user.id()).await?)
}
```

### Scenario B: Logging In with Automatic Cookie Emission
```rust
#[server]
pub async fn login_action(email: String, password: String) -> Result<AppUser, ServerFnError> {
    let auth = server_auth::<AppUser>()?;
    
    // 1. Verifies password via Argon2id (with timing-attack defense)
    // 2. Generates 256-bit CSPRNG session in storage
    // 3. Queues RFC-compliant Set-Cookie header (HttpOnly, SameSite=Lax, Secure)
    let user = auth.login(&email, &password).await?;
    
    Ok(user)
}
```

### Scenario C: Logging Out
```rust
#[server]
pub async fn logout_action() -> Result<(), ServerFnError> {
    let auth = server_auth::<AppUser>()?;
    
    // 1. Deletes session from SessionStore
    // 2. Queues Set-Cookie; Max-Age=0 header to wipe cookie from browser
    auth.logout().await?;
    
    Ok(())
}
```

---

## 5. Pillar 3: The Hydration Bridge (Fixing the F5 / Page Refresh Problem)

### Why the F5 bug happened in our first test:
In our initial demo, `login_server` only stored the user in the client-side memory signal. It did not set a browser cookie, and when the user refreshed the page, client memory reset to `AuthStatus::Unauthenticated`.

### The Native Fix:
1. **Cookie Persistence**: When `login_action` runs, the browser stores the `HttpOnly` cookie.
2. **Hydration Lifecycle**:
   ```rust
   #[component]
   fn App() -> Element {
       rsx! {
           AuthProvider::<AppUser> {
               // Initial status starts as Loading
               // AuthProvider automatically calls `get_current_user()` on mount
               Router::<Route> {}
           }
       }
   }
   ```
3. **During Page Load / Refresh**:
   - Step 1: App mounts with status `AuthStatus::Loading`.
   - Step 2: `<RouteGate>` displays the `fallback` (e.g. spinner or skeleton) instead of prematurely booting the user to `/login`.
   - Step 3: Background query `get_current_user()` reaches the server with the cookie.
   - Step 4: Server confirms session $\to$ status transitions to `AuthStatus::Authenticated(user)`.
   - Step 5: `<RouteGate>` immediately reveals `<Dashboard>`!

---

## 6. Pillar 4: User Registration Flow

Every real auth system must support new user registration:

```rust
// On AuthEngine:
impl<U: PasswordUserStore, S: SessionStore<...>> AuthEngine<U, S> {
    pub async fn register(
        &self,
        identifier: &str,
        raw_password: &str,
        user_builder: impl FnOnce(String) -> U::User,
    ) -> AuthResult<(U::User, Session<...>)> {
        // 1. Validate password policy (e.g. min length 8)
        // 2. Check if identifier already exists
        // 3. Hash password using Argon2id
        // 4. Save user and create initial session
    }
}
```
