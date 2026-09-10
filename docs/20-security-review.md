# 20 — Security Review: Standing Adversarial Review & Attack Scenarios

* **Status**: ACTIVE — living. First-pass self-review + LLM-adversary pass started 2026-09-08; findings below are CODE-GROUNDED (file:line).
* **Drives**: threat-model §5 final checklist; **blocks v0.1.0 tag until this is green** (research/18 §5 last item).
* **Anchors**: `scratch/research/18-threat-model-defense-map.md` (lives in the private knowledge-base via the `scratch/` symlink; not repo-tracked) (scorecard = §5), specs 14/15/16.

> **How to run this review (human)**
> 1. Work the §2 attack scenarios — answer each with file:line evidence, not vibes.
> 2. Get a **second pair of eyes** (another dev who knows Rust + web security but NOT this crate's internals). Time-box 1–2h, hand them §2 + §5, ask: "find anything that contradicts a claim."
> 3. Run an **LLM as hardened adversary**: give it §2 + the key source files + "assume every claim is broken; find the hole." LLMs are useful here precisely because they are not invested in the code being correct.
> 4. 3-way sort each finding: **must-fix** (before v0.1) / **document-as-limitation** / **out-of-scope-defer**.
> 5. Do not tag until every `[ ]` in §5 is checked and each accepted residual is stated in the README.

---

## 1. First-pass findings (2026-09-08, code-grounded)

### 1.1 `SameSite=None` ⇨ Origin enforcement must be MANDATORY (must-fix before v0.1)
- **Where**: `src/security/cookie.rs:205-218` (`validate_cookie_origin` returns `Ok` immediately when `expected_origins` is `None`); `src/security/cookie.rs:180-196` (`validate_origin` returns `Valid` when Origin absent).
- **Scenario**: `expected_origins = None` (the **default**). CSRF then rests entirely on `SameSite`. If any app sets `SameSite::None` (needed for cross-site/embedded/SPA-in-iframe), a cross-site form/request can carry the ambient session cookie and hit `login_cookie`/`logout_current` — which, per spec 15, are the state-changing ops that *should* demand Origin.
- **Fix**: the README "secure config" section must state: **SameSite=None ⇒ `expected_origins` must be configured**. Optionally, `validate_cookie_origin` could WARN (debug) when `same_site == None && expected_origins.is_none()`. At minimum: document prominently. Mark `[x]` in §5 only after README carries it.
- **RESOLVED 2026-09-08**: README gained a "Secure configuration" table (`SameSite=None` row marks `expected_origins` as **mandatory**); the debug-WARN variant remains optional future work.

### 1.2 Rate limiter is keyed by raw identifier → case/whitespace bypass (must-fix)
- **Where**: `src/engine/auth_engine.rs:265-267` `limiter.check(identifier)`; the key is the raw `identifier` string from the request. `find_by_identifier` is called *after*, with the same raw string (`:269`).
- **Scenario**: attacker rotates spelling — `User@x.com`, `user@x.com`, ` user@x.com` — to get 10 fresh attempts per case/spacing variant. Works if the store treats identifiers case-insensitively (very common: `WHERE lower(email) = ?1`).
- **Fix**: normalize the rate-limit key (lowercase + trim) independently of whether the store is case-insensitive, so the limiter and the lookup agree. Add a test: `undefined_case_variants_share_rate_limit_budget`.
- **RESOLVED 2026-09-08**: `do_login` now keys the limiter on `identifier.trim().to_lowercase()` (store lookup still uses the raw identifier); test `rate_limit_key_is_normalized_across_case_and_whitespace` proves `RateNorm@…` + `" ratenorm@…"` share one budget → `RateLimited`.

### 1.3 `check` prunes expired attempts but `max_attempts` is off-by-one per window edge (minor / document)
- **Where**: `src/security/rate_limit.rs:58-63`. `retain` drops attempts older than `window`, then rejects if `len >= max_attempts`. Because timestamps are stored on `record_attempt` (after a failed verify), a *pending-but-unfailed* attempt isn't counted — correct. Minor: an attempt exactly at window boundary may slip; acceptable, document in README ("sliding window is an approximation").
### 1.4 `verify_password` reads the *stored* `PasswordHash` — malformed store hash is an oracle-free `Ok(false)` (OK)
- **Where**: `src/security/password.rs:58-68`. Unparseable hash → `Ok(false)` (no error). Good: an attacker cannot distinguish malformed-store vs bad-password via error codes. Variable-time lookup remains (documented in README). No change.

### 1.5 Dummy-hash is **not** constant-time — README now honest (OK, documented)
- **Where**: `src/engine/auth_engine.rs:277`. Verified the README no longer claims "constant-time". The lookup `find_by_identifier` + dispatch still differ in timing between hit/miss (research/18 A6). Accepted residual; keep documented.

### 1.6 Logged-out-but-in-flight logout race — closed by conditional touch (OK)
- **Where**: `src/engine/auth_engine.rs:137-145`; `src/storage/memory.rs` atomic override; SQLx conditional `UPDATE … WHERE id`. The barrier tests (`tests/concurrency_stress.rs` `spec16_*`) pass. Confirmed no resurrection path when stores implement contract #1.

### 1.7 Wire-vs-store token separation (OK)
- **Where**: `src/session/id.rs:18-30` (256-bit CSPRNG + `sha256(raw)` storage form). Confirmed raw token is only ever the wire value; store key is always the digest. A DB leak yields no replayable token.

### 1.8 Axum `auth_middleware` swallows CSRF as "unauthenticated" (ACCEPTED, spec 15 §4 note)
- **Where**: `src/dioxus/axum.rs` `auth_middleware` maps `current_user(...).ok().flatten()` → any error (incl. `Csrf`) becomes `None` (401-ish) rather than 403. `require_auth_middleware`/`permission_middleware` already map `Csrf → 403`. Decide: (a) accept & document that `auth_middleware` treats CSRF as anonymous, or (b) map `Csrf → 403` there too for parity. Recommend (b) — cheap.
- **RESOLVED 2026-09-08**: option (b) implemented — `auth_middleware` now returns `StatusCode::FORBIDDEN` on `AuthError::Csrf` (with a spec-15 security note in the code); all other errors still map to anonymous `None`.

---

## 2. Attack scenarios to work (answer each with file:line)

| # | Attacker goal | Entry | Must show |
|---|---|---|---|
| S1 | Brute-force real user password | `POST login` | limiter fires BEFORE Argon2 (`auth_engine.rs:265`); case/whitespace variants share budget (ties to 1.2) |
| S2 | Enumerate valid emails via timing | `POST login` | miss runs dummy Argon2 (`:277`); explain residual variable-time lookup |
| S3 | Stolen DB → impersonate sessions | dump `sessions` | only `sha256(raw)` present (`id.rs:26`); no raw token column |
| S4 | XSS steals session | any JS surface | raw token never in `#[server]` return / RSX; `HttpOnly` cookie (`cookie.rs:133-136`) |
| S5 | CSRF state change (logout/login) via cookie | cross-site request | Origin required on cookie ops when configured (`validate_cookie_origin`); SameSite default Lax |
| S6 | Revive a logged-out session | concurrent logout+validate | conditional touch no-ops (`auth_engine.rs:141-145`); race tests green |
| S7 | Hash-bearing `User` leaks over wire | any `#[server]` fn | README warning; examples return hash-free public views |
| S8 | Replay a rotated-out session | re-login single-active | `delete_user_sessions` on login (`:297-299`); race test `spec16_rotate_vs_validate` |
| S9 | `__Host-` bypass via bare name | send bare cookie | `extract_session_id` rejects bare when `host_only` (tests) |
| S10 | Truncated/edge-shaped tokens | headers | exact-name matching, empty-value ignored (extract tests) |

---

## 3. Scorecard (mirrors research/18 §5)

| Item | Checked | Evidence |
|---|---|---|
| T4 cookie-only web | [x] | spec/14 committed; `login_cookie` returns user only |
| T5/T6 Origin + `__Host-` | [x] | spec/15 committed; middleware reads Origin |
| T7 conditional touch | [x] | spec/16 committed; race tests green |
| Rate limiter wired + tests | [x] | `do_login` check/record + tests |
| README honest timing + public-user warning | [x] | committed 0f503d6 |
| CI green (all-targets, fmt, doc) | [x] | verified locally |
| **Independent security review** | [~] | ← THIS DOC; Stage-1 self + LLM pass done (§1). Human second-pass still open |
| 1.1 SameSite=None ⇒ Origin mandatory documented | [x] | README "Secure configuration" table |
| 1.2 Rate-limit key normalization | [x] | `do_login` trim+lowercase; test green |
| 1.8 auth_middleware CSRF→403 parity | [x] | implemented (option b) |
| 1.3 sliding-window approximation documented | [x] | README rate-limiter note |

---

## 4. How to use
- Add a finding here (numbered) before fixing it, always with file:line evidence.
- When a finding is fixed, mark it `[x]` and link the commit.
- Do not delete a finding — strike through with a resolution note.
