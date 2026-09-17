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

## 2a. Adversarial verification pass (2026-09-17, LLM as hardened adversary)

Assumed every §2 claim broken and re-derived each defense from source. Results per scenario, sorted at the end.

| # | Verdict | Evidence (file:line, verified 2026-09-17) | Hole found? |
|---|---|---|---|
| S1 | ✅ HOLDS | limiter key normalized then checked **before** lookup+Argon2: `auth_engine.rs:269-272`; `find_by_identifier` after check at `:275`; dummy Argon2 only reached after limiter (`:283`); failures recorded on normalized key `:281`/`:291`; success resets `:329` | See **F1** — rate limiter is opt-in (`rate_limiter: None` default, `builder.rs:37`) |
| S2 | ✅ HOLDS | miss runs real Argon2 on pre-computed PHC dummy hash: `auth_engine.rs:283`; dummy built at `builder.rs:113-116` (real PHC string); malformed store hash → `Ok(false)` at `password.rs:58-68` (no error oracle) | Residual (already documented): lookup dispatch (`find_by_identifier` hit vs miss) is variable-time — accepted, README honest |
| S3 | ✅ HOLDS | store key = `sha256(raw)`: `id.rs:25-29`; engine always hashes before store calls (`auth_engine.rs:107`, `:164`, `:210`, `:307-308`); `SessionId::generate()` = 256-bit OsRNG (`id.rs:15-21`) — preimage/replay infeasible | None. DB leak yields unreplayable digests |
| S4 | ✅ HOLDS | cookie flow returns user only, cookie set server-side on response headers (`server_fn.rs:251-268`); `HttpOnly` always emitted (`cookie.rs:136-138`); bearer raw token goes only to native `login_bearer` clients (`server_fn.rs:270-283`) | See **F2** — `WebTokenStorage` puts the raw token in `localStorage`, readable by XSS (native/legacy path) |
| S5 | ✅ HOLDS | `login_cookie` enforces `validate_cookie_origin` **before** engine login (`server_fn.rs:259-261`); `logout_current` enforces it when cookie creds are in use (`server_fn.rs:333-339`); `validate_cookie_origin` requires Origin **present + matching** (`cookie.rs:210-222`); `SameSite=Lax` default (`cookie.rs:60`) | See **F3** — if `expected_origins = None`, `validate_cookie_origin` short-circuits `Ok(())` (`cookie.rs:211-213`) — mandatory-origins rule for `SameSite=None` is doc-enforced only (finding 1.1) |
| S6 | ✅ HOLDS | validate reads session, checks expiry/user/auth-hash/idle, then `touch_session_if_present` (`auth_engine.rs:141-146`) — a delete landing between read and touch makes the touch a no-op; contract #1 spelled out in `storage/session.rs:9-24`; barrier tests `tests/concurrency_stress.rs` green | None for contract-following stores. **F4** — the trait's *default* `touch_session_if_present` (`storage/session.rs:37-49`) is find-then-save and does **not** close the race; custom stores must override (documented, not enforced) |
| S7 | ✅ HOLDS (library) | engine/store layer never serializes anything; wire exposure is app-owned. README warning present (`README.md` "keep secrets out of the wire user") | See **F5** — README quickstart §1 & §5 model `User` with `password_hash` and render `auth.user()`, inviting the exact mistake the warning forbids |
| S8 | ✅ HOLDS | single-active login wipes prior sessions pre-issuance (`auth_engine.rs:303-305`); conditional touch covers the rotate-vs-validate race; race test `spec16_rotate_vs_validate` green | Same F4 caveat for default-touch custom stores |
| S9 | ✅ HOLDS | extract-only-expected-name logic in `cookie.rs:141-167` and `transport/extract.rs:36-63`; exact-name match (no prefix/suffix confusion); unit tests: bare rejected when `host_only` (`extract.rs:139-149`), prefixed rejected when not (`extract.rs:151-161`) | None |
| S10 | ✅ HOLDS | `splitn(2,'=')` + trim + exact compare (`extract.rs:36-63`); empty value skipped (`extract.rs:56-59`, test `:111-122`); empty `Bearer ` falls through to cookie (test `:124-135`); malformed `Basic` header falls through (test `:86-97`) | None |

### New findings from this pass (3-way sorted)

**F1 — rate limiter is opt-in (document-as-limitation).**
`AuthEngineBuilder` defaults `rate_limiter: None` (`builder.rs:37`); S1 protection exists only if the app calls `.with_rate_limiter(...)` (`builder.rs:133-136`). The README's feature list mentions the limiter but no setup doc says "do this or brute force is unthrottled."
→ *Action:* one sentence in README "Secure configuration" table. Not a code change.

**F2 — `WebTokenStorage` = raw bearer token in `localStorage` (document-as-limitation).**
`transport/web.rs:5-33` stores the raw token in `localStorage` under `dioxus_auth_session`. Any XSS can read it; `HttpOnly` cookie protection does not apply to this path. This is the known trade-off for token persistence on web (cookie flow is the XSS-resistant default and never touches `TokenStorage`).
→ *Action:* warning on `WebTokenStorage` + in README bearer section: prefer cookie flow on web; bearer+localStorage only for apps that accept XSS-token-theft risk.

**F3 — no runtime WARN when `SameSite=None` + `expected_origins: None` (out-of-scope-defer, matches 1.1's optional variant).**
`CookieConfig::default()` is `Lax`/`None`-origins (`cookie.rs:60-66`) and `validate_cookie_origin` allows all when origins unset (`cookie.rs:211-213`). Doc-enforced today; the debug-WARN idea from finding 1.1 remains unimplemented.
→ *Action:* defer; revisit post-v0.1.

**F4 — default `touch_session_if_present` does not close the resurrection race (document-as-limitation).**
The trait default is find-then-save (`storage/session.rs:37-49`) and its own doc says so; `MemoryStore` overrides it atomically (`storage/memory.rs`). Spec 16 tests cover `MemoryStore`, not hypothetical third-party stores that keep the default. Risk is app-induced, not library-induced.
→ *Action:* strengthen the trait doc contract wording is already there; consider a compile-time nudge (rename default / make required) post-v0.1.

**F5 — README quickstart contradicts the wire-hygiene warning (must-fix before v0.1, doc-only).**
README §1 defines `User { password_hash }` implementing `AuthUser`, and §5 renders `auth.user().unwrap().email` — i.e. the type flowing to the client carries the hash. Later, the README warns verbatim against returning hash-bearing types from `#[server]` fns. The on-ramp example teaches the anti-pattern the library's own docs forbid.
→ *Action:* restructure README quickstart to a public `UserView` (id/email/name) + a server-side `UserRecord` with the hash, matching what `examples/*` already do.

**F6 — duplicate "#### 10. Logout" sections in README (must-fix, cosmetic).**
README contains the `#### 10. Logout` section twice verbatim; section numbering after it is off-by-one (Event hooks = 10, sqlite demos = 11/12).
→ *Action:* dedupe and renumber.

### Pass conclusion

- 9/10 scenarios hold exactly as claimed with no new must-fix code defects.
- Code must-fix: **none**. Doc must-fix: **F5, F6** (README only).
- Document-as-limitation: F1, F2, F4. Deferred: F3.
- The **human second pair of eyes** (§ "How to run" step 2) remains open and is the only remaining gate element before v0.1.0.

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
| §2 adversarial verification pass (S1–S10) | [x] | §2a (2026-09-17); 9/10 hold, doc-only must-fixes F5/F6 |
| F5 README quickstart vs wire-hygiene warning | [ ] | §2a F5 — restructure quickstart to hash-free wire user |
| F6 README duplicate Logout section | [ ] | §2a F6 — dedupe + renumber |
| F1 rate-limiter opt-in documented | [ ] | §2a F1 — one README sentence |
| F2 WebTokenStorage/localStorage risk documented | [ ] | §2a F2 — warning on type + README bearer section |
| F4 default touch_session_if_present caveat | [x] | already documented in trait doc (`storage/session.rs:37-49`); revisit post-v0.1 |
| F3 SameSite=None runtime WARN | [ ] | deferred post-v0.1 (matches 1.1 optional variant) |
| **Human second pair of eyes** | [ ] | § "How to run" step 2 — the last open gate item |

---

## 4. How to use
- Add a finding here (numbered) before fixing it, always with file:line evidence.
- When a finding is fixed, mark it `[x]` and link the commit.
- Do not delete a finding — strike through with a resolution note.
