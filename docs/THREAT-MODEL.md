# Threat model

What `dioxus-auth` guarantees, what it assumes, and what it explicitly does
not cover. Read this before deploying, auditing, or extending the crate.

## Assets

- User credentials (passwords, hashes) and the mapping identifier → user.
- Session tokens: wire tokens in cookies/headers, storage-form hashes in
  the session store.
- Authenticated identities served to components and server functions.

## Trust boundaries

- **Client is untrusted for decisions.** `use_session()` and context state
  are render hints. Every server decision re-validates via `require_user()`
  / `current_user` / `validate_session`.
- **The store is trusted with hashes, never plaintext.** The engine hashes
  before any store call; stores compare byte-for-byte. A leaked store yields
  Argon2 hashes (expensive to crack) and `sha256` session ids (unusable as
  tokens — the raw wire value never reaches storage).
- **The network between app and store is trusted.** No TLS-in-store, no
  encrypted-at-rest beyond hashing. Deploy stores on trusted networks or add
  transport security yourself.

## Guarantees

- **No user enumeration** through errors or timing: unknown identifiers,
  wrong passwords, taken sign-ups, and corrupt hashes all cost one hash plus
  one verification and return `InvalidCredentials`.
- **Session opacity**: 256-bit CSPRNG tokens; storage sees `sha256(raw)`
  only; secrets never render in `Debug`/`Display` (redaction tests pin this).
- **Revocation is real**: sign-out and password change delete rows; validation
  drops expired, orphaned, version-mismatched, and idle-breached sessions
  eagerly. Failures are fail-closed (nothing granted on store error).
- **CSRF backstop**: state-changing cookie operations require a present,
  matching `Origin` when origins are configured; `__Host-` mode binds name,
  path, and `Secure`.
- **Single-active enforcement** is exact per process (login lock); across
  processes it needs a transactional store.

## Assumptions (your responsibility)

- System clock is roughly correct. Expiry is wall-clock: large backwards
  steps can re-validate sessions whose expiry passed unobserved. Expired
  sessions delete eagerly on use, but idle stores need background sweeping
  for hard revocation deadlines.
- `OsRng` is available and sound (sessions, salts).
- Argon2id defaults (m = 19 MiB, t = 2, p = 1) fit your threat profile;
  raise costs with `Argon2Hasher::with_params` for high-value deployments.
- Rate limiting is **opt-in**: any credential endpoint facing the network
  needs `InMemoryRateLimiter::prod()` or tighter. Unconfigured, there is no
  throttle.
- `expected_origins` is set for every `SameSite=None` deployment and
  recommended otherwise. Unset, there is no origin gate.
- Token storage implementations are fast and non-blocking (called
  synchronously during render) and at least as confidential as memory.
- Custom stores uphold the documented contracts: byte-exact matching,
  atomic provisioning, conditional touch, silent no-op updates.

## Explicitly out of scope

- Transport security (TLS), at-rest encryption beyond hashing, HSMs.
- Phishing, social engineering, endpoint compromise, XSS exfiltrating
  non-`HttpOnly` state (keep session cookies `HttpOnly`).
- Denial of service: Argon2 verification is deliberately expensive; without
  rate limiting, login endpoints are CPU-exhaustion vectors. MemoryStore is
  single-process with no background cleanup.
- Async-driver stores (`sqlx` and friends): sync traits panic under
  `block_on` in the server pool. Sync drivers only until async variants
  exist (design question, not a bug).
- Anonymity, unlinkability, or hiding *whether* a session exists from the
  store operator.
