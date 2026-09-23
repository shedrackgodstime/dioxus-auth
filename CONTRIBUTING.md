# Release review checklist (Sim-0 + pre-tag)

Mechanical gates live in `scripts/verify.sh` and CI. This file is the part
that needs human eyes (acceptance `06` §13.1: "a CI assertion or a documented
review step"). Walk it before every minor-version tag.

## Sim-0 budget (plan `00` §6)

Read the quickstart in `README.md` as a beginner would and confirm each:

- [ ] **≤3 auth concepts** before the guarded route (`Auth`, `DefaultUser`,
      verbs; provider/guards arrive with names, not explanations).
- [ ] **0 traits** to implement on the quickstart path (no `AuthUser`, no
      store traits; `DefaultUser` + `memory()` carry it all).
- [ ] **0 `Arc`/handles/hashers/storage-config** on page one.
- [ ] **<25 meaningful lines** for the quickstart block (count non-blank,
      non-comment lines of the ```rust block).
- [ ] **≤50 app lines** to a guarded route including the copied login form.
- [ ] **<10 minutes** wall-clock: follow the README on a fresh checkout with
      a timer running. If it takes longer, the budget decides what gets cut,
      not the reviewer.
- [ ] **Non-durability stated**: memory dies with the process, in the
      quickstart and on `Auth::memory()`.

## Graduation (door 1 → door 2)

- [ ] Rename + add fields + swap constructor is the whole migration (follow
      the README's Graduating section literally).
- [ ] `graduation_preserves_verb_behavior` (root suite) and
      `graduation_from_memory_quickstart_preserves_behavior` (sqlite-reference
      suite) both green with the same verbs and the same error codes across
      the boundary.

## No silent contract changes

- [ ] `ErrorCode` variants only added (`#[non_exhaustive]`), messages unchanged
      or message-only diffs.
- [ ] No new required trait methods, no new required struct fields on
      `DefaultUser`, no verb signature changes. Anything else needs a
      semver-major decision recorded in `CHANGELOG.md`.
- [ ] `plan/00-dx-aim.md` amended for any gate/law change in the release.
