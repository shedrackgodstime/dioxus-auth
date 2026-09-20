# dioxus-auth — Agent Guidelines (Repository)

## Ground Truth

- **Rules of engagement:** `docs` live in the knowledge base at
  `knowledge-base/projects/dioxus-auth/RULES.md` (v1.0.0). Every line of code
  must comply; the stricter rule wins on conflict.
- **Architecture & DX:** `knowledge-base/projects/dioxus-auth/ARCHITECTURE.md`,
  `conclusion/dx-design.md`, and the frozen v1 specs in `archive/`.

## Non-Negotiable Development Rules

- Single import path for users: everything is re-exported through the
  `prelude`. Internal modules are `pub(crate)`.
- No `unsafe`. No `unwrap`/`expect`/`panic!` in library code. No `?` operator.
- No `let _ =`. Explicit `return` on every tail expression.
- Parking-lot locks only. No `std::collections::HashMap` (BTreeMap/Vec ok).
- `pub struct` with public fields is forbidden — use private fields + accessors.
- No `//` comments except the required `// reason:` justification on `#[allow]`
  or `#![allow]` attributes.
- Every file ≤300 lines; functions ≤100 lines; ≤4 parameters per function.
- All tests live in `tests/` (no `#[cfg(test)]` in `src/`).
- No dead code, no stubs, no placeholders.

## Verification (run before finishing any change)

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links" cargo doc --no-deps
bash scripts/check-packaging.sh
```

Only commit when the user explicitly asks.