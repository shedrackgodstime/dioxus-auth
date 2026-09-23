#!/usr/bin/env bash
# Full local gate: fmt, lints, checks, tests, doctests, docs build,
# packaging, and the invariant scripts. Everything mergeable except the
# toolchain-gated jobs (MSRV, audit installs, coverage, wasm stay in CI).
# Single home for the check matrix (CI calls this script; see
# .github/workflows/ci.yml) so local runs and CI runs cannot diverge.
#
# `--workspace` throughout: the sqlite-reference example is a member, and a
# default-only invocation would silently skip it until it rotted.
set -eu

cd "$(dirname "$0")/.." || exit 1

echo "==> fmt"
cargo fmt -- --check

echo "==> clippy (default features)"
cargo clippy --workspace --all-targets -- -D warnings -W clippy::pedantic

echo "==> clippy (dioxus)"
cargo clippy --workspace --all-targets --features dioxus -- -D warnings -W clippy::pedantic

# The dioxus/fullstack layers are cfg-gated out of the default build, so a
# default-only clippy never sees them. Each layer is gated explicitly.
echo "==> check (fullstack without server)"
cargo check --workspace --features dioxus-fullstack --lib

echo "==> clippy (fullstack)"
cargo clippy --workspace --all-targets --features dioxus-fullstack,server -- -D warnings -W clippy::pedantic

echo "==> tests (default features)"
cargo test --workspace --all-targets

echo "==> tests (dioxus)"
cargo test --workspace --all-targets --features dioxus

echo "==> tests (fullstack)"
cargo test --workspace --all-targets --features dioxus-fullstack,server

echo "==> doctests"
cargo test --workspace --doc

echo "==> docs build"
RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links" cargo doc --no-deps --features dioxus-fullstack

echo "==> packaging"
bash scripts/check-packaging.sh

echo "==> doc invariants"
bash scripts/check-docs.sh

echo "==> ssot invariants"
bash scripts/check-ssot.sh

echo "verify ok: fmt, clippy x3, checks, tests x3, doctests, docs, packaging, ssot"
