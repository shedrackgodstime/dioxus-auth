#!/usr/bin/env bash
# Full local gate: everything the CI Test job runs, in the same order.
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

echo "==> ssot invariants"
bash scripts/check-ssot.sh

echo "verify ok: fmt, clippy x3, tests x3, doctests, ssot"
