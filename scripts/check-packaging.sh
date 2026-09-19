#!/usr/bin/env bash
# Packaging-leak guard: fail CI if `cargo package --list` contains any file
# outside the packaging whitelist — or if the whitelist silently dropped
# something that must ship.
#
# Why this exists: the 0.1.0 pre-publish check found that unanchored
# gitignore-style globs in `[package] include` (`README.md`, `LICENSE*`)
# match at ANY depth, and cargo's package walk follows per-clone symlinks
# (scratch/, .agent-rules/) — the tarball was one `cargo publish` away from
# shipping ~80 private knowledge-base files to crates.io, irreversibly.
# `cargo publish --dry-run` does NOT catch this: it packages happily.
#
# Also guards the inverse failure: `include` that drops files cargo would
# otherwise ship (targets get silently "ignored" with only a warning, and
# publish verification still passes — that is how 7 targets went missing
# unnoticed). A missing src/ file would publish a crate that cannot build
# downstream, so src/ coverage is asserted, not assumed.
#
# Usage:
#   scripts/check-packaging.sh                    # runs cargo package --list
#   scripts/check-packaging.sh --stdin < list     # test mode: read the list
#                                                 # from stdin (one path/line)
# Test mode is an explicit flag, NOT stdin sniffing: CI `run:` steps have
# non-TTY stdin, and stdin-detection heuristics either read an empty list in
# CI (false failures) or miss file redirects (`-p` matches only FIFOs).
set -u

cd "$(dirname "$0")/.." || exit 1

# 1. The whitelist — must mirror [package] include in Cargo.toml.
whitelist=(
    '^Cargo\.toml$'
    '^Cargo\.toml\.orig$'
    '^Cargo\.lock$'
    '^\.cargo_vcs_info\.json$'
    '^CHANGELOG\.md$'
    '^README\.md$'
    '^LICENSE-MIT$'
    '^LICENSE-APACHE$'
    '^src/.*$'
    '^tests/auth_lifecycle_integration\.rs$'
    '^tests/concurrency_stress\.rs$'
    '^tests/sqlite_integration\.rs$'
    '^tests/transport_extract\.rs$'
    '^examples/basic_auth\.rs$'
    '^examples/sqlite_adapter\.rs$'
)

# 2. Get the file list: from stdin in test mode (--stdin), otherwise the
#    real command.
if [ "${1:-}" = "--stdin" ]; then
    files=$(cat)
else
    if ! files=$(cargo package --list --allow-dirty 2>/dev/null); then
        echo "FAIL: cargo package --list errored" >&2
        exit 1
    fi
fi

fail=0

# 3. Every packaged file must match the whitelist.
leaked=$(printf '%s\n' "$files" | grep -Ev "$(IFS='|'; echo "${whitelist[*]}")" || true)
if [ -n "$leaked" ]; then
    fail=1
    echo "FAIL: files outside the packaging whitelist would ship:" >&2
    printf '%s\n' "$leaked" | sed 's/^/  LEAK: /' >&2
    cat >&2 <<'MSG'

  Unanchored globs in [package] include match at any depth, and the
  package walk follows per-clone symlinks. Anchor every pattern (leading
  /) and keep this script's whitelist in sync with Cargo.toml.
MSG
fi

# 4. Canary files that MUST be present. Guards against an include list that
#    silently omits shipping code: publish verification only builds the
#    package as packaged, so a crate packaged without src/ "verifies" fine
#    and then cannot build downstream.
for must in \
    Cargo.toml \
    README.md \
    src/lib.rs \
    src/user.rs \
    tests/transport_extract.rs \
    examples/basic_auth.rs; do
    if ! printf '%s\n' "$files" | grep -qx "$must"; then
        fail=1
        echo "FAIL: $must is missing from the package (include list dropped it?)" >&2
    fi
done

# 5. src/ coverage: every file git tracks under src/ must be packaged.
missing_src=$(comm -23 \
    <(git ls-files src/ | sort) \
    <(printf '%s\n' "$files" | sort) || true)
if [ -n "$missing_src" ]; then
    fail=1
    echo "FAIL: git-tracked src/ files missing from the package:" >&2
    printf '%s\n' "$missing_src" | sed 's/^/  MISSING: /' >&2
fi

# 6. Private-path canaries: these must NEVER appear, even if someone later
#    adds a broad include on purpose.
for never in scratch/ .agent-rules/ knowledge-base/; do
    hits=$(printf '%s\n' "$files" | grep -F "$never" || true)
    if [ -n "$hits" ]; then
        fail=1
        echo "FAIL: private path $never found in the package:" >&2
        printf '%s\n' "$hits" | sed 's/^/  LEAK: /' >&2
    fi
done

if [ "$fail" -eq 0 ]; then
    count=$(printf '%s\n' "$files" | grep -c . || true)
    echo "packaging ok: $count files, all whitelisted, no private paths"
    exit 0
fi
exit 1
