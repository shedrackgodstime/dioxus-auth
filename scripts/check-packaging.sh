#!/usr/bin/env bash
set -u

cd "$(dirname "$0")/.." || exit 1

whitelist=(
    '^\.cargo/.*$'
    '^\.cargo_vcs_info\.json$'
    '^\.github/workflows/ci\.yml$'
    '^\.gitignore$'
    '^AGENTS\.md$'
    '^Cargo\.lock$'
    '^Cargo\.toml$'
    # reason: cargo always ships its normalized original manifest in the crate;
    # whitelisting keeps the check green for this cargo artifact.
    '^Cargo\.toml\.orig$'
    '^clippy\.toml$'
    '^rustfmt\.toml$'
    '^README\.md$'
    '^LICENSE$'
    '^LICENSE-MIT$'
    '^LICENSE-APACHE$'
    '^scripts/check-packaging\.sh$'
    '^src/.*$'
)

if [ "${1:-}" = "--stdin" ]; then
    files=$(cat)
else
    if ! files=$(cargo package --list --allow-dirty 2>/dev/null); then
        echo "FAIL: cargo package --list errored" >&2
        exit 1
    fi
fi

fail=0

leaked=$(printf '%s\n' "$files" | grep -Ev "$(IFS='|'; echo "${whitelist[*]}")" || true)
if [ -n "$leaked" ]; then
    fail=1
    echo "FAIL: files outside the packaging whitelist would ship:" >&2
    printf '%s\n' "$leaked" | sed 's/^/  LEAK: /' >&2
fi

for must in \
    Cargo.toml \
    README.md \
    src/lib.rs \
    src/prelude.rs; do
    if ! printf '%s\n' "$files" | grep -qx "$must"; then
        fail=1
        echo "FAIL: $must is missing from the package (include list dropped it?)" >&2
    fi
done

if [ "$fail" -eq 0 ]; then
    count=$(printf '%s\n' "$files" | grep -c . || true)
    echo "packaging ok: $count files, all whitelisted, no private paths"
    exit 0
fi
exit 1
