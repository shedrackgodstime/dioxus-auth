#!/usr/bin/env bash
set -u

cd "$(dirname "$0")/.." || exit 1

whitelist=(
    # reason: the next four entries are cargo-generated artifacts, not
    # `include` entries; whitelisting keeps the check green for them.
    '^\.cargo/.*$'
    '^\.cargo_vcs_info\.json$'
    '^Cargo\.lock$'
    '^Cargo\.toml$'
    # reason: cargo always ships its normalized original manifest in the crate;
    # whitelisting keeps the check green for this cargo artifact.
    '^Cargo\.toml\.orig$'
    '^\.github/workflows/ci\.yml$'
    '^\.gitignore$'
    '^clippy\.toml$'
    '^rustfmt\.toml$'
    '^README\.md$'
    '^CHANGELOG\.md$'
    '^docs/README\.md$'
    '^docs/REVIEW\.md$'
    '^LICENSE$'
    '^LICENSE-MIT$'
    '^LICENSE-APACHE$'
    '^scripts/check-packaging\.sh$'
    '^scripts/check-ssot\.sh$'
    '^scripts/check-docs\.sh$'
    '^scripts/verify\.sh$'
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

# Reverse direction: every whitelist entry must still match something in the
# package. Without this, removing a path from Cargo.toml `include` leaves a
# dead whitelist entry behind and nobody notices the two lists diverged.
# Cargo artifacts that only exist after packaging (or only sometimes) may
# legitimately match nothing in `cargo package --list`.
zero_allowed=(
    '^\.cargo/.*$'
    '^\.cargo_vcs_info\.json$'
    '^Cargo\.lock$'
    '^Cargo\.toml\.orig$'
)
for pattern in "${whitelist[@]}"; do
    skip=0
    for allowed in "${zero_allowed[@]}"; do
        if [ "$pattern" = "$allowed" ]; then
            skip=1
            break
        fi
    done
    if [ "$skip" = 1 ]; then
        continue
    fi
    if ! printf '%s\n' "$files" | grep -Eq "$pattern"; then
        fail=1
        echo "FAIL: whitelist pattern matches nothing in the package (dead entry?): $pattern" >&2
    fi
done

for must in \
    Cargo.toml \
    README.md \
    src/lib.rs \
    src/auth.rs; do
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
