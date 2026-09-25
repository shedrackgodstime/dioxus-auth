#!/usr/bin/env bash
# SSOT enforcement (E7): deterministic grep checks that single-home concepts
# have exactly one definition. See AUDIT-SSOT-2026-09-23.md Part C.
set -u

cd "$(dirname "$0")/.." || exit 1

fail=0

# S3: the `__Host-` spelling lives in one const (src/security.rs). String
# literals anywhere else in src/ are a second definition. (Doc prose and the
# cookies.rs contract-pin test may cite the spelling; only literals count.)
if grep -rn '"__Host-' src/ | grep -v '^src/security.rs:'; then
    fail=1
    echo "FAIL: __Host- literal outside src/security.rs (use CookieConfig::effective_name)" >&2
fi

# S1: HTTP response construction lives in the axum middleware only. Any other
# src/ file naming StatusCode is a second classifier.
if grep -rn 'StatusCode' src/ | grep -v '^src/dioxus/server/axum.rs:'; then
    fail=1
    echo "FAIL: StatusCode outside the axum middleware (render via ServerError::status_code)" >&2
fi

# S10: registration has one path. register_global is registry-internal.
if grep -rn 'register_global' src/ tests/ | grep -v '^src/dioxus/server/registry.rs:'; then
    fail=1
    echo "FAIL: register_global referenced outside registry.rs (use server_init)" >&2
fi

# Canonical fns must be defined exactly once.
for fn in 'fn auth_error_status' 'fn request_origin_header' 'fn check_state_changing_origin' 'fn current_config' 'fn effective_name'; do
    count=$(grep -rn "$fn" src/ | wc -l)
    if [ "$count" -ne 1 ]; then
        fail=1
        echo "FAIL: expected exactly one definition of '$fn', found $count" >&2
    fi
done

if [ "$fail" -eq 0 ]; then
    echo "ssot ok: single-home concepts have one definition each"
    exit 0
fi
exit 1
