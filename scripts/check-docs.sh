#!/usr/bin/env bash
# Doc gates (06 §13.6): no private citations, no future-tense markers, module
# docs everywhere, first sentences within budget, every allow justified.
set -u

cd "$(dirname "$0")/.." || exit 1

fail=0

# D1/D7: private-KB citations and design-journal pointers must never ship in
# source. (N4-style domain terms like "N4 verdict" live in prose, not as
# citations, and are out of scope for this grep. Rule justifications cite
# content — "explicit return on every tail expression" — never rule numbers.
# Plan/gate references (`plan/00`, `Gate 2`) are KB vocabulary, meaningless
# to users; lowercase domain prose like "origin gate" does not match.)
if grep -rnE 'RULES|AM[0-9]+|review finding|Spec [0-9]+|scratch/|conclusion/|archive/|plan/0[0-9]|Gate [0-9]' \
    src/ tests/ examples/sqlite-reference/src examples/sqlite-reference/tests \
    --include='*.rs'; then
    fail=1
    echo "FAIL: private citations in source (see above)" >&2
fi

# Future-tense / placeholder markers: shipped docs describe what exists.
if grep -rnE 'TODO|FIXME|XXX|FUTURE' \
    src/ tests/ examples/sqlite-reference/src examples/sqlite-reference/tests \
    --include='*.rs'; then
    fail=1
    echo "FAIL: placeholder markers in source (see above)" >&2
fi

# Every source file opens with module docs.
while IFS= read -r file; do
    if ! head -n 1 "$file" | grep -q '^//!'; then
        fail=1
        echo "FAIL: $file does not open with //! module docs" >&2
    fi
done < <(find src examples/sqlite-reference/src -name '*.rs')

# First sentences: module docs and item docs stay within 15 words (§10.2).
if ! python3 - <<'PYEOF'; then
import glob

violations = []
for pattern in ('src/**/*.rs', 'examples/sqlite-reference/src/**/*.rs'):
    for path in glob.glob(pattern, recursive=True):
        lines = open(path).read().splitlines()
        # Module doc: first non-empty //! line.
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('//!'):
                text = stripped[3:].strip()
                if text:
                    first = text.split('.')[0]
                    count = len(first.split())
                    if count > 15:
                        violations.append((path, first[:80], count))
                    break
        # Item docs: first /// line of each block (skipping code fences).
        in_fence = False
        prev_doc = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('/// ```'):
                in_fence = not in_fence
            is_doc = (
                stripped.startswith('///')
                and not stripped.startswith('/// #')
                and not in_fence
            )
            if is_doc and not prev_doc:
                text = stripped[3:].strip()
                if text and not text.startswith(('[', '#', '`')):
                    first = text.split('.')[0]
                    count = len(first.split())
                    if count > 15:
                        violations.append((path, first[:80], count))
            prev_doc = is_doc

for path, text, count in sorted(violations):
    print('FAIL: %s first sentence has %d words: %s' % (path, count, text))
raise SystemExit(1 if violations else 0)
PYEOF
    fail=1
    echo "FAIL: first-sentence budget exceeded (see above)" >&2
fi

# Every allow/expect carries a // reason: justification within 5 lines above.
while IFS= read -r hit; do
    file=${hit%%:*}
    lineno=${hit#*:}
    if ! head -n "$lineno" "$file" | tail -n 6 | grep -q '// reason:'; then
        fail=1
        echo "FAIL: $file:$lineno allow/expect without // reason:" >&2
    fi
done < <(grep -rn '#\[allow\|#\[expect' src examples/sqlite-reference/src --include='*.rs' | cut -d: -f1-2)

if [ "$fail" -eq 0 ]; then
    echo "docs ok: no private citations, no placeholders, module docs present, summaries in budget, allows justified"
    exit 0
fi
exit 1
