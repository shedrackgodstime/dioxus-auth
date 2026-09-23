#!/usr/bin/env bash
# Doc gates (06 §13.6): no private citations, no future-tense markers, module
# docs everywhere, first sentences within budget, every allow justified.
set -u

cd "$(dirname "$0")/.." || exit 1

fail=0

# D1/D7: private-KB citations and design-journal pointers must never ship in
# source. (N4-style domain terms like "N4 verdict" live in prose, not as
# citations, and are out of scope for this grep. Rule justifications cite
# content ("explicit return on every tail expression", never rule numbers).
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
# Continued lines join until the first period, so multi-line summaries cannot
# hide behind the line boundary.
if ! python3 - <<'PYEOF'; then
import glob


def first_sentence(lines, start, marker):
    parts = []
    for line in lines[start:]:
        stripped = line.strip()
        if not stripped.startswith(marker):
            break
        text = stripped[len(marker):].strip()
        if not text:
            break
        if text.startswith('#') or text.startswith('```'):
            break
        parts.append(text)
        if '.' in text:
            break
    return ' '.join(parts).split('.')[0]


violations = []
for pattern in ('src/**/*.rs', 'examples/sqlite-reference/src/**/*.rs'):
    for path in glob.glob(pattern, recursive=True):
        lines = open(path).read().splitlines()
        i = 0
        while i < len(lines):
            stripped = lines[i].strip()
            is_mod = stripped.startswith('//!')
            is_item = (
                stripped.startswith('///')
                and not stripped.startswith('/// #')
                and not stripped.startswith('/// ```')
            )
            if is_mod or is_item:
                marker = '//!' if is_mod else '///'
                sentence = first_sentence(lines, i, marker)
                words = sentence.split()
                # Skip link-definition and attribute-like starts.
                if words and not words[0].startswith(('[', '#', '`')):
                    if len(words) > 15:
                        violations.append((path, i + 1, len(words), sentence[:90]))
                while i < len(lines) and lines[i].strip().startswith(marker):
                    i += 1
            else:
                i += 1

for path, line, count, text in sorted(violations):
    print('FAIL: %s:%d first sentence has %d words: %s' % (path, line, count, text))
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

# The em dash character (U+2013) reads machine-written: reword with commas,
# colons, or periods. The pattern below uses an escape so this file stays
# glyph-free and does not flag itself.
if grep -rn $'\u2014' \
    src/ tests/ examples/sqlite-reference/src examples/sqlite-reference/tests \
    README.md docs/ CHANGELOG.md CONTRIBUTING.md scripts/ \
    examples/sqlite-reference/README.md \
    --include='*.rs' --include='*.md' --include='*.sh' 2>/dev/null; then
    fail=1
    echo "FAIL: em-dash found (see above)" >&2
fi

if [ "$fail" -eq 0 ]; then
    echo "docs ok: no private citations, no placeholders, module docs present, summaries in budget, allows justified"
    exit 0
fi
exit 1
