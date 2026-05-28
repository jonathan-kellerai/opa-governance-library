#!/usr/bin/env bash
#
# check-sanitization.sh
#
# Fails if any internal pre-publication term reappears in a tracked file.
#
# The denylist is stored base64-encoded on purpose: committing the plaintext
# terms would republish the very strings this gate exists to keep out, and
# they would be picked up by code search. The list is decoded only at runtime.
#
# Called by .github/workflows/ci.yml and by the lefthook pre-commit hook.
# Exit 0 = clean. Exit 1 = a forbidden term was found.

set -euo pipefail

# Denylist — base64-encoded, one lowercase term per line.
denylist_b64=$(cat <<'EOF'
a2VsbGVyYWk=
c29mcmVw
c29mYQ==
c3RhdHVzIG9mIGZvcmNlcw==
c3RhdGVtZW50IG9mIGZpbmFuY2lhbCBhY3Rpdml0eQ==
dGhpbmtpbmcgbW9hdA==
EOF
)

# "jonathan-kellerai" is the public GitHub organization slug. It contains a
# denylisted substring but is explicitly allowed; it is neutralized before the
# scan so it never produces a false positive.
allow='jonathan-kellerai'

repo_root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$repo_root"

# Scan tracked files only — staging artifacts are gitignored, hence untracked.
files=$(git ls-files)

fail=0
while IFS= read -r term_b64; do
  [ -n "$term_b64" ] || continue
  term=$(printf '%s' "$term_b64" | base64 --decode)
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    [ -f "$f" ] || continue
    if LC_ALL=C tr '[:upper:]' '[:lower:]' <"$f" \
      | sed "s/${allow}//g" \
      | grep -qF -- "$term"; then
      echo "FORBIDDEN: a denylisted internal term was found in ${f}"
      fail=1
    fi
  done <<<"$files"
done <<<"$denylist_b64"

if [ "$fail" -ne 0 ]; then
  echo "Sanitization check FAILED — see the files listed above."
  exit 1
fi

echo "Sanitization check passed: no forbidden terms in tracked files."
exit 0
