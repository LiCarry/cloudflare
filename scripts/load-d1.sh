#!/usr/bin/env bash
# Loads scripts/d1-seed/*.sql into D1 with retries (INSERT OR REPLACE makes
# every chunk safely re-runnable), then verifies the final row count.
#
# Usage:
#   bash scripts/load-d1.sh          # remote database (production)
#   bash scripts/load-d1.sh --local  # local dev database
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCOPE="${1:---remote}"
EXPECTED=$(grep -ch "^INSERT" "$ROOT"/scripts/d1-seed/*.sql 2>/dev/null | awk '{s+=$1} END{print s+0}')
cd "$ROOT/worker"

FAILURES=0
for f in "$ROOT"/scripts/d1-seed/*.sql; do
  ok=0
  for attempt in 1 2 3; do
    if npx wrangler d1 execute FLAGS_DB --file "$f" "$SCOPE" -y > /dev/null 2>&1; then
      ok=1
      break
    fi
    echo "   retry $attempt: $(basename "$f")"
    sleep 2
  done
  if [ "$ok" -ne 1 ]; then
    echo "FAILED after 3 attempts: $f"
    FAILURES=$((FAILURES+1))
  fi
done

if [ "$FAILURES" -gt 0 ]; then
  echo "$FAILURES chunk(s) failed — run this script again (chunks are idempotent)."
  exit 1
fi

COUNT=$(npx wrangler d1 execute FLAGS_DB --command "SELECT count(*) AS n FROM flags" "$SCOPE" --json 2>/dev/null \
  | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['results'][0]['n'])" 2>/dev/null || echo "?")
echo "All chunks loaded ($SCOPE). Rows in flags table: ${COUNT:-unknown} (expected $EXPECTED)"
