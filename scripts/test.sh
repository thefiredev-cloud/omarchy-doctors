#!/bin/bash
# Runs every tool's unit tests. Standard library only, no Omarchy session needed.
set -u
set -o pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
fail=0
for tool in display-doctor input-doctor bar-plugin-audit qs-crash-digest; do
  echo "== $tool"
  (cd "$root/$tool" && python3 -m unittest discover -s tests 2>&1 | tail -3) || fail=$((fail + 1))
done
if [ "$fail" -gt 0 ]; then
  echo "$fail suite(s) failed" >&2
  exit 1
fi
exit 0
