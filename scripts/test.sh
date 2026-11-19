#!/bin/bash
# Runs every tool's unit tests. Standard library only, no Omarchy session needed.
set -u
root=$(cd "$(dirname "$0")/.." && pwd)
fail=0
for tool in display-doctor input-doctor bar-plugin-audit qs-crash-digest; do
  echo "== $tool"
  (cd "$root/$tool" && python3 -m unittest discover -s tests 2>&1 | tail -3) || fail=1
done
exit $fail
