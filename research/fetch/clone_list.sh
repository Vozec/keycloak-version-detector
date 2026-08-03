#!/usr/bin/env bash
set -u
DEST="$2"; mkdir -p "$DEST"; ok=0; fail=0
while read -r r; do
  [ -z "$r" ] && continue
  name=$(echo "$r" | tr '/' '_')
  [ -d "$DEST/$name" ] && { echo "skip $r"; continue; }
  if git clone -q --depth 1 "https://github.com/$r.git" "$DEST/$name" 2>/dev/null; then ok=$((ok+1)); echo "ok $r"; else fail=$((fail+1)); echo "FAIL $r"; fi
done < "$1"
echo "DONE ok=$ok fail=$fail"
