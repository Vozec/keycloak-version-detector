#!/usr/bin/env bash
# Clone owner/repo at highest version tag. Handles v-prefix, release- prefix, and 2-4 dotted parts.
set -u
DEST="$2"; mkdir -p "$DEST"; ok=0; fail=0
while read -r r; do
  [ -z "$r" ] && continue
  name=$(echo "$r" | tr '/' '_'); [ -d "$DEST/$name" ] && { echo "skip $r"; continue; }
  raw=$(git ls-remote --tags "https://github.com/$r.git" 2>/dev/null | grep -oP 'refs/tags/\K[^^]+$' | grep -vi -E 'alpha|beta|rc|dev|pre|snapshot')
  # normalise: strip prefixes, keep numeric-dotted, remember mapping norm->origtag
  tag=$(echo "$raw" | sed -E 's/^release-//; s/^v//' | grep -E '^[0-9]+(\.[0-9]+){1,3}$' | sort -V | tail -1)
  [ -z "$tag" ] && { echo "FAIL notag $r"; fail=$((fail+1)); continue; }
  orig=$(echo "$raw" | grep -E "(^|[^0-9])$(echo "$tag"|sed 's/\./\\./g')\$" | head -1)
  if git clone -q --depth 1 --branch "$orig" "https://github.com/$r.git" "$DEST/$name" 2>/dev/null; then
    echo "ok $r @ $orig ($(du -sh "$DEST/$name" 2>/dev/null|cut -f1))"; ok=$((ok+1))
  else echo "FAIL clone $r @ $orig"; fail=$((fail+1)); fi
done < "$1"
echo "DONE ok=$ok fail=$fail"
