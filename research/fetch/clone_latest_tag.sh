#!/usr/bin/env bash
# Clone owner/repo at its highest semver tag (depth 1). List file = 1 owner/repo per line.
set -u
DEST="$2"; mkdir -p "$DEST"; ok=0; fail=0
while read -r r; do
  [ -z "$r" ] && continue
  name=$(echo "$r" | tr '/' '_')
  [ -d "$DEST/$name" ] && { echo "skip $r"; continue; }
  tag=$(git ls-remote --tags "https://github.com/$r.git" 2>/dev/null \
        | grep -oP 'refs/tags/\K[^^]+$' \
        | grep -iE '^v?[0-9]+\.[0-9]+(\.[0-9]+)?$' | sort -V | tail -1)
  if [ -z "$tag" ]; then echo "FAIL notag $r"; fail=$((fail+1)); continue; fi
  if git clone -q --depth 1 --branch "$tag" "https://github.com/$r.git" "$DEST/$name" 2>/dev/null; then
    echo "ok $r @ $tag ($(du -sh "$DEST/$name" 2>/dev/null|cut -f1))"; ok=$((ok+1))
  else echo "FAIL clone $r @ $tag"; fail=$((fail+1)); fi
done < "$1"
echo "DONE ok=$ok fail=$fail"
