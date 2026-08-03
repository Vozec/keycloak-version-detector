#!/usr/bin/env bash
set -u
TYPE="$1"; PAGES="${2:-2}"; DEST="$3"
mkdir -p "$DEST"; LIST="$DEST/_ranked.tsv"; : > "$LIST"
for p in $(seq 1 "$PAGES"); do
  curl -sS "https://packagist.org/search.json?type=$TYPE&per_page=100&page=$p" 2>/dev/null \
   | jq -r '.results[]? | [.downloads,.name,(.repository//"")] | @tsv' >> "$LIST"
done
ok=0; skip=0; nogh=0; fail=0
while IFS=$'\t' read -r dl name repo; do
  case "$repo" in *github.com*) ;; *) nogh=$((nogh+1)); continue;; esac
  base=$(echo "$name" | tr '/' '_')
  [ -d "$DEST/$base" ] && { skip=$((skip+1)); continue; }
  if git clone -q --depth 1 "${repo%.git}.git" "$DEST/$base" 2>/dev/null; then ok=$((ok+1)); else fail=$((fail+1)); fi
done < "$LIST"
echo "DONE $TYPE ok=$ok skip=$skip non-github=$nogh fail=$fail dirs=$(ls "$DEST"|grep -v _ranked|wc -l)"
