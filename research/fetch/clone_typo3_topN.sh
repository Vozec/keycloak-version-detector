#!/usr/bin/env bash
# Clone the top-N TYPO3 extensions ranked by Packagist downloads.
set -u
N_PAGES=${1:-2}   # 100 per page
DEST=/home/user/sources/code/typo3-extensions
mkdir -p "$DEST"
LIST=/home/user/sources/code/typo3_topN.tsv
: > "$LIST"
for p in $(seq 1 "$N_PAGES"); do
  curl -sS "https://packagist.org/search.json?type=typo3-cms-extension&per_page=100&page=$p" 2>/dev/null \
   | jq -r '.results[]? | [.downloads, .name, (.repository//"")] | @tsv' >> "$LIST"
done
echo "ranked list: $(wc -l < "$LIST") extensions"
ok=0; fail=0; skip=0
while IFS=$'\t' read -r dl name repo; do
  [ -z "$name" ] && continue
  dir="$DEST/$(echo "$name" | tr '/' '_')"
  [ -d "$dir" ] && { skip=$((skip+1)); continue; }
  url="$repo"
  case "$url" in *github.com*) url="${url%.git}.git";; ""|*) 
     url=$(curl -sS "https://repo.packagist.org/p2/$name.json" 2>/dev/null | jq -r ".packages[\"$name\"][0].source.url // empty");; esac
  [ -z "$url" ] && { fail=$((fail+1)); continue; }
  if git clone -q --depth 1 "$url" "$dir" 2>/dev/null; then ok=$((ok+1)); else fail=$((fail+1)); fi
done < "$LIST"
echo "DONE typo3-topN ok=$ok skip=$skip fail=$fail total_dir=$(ls "$DEST"|wc -l)"
