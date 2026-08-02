#!/usr/bin/env bash
# All Packagist prestashop-module repos (official + popular third-party).
set -u
DEST=/home/user/sources/code/prestashop-modules
mkdir -p "$DEST"
LIST=/home/user/sources/code/ps_module_all.tsv; : > "$LIST"
for p in 1 2; do
  curl -sS "https://packagist.org/search.json?type=prestashop-module&per_page=100&page=$p" 2>/dev/null \
   | jq -r '.results[]? | [.downloads, .name, (.repository//"")] | @tsv' >> "$LIST"
done
echo "ranked prestashop-module: $(wc -l < "$LIST")"
ok=0; skip=0; fail=0
while IFS=$'\t' read -r dl name repo; do
  [ -z "$repo" ] && repo=$(curl -sS "https://repo.packagist.org/p2/$name.json" 2>/dev/null | jq -r ".packages[\"$name\"][0].source.url // empty")
  [ -z "$repo" ] && { fail=$((fail+1)); continue; }
  base=$(basename "${repo%.git}")
  dir="$DEST/$base"
  [ -d "$dir" ] && { skip=$((skip+1)); continue; }
  if git clone -q --depth 1 "${repo%.git}.git" "$dir" 2>/dev/null; then ok=$((ok+1)); else fail=$((fail+1)); fi
done < "$LIST"
echo "DONE ps-all ok=$ok skip=$skip fail=$fail total_dir=$(ls "$DEST"|wc -l)"
