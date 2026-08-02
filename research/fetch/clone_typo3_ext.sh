#!/usr/bin/env bash
set -u
DEST=/home/user/sources/code/typo3-extensions
mkdir -p "$DEST"
ok=0; fail=0
while read -r pkg; do
  pkg=$(echo "$pkg" | tr -d ' ')
  case "$pkg" in ''|*'...'*) continue;; esac
  name=$(echo "$pkg" | tr '/' '_')
  [ -d "$DEST/$name" ] && { echo "skip $pkg"; continue; }
  url=$(curl -sS "https://repo.packagist.org/p2/$pkg.json" 2>/dev/null \
        | jq -r ".packages[\"$pkg\"][0].source.url // empty" 2>/dev/null)
  [ -z "$url" ] && { echo "FAIL resolve $pkg"; fail=$((fail+1)); continue; }
  if git clone -q --depth 1 "$url" "$DEST/$name" 2>/dev/null; then
    ok=$((ok+1)); echo "ok $pkg <- $url"
  else fail=$((fail+1)); echo "FAIL clone $pkg ($url)"; fi
done < /home/user/sources/code/typo3_ext_list.txt
echo "DONE typo3-ext ok=$ok fail=$fail"
