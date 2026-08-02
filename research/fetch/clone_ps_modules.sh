#!/usr/bin/env bash
set -u
DEST=/home/user/sources/code/prestashop-modules
mkdir -p "$DEST"
ok=0; fail=0
while read -r m; do
  [ -z "$m" ] && continue
  [ -d "$DEST/$m" ] && { echo "skip $m"; continue; }
  if git clone -q --depth 1 "https://github.com/PrestaShop/$m.git" "$DEST/$m" 2>/dev/null; then
    ok=$((ok+1)); echo "ok $m"
  else fail=$((fail+1)); echo "FAIL $m"; fi
done < /home/user/sources/code/ps_modules.txt
echo "DONE ps-modules ok=$ok fail=$fail"
