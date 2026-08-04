#!/usr/bin/env bash
set -u
DST=/home/user/sources/drupal/modules
LIST=/home/user/sources/drupal/clone_targets.txt
LOG=/home/user/sources/drupal/clone.log
clone_one(){
  local name="$1"; local d="$DST/$name"
  [ -d "$d" ] && return 0
  for attempt in 1 2; do
    if git clone --depth 1 "https://git.drupalcode.org/project/${name}.git" "$d" >/dev/null 2>&1; then
      rm -rf "$d/.git"; echo "OK $name" >> "$LOG"; return 0
    fi
    sleep 2
  done
  echo "FAIL $name" >> "$LOG"
}
export -f clone_one; export DST LOG
: > "$LOG"
xargs -P 6 -a "$LIST" -I{} bash -c 'clone_one "{}"'
echo "CLONE ALL DONE ($(grep -c ^OK "$LOG") ok / $(grep -c ^FAIL "$LOG") fail)" >> "$LOG"
