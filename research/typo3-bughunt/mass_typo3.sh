#!/usr/bin/env bash
# Mass-fetch TYPO3 extensions: resolve every Packagist typo3-cms-extension to its
# GitHub source and shallow-clone it. Dedups with existing dirs, prunes .git.
set -u
DEST=/home/user/sources/code/typo3-extensions
NAMES=/home/user/sources/code/typo3_all_names.txt
RESOLVED=/home/user/sources/code/typo3_resolved.tsv
mkdir -p "$DEST"

# --- Phase 1: resolve name -> github url (parallel) ---
resolve_one(){
  local n="$1"
  local url
  url=$(curl -sS --max-time 20 "https://repo.packagist.org/p2/$n.json" 2>/dev/null | jq -r ".packages[\"$n\"][0].source.url // empty" 2>/dev/null)
  case "$url" in *github.com*) printf '%s\t%s\n' "$n" "${url%.git}" ;; esac
}
export -f resolve_one
echo ">> resolving $(wc -l < "$NAMES") names ..."
: > "$RESOLVED"
cat "$NAMES" | xargs -P 20 -I{} bash -c 'resolve_one "$@"' _ {} >> "$RESOLVED" 2>/dev/null
echo ">> resolved github repos: $(wc -l < "$RESOLVED")"

# --- Phase 2: clone (parallel, shallow), skip existing, prune .git ---
clone_one(){
  local name="$1" url="$2"
  local dir="/home/user/sources/code/typo3-extensions/$(echo "$name" | tr '/' '_')"
  [ -d "$dir" ] && return
  if git clone -q --depth 1 "$url.git" "$dir" 2>/dev/null; then
    rm -rf "$dir/.git"
  fi
}
export -f clone_one
echo ">> cloning ..."
awk -F'\t' '{print $1"\t"$2}' "$RESOLVED" | xargs -P 12 -d '\n' -I{} bash -c 'IFS=$'"'"'\t'"'"' read -r n u <<< "{}"; clone_one "$n" "$u"'
echo ">> DONE. total dirs: $(ls "$DEST" | grep -v _ranked | wc -l)"
