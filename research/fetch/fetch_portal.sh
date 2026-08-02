#!/usr/bin/env bash
# Per-version served theme assets + version markers from liferay-portal,
# via blobless shallow clone + sparse-checkout (tiny footprint per tag).
set -u
REPO=https://github.com/liferay/liferay-portal.git
BASE=/home/user/sources/liferay/portal
MAN=/home/user/sources/liferay/portal_manifest.csv
mkdir -p "$BASE"
[ -f "$MAN" ] || echo "tag,relpath,sha256,bytes" > "$MAN"
SPARSE=(
  'modules/apps/frontend-theme/frontend-theme-classic'
  'modules/apps/frontend-theme/frontend-theme-styled'
  'modules/apps/frontend-theme/frontend-theme-unstyled'
  'modules/apps/frontend-js/frontend-js-web'
  'portal-web/docroot/html/themes'
  'portal-web/docroot/html/js/liferay'
  'portal-impl/src/com/liferay/portal/util/ReleaseInfo.java'
  'portal-kernel/src/com/liferay/portal/kernel/util/ReleaseInfo.java'
  'portal-impl/src/portal.properties'
  'release.properties'
)
fetch_tag(){
  local tag="$1"; local dest="$BASE/$tag"
  [ -d "$dest" ] && { echo "skip $tag"; return; }
  local tmp="$BASE/.tmp_$tag"
  rm -rf "$tmp"
  if ! git clone -q --filter=blob:none --no-checkout --depth 1 --branch "$tag" "$REPO" "$tmp" 2>/dev/null; then
    echo "  FAIL clone $tag"; rm -rf "$tmp"; return; fi
  ( cd "$tmp" && git sparse-checkout set --no-cone "${SPARSE[@]}" >/dev/null 2>&1 && git checkout -q 2>/dev/null )
  mkdir -p "$dest"
  # copy the checked-out tree (minus .git) 
  (cd "$tmp" && find . -type f ! -path './.git/*' -print0 | while IFS= read -r -d '' f; do
     mkdir -p "$dest/$(dirname "$f")"; cp "$f" "$dest/$f"
   done)
  rm -rf "$tmp"
  local n=0
  while IFS= read -r f; do
     h=$(sha256sum "$f" | cut -d' ' -f1); b=$(stat -c%s "$f"); rel="${f#$dest/}"
     echo "$tag,$rel,$h,$b" >> "$MAN"; n=$((n+1))
  done < <(find "$dest" -type f)
  echo "  ok $tag -> $n files"
}

# build target list
TAGS=$(grep -iE '^(6\.1|6\.2|7\.0|7\.1|7\.2|7\.3)\.[0-9].*-ga' /home/user/sources/liferay/all_tags.txt | sort -V)
# 7.4 sample: first three + every ~6th of 7.4.3.x + last two
S74=$( { grep -iE '^7\.4\.[012]\.' /home/user/sources/liferay/all_tags.txt | grep -i ga
        grep -iE '^7\.4\.3\.' /home/user/sources/liferay/all_tags.txt | grep -i ga | sort -V | awk 'NR%6==1'
        grep -iE '^7\.4\.3\.' /home/user/sources/liferay/all_tags.txt | grep -i ga | sort -V | tail -2
      } | sort -uV )
QUART=$(grep -iE '^20[0-9]{2}\.q[1-4]' /home/user/sources/liferay/all_tags.txt | sort -V)
ALL=$(printf "%s\n%s\n%s\n" "$TAGS" "$S74" "$QUART" | awk 'NF' | sort -uV)
echo "targets:"; echo "$ALL" | tr '\n' ' '; echo
for t in $ALL; do fetch_tag "$t"; done
echo "DONE portal"
