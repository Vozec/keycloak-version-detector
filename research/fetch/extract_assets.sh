#!/usr/bin/env bash
# Per-version served public assets + version marker for TYPO3, from the
# local blobless clone (checks out latest patch of each minor).
set -u
CLONE=/home/user/sources/typo3/typo3-core
BASE=/home/user/sources/typo3/assets
MAN=/home/user/sources/typo3/typo3_manifest.csv
mkdir -p "$BASE"
[ -f "$MAN" ] || echo "version,relpath,sha256,bytes" > "$MAN"
cd "$CLONE" || exit 1
# served-asset sysexts of interest (pre-auth backend login / install / frontend)
KEEP='typo3/sysext/(backend|core|install|frontend|rte_ckeditor|t3skin|felogin|dashboard)/Resources/Public'
VERF='typo3/sysext/core/Classes/Information/Typo3Version.php typo3/sysext/core/Classes/Core/SystemEnvironmentBuilder.php t3lib/config_default.php typo3/sysext/core/Classes/Core/Bootstrap.php'

# latest patch per minor across all majors
mapfile -t MINORS < <(git tag | sed 's/^v//' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -V \
   | awk -F. '{print $1"."$2}' | sort -uV)
for m in "${MINORS[@]}"; do
  tag=$(git tag | grep -E "^v?${m//./\\.}\.[0-9]+$" | sed 's/^v//' | sort -V | tail -1)
  # find the actual tag name (with or without v)
  real=$(git tag | grep -E "^v?${tag//./\\.}$" | tail -1)
  [ -z "$real" ] && continue
  dest="$BASE/$tag"
  [ -d "$dest" ] && { echo "skip $tag"; continue; }
  git checkout -q "$real" 2>/dev/null || { echo "  FAIL checkout $real"; continue; }
  mkdir -p "$dest"
  # copy served public assets
  git ls-tree -r --name-only HEAD | grep -E "$KEEP" | while read -r f; do
     [ -f "$f" ] || continue
     mkdir -p "$dest/$(dirname "$f")"; cp "$f" "$dest/$f" 2>/dev/null
  done
  # copy version markers
  for vf in $VERF; do [ -f "$vf" ] && { mkdir -p "$dest/$(dirname "$vf")"; cp "$vf" "$dest/$vf"; }; done
  n=$(find "$dest" -type f | wc -l)
  find "$dest" -type f | while read -r f; do
     h=$(sha256sum "$f" | cut -d' ' -f1); b=$(stat -c%s "$f"); rel="${f#$dest/}"
     echo "$tag,$rel,$h,$b" >> "$MAN"
  done
  echo "  ok $tag -> $n files"
done
git checkout -q main 2>/dev/null || git checkout -q master 2>/dev/null
echo "DONE typo3"
