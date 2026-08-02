#!/usr/bin/env bash
# Fetch WildFly/JBoss AS dist archives from Maven Central, extract the
# pre-auth served web assets + version markers per version, drop the zip.
set -u
BASE=/home/user/sources/jboss
MAN=$BASE/manifest.csv
mkdir -p "$BASE/wildfly" "$BASE/jbossas7"
[ -f "$MAN" ] || echo "product,version,relpath,sha256,bytes" > "$MAN"

fetch_one(){ # $1=group_url $2=artifact $3=version $4=destroot $5=product
  local url="$1/$3/$2-$3.zip"
  local dest="$4/$3"
  [ -d "$dest" ] && { echo "skip $5 $3 (have)"; return; }
  local tmp; tmp=$(mktemp -d)
  echo "GET $5 $3"
  if ! curl -sS --fail -o "$tmp/d.zip" "$url"; then echo "  FAIL dl $3"; rm -rf "$tmp"; return; fi
  mkdir -p "$dest"
  # extract only pre-auth served + version-marker paths
  unzip -qq -o "$tmp/d.zip" \
     '*/welcome-content/*' \
     '*/docs/contrib/*' \
     '*.txt' \
     '*/product.conf' \
     '*/dir/META-INF/MANIFEST.MF' \
     '*/version.txt' \
     -d "$dest" 2>/dev/null
  # flatten single top dir
  local top; top=$(ls "$dest" 2>/dev/null | head -1)
  if [ -d "$dest/$top" ]; then mv "$dest/$top"/* "$dest/" 2>/dev/null; rmdir "$dest/$top" 2>/dev/null; fi
  # hash manifest
  find "$dest" -type f | while read -r f; do
     local rel="${f#$dest/}"; local h b
     h=$(sha256sum "$f" | cut -d' ' -f1); b=$(stat -c%s "$f")
     echo "$5,$3,$rel,$h,$b" >> "$MAN"
  done
  local n; n=$(find "$dest" -type f | wc -l)
  echo "  ok $3 -> $n files"
  rm -rf "$tmp"
}

# WildFly 8..41 Final
WF=https://repo1.maven.org/maven2/org/wildfly/wildfly-dist
for v in $(curl -sS $WF/maven-metadata.xml | grep -oP '(?<=<version>)[^<]+' | grep 'Final$'); do
  fetch_one "$WF" wildfly-dist "$v" "$BASE/wildfly" wildfly
done
# JBoss AS7 Final
AS7=https://repo1.maven.org/maven2/org/jboss/as/jboss-as-dist
for v in $(curl -sS $AS7/maven-metadata.xml | grep -oP '(?<=<version>)[^<]+' | grep 'Final$'); do
  fetch_one "$AS7" jboss-as-dist "$v" "$BASE/jbossas7" jboss-as7
done
echo "DONE wildfly/as7"
