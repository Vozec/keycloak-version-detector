#!/usr/bin/env bash
# Reproducible codeql-php run. Env: TOOL=path to codeql-php, SRC=source root.
set -eu
TOOL="${TOOL:-/home/user/sources/tools/codeql-php}"
SRC="${SRC:?set SRC=source root}"
CODEQL="$TOOL/.tooling/codeql/codeql"; EXT=/tmp/php-ext; DB=/tmp/php-db
( cd "$TOOL/php/extractor" && cargo build --release )
rm -rf "$EXT"; mkdir -p "$EXT/tools/linux64"
cp "$TOOL/php/codeql-extractor.yml" "$EXT/"
cp "$TOOL/php/ql/lib/php.dbscheme" "$TOOL/php/ql/lib/php.dbscheme.stats" "$EXT/"
cp "$TOOL/target/release/codeql-extractor-php" "$EXT/tools/linux64/extractor"
cp -r "$TOOL/php/tools/"* "$EXT/tools/" 2>/dev/null || true
"$CODEQL" database create "$DB" --language=php --source-root="$SRC" --search-path="$EXT" --ram=8000 --threads=4 --overwrite
"$CODEQL" database analyze "$DB" "$TOOL/php/ql/src/codeql-suites/php-security-extended.qls" \
  "$TOOL/php/ql/src/Security/SemgrepAudit.ql" --format=csv --output=/tmp/results.csv \
  --search-path="$TOOL/php" --additional-packs="$TOOL" --ram=8000 --threads=4 --rerun
echo "results -> /tmp/results.csv"
