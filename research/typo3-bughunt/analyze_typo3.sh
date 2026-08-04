#!/usr/bin/env bash
set -u
ROOT=/home/user/sources/tools/codeql-php
EXT=/home/user/sources/tools/php-ext
CODEQL=$ROOT/.tooling/codeql/codeql
SRC=/home/user/sources/code/typo3-extensions
OUT=/home/user/sources/code/typo3_bugs.csv
PROG=/home/user/sources/code/typo3_progress.txt
Q="$ROOT/php/ql/src/Security/SqlInjection.ql $ROOT/php/ql/src/Security/CodeInjection.ql $ROOT/php/ql/src/Security/CommandInjection.ql $ROOT/php/ql/src/Security/UnsafeDeserialization.ql $ROOT/php/ql/src/Security/FileInclusion.ql $ROOT/php/ql/src/Security/Ssrf.ql $ROOT/php/ql/src/Security/PathTraversal.ql $ROOT/php/ql/src/Security/ReflectedXss.ql $ROOT/php/ql/src/Security/XmlExternalEntity.ql"

process_batch(){
  local bid="$1"; local listfile="$2"
  local bdir=/tmp/tb_$bid bdb=/tmp/tb_${bid}_db
  rm -rf "$bdir" "$bdb"; mkdir -p "$bdir"
  while read -r d; do [ -n "$d" ] && cp -r "$d" "$bdir/$(basename "$d")" 2>/dev/null; done < "$listfile"
  "$CODEQL" database create "$bdb" --language=php --source-root="$bdir" --search-path="$EXT" --ram=4500 --threads=2 --overwrite >/dev/null 2>&1
  "$CODEQL" database analyze "$bdb" $Q --format=csv --output=/tmp/tb_${bid}.csv --search-path="$ROOT/php" --additional-packs="$ROOT" --threads=2 --ram=4500 >/dev/null 2>&1
  python3 - "$bid" <<'PY' >> "$OUT" 2>/dev/null
import csv,re,sys
bid=sys.argv[1]
try: rows=[r for r in csv.reader(open(f"/tmp/tb_{bid}.csv")) if len(r)>=6]
except: rows=[]
seen=set()
for r in rows:
    sinkext=r[4].strip('/').split('/')[0]
    srcs=set(re.findall(r'relative:///([^/"|\]\)]+)/', r[3]))
    if srcs and srcs <= {sinkext}:    # STRICT: every taint source is in the sink's extension
        k=(r[0],r[4],r[5])
        if k in seen: continue
        seen.add(k)
        q=r[0].replace('"','')
        print(f'"{q}","{sinkext}","{r[4]}","{r[5]}"')
PY
  rm -rf "$bdir" "$bdb" /tmp/tb_${bid}.csv "$listfile"
  echo "$(date +%H:%M) batch $bid done" >> "$PROG"
}
export -f process_batch; export CODEQL EXT ROOT Q OUT PROG

echo "query,extension,sink_file,sink_line" > "$OUT"; : > "$PROG"
# build batch list files (25 exts each)
ls -d "$SRC"/*/ | grep -v _ranked > /tmp/all_exts.txt
split -l 25 -d -a 4 /tmp/all_exts.txt /tmp/tbatch_
ls /tmp/tbatch_* | nl -w1 -s' ' | xargs -P 2 -n 2 bash -c 'process_batch "$0" "$1"'
echo "ALL DONE" >> "$PROG"
