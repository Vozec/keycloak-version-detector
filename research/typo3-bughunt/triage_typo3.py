#!/usr/bin/env python3
import csv,sys,re
NOISE=re.compile(r'(Tests?/|/Lib/|Resources/Public/|/cli/|/vendor/|PHP_XLSXWriter|h5p-core|Fixtures?/)',re.I)
CRIT={'Code injection','Command injection','Unsafe deserialization','File inclusion','SQL injection','Server-side request forgery','XML external entity'}
rows=[r for r in csv.reader(open('typo3_bugs.csv')) if len(r)>=4 and r[0]!='query']
kept=[r for r in rows if not NOISE.search(r[2])]
def rank(r):
    s=0
    if r[0] in CRIT: s+=10
    if 'XSS' in r[0]: s+=6
    if 'Controller' in r[2]: s+=4          # web-reachable
    if 'Middleware' in r[2] or 'Eid' in r[2] or 'Ajax' in r[2]: s+=5
    return -s
kept.sort(key=rank)
print(f"# {len(rows)} raw -> {len(kept)} after noise filter\n")
for r in kept[:40]:
    tag='CRIT' if r[0] in CRIT else ('XSS' if 'XSS' in r[0] else 'med')
    print(f"[{tag:4}] {r[0][:20]:20} {r[1][:28]:28} {r[2].split('/',2)[-1]}:{r[3]}")
