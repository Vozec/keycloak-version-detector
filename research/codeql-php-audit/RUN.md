# codeql-php — first run on the CMS corpus (step 2) + top blind spot (→ step 3)

The full pipeline runs in this environment (the CodeQL CLI release asset **is**
reachable, `cargo`/crates.io work):

```bash
# 1. build the Rust extractor (workspace pruned to php/extractor + shared/* that exist)
cd php/extractor && cargo build --release
# 2. CodeQL CLI
curl -sSL -o codeql.zip https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip && unzip -q codeql.zip
# 3. assemble the extractor pack (see bench/run.sh), then:
codeql database create DB --language=php --source-root=SRC --search-path=EXT --ram=8000 --threads=4
codeql database analyze DB php/ql/src/codeql-suites/php-security-extended.qls \
  php/ql/src/Security/SemgrepAudit.ql --format=csv --output=results.csv \
  --search-path=$PWD/php --additional-packs=$PWD --ram=8000 --threads=4
```

> Give it RAM. With the CLI's default `-Xmx1800M` it does **not** cache dataflow
> stages ("Not caching stages …") and every query recomputes global flow (~3 min
> each → ~45 min). `--ram=8000` restores stage caching → the same 21 queries ran
> in **~40 s**.

## First run — subset (1443 PHP files: PrestaShop front controllers + Db layer,
pow-captcha, cundd_rest, powermail, query-monitor, acquia_cohesion)

470 alerts total. By query (deduped):

| Query | n | Query | n |
|---|---|---|---|
| Dangerous code shape (audit) | 308 | SSRF | 10 |
| Path traversal | 44 | IDOR | 7 |
| SQL injection | 29 | SSTI | 6 |
| Blind file read (filter chain) | 26 | Open redirect | 5 |
| Code injection | 24 | File inclusion / Reflected XSS | 4 / 4 |

## Top blind spot found → step 3: one mis-modelled source drives ~all FPs

**154 of the ~156 taint findings share a single source node:**
`classes/db/DbPDO.php:334:19` — the return of **`$link->query($sql)`** (a PDO DB
read) — treated as a `user-provided value`.

Root cause: `php/ql/lib/ext/laravel.model.yml`
```yaml
- ["method", "query", "laravel-request"]     # meant: Laravel $request->query()
```
This is an **untyped** (`method`, any receiver) source on the bare name `query`.
`query` is one of the most generic method names in PHP — PDO `$pdo->query()`,
mysqli, `$wpdb->query()`, Doctrine, every `->query()` — so **every DB read return
value becomes a request source**, and its taint floods SQLi / path-traversal /
XSS / code-injection / SSRF alike. (Note the same name is a *sink* in
`wordpress.model.yml`/`modern-frameworks.model.yml` — modelling it as an untyped
source is the bug.)

**Proposed fix (step 3):** scope it to Laravel's Request, e.g.
```yaml
# typedSourceModel — only $request->query() on a Request/Http object
- ["Request", "query", "laravel-request"]
```
and drop the untyped `["method","query",…]` row. Expected effect: collapse the
~154 DB-`query()`-rooted false positives while keeping genuine
`$request->query()` sources. Re-run and diff the alert count to confirm (and
watch for any real finding that *only* flowed through the bare rule — unlikely,
since real Laravel request flow is typed).

## Also queued for step 3 (from the static AUDIT.md)
- PrestaShop raw `Db::execute($sql)` not a SQLi sink (521 uses) — recall gap.
- `add_query_arg`/`remove_query_arg` missing source semantics (2238 uses).
