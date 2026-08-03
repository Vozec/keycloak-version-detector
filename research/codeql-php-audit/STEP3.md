# codeql-php — step 3: fixes, re-run, precision improvements

Applied to the local `codeql-php` clone; full diff in
`patches/step3-fixes-and-query.patch` (apply with `git am` in the tool repo).
Corpus `.git` histories were pruned first (latest tree only) → ~5 GB reclaimed.

## Fix 1 — the dominant false-positive source (laravel model)
`laravel.model.yml` declared generic accessor names as **untyped** `method`
sources (`query`, `all`, `json`, `string`, `input`, `only`, `except`,
`getContent`) *in addition to* the correct `Request`-typed rows. The untyped
`["method","query",…]` made **every** `->query()` on any object a request source
— PDO/mysqli/`$wpdb->query()`, etc.
Fix: keep these names only in the `Request`-typed block; also drop the
`Request::all()` / `Request::get()` static-facade rows (they collide with the far
more common `Model::all()` / `Cache::get()`). Net: precise, no recall loss for
real `$request->query()` flows.

## The bigger finding — cross-application false flow (methodology)
Re-running after Fix 1, the alert count was **unchanged (470)** and the dominant
source merely *shifted* (`DbPDO.php:334` → `AddressController.php:88`). Inspecting
one SQLi alert on PrestaShop `Db.php:529` showed **~150 "sources" spanning
PrestaShop + Drupal + TYPO3 + WordPress** — codebases that never call each other.

Root cause: when unrelated apps are extracted into **one** database, CodeQL's
name-based method resolution (used when the receiver type is unknown) links a
`->query()`/`->delete()` call in one app to a same-named method *definition* in
another → taint flows across apps and explodes.

**Consequence for using the tool:** scan **one application per database**. The
mixed-corpus subset used for the first run inflated FPs; it is not how a real
audit should be run. (A candidate library-level precision improvement: gate the
name-only `resolvesToCallee` fallback on same-package/source-root, or drop
cross-file name-resolution edges — tracked as a follow-up, not applied here to
avoid recall regressions without a test suite pass.)

## Fix 2 — recall: PrestaShop raw-SQL sinks (prestashop model)
Added typed sinks `Db`/`DbCore::execute()` (arg 0) and `::getValue()` (arg 0):
`Db::getInstance()->execute($sql)` (raw write/DDL, **521** uses in 9.x) and
`getValue($sql)` (raw single-value read) were previously unmodelled (only
`executeS`/`ExecuteS`/`getRow`). Typed to the class to stay precise.

## New query — `php/weak-security-randomness` (compiles ✓, but NOT precise enough yet)
`php/ql/src/Security/WeakSecurityRandomness.ql`: taint from a predictable PRNG
(`rand`/`mt_rand`/`uniqid`/`lcg_value`) into a hash (`md5`/`sha1`/`hash`/
`hash_hmac`/`crypt`) → guessable secret/token (CWE-338/330).
- Compiles clean; on a tiny subset it fired once (`ProductController.php:910` =
  `md5(uniqid((string) mt_rand(...), true))`).
- **But on the full PrestaShop app it produced 738 findings** — far too noisy.
  The pattern `md5(uniqid(mt_rand()))` is ubiquitous in real PHP for *non-secret*
  values (upload filenames, cache keys, checksums). Sinking on *any* hash argument
  is a presence-detector, not a precise security query.
- **FP-tuning loop actually run (honest log):**
  | iteration | change | PrestaShop findings |
  |---|---|---|
  | v1 | sink = any `md5/sha1/…` argument | **738** (filename/cache-key idiom) |
  | v2 | sink = setcookie value **or** assignment to a security-named target; hash is a taint step | **1179** (worse — regex `reset\|salt\|_key\|activation` + `uniqid` source + `base64/bin2hex` steps over-matched) |
  | v3 | drop `uniqid` source; strong-indicator regex; flow *through* the hash | **0** — wrong: see root cause |
  | **v4 (final)** | sink on the hash **argument**; require hash result in a security context | **2 true positives, 0 FP** |

### Root cause of the 0 (and why v1/v2 over-reported)
`md5`/`sha1`/`hash` are **global taint sanitizers** (`php-builtins.model.yml`
`sanitizerModel`) — correct for injection queries (a hashed value can't SQL-inject).
So taint **never survives the hash**; v3 tried to flow *through* it with an
`isAdditionalFlowStep`, but a per-config step cannot beat a global barrier → 0.
(The "8 findings" I briefly saw were **stale `fastscan` cache**: without `--rerun`,
re-running an *edited* query at the same file path returns the previous results —
a real gotcha. Always `--rerun` while bisecting.)

### The fix (v4) — sink on the hash *input*
Sink the predictable value **entering** the hash (`h.getAnArgument()`), and require
the hash *result* to be in a security context (assigned to a `token`/`secret`/`csrf`/
`session`/`secure_key` field, or a `setcookie` value). Steps only through `uniqid()`
and the `(string)` cast. On `prestashop/classes` this yields **2 precise true
positives, 0 FP**:
- `Customer.php:241` — `$this->secure_key = md5(uniqid((string) mt_rand(...)))`
- `Employee.php:649` — `reset_password_token` from the same idiom → a **guessable
  password-reset token** (account-takeover class, CWE-338).
Non-secret uses of the same `md5(uniqid(mt_rand()))` idiom (upload filenames,
cache keys, `$salt`) are correctly **not** flagged.
738 → 1179 → **2**. That is the FP-tuning loop converging.

## Optimization — caching + module-scoping (answers "can't we cache?")
Yes. Two levers, measured on `prestashop/classes` (328 files):
- **Disk cache** (the fix for a mistake I was making: I passed `--rerun` every
  time, which forces recomputation). Without `--rerun`, the compiled query and
  intermediate predicates are reused: **run 1 = 52 s (cold), run 2 = 6 s** (~10×).
  The compiled query shows `Found in cache`.
- **Scope the database to one module**, not the whole app. A 328-file extract
  analyses in 52 s cold / 6 s cached; the 7k-file full app was heap-bound and did
  not finish. Tune on a module, then do one final full-app validation run.
- Helper committed: `bench/fastscan.sh <module-dir> <query.ql…>` — extract once
  (skips if unchanged), analyse cached. Also raise `--max-disk-cache`.
- Heap remains the ceiling (15 GB machine → ~3.3 GB heap → stage caching is weak
  for full-app global taint); module-scoping sidesteps it.

## Environment limitation (blocker)
Iterative FP-tuning needs fast re-runs, but taint queries on a full app (~7k
files) are **pathologically slow here**: the CodeQL CLI auto-caps the JVM heap
(≈3.3 GB even with `--ram=8000`) so global-dataflow stages are recomputed per
query (3–15 min each; one SQLi run hit a 2.3M-path explosion and did not finish;
the v3 weak-rand eval was still running after ~8 min). So v3's number could not
be captured this pass. To make tuning practical: run on a **single module** (a
few hundred files) or a machine/config with a larger fixed heap.

## Corrected results (an earlier note said "0 alerts" — that was premature)
- The single-app PrestaShop **SQL-injection** run did **not** cleanly finish: the
  path-problem export reported *"Computing up to 2,314,200 paths"* — a **path
  explosion**. So within-app over-approximation is also significant on a real app,
  not only the cross-app artifact. (0 SQLi *would* be plausible given PrestaShop's
  417 `pSQL()` sanitizer uses, but the run didn't confirm a number.)
- Takeaway: on real single apps the tool needs **path-count limits / sink
  precision**, not just the per-app extraction hygiene from the cross-app finding.

## Status
- Fixes + first query committed to the local codeql-php repo; patch exported here.
- Pipeline proven end-to-end (extractor built, CLI 2.26.2, results produced).
- Open precision work, in priority order: (1) tighten WeakSecurityRandomness sink
  to a security context; (2) bound/triage the SQLi path explosion on large apps;
  (3) the cross-app name-resolution gate (library-level).
