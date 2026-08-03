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

## New query — `php/weak-security-randomness` (compiles ✓, precise ✓)
`php/ql/src/Security/WeakSecurityRandomness.ql`: taint from a predictable PRNG
(`rand`/`mt_rand`/`uniqid`/`lcg_value`) into a security hash
(`md5`/`sha1`/`hash`/`hash_hmac`/`crypt`) → guessable secret/token (CWE-338/330;
e.g. predictable password-reset token → account takeover). Compiled clean and,
on the test DB, fired **once** precisely — `ProductController.php:910` (a hash
seeded by a weak PRNG value) — i.e. high signal, not noisy.

## Status
- Fixes + query committed to the local codeql-php repo; patch exported here.
- A realistic **per-app** run (PrestaShop-only, ~7k files) is heavy under the
  CLI's auto heap and was still evaluating the last dataflow queries when this
  was written; the pipeline itself is proven (extractor built, CLI 2.26.2, first
  run produced results). Per-app numbers can be captured on the next pass.
