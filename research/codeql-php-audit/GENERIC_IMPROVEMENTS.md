# codeql-php — generic engine/precision improvements

Engine- and shared-model-level changes that improve precision for **any** PHP CMS
(not per-app tuning). Each is validated by `bench/run.sh` (recall must not drop)
and measured on a real app. Applied to the local `codeql-php` clone; combined diff
in `patches/generic-precision.patch` (`git am`).

Baseline (unchanged throughout): `bench/run.sh` = **RECALL 183/232 (78%), FP-on-ok 40/176**.

## 1. Name-arity gate on call resolution  (`DataFlowPrivate.qll`, `TaintTrackingPrivate.qll`)
When a method call's receiver type is unknown, the call graph fell back to matching
**every** callable with the same name. Generic names (`query`, `get`, `execute`,
`delete`) are defined across dozens of unrelated classes, so this merged taint
between unrelated code, produced cross-file/cross-app false flows, and exploded path
counts (the 2.3M-path SQLi blow-up on the full app).

Fix: `nameFallbackAcceptable(name)` — only resolve by name when the name has ≤ 8
defining callables (tunable). Functions and rare method names are unaffected.
Applied at all three name-only resolution sites: `viableCallable` (call graph),
`resolvesToCallee` (by-ref / named-argument steps), and first-class-callable method
resolution (`$obj->m(...)`) — the rule is now applied uniformly.

Measured — PrestaShop `classes/` (328 files), SQL-injection query:
| | time | paths | path-rows |
|---|---|---|---|
| without gate | 40 s | 44 828 | 11 207 |
| **with gate** | **19 s** | **11 640** | **2 910** |

≈ **−74 % paths, 2× faster**, recall unchanged. (Distinct alerts 279→263: the main
win is the path explosion / performance that made full-app scans finish at all.)

**The headline: it makes the full app analysable.** SQL-injection on the *whole*
PrestaShop 9.1.4 (~7k files):
| | paths | result |
|---|---|---|
| without gate | **2 314 200** | did **not** finish (killed ~30 min) |
| **with gate** | **486 836** | **finishes in ~4 min**, 553 alerts |

A previously-impossible whole-app scan now completes — the single most useful
outcome of the change.

## 2. Numeric/boolean casts are taint barriers  (`FlowSources.qll`)
The cast **syntax** `(int)` / `(integer)` / `(float)` / `(double)` / `(real)` /
`(bool)` / `(boolean)` was treated as an ordinary taint-propagating expression, so
`(int) $_GET['id']` concatenated into SQL stayed tainted — a false positive on the
pervasive PHP-CMS idiom `Db::...('… = ' . (int)$x)`. Added `NumericCastSanitizer`
(complements the existing `intval`/`floatval`/`settype`/`absint` *function*
sanitizers).

Validated by a controlled micro-test: `(int)$a` in a SQL string is no longer
flagged; raw `$b` still is. `bench` recall unchanged. (On PrestaShop `classes/` it
removed 0 of the 263 residual SQLi alerts — those don't rely on a numeric-cast path
— but it is correct and prevents this FP class on any codebase / for XSS/path/cmd
queries too.)

## Method
- Every change keeps `bench/run.sh` recall at 183/232 (no new false negatives).
- Thresholds (`nameFallbackMaxArity = 8`) are single named constants, tunable and
  re-benchable.
- Fast iteration via `bench/fastscan.sh <module> <query>` (module-scoped DB + disk
  cache; **use `--rerun` while editing a query** — otherwise stale cached results).

## Genericity — applies to any PHP CMS (not per-app)
Both changes are language/engine-level, so they hold across CMS. With the fixes,
the SQL-injection + weak-randomness queries run to completion (module-scoped) on:
- **PrestaShop** classes/ (328 files) — 19 s
- **Drupal** getdkan/dkan (438 files) — 19 s, 181 alerts
- **WordPress** wp-graphql (663 files) — 15 alerts
No per-CMS code paths were added; only shared engine predicates and generic
sanitizers were touched.

## Still open (generic, next)
- PrestaShop `classes/` still yields ~263 SQLi alerts whose taint reaches the sink
  without a numeric cast (sources include `Tools::getValue` and an
  `AdminController` accessor). Next step: trace whether a shared source is
  over-broad or a second-order/concat path needs a barrier — fix generically.

## 3. `method_exists()` as a sanitizer guard — kills the dominant dynamic-dispatch FP class (`php-builtins.model.yml`)
The code-injection query correctly treats the *callee identity* of a dynamic call (`$obj->$m()`,
`$fn()`, `new $c()`) as the sink. But the pervasive **guarded-dispatch** idiom
`if (method_exists($obj, $m)) { $obj->$m(...); }` bounds `$m` to the **declared methods of a concrete
object** — not arbitrary code execution — yet was still reported as RCE. This was the single most
common code-injection false positive across both hunts: TYPO3 `er24-rechtstexte`, `t3-cat-search`,
`femanager`/`datamints_feuser` setter mass-assignment, and the Drupal dynamic-op dispatchers.

Fix: add `method_exists` to `sanitizerGuardModel` (one data row). The existing `isGuardedRead`
barrier then treats a tainted method name used in the positive branch of an `if (method_exists(...))`
as sanitized. **Deliberately NOT `is_callable`/`function_exists`** — those are true for `system`/`exec`,
so they do *not* bound the callee and must keep reporting.

- Bench: **RECALL 183/232, FP-on-ok 40/176 — unchanged** (no true positive lost).
- Controlled micro-test: `if (method_exists($this,$m)) $this->$m()` (guarded) → **no alert**; an
  unguarded `$this->$m()` on the same tainted `$m` → **still alerted**. Exactly the intended split.
- `in_array` / `array_key_exists` (constant-whitelist guards) were already modeled; `method_exists`
  was the missing existence-guard behind the residual dynamic-dispatch noise.

Patch: `patches/method-exists-guard.patch`.

## 4. Narrow the bare `query` SQL sink from arg -1 (any) to arg 0 (`modern-frameworks`, `wordpress` models)
Two bare-method rows `["method", "query", -1, "SQL injection"]` matched `->query()` on **any** object
at **any** argument. That is over-broad: a raw-SQL `query()` (`mysqli::query`, `PDO::query`, `$wpdb->query`,
unmodelled ORMs) always takes the SQL string as **arg 0**, but `-1` also flagged taint reaching arg 1+
of *non-SQL* `query()` methods with the same name — Symfony `Ldap::query($dn, $filter, $options)`
(the `ldap` module's 12 "SQLi" FPs), Solr/Elasticsearch query builders, HTTP-client `query()`, etc.

Fix: `-1 → 0` on both rows. Raw SQL is preserved (arg 0); the false-positive arg-1+ matches on
same-named non-SQL methods are dropped.
- Bench: **RECALL 183/232 — unchanged**, `wordpress-plugins 42/42` unchanged (all `$wpdb->query($sql)`
  are arg 0).
- Micro-test: `$db->query($_GET['sql'])` (arg 0) → **alert**; `$ldap->query($dn, $_GET['filter'], $o)`
  (taint at arg 1) → **no SQLi alert**. Exactly the intended split.

Patch: `patches/query-arg0.patch`.

## 5. New query: LDAP injection (CWE-090) — turns the `Ldap::query` "SQLi" mislabel into a real bug class
Investigating the `ldap` module's "SQL injection" FPs revealed they are actually **LDAP** queries
(`Symfony\Component\Ldap\Ldap::query($dn, $filter)`, procedural `ldap_search/list/read`). Rather than
only suppress them, added a proper **LDAP-injection** sink kind + `LdapInjection.ql`: user input into
an LDAP **filter** or **base DN** without `ldap_escape` → auth bypass (`*)(uid=*))(|(uid=*`) / attribute
disclosure. `ldap_escape` (PHP 5.6+) is the sanitizer.
- New sink kind `"ldap injection"`; `bench/run.sh` recall **unchanged 183/232** (additive, no effect on
  existing kinds).
- Correctly **0 findings** on the maintained `ldap` module (properly escaped) — no FP on clean code.
- Wired into the TYPO3 + Drupal batch pipelines to run corpus-wide alongside the 9 existing queries.
- Model: `ext/ldap-injection.model.yml`; query: `src/Security/LdapInjection.ql`.

Patch: `patches/ldap-injection-query.patch`.

## 6. New sink: `preg_replace('/…/e', …)` code injection (PHP<7 PREG_REPLACE_EVAL RCE)
`preg_replace` was modelled only as a taint *step*, not a *sink* — but the `e` modifier executes the
**replacement** (arg 1) as PHP code, first expanding backreferences from the **subject** (arg 2). This
is a classic RCE and is still shipped across the many legacy D5/6/7 modules in the corpus (autoweight,
importpage, interview, coolfilter, drutex, flickrmodule, kasahorow, …). Added a structural sink: when
the pattern (arg 0) is a constant string whose trailing PCRE modifier flags include `e`
(`regexpMatch("(?s).*[/#~!@%|][imsxuADSUXJ]*e[imsxuADSUXJ]*")`), arg 1 and arg 2 become
`"code injection"` sinks.
- Bench: **RECALL 183/232 — unchanged** (additive; only fires on a rare constant-pattern shape).
- Micro-test: `preg_replace('/(.*)/e', $_GET[x], $s)` and `preg_replace('#a#ie', $_GET[x], $s)` and
  `preg_replace('/…/e', 'c', $_GET[s])` → **alert**; `preg_replace('/(.*)/', $_GET[x], $s)` (no `e`)
  → **no alert**. Exactly the intended split.

Patch: `patches/preg-replace-e-sink.patch`.

## 7. `$_SERVER` server-controlled keys are not attacker sources (mirrors the `getenv()` split)
`$_SERVER` was modelled as a whole remote source, so `$_SERVER['SCRIPT_FILENAME']`,
`['DOCUMENT_ROOT']`, `['PWD']`, `['SERVER_ADDR']`, … (SERVER/environment-controlled, not client-
influenced) were treated as attacker input — flooding file/path/**include** sinks. Concretely: the
pervasive fixed-path bootstrap `require $_SERVER['SCRIPT_FILENAME'] . '/…/bootstrap.inc'` (authcache
front controller, advancedqueue_runner, and the whole File-inclusion FP cluster surfaced this round).
The pack already did exactly this for `getenv()` (`GetenvSource` excludes TEMP/PATH/HOME…); this
extends the same principle to `$_SERVER`.

Fix: a `$_SERVER` read is a source UNLESS it is subscripted with a constant, clearly server-controlled
key (`SCRIPT_FILENAME`, `DOCUMENT_ROOT`, `CONTEXT_DOCUMENT_ROOT`, `PWD`, `SERVER_ADDR`, `SERVER_SOFTWARE`,
`SERVER_ADMIN`, `SERVER_SIGNATURE`, `GATEWAY_INTERFACE`, `SERVER_PORT`, `SERVER_PROTOCOL`, `CONTEXT_PREFIX`,
`REQUEST_TIME[_FLOAT]`). **Request-derived keys stay sources** (`REQUEST_URI`, `QUERY_STRING`, `HTTP_*`,
`PHP_SELF`, `PATH_INFO`, `SERVER_NAME`, …); dynamic/absent keys and the bare array stay sources (conservative).
- Bench: **RECALL 183/232 — unchanged**.
- Micro-test: `include $_SERVER['SCRIPT_FILENAME'].'/x.inc'` / `echo $_SERVER['SERVER_SOFTWARE']` → **no
  alert**; `include $_SERVER['PATH_INFO']` (LFI) / `echo $_SERVER['REQUEST_URI']` (XSS) → **alert**.
- Corpus: authcache FileInclusion hits `frontcontroller.php:41,42` → **0** (the exact FP from this round).

Patch: `patches/server-superglobal-key-split.patch`.
