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
Applied at both resolution sites (`viableCallable` for the call graph;
`resolvesToCallee` for by-ref / named-argument steps).

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
