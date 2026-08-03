# codeql-php — model/syntax audit vs the real CMS corpus (step 1)

Goal: find the **blind spots** — where `Vozec/codeql-php` fails to recognise the
syntax/idioms of the retrieved CMS code, so taint is silently dropped. Audited
statically against the corpus in `/home/user/sources` before any run.

## Extractor / AST — no obvious blind spot
- Grammar pinned to **tree-sitter-php 0.24** (full PHP 8.x).
- The QL AST/dataflow layer *does* model the modern constructs (verified in
  `php/ql/lib/codeql/php/**` and `dataflow/internal/TaintTrackingPrivate.qll`):
  `match`, nullsafe `?->` (`NullsafeMemberCallExpression`), enums, attributes,
  **arrow functions + closures** (body/params/return all walked),
  **named arguments** (`hasNamedArgument`, resolved to `__construct` too),
  **first-class callables** `f(...)`, variadics/spread.
- So modern syntax is not the gap.

## Models — mostly covered, via a generic catch-all
Key point that kills most "candidate" blind spots: sinks/sources come from **two**
places, not just `php/ql/lib/ext/*.model.yml`:
1. Models-as-Data (per framework), **plus** a generic `modern-frameworks.model.yml`
   that models bare method names (`getQueryParams`, `getParsedBody`, `getRequest`…)
   — this is why **TYPO3 PSR-7** (`$request->getQueryParams()`, 1586× in corpus)
   is already covered although `typo3.model.yml` only lists the legacy
   `GeneralUtility::_GP` (63×).
2. **QL-level sinks** inside the queries/library: dynamic `include`/`require`
   (FileInclusion / SemgrepAudit), `echo` XSS sinks, `unserialize` — all handled
   in QL even though absent from every `.model.yml`.

⚠️ Methodological rule (baked into `audit_coverage.sh` v2): *absence from the model
files ≠ blind spot* — always cross-check the QL queries before claiming a miss.

## Genuine gaps found (evidence-backed)

| # | Gap | Evidence in corpus | Fix |
|---|---|---|---|
| 1 | **PrestaShop raw `Db::getInstance()->execute($sql)`** is not a SQLi sink — only `executeS`/`ExecuteS`/`getRow` are modelled. Write/DDL SQLi (`INSERT/UPDATE/DELETE` with interpolation) is missed. | `->execute(` appears **521×** across `prestashop-9.1.4` + modules | add to `prestashop.model.yml`: a **typed** sink `["Db","execute",0,"SQL injection"]` / `["DbCore","execute",0,…]` (scope to the class to avoid FP on generic `execute`) |
| 2 | **`add_query_arg` / `remove_query_arg` missing source semantics.** Modelled only as a taint *summary* (`arg→return`). But with no URL arg they return `$_SERVER['REQUEST_URI']` verbatim → the classic reflected-XSS (2015 mass-disclosure) is not flagged when the args are constant. | `add_query_arg(` **2238×** in WP core+plugins | add a `sourceModel` row for `add_query_arg`/`remove_query_arg` (tag `wordpress-request`) in addition to the existing summary |

Everything else probed (superglobals `$_GET/$_POST`, `Tools::getValue`, Magento
`getParam`/`getPost`, Joomla `Input::get`/`getRaw`, Drupal `FormState::getValue`,
`shell_exec`/`proc_open`/`call_user_func`, `mysqli_query`, `unserialize`) is
already covered by a model or a QL sink.

## The auditor
`audit_coverage.sh` — per dangerous idiom: real-code frequency per CMS corpus ×
whether the identifier is defined in a model **or** a QL query. `coverage_audit.csv`
is its output. Known limitation: idiom regexes starting with `->` must be passed as
`grep -E -- "$rx"` (a leading `-` is otherwise parsed as a flag → false 0s); the
`->x(` counts in the CSV come from direct greps, not the table.

## Next (step 2 — feasible here)
CodeQL CLI release asset **is** reachable (200) and `cargo`/crates.io work, so we can
build the Rust extractor + download the CLI and actually run the security suite on a
corpus subset — the empirical way to surface real dropped-taint blind spots, then
tighten queries (FP/FN) in step 3.
