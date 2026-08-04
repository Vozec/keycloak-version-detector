# TYPO3 extension pre-auth bug hunt — final summary

Autonomous, source-verified hunt for **pre-authentication** vulnerabilities across the
public TYPO3 extension ecosystem. Two complementary tracks:

- **With source** — mass-clone the ecosystem, run an improved CodeQL-for-PHP over it,
  triage the candidates, and have an agent fleet **read the actual code** to confirm or
  kill each one.
- **Without source (version→CVE)** — map cloned/deployed versions to known advisories.

Every "CONFIRMED" below was re-read in source by me before it landed here. Every cleared
candidate is recorded with its reason in `VERIFIED_FALSE_POSITIVES.md` — the FP ledger is
part of the deliverable (it says *why* the maintained ecosystem mostly holds).

## Corpus & pipeline
- **3350 TYPO3 extensions** cloned from Packagist (`type=typo3-cms-extension`, `--depth 1`,
  `.git` pruned; `mass_typo3.sh`).
- CodeQL analysis in batches of 25 (`analyze_typo3.sh`), 9 critical+XSS queries
  (SQLi, Code-inj, Command-inj, Unsafe-deser, File-inclusion, SSRF, Path-traversal,
  Reflected-XSS, XXE), with a **strict intra-extension source filter** (a finding is kept
  only when *every* taint source is inside the sink's own extension — kills the
  cross-extension false flows a mixed DB produces). **~1150+ candidates** over 134 batches.
- Run with the **generic codeql-php precision fixes** from `../codeql-php-audit/`
  (name-arity call-resolution gate + numeric-cast sanitizer) — the fix that made whole-app
  PrestaShop analysis finish at all, recall unchanged at bench 183/232.

## CONFIRMED pre-auth vulnerabilities (source-verified)

### CRITICAL — pre-auth remote code execution
| # | Extension | Version | Vector |
|---|-----------|---------|--------|
| 1 | interfrog/if_basic | 2.0.0 | eID `ajaxupload`, client-MIME-only check, original `.php` name kept → RCE |
| 1b | phorax/formhandler | current | iterates **all** `$_FILES`, no extension gate → RCE (widely deployed) |
| 1d | **dmk/mkforms** | **12.0.5 (current)** | UPLOAD/MEDIAUPLOAD widgets omit `fileDenyPattern` (sibling SWFUPLOAD has it) → RCE |
| 8 | chrisgruen/realty-manager | 4.0.0 | 2× pre-auth SQLi (`cityId` quoted UNION + unquoted search params) |

### HIGH — pre-auth SQL injection (ORDER BY / repository)
| # | Extension | Version | Vector |
|---|-----------|---------|--------|
| 11 | auba/cms-census | 1.1.1 | ORDER BY **direction** (`formate` GP) raw into v11 `addOrderBy` via anonymous `Chartcmscensus` search plugin |

### HIGH — pre-auth injection / object-injection / SSRF
| # | Extension | Version | Vector |
|---|-----------|---------|--------|
| 1c | ameos/ameos_filemanager | 3.1.2 (current v13) | SQLi (hand-quoted `like()`) + anonymous FAL file read (regression of TYPO3-EXT-SA-2017-008) |
| 5 | bvbmedia/multishop | 5.1.110 (abandoned) | SQLi (`price_filter`→HAVING) **+** SSRF (`file_url`→curl, `file://`/cloud-metadata) via guest `run_job` |
| 6 | **creativekallol/ck-faq** | **1.0.0 (current v13.4)** | PHP object injection — raw `unserialize` of `faq_rating_<uid>` cookie |
| 4 | georgringer/news | ≤14.0.2 | pre-auth SQLi (**known** CVE-2026-8726 / TYPO3-EXT-SA-2026-010) — version→CVE result |

### MEDIUM — privesc / auth-bypass / IDOR / stored-XSS
| # | Extension | Version | Vector |
|---|-----------|---------|--------|
| 2 | in2code/femanager | 13.3.3 | usergroup mass-assignment → privesc (default-vulnerable) |
| 10 | datamints/datamints_feuser | 0.12.5 | usergroup mass-assignment → privesc (needs `usergroup` field configured) |
| 3 | extcode/cart | 12.0.0 | anonymous guest-order disclosure (IDOR) + no-ownership `showAction` |
| 7 | caretaker/caretaker | 1.0.3 | eID auth-bypass (empty apiKey matches empty fe_users key) → monitoring disclosure |
| 9 | azich/direct-mail | 6.0.0-dev | inverted authCode check → recipient/PII enumeration (fork regression) |

### Lower-severity / conditional (verified)
causal/routing 0.5.0 (eID `REQUEST_URI` reflected XSS) · glcrossword 9.0.0 (pre-auth unsafe
dynamic dispatch → DoS) · ecodev/tagpack 0.13.0 (reflected XSS) · simonschaufi/ve_guestbook
3.3.0 (stored XSS, default config) · sourcebroker/restrictfe 12.0.1 (Host-header XSS,
needs permissive `trustedHostsPattern`).

### Authenticated (out of pre-auth scope, still real)
- **gdpr-extensions-com/\* `uploadImageAction`** — low-priv backend editor → RCE (raw
  `move_uploaded_file`, no allow-list, bypasses `fileDenyPattern`), replicated **byte-identical
  across ~19 extensions**. One shared fix.
- **jvelletti/jvchat 13.4.1** — FE-user stored XSS via chat `[img]` BBCode attribute
  break-out → steals moderator/superuser cookies.
- kohlercode/slug, phorax/mydashboard — real ORDER-BY / dynamic-call issues but backend-auth.

## The headline pattern (for R&D targeting)
Real pre-auth bugs cluster in exactly two places:
1. **Abandoned / legacy extensions** — raw `$TYPO3_DB->sql_query`, hand-quoted SQL,
   hand-rolled eID auth, unrestricted `$_FILES` handling (multishop, realty-manager,
   if_basic, caretaker, ve_guestbook, datamints_feuser).
2. **A handful of *current* extensions that skip one framework guard** — mkforms (missing
   `fileDenyPattern`), ck-faq (raw cookie `unserialize`), ameos_filemanager (hand-quoted
   `like()`). These are the highest-value finds because they affect maintained, up-to-date
   installs.

Conversely, the **maintained mainstream** ecosystem is largely solid: the overwhelming
majority of CodeQL candidates in current extensions are false positives because the code
uses the framework correctly — `createNamedParameter`, Extbase reflection dispatch, Fluid
auto-escaping, `fileDenyPattern`, `intExplode`, whitelisted ORDER BY, JSON content-types,
`allowed_classes=>false`. The FP ledger catalogs each shape.

## codeql-php precision backlog (the FPs point at these generic query fixes)
The recurring FP shapes are worth fixing at the query/engine level (generic, not per-CMS):
1. **Separate search-engine query sinks from SQL** — Solr/Solarium/Elasticsearch
   `setQuery()` flagged as "SQL injection" (kitodo, apache-solr). Distinct sink kind.
2. **Model dynamic dispatch bounded by `method_exists`/whitelist as not-code-injection** —
   `$obj->$m()` / `makeInstance($constantOrConfigClass)` where the request controls only the
   *argument*, not the callable identity (er24, d-ai, t3-cat-search, zahnstocher, site-core,
   pxa-pm-importer, tca-api). Require the callable *identity* to be tainted.
3. **Recognize cross-file/return-through-array sanitizers** — `escapeshellarg` in a helper
   that returns through a by-ref loop (webkitpdf) was missed → FP command-injection.
4. **Treat `unserialize($x, ['allowed_classes'=>false])` as a deserialization barrier** —
   bitpatroon FP.
5. **Distinguish config/FlexForm/TypoScript reads from request sources** — ORDER-BY-from-
   FlexForm (kk-downloader), `addWhereClause` from config (realurl) rank as request-sourced.
6. **Model `resolveBackPath()`-then-`str_starts_with($base)` and separator-stripping
   `preg_replace('#[^\w._]+#','_')` as path-traversal sanitizers** (maispace_assets, pluploadfe).

Items 1–2 alone would remove the large majority of the residual candidate noise.

## Reproduce
- `mass_typo3.sh` — rebuild the corpus.
- `analyze_typo3.sh` / `resume_typo3.sh` — run/resume the CodeQL batch pipeline → `typo3_bugs.csv`.
- `triage_typo3.py` — rank candidates by severity + web-reachability.
- `aggregate_vulns.sh` — merge audit reports + CVE map + candidates → `VULN_REPORT.md`.
- Per-extension agent audits live in `/home/user/sources/code/audit/*.md`.
