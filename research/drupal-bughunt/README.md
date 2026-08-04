# Drupal contrib — pre-auth bug hunt (in progress)

Second CMS in the pre-auth attack-surface research (after the completed TYPO3 hunt in
`../typo3-bughunt/`). Same methodology, adapted to Drupal's architecture.

## Corpus
- **Drupal core** (11.x) cloned from GitHub.
- **~1000 contrib modules** cloned from `git.drupalcode.org/project/<name>.git` (`--depth 1`,
  `.git` pruned) — a curated high-usage seed (`seed_modules.txt`) unioned with a GitLab-API
  enumeration of the canonical `project/` group. `clone_drupal.sh` reproduces it.

## Two tracks

### 1. Access-bypass surface map (Drupal-specific, structural) — `map_access_surface.py`
Drupal's #1 contrib bug class is **missing access control**, not taint. The mapper parses every
`*.routing.yml` for routes with `_access: 'TRUE'` (fully public) or an anonymous `_permission`
(`access content`, …), and every D7 `hook_menu` entry with `'access callback' => TRUE`, then
records the route → controller/callback target. Output: `access_surface.json`.

**207 public entry points** mapped in the current corpus. After dropping `*_test` submodules, the
real pre-auth surface to audit by hand includes:
- `plupload` `/plupload-handle-uploads` → `UploadController::handleUploads` (**anonymous file upload**)
- `select2` entity-autocomplete (`selection_settings_key` — access-bypass / label disclosure class)
- `mailchimp` `mailchimp/webhook/{hash}` (webhook `{hash}` authentication strength)
- `feeds` PubSubHubbub `push_callback` (token validation / SSRF / content injection)
- `cas` `/casproxycallback` (PGT handling / origin validation)
- `imagecache` (D7) `system/files/imagecache` (private-file derivative access bypass)
- `simple_sitemap_engines` IndexNow key-file, `og_vocab` autocomplete, `social_auth` OAuth callback.

Each public route is only a *candidate* — a route is legitimately public (login/OAuth/webhook
endpoints exist by design). The finding is whether the target performs a dangerous operation
(entity write/delete, file write, SQL, `unserialize`, outbound fetch) **without** re-checking
authorization, validating a token with `hash_equals` against a per-site secret, or confining a
file path/extension.

### 2. CodeQL taint (SQLi / XSS / code-inj / SSRF / deserialize) — reuses `../codeql-php-audit/`
The same improved `codeql-php` pack from the TYPO3 hunt, with an **augmented Drupal model**
(`patches/drupal-model.patch` under `../codeql-php-audit/patches/`): Symfony `Request` accessors
are already sources; added `Markup::create` / `FormattableMarkup::__construct` / `SafeMarkup::set`
as XSS sinks (wrapping tainted data as "safe HTML"), and `Xss::filter` / `Xss::filterAdmin` /
`Html::escape` / `Connection::escapeField` as sanitizers. `db_query` (D7) and `Connection::query`
(D8+ DBTNG) are the SQL sinks; most Drupal DB access is parameterized, so real SQLi concentrates
in `db_query("… $var")`, dynamic `->orderBy()`/`->addExpression()`, and D7 legacy modules.

## Drupal pre-auth threat model (how it differs from TYPO3)
- **Access bypass** dominates: a route/controller/entity-operation reachable without the right
  permission (the structural map above), plus `hook_entity_access` / `EntityAccessCheck` gaps.
- **SQLi**: parameterized by default; risk in `db_query` string interpolation and dynamic
  identifiers (order/field names) not passed through `escapeField`.
- **XSS**: unsanitized data in render arrays (`#markup`, `Markup::create`, Twig `|raw`), D7
  `theme()` / `drupal_set_message`.
- **Upload → RCE**: public file endpoints (plupload, filefield_sources, media) writing
  attacker-named files to web-served dirs without an extension allow-list / `.htaccess` guard.
- **SSRF**: `\Drupal::httpClient()` / `drupal_http_request` / `system_retrieve_file` on a
  request-controlled URL (feeds, migrate, oembed, CAS/OAuth callbacks).
- **Legacy (D7)**: abandoned modules with `db_query` concatenation and `access callback => TRUE`.

## Status
Corpus cloned, access surface mapped, CodeQL model augmented. Source-verification of the top
public routes is underway; confirmed findings will be recorded in `CONFIRMED_VULNS.md` and cleared
candidates in `VERIFIED_FALSE_POSITIVES.md` (same discipline as the TYPO3 hunt — every finding
re-read in source before it lands).
