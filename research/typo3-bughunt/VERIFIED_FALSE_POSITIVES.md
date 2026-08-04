# TYPO3 hunt — verified FALSE POSITIVES (CodeQL candidates cleared by source review)

Every candidate here was flagged by the mass CodeQL run, then traced request→sink by
a verification agent and **rejected** with a concrete reason. Kept as an R&D ledger:
knowing what was checked and *why it's safe* is as useful as the confirmed list, and it
documents the recurring FP shapes our queries still emit (input to fix generically).

## Dynamic-dispatch where the request controls only ARGUMENTS, not the callable identity
The dominant "Code injection" FP class. `$obj->$name(...)` / `[$obj,$name]` where `$name`
is fixed/whitelisted and the receiver is a concrete object — request controls only args.
- **cundd/rest 5.1.0** — `DataProvider.php:177/182` `$model->$getter()`. Hard `'get'.ucfirst()`
  prefix + `method_exists && is_callable` on a fixed Extbase model, zero args. A read
  primitive (`GET /rest/{Type}/{id}/{prop}`), not RCE.
- **ameos/ameos_form 3.0.2** — `SearchableRepository.php:20/49` `$query->$clause['type'](...)`.
  `type` is a hardcoded literal per form element (`like`/`equals`/`in`/`contains`) or a
  developer Closure; request controls only `value`/`field`, which flow into a
  **parameterized** Extbase query (not even SQLi). Receiver is a fixed QueryInterface.
- **dreistein/d-ai 0.1.1** — `ApiMiddleware.php:86` `$action($request,$params)`. `[class,action]`
  come from a compile-time-constant `Router` table; request only selects among whitelisted
  routes + supplies the arg array. (Real routes additionally need a backend-minted JWT.)
- **erecht24/er24-rechtstexte 4.0.0** — `AjaxController.php:131` `$domainConfig->$setterName()`.
  `method_exists` + `set`-prefix on one entity = mass-assignment, and it's a **backend** AJAX
  route (`be_user` required), not pre-auth.

## Reflected-XSS where output is encoded, or the tainted value never reaches the markup
- **bytebuilders/t3clickmark 0.3.55** — `InjectWidgetMiddleware.php:85`. HTML-body path
  json_encodes (JSON_HEX_* flags) + htmlspecialchars everything; the pre-auth path is a
  `http_build_query`-encoded 302 redirect with an empty body. HTML injection is also
  auth/config-gated.
- **ehaerer/eh_bootstrap 1.0.4** — `ExtbaseDispatcher.php:155` `echo $response->getContent()`.
  Genuinely a pre-auth eID, but the only reachable controller action never assigns the
  tainted `request[arguments]` to the view; the template outputs only Fluid-escaped,
  admin-configured `emSettings`. Taint dies before the markup.
- **dl_yag 4.1.2** — `AjaxController.php:503` `echo $content`. Reflection gated by
  `is_dir($base.$path)` (an XSS payload isn't a real dir → no output), dir names are
  `htmlentities`-escaped, and the endpoint is backend-only; the frontend AJAX path is
  `application/json`.

## Command-injection where every dynamic component is shell-escaped
- **dmk/webkitpdf 13.0.1** — `Plugin.php:310` `exec($this->scriptCall)`. The request-controlled
  target URL (`tx_webkitpdf_pi1[urls][]`) is host-allow-listed to the site's own host AND
  `escapeshellarg`'d in `Utility::sanitizeUrl` (`Utility.php:82`) before `implode(' ',$urls)`;
  option values/cookies `escapeshellarg`'d, binary path `escapeshellcmd`'d, output filename
  `escapeshellarg`'d. CodeQL missed the sanitizer because it lives in another file and returns
  through a by-ref loop + intermediate array. No unescaped bytes reach the shell.

## Path-traversal / LFI where the path is allow-listed or the sink isn't a filesystem op
- **andersundsehr/ssi-include** — `InternalSsiRedirectMiddleware.php:37/61`
  `file_get_contents($publicPath.'/typo3temp/tx_ssiinclude/'.$ssi_include)`. `ssi_include`
  (pre-auth GET) is gated by anchored `^[a-zA-Z0-9_-]+\.html$` (no `.`/`/` in body) → HTTP 400
  on any `../`. Flat filename in a fixed dir; no traversal survives.
- **dla/dla_opac_ng** — `Ajax/Decisiontree.php:54/77` `file_get_contents(...)` is an **HTTP fetch
  to a fixed env-configured Solr host** (`$host=getenv('SOLR_HOST')`), not a filesystem read;
  request input lands only after `?` in the query string. Not LFI. (Minor real issue, out of
  scope: `relation1/2` are concatenated un-urlencoded → Solr request-parameter injection within
  the fixed host.)

## SQL-injection where the flagged concat is actually escaped / parameterized
- **helhum/realurl 2.1.8** — `UrlRewritingHook.php:769/1701`. The decoded URL path *is*
  attacker input, but it reaches the sink only via `INSERTquery`→`fullQuoteArray` /
  `fullQuoteStr`, and the hand-appended `ON DUPLICATE KEY UPDATE tstamp=` is `time()` (int).
  Fully sanitized.
- **ecodev/tagpack 0.13.0** — FE `pi1` SQL paths use `intExplode`/`fullQuoteStr`; the raw-`pid`
  SQLi in `ajaxsearch_server.php` is real but **backend-authenticated** only. (Its FE reflected
  XSS is confirmed separately — see CONFIRMED_VULNS.md.)

## No pre-auth surface / backend-authed / config-sourced
- **dmk/t3socials 3.0.1** — 9 "code/command injection" hits are `makeInstance()` of class
  names from backend network-config (object factory, not exec/eval); `file_get_contents` uses
  a backend-configured URL. Only unauth surface (hybridauth eID) is int-cast/constant-matched.
- **aoe/extracache 0.9.1** — the pre-auth `echo $content` reflects a server-written static-cache
  file, not request input; the real SQLi + arbitrary controller-method call are **backend**-authed.
- **aoepeople/crawler 13.0.0** — `FrontendUserAuthenticator` middleware is correctly hardened
  (`hash_equals` against `md5(qid|set_id|encryptionKey)`, parameterized lookup, `json_decode`
  not `unserialize`). Forgery needs the secret `encryptionKey`. The XSS flag is a backend
  forced-attachment download.
- **directmailteam/direct-mail 9.5.2** (mainline) — authCode polarity correct; already carries
  the TYPO3-EXT-SA-2020-005 fixes. (The **azich** fork regresses this — see CONFIRMED_VULNS.md #9.)

## Hardened / not-pre-auth (verified, legacy cluster)
- **ribase/sr_sendcard 4.0.1** — global input sanitizer runs before any use
  (`SendcardPluginController.php:118-127`: `htmlspecialchars(strip_tags())` on every `_GP`,
  `card_image_path` force-cleared). SQLi uses `intval`/`fullQuoteStr`/array-INSERT; mail via
  Swift `MailMessage` (CRLF-safe); no user-controlled redirect; SSRF path cleared. All FP.
- **phorax/mydashboard** — **backend module** (`extends BaseScriptClass`, `addModule`
  `user_txmydashboardM1`, all entry points use `$GLOBALS['BE_USER']`). Not pre-auth. SQLi is
  `intval` on the acting BE user's own uid; no upload code; IDOR bound to own uid. (Residual:
  BE-authenticated self-XSS/CSRF in the AJAX handlers — not pre-auth.)
- **dmitryd/dd-googlesitemap 2.3.2 & communiacs/dd-googlesitemap 2.1.7** — the historic
  `L`/`pidList` eID SQLi is **fixed** in both cloned forks (byte-identical generator code):
  `pidList` via `intExplode`, `L` via `MathUtility::canBeInterpretedAsInteger`, `offset`/`limit`
  via `(int)`, `newsId`/`singlePid` via `intval`. No tainted string reaches raw SQL.

## Recurring FP shapes → generic query improvements to make (feeds codeql-php work)
1. **Code-injection on dynamic dispatch must require the METHOD/CLASS NAME to be tainted**,
   not just an argument. A `'get'.ucfirst($x)` / `method_exists`-guarded / literal-`switch`
   method name on a fixed receiver should not alert. (biggest FP source above)
2. **Separate object-factory `makeInstance($cls)` from exec/eval** — a class-name into a DI
   container is not command/code execution.
3. **Model the framework escapers as sanitizers**: `INSERTquery`/`UPDATEquery`→`fullQuoteArray`,
   `fullQuoteStr`, `createNamedParameter`, `intExplode`, Fluid auto-escaping, `RedirectResponse`
   (header, not body), `json_encode` with `JSON_HEX_*`.
4. **Rank config/TypoScript reads (`$this->conf`, `extConf`, backend DB config) below request
   sources** so config-sourced flows don't present as pre-auth-remote.
