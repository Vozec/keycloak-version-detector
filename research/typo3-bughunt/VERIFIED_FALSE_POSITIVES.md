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
- **friendsoftypo3/rtehtmlarea 8.7.4** — the aspell `shell_exec` (`SpellCheckingController.php:299`,
  `:393`) wraps every request-derived arg (`dictionary` allow-listed + `escapeshellarg`; tmpfile,
  charset, pspell_mode all escaped) and the binary path is instance-admin config, not request input.
  Route is a backend AJAX endpoint (`/rte/spellchecker`, be_user), the learn branch adds a second
  `BE_USER` gate. Historical cmd-inj class fully mitigated. FP.
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

- **ubl/supportchat 2.9.2** — pre-auth eID chat, but all DB access is `(int)`-cast / Extbase
  `equals(int)`; message+username `htmlspecialchars`'d (`Chat.php:264`, `AjaxFrontendController.php:166`),
  read-back is JSON; `createChatLog` is `text/plain`+attachment+`strip_tags`; chat access gated by
  a secret `fe_typo_user`-cookie match with an empty-token guard. (Nits: loose `==`→`hash_equals`,
  unauth `createChat` spam/DoS.) FP.
- **smichaelsen/social_grabber 2.4.0** — eID OAuth handler gated by
  `requestToken===hash('sha256',beUserUid.encryptionKey)` (strict, secret key), no DB touch,
  static responses. The raw `exec_SELECTquery` in `FeedDataProcessor` is built from editor
  FlexForm + DB channel rows (`intExplode`'d), not request input. Hardened/FP.
- **bitpatroon/bpn_request_access 10.4.0** — the alarming `LIKE '%$q%'` in `UserSearchEid.php:48`
  is **dead/unreachable** (eID points at a bare file that only declares the class, no bootstrap),
  additionally FE-auth-gated and `mysqli_real_escape_string`'d. The unauth grant/deny actions are
  gated by a single-use expiring `hash_hmac` verification code (parameterized lookup + HMAC
  recompute, `===`, empty rejected), emailed only to the admin. Hardened/FP.

- **subugoe/bib 1.6.1 & ipf/bib 1.6.1** (byte-identical pi1) — anonymous search input reaches SQL
  only via `intExplode`/`fullQuoteStr` (`ReferenceReader.php`), ORDER BY is FlexForm-driven (not
  `piVars`), and the lone raw pi1 query (`:3087`) is `edit_mode`-auth-gated + integer-sourced.
  No pre-auth SQLi/XSS. (The ve_guestbook stored XSS is confirmed separately.)

## Path-traversal / upload FPs — separator-stripping sanitizer or resolve-then-check confinement
- **felixnagel/pluploadfe 9.0.3-dev (TYPO3 14.2)** — FE upload middleware, but the request
  filename (`$_REQUEST['name']`/`$_FILES['file']['name']`) is `preg_replace('#[^\w\._]+#','_')`'d
  (`Upload.php:273`) — every `/`,`\`,NUL → `_`, so no separator survives to
  `fopen`/`rename`/`unlink($filePath)` (`:326/353/371`); `upload_path` is FAL-validated under the
  public path. RCE additionally needs admin misconfig AND is blocked by core `fileDenyPattern`
  (`FileNameValidator`). No traversal, no default-config RCE.
- **maispace/mai-assets 1.0.0** — `StaticFileServeMiddleware.php:119`
  `file_get_contents($filePath)` where the URI-derived path goes through
  `GeneralUtility::resolveBackPath` (collapses `../` textually) **before** the
  `str_starts_with($baseDir)` guard (applied twice), and the resolved name is always the
  hardcoded `/index.html`. `../` escapes throw → null → pass-through. Arbitrary read not achievable.

## "SQLi" sinks that are actually search-engine (Solr/Elasticsearch) queries
- **kitodo/presentation (dlf) 7.0.1** — `SearchInDocument.php:152` / `SearchSuggest.php:64`
  `$query->setQuery(...)` are **Solarium/Apache-Solr** query objects (`Solr.php:581`
  `makeInstance(Solarium\Client)`), not a DB QueryBuilder → misclassified as SQLi. `q` is
  `Solr::escapeQuery()`-escaped; the only raw value is a non-numeric `uid` in SearchInDocument =
  a low-severity **Solr query injection** (index read), and both middlewares are gated by an
  encryptionKey-derived token (`encrypted` / HMAC `uHash`), so not cleanly anonymous. Not SQLi.

## ORDER BY / identifier concat where the sort field is a fixed allow-list or backend-only
- **phorax/loginusertrack 3.0.0** — `orderby` (`_GP`) whitelisted by
  `GeneralUtility::inList('username,name,email,lastlogin', $orderBy)` (fallback `name`);
  `id`/`daysBack` int-cast; backend-only module (`web_txloginusertrackM1`, be_user). FP.
- **labor-digital/typo3-frontend-api 10.8.4** — `$value->$method()`
  (`TransformationSchema.php:119`) where `$method` is harvested by `AbstractReflector` from the
  server-side model's existing zero-arg `get*/is*/has*` getters via `ReflectionClass`; request
  controls neither method name nor args. Anonymous API, but bounded getter dispatch, not code-inj. FP.
- **maispace/mai-faq 1.0.0** — `orderBy('f.'.$sort,$order)` (`FaqApiMiddleware.php:140`) but
  `$sort` is `in_array(…,['sorting','question','uid'])`-whitelisted and `$order` normalized to
  literal ASC/DESC; all other inputs `createNamedParameter`/`(int)`. Pre-auth `/api/faq` reachable
  but no injectable sink. FP.
- **kohlercode/slug 5.1.0** — real `orderBy($orderby,$order)` + raw table/column concat
  (`PageRepository.php:136`, `RecordRepository.php:89`), request-sourced via `getQueryParams`,
  but the routes are **backend AJAX** (`Configuration/Backend/AjaxRoutes.php`, BE-auth + CSRF,
  none `access=public`). "slug" is a backend editorial module, not FE slug resolution. Not pre-auth.
- **in2code/lux 43.1.0** — raw-concat SQL at `PagevisitRepository.php:341`, but time filter is
  `format('U')` ints, site filter is `Connection::quote()`, domains pass a `cleanString('./_-')`
  allow-list, limit is typed int. Only caller is a backend dashboard widget. FP.
- **jweiland/kk-downloader 7.0.0** — `orderBy('i.'.$orderBy,$direction)` (`DownloadRepository.php:67`)
  but `$orderBy`/`$direction` come from the content element's **FlexForm** (`pi_getFFvalue`),
  fixed `selectSingle` allow-lists (name/image/crdate/…, ASC/DESC) — editor config, not request.
  `pointer` is `(int)`-cast. Anonymous FE plugin, but the injectable inputs aren't request-reachable.

## More dynamic-dispatch FPs — eID/middleware dispatchers bounded to whitelisted callables
- **stmllr/zahnstocher** — eID `Dispatcher.php:61` `$class::$method` from `_GP`, but both are
  `^[a-zA-Z]+$`-filtered, class prefix hardcoded `Stmllr\Zahnstocher\Controller\` behind
  `class_exists`, method `$name.'Action'` behind `method_exists`; only `MailboxController` exists
  (no-arg helpers). Not RCE. (Minor pre-auth mailbox flush, out of scope.)
- **site/site-core** — `AjaxMiddleware.php:79` `makeInstance($cfg['target'])` where target is a
  developer-registered class from `$GLOBALS[...]['site_core']['AJAX']`; `vendor`/`ajax` params only
  *select* a registered entry. (Secondary: wildcard-branch `$method` lacks `method_exists` — method
  selection on an already-whitelisted instance, needs a `*` config; not RCE.) `@deprecated`.
- **skynettechnologies/allinoneaccessibility 14.0.1** — `AwesomeMiddleware.php` curl target is the
  hardcoded `https://ada.skynettechnologies.us/api/widget-settings`; attacker `HTTP_HOST` only
  fills the POST body `website_url`, never host/scheme. No request-controlled fetch URL. FP for SSRF.

## More dynamic-dispatch / assert FPs (argument-only or non-sink)
- **madj2k/t3-cat-search 13.4.1** — `$search->$setter($value)` (`AbstractSearchController.php:271`),
  `method_exists`-guarded on a `final Search` DTO; request controls only the argument → mass-assign,
  not RCE.
- **oliverklee/seminars 6.0.x** — the 5 flagged lines are `\assert($x instanceof C)` (boolean
  type-asserts, not `assert('code')`) and `array_map([$this,'pi_getClassName'],…)` (constant
  callable). No dynamic sink.
- **pixelant/pxa-pm-importer 2.0.1** — `$this->{$action}($request)` with request-controlled
  `$action`, but bounded to the controller's own 4 methods AND the route is **backend**
  (`Configuration/Backend/AjaxRoutes.php`, `be_user`). Not FE, not arbitrary-callable.
- **maikschneider/tca-api 0.6.2** — `makeInstance($class)->$method(...)` where `[$class,$method]`
  is a build-time-validated developer-config checker tuple; request flows only as arguments.

## Reflected-XSS flags where the "sink" is an HTTP redirect header, not an HTML body
- **webentwicklerat/openid-connect 0.0.0 (v13.4)** — `AbstractRedirect` middleware emits only
  `RedirectResponse($originalRedirectUri)` (`:76`) — a `Location` header, no `echo`/HTML anywhere,
  so `tx_openidconnect_redirecturi` is not an XSS sink. Open-redirect is separately gated by
  `OpenidConnectUtility::isTrustedRedirectUrl($originalRedirectUri)` (`:70`). Pre-auth (OIDC flow)
  but no reflected-XSS primitive. FP.

## Reflected-XSS flags killed by response Content-Type / unwired library entry
- **jvelletti/jvchat 13.4.1** — the reflected sinks are FP: `Chat.php:689` is a JSONP
  `callback` echo under `application/json`; `:980` is an `application/xml` `<![CDATA[]]>`
  envelope (not executed on navigation); `JvchatEid.php:41/48` is unregistered dead code; eID
  DB access is int-cast + parameterized QueryBuilder. (The chat-message **stored** XSS is a real
  auth-gated finding — see CONFIRMED_VULNS.md authenticated section.)
- **jambagecom/taxajax 1.4.0** — ships the xajax **library**; registers no handler and never
  calls `processRequests()`/`printJavascript()` (consumer-invoked). `XajaxHandler.php:117`
  `trigger_error` goes to the log not the response; `class.tx_taxajax.php:672/710` are
  `text/xml`/library API with no in-extension caller. Latent defects (unescaped `]]>` in CDATA;
  raw request-URI into an inline `<script>` in `getJavascriptConfig`) require a consumer to wire
  the library + a same-origin xajax client — not a request→executing-sink chain as shipped. FP.

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
