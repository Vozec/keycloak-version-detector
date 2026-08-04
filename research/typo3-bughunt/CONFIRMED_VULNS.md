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
- realurl 1.12.8.19: conditional 404-URL-reflection XSS + below the 1.12.9 XSS fix.
- ecodev/tagpack 0.13.0: pre-auth reflected XSS — `pi1` echoes `piVars[searchWord|from|to]`
  and arbitrary GET params into `<input value="…">` unencoded
  (`class.tx_tagpack_pi1.php:302/316/321/366`). Its `ajaxsearch_server.php` `pid` SQLi
  is backend-auth only. Med.
- powermail 13.1.0: `print_r($_REQUEST)` reflected into the admin spam-notification mail (Low).
- cundd/rest 5.1.0: API-key brute-force (no rate limit); mass-disclosure only if `paths.*.read=allow` misconfigured.
- beechit/fal_securedownload 6.0.3: cross-storage folder-existence oracle via the FileTreeState eID (Low, no file bytes).
- extcode/cart: negative cart quantities (hardening gap).

### Hardened in the audited (latest) version — no pre-auth finding
apache-solr, sf_event_mgt, jweiland/events2, friendsoftypo3/tt_address,
in2code/powermail (core sinks), innologi/decosdata (HMAC-gated), oliverklee/realty
(int-cast). Confirms: latest maintained extensions are patched; the risk lives in
**old versions in the wild** (version→CVE map) and **abandoned** extensions.
