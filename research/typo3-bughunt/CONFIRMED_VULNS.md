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

## 5. bvbmedia/multishop 5.1.110 — (abandoned, TYPO3 6.2–7.9) — multiple criticals flagged
- Flagged by the version→CVE mapper as abandoned with SQLi / insecure
  deserialization / arbitrary-file classes; dedicated source audit in progress.

---

### Lower-severity / conditional (verified, for completeness)
- realurl 1.12.8.19: conditional 404-URL-reflection XSS + below the 1.12.9 XSS fix.
- powermail 13.1.0: `print_r($_REQUEST)` reflected into the admin spam-notification mail (Low).
- cundd/rest 5.1.0: API-key brute-force (no rate limit); mass-disclosure only if `paths.*.read=allow` misconfigured.
- beechit/fal_securedownload 6.0.3: cross-storage folder-existence oracle via the FileTreeState eID (Low, no file bytes).
- extcode/cart: negative cart quantities (hardening gap).

### Hardened in the audited (latest) version — no pre-auth finding
apache-solr, sf_event_mgt, jweiland/events2, friendsoftypo3/tt_address,
in2code/powermail (core sinks), innologi/decosdata (HMAC-gated), oliverklee/realty
(int-cast). Confirms: latest maintained extensions are patched; the risk lives in
**old versions in the wild** (version→CVE map) and **abandoned** extensions.
