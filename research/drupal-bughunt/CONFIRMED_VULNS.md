# Drupal hunt — CONFIRMED pre-auth findings (source-verified)

Findings re-read in source. Drupal's maintained modules have strong access primitives, so — as in
the TYPO3 hunt — most public routes are properly defended (see `VERIFIED_FALSE_POSITIVES.md`); the
real issues are edge cases (fail-open-when-unconfigured, a missing origin check) and, expected, the
legacy/abandoned cluster (CodeQL pipeline running).

---

## 1. cas `/casproxycallback` — LOW/MEDIUM — pre-auth unauthenticated DB write + bounded PGT injection (ORIGINAL)
- **Entry (pre-auth):** route `cas.proxyCallback` is `_access: 'TRUE'` → `ProxyCallbackController::callback`.
- **Cause:** the controller **does not validate the request originates from the configured CAS
  server** — the code says so itself: `ProxyCallbackController.php:37`
  `// @todo Check that request is coming from configured CAS server to avoid filling up the table
  with bogus pgt values.` It only checks that `pgtId` and `pgtIou` query params are present (`:43`),
  then stores the **attacker-controlled** values: `storePgtMapping($pgt_iou, $pgt_id)` (`:51` →
  `:72`, a parameterized INSERT into `cas_pgt_storage` — no SQLi).
- **Exploit:** `GET /casproxycallback?pgtId=X&pgtIou=Y` → `200 OK`, a row is written anonymously.
- **Impact:** unauthenticated persistent DB writes → `cas_pgt_storage` table-flooding DoS (the
  `@todo`'s own stated concern). Full proxy-ticket hijack is **conditional** — it requires
  predicting the server-issued `pgtIou` later looked up by `CasProxyHelper::storePgtSession`
  (`CasProxyHelper.php:187`), which is normally unpredictable. No outbound fetch → no SSRF.
- **Fix:** implement the `@todo` — reject callbacks whose source IP/host isn't the configured CAS
  server; rate-limit / cap the PGT table.

## 2. mailchimp `mailchimp/webhook/{hash}` — LOW — pre-auth webhook auth fail-open when unconfigured (ORIGINAL, needs-config-default)
- **Entry (pre-auth):** route is `_access: 'TRUE'` → `MailchimpWebhookController::endpoint($hash)`.
- **Cause:** the auth gate is `if (!empty($webhook_hash) && !hash_equals($webhook_hash, $hash))`
  (`MailchimpWebhookController.php:57`) — when `webhook_hash` is **empty the check is skipped
  entirely** and the POST body is processed unauthenticated. It **is** empty by default:
  `config/install/mailchimp.settings.yml` ships no `webhook_hash`; it is only generated when an admin
  saves the settings form (`MailchimpAdminSettingsForm.php:231`). The module's own
  `WebhookHashTest.php:30-32` documents "if there are no settings, any request should work → 200".
- **Exploit (default/pre-config state):**
  `POST /mailchimp/webhook/anything` body `type=unsubscribe&data[list_id]=abc&data[email]=victim@…`
  → `200`, processed unauthenticated (list cache refresh + `hook_mailchimp_process_webhook`).
- **Impact:** LOW — no SQLi/`unserialize`/SSRF from the body; effect is limited to cache refresh
  and any (no in-tree) webhook-process hook implementors. When configured, comparison is
  `hash_equals` against a per-site `md5(uniqid(mt_rand(),TRUE))` secret — secure.
- **Fix:** fail closed — require a configured `webhook_hash` (reject if unset).

## 3. social_auth `user/login/{network}/callback` — MEDIUM/HIGH (provider-dependent) — pre-auth account takeover via unverified-email linking (ORIGINAL)
- **Entry (pre-auth):** `_access: 'TRUE'` → `OAuth2ControllerBase::callback`. OAuth `state`/PKCE are
  correctly validated (from session), and token exchange is delegated to `league/oauth2-client` —
  those are **not** the issue.
- **Cause:** after a successful provider round-trip, `UserAuthenticator::authenticateWithEmail()`
  (`src/User/UserAuthenticator.php:223-248`) does `loadUserByProperty('mail', $providerEmail)` and,
  if any Drupal user has that email, calls `authenticateExistingUser($drupal_user)` — logging the
  caller into that account. There is **no `email_verified` claim check** (grep: the string appears
  nowhere in `src/`) and **no config toggle** gating the behaviour (unlike openid_connect's
  default-off `connect_existing_users`). The module trusts the email from *every* configured
  provider unconditionally.
- **Exploit:** on a site with any social-login network whose provider lets a user set/return an
  **unverified** email, the attacker sets their provider-account email to the victim's Drupal email,
  completes the OAuth flow in their own browser (so `state` is satisfied), and is logged in as the
  victim. uid 1 and blocked/roleless accounts are excluded, but ordinary accounts are takeable.
- **Impact:** pre-auth account takeover, **provider-dependent** (mainstream IdPs that enforce
  verified email are safe; providers permitting unverified/arbitrary emails are not — and the module
  makes that an all-or-nothing trust decision the operator can't scope).
- **Fix:** require an `email_verified`/equivalent claim (or a per-network "emails are verified" trust
  flag) before linking to an existing account by email.

## 4. coolfilter (Drupal 5/6, abandoned) — HIGH — pre-auth PHP object injection via bundled PHPRPC 2.1 standalone scripts (ORIGINAL)
- **Entry (pre-auth, bypasses Drupal entirely):** the module ships standalone scripts that
  instantiate a 2006 PHPRPC server at **file scope with no Drupal bootstrap / access check** —
  `rpc.php:1365 new phprpc_server(['play_media','coolplayer_rpc_version'])` and
  `mbstring.php:15 new phprpc_server(['mb_urlencode','mb_convert_encoding'])`. Directly reachable at
  e.g. `GET/POST /sites/all/modules/coolfilter/rpc.php` (or `/modules/coolfilter/rpc.php`).
- **Sink:** the constructor → `start()` reads `$_REQUEST` and at `phprpc_server.php:195` does
  `$arguments = unserialize(base64_decode($_REQUEST['phprpc_args']))` — **raw `unserialize` of
  fully attacker-controlled bytes, no `['allowed_classes'=>false]`** (2006 code). The only gate to
  reach it is `phprpc_func` ∈ the registered list (satisfied by `play_media`/`mb_urlencode`) and
  `encrypt` defaults to 0 (no xxtea layer).
- **Exploit:** `POST /sites/all/modules/coolfilter/rpc.php` body
  `phprpc_func=play_media&phprpc_args=<base64(serialized POP-gadget object)>` → the object graph is
  instantiated during `unserialize` before any RPC function runs → PHP object injection → RCE via a
  POP chain in the host's autoloaded runtime (Symfony/Guzzle/…).
- **Also (pre-auth reflected XSS):** `coolplayer.php` runs at file scope, echoes `$_GET` unescaped
  (`:51 echo $url` from `coolplayer_url`; `:22-42` reflect `coolplayer_src/width/height/...` into a
  `document.writeln`), `Content-Type: text/html`. `GET /…/coolplayer.php?coolplayer_url=<script>…</script>`.
- **Caveat (honest):** coolfilter targets Drupal 5/6 (abandoned, low current deployment), and RCE
  needs a POP gadget in the running app. But the standalone scripts are directly reachable
  regardless of Drupal version, and the object-injection primitive is unconditional. HIGH.
- `phprpc_client.php` "SSRF" is a FP (fsockopen host is the hardcoded coolcode.cn, not request-driven).

## 5. banner (Drupal 6, abandoned) — MEDIUM — pre-auth path traversal + unserialize via standalone banner_file.php (ORIGINAL)
- **Entry (pre-auth, bypasses Drupal):** `modules/banner/banner_file.php` runs at file scope and does
  its file I/O **before** any `drupal_bootstrap` (first bootstrap is `:100`, the file loop starts
  `:18`). Directly reachable: `GET /sites/all/modules/banner/banner_file.php`.
- **Chain:** `$path = $_GET['path']` (`:13`) → `$cache_file = $path.'/.'.$i.'.banner.cache'` (`:19`) →
  `fopen($cache_file,'r+')` (`:20`) → `fread` (`:42`) → `unserialize($contents)` (`:44`) → `fwrite`
  back (`:135`). **No `basename`/`realpath`/`..` filtering and no fixed base dir** → `$path` traverses
  freely. `?path=../../../../some/dir&max=1&group=0&count=1&terms=0`.
- **Primitives:** (1) path-traversal read/rewrite of any `*/.N.banner.cache` file (suffix hard-coded,
  `r+` needs an existing writable file); (2) the sharper one — `unserialize()` of attacker-influenced
  cache content = PHP object injection where the attacker can plant/redirect to a `.N.banner.cache`.
- **Caveat (honest):** Drupal 6-era (abandoned, low deployment); the object-injection leg needs
  attacker-controlled cache-file content. The pre-auth traversal + raw unserialize are unconditional. MED.

## 6. drutex (Drupal 5, abandoned) — HIGH — pre-auth command injection → RCE (ORIGINAL, config-gated)
- **Entry (pre-auth):** the `remote` submodule registers `drutex/remote` with **`'access' => TRUE`**
  (anonymous) → `drutex_remote_do_render` (`drutex.module:39-42`).
- **Sink:** `drutex_remote.inc` reads `$dpi = $_REQUEST['dpi']` and `$text = $_REQUEST['text']`
  (`:314-315`), substitutes `$dpi` **unescaped** into the `[DPI]` placeholder of the (admin-config)
  command template, and runs each line with `exec($cmd)` (`:353`) — **no `escapeshellarg`**. Second
  vector: `$text` is written into the `.tex` file compiled by `latex`, enabling `\write18` shell
  escape. `?dpi=1;id` / shell metacharacters in `dpi` inject directly.
- **Gate (not an auth gate):** `$allowed_to_run` requires `drutex_remote_rendering_enabled==1`
  (off by default) and passing an `eregi()`-based IP allow-list (weak matching). When the site is
  deployed as a DruTeX **remote-render server** (its intended role), it is unauthenticated RCE.
- **Caveat:** Drupal 5-era (abandoned), and exploitation requires the remote-render config enabled.
  But no Drupal login is involved and the injection is unescaped. HIGH (config-conditional).

## 7. trackback (Drupal 6, abandoned) — MEDIUM — anonymous (blind) SSRF (ORIGINAL, config-gated)
- **Entry (pre-auth):** `trackback/%node` → `trackback_receive` (`trackback.module:326`), access
  `_trackback_access('receive')` = `can_receive` (defaults 1) + `node_access('view')` — satisfied
  for anonymous on any published node; no permission required.
- **Sink:** `trackback.ping.inc:31` `drupal_http_request($_REQUEST['url'])` — outbound fetch to a
  URL taken **verbatim** from the anonymous request body. `_trackback_valid_url`
  (`trackback.module:467`) checks only `^(https?)://` + a charset regex — **no host/IP filtering**,
  so `http://169.254.169.254/…`, `http://127.0.0.1/…`, internal hosts all pass.
- **Gate:** fires only when `variable_get('trackback_reject_oneway', 0)` is enabled (a non-default
  anti-spam option that verifies the sender links back).
- **Exploit (when enabled):** `POST /?q=trackback/123` body `url=http://169.254.169.254/latest/meta-data/`
  → blind SSRF (response body not returned, only `<error>`), reaching internal services / cloud
  metadata. The other `drupal_http_request` calls in the file use node-body/editor URLs, not the
  anonymous ping body. MED (config-conditional).

## 8. statichtml (pre-D6, abandoned) — LOW/MED — pre-auth path traversal → arbitrary file read (writable files) (ORIGINAL)
- **Entry (pre-auth, bypasses Drupal):** `static.php` is a standalone script — `require('config.php')`
  only sets `$staticHTML_storage_folder`, **no `drupal_bootstrap`**. Directly reachable:
  `GET /sites/all/modules/statichtml/static.php?id=…`.
- **Chain:** `static.php:18` `print staticHTML_getpage($staticHTML_storage_folder.'/staticHTML/'.$_GET['id'])`
  → `:6` `fopen($file,"r+")` → read + printed. `$_GET['id']` is concatenated after a fixed prefix and
  passed **unmodified** to `fopen` — **no `basename`/`realpath`/`..` rejection**. `?id=../../../<target>`
  escapes the prefix.
- **Primitive (honest caveat):** `"r+"` mode requires the target be webserver-**writable** (so not
  `/etc/passwd`) — arbitrary read of webserver-writable files (uploads, logs, session files,
  Drupal-writable source), echoed in the response. Pre-D6 era, abandoned. LOW/MED.

## 9. amocrm_widget (Drupal 7) — CRITICAL/HIGH — anonymous arbitrary function invocation + auth bypass (ORIGINAL)
- **9a — Arbitrary function invocation (CRITICAL, CWE-749):** `amocrm_widget/form-submit`
  (`amocrm_widget.module:32-35`, **`'access callback' => TRUE`** = anonymous) →
  `amocrm_widget_form_submit()` (`:270-280`): `$form_data = $_POST;` then
  `if (!empty($form_data['callback']) && function_exists($form_data['callback'])) { $data = $form_data['callback']($form_data); }`
  — the attacker names **any defined PHP function**, called with the `$_POST` array as its argument.
  `function_exists` does **not** bound the callee to safe functions (it is true for `system`,
  `phpinfo`, Drupal internals, file/DB helpers). `POST /amocrm_widget/form-submit` with
  `callback=phpinfo` → full `phpinfo()` disclosure; other single-array-arg functions give
  file/DB/redirect primitives. Anonymous, no token/CSRF.
- **9b — Auth bypass / session takeover (HIGH):** `amocrm_widget/widget-init?api_key=…`
  (`:11-14`, `access callback TRUE`) → `_amocrm_widget_user_login_by_key()` (`:250-264`):
  `amocrm_widget_get_user_by_api_key($api_key)` (plain `array_search`/`==`), then for anonymous
  (`$user->uid==0`) any matched account triggers `$user = $account; user_login_finalize();` — logs
  the caller in **as that user**. The api_key travels in the GET URL (leaks via logs/referer/history)
  and there is no flood/rate-limit or constant-time compare. Session takeover on key knowledge/leak.

## 10. api_normalization 1.x (CURRENT, Drupal ^10||^11) — MEDIUM/HIGH — anonymous entity IDOR / info disclosure (ORIGINAL)
- **Entry (pre-auth):** route `api_normalization.schema_org.transform_entity`
  (`api_normalization.routing.yml:1036`): `/api_normalization/schema-org/transform/{entity_type}/{entity_id}`,
  `_permission: 'access content'` (held by anonymous by default), GET, `_format: json`.
- **Cause:** `SchemaOrgController::transformEntity()` does
  `$entity = $this->entityTypeManager->getStorage($entity_type)->load($entity_id)` and returns the
  entity's field values as JSON-LD **with no `$entity->access('view')` / publish check**. (The class
  ships an `access()` method requiring an admin perm, but it is **not wired to the route** — dead code.)
- **Exploit:** `GET /api_normalization/schema-org/transform/node/<id>` returns **unpublished** node
  fields; `…/transform/user/<uid>` returns user-entity fields (email, etc.) — anonymous enumeration by
  incrementing id. Current maintained module → higher impact. Fix: enforce `$entity->access('view')`.
- The submodule webhook `/api/webhook/{webhook_id}` is properly HMAC-SHA256 + `hash_equals` fail-closed (FP).

## 11. better_register 8.x (Drupal 8) — MEDIUM — forgeable email-verification token (ORIGINAL)
- **Entry (pre-auth):** `/user/register/verify-email/{account}/{hash}` (`_access: 'TRUE'`) →
  `ConfirmationEmailController` — grants the `email_confirmed` role when
  `$hash == static::getUserHash($account)` (`:67`).
- **Cause:** `getUserHash()` (`:88`) returns `md5($account->getEmail() . $account->getPreferredLangcode())`
  — **no site secret/salt**, and compared with loose `==` (not `hash_equals`). Since the module sets
  username = email, emails are public → an attacker computes `md5(<email>.'en')` and **confirms/verifies
  any account** without inbox access (email-verification bypass). Fix: HMAC with the site hash-salt +
  `hash_equals`. (Register-form role mass-assignment was checked — no roles field exposed, FP.)

## 12. filerequest (Drupal, abandoned) — MEDIUM — pre-auth access-control bypass (download access-restricted files) (ORIGINAL)
- **Entry (pre-auth, bypasses Drupal grants):** `filerequest/throttle.php` is a standalone script
  (`require_once("downloadhandler.php")` + `require("throttle.config.php")` at file scope; both
  shipped) that streams a request-selected file via `__fr_process_download($config["filename"], …)`
  (`throttle.php:30`) **before** Drupal bootstrap (`require("index.php")` is at `:46`, after the
  `exit()`).
- **Cause:** unlike the Drupal-native `_filerequest_download()` (`filerequest.module:115-118`, which
  enforces `hook_file_download` grants), the throttle path performs **no grant/permission check**. The
  only gate is a referer "antileech" that **returns true on an empty `Referer`**
  (`downloadhandler.php:107`) — trivially bypassed. Path traversal to system files is blocked
  (`__fr_file_create_path` does `realpath()` + `strncmp()` prefix-confine to `<base>/files/`), so this
  is an **access bypass within `files/`**, not arbitrary FS read.
- **Exploit:** `GET /sites/all/modules/filerequest/throttle.php?file=<path under files/>` with **no
  Referer** → downloads private/access-controlled managed files anonymously (bypasses node/file
  access). MED.

## 13. audio_streaming_player (Drupal) — MEDIUM — pre-auth SSRF via standalone as_getnowplaying.php (ORIGINAL)
- **Entry (pre-auth, bypasses Drupal):** `audio_streaming_player/NowPlaying/as_getnowplaying.php` is a
  pure file-scope script — **no bootstrap, no auth**. Directly reachable:
  `POST /sites/all/modules/audio_streaming_player/NowPlaying/as_getnowplaying.php`.
- **Sink:** `$audio_streaming_player_stream_url = $_POST['audio_streaming_player_stream_url']` (`:7`) →
  `$stream = fopen($audio_streaming_player_stream_url, 'r')` (`:22`) — attacker fully controls the
  host/port/scheme with **no validation** (`http://169.254.169.254/latest/meta-data/`, `file:///etc/passwd`,
  internal hosts). Reflection is limited to the ICY `StreamTitle` (≤39 chars), so it's blind/semi-blind
  SSRF (+ marginal XSS only via an attacker-controlled ICY server). MED.

## 14. admin_database (CURRENT, Drupal ^9||^10) — HIGH — pre-auth local file inclusion → RCE via cookie-controlled include (ORIGINAL)
- **Entry (pre-auth, bypasses Drupal):** `admin_database/assets/adminer_with_plugins.php` is a
  standalone loader with **no authentication of any kind**. Directly reachable:
  `GET /modules/admin_database/assets/adminer_with_plugins.php`.
- **Sink:** `$adminerFile = $_COOKIE["admin_database_adminer_file"]` (`:7`) → `include $adminerFile;`
  (`:42`). The value is included **with no path validation / basename / realpath / allow-list**; the
  only gate is that the cookie be non-empty (client-supplied).
- **Exploit:** `GET …/adminer_with_plugins.php` with `Cookie: admin_database_adminer_file=/etc/passwd`
  → arbitrary local file inclusion; with PHP wrappers
  (`php://filter/convert.base64-encode/resource=…` for source disclosure, or `data://`/log-poisoning/
  a plantable upload) → **RCE**. Current maintained (^9||^10) → high impact. HIGH.

## 15. arcade (Drupal 6, abandoned) — MEDIUM/HIGH — pre-auth local file inclusion (ORIGINAL)
- **Entry (pre-auth):** `arcade/gameserver.php` self-bootstraps Drupal (`:30`) with **no access
  check** (`arcade_check_secure()` is defined `:10` but never called at file scope). Directly reachable.
- **Sink:** `include_once("protocols/{$_POST['game_protocol']}.inc")` (`:42`) — the POST value is
  concatenated into the include path with **no whitelist/basename/realpath**. `.inc` is appended.
- **Exploit:** `POST game_protocol=../../../../sites/default/files/<plantable>` → includes an
  attacker-plantable `.inc` (e.g. via any file-upload sink) → RCE; also arbitrary `.inc` disclosure /
  traversal. Score-submission SQL there is `%d`-parameterized (clean). MED/HIGH (`.inc`-restricted).

## 16. about (Drupal 7 theme) — MEDIUM — pre-auth SSRF via standalone imageFactory.php (ORIGINAL)
- **Entry (pre-auth, bypasses Drupal):** `about/tools/imageFactory.php` runs at file scope (no
  bootstrap, no auth); `require_once('simpleImage.php')` resolves in the same dir (no fatal). Directly
  reachable: `GET /modules/about/tools/imageFactory.php?i=…`.
- **Sink:** `$img = $_GET['i']` (`:3`) → guard `preg_match("/^[^\.\/]/", $img)` (`:5`) which only checks
  the **first byte** is not `.`/`/` → `$image->load($img)` → `getimagesize($img)` (`simpleImage.php:30`)
  + `imagecreatefrom{jpeg,gif,png}($img)`. The regex is near-useless: `http://169.254.169.254/x`,
  `php://filter/…`, and `a/../../../etc/passwd` all pass (first char is a letter).
- **Exploit:** `GET …/imageFactory.php?i=http://169.254.169.254/latest/meta-data/&w=100` → server-side
  fetch = SSRF (cloud metadata / internal hosts); `?i=php://filter/convert.base64-encode/resource=…` →
  local file read as "image". MED.

## 17. azure_blob (Drupal 7) — MEDIUM/HIGH — pre-auth arbitrary private-blob read / file-access bypass (ORIGINAL)
- **Entry (pre-auth):** hook_menu `azure/remote` is **`'access callback' => TRUE`** (`azure_blob.module:84`)
  → `azure_blob_remote_files($scheme)`. Its sibling `azure_blob_image_style_deliver` enforces
  `IMAGE_DERIVATIVE_TOKEN` (`:123-124`), but `remote_files` has **no token / grant check** — only
  `file_stream_wrapper_valid_scheme($scheme)` (validates the scheme *name*, not access).
- **Sink:** `$scheme = arg(1)`, `$target = implode('/', array_slice(func_get_args(),1))` (the rest of the
  request path) → `file_stream_wrapper_get_instance_by_uri("$scheme://$target")->downloadContent()`
  (`azure_blob.streamwrappers.inc:222`) → `getBlob(container, getFileName())` (blob name = request path
  verbatim, `getTarget()` only trims slashes — **no confinement, no grant check**) → `fpassthru`.
- **Exploit:** the container is **private by default**, so
  `GET /azure/remote/<azure_scheme>/path/to/private/secret.pdf` streams any blob in the container to an
  anonymous caller, bypassing Drupal's private-file access system. MED/HIGH. Fix: enforce a per-file
  access/token check like the image-style sibling.

## 18. adaptive_image (Drupal 7) — MEDIUM/HIGH — pre-auth private-file (image derivative) disclosure (ORIGINAL)
- **Entry (pre-auth):** hook_menu `system/files/styles/%image_style/adaptive-image` (`access callback => TRUE`)
  → `adaptive_image_style_deliver` → `adaptive_image.image.inc`.
- **Cause:** for the `private` scheme, when the derivative is **already cached**
  (`if (file_exists($derivative_uri))`, `:64`) it calls core `file_download($scheme, …)` (`:65`) but
  **discards the return value**. `file_download()` on a denied request returns `drupal_access_denied()`
  **without `exit()`**, so execution falls through to the unconditional `file_transfer($image->source, …)`
  (`:105`) and streams the private image derivative. (The `else`/uncached branch `:70` correctly `return`s
  — the bug is the cached-file shortcut.)
- **Exploit:** `GET /system/files/styles/<style>/adaptive-image/private/path/secret.jpg` (with an
  `adaptive_image` cookie matching a cached derivative) → anonymous read of a private image, bypassing
  Drupal's private-file access. MED/HIGH.

## 19. avantlinker (Drupal 7) — MEDIUM — pre-auth reflected XSS (ORIGINAL)
- **Entry (pre-auth):** hook_menu `avantlink-search-results` (`access callback => TRUE`) →
  `avantlinker_product_import_display` → `avantlinker_api.inc`.
- **Cause:** `$str_search_term_safe = check_plain($search_term)` (`:29`) is computed but **never used**;
  the zero-results branch echoes the **raw** URL path arg: `$str_output .= "$search_term Search Term"`
  (`:59`), rendered into the HTML page. Zero results are trivially forced (a payload matches nothing /
  affiliate IDs unset). SSRF is a FP (fixed host `www.avantlink.com`).
- **Exploit:** `GET /avantlink-search-results/<img src=x onerror=alert(document.cookie)>`. MED.

## 20. api_source (Drupal, standalone) — MEDIUM — pre-auth source-code disclosure / access bypass (ORIGINAL)
- **Entry (pre-auth):** hook_menu `api/source/%/%` (`api_source.module:21`, **`access callback => TRUE`**)
  → `api_source_megarow_callback($did, $type)` (`:30`) returns `$doc->code` — the member/function **source
  code** indexed by the api.module — by numeric `did`, **bypassing** the api.module's `access API reference`
  permission (which anonymous does not hold by default). SQLi is a FP (`api_object_load` uses parameterized
  `db_select()->condition()`); `$doc->code` is server-pre-escaped (no XSS).
- **Exploit:** `GET /api/source/123/function`, iterate `did` to dump the site's indexed PHP source. MED.

## 21. ajax_dlcount (Drupal 7) — LOW — anonymous DB mutation (counter inflation + storage DoS) (ORIGINAL)
- **Entry (pre-auth):** hook_menu `file/%/dlcounter` (`access callback => TRUE` overrides the `access
  content` arg, `:14-21`) → `ajax_dlcount_count()` (`:37`), anonymous GET, **no CSRF token**.
- **Cause:** for **any** `$fid` (no existence check) it `UPDATE file_dlcount` (`:50`) / `INSERT INTO
  file_dlcount` (`:53`). `GET /file/<n>/dlcounter` inflates the public download counter and seeds
  unbounded junk rows (storage DoS). Per-IP dedup is bypassable via rotating IPs and resets after the
  24h retention cron. **SQLi is a FP** — all queries use named placeholders (`:fid`,`:ip`). LOW.

## 22. azure (azure_storage, Drupal 7) — MEDIUM/HIGH — pre-auth private-file (image derivative) read (ORIGINAL)
- **Entry (pre-auth):** hook_menu `azure/generate/%image_style` (`azure_storage.module:39-43`,
  **`access callback => TRUE`**) → `azure_storage_image_style_deliver($style, $scheme)` (`:49`).
- **Cause:** it's a copy of core's `image_style_deliver` that **dropped the `itok` token check, the
  `drupal_access_denied()` denial, and the `hook_file_download` access hooks** (grep: no `itok` /
  `file_download` / `drupal_access_denied` anywhere in the module). `$target = implode('/', $args)`
  (`:58`) is the unsanitized trailing URL path → `"$scheme://$target"` → `copy()` → the derivative is
  generated and served.
- **Exploit:** `GET /?q=azure/generate/thumbnail/private/confidential/secret.jpg` → 302 to a generated
  derivative of the **private** image — anonymous read of `private://` (and any wrapper-reachable)
  image files, bypassing Drupal's private-file access + the anti-enumeration `itok`. MED/HIGH. (Same
  class as azure_blob #17 and adaptive_image #18 — a delivery callback missing the access re-check.)

## 23. aegir_ansible (aegir_ansible_inventory, Drupal 7 / Aegir-DevShop) — MEDIUM — pre-auth infrastructure info disclosure (ORIGINAL)
- **Entry (pre-auth):** hook_menu `inventory` (`aegir_ansible_inventory.module:12-14`,
  **`access callback => TRUE`**) → an Ansible dynamic-inventory JSON endpoint. The source header
  literally says `@TODO: Access control!` (`inventory-endpoint.php:6`).
- **Cause / leak:** `GET /inventory` returns, unauthenticated, JSON of **every managed server's**
  hostname, **IP addresses** (`db_query("SELECT ip_address FROM {hosting_ip_addresses} …")`, `:36`),
  all Ansible variables, and `aegir_user_authorized_keys = variable_get('devshop_public_key')` (`:55`).
- **Impact:** full internal topology + IP map + infra config of an Aegir/DevShop hosting fleet
  (+ the DevShop public key) to any anonymous caller — high-value recon for attacking the hosting
  infrastructure. MED. (The sibling `keys/%` route targets `devshop_servers_user_keys`, defined in the
  external `devshop_servers` module — not vendored here, so unconfirmable from this source.)

## 24. blackbaud_netcommunity_sso (Drupal 7) — HIGH — pre-auth account takeover via signature-scope gap (ORIGINAL)
- **Entry (pre-auth):** `bbuser` (`blackbaud_netcommuniy_sso.module:8-11`, **`access callback => TRUE`**)
  stores `$_SESSION['bbuser_information'] = serialize($_GET)` (`:57`) — the attacker's arbitrary
  `?email=&username=` go into the session **unsigned**. Then the `/callback` signin runs.
- **Cause (signature-scope gap):** the SSO MAC `$in_sig == $signature` (`:183`) validates
  `md5($userid.$ts.$secret)` — it covers **only `userid` + `ts`, NOT the email/username** that select
  the Drupal account. `blackbaud_netcommuniy_sso_signin` does `user_load_by_mail($email)` on the
  **attacker-supplied** email, links the attacker's `buid` to the victim uid, overwrites the victim's
  mail/name, then `user_login_submit()` (`:133/227`) → the attacker is **logged in as the victim/admin**.
- **Exploit:** with any one valid Blackbaud assertion for the attacker's **own** account (relative to
  Drupal they're anonymous): `GET /bbuser?email=admin@site&username=x`, then
  `GET /callback/blackbaud?userid=<attacker_buid>&ts=…&sig=<valid-for-attacker>` → session as admin.
- Contributing weaknesses: `==` not `hash_equals` (`:183,318`), home-rolled `md5` not HMAC, `ts` never
  checked → unlimited replay. (The `:157` `unserialize` is a `serialize($_GET)` roundtrip — not POI.) HIGH.

## 25. referral (Drupal 6, abandoned) — HIGH — pre-auth PHP object injection via cookie at registration (ORIGINAL)
- **Entry (pre-auth):** on anonymous user registration — `hook_user` `case 'insert'` →
  `_referral_user_save($arg_user->uid)` (`referral.module:195-197`).
- **Sink:** `_referral_user_save()` does `$cookie = unserialize($_COOKIE['referral_data'])`
  (`referral.module:172`) — **raw `unserialize` of a fully client-controlled, unsigned cookie, no
  `['allowed_classes'=>false]`** (D6/PHP5). Object-injection primitive (RCE gadget-dependent).
- **Exploit:** submit `/user/register` with `Cookie: referral_data=<serialized POP-gadget object>` →
  object instantiated during registration. `db_query` are `%d`/`%s`-parameterized (no SQLi); the
  http_referer stored-XSS is admin-only + `check_plain`'d (no finding). HIGH.

## 26. accuweather (Drupal 6, abandoned) — HIGH — pre-auth PHP object injection via cookie (ORIGINAL)
- **Entry (pre-auth):** hook_menu `accuweather` (`accuweather.module:34`,
  `access arguments => array('access content')` = anonymous) → `accuweather_weather_page()` (`:206`).
- **Sink:** `:210` calls `_accuweather_get_current_city($city)` which does
  `unserialize($_COOKIE['accuweather_city'])` (`:178-179`, also `:186-187`) — **raw `unserialize` of a
  fully client-controlled, unsigned cookie, no `['allowed_classes'=>false]`** (D6/PHP5).
- **Exploit:** `GET /accuweather` with `Cookie: accuweather_city=<serialized POP-gadget object>` → object
  instantiated during unserialize → object injection (RCE gadget-dependent). Same class as referral #25,
  coolfilter #4, banner #5. HIGH.

## 27. track (Drupal 6, abandoned) — HIGH — pre-auth SQL injection via URL path segment (ORIGINAL)
- **Entry (pre-auth):** hook_menu `track/ajax/detail` (`track.module:73-77`,
  `page callback => trackback_detail`, `access callback => user_access` /
  `access arguments => array('access content')` = **anonymous**, `MENU_CALLBACK`). In D6 the trailing
  path segment is passed positionally, so `track/ajax/detail/<nid>` → `trackback_detail($nid)` with
  `$nid` = the raw URL segment (no `intval`/quoting).
- **Sink:** `trackback_detail()` (`track.module:155`) builds a `GoogleMap`, `Init()` sets
  `mapaction = $_GET['action']` (`track.google.map.inc:42`); when `action == "initsync"` it runs
  `db_query('SELECT … FROM {track} WHERE nid='.$nid)` (`track.module:164`) — **raw string concatenation
  of the request-controlled `$nid`, no `%d` placeholder, no escaping** (numeric context). Same raw-concat
  reachable at `:241` (`initsync` in a sibling callback).
- **Exploit (UNION / boolean oracle):**
  `GET /?q=track/ajax/detail/0 UNION SELECT name,pass,3,4,5,6 FROM users LIMIT 1&action=initsync`
  (6 columns match the 6 aggregate selects), or boolean `…/1 AND 1=1` vs `…/1 AND 1=2`. Full pre-auth DB
  read (password hashes). HIGH. Distinct module from #7 trackback (that one is SSRF).

## 28. flickrhood (bundled phpFlickr lib) — MED — pre-auth open redirect in a directly-servable script (ORIGINAL)
- **Entry (pre-auth):** the bundled auth callback `flickrhood/lib/phpFlickr/auth.php` runs at **file scope**
  (no Drupal bootstrap, README says to link to it directly) → web-servable at
  `/sites/all/modules/flickrhood/lib/phpFlickr/auth.php`.
- **Source→Sink:** `:19-20` `$redirect = $_GET['extra']` → `:34` `header("Location: " . $redirect)` — raw,
  no host allow-list.
- **Reachability:** with `frob` empty the code takes `$f->auth(...)` which `exit`s at `phpFlickr.php:433`
  (redirect not reached); supplying **`frob`** routes to `auth_getToken($_GET['frob'])`, which does **not**
  exit (`die_on_error` defaults `false`, `:24/30/86`) even on an API error → execution falls through to the
  attacker-controlled `header("Location: …")`. Works regardless of the (placeholder) API key.
- **Exploit:** `GET /sites/all/modules/flickrhood/lib/phpFlickr/auth.php?frob=1&extra=https://evil.example`
  → `302 Location: https://evil.example` (phishing / OAuth-callback abuse).
- **Bounds:** needs `short_open_tag=On` (`<?`); one outbound Flickr request first; PHP `header()` CRLF
  filtering blocks response-splitting → impact limited to open redirect. MED. (Same host-pinning gap that
  codeql-php improvement #8 now models as safe *only when* a constant scheme prefix is present — here the
  prefix is a bare `"Location: "`, so it is correctly a finding, not sanitized.)
