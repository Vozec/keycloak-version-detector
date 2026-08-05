# Drupal hunt — verified false positives / properly-gated public routes

Public routes from the access-surface map that are reachable but **correctly defended** when
read in source. Recorded so the map's 207 entry points aren't mistaken for 207 bugs.

## Upload / file endpoints defended
- **plupload `/plupload-handle-uploads` (D10.3/D11)** — not `_access:TRUE`; it is
  `_permission: 'access content'` **+ `_csrf_token: 'TRUE'`** (`plupload.routing.yml`). The CSRF
  token is only emitted when a plupload form element renders (session-bound), so a blind
  unauthenticated POST can't satisfy it. Even with a token: destination is `temporary://`
  (non-web, `.htaccess` deny-all written by `htaccessWriter`), and `getFilename()` enforces
  `^\w+\.tmp$` (`UploadController.php:159`) — no traversal, no executable extension. Promotion to
  a managed file only happens through the Form API element (which re-munges `.php|.pl|...`). At
  most a token-gated temp disk-fill DoS. FP for RCE/arbitrary-write.

## Access-bypass / info-disclosure endpoints properly gated
- **select2 entity-autocomplete (D9/D10)** — `_access:TRUE`, but `selection_settings_key` is a
  lookup into the server-side `entity_autocomplete` keyvalue store; unknown key → 403, and the
  stored settings are re-verified with `hash_equals` against `Crypt::hmacBase64(…, hashSalt)`
  (unforgeable). `EntityAutocompleteMatcher` runs the selection query with the access-check tag as
  the anonymous user, so only entities that user may already view are returned. Same trust model as
  core `system.entity_autocomplete`. No bypass / no disclosure. FP.

## Webhook / callback endpoints properly validated
- **feeds `/feed/{id}/{token}/push_callback` (SubscriptionController)** — `subscribe` validates
  `getToken() !== $token` + topic + state (`:108`); `receive` validates the token **and** an
  `X-Hub-Signature` HMAC-SHA1 before `pushImport` (`:174-183`). Token (20B) and HMAC secret (32B)
  are per-subscription `Crypt::randomBytesBase64` CSPRNG values; the topic is pinned to the
  admin-set feed URL (no SSRF via `hub_topic`). Forging content needs the secret. FP.
- **imagecache (D6) `system/files/imagecache` → `imagecache_cache_private`** — `access callback
  => TRUE`, but the callback re-checks `user_access('view imagecache '.$preset)` **and** runs
  `hook_file_download` on the source path (`imagecache.module:416`) — the standard private-file
  access re-check — returning 403 otherwise. No bypass. FP.

## Auth modules that correctly delegate to vetted libraries (safe by default)
- **simple_oauth** — `/oauth/token`,`/oauth/authorize` delegate to `league/oauth2-server`
  (redirect_uri exact-match, PKCE, code single-use inside the lib); client secret via
  `password_verify` (constant-time), scope escalation rejected. FP.
- **samlauth** — `/saml/acs` delegates to `onelogin/php-saml`; ships `strict: true` +
  `security_messages_sign: true` by default → unsigned/invalid assertions rejected (XML-sig-wrapping
  handled by the lib). NEEDS-CONFIG only if an admin disables strict/signing. FP by default.
- **jwt** — no anonymous route (only `/admin/config/system/jwt`, `administer jwt`); algorithm pinned
  via `Firebase\JWT\Key($key,$algorithm)` from config (not the token header) → no alg=none / HS↔RS
  confusion. FP.
- **openid_connect** — RP callback is `state`-token gated (session, single-use); id_token is fetched
  over the TLS back-channel (unsigned parse is OIDC-§3.1.3.7-compliant). Email account-linking exists
  but only when the **default-off** `connect_existing_users` is enabled → NEEDS-CONFIG, not
  default-vulnerable (contrast social_auth #3, which has no toggle).

## CodeQL taint FPs (bounded dispatch / name-collision / config-source / authenticated)
- **key** `AuthenticationMultivalueKeyType.php:54` "unsafe deserialization" — the method *named*
  `unserialize()` is `return Json::decode($v)` (json_decode → scalars/arrays only, no object
  instantiation); source is admin-set key material behind `administer keys`. Name collision. FP.
- **betterupload** `file.inc:74` "code injection" — `call_user_func_array('file_'.$toolkit.'_'.$method,…)`
  where `$method` is always a hard-coded literal (`create_url`/`check_upload`/…), `$toolkit` is a
  server-registered toolkit, and the name is `function_exists`-gated; request input reaches only the
  args. Non-routable `.inc`, reached behind `upload files` permission. FP (legacy D5/6).
- **inline_entity_form** `ElementSubmit.php:109` "code injection" — `call_user_func_array($cb,…)` over
  `#ief_element_submit`, a Form API render-array property set by IEF's own PHP (server-side), not
  request input; inside authenticated entity add/edit forms. Framework dispatch. FP.

## imce (widely-used file manager, D9-11) — both CodeQL alerts FP + auth-gated
- `ImceFM.php:374` "code injection" — `call_user_func($this->getConf('scanner','Imce::scanDir'),…)`;
  the `scanner` conf key is never written from request input (always the hardcoded default). The
  real op dispatch (`run()`) requires a per-user token then resolves the `jsop` string against
  **registered plugin definitions** (whitelisted method), not the raw request. FP.
- `ImceItem.php:111` "SSRF" — `getUri()` is a pure `Imce::joinPaths(root_uri,$path)` string join
  producing a local stream-wrapper URI; nothing is fetched. FP.
- Access is profile-gated (`Imce::access` → `roles_profiles`); anonymous only if an admin assigns
  the anonymous role an IMCE profile. Auth-required by default.

## Standalone-script / path cluster — FP or auth-required
- **bookimport/contrib/outline.php** — CLI utility (`#!/usr/bin/php`, `argv[1]`); web reach needs
  `register_argc_argv=On` and even then fatals at `require_once('node.php')` (missing in `contrib/`). FP.
- **image_pub (D6)** `common.inc:183` — `filesize($_FILES['userfile']['tmp_name'])` (server temp path,
  not request filename; upload is `create images`-gated); `gr.inc:141` echoes under `text/plain` and
  the value is `check_plain`'d via `theme('placeholder')`. FP.
- **email_verify (D7)** `email_verify.inc:573` — `fwrite($connect,"HELO…")` is an **fsockopen SMTP
  socket**, not a file (CodeQL socket/file confusion); `valid_email_address()` blocks CRLF. The
  `check.inc:218/268` SQLi is behind `administer users` + `is_numeric`. Not pre-auth. FP.
- **go (D7)** `go.hooks.form.inc:14` — `"{$_GET['module']}_cron"()` guarded by `module_exists`, only
  inside the `administer site configuration` cron-settings form. Auth-required + constrained. FP.
- **commerce (D10/11)** `ProductVariationFieldRenderer.php:44` — `call_user_func` over core
  `#pre_render` callables (code/config-populated render pipeline), never request input. FP.

## Reflected-XSS FPs — logger/routing/non-HTML sinks (maintained modules)
- **seckit (^9.5-^11)** `SeckitExportController.php:83` — the CSP-report data goes to
  `$this->logger->warning(...)` (`@`-prefixed → `Html::escape`'d in dblog), and the controller
  returns an **empty `Response()`**. Nothing is reflected to the requester. The `/report-csp-violation`
  route is anonymous but the only effect is log-spam, not XSS. FP.
- **domain / domain_source (^10.2-^11)** `DomainSourceRouteProvider.php:32` — `getPathInfo()` is
  consumed **entirely inside the routing subsystem** (path processors → route lookup → RouteCollection);
  no echo/render/Response body anywhere. Not an HTML sink. FP.
- **gdata (D6 abandonware)** `extras/info.php:49` reflects `$_SERVER['REQUEST_METHOD']` (not `$_GET`);
  HTML metachars in the method token are rejected (400) before PHP runs → no realistic XSS. (Note: the
  script does expose unauth `phpinfo()` on POST = env/secret disclosure — delete it from any webroot.)

## Command-injection cluster — CLI-only / escaped / admin-gated
- **cvslog** `xcvs-loginfo.php:151`, `xcvs-config.php:267` — CVS **server hook scripts**
  (`#!/usr/bin/php`, input from `argv`/`STDIN`/`$_ENV[CVSROOT]`, no `$_GET/$_POST`); require CVS
  commit access, not HTTP, and `xcvs/.htaccess` denies web access to `.php`. Not a web finding.
- **securesite** `securesite.inc:153` — runs anonymously in `hook_boot`, but every request value
  (`PHP_AUTH_DIGEST`, method, request_uri) is `escapeshellarg()`'d before `exec()`; the only
  unescaped part is a config path. FP.
- **nutch** `nutch.admin.inc:202/211` — reachable only via `admin/settings/nutch/*` behind
  `administer nutch`, and every command component is `escapeshellarg()`'d. Auth-required + escaped. FP.

## zina (D6) — bundled app is functions-only, all sinks auth-gated (FP for pre-auth)
- `zina/zina/index.php` (Zina 2.0b22) is a **pure function library** (opens `function zina($conf)`,
  every top-level construct is a def, no file-scope executable code); direct `GET …/index.php` runs
  nothing. The vestigial `zina/.htaccess` rewrites to a non-existent `zina/index.php`. All sinks are
  reached only via `zina.module`→`zina_main()` behind `user_access('access zina')` (`zina.module:91`).
- `passthru()` cmd-injection (`:6544/6547`, `mp3s`→zip, only `..`-filtered, no `escapeshellarg`) is a
  **real bug but auth-required** (`access zina`) AND needs the non-default `cmp_sel==1` (default 0).
- Code-injection `:994` is `in_array`-whitelisted; `:4265/4291/4304` `call_user_func` over hard-coded
  form-def strings (not request). Unserialize `common.php:349/351` feeds on `$_SESSION`/file/DB ID3
  data, never `$_GET/$_POST/$_COOKIE`. No pre-auth object injection.

## Standalone-script / traversal FPs (2)
- **sparkline (D6)** `sparklib/samples/stock_chart*.php` — `@file($url)` where `$url` is a hard-coded
  `http://ichart.finance.yahoo.com/...` literal; only `$_GET['s']` (regex `^[a-z\^]{1,5}$`) and
  `$_GET['y']` (0-5) interpolate as query params. Remote-fetch to a fixed host, not a file-read/SSRF
  primitive. Bundled demo — hygiene only. FP.
- **pacs (pre-D6)** `pacs_xml.inc:129` — `fopen($_FILES['branch_file']['tmp_name'],"r")` guarded by
  `is_uploaded_file()`; `tmp_name` is PHP-assigned, not client-controlled. Also an `.inc` reached via
  `pacs/import/%` behind `user_access('manage tree')` — auth-required. FP.

## Reflected-XSS FPs + one hardening-only (voting/wghtml/sso/tablemanager)
- **voting (D4.x)** `update-voting.php:23` — reflects `$_SERVER['PHP_SELF']` (server var, not request);
  and the script fatals in place (relative `include 'includes/bootstrap.inc'` fails), reachable only
  if copied to docroot. FP.
- **wghtml (D4.6)** `class_wghtml.php:246` — `echo $content` where `$content` is
  `file_get_contents(DOCUMENT_ROOT.$fname)` (on-disk file bytes); the request only selects the file,
  it doesn't reflect the request string. Local-file passthrough, not reflected XSS. FP.
- **tablemanager (D6)** `tables.inc:378` — `print_r($clicked_button['#post'])` debug dump, but behind
  `administer tables` + form token → admin self-XSS, not pre-auth. Auth-required.
- **sso (D6)** `singlesignon.inc:169` — `return $hmac == $_GET['auth'];` (loose `==` on the SSO token).
  **Hardening nit, not exploitable:** `$hmac = substr(hash_hmac('ripemd160',$msg,$key),0,24)` is a
  secret-keyed 24-hex-char value the attacker can neither control nor predict; the `0e`-magic-hash
  juggle would need the server hmac to be `^0e\d{22}$` (~16⁻²⁴), and PHP-8 `==` only juggles two
  numeric strings. Should be `hash_equals`, but no practical auth bypass. (Debug `print_r($_COOKIE)`
  at :243 goes to a log file behind `SSO_DEBUG=false`, not HTTP — not XSS.)

## Anonymous-facing modules that are properly gated (expanded corpus)
- **anonymous_subscriptions (^8.7-^9)** — confirm/unsubscribe tokens are per-record
  `Crypt::randomBytesBase64(20)` (160-bit CSPRNG); wrong code → redirect to front, no action. All SQL
  via parameterized `entityQuery`. Residual is only flood-limited email-spam via `/subscribe`. FP.
- **autoshortqr (^10-^11)** — the redirect target comes from the stored `redirect` entity via
  `TrustedRedirectResponse`, never from the request (query only appends UTM); ids `intval(...,36)` →
  entity `load()` (no SQLi); no SSRF. Missing `$entity->access('view')` = LOW (canonical-URL QR only). FP
  for open-redirect/SQLi.

## Round-2 (expanded corpus) FPs — config-sourced / bounded-dispatch / DB-deserialize
- **abbila (D6)** SSRF `abbila.lib.inc:39-71` — cURL host is `variable_get('abbila_host')` (config);
  the anonymous `Abbila` path injects only the trailing **query string** against the *configured*
  server (parameter injection into a fixed host, not SSRF). The one full-URL sink (`case 'check'`) is
  admin-gated (`administer search`). FP.
- **addresses (D6)** code-inj `addresses.inc:620` — `('addresses_province_list_'.$country_code)()`
  behind `function_exists` AND the `$countries_all[$country]` ISO-country whitelist (`:604`); fixed
  prefix + whitelist → no attacker-controlled callable identity. FP.
- **a12s/page_context (^9-^11)** deserialize `Record.php:62` — `unserialize($value)` where `$value` is
  a DB column hydrated via `fetchAll(PDO::FETCH_CLASS)`; server-side storage, not request. FP.
- **active_form (^8.8-^9)** code-inj `BaseForm.php:187` — `$this->$method($request)` bounded by
  `method_exists($this,$method)` (`checkMethod()`:236) + CSRF + HMAC storage token; dispatch limited to
  the plugin's own methods. FP. (Note: the `method_exists` guard is in a *separate* validate method
  from the dispatch, so the intra-`if` `method_exists` sanitizer-guard does not clear it — a
  cross-function-guard case for a future codeql-php refinement.)
- **acsf (Acquia Site Factory)** code-inj `AcsfMessage.php:159` (`$callback` is a constructor-injected
  Closure, server-side) + SSRF `AcsfMessageRest.php:48/73` (URL from `AcsfConfig::getUrl()`, config).
  No anonymous route reaches them (Drush/hooks). FP.

## Standalone-script FPs (round-2 batch 2)
- **addonchat** `addonchat_auth.php`/`addonchat_exit.php` — all SQL uses `%s`/`%d` placeholders,
  password check uses `strcmp` (not `==`), output is `text/plain` (name never echoed), and the
  CWD-relative `./includes/bootstrap.inc` include fatals in the module dir (only runs if copied to
  docroot per INSTALL.txt). Residual: unauth un-rate-limited password oracle — not the target class. FP.
- **admintheme** DataTables `ssp.php` — directly reachable but `require('../../../../examples/…/ssp.class.php')`
  targets a file absent from the package (the whole `examples/` tree is missing) → fatal before `$_GET`
  reaches any SQL; `$sql_details` creds empty. Dead code. FP.

## Standalone-script FPs (round-2 batch 3)
- **biz (D7 theme)** `images/img.php` — GD text→PNG renderer; `msg` drawn only, `size` numeric,
  `font` whitelisted against a `readdir()` of the local `fonts/`, sole `include` is a fixed filename.
  No URL fetch, no request-controlled path. FP.
- **citizenspeak (D5/6)** `citizenspeak.reports.php` — function definitions only, **zero file-scope
  execution** (direct access does nothing; would fatal on undefined `db_query`). Queries `%d`-parameterized. FP.
- **booklists (D7)** `includes/booklists-ebooks.php` — prints a static HTML lightbox, serves **no
  files**; `catalog-url` flows only into Drupal `l()` (sanitized href), no download/`readfile` sink.
  Also `chdir('../../../../../../')` is one level too high → fatals in a standard install. FP.

## Standalone-script FPs (round-2 batch 4)
- **about/tools/cookieFactory.php** — cookie only `isset()`-tested, never reaches unserialize/eval/DB
  (no `unserialize` in the file). Marginal REQUEST_URI-into-JS reflection only (browser-URL-encoded). FP.
- **about_tools/mailman.php** — file-scope dispatch on `$_GET['a']`, but **every sink is commented out**
  (`mysql_query` L60/93/103, the whole `mail()` assembly L100-107); `$sent` never set. Dead code. FP.
- **groups/generate-utids.php & generate-ntids.php (D4.6/4.7)** — mutation gated by `$user->uid == 1`
  (super-user); relative `include includes/bootstrap.inc` fails in module dir → `$user` null → access
  denied anonymously. SQL is `%d`-parameterized. Auth-required + FP.
- **drupalvb/drupalvb.inc.php (D7)** — functions-only (no top-level statements → no file-scope sink);
  all queries use `:named` bound params; update uses a hardcoded column whitelist. FP.

## Round-2 triage noise (documented so future rounds skip)
- **Full-distro / core forks** (`1087726`, `aeg`) — these bundle Drupal core + contrib (ctools, features,
  backup_migrate) inside a distribution/sandbox. Their code-inj/SSRF hits are core/contrib admin code, not
  a standalone plugin's pre-auth surface. Excluded from triage.
- **API-response hydrator factories** (`activecampaign_api` `Field.php:39`, `Tag.php:56`, …) —
  `call_user_func([__NAMESPACE__.'\\Field\\'.ucfirst($json->type), 'createFromJsonResponse'], $json)`:
  the class is `class_exists`-guarded under a **fixed namespace** and the method is a **constant literal**,
  and `$json` is the upstream API's response (server-to-server), not the incoming request. Bounded factory
  over a trusted source → not attacker-controlled code exec. (No clean generic codeql fix — de-modeling
  API-client responses as non-sources would lose real second-order flows.) FP.

## D7 anonymous hook_menu callbacks that ARE properly controlled
- **alipay_api** `alipay/notify` — `$_POST` is trusted only inside `if ($verify_result)` where
  `$verify_result = AlipayNotify::verifyNotify()` (RSA/MD5 sign + notify_id re-check via the Alipay SDK);
  forged notifications hit `else → print 'fail'; exit()`. Order lookup bound `:order_id`. (Caveat: no
  amount cross-check; strength depends on the out-of-tree SDK.) FP for payment bypass.
- **bluga** `bluga/fetch` — `drupal_http_request()` always targets the hard-coded `BLUGA_API_END_POINT`;
  the request supplies only a numeric `rid` (DB key) + whitelisted `size`. No attacker URL → no SSRF. FP.
- **bassets_server** `bassetsfile/%` — the `%` arg is an HMAC `drupal_get_token` **cache token** (1h
  expiry), not a path; the served `$file->uri` comes from cache→UUID→entity. `../` → cache miss → 404.
  Not path traversal. FP. (Token-minting resource is `access content`-gated — separate Services concern.)
- **amazons3_cors** `ajax/amazons3_cors` — returns a **scoped** S3 browser-upload policy (fixed bucket,
  server-side key-prefix+ACL, +5min expiry); no AWS secret in the JSON, and `ajax_get_form()` requires a
  valid `form_build_id` from a rendered widget. Not an open signing oracle. FP.

## D7 anonymous callbacks — flagged primitive is FP (lower-severity residual noted)
- **audiorecorderfield (D6)** `nanogong_file_receive` — anonymous upload, but `audiorecorderfield.module:64`
  forces the name to `file_create_filename(time().'.wav')` before `file_save_upload` → always `<ts>.wav`
  in the public dir; no attacker extension/traversal → no RCE. Residual: anonymous upload disk-fill DoS +
  a minor `nanogong_preview` fid IDOR (parameterized `%d`). FP for RCE.
- **ajaxchat (D7)** `ajaxchat_router` — bundled blueimp AJAX Chat glue; every SQL value goes through
  `makeSafe()` (mysqli escape), output HTML-encoded, identity from the Drupal session (guest fallback by
  design). No raw request→SQL/HTML sink. FP.

## D7 anonymous callbacks that die on a concrete mitigation (wave 3)
- **appserver** `app/export` — the manifest (`appserver.export.inc:30-61`) is public app-listing data
  (name/version/author/rating); no secrets/creds/paths/module-list. `app/export` passes literal `"export"`
  → `taxonomy_term_load` returns FALSE → returns nothing. FP.
- **available_updates_d7** `available_updates_d7.json` — the module/version/core fingerprint disclosure is
  gated by `$_SERVER['REMOTE_ADDR'] == '18.130.46.80'` (`:34`, socket peer, **not** X-Forwarded-For) →
  not spoofable remotely; everyone else gets `"no"`. FP (residual: IP-auth fragility noted).
- **phpbb2drupal** `viewtopic.php` — `$_GET[t|p|f]` are `is_numeric`-guarded + parameterized
  `->condition()`; redirect targets are internal paths from DB integers. No open redirect/SQLi. FP.
- **adaptive_payments** `paypal_redirect/%/%` — lives in the `adaptive_payments_test` example submodule;
  `$cmd`/`$key` go only into the query string after the fixed `https://www.paypal.com/webscr?` (host fixed);
  no order/payment state mutation. FP.

## Real bugs but NOT pre-auth (auth/secret-gated) — round-2 wave 4
- **addressbook 6.x-4.2 (D6)** — GENUINE SQLi: `addressbook_{family,member,picture,map}.inc` concatenate
  `$_POST[Search|Sort|fid|mid]` straight into `db_query($query)` (no `%d`/`%s` args) at ~13 sinks; but
  every path is dispatched by the `addressbook/family`|`/member` callbacks gated by the `view addressbook`
  permission (not anonymous by default). **Low-priv authenticated SQLi**, becomes pre-auth only if an
  operator grants `view addressbook` to anonymous. (Recorded here as it's not default-pre-auth.)
- **bd_video (D6)** — GENUINE request-fed `unserialize($_POST['params'])` on the anonymous
  `system/bd_video/incoming` route, BUT gated by a prior `WHERE video_id=%d AND secret='%s'` check; the
  32-char per-video `secret` (`md5(user_password())`) is shared only with the external transcoder and
  needs `administer video` to create. Not reachable pre-auth (secret-gated).
- **bitaps (^10-^12)** `Pages.php:83` — `@unserialize($payment->data)` where `data` is a DB column the
  module serialized itself; `$_GET['oid']` only selects the row, and an HMAC `hash` check precedes it.
  DB-sourced → not object injection. FP.

## codeql R&D note: LDAP-injection query validated end-to-end
Micro-test confirmed `LdapInjection.ql` flags `ldap_search($c,$base,"(uid=$_GET[user])")` (tainted filter)
and clears the `ldap_escape(...)`-sanitized variant. The 0 findings across the cloned LDAP modules
(`ldap`, `ldap_integration`, `ldap_addressbook`, `pubcookie`) are therefore genuine — those modules
escape/parameterize their filters — not a broken query.

## File-inclusion FPs — fixed-path bootstrap/autoloader includes (server env var + literal suffix)
- **authcache (D7)** `authcache_p13n/frontcontroller/authcache.php:41-42` — standalone front controller,
  but `require_once DRUPAL_ROOT.'/includes/bootstrap.inc'` / `AUTHCACHE_P13N_ROOT.'/includes/frontcontroller.inc'`;
  DRUPAL_ROOT derives from `$_SERVER['SCRIPT_FILENAME']` via an **anchored** regex (`exit()` if it doesn't
  end in the exact path). No request value / no `..` reaches the include. The `safe_frontcontroller` sibling
  differs only in root-detection, not LFI. FP.
- **advancedqueue_runner** `src/Scripts/jobs.php:17` — `require $_SERVER['PWD'].'/../vendor/autoload.php'`;
  ReactPHP CLI daemon (`$loop->run()`), `PWD` is CLI-only shell env (absent under web SAPI). Not web-reachable. FP.
- **apps (D7)** `apps.manifest.inc:599` — `require_once $app['file']` where `$app['file']` is always
  `drupal_get_path('module','apps').'/apps.{installer,profile}.inc'`, behind `administer apps`. Fixed + admin. FP.
- **afterburner (^10-^11)** `TaskBase.php:42` — `require $this->context['app_root'].'/autoload.php'` with
  `app_root = DRUPAL_ROOT`; abstract Spatie async Task run in a forked child, not a route. FP.
- **Root cause (→ codeql R&D):** `$_SERVER['SCRIPT_FILENAME']` / `['PWD']` / `['DOCUMENT_ROOT']` are
  **server/environment-controlled**, not attacker-influenced, yet were treated as remote sources.
