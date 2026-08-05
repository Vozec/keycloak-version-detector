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

- **addresses (D6)** `addresses.inc:615` File-inclusion — `include_once …/countries/$country_code.'.inc'`
  where `$country_code` iterates `$countries` = keys of `$countries_all` (the ISO-country list); `$country`
  is validated `$countries_all[$country]` before use → bounded to real `/countries/<iso>.inc` files. Same
  whitelist that makes its `:620` code-injection sibling a FP. FP.

## D7 anonymous callbacks properly controlled (wave 5)
- **allplayers** `allplayers/auth` — acts only on the caller's own `$_SESSION` OAuth tokens; post-auth
  destination is the admin `allplayers_redirect` variable (not request) → no open redirect. Residual:
  email auto-link/auto-login only if the IdP allows unverified emails (+ no CSRF state). Not a clean
  pre-auth bug. FP.
- **beanstalk** `beanstalk/webhook` — requires a per-repo secret `?t=` token validated against
  `{beanstalk_repository}` (hard `drupal_access_denied()` otherwise); token is `drupal_get_token`/
  `md5(...private_key)` (unguessable). Even with it, the only sink is node creation; SQL escaped. FP.
- **ark** `ark:/%/%` — `$naan` must equal the site's configured NAAN; redirect target is `entity_uri()`
  of a server-side-matched local entity (not attacker URL); lookups use `:named` placeholders. No open
  redirect, no SQLi. FP.

- **ajax_checklist (D6)** `ajaxchecklist/loadnid` — anonymous, but `db_query` uses `%d` placeholders
  (nid/uid integer-coerced); the `'user-%'` literal wildcards consume no placeholders; no `unserialize`;
  only non-sensitive checkbox state exposed. FP.

- **scraper** — `unserialize($_POST['edit']['scraper_job_import_vals'])` (`:121`) is real request-fed
  deserialization, but the hook_menu path is `admin/scraper` (admin-gated) → not pre-auth. Auth-required.

## Object-injection FPs — request value is a DB lookup KEY, not the deserialized bytes
(Recurring shape: `unserialize($row->col)` where the request only picks *which* row via a WHERE clause.)
- **apdqc (D7)** — all `unserialize()` sinks read server-side storage: `$user->data` (`session.inc:207`,
  auth-gated `uid>0 && status==1`, core's `_drupal_session_read` pattern), cache-bin rows, `{menu_router}`
  `page_arguments`, `{variable}` (install/CLI). The `$_COOKIE` SID is only escaped into `WHERE s.sid='…'`;
  it never supplies serialized bytes. FP.
- **kasahorow/kdictionary (D6)** — the 9 `unserialize()` sinks all take `{kdictionary}` column values
  (`children`/`langindex`/`editor`/`alphabets`); `$_GET['id']`→`WHERE did='%s'`, `arg(1)`→`WHERE iso='%s'`
  are lookup keys only. Callbacks are `use dictionary`/`administer dictionary` permission-gated. FP.

## SQLi wave (checkout / gradebook / ejournal / taxonomy_context) — all cleared
- **checkout** (D6) — `checkout.module:345-346` `db_query("… WHERE nid = %d".$add_sql,$args)`: the
  concatenated `$add_sql` is only a **static literal** `" AND uid = %d"`; tainted `$nid`/`$uid` bound via
  `%d`. No anon entry (hook_init gated by `$user->uid && user_access`). FP (static-literal concat).
- **gradebook** (D5-era) — `IN (…)` concats at `:423/919/950` interpolate `$str_uids`/`$str_rids` that are
  **server-derived** (UIDs from `gradebookapi_get_students()`/`{users_roles}`, RIDs from `user_roles()`).
  Anonymous `gradebook/<tid>` reaches `:423` but no request value reaches the concat; `$_GET['order'/'sort']`
  go to a different, non-concatenated path. FP (server-derived IN-list — request-as-key non-pattern kin).
- **ejournal** (v0.92) — only raw-concat request value is `$iid` at `:2178`, but both callers (`:1832/2020`)
  are **chief-editor/editor** admin forms (auth-required). Every concat reachable from anon
  `ejournal_public_page` (`access content`) is `%d`-bound or `db_escape_string`'d (`:724/1355/3315`). Not
  pre-auth (authenticated-only real sink).
- **taxonomy_context** — concats at `:80/83/87/238` interpolate only core literals (`term`/`vocabulary`,
  `tid`/`vid`); data `%d`-bound; runs under `administer taxonomy`. `:493/531` build SQL from string
  literals. FP (no request string concatenated).

## anon-JSON/autocomplete IDOR wave (accordions / aef_image / ajax_chain_select / autocomplete_google_places / autordf / biblio_autocomplete / appserver) — all cleared
- **accordions** — `accordions/autocomplete` (`access=>TRUE`): `$string` only into parameterized
  `db_select()->condition('name', db_like($string).'%','LIKE')`, returns admin-configured names,
  `check_plain`'d. FP (request-as-key autocomplete).
- **aef_image** — `aef_image/noderef_autocomplete` (`access content`): `$string` via `%s`+`$args` (escaped),
  wrapped in `db_rewrite_sql()` (node-access enforced), output `check_plain`'d; the `unserialize` acts only
  on stored CCK `data` columns, never request input. FP.
- **ajax_chain_select** — `ajax_chain_select/callback` (`access=>TRUE`) base64-decodes `$dc`→function and
  calls it, BUT only after `drupal_hmac_base64($value, private_key.hash_salt)` token check; anon cannot forge
  the HMAC. FP (HMAC-gated dynamic dispatch).
- **autocomplete_google_places** — `google/places/autocomplete/%/%/%` (`access=>TRUE`):
  `drupal_http_request` uses **fixed host** `maps.googleapis.com`, `$string` only the `input=` value; resp
  `check_plain`'d. FP (fixed-host fetch, not SSRF).
- **autordf** — anon `autordf` just renders a form; `autordf/autocomplete` needs `access autordf tags` and
  matches a fixed vocab; admin pages need `administer autordf`. FP (no anon sink).
- **biblio_autocomplete** (biblio_ipni) — `biblio_ipni_*` (`access=>TRUE`): `file_get_contents` targets
  **fixed host** `www.ipni.org`, `$string` only a query value; returns proxy of public botanical DB, no
  Drupal data. FP (fixed-host fetch).
- **appserver** — `app/export`,`app/query/%`,`apps/vote/%/%` (`access=>TRUE`): export uses
  `taxonomy_select_nodes(...,FALSE)` (node_access-tagged, published-only) — **intended public app-catalog
  export**, not IDOR; `$_REQUEST` only into `drupal_alter` (no implementer) / parameterized EFQ. NOTE:
  `appserver_voting_vote()` allows anon vote-stuffing via `$_REQUEST['client_id']` — a vote-integrity logic
  weakness, **out of the pre-auth disclosure/injection scope** (recorded for completeness, not a finding).

## Standalone-script wave 2 (zina / lobby / bawstats / about_tools / flickrhood) — 1 confirmed (#28), 7 cleared
- **zina/zina/index.php, common.php, batch.php, extras/tag_editor.php** — all **function-only libraries,
  zero file-scope execution** (only `define()` + `class`). Request handling lives in `zina($conf)`, called
  only from `zina.module:130` **after full bootstrap**, and every admin op gated by
  `if(!$zc['is_admin']) return zina_access_denied()`. NOTE: these DO contain genuinely-dangerous shapes —
  `preg_replace('/…/e', …)` (common.php:805, batch.php via `unserialize_utf8`) and `unserialize()`
  (batch.php:122, sitekey-HMAC-token-gated) — so codeql-php's `preg_replace('/e')` sink (improvement) and
  the object-injection query WILL flag them; source-verification clears them as bootstrap+admin+token gated.
  A textbook "dangerous shape, correctly gated" FP. The only standalone sibling (`extras/filler.php`) has an
  unconditional `exit;` at line 15.
- **lobby/eactions.php** — function-only library (helpers), no file-scope statements, no superglobal reads,
  depends on Drupal/CiviCRM symbols. Never entered directly. FP.
- **bawstats/modules/render_jpgraph.inc.php** — DOES execute at file scope
  (`if(isset($_GET['getgraph'])) baw_render_jpgraph_img();`) and the `PHP_SELF` sentinel is broken (tests a
  typo'd filename), so web-servable — **but no request input reaches a live sink**: `include`s are
  static/config paths (`../config.php`, `$BAW_CONF['jpgraph_path']`), `$_GET['type']` only picks literal
  switch cases, `$_GET['d']/['f']` flow only into jpgraph plot objects. FP (config-derived includes).
- **about_tools/mailman.php** — executes at file scope (`switch($_GET['a'])`), web-servable, unguarded, **but
  every dangerous sink is commented out** — all `mysql_query()` (`:60,93-107`) and the `mail()` call are
  commented; output is a static md5 ticket + JSON. No live SQL/mail/exec/echo of request data. FP (dead sinks).

## Bootstrap-then-anon wave (addonchat / booklists-ebooks / carto / voting / groups) — 1 confirmed (#29), rest cleared
- **addonchat/addonchat_auth.php** — web-servable, `DRUPAL_BOOTSTRAP_LATE_PAGE_CACHE`, no auth; reads
  `$_REQUEST['username'/'password'/'rasver']` but every `db_query` uses `%s`/`%d`+args (REPLACE/SELECT,
  `:70-71,102-103,179,190,224`), no echo (Content-type text/plain, fixed keys), no unserialize/include/exec/
  redirect/session-login. FP. **Low note:** `strcmp($user->pass,…)` (`:81`) is an unauth password/user-enum
  oracle — not an in-scope sink.
- **addonchat/addonchat_exit.php** — `DELETE … WHERE username='%s'` uses **session** `$user->name` (not
  request); `header('location: '.$base_url.'/')` is server-derived site root (not request) → no open redirect;
  `$_REQUEST['close']` only gates a static `window.close()`. FP.
- **booklists/includes/booklists-ebooks.php** — `$_GET['catalog-url']`→`urldecode`→`l('…',$url)` printed; D6
  `l()` routes href through `check_url()` (strip_dangerous_protocols + check_plain) → sanitized clickable
  link, not injectable. FP.
- **carto/widgets/CartoGPXFiles.php** — anon (full bootstrap, no access check) but SQL is
  `… nid=%d and filename='%s'` (parameterized); the loaded path `$drupaldir.$filepath` comes from the **DB
  row**, not the request; all 5 bundled `.xsl` verified to contain **no `php:function`** so
  `registerPhpFunctions()` is a no-op (no XSLT RCE). FP. **Low note:** missing access check → anon can XSLT
  any node's GPX attachment by nid+filename (bounded node-access bypass).
- **voting/update-voting.php** — anon (full bootstrap, no access check) but the only variable `db_query`
  (`UPDATE {votingapi_vote} …`) is parameterized with **DB-row** values, no request data at a sink. FP.
  **Medium note:** left-in-place one-shot migration script → anon `POST start=1` triggers destructive vote
  re-migration (data corruption/DoS) — not an injection sink.
- **groups/generate-utids.php, generate-ntids.php** — include bootstrap.inc/common.inc but **never call
  `drupal_bootstrap()`**, so `$user` is unpopulated → the `if($user->uid == 1)` guard (`:79`) fails closed;
  anonymous never reaches the (parameterized) write sinks. FP (fail-closed access guard).

## scraper — request-`unserialize` object injection, but AUTH-gated (not pre-auth)
`scraper_job_import_submit()` (`scraper.module:121`) does raw `unserialize($_POST["edit"]
["scraper_job_import_vals"])` with no `allowed_classes` — a genuine object-injection primitive — BUT it is
the submit handler of the `admin/scraper/import` form, whose hook_menu item has
`'access' => user_access('administer scraper')` (`:28-31`). Drupal checks menu access for the current path
before processing the form, so an anonymous user is denied before the submit handler runs. Real
**authenticated (`administer scraper`) POI**, not default-pre-auth — recorded here like addressbook SQLi /
bd_video secret-gated unserialize. (This is the only raw request-`unserialize` remaining in the corpus after
the standalone-script veins; all pre-auth ones — coolfilter #4, banner #5, referral #25, accuweather #26 —
are already recorded.)

## anon-callback SSRF/auth trio (age_checker / aweber / azure_acs) — all cleared
- **age_checker** — anon `agegate` (`:233-236` `access=>TRUE`). (a) `$_GET['destination']` open-redirect: the
  value is rewritten to `$base_url.'/'.$destination` (`:75`) before reaching the JS `window.location`
  (`age_checker.js:132`) — scheme+host hard-fixed to the site, only a path segment is client-controlled
  (`destination=http://evil.com` → `https://site/http://evil.com`, same-origin); delivered via
  `drupal_add_js` (JSON-encoded) so no XSS. (b) `drupal_http_request($url)` (`:542`): host is
  `variable_get('age_checker_country_code_url','http://geoip.nekudo.com/api/').ip_address()` — admin config
  host, only the IP path appended. FP (both: host-pinned).
- **aweber** (D6) — anon `aweberreturnpage` (`:20-25`). The GET-derived `$data` (`:303-306`) flows ONLY into
  `_aweber_save_lead()` D6-parameterized insert (`%s`/`%d`), never to `drupal_http_request`. The SSRF sink
  (`:498`) uses hardcoded `http://www.aweber.com/scripts/addlead.pl` and is called from `hook_user`, not the
  anon callback. FP. **Low note:** anon can insert one junk "lead" row (uid=0) — junk-data spam, no injection.
- **azure_acs** — anon `acs`/`acserror` (`:36-52` `access=>TRUE`). WS-Fed return handler validates the SWT via
  `TokenValidator::Validate` (`lib/swt.php:38`) BEFORE any login: enforces expiry, issuer, audience, and
  `IsHMACValid` (recomputes `hash_hmac('sha256',$swt,base64_decode($signingKey))` vs the token field) — any
  mismatch throws → `drupal_goto('<front>')`. Login (`user_login_submit`) only runs after Validate succeeds;
  forging requires the admin signing key. SSRF `$url` (`:264`) is config-derived (namespace+realm), in a
  block_view path not the anon handler. Open-redirect `previous_page` (`$_GET['q']`, `:16`) is only passed to
  a `drupal_alter` hook; default `$goto_path` is hardcoded `<front>`. FP (SSO HMAC-gated; hardening note:
  `==` not `hash_equals` on the HMAC — theoretical timing side-channel only).

## Modern anonymous AI-endpoint wave (D10/11) — all 6 cleared (ecosystem data point: fail-closed guards)
42 un-audited modules expose anonymous *write* routes; the 6 highest-risk AI-integration endpoints were
deep-audited. **All properly gated** (mirrors the "maintained modules' access primitives are solid" pattern):
- **ai_face_login** `/ai-face/verify` (`_access:'TRUE'`) — `user_login_finalize()` (`FaceLoginController:225`)
  runs only if euclidean distance of the attacker's 128-float descriptor ≤ config threshold vs the victim's
  **stored** descriptor (`FaceMatcher:21-29`, full 128-dim). The stored descriptor is the biometric secret;
  threshold is config-only (not attacker-influenceable); generic 401 (no oracle); flood control 5/60s/IP. No
  image upload / URL fetch → no SSRF/traversal. FP (biometric-secret distance gate). *(Design caveat, not a
  code CVE: a victim photo could be turned into a matching descriptor client-side — inherent to face-login.)*
- **ai_rag_api** `/api/ai-rag/v1/chat/completions` — `authenticator->authenticate()` (`:123`) BEFORE retrieval/
  LLM; `ApiKeyAuthenticator:58` `hash_equals` bearer vs profile key, fails closed (unconfigured→throw); session
  fallback needs `use ai rag api` perm (non-anon). `model` selects a config profile, no request URL → no SSRF. FP.
- **ai_image** `/api/ai-image/getimage` (`_permission:'access content'`) — `provider` is a plugin-id (not a
  URL), image freshly generated to `public://` (no id lookup) → no SSRF/traversal/IDOR. FP. **Low note:**
  unauthenticated AI-image generation = anon can burn the site's AI-provider API credits (cost/DoS abuse).
- **ai_slack** `/ai-slack/events` — `verify()` (`:71`) before any side effect: real HMAC-SHA256 over
  `v0:{ts}:{body}` w/ per-bot signing secret, `hash_equals`, ±300s skew. `url_verification` only echoes. FP.
- **ai_agents_ossa** `/api/agents/webhook/gitlab` — `X-Gitlab-Token` `hash_equals` vs config (`:66`), fails
  closed on empty; action runs after; the GitLab fetch is a stub (no real outbound) → no SSRF. FP.
- **akismet_antispam** `/akismet/v1/webhook` — body `key` `hash_equals` vs site Akismet key (`:83`), fails
  closed (empty→401, unconfigured→503); side effects only after auth. FP (minor: case-insensitive compare).

## Proxy/SSRF wave (api_proxy / alert_telegram / api_insight_lab / billing_hub / bitpay) — 1 confirmed (#30 api_explorer), 5 cleared
- **api_proxy** — `/api-proxy/{api_proxy}` (`_access:'TRUE'`) but `Forwarder::forward` enforces a per-proxy
  `hasPermission('use <id> api proxy')` (`Forwarder.php:66`), AND the target host is the plugin's hard-coded
  `serviceUrl` annotation — `HttpApiPluginBase::forward` builds `rtrim(getBaseUrl(),'/').'/'.ltrim(path,'/')`
  so user input contributes only path+query, never the host (leading `//` stripped). FP (fixed-host allow-list).
- **alert_telegram** — `/alert-telegram/webhook/{secret}`: strict `$secret !== $webhook_secret` (`:106`, type-safe,
  not `==`); route regex `secret:'.+'` requires ≥1 char and there's no `config/install` default, so an empty
  config secret can never equal a mandatory non-empty path segment (no empty-default bypass). Body → parameterized
  inserts + `Html::escape` + fixed Telegram API. FP.
- **api_insight_lab** — `/api/test/echo` returns a **JsonResponse** (application/json), input echoed but not HTML
  → no reflected XSS. FP (non-HTML sink).
- **billing_hub** — `/billing/webhook/{gateway_id}`: `verifyWebhook($request)` runs BEFORE business logic
  (`WebhookDispatcherService:73`), Stripe gateway uses `\Stripe\Webhook::constructEvent` and fails closed on
  empty `webhook_secret`. No state change on forged/unsigned request. FP (fail-closed signature).
- **bitpay** — `/bitpay/callback`: reads only `webhook->id` from the body, then **re-fetches the authoritative
  invoice** via the authenticated BitPay client (`getInvoice($id)`, `:45`); attacker payload can't inject a
  "paid" status. FP (server-side IPN re-verification — the recommended pattern).

## Anon-callback SQLi wave 2 (epublish / agree_threshhold / bassets_server / drupalvb) — 2 confirmed (#31 betting, #32 block_quiz), 4 cleared
- **epublish** — anon `epublish`/`headlines` reach raw-concat queries, but every concatenated fragment is
  parameterized (`$pub` via `%d`/`%s`) or regex-digit-constrained (`$ed`→`preg_match('/(v([0-9]+))?(n([0-9]+))?/')`
  → digit-only `$volume`/`$number`); other interpolated pieces are `variable_get`/DB/`%d`-derived. FP.
- **agree_threshhold** — anon `ajax/agree/%/%/%` path uses `:named` placeholders throughout; the raw-concat
  queries live in `agree_threshhold_cron()` (not HTTP-reachable) with `{field_config}` schema names. FP.
- **bassets_server** — anon `bassetsfile/%`/`bassetsajax/%` run no `db_query` on request input (cache_get +
  entity_uuid_load; `$_POST['file']['id']` used only as a filesystem path); the one raw-concat query
  (`WHERE $algo = :hash`) has a server-defined `$algo` + parameterized `:hash` and runs only in an
  authenticated upload validate hook. FP.
- **drupalvb** (Drupal↔vBulletin bridge) — all request-derived usernames flow through `:username`/`:userid`
  named placeholders wrapped in `drupalvb_htmlspecialchars()`; raw `IN(…)` clauses implode vB-DB-returned
  userids; auth uses core `user_login` submit with strict `=== md5(md5(pw).salt)` and vB cookies are written
  only AFTER Drupal auth (no inbound cookie/sessionhash trusted); the only `unserialize` is on `{datastore}`
  DB data; no `drupal_http_request`/curl anywhere. FP (parameterized + server-derived + core-auth).

## Access-bypass/IDOR/XSS wave (at_menu / basic_ads / arlo / badges_async / autoalt / aws_bedrock_chat) — all cleared (low notes)
- **at_menu** (cheeseburger_menu) — `/cheeseburger-menu-render-request` renders a menu tree, but
  `getMenuTree()` runs `menu.default_tree_manipulators:checkAccess` so only links the anon user may already
  see are rendered; `block_id` not reflected; `current_route` used only in `strpos` (never output). FP (no XSS,
  no meaningful disclosure). *(Low: missing block-access check + unfiltered taxonomy loadTree — informational.)*
- **basic_ads** — `/ad/view/{nid}` returns only `{status,nid}` (no node fields → no IDOR); `/ad/click/{nid}`
  redirects via `TrustedRedirectResponse` to `field_ad_link` read **from the node** (admin-authored, not
  request); `placement` query arg only stored. Tracking uses int-cast/query-builder (no SQLi). FP. *(Low: anon
  can track impressions on an unpublished basic_ad node.)*
- **arlo** — `api/arlo/json` gates every action behind HMAC-SHA512 (`X-Arlo-Signature` vs
  `hmac_sha512(body, base64_decode(webhook_key))`); `fetchEvent` uses a fixed Arlo host (config platform_id),
  entityQuery `accessCheck(TRUE)`, returns only Success/Failure. FP (HMAC-gated + fixed host).
- **badges_async** — `/badges-async/get/json` (commented `#_role:'authenticated'` NOT enforced → anon). Only
  plugin `node_is_new`; uses `currentUser()->id()` (not a request uid) + `:uid`/`:nid` placeholders; output is
  only `new`/`updated`/`''`. FP (no uid-IDOR, no SQLi). *(Low: `Node::load($attributes)` no access check →
  new-in-7-days boolean oracle for arbitrary nid — trivial.)*
- **autoalt** — `/api/autoalt/generate` loads a local `File` by `fid` and POSTs bytes to a **hardcoded**
  `https://ahxdfj.autoalt.ai/...` (no request URL → SSRF FP); `fid` is an entity id (no traversal). *(Low
  confirmed: unauth AI-credit-burn; `File::load($fid)` no access check → an anon can have an arbitrary/private
  file's image sent to the 3rd-party API and get its description back = partial private-image leak; anon
  `historyList`/`historyPage` (`access content`) expose the `autoalt_history` table. SQL uses builder +
  `escapeLike` — no SQLi.)* FP for the dangerous-sink claims.
- **aws_bedrock_chat** — `/aws-bedrock-chat/get-response`: model/agent/endpoint all from config, not request →
  SSRF FP. User `message` is `Html::escape`'d where echoed; only LLM output is embedded (model-driven, not
  reflected input). *(Low confirmed: unauth LLM proxy / credit burn.)* FP.

## CodeQL discovery batch #1 (12 fresh modules) — high-sev triage: 1 confirmed (#33 apex_ai), 6 cleared
Ran the improved codeql-php pack (security-extended + LdapInjection) over 12 unaudited modules with anon
entries (annotations, i18n, billwerk_subscriptions, simple_sitemap, blockchain, akismet, symfony_mailer,
import_html, devel, entity_browser, apex_ai, azure_ad) → 72 raw candidates; high-sev verified in source:
- **annotations SSTI** (`ContextMcpController:189`, `ContextPreviewController:175/178/205`) — MCP route is
  `_mcp_access` (bearer `mcp_api_key` or `view/administer annotations` perm, fails closed for anon); preview/
  export routes need `view annotations context`+`administer annotations`. Sink is `ContextRenderer::render`, a
  stateless markdown string-builder (implode/concat) — **no Twig / renderInline / createTemplate**. FP
  (perm/bearer-gated + variables-not-template).
- **apex_ai_prompts SSTI** (`PromptPreviewController:50/56`) — route needs `_permission:'administer apex ai'`.
  FP (admin-gated).
- **entity_browser SSTI** (`Modal.php:130`) — `render($content)` where `$content` is a **render array**
  (`#type html_tag`), core render-array renderer not Twig; `$src` is an auto-escaped attribute value; also a
  form AJAX callback, not an anon route. FP (variables-not-template).
- **blockchain SSRF** (`BlockchainApiService:115/177`) — anon `/blockchain/api/*` are *responder* methods that
  don't fetch a request URL; `:115` runs in admin `BlockchainSubscribeForm`/cron (config host); `:177`
  `executeAnnounce` POSTs to **stored** peer endpoints on local block creation/cron (at most blind second-order
  stored-SSRF, sink off any anon request path). FP.
- **symfony_mailer code injection** (`CallbackEmailProcessor:117`) — `$this->callbacks[...]($email)` where
  callbacks are `?callable` registered only programmatically by the mailer plugin/adjuster system; never
  request-derived. FP (code-derived callable).
- **import_html code/command injection** (`import_html_process.inc:569/2073/2080`,
  `coders_php_library/tidy-functions.inc:177/183`, +path-traversal/XSS cluster) — **Drupal 7** admin tool;
  every `hook_menu` callback requires `access import_html` (admin perm); sinks reachable only via the admin
  import UI/batch/Drush. **No anonymous entry point** → the entire import_html candidate cluster is FP (admin-gated).
- (Medium-sev leftovers — blockchain open-redirect `BlockchainController:72`, azure_ad logger XSS,
  annotations export path-traversal — are in export/admin/logger paths, not anon request→sink; not pursued.)

## CodeQL discovery batch #2 (12 modules: tfa/appointments/bookit/ai_search_block/achlaai_search/anu_lms/migrate_plus/action_link/flag/xmlsitemap/agtp/billing_hub) — clean, 0 anon findings
16 raw candidates, all cleared: hardcoded-key in tfa `McryptAES128Encryption`/`TfaRecoveryCode` (per-user
auth'd recovery-code encryption, legacy Mcrypt plugin — not pre-auth) and achlaai_search `OwnershipProtocol`;
ai_search_block Reflected XSS in a **SettingsForm** (admin); migrate_plus path-traversal in the XML data_parser
(migration/Drush, admin); action_link `StateActionPlugin.php:129` "code injection" is
`$pluginManager->{$element['#plugins_method']}()` where `#plugins_method` is a **form-element definition value**
set by the form builder (developer/admin), not request input, in a render Element (not an anon route);
action_link type-juggling in `StateActionBase:340`. No anonymous request→dangerous-sink flow. (These modern
modules are clean — consistent with the "maintained modules are solid" pattern.)

## CodeQL discovery batch #3 (12 modules) — high-sev triage: 0 confirmed, all cleared
Batch: g2, blizzardapi, basket_novaposhta, automatic_updates, amber, better_entity_reference,
amazon_product_widget, amazon_store, address, ai_content_rag, ada_compliance, currency. Candidates cleared:
- **amber** path-traversal/file-read (`AmberStorage.php:57/67` `file_get_contents`, anon `amber/cache`,
  `amber/cacheframe/%/assets` `access callback=>TRUE`) — every path from `get_cache_item_path()` is gated by
  `is_within_cache_directory()` (`:206` `strpos(realpath($path), realpath($file_root)) !== 0`) which collapses
  `../` before the prefix check and defeats `php://filter`; plus `get_metadata()` re-md5s non-32-hex keys →
  arbitrary ids yield empty metadata → NOT_FOUND. FP (realpath containment guard).
- **blizzardapi_login** type-juggling (`pages.inc:177` `$hashed_pass == rehash(...)`, anon
  `blizzardapi/verify/%/%/%`) — `rehash()` = `user_pass_rehash` = `drupal_hmac_base64` (base64url, non-numeric)
  so `==` degrades to exact string compare; RHS server-generated (not forceable to `0e…`/all-digit), match
  still needs the secret `$account->pass`. Mirrors D7 core reset-link compare. FP (hardening nit: use hash_equals).
- **basket_novaposhta** — type-juggling `NovaposhtaHooks.php:92` `$tokenName=='NP'` is a template-render hook
  (not route-reachable, not a security decision, non-numeric→exact); XSS `NovaPoshtaAPI.php:729` is a
  `\Drupal::logger()->notice('<pre>'.print_r(...))` **dblog** sink (admin-viewed, escaped), and anon
  autocomplete controllers return `JsonResponse` (never raw HTML). FP.
- **ai_content_rag** (RAG, same family as apex_ai #33) — **SAFE**: `TreeRetriever` uses Drupal's parameterized
  builder with **hardcoded table literals** (`'ai_content_rag_section'`); the user query is bound
  (`MATCH…AGAINST(:q IN BOOLEAN MODE)`), vector rank computed in PHP, `vdb_collection` from the perm-gated
  settings form. **No unparameterized concatenation — the exact discipline apex_ai #33 lacked** (which
  interpolated the request `collection` into the table identifier). Instructive contrast, not a finding.
- (amazon_product_widget unserialize has `allowed_classes=>FALSE` (safe); automatic_updates IDORs are in a CLI
  `ConverterCommand`; migrate_plus/ai_search_block/action_link candidates admin/CLI/form-infra — all FP.)

## CodeQL discovery method — running tally
Batch #1 (annotations/i18n/billwerk/simple_sitemap/blockchain/akismet/symfony_mailer/import_html/devel/
entity_browser/apex_ai/azure_ad): **1 CRITICAL (#33 apex_ai SQLi)** + 6 high-sev FP. Batch #2 (12 modern
modules): 0. Batch #3 (12 modules): 0. The taint pass reaches multi-file flows grep can't (found #33 across
3 files); modern/maintained modules are otherwise clean, consistent with the abandoned-vs-maintained pattern.

## CodeQL discovery batch #4 (12 modules: 1530604/akismet/bittorrent/basket_imex/aggregator/api_insight_lab/acquia_cms_headless/rest_api_authentication/views_bulk_operations/bigcommerce/weather/assistant) — 0 confirmed
High-sev cleared:
- **akismet** code-injection `FormController.php:280/573` — `call_user_func($form_state->getValue('akismet')
  ['context created callback'],…)` but the `akismet` form element declares `#input => FALSE` (FormBuilder
  never populates it from POST); the value is set programmatically from server config and the callback name is
  hard-coded (`node_akismet_context_created` via `hook_akismet_form_info`), also `function_exists`/`is_callable`
  -gated. FP (fixed module-defined callable, no POST-injection).
- **bittorrent** — tracker announce is anon by design (`bt_tracker.module` hook_menu `access callback=>TRUE`),
  but `:227` loose `==` is on an **integer `passkey_status` flag** (not a secret; real passkey auth at `:190`
  is parameterized exact-match SQL), and the `:1061` "XSS" is inside `bencode_response_raw()` which sends
  `Content-Type: text/plain` (bencoded tracker protocol, not HTML). FP.
- **views_bulk_operations** — `ActionProcessor:630` `finished_callback` = `[$definition['class'],'finished']`
  from the action **plugin annotation** (module-registered; unknown id throws); `ViewData:153/156`
  file-include/callable come from an event subscriber (`[$this->viewData,'getEntityDefault']`, bound method;
  optional `file` set only by a module subscriber) — neither request-derived. FP.
- (SSRF akismet `Client.php:338` fixed akismet.com host; weather/basket_imex path-traversal are Drush
  Commands/AdminPages; 1530604 is a cs_solr client library in a numeric issue-fork; aggregator loose-compare is
  core-vetted — all FP/non-anon.)

CodeQL discovery running tally: batch #1 = 1 CRITICAL (#33 apex_ai); batches #2, #3, #4 = 0 confirmed. The
large-modern-module cohort is clean; the taint pass earns its keep on the occasional multi-file flow (#33).
