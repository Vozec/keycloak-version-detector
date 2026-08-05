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
