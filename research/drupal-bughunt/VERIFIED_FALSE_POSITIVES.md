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
