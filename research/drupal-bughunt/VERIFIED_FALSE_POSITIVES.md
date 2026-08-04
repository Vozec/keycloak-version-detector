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
