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
