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
