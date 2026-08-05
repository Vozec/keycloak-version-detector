# Drupal contrib — pre-auth bug hunt, summary

Second CMS in the pre-auth attack-surface research (after the completed TYPO3 hunt). Same
verification-first discipline: every "CONFIRMED" was re-read in source; every cleared candidate is
logged with its reason in `VERIFIED_FALSE_POSITIVES.md`.

## Corpus & method
- **Drupal core 11.x** + **~1000 contrib modules** (`git.drupalcode.org`, `--depth 1`, `.git` pruned).
- **Two tracks:**
  1. **Access-bypass surface map** (`map_access_surface.py`) — enumerates public routes
     (`_access: 'TRUE'` / anonymous `_permission`) and D7 `hook_menu` `access callback => TRUE`.
     **207 public entry points** → hand-audited the non-test ones.
  2. **CodeQL taint** — the improved `codeql-php` pack with an augmented Drupal model
     (`Markup::create`/`SafeMarkup` XSS sinks, `Xss::filter`/`Html::escape` sanitizers), batch-run
     over the corpus with the strict intra-module source filter (~140 candidates over 41 batches).
- **~25 modules deep-audited in source** by the verification agent fleet.

## CONFIRMED pre-auth findings (7, source-verified)
| # | Module | Sev | Class | State |
|---|--------|-----|-------|-------|
| 4 | **coolfilter** | HIGH | PHP **object injection** — bundled PHPRPC `rpc.php`/`mbstring.php` raw `unserialize($_REQUEST)`, no bootstrap → RCE via POP chain (+ `coolplayer.php` reflected XSS) | D5/6, abandoned |
| 6 | **drutex** | HIGH | **command injection → RCE** — `drutex/remote` `access=>TRUE`, `$_REQUEST[dpi]` unescaped → `exec()` | D5, abandoned (config-gated) |
| 5 | **banner** | MED | **path traversal + `unserialize`** — standalone `banner_file.php`, `$_GET[path]` → `fopen`/`unserialize` before bootstrap | D6, abandoned |
| 3 | **social_auth** | MED/HIGH | **account takeover** — links to existing account by provider email, no `email_verified` check, no toggle | **current** (^9.5-^11), provider-dependent |
| 1 | **cas** | LOW/MED | **unauth DB write** — `/casproxycallback` stores attacker `pgtId`/`pgtIou`, no origin check (`@todo` in code) → DoS / bounded PGT injection | **current** |
| 7 | **trackback** | MED | anonymous **blind SSRF** — `drupal_http_request($_REQUEST[url])`, no host filter (config-gated) | D6, abandoned |
| 2 | **mailchimp** | LOW | **webhook auth fail-open** — `if (!empty($hash) && !hash_equals(...))` skips auth when `webhook_hash` unset (default) | **current** |

## The pattern (same as TYPO3)
- **Maintained modules' access primitives are solid** — the public-route audit cleared plupload
  (CSRF + `\w+.tmp` in non-web dir), select2 (unforgeable HMAC key + entity-access), feeds (per-sub
  HMAC), imagecache (hook_file_download re-check), imce (profile-gated), and the whole **auth-module
  suite** delegates to vetted libraries with safe defaults (simple_oauth→league/oauth2-server,
  samlauth→onelogin/php-saml, jwt→firebase/php-jwt with pinned alg). The two current-module findings
  that survived are *logic* gaps, not missing library calls: an email-trust decision (social_auth)
  and a fail-open/no-origin-check (mailchimp/cas).
- **Real pre-auth RCE lives in abandoned modules' directly-reachable standalone scripts** — `.php`
  files inside the module dir that execute at file scope with **no Drupal bootstrap**, bypassing the
  access system entirely (coolfilter, banner, drutex-remote). These are the Drupal analogue of the
  TYPO3 abandoned-extension goldmine: raw `unserialize`, path traversal, unescaped `exec`.

## CodeQL FP shapes (→ same generic query backlog as TYPO3)
Recurring, all logged: bounded dynamic dispatch (`call_user_func` over a whitelisted op / Form API
`#callback` / config-set callable — imce, betterupload, inline_entity_form, commerce), method-name
collisions (`key`'s `unserialize()` is `Json::decode`), search/LDAP query sinks flagged as SQL
(`ldap`), socket writes flagged as file writes (`email_verify`), and logger/routing/`REQUEST_METHOD`
sinks flagged as reflected XSS (seckit, domain, gdata). These reinforce the six generic codeql-php
fixes proposed in `../typo3-bughunt/FINDINGS_SUMMARY.md` (notably: taint-the-callable-identity for
dynamic dispatch, and separate search-engine query sinks from SQL).

## Reproduce
`clone_drupal.sh` (corpus) · `map_access_surface.py` (→ `access_surface.json`) ·
`/home/user/sources/code/analyze_drupal.sh` (CodeQL batch pipeline) · per-module audit reports in
`/home/user/sources/drupal/audit/`.
