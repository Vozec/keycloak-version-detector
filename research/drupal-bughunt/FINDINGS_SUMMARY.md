# Drupal contrib — pre-auth bug hunt, summary

Second CMS in the pre-auth attack-surface research (after the completed TYPO3 hunt). Same
verification-first discipline: every "CONFIRMED" was re-read in source; every cleared candidate is
logged with its reason in `VERIFIED_FALSE_POSITIVES.md`.

## Corpus & method
- **Drupal core 11.x** + **~4,900 contrib modules** — the full canonical `git.drupalcode.org`
  `project/` enumeration, cloned `--depth 1`, `.git` pruned (grown from an initial ~1,000).
- **Three tracks:**
  1. **Access-bypass surface map** (`map_access_surface.py`) — enumerates public routes
     (`_access: 'TRUE'` / anonymous `_permission`) and D7 `hook_menu` `access callback => TRUE`:
     **2,385 public entry points** (393 of them un-audited D7 callbacks) → hand-audited the
     highest-risk non-test ones.
  2. **Standalone-script mining** — `.php` files inside module dirs that execute at file scope with
     no Drupal bootstrap (directly web-servable, bypassing the access system). Highest-yield vein for
     abandoned-module RCE/LFI/SSRF (coolfilter, banner, statichtml, admin_database, arcade, about,
     audio_streaming_player, filerequest).
  3. **CodeQL taint** — the improved `codeql-php` pack (augmented Drupal model + `method_exists`
     guard + `query` arg-0 narrowing + new **LDAP-injection** query), batch-run over the corpus with
     the strict intra-module source filter (~800 candidates over ~200 batches).
- **~65 modules deep-audited in source** by the verification agent fleet; every confirmed finding
  re-read in source, every cleared candidate ledgered with its reason (incl. module-classes to skip:
  distro forks, API-response hydrators, properly-controlled callbacks).

## CONFIRMED pre-auth findings (28, source-verified)
| # | Module | Sev | Class | State |
|---|--------|-----|-------|-------|
| 4 | **coolfilter** | HIGH | PHP **object injection** — bundled PHPRPC `rpc.php`/`mbstring.php` raw `unserialize($_REQUEST)`, no bootstrap → RCE via POP chain (+ `coolplayer.php` reflected XSS) | D5/6, abandoned |
| 6 | **drutex** | HIGH | **command injection → RCE** — `drutex/remote` `access=>TRUE`, `$_REQUEST[dpi]` unescaped → `exec()` | D5, abandoned (config-gated) |
| 5 | **banner** | MED | **path traversal + `unserialize`** — standalone `banner_file.php`, `$_GET[path]` → `fopen`/`unserialize` before bootstrap | D6, abandoned |
| 3 | **social_auth** | MED/HIGH | **account takeover** — links to existing account by provider email, no `email_verified` check, no toggle | **current** (^9.5-^11), provider-dependent |
| 1 | **cas** | LOW/MED | **unauth DB write** — `/casproxycallback` stores attacker `pgtId`/`pgtIou`, no origin check (`@todo` in code) → DoS / bounded PGT injection | **current** |
| 7 | **trackback** | MED | anonymous **blind SSRF** — `drupal_http_request($_REQUEST[url])`, no host filter (config-gated) | D6, abandoned |
| 2 | **mailchimp** | LOW | **webhook auth fail-open** — `if (!empty($hash) && !hash_equals(...))` skips auth when `webhook_hash` unset (default) | **current** |
| 9 | **amocrm_widget** | CRITICAL | anonymous **arbitrary function invocation** (`$_POST['callback']($_POST)`, `function_exists`-gated only) + **auth bypass** by api_key (`==`) | D7, abandoned |
| 10 | **api_normalization** | MED/HIGH | anonymous **entity IDOR** — `transformEntity` loads any entity by id, no `->access()` check → unpublished/user fields as JSON-LD | **current** (^10-^11) |
| 11 | **better_register** | MED | **forgeable email-verify token** — `md5(email.langcode)`, no secret, `==` compare → verify any account | D8 |
| 8 | **statichtml** | LOW/MED | pre-auth **path traversal** — standalone `static.php`, `$_GET[id]`→`fopen`, no bootstrap (writable-file read) | pre-D6, abandoned |
| 14 | **admin_database** | HIGH | pre-auth **LFI→RCE** — `include $_COOKIE['…adminer_file']`, no auth (PHP-wrapper/log-poison RCE) | **current** (^9-^10) |
| 15 | **arcade** | MED/HIGH | pre-auth **LFI** — standalone `gameserver.php`, `include "protocols/{$_POST[game_protocol]}.inc"` | D6, abandoned |
| 12 | **filerequest** | MED | pre-auth **file-access bypass** — `throttle.php` streams `files/` blobs, no grant check (bypassable empty-Referer) | abandoned |
| 17 | **azure_blob** | MED/HIGH | pre-auth **private-blob read** — `azure/remote` `access=>TRUE`, no token (sibling has one) | D7 |
| 22 | **azure** (azure_storage) | MED/HIGH | pre-auth **private-file read** — `azure/generate` delivery dropped the `itok`/access checks | D7 |
| 18 | **adaptive_image** | MED/HIGH | pre-auth **private-derivative read** — `file_download()` return discarded → falls through to `file_transfer()` | D7 |
| 20 | **api_source** | MED | pre-auth **source-code disclosure** — `api/source/%/%` `access=>TRUE`, bypasses `access API reference` | D7 |
| 23 | **aegir_ansible** | MED | pre-auth **infra info disclosure** — `/inventory` anon JSON of server IPs/vars/authorized-keys (`@TODO: Access control!`) | D7/DevShop |
| 13 | **audio_streaming_player** | MED | pre-auth **SSRF** — standalone `as_getnowplaying.php`, `$_POST[url]`→`fopen`, no bootstrap | abandoned |
| 16 | **about** (imageFactory) | MED | pre-auth **SSRF + `php://` read** — standalone `imageFactory.php`, `$_GET[i]`→`getimagesize` (weak 1-byte regex) | D7 theme |
| 19 | **avantlinker** | MED | pre-auth **reflected XSS** — `$search_term` (URL path) echoed raw; the `check_plain` result is unused | D7 |
| 21 | **ajax_dlcount** | LOW | anonymous **DB mutation** — `file/%/dlcounter` writes for any fid, no CSRF (counter inflation / storage DoS) | D7 |
| 24 | **blackbaud_netcommunity_sso** | HIGH | pre-auth **account takeover** — SSO sig covers `userid`+`ts` but not the email that selects the account → login as victim/admin | D7 |
| 25 | **referral** | HIGH | pre-auth **PHP object injection** — `unserialize($_COOKIE['referral_data'])` at anonymous registration, no `allowed_classes` | D6, abandoned |

| 26 | **accuweather** | HIGH | pre-auth **PHP object injection** — `unserialize($_COOKIE['accuweather_city'])` on the anon `/accuweather` page, no `allowed_classes` | D6, abandoned |
| 27 | **track** | HIGH | pre-auth **SQL injection** — anon `track/ajax/detail/<nid>` concatenates raw URL segment into `db_query(... WHERE nid='.$nid)`, no `%d` (branch gated by `?action=initsync`) | D6, abandoned |
| 28 | **flickrhood** | MED | pre-auth **open redirect** — bundled `phpFlickr/auth.php` runs at file scope; `header("Location: ".$_GET[extra])`, reached via `?frob=1` (auth_getToken does not exit) | D6/7 lib |

Plus authenticated/secret-gated real bugs (addressbook SQLi behind `view addressbook`; bd_video request-`unserialize` behind a per-video secret) — recorded in `VERIFIED_FALSE_POSITIVES.md` as not-default-pre-auth.

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
