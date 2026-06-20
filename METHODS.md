# Pre-auth Keycloak version detection — method catalogue

Every vector below is reachable **without authentication**. Ranked roughly by
precision × robustness. "Robust to hardening" means it still works when the
operator hid the version (non-semver `resourceVersion`), shipped a custom theme,
and sits behind a reverse proxy.

Legend: ✅ implemented · 🟡 partial · ⬜ planned/possible

---

## Tier 1 — exact or near-exact

### 1. `resourceVersion` path == version  ✅
Keycloak sets `RESOURCES_VERSION = VERSION.toLowerCase()` (verified 20.x–26.x).
A stock instance serves `/resources/25.0.6/...` → **exact version, instantly**.
- Granularity: exact patch.
- Robust to hardening: ❌ (defeated by overriding the token, e.g. `w4xzs`).
- Source: live HTML. Already the first thing `kcvf` checks.

### 2. Distribution asset hashing — all themes & npm bundles  ✅ (engine) / 🟡 (DB)
Hash every served static file (`login/welcome/account/admin/common` ×
`keycloak/keycloak.v2/base`, incl. PatternFly + account/admin SPA bundles) and
intersect against a per-version hash DB built from `keycloak-themes-<v>.jar`.
Only **discriminating** files (≥2 hash buckets) are probed.
- Granularity: patch-level once the dist DB is fully built (PatternFly alone
  splits 24/25/26; SPA bundles split most minors).
- Robust to hardening: ✅ for masked rv; ⚠️ partially defeated by a *fully*
  custom theme, but `common`/npm assets (PatternFly, adapters) are rarely themed.
- Build: `kcvf builddb dist` (Maven). DB currently source-only; needs the heavy
  download to reach full precision.

---

## Tier 2 — behavioural, theme-independent (work even with custom themes)

### 2b. File presence / add-remove boundaries  ✅
Beyond hashing file *content*, the mere **presence** of a stock file bounds the
version: the builder records, for every committed `keycloak`-theme file, the
exact version set in which it exists. Many files were added or removed across
redesigns (legacy welcome images `bug.png`/`mail.png`, login `feedback-*-arrow`
images, new login JS like `kcNumberFormat.js`). So:
- served (200) ⇒ candidate ⊆ versions that ship the file (both a floor *and* a
  ceiling when the file existed only in a window),
- absent (404) ⇒ candidate ⊆ the complement — applied **only once the stock
  theme is confirmed** (a content hash matched), so a custom theme dropping a
  file cannot cause a false exclusion.
Applied only to fully-covered source files (not partial npm/dist entries).

### 3. OIDC discovery field-presence floor  ✅ (auto-built from source)
`/realms/{realm}/.well-known/openid-configuration`. Each `@JsonProperty` field
in `OIDCConfigurationRepresentation` was added at a known release; the newest
field present sets a **version floor**. The field→version map is auto-derived by
diffing that source file across tags (no guessing).
- Granularity: floor (lower bound), occasionally tight when a field is recent.
- Robust to hardening: ✅✅ (pure behaviour; immune to theme/rv/proxy).

### 4. OIDC discovery value-set fingerprint  ⬜
Beyond presence, the *contents* of version-characteristic arrays —
`id_token_signing_alg_values_supported`, `code_challenge_methods_supported`,
`grant_types_supported`, `response_modes_supported`, `request_object_*`,
`acr_values_supported` — change between releases. Hash the sorted union of these
(host-independent) arrays → a behavioural signature comparable across versions.
- Granularity: can be tight; complements the floor.
- Robust to hardening: ✅✅.
- Build caveat: reference values depend on enabled features; best built from a
  matrix of stock instances, or approximated from registered provider lists in
  source.

### 4b. Behavioural / parser differentials  ⬜  (your idea — strong)
Send a crafted request and watch how the server *handles input* — accepted vs
rejected parameters, accepted types, error codes. These reflect server logic, so
they survive masked rv + custom theme + proxy.

Concrete pre-auth differentials:
- **Token endpoint grant_type recognition.** `POST …/token` with a dummy client
  and `grant_type=X`. If the server *knows* the grant it proceeds to client auth
  → `invalid_client` (401); if not → `unsupported_grant_type` (400). The set of
  recognized grants is version-characteristic:
  `urn:openid:params:grant-type:ciba` & `…:device_code` → ≥13,
  token-exchange / OAuth 2.1 grants → later. No credentials needed.
- **`response_mode` acceptance.** `…/auth?response_mode=jwt` (JARM) → accepted
  ≥15, `invalid_request` before. Same for `query.jwt` / `form_post.jwt`.
- **`prompt=create`** (registration-as-prompt) → handled ≥21, rejected before.
- **Parameter typing / multiplicity.** How a repeated parameter
  (`scope=a&scope=b`) or an unexpected array/JSON type (in the `claims` param or
  a JSON body) is coerced/rejected changed with the Quarkus + Jackson updates —
  a value accepted on one major and 400'd on another.
- **PKCE / nonce enforcement** defaults and error wording.

Granularity: floor, sometimes a tight band. Robust: ✅✅. Cost: **active**
probing (fine for authorized tests). Building the reference matrix is best done
by running each version once (a Docker matrix — the `builddb` idea applied to
behaviour); some boundaries are derivable from source (when a grant/param check
was added).

### 5. Other discovery documents  ✅
Detection probes `openid-configuration`, `oauth-authorization-server` **and**
`uma2-configuration`, unioning their fields before applying the #3 markers — so
the floor still works if one document is disabled but another is exposed.

### 6. Framework / error-shape fingerprint  ⬜
A deliberately malformed request elicits framework-specific errors:
- RESTEasy classic (≤16) vs **RESTEasy Reactive / Quarkus** (17+) differ in
  wording and JSON shape (e.g. `"Unable to find matching target resource
  method"` is Quarkus-era).
- 405/404/400 bodies and `Allow` headers shift across majors.
- Granularity: coarse (era / major band) but fully robust; great as a floor.

---

## Tier 3 — corroborating signals

### 7. JS adapter file hash  ⬜
`/js/keycloak.js`, `/js/keycloak-authz.js` are shipped with the server and
change content by release (the embedded `adapter` string `0.11.0` is **not** the
server version — ignore it; hash the file). Theme-independent.
- Build: also present in the distribution; hashable like #2.

### 8. Default security headers  🟡
Keycloak's default `Content-Security-Policy`, `X-Frame-Options`,
`Referrer-Policy`, `Strict-Transport-Security` defaults changed across versions.
- Robust: ❌ when a proxy rewrites headers (common — e.g. the w-ha targets).

### 9. Cookie names & attributes  ⬜
Flow cookies (`AUTH_SESSION_ID`, `AUTH_SESSION_ID_LEGACY`, `KC_RESTART`,
`KEYCLOAK_IDENTITY`, `KEYCLOAK_SESSION`, SameSite/secure attributes) were
introduced/changed at known versions. Observe on the auth flow.
- Robust: ⚠️ proxies may add/replace cookies.

### 10. Endpoint existence (appeared/removed)  🟡
Probe presence (200 vs 404) of endpoints tied to a release:
- `…/protocol/openid-connect/ext/ciba/auth` (CIBA), `…/ext/device/` (device)
- `…/login-status-iframe.html`, `…/3p-cookies/step1.html`
- `/realms/{realm}/.well-known/oauth-authorization-server`
- health/metrics moved to the **management port 9000** in KC 25 — absence on the
  main port (where it existed pre-25) is itself a signal.

### 11. Login / welcome / account HTML structure  ⬜
After stripping dynamic bits (CSRF, session_state, nonces, the rv token), the
rendered HTML scaffolding (element classes, data-attrs, script ordering) changes
between versions. Normalize → hash. Defeated by custom themes for `login`, but
the account/admin consoles are rarely re-themed.

### 12. ETag / Last-Modified of static assets  ⬜
Weak: cache headers may encode build time, but Keycloak uses far-future caching
and content-based ETags; low signal, noted for completeness.

---

---

## Recon side-channel (not version, but gathered pre-auth)  ✅
`kcvf enum` discovers realms (URL realm + wordlist) and dumps each realm's
issuer, RSA public key, OIDC endpoints, grant types, scopes, id_token algs, JWKS
signing keys, and **SAML NameID formats** (from `/protocol/saml/descriptor`),
plus self-service flags. Some of these double as version hints (e.g. the
`organization` scope ⇒ Organizations feature ⇒ ≥26; CIBA/device grants ⇒ ≥13).

---

## Strategy

`kcvf` combines Tiers 1–2 and intersects:
`exact-rv` → else `asset-hash range` ∩ `discovery floor` ∩ `soft signals`.
For a hardened target (masked rv + custom theme), Tiers 2 (#3, #4, #6) and the
non-theme assets of #2 (#7 PatternFly/adapters) are the load-bearing signals.
