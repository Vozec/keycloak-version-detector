# Pre-auth attack surface map — TYPO3 / PrestaShop / Liferay

Entry points reachable **without authentication**, plus the auth and crypto
subsystems, extracted from the latest source trees fetched into this session
(`/home/user/sources`). Paths are relative to each app's source root. This is a
research map (where to look), not a vuln report.

---

## TYPO3 14.3.5 (PHP)  ·  `typo3/typo3-core`

### Unauthenticated entry points
- **eID handlers** — dispatched by `TypoScriptFrontendController`/`eID`
  middleware **before** FE user auth ⇒ the classic TYPO3 pre-auth surface.
  Registered via `$GLOBALS['TYPO3_CONF_VARS']['FE']['eID_include']`.
  Core handlers found:
  - `dumpFile` → `typo3/sysext/core/Classes/Controller/FileDumpController.php`
  - `tx_cms_showpic` → `typo3/sysext/frontend/Classes/Controller/ShowImageController.php`
  (both take signed HMAC params — `HashService`; parameter tampering / hash
  handling is the interesting bit. Historically eID scripts are where unauth
  bugs land — enumerate every extension's `eID_include` too.)
- **FE request middleware chain** (runs per request, pre-auth):
  `typo3/sysext/frontend/Configuration/RequestMiddlewares.php`,
  `typo3/sysext/core/Configuration/RequestMiddlewares.php`.
- **Public backend routes** (no BE session required) declared
  `'access' => 'public'` in:
  - `typo3/sysext/backend/Configuration/Backend/Routes.php` — `login`,
    `password_forget`, …
  - `typo3/sysext/backend/Configuration/Backend/AjaxRoutes.php`
  - `typo3/sysext/install/Configuration/Backend/Routes.php` (Install Tool —
    gated by `ENABLE_INSTALL_TOOL` file + session)
  - `typo3/sysext/reactions/Configuration/Backend/Routes.php` (incoming webhook
    reactions — unauthenticated by design, token-checked)
- Frontend rendering: `typo3/sysext/frontend/Classes/Controller/` (page `type`,
  `?eID=`, `?tx_*` plugin args).

### Authentication
`typo3/sysext/core/Classes/Authentication/` — `AbstractUserAuthentication`,
`FrontendUserAuthentication`, `BackendUserAuthentication`,
`AuthenticationService`, MFA under `Mfa/`.

### Crypto
`typo3/sysext/core/Classes/Crypto/`:
- Password hashing: `PasswordHashing/{Argon2id,Argon2i,Bcrypt,Pbkdf2,Phpass,Blowfish,Md5}PasswordHash.php`
  (+ `PasswordHashFactory`).
- `Random.php` (CSPRNG), `HashService.php` / `HashAlgo.php` (HMAC for the signed
  eID/URL params above), `Cipher/{CipherService,SharedKey,KeyFactory,CipherValue}.php`.

---

## PrestaShop 9.1.4 (PHP)  ·  `code/prestashop-9.1.4`

### Unauthenticated entry points
- **Anonymous route allowlist** — the authoritative list of routes served
  without a customer/employee session:
  `src/PrestaShopBundle/Routing/AnonymousRouteProvider.php`
  (+ `LegacyRouterChecker.php`, `LegacyControllerConstants.php`).
- **33 core front controllers** (`controllers/front/*.php`) — all guest-reachable
  by nature. High-signal: `AuthController`, `PasswordController`,
  `RegistrationController`, `GetFileController`, `UploadController`,
  `PdfInvoiceController`, `ProductController`, `CartController`,
  `ContactController`, `GuestTrackingController`, `OrderController`,
  `SitemapController`. Dispatch: `classes/Dispatcher.php`.
- **Module front controllers** — each installed module ships
  `controllers/front/*.php` reachable via
  `?fc=module&module=<m>&controller=<c>` **without auth**. This is the biggest
  variable surface — sweep every module in `code/prestashop-modules/` for
  `controllers/front/`.
- **Webservice API** (key-authenticated, but the parser is pre-auth):
  `webservice/dispatcher.php`, `classes/webservice/WebserviceRequest.php`,
  `classes/webservice/SQLUtils.php`, `WebserviceSpecificManagement*.php`.

### Authentication
`controllers/front/AuthController.php`; identity in `classes/Customer.php`
(`getByEmail()` L457, `checkPassword()` L837), `classes/Employee.php`; session
in `classes/Cookie.php`.

### Crypto
- Session cookie encryption: `classes/Cookie.php` → `classes/PhpEncryption.php`
  / `classes/PhpEncryptionEngine.php` (`defuse/php-encryption`, AES-256 + HMAC;
  key `_COOKIE_KEY_` / `_NEW_COOKIE_KEY_`).
- Password hashing: `src/Core/Crypto/Hashing.php`,
  `src/Core/Domain/Customer/ValueObject/Password.php` (`password_hash`/bcrypt).
- `src/Core/Security/OpenSsl/OpenSSL.php`.

---

## Liferay 2026.q2.0 (Java)  ·  `code/liferay-2026.q2.0`

### Unauthenticated entry points
- **`auth.public.paths`** — struts/portal paths served to the Guest user,
  `portal-impl/src/portal.properties` (L3697). Notable:
  `/portal/json_service`, `/document_library/get_file`,
  `/document_library/find_file_entry`, `/image_gallery_display/find_image`,
  `/message_boards/{find_message,find_thread,rss}`, `/portal/open_id_request`,
  `/portal/open_id_response`, `/portal/expire_session`, `/portal/extend_session`,
  `/iframe/proxy`, `/portal/robots`, `/portal/sitemap`,
  `/portal/comment/get_comments`. (Historically `get_file`, `find_*` and
  `/iframe/proxy` are where unauth IDOR/SSRF bugs surface.)
- **Auth pipeline / verifiers** (decide what's pre-auth):
  `portal-kernel/src/com/liferay/portal/kernel/security/auth/` —
  `AuthVerifier`, `AuthTokenWhitelist`, `AuthTokenWhitelistUtil`
  (CSRF/`p_auth` token allowlist — bypass-relevant), `Authenticator`.
- **JSON web services** `/api/jsonws` — the OAuth2 JSONWS auth-verifier filter:
  `modules/apps/oauth2-provider/oauth2-provider-jsonws/.../OAuth2WebServerServletAuthVerifierFilter.java`.
- **Login module anonymous commands** (reachable without a session):
  `modules/apps/login/login-web/.../portlet/action/` —
  `CreateAnonymousAccountMVCActionCommand`, `CreateAccountMVCActionCommand`,
  `ForgotPasswordMVCRenderCommand`; `LoginPortlet`, `FastLoginPortlet`.

### Authentication
`portal-kernel/.../security/auth/` (AutoLogin, AuthPipeline, Authenticator);
login UI+actions in `modules/apps/login/`.

### Crypto
- Password: `portal-kernel/src/com/liferay/portal/kernel/security/pwd/`
  (`PasswordEncryptorUtil`, `Toolkit`, `BasicToolkit`).
- Pluggable hashing providers: `modules/apps/portal-crypto-hash/` —
  `portal-crypto-hash-provider-bcrypt`,
  `portal-crypto-hash-provider-message-digest` (+ SPI/factory).

---

## Cross-cutting research method

1. **Enumerate every plugin's entry points**, not just core:
   - PrestaShop: `code/prestashop-modules/*/controllers/front/*.php`
   - TYPO3: each extension's `ext_localconf.php` `eID_include` +
     `Configuration/RequestMiddlewares.php` + FE plugins
   - Liferay: each module's `*MVCActionCommand`/`*MVCResourceCommand` +
     `@Component ... "auth.verifier...=false"` / `guest` properties
2. **Diff across versions** (the fingerprint corpus in `manifests/`) to pin when
   an endpoint/param appeared → maps a finding to affected version ranges.
3. Feed confirmed unauth endpoints back into the detector as behavioural
   presence probes (same idea as Keycloak's OIDC-discovery floor).
