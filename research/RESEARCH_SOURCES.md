# Pre-auth CMS / app-server source corpus

Version-labelled source & served-asset corpus for **TYPO3**, **Liferay** and
**JBoss/WildFly**, gathered to extend the `kcvf` fingerprinting methodology
(per-version asset hashing + behavioural floor) beyond Keycloak.

The raw corpus is large (~2.7 GB) and is fetched into a working tree **outside**
this repo (`/home/user/sources` in the build session). What is version-controlled
here is the **reproducible tooling** (`fetch/`) and the **per-version file-hash
manifests** (`manifests/`) — which are the actual material a version detector
needs (hash what the target serves → match against the manifest → intersect).

## What was retrieved

| Product | Retrieved | Versions | Files hashed |
|---|---|---|---|
| **TYPO3** | full source clone (all tags checkoutable) + per-version served-asset corpus | 6.2.31 → 14.3.5 (47 sampled: latest patch of every minor) | 128 045 |
| **Liferay Portal** | per-version theme/JS/served-asset corpus | 6.1.0-ga1 → 2026.q2.0 (56: all GA 6.1–7.3, sampled 7.4, quarterly CE) | 45 706 |
| **Liferay plugins SDK** | full clone (hooks / portlets / themes / layout templates) | 6.x plugins tree | (source clone) |
| **JBoss WildFly** | per-version served-asset corpus (welcome-content, banners, version markers) | 8.0.0.Final → 41.0.0.Final (73 Final releases) | ~3 400 |
| **JBoss AS7** | served-asset corpus | 7.0.0 → 7.1.1.Final (5) | incl. above |
| **JBoss AS4** | served + jmx-console / web-console | 4.2.3.GA | incl. above |

Manifest columns: `version,relpath,sha256,bytes` (gzipped CSV per product).

## Retrieval channels (this session's egress policy)

Outbound HTTPS is proxied; only some hosts are allowed. Verified working:

- ✅ `git clone` / `git ls-remote` over **github.com** (HTTPS) — primary channel.
- ✅ **raw.githubusercontent.com**.
- ✅ **Maven Central** `repo1.maven.org` — WildFly `wildfly-dist`, JBoss AS7
  `org.jboss.as:jboss-as-dist`, legacy `org.jboss.jbossas:jboss-as-dist`.
- ❌ blocked: `codeload.github.com`, GitHub archive tarballs (`/archive/*.tar.gz`),
  `download.jboss.org`, `repository.jboss.org`, `maven.repository.redhat.com`,
  `repository.liferay.com`, `releases-cdn.liferay.com`.

Consequence: **git (not release tarballs)** for source, **Maven Central** for
binary distributions.

## Per-product method & pre-auth served paths

### TYPO3 — `TYPO3/typo3`
- **Source:** `git clone --filter=blob:none github.com/TYPO3/typo3` → any of 408
  release tags checkoutable on demand.
- **Corpus:** `fetch/extract_assets.sh` checks out the latest patch of every minor
  and copies the served public assets + version markers.
- **Served pre-auth paths** (backend login / install tool / frontend load these):
  `typo3/sysext/{backend,core,install,frontend,rte_ckeditor,t3skin,felogin,dashboard}/Resources/Public/…`
- **Version markers:** `typo3/sysext/core/Classes/Information/Typo3Version.php`
  (modern), `…/Core/SystemEnvironmentBuilder.php`, `t3lib/config_default.php`
  (`TYPO3_version`, 6.x).

### Liferay Portal — `liferay/liferay-portal`
- **Method:** per-tag `git clone --filter=blob:none --no-checkout --depth 1
  --branch <tag>` + `git sparse-checkout` limited to theme/asset + version-marker
  paths (~33 MB/version instead of cloning the multi-GB monorepo).
- **Served pre-auth paths / fingerprint gold:**
  - 7.x OSGi modules: `modules/apps/frontend-theme/frontend-theme-{classic,styled,unstyled}`
    (served under `/o/frontend-theme-*`), `modules/apps/frontend-js/frontend-js-web`.
  - 6.x: `portal-web/docroot/html/themes/…`, `portal-web/docroot/html/js/liferay/…`.
- **Version markers:** `…/portal/{util,kernel/util}/ReleaseInfo.java`,
  `portal-impl/src/portal.properties` (`release.info.*`), `release.properties`.
- **Behavioural pre-auth surface** (research targets): `/api/jsonws`,
  `/c/portal/`, `/o/` OSGi endpoints, `Liferay-Portal` response header.

### Liferay plugins SDK — `liferay/liferay-plugins`
- Full clone: the classic 6.x plugin ecosystem — `hooks/`, `portlets/`, `themes/`,
  `layouttpl/`, `webs/` — useful for plugin-level fingerprinting and known-vuln
  research.

### JBoss / WildFly
- **WildFly 8–41:** Maven Central `org.wildfly:wildfly-dist:<v>:zip`. Per version
  download → extract only served + version-marker paths → drop the zip
  (`fetch/fetch_wildfly.sh`).
- **AS7:** `org.jboss.as:jboss-as-dist` (7.0.0–7.1.1; 7.1.3/7.2.0 have no dist
  artifact on Central).
- **AS4:** `org.jboss.jbossas:jboss-as-dist:4.2.3.GA` incl. the classic
  `jmx-console` / `web-console` (historic pre-auth surface).
- **Served pre-auth paths:** `welcome-content/` (served at `/` on :8080 —
  `index.html`, `wildfly.css`, logos, `favicon.ico`); version banners at
  `modules/system/layers/base/org/jboss/as/product/*/dir/META-INF/MANIFEST.MF`
  and `.installation/`.

## Regenerate

```bash
# set a target dir; scripts default to /home/user/sources
research/fetch/fetch_wildfly.sh      # WildFly + AS7 served assets  (Maven Central)
research/fetch/fetch_portal.sh       # Liferay portal theme corpus  (git sparse)
research/fetch/extract_assets.sh     # TYPO3 served assets          (from local clone)
# plus:
git clone --filter=blob:none https://github.com/TYPO3/typo3
git clone --filter=blob:none https://github.com/liferay/liferay-plugins
```

> Scripts currently hardcode `/home/user/sources` as the base — edit the `BASE`
> variable at the top of each to relocate.

## Full source code (latest) + public plugins — for code R&D

Separate from the fingerprint asset corpus above, the **complete latest source
trees** and **public plugin ecosystems** are materialised in the build session
(`/home/user/sources`) for code review (routing, account handling,
authentication, crypto). Not committed (multi-GB); the tooling + package lists
here reproduce them. See `lists/code_corpus_inventory.csv`.

| App (latest) | Lang | Source | Notes |
|---|---|---|---|
| **TYPO3 14.3.5** | PHP | `git clone --filter=blob:none TYPO3/typo3` → `checkout v14.3.5` | 19.4k files. Auth/crypto/routing: `typo3/sysext/core/Classes/{Authentication,Crypto,Security,Session,Http,Routing}` |
| **PrestaShop 9.1.4** | PHP | `git clone --depth 1 --branch 9.1.4 PrestaShop/PrestaShop` | 14.5k files. Auth: `classes/Customer.php`, `classes/Employee.php`, `src/Core/`, `src/Adapter/`, `src/PrestaShopBundle/`; crypto: `classes/*Encryptor*`, PHP-Encryption/Rijndael |
| **Liferay 2026.q2.0** | Java | `git clone --filter=blob:none --depth 1 --branch 2026.q2.0 liferay/liferay-portal` (full checkout) | 59.7k `.java`. Auth/crypto/routing: `portal-kernel/src/com/liferay/portal/kernel/security/**`, `modules/apps/**/*security*`, `portal-impl` |

Public plugins (R&D targets):

| Ecosystem | Retrieved | How |
|---|---|---|
| **PrestaShop modules** | **194** modules — every Packagist `prestashop-module` (official `ps_*`/dash*/stats* + popular third-party) | `search.json?type=prestashop-module` ranked by downloads → clone by `repository` (`fetch/clone_ps_all.sh`; official-only subset in `fetch/clone_ps_modules.sh` + `lists/ps_modules.txt`) |
| **TYPO3 public extensions** | **207** — top-200 by Packagist installs (helhum/typo3-console, news, powermail, solr, content-defender, vhs, container …) + curated | `search.json?type=typo3-cms-extension` (download-ranked) → clone by `repository` (`fetch/clone_typo3_topN.sh`; curated seed in `fetch/clone_typo3_ext.sh`) |
| **Liferay plugins SDK** | full clone (hooks/portlets/themes/layouttpl) | `git clone liferay/liferay-plugins` |
| **Liferay in-tree modules** | all OSGi app modules | already inside the `liferay-portal` latest checkout under `modules/apps/**` |

**Expansion:** TER (`extensions.typo3.org`) is blocked by egress, but **Packagist
is reachable** — `lists/typo3_ext_packagist_all.json` holds all **4412**
`typo3-cms-extension` package names; feed any subset to `clone_typo3_ext.sh` to
widen the TYPO3 corpus. PrestaShop third-party/addons modules can be added the
same way (any `github.com/<vendor>/<module>`).

## More CMS: WordPress / Joomla / Drupal (latest core + plugins)

| App (latest) | Lang | Core | Public plugins |
|---|---|---|---|
| **WordPress 7.0.2** | PHP | `git clone --depth 1 --branch 7.0.2 WordPress/WordPress` | **197** — top `wordpress-plugin` by Packagist installs (woocommerce, action-scheduler, wp-rocket, query-monitor, elasticpress …) |
| **Joomla 6.1.2** | PHP | `git clone --depth 1 --branch 6.1.2 joomla/joomla-cms` | **16** curated — `joomla-extensions` org (weblinks, jedchecker, search), Kunena forum, Joomla-Component-Builder, Akeeba components (sociallogin, skeletonkey, com_datacompliance) |
| **Drupal 11.4.4** | PHP | `git clone --depth 1 --branch 11.4.4 drupal/drupal` | **196** — top `drupal-module` by Packagist installs, github-sourced |

Plugins fetched with `fetch/clone_packagist_type.sh <type> <pages> <dest>`
(download-ranked, clones the `repository` when it is on GitHub) and
`fetch/clone_list.sh` (explicit owner/repo list). Ranked reference lists:
`lists/wordpress_plugins_ranked.tsv`, `lists/drupal_modules_ranked.tsv`,
`lists/joomla_ext_list.txt`.

### Egress blockers hit (and the workaround)
Only **github.com (git), Packagist, Maven Central, raw.githubusercontent** are
reachable. These plugin/source hosts are **blocked** by the session egress policy
(HTTP 000/403) and were routed around via GitHub + Packagist:
- `api.wordpress.org` / `downloads.wordpress.org` (official WP plugin/theme zips)
- `git.drupalcode.org` + `www.drupal.org` / `packages.drupal.org` (canonical
  Drupal **contrib** — so `drupal/token`, `drupal/pathauto`, `views` etc. that
  live only on drupalcode are **missing**; the 196 fetched are the GitHub-hosted
  subset)
- `extensions.typo3.org` (TER)
- Liferay/JBoss vendor CDNs & Nexus

**To close those gaps** the egress allowlist would need those hosts added, or the
zips supplied out-of-band. Everything else was obtained without them.

## Next step (fingerprinting)

Each manifest is directly consumable the way `kcvf` uses `db.json`: keep only the
`relpath`s that have **more than one `sha256` across versions** (the discriminating
files), probe those paths on a live target, hash the response, and intersect the
matching version sets. Add a behavioural floor per product (headers / endpoint
presence) exactly like the OIDC-discovery floor does for Keycloak.
