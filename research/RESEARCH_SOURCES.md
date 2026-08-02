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

## Next step (fingerprinting)

Each manifest is directly consumable the way `kcvf` uses `db.json`: keep only the
`relpath`s that have **more than one `sha256` across versions** (the discriminating
files), probe those paths on a live target, hash the response, and intersect the
matching version sets. Add a behavioural floor per product (headers / endpoint
presence) exactly like the OIDC-discovery floor does for Keycloak.
