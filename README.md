<div align="center">

# 🔑 keycloak-version-detector

**Pre-auth Keycloak fingerprinter — pin the exact version in seconds, no credentials.**

Pinpoints a **Keycloak** server's version without touching the admin console or any auth flow —
reading the live `resourceVersion` path, hashing theme-independent static assets against a
per-release database, bounding the range by file presence, and intersecting an **OIDC-discovery
behavioural floor**. Even a hardened target that masks its version is narrowed to a tight band —
all driven by a fingerprint database built across **every Keycloak release (1.0 → 26.x)**.

[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Keycloak](https://img.shields.io/badge/Keycloak-1.0->26.x-blue?logo=keycloak&logoColor=white)](https://github.com/keycloak/keycloak)

</div>

---

```text
  kcvf -> https://sso.example.com/

  Keycloak 25.0.0 - 25.0.6   ◐ medium

  resourceVersion   w4xzs  · overridden — version hidden
  determined by     12 theme asset hashes ∩ OIDC discovery floor
  candidates (6)    25.0.0  25.0.1  25.0.2  25.0.4  25.0.5  25.0.6
     |- welcome/keycloak/css/welcome.css      sha256:6f2a… -> 25.0.x
     |- common/keycloak/web_modules/…patternfly.css   -> 24|25|26 split
     |- login/keycloak/js/passwordVisibility.js       present -> ≥ 24
  oidc floor        ≥ 23.0.0  · iss response param (RFC 9207), DPoP …
  signals           ✓ password-visibility toggle
```

## ✨ Features

- **Exact version, instantly (stock config)** — Keycloak sets `RESOURCES_VERSION = VERSION`,
  so a stock instance literally serves `/resources/25.0.6/…` → **exact patch, one GET**.
- **Robust to hardening** — when the operator masks the token (`/resources/w4xzs/…`), `kcvf`
  falls back to **`sha256` of theme-independent assets** intersected against a per-release
  UNION database. `common`/PatternFly/SPA bundles survive custom `login` themes.
- **File-presence boundaries** — a stock file served (200) or `404`'d bounds the range from
  **both sides** (files were added *and* removed across redesigns), applied only once the
  stock theme is confirmed by a content-hash match — no false exclusions from custom themes.
- **OIDC-discovery floor** — each field in `.well-known/openid-configuration` was added at a
  known release; the newest field present sets a **version floor** — pure behaviour, immune to
  theme / rv-masking / reverse-proxy. Auto-derived by diffing source across tags (no guessing).
- **Custom-theme sanity check** — a `resourceVersion` that *looks* like a version but is
  contradicted by the OIDC floor is treated as a custom theme and ignored for the verdict.
- **Pre-auth realm recon** — `kcvf enum` dumps issuer, realm RSA key, OIDC endpoints, grant
  types, scopes, JWKS keys, **SAML NameID formats**, and self-service flags, per realm.
- **Fast & concurrent** — single target in seconds; scan a list of targets in parallel.
- **Library + CLI** — embeddable Go SDK (`kcfinger`) and a colorized CLI with JSON output.

## 📦 Install

```bash
go install github.com/vozec/keycloak-version-detector/cmd/kcvf@latest
```

Or build from source:

```bash
git clone https://github.com/Vozec/keycloak-version-detector
cd keycloak-version-detector
make build       # -> ./kcvf   (DB is embedded, the binary is self-contained)
make install     # -> /usr/local/bin/kcvf   (PREFIX= to change)
make check       # gofmt + vet + build (CI gate)
```

## 🚀 Usage

```bash
kcvf https://sso.example.com/                   # detect — single target, detailed view
kcvf -v https://sso.example.com/                # + per-asset table, OIDC markers, realm facts
kcvf -l urls.txt                                # scan a list -> compact ASCII table
cat urls.txt | kcvf -k                          # …or pipe the list on stdin
kcvf --base-path /iam https://sso.example.com   # pin the KC root prefix (reverse-proxy)
kcvf --json https://a/ https://b/ | jq          # machine-readable, one object per target
kcvf enum https://sso.example.com/              # pre-auth realm / issuer / key recon
```

| Flag | Description |
|------|-------------|
| `-v` | Verbose — per-asset table, all OIDC markers, **and observed realm facts** |
| `-l <file>` | Read one target URL per line (`#` comments / blanks ignored); `-` / stdin too |
| `--base-path <p>` | Force the Keycloak root prefix (e.g. `/iam`) instead of auto-deriving |
| `--json` | Machine-readable output, one JSON object per target |
| `-k` | Skip TLS certificate verification |
| `-c <n>` | Concurrent targets in list mode (default 12) |
| `-retry <n>` | Attempts per target if the host looks down (default 3) |
| `-table` | Force the compact table even for a single target |
| `-timeout <dur>` | Per-request timeout |
| `--no-color` | Plain text (auto-disabled when piped or `NO_COLOR` is set) |

### Scanning lists

`-l <file>` (or stdin) scans many targets **concurrently** and renders a compact table:

```text
TARGET                                KEYCLOAK         CONF  RESOURCEVERSION  OIDC≥    CANDS
────────────────────────────────────  ───────────────  ────  ───────────────  ───────  ─────
sso.example.com                       25.0.1 – 25.0.6  med   w4xzs (hidden)   ≥23.0.0  5
admin.example.org/auth                26.4.0 – 26.5.7  med   26.4.2 (=ver)    ≥26.1.0  1
legacy.example.net                    not keycloak     -     -                -        -
```

## 🧠 How it works

Keycloak serves its static theme assets under a **versioned** path:

```
/resources/<resourceVersion>/<type>/<theme>/<file>
        e.g. /resources/25.0.6/welcome/keycloak/css/welcome.css
```

Two facts make this fingerprintable:

1. **`resourceVersion` == the version, by default.** `RESOURCES_VERSION = VERSION.toLowerCase()`
   (verified 20.x–26.x) → a stock instance exposes its version in the path. A *non*-version
   token means the operator deliberately hid it — we fall back to hashing.
2. **Theme files are byte-identical within a release** and change between releases. Hash what
   the target serves, match against a per-release hash DB, and **intersect**.

The detector probes only **discriminating** files (those with more than one hash bucket in the
DB) — literally "the files that changed between versions" — so a richer DB automatically yields
tighter results, with no code changes. All signals are combined and intersected:

| Source | Covers | Built by |
|---|---|---|
| **resourceVersion** | exact version (stock config) | — *(read live)* |
| **Source theme files** | committed CSS/JS/img across releases | `builddb` (GitHub, fast) |
| **Distribution files** | *every* served file, all themes + npm bundles (PatternFly, SPAs) | `builddb dist` (Maven jars) |
| **File presence** | add/remove boundaries — a served/404'd stock file bounds the range | `builddb` (per-version coverage) |
| **OIDC discovery** | behavioural floor (Device Flow→9, CIBA→12, PAR→15, iss→17, DPoP→18…) | static table, extensible |
| **Soft signals** | e.g. `passwordVisibility.js` → ≥24 | static |

**Confidence:** ● **high** = exact (semver `resourceVersion`, or a single candidate) · ◐ **medium**
= a range from ≥2 discriminating files · ○ **low** = soft signals only. The `determined by`
line shows which signals were intersected.

> See **[METHODS.md](METHODS.md)** for the full catalogue of pre-auth version-detection vectors
> (Tiers 1–3: exact, behavioural/theme-independent, and corroborating signals).

## 🔎 Recon / enumeration

```bash
kcvf enum https://sso.example.com/                    # discover realms + public info
kcvf enum -realms master,corp,intranet https://...    # custom realm wordlist
kcvf enum -json https://... | jq                      # structured
```

`enum` gathers, pre-auth, per realm: issuer, realm RSA public key, OIDC endpoints, supported
grant types / scopes / id_token algs, JWKS signing keys, **SAML NameID formats** (from the
public IdP descriptor), and self-service flags (registration / reset-password). It probes the
realm in the URL plus a built-in wordlist. Some of these double as version hints (the
`organization` scope ⇒ ≥26; CIBA / device grants ⇒ ≥13).

## 📚 SDK

```go
import "github.com/vozec/keycloak-version-detector/pkg/kcfinger"

f, _ := kcfinger.New()                          // embedded DB
res, err := f.Detect(ctx, "https://sso.example.com/")
fmt.Println(res.Range, res.Confidence, res.Candidates)
```

Options: `WithInsecure(true)`, `WithDB(db)`, `WithHTTPClient(c)`. `Result` is fully
JSON-serializable. Set `f.ProbeConcurrency` to tune per-scan parallelism.

## 🗂️ Project layout

```
.
├── Makefile                     # build / install / db targets (make help)
├── METHODS.md                   # full catalogue of pre-auth detection vectors
├── cmd/kcvf/main.go             # CLI (detect · enum · builddb source|wellknown|dist|all)
└── pkg/kcfinger/
    ├── finger.go                # detection engine (Fingerprinter.Detect)
    ├── enum.go                  # realm/issuer/keys/SAML enumeration (Enumerate)
    ├── probes.go                # probe definitions + soft signals
    ├── wellknown.go             # OIDC discovery markers -> version floor
    ├── builder.go               # source DB builder (GitHub)
    ├── builder_wellknown.go     # OIDC discovery field->version table (source-derived)
    ├── builder_dist.go          # distribution DB builder (Maven jars, all themes)
    ├── db.go                    # DB types, embedding, version compare
    └── db.json                  # embedded fingerprint database (go:embed)
```

### Building the database

Coverage spans **Keycloak 1.0 → present**. The builder discovers release tags from the GitHub
tags API by default (future versions are picked up with zero maintenance — just rebuild),
falling back to an offline grid (`-grid`). The builder only ever probes GitHub / Maven — it
**never touches your target**; detection against a live host only requests static
`/resources/…` and public routes (`/realms/…`, `.well-known`, SAML).

```bash
make db                  # source-only DB from GitHub tags (fast, ~1 min)
make db-wellknown        # refresh only the OIDC discovery field->version table
make db-all MIN=24.0.0   # source + discovery + dist, skipping the old back-catalogue
make db-rebuild          # full DB (source+discovery+dist) AND re-embed into the binary
```

Or with the CLI directly: `kcvf builddb [source|wellknown|dist|all] -o pkg/kcfinger/db.json`.
Flags: `-c` concurrency, `-min` lowest version to include, `-grid` force the offline grid,
`-timeout-hours` overall budget, `-i`/`-o` DB paths. Not every patch publishes a
`keycloak-themes` artifact to Maven; missing versions are reported and skipped.

## ⚖️ Legal

For **authorised security testing only** — bug-bounty programs, pentest engagements, asset
inventory, and patch-status auditing of systems you own or may test. Detection against a live
target only requests static resources and public discovery routes. A hashed (non-version)
`resourceVersion` is the hardened default and good hygiene — `kcvf` reports when a target
does this. You are responsible for having permission.

## License

MIT © [Vozec](https://github.com/Vozec)
