# Keycloak Version Finder (`kcvf`)

Pre-auth fingerprinting of a **Keycloak** server's version — no credentials, no
admin console. Built for authorized recon / asset inventory / patch auditing.

## Why it works

Keycloak serves its static theme assets under a versioned path:

```
/resources/<resourceVersion>/<type>/<theme>/<file>
        e.g. /resources/25.0.6/welcome/keycloak/css/welcome.css
```

Two facts make this fingerprintable:

1. **`resourceVersion` == the version, by default.** Keycloak sets
   `RESOURCES_VERSION = VERSION.toLowerCase()` (verified across 20.x–26.x). So a
   stock instance literally exposes its version in the path → exact match, zero
   work. When the token is *not* a version (e.g. `w4xzs`), the operator
   deliberately overrode it to hide the version — we then fall back to hashing.

2. **Theme files are byte-identical within a release** and change between
   releases. Hash what the target serves, match against a database of hashes
   built from official Keycloak releases, and intersect.

## Signal sources (all combined & intersected)

| Source | Covers | Built by |
|---|---|---|
| **resourceVersion** | exact version (stock config) | — (read live) |
| **Source theme files** | committed CSS/JS/img across releases | `builddb` (GitHub, fast) |
| **Distribution files** | *every* served file, all themes (`keycloak`, `keycloak.v2`, `base`) and npm bundles (PatternFly, account/admin SPAs) | `builddb dist` (Maven jars) |
| **File presence** | add/remove boundaries — a stock file served or 404'd bounds the range (both floor & ceiling) | `builddb` (per-version coverage) |
| **OIDC discovery** | behavioural floor — fields in `.well-known/openid-configuration` (Device Flow→9, CIBA→12, PAR→15, iss→17, DPoP→18, …) | static table, extensible |
| **Soft signals** | e.g. `passwordVisibility.js` → ≥24 | static |

The detector probes only **discriminating** files (those with more than one hash
bucket in the DB) — literally "the files that changed between versions" — so a
richer DB automatically means tighter results, with no code changes.

## Build

```bash
make            # build ./kcvf
make install    # install to /usr/local/bin (PREFIX= to change)
make check      # gofmt + vet + build (CI gate)
make help       # list all targets
```

Or directly: `go build -o kcvf ./cmd/kcvf`.

## Usage

```bash
./kcvf https://sso.example.com/                 # detect (single → detailed view)
./kcvf -v https://sso.example.com/              # + per-asset table, OIDC markers, realm facts
./kcvf -k https://keycloak.internal/            # skip TLS verify
./kcvf -l urls.txt                              # scan a list → compact ASCII table
cat urls.txt | ./kcvf -k                        # …or pipe the list on stdin
./kcvf --base-path /iam https://sso.example.com # pin the KC root prefix (reverse-proxy)
./kcvf --json https://a/ https://b/ | jq        # machine-readable (one obj/target)
./kcvf --no-color https://...                   # plain text
```

`--base-path <p>` forces the Keycloak root path prefix (e.g. `/iam`) instead of
auto-deriving it — handy when Keycloak sits behind a reverse-proxy prefix and the
welcome/login page doesn't embed an absolute `/resources` path.

### Scanning lists

`-l <file>` (or stdin) reads one URL per line (`#` comments and blanks ignored).
Multiple targets are scanned **concurrently** and rendered as a compact table:

```
TARGET                                KEYCLOAK         CONF  RESOURCEVERSION  OIDC≥    CANDS
────────────────────────────────────  ───────────────  ────  ───────────────  ───────  ─────
sso.example.com                       25.0.1 – 25.0.6  med   w4xzs (hidden)   ≥23.0.0  5
admin.example.org/auth                26.4.0 – 26.5.7  med   26.4.2 (=ver)    ≥26.1.0  1
legacy.example.net                    not keycloak     -     -                -        -
```

Flags: `-c N` concurrent targets (default 12), `-retry N` attempts per target if
the host looks down (default 3), `-table` force the table for a single target.

Flags: `--json`, `-v` (verbose: per-asset table, all OIDC markers, **and
observed realm facts** — issuer, realm key, grant types, scopes, SAML NameID
formats, self-service flags), `-k` (insecure TLS), `--no-color`, `-timeout`.
Colors auto-disable when output is piped or `NO_COLOR` is set.

You can pass a full login/auth URL (the realm is taken from it) or just the base.

### Recon / enumeration

```bash
./kcvf enum https://sso.example.com/                  # discover realms + public info
./kcvf enum -realms master,corp,intranet https://...  # custom realm wordlist
./kcvf enum -json https://... | jq                    # structured
```

`enum` gathers, pre-auth, per realm: issuer, realm RSA public key, OIDC
endpoints, supported grant types / scopes / id_token algs, JWKS signing keys,
**SAML NameID formats** (from the public IdP descriptor), and self-service flags
(registration / reset-password). It probes the realm in the URL plus a built-in
wordlist.

Example:

```
────────────────────────────────────────────────────────────
▸ https://sso.example.com/

  Keycloak 25.0.0 – 25.0.6   ◐ medium

  resourceVersion   w4xzs  · overridden — version hidden
  determined by     12 theme asset hashes ∩ OIDC discovery floor
  candidates (6)    25.0.0  25.0.1  25.0.2  25.0.4  25.0.5  25.0.6
  oidc floor        ≥ 23.0.0  · iss response param (RFC 9207), DPoP …
  signals           ✓ password-visibility toggle
```

Confidence: **● high** = exact (semver resourceVersion, or a single candidate);
**◐ medium** = a range from ≥2 discriminating files; **○ low** = soft signals
only. The `determined by` line shows which signals were intersected.

A `resourceVersion` token that *looks* like a version but is contradicted by the
behavioural OIDC floor (e.g. a custom theme versioned `0.23.11` on a 19–21 server)
is treated as a custom theme — not Keycloak's — and ignored for the verdict, which
falls back to the evidence-based range:

```
  Keycloak 19.0.0 – 21.1.2   ◐ medium
  resourceVersion   ignored  · path says "0.23.11" (custom theme, not Keycloak)
  determined by     10 theme asset hashes ∩ OIDC discovery floor
```

## Building the database

Coverage spans **Keycloak 1.0 → present**. The builder discovers release tags
from the **GitHub tags API by default** (so future versions are picked up with
zero maintenance — just rebuild), falling back to an offline grid (`-grid`).
Old tags carry the historical `.Final` suffix; all of that is handled
automatically.

> The builder probes GitHub (`raw.githubusercontent.com` / the tags API) to
> learn which versions exist and to hash source files — it never touches your
> target. **Detection against a live target only ever requests static resources
> (`/resources/…`) and routes (`/realms/…`, `.well-known`, SAML)** — never
> `pom.xml` or anything a reverse proxy would hide.

The repo ships a source-built DB (fast to regenerate). The distribution DB is
large to build (each `keycloak-themes-<v>.jar` is ~23 MB) — build it once on a
fast link.

Via the Makefile:

```bash
make db                 # source-only (fast)
make db-wellknown       # refresh OIDC discovery table only
make db-rebuild         # full DB (source+discovery+dist) AND re-embed
make db-all MIN=12.0.0  # full DB but skip the old back-catalogue
```

Or with the CLI directly:

```bash
# 1. Fast: source theme files from GitHub (~1 min)
./kcvf builddb -o pkg/kcfinger/db.json

# 2. Heavy: every served file from all distribution jars (needs bandwidth)
./kcvf builddb dist -i pkg/kcfinger/db.json -o pkg/kcfinger/db.json

# OIDC discovery field->version table (source-derived, cheap):
./kcvf builddb wellknown -o pkg/kcfinger/db.json

# …source + discovery + dist in one shot:
./kcvf builddb all -o pkg/kcfinger/db.json

# Limit the range (skip the old, large back-catalogue):
./kcvf builddb all -min 24.0.0

# Then re-embed:
go build -o kcvf ./cmd/kcvf
```

Flags: `-c` concurrency, `-min` lowest version to include (e.g. `-min 12.0.0`
to skip the old back-catalogue), `-grid` force the offline version grid,
`-timeout-hours` overall budget, `-i`/`-o` DB paths.

> Note: not every patch release publishes a `keycloak-themes` artifact to Maven
> Central; missing versions are reported and skipped. PatternFly/SPA hashes are
> constant within a minor, so gaps rarely matter.

## SDK

```go
import "github.com/vozec/keycloak-version-detector/pkg/kcfinger"

f, _ := kcfinger.New()                       // embedded DB
res, err := f.Detect(ctx, "https://sso.example.com/")
fmt.Println(res.Range, res.Confidence, res.Candidates)
```

Options: `WithInsecure(true)`, `WithDB(db)`, `WithHTTPClient(c)`. `Result` is
fully JSON-serializable. Set `f.ProbeConcurrency` to tune per-scan parallelism.

## Layout

```
Makefile                    build / install / db targets (make help)
cmd/kcvf/main.go            CLI (detect · enum · builddb source|wellknown|dist|all)
pkg/kcfinger/
  finger.go                 detection engine (Fingerprinter.Detect)
  enum.go                   realm/issuer/keys/SAML enumeration (Enumerate)
  probes.go                 probe definitions + soft signals
  wellknown.go              OIDC discovery markers → version floor
  builder.go                source DB builder (GitHub)
  builder_wellknown.go      OIDC discovery field→version table (source-derived)
  builder_dist.go           distribution DB builder (Maven jars, all themes)
  db.go                     DB types, embedding, version compare
  db.json                   embedded fingerprint database
```

See `METHODS.md` for the full catalogue of pre-auth version-detection vectors.

## Legitimate use

Authorized assessments, inventory, and patch-status auditing of systems you own
or may test. A hashed (non-version) `resourceVersion` is the hardened default and
good hygiene — `kcvf` reports when a target does this.
