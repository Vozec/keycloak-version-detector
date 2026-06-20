// Package kcfinger fingerprints the version of a Keycloak server without
// authentication, by hashing the static theme assets it serves under
// /resources/<resourceVersion>/ and matching them against a database of
// hashes derived from official Keycloak releases.
package kcfinger

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Fingerprinter detects the Keycloak version of a target.
type Fingerprinter struct {
	HTTP      *http.Client
	DB        *DB
	UserAgent string
	// Insecure skips TLS verification when true.
	Insecure bool
	// ProbeConcurrency bounds concurrent asset requests per Detect (default 16).
	ProbeConcurrency int
	// Enrich, when true, also gathers certain realm facts (issuer, keys, grant
	// types, SAML NameID formats, …) into Result.Realm.
	Enrich bool
	// BasePath, when non-empty, pins the Keycloak root path prefix (e.g. "/iam")
	// instead of auto-deriving it. Useful behind a reverse-proxy prefix when the
	// welcome/login page doesn't embed an absolute /resources path.
	BasePath string
}

// Option configures a Fingerprinter.
type Option func(*Fingerprinter)

// WithDB sets a custom database (defaults to the embedded one).
func WithDB(db *DB) Option { return func(f *Fingerprinter) { f.DB = db } }

// WithInsecure disables TLS certificate verification.
func WithInsecure(b bool) Option { return func(f *Fingerprinter) { f.Insecure = b } }

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(c *http.Client) Option { return func(f *Fingerprinter) { f.HTTP = c } }

// WithBasePath pins the Keycloak root path prefix (e.g. "/iam"), overriding
// auto-derivation. Empty means auto-derive (default).
func WithBasePath(p string) Option { return func(f *Fingerprinter) { f.BasePath = p } }

// New builds a Fingerprinter. By default it loads the embedded database.
func New(opts ...Option) (*Fingerprinter, error) {
	db, err := LoadEmbedded()
	if err != nil {
		return nil, err
	}
	f := &Fingerprinter{
		DB:        db,
		UserAgent: "kcfinger/1.0 (+keycloak-version-finder)",
	}
	for _, o := range opts {
		o(f)
	}
	if f.HTTP == nil {
		tr := &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: f.Insecure},
			MaxIdleConnsPerHost: 32,
		}
		f.HTTP = &http.Client{Timeout: 20 * time.Second, Transport: tr}
	}
	return f, nil
}

// FileResult is the outcome of probing a single asset.
type FileResult struct {
	Path        string   `json:"path"`
	Status      int      `json:"status"`
	MD5         string   `json:"md5,omitempty"`
	Size        int      `json:"size,omitempty"`
	Matched     bool     `json:"matched"`
	Versions    []string `json:"versions,omitempty"`
	Discriminat bool     `json:"discriminator"`
}

// SoftResult records presence/absence of a soft-signal asset.
type SoftResult struct {
	Label      string `json:"label"`
	Path       string `json:"path"`
	Present    bool   `json:"present"`
	MinVersion string `json:"minVersion"`
}

// Result is the full detection report.
type Result struct {
	Target          string       `json:"target"`
	IsKeycloak      bool         `json:"isKeycloak"`
	ResourceVersion string       `json:"resourceVersion"`
	ResourcesBase   string       `json:"resourcesBase"`
	Files           []FileResult `json:"files"`
	Soft            []SoftResult `json:"soft"`
	Candidates      []string     `json:"candidates"`   // intersected version set
	MinVersion      string       `json:"minVersion"`   // floor from soft signals
	Range           string       `json:"versionRange"` // human summary, e.g. "24.0.0 – 25.0.6"
	ExactFromRV     []string     `json:"exactFromResourceVersion,omitempty"`
	// VersionFromRV is set when the resourceVersion token is itself a version
	// string. Since Keycloak computes RESOURCES_VERSION = VERSION.toLowerCase()
	// for every release (verified 20.x–26.x), a semver token IS the exact
	// version — unless the operator overrode it (see RVOverridden).
	VersionFromRV string `json:"versionFromResourceVersion,omitempty"`
	// RVOverridden is true when the resourceVersion token is non-semver,
	// meaning the default (version == token) was deliberately changed, e.g. to
	// hide the version. Detection then falls back to asset hashing.
	RVOverridden bool `json:"resourceVersionOverridden"`
	// RVSpoofed is true when the resourceVersion token IS a syntactic semver but
	// is contradicted by harder evidence (asset-hash candidates and/or the
	// behavioural OIDC/soft floor) — meaning the /resources/<x>/ path is a
	// custom-theme version or a spoofed/rewritten path, not the real Keycloak
	// version (e.g. a custom theme versioned "0.23.11"). The token is then
	// ignored for the verdict and detection falls back to the evidence range.
	RVSpoofed bool             `json:"resourceVersionSpoofed"`
	WellKnown *WellKnownResult `json:"wellKnown,omitempty"`
	Realm        *RealmInfo       `json:"realm,omitempty"` // certain facts (with -enrich)
	Confidence   string           `json:"confidence"`      // high | medium | low
	Notes        []string         `json:"notes,omitempty"`
}

var reResources = regexp.MustCompile(`["'=(]([^"'()\s]*resources/[A-Za-z0-9._\-]+/)`)
var reKeycloakHint = regexp.MustCompile(`(?i)keycloak`)

// reSemverRV matches a resourceVersion token that is a plain release version
// (optionally with a vendor suffix like "-redhat-00001" that we strip).
var reSemverRV = regexp.MustCompile(`^(\d+\.\d+\.\d+)`)

// probePagesFor returns paths (relative to the Keycloak root) likely to embed
// the resourceVersion token, biased toward the realm parsed from the input.
func probePagesFor(realm string) []string {
	rd := url.QueryEscape("http://localhost")
	pages := []string{"/"}
	realms := []string{realm}
	if realm != "master" {
		realms = append(realms, "master")
	}
	for _, r := range realms {
		pages = append(pages,
			"/realms/"+r+"/protocol/openid-connect/auth?client_id=account&response_type=code&scope=openid&redirect_uri="+rd,
			"/realms/"+r+"/account/",
		)
	}
	pages = append(pages, "/auth/")
	return pages
}

// Detect fingerprints the Keycloak instance at rawURL.
func (f *Fingerprinter) Detect(ctx context.Context, rawURL string) (*Result, error) {
	base, err := normalizeBase(rawURL)
	if err != nil {
		return nil, err
	}
	res := &Result{Target: base.String()}
	kcRoot, realm := deriveRoot(base)

	// Explicit override: pin the Keycloak root path prefix (e.g. /iam) instead
	// of relying on auto-derivation. Realm parsed from the URL (if any) is kept.
	if f.BasePath != "" {
		bp := "/" + strings.Trim(f.BasePath, "/")
		kcRoot = strings.TrimRight(base.Scheme+"://"+base.Host+bp, "/")
		res.Notes = append(res.Notes, "forced base path '"+bp+"' (root pinned to "+kcRoot+")")
	}

	// 1. Find the resourceVersion token and resources base URL.
	rvBase, rv, htmlSawKeycloak, err := f.findResourceVersion(ctx, kcRoot, realm)
	if err != nil {
		return nil, err
	}
	res.IsKeycloak = htmlSawKeycloak || rv != ""
	if rv == "" {
		if !res.IsKeycloak {
			return res, errors.New("could not locate a /resources/<version>/ path: target may not be Keycloak or is not exposing the welcome/login UI")
		}
		res.Notes = append(res.Notes, "resourceVersion token not found; cannot hash assets")
		return res, nil
	}
	res.ResourceVersion = rv
	res.ResourcesBase = rvBase
	res.IsKeycloak = true

	// Best case: a stock instance serves /resources/<version>/ verbatim
	// (RESOURCES_VERSION = VERSION.toLowerCase()). A semver token is the exact
	// version. A non-semver token means the operator overrode it.
	if m := reSemverRV.FindStringSubmatch(rv); m != nil {
		res.VersionFromRV = m[1]
	} else {
		res.RVOverridden = true
		res.Notes = append(res.Notes, "resourceVersion is not a version string — operator overrode it (version hidden); using asset hashing")
	}

	// resourceVersion -> exact version via DB (covers snapshot/odd tokens
	// captured by `builddb dist`).
	if vs := f.DB.ResourceVersions[rv]; len(vs) > 0 {
		res.ExactFromRV = append([]string(nil), vs...)
		sort.Sort(byVersion(res.ExactFromRV))
	}

	// 2. Probe + hash each asset (concurrently) and intersect candidate sets.
	// The probe list is DefaultProbes plus every DB path that actually
	// discriminates (varies across versions) — so a dist-built DB auto-extends
	// coverage to all themes and npm bundles without code changes.
	probes := f.probeList()
	frs := make([]FileResult, len(probes))
	conc := f.ProbeConcurrency
	if conc <= 0 {
		conc = 16
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, conc)
	for i, p := range probes {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p Probe) {
			defer wg.Done()
			defer func() { <-sem }()
			fr := f.probeFile(ctx, rvBase, p.ServedPath)
			fr.Discriminat = p.Discriminator
			frs[i] = fr
		}(i, p)
	}
	wg.Wait()

	var intersection map[string]bool
	intersectInit := false
	narrow := func(set map[string]bool) {
		if !intersectInit {
			intersection = set
			intersectInit = true
		} else {
			intersection = intersectKeepIfBoth(intersection, set)
		}
	}

	// Status semantics matter: only 200 means "served" and only 404 means
	// "absent". Anything else (403/429/5xx/redirects/timeouts) is a block,
	// rate-limit or transient error — NOT evidence — and must never count as a
	// difference, or a spammed/banned host would yield bogus intersections.
	blocked := 0
	for _, fr := range frs {
		if isBlockStatus(fr.Status) {
			blocked++
		}
	}

	// Pass 1: content-hash intersection + version floor. A content match also
	// proves the target runs the stock theme (gates the absence signal below).
	stockTheme := false
	for i, p := range probes {
		fr := frs[i]
		if fr.Status == 200 {
			if p.Floor != "" && CompareVersions(p.Floor, res.MinVersion) > 0 {
				res.MinVersion = p.Floor
			}
			if fr.MD5 != "" {
				if vs := f.DB.VersionsForHash(p.ServedPath, fr.MD5); len(vs) > 0 {
					fr.Matched = true
					fr.Versions = vs
					stockTheme = true
					narrow(toSet(vs))
				}
			}
		}
		frs[i] = fr
		res.Files = append(res.Files, fr)
	}

	// Absence is trustworthy only if the host is responding cleanly (no blocking
	// seen). Any 403/429/5xx ⇒ a "404" might be a WAF, so disable absence.
	absenceOK := stockTheme && blocked == 0
	if blocked > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%d probe(s) returned block/rate-limit/error status — treated as no-evidence; absence narrowing disabled", blocked))
	}

	// Pass 2: absence-based narrowing. A genuinely-served stock file already
	// matched by content in pass 1 (the DB has every version's hash), so a
	// "served (200)" signal adds nothing safe here — a 200 could be a WAF/SPA
	// catch-all page, which would falsely imply presence. We therefore use ONLY
	// real 404s: candidate ⊆ versions WITHOUT the file — gated on a confirmed
	// stock theme and a clean (un-blocked) host so a custom theme or a WAF can't
	// cause false exclusions.
	allV := toSet(f.DB.Versions)
	srcSet := toSet(SourceUniverse) // only these have complete per-version coverage
	if absenceOK {
		for i, p := range probes {
			fr := frs[i]
			if fr.Status != 404 || !srcSet[p.ServedPath] {
				continue
			}
			having := f.DB.VersionsHavingFile(p.ServedPath)
			if len(having) == 0 {
				continue
			}
			comp := map[string]bool{}
			hset := toSet(having)
			for v := range allV {
				if !hset[v] {
					comp[v] = true
				}
			}
			if len(comp) > 0 {
				narrow(comp)
			}
		}
	}

	// 3. Soft signals (presence => version floor).
	for _, s := range SoftSignals {
		present := f.exists(ctx, rvBase, s.Path)
		res.Soft = append(res.Soft, SoftResult{Label: s.Label, Path: s.Path, Present: present, MinVersion: s.MinVersion})
		if present && CompareVersions(s.MinVersion, res.MinVersion) > 0 {
			res.MinVersion = s.MinVersion
		}
	}

	// 3b. OIDC discovery markers (behavioural floor; works even when the theme
	// is identical across versions and the resourceVersion is hidden).
	if kcRoot != "" {
		wk := f.probeWellKnown(ctx, kcRoot, realm)
		if wk.Reached {
			res.WellKnown = &wk
			if CompareVersions(wk.MinVersion, res.MinVersion) > 0 {
				res.MinVersion = wk.MinVersion
			}
		}
	}

	// 3c. Certain realm facts (optional, additive — never affects the verdict).
	if f.Enrich && kcRoot != "" {
		ri := f.EnumerateRealm(ctx, kcRoot, realm)
		if ri.Exists {
			res.Realm = &ri
		}
	}

	// 4. Build candidate list.
	var cands []string
	if intersectInit {
		for v := range intersection {
			if res.MinVersion == "" || CompareVersions(v, res.MinVersion) >= 0 {
				cands = append(cands, v)
			}
		}
	}
	sort.Sort(byVersion(cands))
	res.Candidates = cands

	// 5. Summarize.
	f.summarize(res)
	return res, nil
}

func (f *Fingerprinter) summarize(res *Result) {
	// A semver resourceVersion token is normally the exact version (Keycloak
	// sets RESOURCES_VERSION = VERSION.toLowerCase()). But /resources/<x>/ is
	// operator/attacker-controllable (custom theme dir, reverse-proxy rewrite),
	// so the token can be a custom-theme version or a spoofed path.
	//
	// The behavioural OIDC/soft floor is hard to spoof: if the evidence proves a
	// minimum version ABOVE the path's version, the path is definitively wrong
	// (e.g. a custom theme versioned "0.23.11" on a 19.x–21.x server whose OIDC
	// floor is ≥ 18). Demote it and fall back to the evidence-based range.
	//
	// An asset-hash mismatch ALONE is not enough to demote: the DB may simply
	// not cover this (often old) version, which would also leave the token out
	// of the candidate set. That case keeps the token as the verdict but lowers
	// confidence and warns (handled in the switch below).
	if res.VersionFromRV != "" && res.MinVersion != "" &&
		CompareVersions(res.VersionFromRV, res.MinVersion) < 0 {
		res.RVSpoofed = true
		res.Notes = append(res.Notes, "resourceVersion path '"+res.VersionFromRV+
			"' is below the behavioural OIDC/soft floor (≥ "+res.MinVersion+
			") — treated as a custom theme version, not Keycloak's; ignored for the verdict")
		res.VersionFromRV = "" // ignore for the verdict; fall through to the evidence-based range
	}

	switch {
	case res.VersionFromRV != "":
		res.Range = res.VersionFromRV
		res.Confidence = "high"
		res.Notes = append(res.Notes, "exact version read directly from the /resources/<version>/ path (stock config)")
		// Asset hashes matched but disagree with the path version: likely a
		// custom theme, or the DB does not cover this version. Keep the path
		// version (it is the stock default) but lower confidence and flag it.
		if len(res.Candidates) > 0 && !contains(res.Candidates, res.VersionFromRV) {
			res.Confidence = "medium"
			res.Notes = append(res.Notes, "warning: theme asset hashes do not include "+res.VersionFromRV+" — assets may be a custom theme or the path was spoofed")
		}
	case len(res.ExactFromRV) == 1:
		res.Range = res.ExactFromRV[0]
		res.Confidence = "high"
		res.Notes = append(res.Notes, "exact match from resourceVersion token in DB")
	case len(res.Candidates) == 0:
		if res.MinVersion != "" {
			res.Range = ">= " + res.MinVersion
			res.Confidence = "low"
			res.Notes = append(res.Notes, "no asset hash matched the DB; range inferred from soft signals only (DB may not cover this version — try `kcvf builddb`)")
		} else {
			res.Confidence = "low"
			res.Notes = append(res.Notes, "no asset matched and no soft signal; DB likely does not cover this version")
		}
	case len(res.Candidates) == 1:
		res.Range = res.Candidates[0]
		res.Confidence = "high"
	default:
		lo := res.Candidates[0]
		hi := res.Candidates[len(res.Candidates)-1]
		res.Range = lo + " – " + hi
		// confidence: high if the matched discriminators agree tightly
		matchedDisc := 0
		for _, fr := range res.Files {
			if fr.Matched && fr.Discriminat {
				matchedDisc++
			}
		}
		if matchedDisc >= 2 {
			res.Confidence = "medium"
		} else {
			res.Confidence = "low"
		}
	}
}

// findResourceVersion fetches candidate pages (relative to kcRoot, biased to
// realm) and extracts the resources path.
func (f *Fingerprinter) findResourceVersion(ctx context.Context, kcRoot, realm string) (rvBase, rv string, sawKC bool, err error) {
	var firstErr error
	for _, page := range probePagesFor(realm) {
		full := strings.TrimRight(kcRoot, "/") + page
		body, finalURL, _, e := f.getBody(ctx, full)
		if e != nil {
			if firstErr == nil {
				firstErr = e
			}
			continue
		}
		if reKeycloakHint.Match(body) {
			sawKC = true
		}
		if m := reResources.FindSubmatch(body); m != nil {
			rel := string(m[1]) // e.g. "resources/w4xzs/" or "/auth/resources/w4xzs/"
			return resolveResources(finalURL, rel), extractToken(rel), true, nil
		}
	}
	return "", "", sawKC, firstErr
}

// deriveRoot splits a Keycloak URL into its root (where /realms lives) and the
// realm. It strips a trailing "/realms/<realm>/…" and a "/resources/<rv>/…"
// segment so users can paste any login/auth/account URL.
func deriveRoot(u *url.URL) (kcRoot, realm string) {
	realm = "master"
	path := u.Path
	if m := reRealmInPath.FindStringSubmatch(path); m != nil {
		realm = m[1]
		path = path[:strings.Index(path, "/realms/")]
	} else if i := strings.Index(path, "/resources/"); i >= 0 {
		path = path[:i]
	}
	root := u.Scheme + "://" + u.Host + path
	return strings.TrimRight(root, "/"), realm
}

// resolveResources turns a relative/absolute resources path into a full URL
// prefix ending in "/resources/<token>/".
func resolveResources(pageURL *url.URL, rel string) string {
	ref, err := url.Parse(rel)
	if err != nil {
		return strings.TrimRight(pageURL.Scheme+"://"+pageURL.Host, "/") + "/" + strings.TrimLeft(rel, "/")
	}
	abs := pageURL.ResolveReference(ref)
	return strings.TrimRight(abs.String(), "/") + "/"
}

func extractToken(rel string) string {
	rel = strings.TrimRight(rel, "/")
	i := strings.LastIndex(rel, "resources/")
	if i < 0 {
		return ""
	}
	return rel[i+len("resources/"):]
}

func (f *Fingerprinter) probeFile(ctx context.Context, rvBase, servedPath string) FileResult {
	fr := FileResult{Path: servedPath}
	body, _, code, err := f.getBody(ctx, rvBase+servedPath)
	fr.Status = code
	if err != nil || code != 200 {
		return fr
	}
	sum := md5.Sum(body)
	fr.MD5 = hex.EncodeToString(sum[:])
	fr.Size = len(body)
	return fr
}

func (f *Fingerprinter) exists(ctx context.Context, rvBase, path string) bool {
	_, _, code, err := f.getBody(ctx, rvBase+path)
	return err == nil && code == 200
}

func (f *Fingerprinter) getBody(ctx context.Context, full string) (body []byte, finalURL *url.URL, code int, err error) {
	// Retry transient network/resolver failures a few times; a real HTTP
	// response (any status) is returned immediately.
	for attempt := 0; ; attempt++ {
		var resp *http.Response
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
		if e != nil {
			return nil, nil, 0, e
		}
		req.Header.Set("User-Agent", f.UserAgent)
		req.Header.Set("Accept", "*/*")
		resp, err = f.HTTP.Do(req)
		if err != nil {
			if attempt < 3 && ctx.Err() == nil && isTransient(err) {
				continue
			}
			return nil, nil, 0, err
		}
		b, e := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if e != nil {
			if attempt < 3 && ctx.Err() == nil {
				continue
			}
			return nil, resp.Request.URL, resp.StatusCode, e
		}
		return b, resp.Request.URL, resp.StatusCode, nil
	}
}

func normalizeBase(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid url %q: %w", raw, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid url %q: missing host", raw)
	}
	return u, nil
}

// probeList is DefaultProbes plus any DB path that discriminates and is not
// already covered, so detection automatically uses everything the DB knows.
func (f *Fingerprinter) probeList() []Probe {
	out := append([]Probe(nil), DefaultProbes...)
	seen := map[string]bool{}
	for _, p := range DefaultProbes {
		seen[p.ServedPath] = true
	}
	for _, path := range f.DB.DiscriminatingPaths() {
		if !seen[path] {
			out = append(out, Probe{ServedPath: path, Discriminator: true})
			seen[path] = true
		}
	}
	return out
}

// isBlockStatus reports whether a status code indicates a block, rate-limit, or
// server error — i.e. no-evidence, must not be read as "file absent/different".
// 0 = no response (timeout). 200 and 404 are the only meaningful outcomes.
func isBlockStatus(code int) bool {
	switch code {
	case 0, 401, 403, 405, 406, 408, 409, 425, 429, 500, 502, 503, 504:
		return true
	}
	return code >= 300 && code != 404 // redirects/other 4xx-5xx are also no-evidence
}

func contains(vs []string, target string) bool {
	for _, v := range vs {
		if v == target {
			return true
		}
	}
	return false
}

func toSet(vs []string) map[string]bool {
	m := make(map[string]bool, len(vs))
	for _, v := range vs {
		m[v] = true
	}
	return m
}

func intersectKeepIfBoth(a, b map[string]bool) map[string]bool {
	out := map[string]bool{}
	for v := range a {
		if b[v] {
			out[v] = true
		}
	}
	// Guard: if intersection becomes empty (e.g. a custom/overridden asset),
	// keep the previous set rather than collapsing to nothing.
	if len(out) == 0 {
		return a
	}
	return out
}
