package kcfinger

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const rawBase = "https://raw.githubusercontent.com/keycloak/keycloak/refs/tags/"
const themeRoot = "themes/src/main/resources/theme/keycloak/"

// Builder constructs a fingerprint DB from the Keycloak source tree on GitHub.
type Builder struct {
	HTTP        *http.Client
	Concurrency int
	// Progress is called with human-readable progress lines (optional).
	Progress func(string)
}

// NewBuilder returns a Builder with sane defaults.
func NewBuilder() *Builder {
	return &Builder{
		HTTP:        &http.Client{Timeout: 30 * time.Second},
		Concurrency: 12,
	}
}

// DefaultVersionGrid generates a broad set of candidate version tags spanning
// Keycloak's whole history (1.0 → present). Non-existent candidates are dropped
// automatically (the existence probe 404s). Tags for majors 1–4 carry the
// historical ".Final" suffix; 5.0.0+ are plain.
//
// Prefer TagsFromGitHub when online — it auto-covers future releases. This grid
// is the offline fallback and a forward cushion (up to major 35).
func DefaultVersionGrid() []string {
	var out []string
	for major := 1; major <= 35; major++ {
		for minor := 0; minor <= 9; minor++ {
			for patch := 0; patch <= 15; patch++ {
				v := fmt.Sprintf("%d.%d.%d", major, minor, patch)
				if major <= 4 {
					out = append(out, v+".Final")
				} else {
					out = append(out, v)
				}
			}
		}
	}
	return out
}

// Build probes every version in the grid for every probe file and returns a DB.
// It first checks existence cheaply (the welcome.css discriminator), then
// fetches the remaining files only for versions that exist.
func (b *Builder) Build(ctx context.Context, versions []string, builtAt string) (*DB, error) {
	db := &DB{
		Files:            map[string]map[string][]string{},
		ResourceVersions: map[string][]string{},
		BuiltAt:          builtAt,
	}
	for _, served := range SourceUniverse {
		db.Files[served] = map[string][]string{}
	}

	// Stage 1: existence probe (one cheap file per version).
	existing := b.filterExisting(ctx, versions)
	b.log(fmt.Sprintf("existing versions: %d / %d candidates", len(existing), len(versions)))

	// Stage 2: hash all probe files for existing versions, concurrently.
	// Workers write straight into the DB under a mutex (no channel, so there
	// is no producer/consumer ordering hazard regardless of result count).
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, b.Concurrency)
	done := 0
	total := len(existing) * len(SourceUniverse)
	for _, v := range existing {
		for _, served := range SourceUniverse {
			wg.Add(1)
			sem <- struct{}{}
			go func(v, served string) {
				defer wg.Done()
				defer func() { <-sem }()
				h, ok := b.hashRepoFile(ctx, v, servedToRepo(served))
				mu.Lock()
				if ok {
					m := db.Files[served]
					m[h] = append(m[h], v)
				}
				done++
				if done%400 == 0 {
					b.log(fmt.Sprintf("hashed %d / %d files", done, total))
				}
				mu.Unlock()
			}(v, served)
		}
	}
	wg.Wait()

	db.Versions = existing
	// sort version lists within each hash bucket
	for _, hm := range db.Files {
		for h := range hm {
			vs := hm[h]
			sortVersions(vs)
			hm[h] = vs
		}
	}
	sortVersions(db.Versions)
	return db, nil
}

func (b *Builder) filterExisting(ctx context.Context, versions []string) []string {
	var mu sync.Mutex
	var out []string
	var wg sync.WaitGroup
	sem := make(chan struct{}, b.Concurrency)
	for _, v := range versions {
		wg.Add(1)
		sem <- struct{}{}
		go func(v string) {
			defer wg.Done()
			defer func() { <-sem }()
			// pom.xml is present at every tag across all eras → universal
			// "does this version exist" probe.
			if b.tagExists(ctx, v) {
				mu.Lock()
				out = append(out, v)
				mu.Unlock()
			}
		}(v)
	}
	wg.Wait()
	sortVersions(out)
	return out
}

// tagExists reports whether a git tag exists, by probing pom.xml (present in
// every Keycloak release across all eras).
func (b *Builder) tagExists(ctx context.Context, version string) bool {
	u := rawBase + version + "/pom.xml"
	for attempt := 0; attempt < 8; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return false
		}
		req.Header.Set("User-Agent", "kcfinger-builddb")
		req.Header.Set("Range", "bytes=0-0") // we only need existence
		resp, err := b.HTTP.Do(req)
		if err != nil {
			if isTransient(err) && ctx.Err() == nil {
				time.Sleep(time.Duration(120*(attempt+1)) * time.Millisecond)
				continue
			}
			return false
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode == 200 || resp.StatusCode == 206
	}
	return false
}

// TagsFromGitHub lists Keycloak GA release tags via the GitHub API (paginated),
// so the builder auto-covers future releases. Returns nil on failure (callers
// fall back to DefaultVersionGrid). GA = "X.Y.Z" or "X.Y.Z.Final".
func (b *Builder) TagsFromGitHub(ctx context.Context) []string {
	reGA := regexp.MustCompile(`^\d+\.\d+\.\d+(\.Final)?$`)
	var out []string
	for page := 1; page <= 20; page++ {
		u := fmt.Sprintf("https://api.github.com/repos/keycloak/keycloak/tags?per_page=100&page=%d", page)
		body, err := b.getText(ctx, u)
		if err != nil || body == "" {
			break
		}
		var tags []struct {
			Name string `json:"name"`
		}
		if json.Unmarshal([]byte(body), &tags) != nil || len(tags) == 0 {
			break
		}
		for _, t := range tags {
			if reGA.MatchString(t.Name) {
				out = append(out, t.Name)
			}
		}
	}
	sortVersions(out)
	return out
}

func (b *Builder) hashRepoFile(ctx context.Context, version, repoPath string) (string, bool) {
	u := rawBase + version + "/" + themeRoot + repoPath
	// Retry transient network/DNS failures (some environments have flaky
	// resolvers under concurrency); a 404 is authoritative and not retried.
	for attempt := 0; attempt < 8; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", false
		}
		req.Header.Set("User-Agent", "kcfinger-builddb")
		resp, err := b.HTTP.Do(req)
		if err != nil {
			if isTransient(err) && ctx.Err() == nil {
				time.Sleep(time.Duration(150*(attempt+1)) * time.Millisecond)
				continue
			}
			return "", false
		}
		if resp.StatusCode != 200 {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return "", false
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if err != nil {
			if ctx.Err() == nil {
				time.Sleep(150 * time.Millisecond)
				continue
			}
			return "", false
		}
		if len(body) == 0 {
			return "", false
		}
		sum := md5.Sum(body)
		return hex.EncodeToString(sum[:]), true
	}
	return "", false
}

func isTransient(err error) bool {
	s := err.Error()
	return strings.Contains(s, "no such host") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "timeout") ||
		strings.Contains(s, "EOF") ||
		strings.Contains(s, "TLS handshake")
}

func (b *Builder) log(s string) {
	if b.Progress != nil {
		b.Progress(s)
	}
}

// servedToRepo converts a served path "<type>/keycloak/<rest>" into the repo
// path relative to themeRoot ("theme/keycloak/"), i.e. "<type>/resources/<rest>".
func servedToRepo(served string) string {
	a := strings.SplitN(served, "/", 3)
	if len(a) < 3 {
		return served
	}
	return a[0] + "/resources/" + a[2]
}

func sortVersions(vs []string) {
	// simple insertion sort via CompareVersions to avoid extra imports churn
	for i := 1; i < len(vs); i++ {
		for j := i; j > 0 && CompareVersions(vs[j-1], vs[j]) > 0; j-- {
			vs[j-1], vs[j] = vs[j], vs[j-1]
		}
	}
}
