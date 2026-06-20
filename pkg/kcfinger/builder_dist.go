package kcfinger

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// mavenThemesJar is the URL template for the official keycloak-themes artifact,
// which bundles the runtime theme resources including the npm-built assets.
const mavenThemesJar = "https://repo1.maven.org/maven2/org/keycloak/keycloak-themes/%s/keycloak-themes-%s.jar"

// BuildDist downloads the keycloak-themes distribution jar for each version and
// hashes EVERY served static asset across all themes (login, welcome, account,
// admin, common × keycloak, keycloak.v2, base, …) — including the npm-built
// bundles (patternfly, the account/admin SPAs) that are absent from the source
// tree. This realises the "diff every served file between versions" strategy:
// any file that changes becomes a discriminator automatically.
//
// db should already contain the source-built entries (call Build first); dist
// entries are merged in. Requires outbound access to Maven Central.
func (b *Builder) BuildDist(ctx context.Context, db *DB, versions []string) error {
	if db.Files == nil {
		db.Files = map[string]map[string][]string{}
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, b.Concurrency)
	done := 0
	for _, v := range versions {
		wg.Add(1)
		sem <- struct{}{}
		go func(v string) {
			defer wg.Done()
			defer func() { <-sem }()
			jar, ok, is404 := b.download(ctx, fmt.Sprintf(mavenThemesJar, v, v))
			mu.Lock()
			done++
			n := done
			mu.Unlock()
			if !ok {
				why := "timeout/unreachable"
				if is404 {
					why = "404 (not published)"
				}
				b.log(fmt.Sprintf("[%d/%d] %s: themes jar %s", n, len(versions), v, why))
				return
			}
			hashes, err := hashAllJarStatics(jar)
			if err != nil {
				b.log(fmt.Sprintf("[%d/%d] %s: %v", n, len(versions), v, err))
				return
			}
			mu.Lock()
			for served, h := range hashes {
				if db.Files[served] == nil {
					db.Files[served] = map[string][]string{}
				}
				db.Files[served][h] = append(db.Files[served][h], v)
			}
			mu.Unlock()
			b.log(fmt.Sprintf("[%d/%d] %s: +%d served files", n, len(versions), v, len(hashes)))
		}(v)
	}
	wg.Wait()

	for served := range db.Files {
		for h := range db.Files[served] {
			sortVersions(db.Files[served][h])
		}
	}
	return nil
}

// staticExt is the set of extensions served as static theme resources.
var staticExt = map[string]bool{
	".css": true, ".js": true, ".svg": true, ".png": true, ".ico": true,
	".gif": true, ".jpg": true, ".jpeg": true, ".woff": true, ".woff2": true,
	".ttf": true, ".eot": true, ".html": true, ".json": true, ".map": true,
}

// jarToServed converts a keycloak-themes jar entry path to the URL path served
// under /resources/<rv>/, or "" if it is not a served static resource.
//
//	jar:    theme/<theme>/<type>/resources/<rest>
//	served: <type>/<theme>/<rest>
func jarToServed(name string) string {
	const pfx = "theme/"
	if !strings.HasPrefix(name, pfx) {
		return ""
	}
	rest := name[len(pfx):]
	// rest = <theme>/<type>/resources/<rest...>
	a := strings.SplitN(rest, "/", 4)
	if len(a) < 4 {
		return ""
	}
	theme, typ, marker, tail := a[0], a[1], a[2], a[3]
	if marker != "resources" {
		return ""
	}
	dot := strings.LastIndex(tail, ".")
	if dot < 0 || !staticExt[strings.ToLower(tail[dot:])] {
		return ""
	}
	return typ + "/" + theme + "/" + tail
}

// hashAllJarStatics returns servedPath -> md5 for every static asset in the jar.
func hashAllJarStatics(jar []byte) (map[string]string, error) {
	zr, err := zip.NewReader(bytes.NewReader(jar), int64(len(jar)))
	if err != nil {
		return nil, fmt.Errorf("open jar: %w", err)
	}
	out := map[string]string{}
	for _, f := range zr.File {
		served := jarToServed(f.Name)
		if served == "" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(rc, 32<<20))
		rc.Close()
		if err != nil || len(body) == 0 {
			continue
		}
		sum := md5.Sum(body)
		out[served] = hex.EncodeToString(sum[:])
	}
	return out, nil
}

// download fetches a URL with several concurrent persistent retriers over a
// bounded budget. This survives flaky resolvers (a fresh DNS lookup may fail
// then succeed moments later) far better than a single connection. A 404 is
// authoritative and ends immediately. Returns (body, ok, is404).
func (b *Builder) download(ctx context.Context, url string) ([]byte, bool, bool) {
	type result struct {
		body  []byte
		is404 bool
	}
	out := make(chan result, 1)
	var once sync.Once
	deadline := time.Now().Add(140 * time.Second)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) && ctx.Err() == nil {
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
				req.Header.Set("User-Agent", "kcfinger-builddb")
				resp, err := b.HTTP.Do(req)
				if err != nil {
					time.Sleep(150 * time.Millisecond)
					continue
				}
				if resp.StatusCode == 404 {
					resp.Body.Close()
					once.Do(func() { out <- result{nil, true} })
					return
				}
				if resp.StatusCode != 200 {
					resp.Body.Close()
					time.Sleep(150 * time.Millisecond)
					continue
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					time.Sleep(150 * time.Millisecond)
					continue
				}
				once.Do(func() { out <- result{body, false} })
				return
			}
		}()
	}
	go func() { wg.Wait(); once.Do(func() { out <- result{nil, false} }) }()
	r := <-out
	return r.body, r.body != nil, r.is404
}
