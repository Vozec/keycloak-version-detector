package kcfinger

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"
)

// oidcReprPath is the source file that declares every OIDC discovery field.
const oidcReprPath = "core/src/main/java/org/keycloak/protocol/oidc/representations/OIDCConfigurationRepresentation.java"

var reJSONProperty = regexp.MustCompile(`@JsonProperty\("([^"]+)"\)`)

// BuildWellKnown derives the OIDC discovery field -> first-seen-version table by
// diffing OIDCConfigurationRepresentation.java across the given tags. Fields
// that exist in the earliest covered version are dropped (they only yield a
// useless floor). Result is sorted by version then field.
func (b *Builder) BuildWellKnown(ctx context.Context, versions []string) ([]WellKnownMarker, error) {
	first := map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, b.Concurrency)
	for _, v := range versions {
		wg.Add(1)
		sem <- struct{}{}
		go func(v string) {
			defer wg.Done()
			defer func() { <-sem }()
			body, err := b.getText(ctx, rawBase+v+"/"+oidcReprPath)
			if err != nil || body == "" {
				return
			}
			mu.Lock()
			for _, m := range reJSONProperty.FindAllStringSubmatch(body, -1) {
				f := m[1]
				if cur, ok := first[f]; !ok || CompareVersions(v, cur) < 0 {
					first[f] = v
				}
			}
			mu.Unlock()
		}(v)
	}
	wg.Wait()

	// baseline = lowest covered version; fields present then are not markers.
	baseline := ""
	for _, v := range versions {
		if baseline == "" || CompareVersions(v, baseline) < 0 {
			baseline = v
		}
	}
	var out []WellKnownMarker
	for f, v := range first {
		if v == baseline {
			continue
		}
		out = append(out, WellKnownMarker{Field: f, MinVersion: v, Label: f})
	}
	sortMarkers(out)
	return out, nil
}

func sortMarkers(m []WellKnownMarker) {
	for i := 1; i < len(m); i++ {
		for j := i; j > 0; j-- {
			a, b := m[j-1], m[j]
			c := CompareVersions(a.MinVersion, b.MinVersion)
			if c < 0 || (c == 0 && a.Field <= b.Field) {
				break
			}
			m[j-1], m[j] = m[j], m[j-1]
		}
	}
}

// getText fetches a URL as text with retries (flaky-resolver tolerant).
func (b *Builder) getText(ctx context.Context, url string) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", "kcfinger-builddb")
		resp, err := b.HTTP.Do(req)
		if err != nil {
			if isTransient(err) && ctx.Err() == nil {
				time.Sleep(time.Duration(150*(attempt+1)) * time.Millisecond)
				continue
			}
			return "", err
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return "", nil // 404 => field file absent at this tag
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		return string(body), nil
	}
	return "", nil
}
