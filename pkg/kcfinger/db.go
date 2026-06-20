package kcfinger

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
)

//go:embed db.json
var embeddedDB []byte

// DB is the fingerprint database: for each served file path, a map from the
// file's md5 hex digest to the list of Keycloak versions that ship that exact
// content. ResourceVersions optionally maps a deterministic /resources/<hash>/
// token to the version(s) that produce it (populated by `builddb dist`).
type DB struct {
	// Files: servedPath -> md5 -> []version
	Files map[string]map[string][]string `json:"files"`
	// ResourceVersions: resourceVersion token -> []version
	ResourceVersions map[string][]string `json:"resourceVersions"`
	// Versions is the full ordered list of versions covered by the DB.
	Versions []string `json:"versions"`
	// WellKnown is the OIDC discovery field -> intro-version table, auto-derived
	// from source. When present it overrides the built-in WellKnownMarkers.
	WellKnown []WellKnownMarker `json:"wellKnownMarkers,omitempty"`
	// BuiltAt is a free-form stamp (set by builddb).
	BuiltAt string `json:"builtAt,omitempty"`
}

// LoadEmbedded returns the database compiled into the binary.
func LoadEmbedded() (*DB, error) {
	return Parse(embeddedDB)
}

// Parse loads a DB from JSON bytes.
func Parse(b []byte) (*DB, error) {
	var db DB
	if err := json.Unmarshal(b, &db); err != nil {
		return nil, fmt.Errorf("parse db: %w", err)
	}
	if db.Files == nil {
		db.Files = map[string]map[string][]string{}
	}
	if db.ResourceVersions == nil {
		db.ResourceVersions = map[string][]string{}
	}
	return &db, nil
}

// DiscriminatingPaths returns served paths whose content varies across
// versions (more than one hash bucket) — i.e. the files worth probing because
// they actually narrow the version. This is the "test the files that changed"
// set, derived directly from the DB.
func (d *DB) DiscriminatingPaths() []string {
	var out []string
	for path, buckets := range d.Files {
		if len(buckets) > 1 {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}

// VersionsHavingFile returns the union of all versions in which servedPath
// exists (any content). Used for presence-based narrowing.
func (d *DB) VersionsHavingFile(servedPath string) []string {
	m, ok := d.Files[servedPath]
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, vs := range m {
		for _, v := range vs {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	sort.Sort(byVersion(out))
	return out
}

// VersionsForHash returns the versions matching a (servedPath, md5) pair.
func (d *DB) VersionsForHash(servedPath, md5hex string) []string {
	if m, ok := d.Files[servedPath]; ok {
		if vs, ok := m[md5hex]; ok {
			out := append([]string(nil), vs...)
			sort.Sort(byVersion(out))
			return out
		}
	}
	return nil
}

// byVersion sorts dotted semver-ish strings numerically.
type byVersion []string

func (s byVersion) Len() int      { return len(s) }
func (s byVersion) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s byVersion) Less(i, j int) bool {
	return CompareVersions(s[i], s[j]) < 0
}

// CompareVersions compares "a.b.c" strings numerically. Missing parts = 0.
func CompareVersions(a, b string) int {
	pa, pb := splitVer(a), splitVer(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func splitVer(v string) [3]int {
	var out [3]int
	part := 0
	cur := 0
	seen := false
	for i := 0; i < len(v) && part < 3; i++ {
		c := v[i]
		if c >= '0' && c <= '9' {
			cur = cur*10 + int(c-'0')
			seen = true
		} else if c == '.' {
			out[part] = cur
			part++
			cur = 0
			seen = false
		} else {
			break
		}
	}
	if seen && part < 3 {
		out[part] = cur
	}
	return out
}
