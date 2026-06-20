// kcvf — Keycloak Version Finder.
//
// Pre-auth fingerprinting of a Keycloak server by hashing the static theme
// assets it serves under /resources/<resourceVersion>/ and matching them
// against a database of hashes built from official Keycloak releases.
//
// Usage:
//
//	kcvf <url> [<url> ...]      detect version(s)
//	kcvf -json <url>            machine-readable output
//	kcvf builddb [-o file]      (re)build the fingerprint database from GitHub
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vozec/keycloak-version-finder/pkg/kcfinger"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "builddb" {
		runBuildDB(os.Args[2:])
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "enum" {
		runEnum(os.Args[2:])
		return
	}

	fs := flag.NewFlagSet("kcvf", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	insecure := fs.Bool("k", false, "skip TLS certificate verification")
	verbose := fs.Bool("v", false, "show per-file probe details")
	noColor := fs.Bool("no-color", false, "disable ANSI colors")
	listFile := fs.String("l", "", "read targets from a file (one URL per line; '-' for stdin)")
	basePath := fs.String("base-path", "", "force Keycloak root path prefix (e.g. /iam), overriding auto-derivation")
	table := fs.Bool("table", false, "force compact table output (default for >1 target)")
	conc := fs.Int("c", 12, "concurrent targets when scanning a list")
	retries := fs.Int("retry", 3, "attempts per target if the host seems down")
	timeout := fs.Duration("timeout", 20*time.Second, "per-request timeout")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Keycloak Version Finder\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  kcvf [flags] <url> [<url> ...]      detect version(s)\n  kcvf -l urls.txt                    scan a list → compact table\n  kcvf enum [-json] <url>             enumerate realms / public info\n  kcvf builddb [source|wellknown|dist|all] [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(os.Args[1:])
	if *noColor || *asJSON {
		useColor = false
	}

	targets := gatherTargets(fs.Args(), *listFile)
	if len(targets) == 0 {
		fs.Usage()
		os.Exit(2)
	}

	f, err := kcfinger.New(kcfinger.WithInsecure(*insecure), kcfinger.WithBasePath(*basePath))
	if err != nil {
		fatal(err)
	}
	f.Enrich = *verbose || *asJSON // gather certain realm facts for -v / --json

	tableMode := (*table || len(targets) > 1) && !*verbose
	reports := scanTargets(f, targets, *conc, *retries, *timeout, !*asJSON)

	switch {
	case *asJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if len(reports) == 1 {
			enc.Encode(reports[0])
		} else {
			enc.Encode(reports)
		}
	case tableMode:
		renderTable(reports)
	default:
		for _, r := range reports {
			printHuman(r, *verbose)
		}
	}
}

// gatherTargets collects targets from args, an optional list file, and stdin.
func gatherTargets(args []string, listFile string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, a := range args {
		add(a)
	}
	readLines := func(r io.Reader) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			add(sc.Text())
		}
	}
	if listFile == "-" {
		readLines(os.Stdin)
	} else if listFile != "" {
		fh, err := os.Open(listFile)
		if err != nil {
			fatal(err)
		}
		defer fh.Close()
		readLines(fh)
	} else if len(args) == 0 && !stdinIsTTY() {
		// piped list with no args: read stdin
		readLines(os.Stdin)
	}
	return out
}

func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

// scanTargets detects every target concurrently (bounded), with per-target
// retries on transient/host-down errors and a live progress line on stderr.
func scanTargets(f *kcfinger.Fingerprinter, targets []string, conc, retries int, timeout time.Duration, progress bool) []*kcfinger.Result {
	if conc < 1 {
		conc = 1
	}
	if retries < 1 {
		retries = 1
	}
	results := make([]*kcfinger.Result, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, conc)
	var mu sync.Mutex
	done := 0
	showProgress := progress && len(targets) > 1 && stderrIsTTY()

	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = scanOne(f, t, retries, timeout)
			if showProgress {
				mu.Lock()
				done++
				fmt.Fprintf(os.Stderr, "\r\033[K  scanning… %d/%d", done, len(targets))
				mu.Unlock()
			}
		}(i, t)
	}
	wg.Wait()
	if showProgress {
		fmt.Fprint(os.Stderr, "\r\033[K")
	}
	return results
}

// scanOne detects a single target, retrying when the host looks transiently
// down (connection refused/timeout/DNS), but not when it's reachable-but-not-KC.
func scanOne(f *kcfinger.Fingerprinter, target string, attempts int, timeout time.Duration) *kcfinger.Result {
	var lastErr error
	for i := 0; i < attempts; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeout*4)
		res, err := f.Detect(ctx, target)
		cancel()
		if err == nil {
			return res
		}
		lastErr = err
		if i < attempts-1 && looksDown(err) {
			time.Sleep(time.Duration(i+1) * 500 * time.Millisecond)
			continue
		}
		break
	}
	return &kcfinger.Result{Target: target, Notes: []string{lastErr.Error()}}
}

func looksDown(err error) bool {
	s := strings.ToLower(err.Error())
	for _, n := range []string{"refused", "timeout", "no such host", "deadline", "reset", "eof", "no route", "unreachable", "tls"} {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func stderrIsTTY() bool {
	fi, err := os.Stderr.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

// ---- compact table for list scans ----

func renderTable(reports []*kcfinger.Result) {
	headers := []string{"TARGET", "KEYCLOAK", "CONF", "RESOURCEVERSION", "OIDC≥", "CANDS"}
	rows := make([][]string, 0, len(reports))
	confOf := make([]string, 0, len(reports)) // parallel: confidence per row for coloring
	for _, r := range reports {
		rows = append(rows, tableRow(r))
		confOf = append(confOf, rowConf(r))
	}

	// column widths from plain text
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = len(h)
	}
	for _, row := range rows {
		for i, c := range row {
			if n := dispLen(c); n > w[i] {
				w[i] = n
			}
		}
	}

	// header
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(pad(h, w[i]))
		if i < len(headers)-1 {
			hb.WriteString("  ")
		}
	}
	fmt.Println(cBold(hb.String()))
	// rule
	var rb strings.Builder
	for i := range headers {
		rb.WriteString(strings.Repeat("─", w[i]))
		if i < len(headers)-1 {
			rb.WriteString("  ")
		}
	}
	fmt.Println(cDim(rb.String()))
	// rows
	for ri, row := range rows {
		var b strings.Builder
		for i, c := range row {
			cell := pad(c, w[i])
			if i == 1 { // KEYCLOAK column → colorize by confidence
				cell = colorByConf(cell, confOf[ri])
			}
			b.WriteString(cell)
			if i < len(row)-1 {
				b.WriteString("  ")
			}
		}
		fmt.Println(b.String())
	}
}

func tableRow(r *kcfinger.Result) []string {
	target := compactTarget(r.Target)
	if !r.IsKeycloak {
		reason := "not keycloak"
		if len(r.Notes) > 0 && looksDown(fmt.Errorf("%s", r.Notes[0])) {
			reason = "unreachable"
		}
		return []string{target, reason, "-", "-", "-", "-"}
	}
	ver := r.Range
	if ver == "" {
		ver = "unknown"
	}
	rv := r.ResourceVersion
	if r.RVOverridden {
		rv += " (hidden)"
	} else if r.VersionFromRV != "" {
		rv += " (=ver)"
	}
	floor := "-"
	if r.WellKnown != nil && r.WellKnown.MinVersion != "" {
		floor = "≥" + r.WellKnown.MinVersion
	}
	cands := "-"
	if n := len(r.Candidates); n > 0 {
		cands = fmt.Sprintf("%d", n)
	}
	return []string{target, ver, confShort(r.Confidence), rv, floor, cands}
}

func rowConf(r *kcfinger.Result) string {
	if !r.IsKeycloak {
		return "low"
	}
	return r.Confidence
}

func confShort(c string) string {
	switch c {
	case "high":
		return "high"
	case "medium":
		return "med"
	default:
		return "low"
	}
}

func colorByConf(s, conf string) string {
	switch conf {
	case "high":
		return cGreen(s)
	case "medium":
		return cYellow(s)
	default:
		return cDim(s)
	}
}

func compactTarget(t string) string {
	t = strings.TrimPrefix(t, "https://")
	t = strings.TrimPrefix(t, "http://")
	t = strings.TrimRight(t, "/")
	// keep host + a short path hint
	if len(t) > 48 {
		t = t[:47] + "…"
	}
	return t
}

// pad right-pads to width based on display length (ignores ANSI, handles wide runes).
func pad(s string, width int) string {
	n := dispLen(s)
	if n >= width {
		return s
	}
	return s + strings.Repeat(" ", width-n)
}

// dispLen approximates display width: counts runes, ignoring ANSI escapes.
func dispLen(s string) int {
	n := 0
	inEsc := false
	for _, r := range s {
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		if r == '\x1b' {
			inEsc = true
			continue
		}
		n++
	}
	return n
}

// ---- color / styling (respects TTY + NO_COLOR) ----

var useColor = colorEnabled()

func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

func sgr(code, s string) string {
	if !useColor {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func cBold(s string) string   { return sgr("1", s) }
func cDim(s string) string    { return sgr("2", s) }
func cGreen(s string) string  { return sgr("32", s) }
func cYellow(s string) string { return sgr("33", s) }
func cRed(s string) string    { return sgr("31", s) }
func cCyan(s string) string   { return sgr("36", s) }

// kv prints an aligned "label  value" row.
func kv(label, value string) {
	fmt.Printf("  %s  %s\n", cDim(fmt.Sprintf("%-16s", label)), value)
}

func confidenceBadge(conf string) string {
	switch conf {
	case "high":
		return cGreen("● high")
	case "medium":
		return cYellow("◐ medium")
	default:
		return cRed("○ low")
	}
}

func printHuman(r *kcfinger.Result, verbose bool) {
	rule := strings.Repeat("─", 60)
	fmt.Printf("\n%s\n", cDim(rule))
	fmt.Printf("%s %s\n", cCyan("▸"), cBold(r.Target))

	if !r.IsKeycloak {
		fmt.Printf("  %s\n", cRed("✗ not detected as Keycloak"))
		return
	}

	// Headline verdict.
	verdict := r.Range
	if verdict == "" {
		verdict = "unknown"
	}
	headline := cBold("Keycloak " + verdict)
	switch r.Confidence {
	case "high":
		headline = cGreen(cBold("Keycloak " + verdict))
	case "medium":
		headline = cYellow(cBold("Keycloak " + verdict))
	}
	fmt.Printf("\n  %s   %s\n\n", headline, confidenceBadge(r.Confidence))

	// resourceVersion + how it was determined.
	rvline := r.ResourceVersion
	switch {
	case r.RVSpoofed:
		rvline = cYellow("ignored") + "  " + cDim("· path says \""+r.ResourceVersion+"\" (custom theme, not Keycloak)")
	case r.VersionFromRV != "":
		rvline += "  " + cDim("· equals version (stock config)")
	case r.RVOverridden:
		rvline += "  " + cYellow("· overridden — version hidden")
	}
	kv("resourceVersion", rvline)
	kv("determined by", evidenceSummary(r))

	// Candidates.
	if len(r.ExactFromRV) > 0 {
		kv("exact (rv→ver)", strings.Join(r.ExactFromRV, ", "))
	}
	if n := len(r.Candidates); n > 0 {
		if n <= 10 {
			kv(fmt.Sprintf("candidates (%d)", n), strings.Join(r.Candidates, "  "))
		} else {
			kv(fmt.Sprintf("candidates (%d)", n), fmt.Sprintf("%s … %s", r.Candidates[0], r.Candidates[n-1]))
		}
	}

	// OIDC discovery floor.
	if r.WellKnown != nil && r.WellKnown.Reached && r.WellKnown.MinVersion != "" {
		detail := ""
		if labels := r.WellKnown.PresentLabels(); len(labels) > 0 {
			detail = "  " + cDim("· "+firstN(labels, 2))
		}
		kv("oidc floor", "≥ "+r.WellKnown.MinVersion+detail)
	}

	// Soft signals.
	var soft []string
	for _, s := range r.Soft {
		if s.Present {
			soft = append(soft, cGreen("✓")+" "+s.Label)
		} else {
			soft = append(soft, cDim("✗ "+s.Label))
		}
	}
	if len(soft) > 0 {
		kv("signals", strings.Join(soft, "   "))
	}

	if verbose {
		printVerbose(r)
	}

	for _, n := range r.Notes {
		fmt.Printf("  %s %s\n", cDim("›"), cDim(n))
	}
}

// printVerbose renders the full evidence: resources base, every probed asset,
// all OIDC discovery markers, and certain realm facts.
func printVerbose(r *kcfinger.Result) {
	if r.ResourcesBase != "" {
		fmt.Printf("\n  %s %s\n", cDim("resources base"), cDim(r.ResourcesBase))
	}

	// Certain, observed facts (100% — not inferred).
	if r.Realm != nil {
		fmt.Printf("\n  %s %s\n", cBold("realm facts"), cDim("(observed, certain)"))
		ri := r.Realm
		if ri.Issuer != "" {
			fmt.Printf("   %s %s\n", cDim("issuer       "), ri.Issuer)
		}
		if ri.PublicKeyHead != "" {
			fmt.Printf("   %s %s\n", cDim("realm key    "), cDim(ri.PublicKeyHead))
		}
		if len(ri.GrantTypes) > 0 {
			fmt.Printf("   %s %s\n", cDim("grant types  "), strings.Join(ri.GrantTypes, ", "))
		}
		if len(ri.Scopes) > 0 {
			fmt.Printf("   %s %s\n", cDim("scopes       "), strings.Join(ri.Scopes, ", "))
		}
		if len(ri.SAMLNameIDs) > 0 {
			fmt.Printf("   %s %s\n", cDim("SAML NameIDs "), strings.Join(shortNameIDs(ri.SAMLNameIDs), ", "))
		}
		fmt.Printf("   %s %s   %s\n", cDim("self-service "),
			boolflag("registration", ri.Registration), boolflag("reset-password", ri.PasswordReset))
	}

	// Assets table — discriminators first, then served, then missing.
	fmt.Printf("\n  %s\n", cBold("assets probed")+cDim("  (* = discriminator)"))
	rows := append([]kcfinger.FileResult(nil), r.Files...)
	sort.SliceStable(rows, func(i, j int) bool { return assetRank(rows[i]) < assetRank(rows[j]) })
	for _, fr := range rows {
		mark := " "
		if fr.Discriminat {
			mark = cCyan("*")
		}
		var status string
		switch {
		case fr.Matched:
			status = cGreen(fmt.Sprintf("✓ %d versions", len(fr.Versions)))
		case fr.Status == 200:
			status = cYellow("served, not in DB")
		case fr.Status == 0:
			status = cDim("no response")
		default:
			status = cDim(fmt.Sprintf("HTTP %d", fr.Status))
		}
		hash := cDim("········")
		if fr.MD5 != "" {
			hash = cDim(shortMD5(fr.MD5))
		}
		fmt.Printf("   %s %s  %s  %s\n", mark, hash, padTrunc(fr.Path, 52), status)
	}

	// OIDC discovery markers (all present, newest first).
	if r.WellKnown != nil && r.WellKnown.Reached {
		if len(r.WellKnown.Present) == 0 {
			fmt.Printf("\n  %s %s\n", cBold("oidc discovery"), cDim("reached, no version-tied field present"))
		} else {
			fmt.Printf("\n  %s %s\n", cBold("oidc discovery"), cDim(fmt.Sprintf("(realm %s) — newest field sets the floor", r.WellKnown.Realm)))
			for _, m := range r.WellKnown.Present {
				fmt.Printf("   %s  %s %s\n", cGreen("≥"+padRight(m.MinVersion, 8)), m.Label, cDim("("+m.Field+")"))
			}
		}
	}
}

// assetRank orders assets: matched, then served-not-matched, then missing.
func assetRank(fr kcfinger.FileResult) int {
	switch {
	case fr.Matched:
		return 0
	case fr.Status == 200:
		return 1
	default:
		return 2
	}
}

// evidenceSummary describes which signals produced the verdict.
func evidenceSummary(r *kcfinger.Result) string {
	var parts []string
	if r.VersionFromRV != "" {
		parts = append(parts, "resourceVersion path")
	}
	if len(r.ExactFromRV) > 0 {
		parts = append(parts, "rv→version table")
	}
	matched := 0
	for _, fr := range r.Files {
		if fr.Matched {
			matched++
		}
	}
	if matched > 0 {
		parts = append(parts, fmt.Sprintf("%d theme asset hashes", matched))
	}
	if r.WellKnown != nil && r.WellKnown.Reached && r.WellKnown.MinVersion != "" {
		parts = append(parts, "OIDC discovery floor")
	}
	if len(parts) == 0 {
		return cDim("no matching signal")
	}
	return strings.Join(parts, " ∩ ")
}

func firstN(s []string, n int) string {
	if len(s) <= n {
		return strings.Join(s, ", ")
	}
	return strings.Join(s[:n], ", ") + fmt.Sprintf(" (+%d more)", len(s)-n)
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func padTrunc(s string, n int) string {
	if len(s) == n {
		return s
	}
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s + strings.Repeat(" ", n-len(s))
}

func shortMD5(s string) string {
	if len(s) >= 8 {
		return s[:8]
	}
	return strings.Repeat(" ", 8)
}

func runBuildDB(args []string) {
	// Modes:
	//   builddb            source-only DB from GitHub (fast, ~1 min)
	//   builddb dist       augment an existing DB with full per-version theme
	//                      hashes from Maven distribution jars (heavy download)
	//   builddb all        source then dist, in one shot
	mode := "source"
	if len(args) >= 1 && (args[0] == "dist" || args[0] == "all" || args[0] == "wellknown") {
		mode = args[0]
		args = args[1:]
	}

	fs := flag.NewFlagSet("builddb", flag.ExitOnError)
	out := fs.String("o", "pkg/kcfinger/db.json", "output path for the database")
	in := fs.String("i", "pkg/kcfinger/db.json", "(dist) input DB to augment")
	minV := fs.String("min", "", "only include versions >= this (e.g. 24.0.0 to skip the heavy old range)")
	conc := fs.Int("c", 8, "concurrency")
	hours := fs.Int("timeout-hours", 8, "overall timeout in hours (dist of all versions is large)")
	offline := fs.Bool("grid", false, "use the offline version grid instead of the GitHub tags API")
	_ = fs.Parse(args)

	b := kcfinger.NewBuilder()
	b.Concurrency = *conc
	b.Progress = func(s string) { fmt.Fprintln(os.Stderr, "[builddb] "+s) }

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*hours)*time.Hour)
	defer cancel()

	filter := func(vs []string) []string {
		if *minV == "" {
			return vs
		}
		var f []string
		for _, v := range vs {
			if kcfinger.CompareVersions(v, *minV) >= 0 {
				f = append(f, v)
			}
		}
		return f
	}

	// Version list: GitHub tags API (auto-covers future releases) with the
	// offline grid as fallback. Computed once.
	var allVersions []string
	versionList := func() []string {
		if allVersions != nil {
			return allVersions
		}
		if !*offline {
			if tags := b.TagsFromGitHub(ctx); len(tags) > 0 {
				fmt.Fprintf(os.Stderr, "[builddb] %d GA tags from GitHub API (1.0 → latest)\n", len(tags))
				allVersions = filter(tags)
				return allVersions
			}
			fmt.Fprintln(os.Stderr, "[builddb] GitHub tags API unavailable; using offline grid")
		}
		allVersions = filter(kcfinger.DefaultVersionGrid())
		return allVersions
	}

	var db *kcfinger.DB

	// wellknown: refresh only the OIDC discovery field table in an existing DB.
	if mode == "wellknown" {
		raw, err := os.ReadFile(*in)
		if err != nil {
			fatal(fmt.Errorf("read input DB (%s): %w", *in, err))
		}
		if db, err = kcfinger.Parse(raw); err != nil {
			fatal(err)
		}
		fmt.Fprintln(os.Stderr, "[builddb] deriving OIDC discovery field table from source…")
		markers, err := b.BuildWellKnown(ctx, versionList())
		if err != nil {
			fatal(err)
		}
		db.WellKnown = markers
		fmt.Fprintf(os.Stderr, "[builddb] %d discovery markers\n", len(markers))
		writeDB(db, *out)
		return
	}

	// Source phase (for "source" and "all", or as the base loaded from disk for "dist").
	if mode == "dist" {
		raw, err := os.ReadFile(*in)
		if err != nil {
			fatal(fmt.Errorf("read input DB (%s): %w", *in, err))
		}
		if db, err = kcfinger.Parse(raw); err != nil {
			fatal(err)
		}
	} else {
		stamp := time.Now().UTC().Format(time.RFC3339)
		fmt.Fprintln(os.Stderr, "[builddb] crawling keycloak source tags on GitHub…")
		var err error
		if db, err = b.Build(ctx, versionList(), stamp); err != nil {
			fatal(err)
		}
		if mode == "source" {
			writeDB(db, *out)
			return
		}
	}

	// "all" also refreshes the OIDC discovery table (cheap, source-derived).
	if mode == "all" {
		fmt.Fprintln(os.Stderr, "[builddb] deriving OIDC discovery field table from source…")
		if markers, err := b.BuildWellKnown(ctx, versionList()); err == nil {
			db.WellKnown = markers
			fmt.Fprintf(os.Stderr, "[builddb] %d discovery markers\n", len(markers))
		}
	}

	// Dist phase ("dist" or "all").
	vers := filter(db.Versions)
	fmt.Fprintf(os.Stderr, "[builddb] downloading %d keycloak-themes jars from Maven Central (~23MB each)…\n", len(vers))
	if err := b.BuildDist(ctx, db, vers); err != nil {
		fatal(err)
	}
	writeDB(db, *out)
}

func writeDB(db *kcfinger.DB, out string) {
	data, err := json.MarshalIndent(db, "", " ")
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "[builddb] wrote %s (%d versions, %d KB)\n", out, len(db.Versions), len(data)/1024)
	fmt.Fprintln(os.Stderr, "[builddb] rebuild the binary to embed: go build ./cmd/kcvf")
}

func runEnum(args []string) {
	fs := flag.NewFlagSet("enum", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	insecure := fs.Bool("k", false, "skip TLS certificate verification")
	noColor := fs.Bool("no-color", false, "disable ANSI colors")
	realms := fs.String("realms", "", "comma-separated realm wordlist (overrides the default)")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: kcvf enum [-k] [-json] [-no-color] [-realms a,b,c] <url>")
		os.Exit(2)
	}
	if *noColor || *asJSON {
		useColor = false
	}

	f, err := kcfinger.New(kcfinger.WithInsecure(*insecure))
	if err != nil {
		fatal(err)
	}
	var extra []string
	if *realms != "" {
		for _, r := range strings.Split(*realms, ",") {
			if r = strings.TrimSpace(r); r != "" {
				extra = append(extra, r)
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	infos, err := f.Enumerate(ctx, fs.Arg(0), extra)
	if err != nil {
		fatal(err)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(infos)
		return
	}
	if len(infos) == 0 {
		fmt.Println(cDim("no realms found (try -realms with custom names)"))
		return
	}
	fmt.Printf("\n%s %s\n", cCyan("▸"), cBold(fmt.Sprintf("%d realm(s) found", len(infos))))
	for _, in := range infos {
		fmt.Printf("\n%s\n", cBold(cCyan("realm  "+in.Realm)))
		if in.Issuer != "" {
			kv("issuer", in.Issuer)
		}
		if in.PublicKeyHead != "" {
			kv("realm RSA key", cDim(in.PublicKeyHead))
		}
		kv("self-service", strings.Join([]string{
			boolflag("registration", in.Registration),
			boolflag("reset-password", in.PasswordReset),
		}, "   "))
		if len(in.GrantTypes) > 0 {
			kv("grant types", strings.Join(in.GrantTypes, ", "))
		}
		if len(in.Scopes) > 0 {
			kv("scopes", strings.Join(in.Scopes, ", "))
		}
		if len(in.IDTokenAlgs) > 0 {
			kv("id_token algs", strings.Join(in.IDTokenAlgs, ", "))
		}
		if len(in.JWKS) > 0 {
			var ks []string
			for _, k := range in.JWKS {
				ks = append(ks, fmt.Sprintf("%s/%s%s", k.Kty, k.Alg, useSuffix(k.Use)))
			}
			kv("signing keys", fmt.Sprintf("%d  %s", len(in.JWKS), cDim("["+strings.Join(ks, ", ")+"]")))
		}
		if len(in.SAMLNameIDs) > 0 {
			kv("SAML NameIDs", strings.Join(shortNameIDs(in.SAMLNameIDs), ", "))
		}
		if len(in.Endpoints) > 0 {
			kv("OIDC endpoints", cDim(fmt.Sprintf("%d (token, authz, userinfo, jwks, …)", len(in.Endpoints))))
		}
	}
}

func boolflag(name string, on bool) string {
	if on {
		return cGreen("✓") + " " + name
	}
	return cDim("✗ " + name)
}

func useSuffix(u string) string {
	if u == "" {
		return ""
	}
	return "(" + u + ")"
}

func shortNameIDs(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if i := strings.LastIndex(id, ":"); i >= 0 {
			out = append(out, id[i+1:])
		} else {
			out = append(out, id)
		}
	}
	return out
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
