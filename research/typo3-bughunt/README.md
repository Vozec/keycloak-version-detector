# TYPO3 extensions — mass CodeQL bug hunt (critical + XSS)

## Corpus
**3350 TYPO3 extensions** fetched from Packagist (`type=typo3-cms-extension`,
4417 total → 3382 GitHub-hosted resolved → 3350 cloned, `--depth 1`, `.git`
pruned). `mass_typo3.sh` reproduces it.

## Pipeline (`analyze_typo3.sh`)
Extensions are analysed in **batches of 25** (copy → `codeql database create` →
analyze → cleanup), 2 workers, with the focused critical + XSS query set:
SQL injection, Code injection, Command injection, Unsafe deserialization, File
inclusion, SSRF, Path traversal, **Reflected XSS**, XXE.

**Intra-extension filter (key):** a finding is kept only when the sink's
extension appears among its taint **sources' extensions**. This drops the
cross-extension false flows that a mixed database produces (see
`../codeql-php-audit/STEP3.md`) — the reason we batch small and filter rather
than build one giant DB.

Runs with the engine precision fixes from `../codeql-php-audit/` (name-arity
gate, numeric-cast sanitizer) already applied.

## Findings
`findings_snapshot.csv` — columns `query,extension,sink_file,sink_line`.
`triage_typo3.py` filters vendored/test/CLI noise (`Resources/Public`, `/Lib/`,
`Tests/`, `cli/`, `PHP_XLSXWriter`, `h5p-core`, `Fixtures/`) and ranks by
severity + web-reachability (Controller/Middleware/eID/Ajax paths score higher).

## Honest triage notes (automated ≠ confirmed)
Sampling the early candidates, the classes to expect:
- **Real injection shape, but config/TypoScript-sourced** — e.g. RealURL
  `exec_SELECTgetRows(..., $cfg['addWhereClause'])`: real SQL built from
  extension **configuration**, not direct request input → not pre-auth-remote
  unless the config is attacker-influenced.
- **CLI scripts** (`cli/*.php`, `include($root.'/index.php')`) — local, not web.
- **Domain false positives** — Apache-Solr `Search/*Component` flagged as "SQL
  injection" are building **Solr** queries, not SQL; `array_map([$obj,'method'],
  $tainted)` flagged as Code injection has a **constant** callback (not RCE).
- **Genuinely worth manual review** — request-sourced SQLi/XSS in `Classes/…
  Controller`, eID handlers, and middlewares (these are the pre-auth surface).

So treat the CSV as a **ranked candidate list to triage**, not confirmed bugs.
The intra-extension filter + noise filter cut most of the obvious FPs; the
remaining judgement (request-source vs config-source, sink domain) is manual.

## Next precision improvements (generic, would cut the noise at the source)
- Code-injection: require the **callback** itself to be tainted (not just the
  data) for `array_map`/`call_user_func` — kills the constant-callback FP.
- Separate Solr/Elasticsearch query sinks from SQL sinks.
- Distinguish TypoScript/config reads from request sources so config-sourced
  flows rank below request-sourced ones.
