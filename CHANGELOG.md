# Changelog

## [Unreleased]

### Added (interactive console milestone)
- Running `anansi` with no arguments now enters an interactive
  Metasploit-style console with its own `anansi >` prompt (module context is
  shown as `anansiλ[paths] >`); all existing one-line commands keep working
- A startup banner and help hint are printed when the console runs on a real
  terminal; piped sessions stay quiet so scripts get clean output
- CLI flags passed without a target (e.g. `anansi --deep --threads 250`) are
  inherited by the console as its initial option values
- Console commands: `scan <target>`, `run [target]`, `set`/`unset`/`options`
  (option management mirroring the CLI flags), `use <module>`/`back`
  (module context), `info`, `search`, `banner`, `history`, `version`,
  `help`, `exit`/`quit`

### Fixed (runtime hardening)
- Progress bars are only rendered on a real terminal; piped/redirected output
  no longer floods with carriage-return frames
- New `scan <target>` subcommand: the REPL habit now works at the CLI instead
  of silently treating "scan" as the target domain
- The interactive console degrades to plain line-reading (with a notice) if
  the line editor cannot start, instead of dying with a cryptic error
  and dumping cobra usage
- `options` truncates long values so columns no longer collide
- A signal arriving after a scan completes can no longer print a spurious
  "Scan interrupted by user" block and force exit code 130; SIGTERM is now
  handled alongside SIGINT (SIGKILL can never be caught)
- Discovery no longer prints the "Resolving N candidates" line twice
- `set RHOSTS <target>` + `run` mirrors the classic Metasploit flow; `use
  <module>` + `run` restricts a scan to a single module
- Arrow-key history, tab completion (commands, options, modules), and
  persistent history in `~/.anansi_history` via `chzyer/readline` (same line
  editor as the sibling JABARI console)
- Console chrome upgraded to match the scan experience: green spider banner
  with version footer, a live status strip (`▮ rhosts ... module ... · v dev`)
  above every prompt, sectioned help tables, colored status glyphs, and a
  bold-green prompt that carries the module context (`anansiλ[paths] >`)
- Piped input is supported, so console sessions can be scripted
- Ctrl+C during a console scan prints partial results and returns to the
  prompt instead of killing the process
- Console tests: option parsing/validation, set/unset, module context,
  help/options/info/search output, target resolution, prompt rendering,
  tab completion

### Added (exploit-chain milestone)
- New `chain` module (Phase 09): assembles findings into multi-step exploit
  paths ranked from low-severity foothold to full compromise
- 30 vulnerability classes (`internal/assets/wordlists/chain/classes.txt`), each with keywords
  matched against finding titles and a recommended exploitation technique
- 18 curated kill-path templates (`internal/assets/wordlists/chain/chains.txt`): Full
  Compromise, RCE via Exposed Admin, WebShell Upload, SSRF Pivot, SQLi to Full
  Access, XSS to Account Takeover, Subdomain Hijack, and more
- Generic escalation path fallback: any host with 2+ distinct classes gets a
  chain ordered from least to most severe
- Chains rendered in terminal (`ChainTable`), HTML card, Markdown section, and
  included in JSON; the top chain is surfaced in the summary
- Chain engine tests: classification, template matching, per-host grouping,
  severity ordering, ranking, empty input
- Wordlist integrity tests: exactly 30 classes with valid fields, template step
  IDs must reference known classes

### Added (zero-config install & security milestone)
- `install.sh` rewritten as a zero-decision installer: auto-detects
  OS/arch/shell, downloads the checksum-verified prebuilt binary
  (SHA-256 vs published `checksums.txt`), falls back to a source build,
  installs to `~/.local/bin`, and configures PATH in bash/zsh/fish
- One-liner install: `curl -fsSL https://raw.githubusercontent.com/QYVORA/qyvora-anansi-cli/main/install.sh | bash`
- `anansi version` subcommand + `anansi --version` flag, stamped via ldflags
  (`cmd.Version`); the installer verifies a genuine binary with `anansi version`
- `make verify` — one command running lint + vet + race tests + build
- Security regression tests in `security_test.go`: no `os/exec` imports (no
  subprocess/RCE backdoor surface), no environment secret access, and a
  allowlist test proving the tool only contacts documented external hosts
- CLI tests: version flag/subcommand output, module flag parsing, findings
  dedupe, target validation
- Probe edge-case tests: empty host list, nil ports
- Wordlist data-integrity tests: vuln severity columns, stack-file format,
  fingerprint needles, takeover/header rule formats
- `checksums.txt` generated and attached to every release (sha256)
- `-trimpath` on all release builds for reproducible binaries
- CI now runs the race detector (`go test -race`) on every push/PR

### Added
- LICENSE file (MIT)
- SECURITY.md with vulnerability disclosure policy
- Dependabot config for Go deps and GitHub Actions
- golangci-lint configuration
- Makefile with build/test/lint/clean targets
- CONTRIBUTING.md with coding standards
- goreleaser configuration for automated releases
- CI workflow running tests and lint on every push/PR
- SIGINT/SIGTERM handling for clean partial-result abort
- New `tech` module: deep application-stack audit (CMS fingerprinting, version
  detection, WordPress plugin/theme enumeration, stack-specific probes, and
  CVE-backed known-vulnerable version matching)
- New `internal/httpclient` package: process-wide shared connection pool
  (keep-alives) reused across all phases for a major speedup
- New `internal/dnscache` package: TTL-based resolver cache shared across
  discovery/recursive/mutation/tls/takeover phases
- Soft-404 baseline in tech path probing to cut false positives on catch-all
  servers
- Tech-stack results rendered in terminal, JSON, Markdown, and HTML reports

### Performance (10x milestone)
- All hot phases (paths, discovery, probe, techstack) switched from
  goroutine-per-job + semaphore to fixed worker pools pulling from channels:
  stable concurrency, no goroutine churn on 8k+ path rules, atomic progress
- Default `--threads` raised 50 -> 100
- robots.txt mining: each host's Allow/Disallow entries are probed as extra
  low-severity paths at no extra cost (one request per host)

### Depth (10x milestone)
- Fingerprint table grown from 37 -> 170 signatures covering CMS, front-end
  frameworks, backend frameworks, app servers, CDN/edge, and JS libraries
- CVE vuln table grown from 27 -> 68 rules (WordPress core/plugins, Drupal,
  Joomla, Magento, Ghost, MediaWiki, Moodle)
- New stack-specific audit rule files: Magento, Ghost, Moodle, MediaWiki,
  Laravel/Symfony (with Ignition RCE CVE-2021-3129, profiler, telescope, etc.)
- New stack version detection: Magento (/magento_version), Ghost (generator
  meta), MediaWiki (/api.php siteinfo), Moodle (/login/index.php + body)
- New component enumeration: Drupal modules, Joomla components, MediaWiki
  extensions alongside WordPress plugins/themes
- Expanded generic probe set (actuator heapdump/env/loggers, GraphQL/GraphiQL,
  swagger/openapi, composer/package lockfiles, docker-compose, error logs,
  backup archives, .env variants)

### Changed
- Pinned Go version to 1.22.0 in go.mod
- Replaced init() with sync.Once lazy loading in probe, headers, takeover
- Replaced raw int completed counter with atomic.Int64 in discovery, probe, takeover
- Removed unused stealth parameter from tls.probeHost
- Fixed shadowed delay variable in probe.probeHost
- DNS-label validation on target input (rejects IPs, empty labels, >253 chars)
- WHOIS privacy warning about unencrypted TCP transport
- All HTTP modules now share one connection-pooled client (keep-alives enabled,
  replacing DisableKeepAlives) — probe, paths, headers, takeover, osint, discovery
- Global dedupe of findings across phases (paths/tech overlap)

### Fixed
- Race condition in concurrent progress counters
