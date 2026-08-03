# Changelog

## [Unreleased]

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
