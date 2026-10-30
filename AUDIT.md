# AUDIT.md — qyvora-anansi

## 1. Framework identity and intended domain
- **Repository/module:** `github.com/QYVORA/qyvora-anansi` (go 1.26.5) — `/home/wsuits6/WORK/QYVORA/products/QYVORA-AI/frameworks/qyvora-anansi/` (git: clean; latest commit `b09c0fc` chore(audit): correct framework identities...)
- **Identity (from README):** ANANSI CLI — Web Application Penetration Testing Framework (Terminal Edition). Built by QYVORA OffSec (Tamale, Ghana). "Reconnaissance is the entry point, not the whole tool."
- **Actual domain (evidence):** Web application penetration testing / attack surface intelligence. Full pipeline: discovery (crt.sh CT + DNS brute-force) → probe (HTTP/HTTPS) → tls → headers → paths (exposed files/dirs) → techstack (deep CMS/framework audit, CVE matching) → takeover (dangling CNAMEs) → osint → chain (exploit paths) → exploit (PoC validation with live HTTP). Also has interactive Metasploit-style console, scripting (`qyvora-script`), self-update, multiple output formats.
- **Exit codes:** Follows QYVORA pattern (Execute returns 0/1/2/130 per root.go:304-321). 
- **Prebuilt binary (verified):** `bin/anansi version -o json` → `{"framework":"anansi","version":"0.1.0","commit":"b09c0fc",...}` (semver-like `0.1.0` without leading v in this output; contract says "must be semver" - needs checking). `bin/anansi capabilities` → unknown command (error). Bare invocation starts console/banner.
- **Notable:** README says "Only scan targets you own or have explicit written permission to test." Has safety gates for exploit phase (`--authorized` required for high-risk modules).

## 2. Audit scope and evidence sources
- **Scope:** Source (cmd/root.go, cmd/exploit.go, cmd/script.go, internal/* modules), README, go.mod, prebuilt binary behavior, git history/status, help audit.
- **Evidence:** `cmd/root.go`, `main.go`, `internal/output/types.go`, `internal/exploit/*` (implied by cmd/exploit.go), `README.md`, go.mod, `bin/anansi`, `docs/audit/help/anansi.txt`, shared contracts.
- **Verification performed:** git status/log (clean), read README/go.mod/root structure, executed `bin/anansi version -o json` and `bin/anansi capabilities` (fails as expected), checked help.

## 3. Existing capability inventory
From README and codebase:
- **Recon/Discovery:** discovery (crt.sh + DNS brute-force), probe, tls analysis, headers/CORS, paths/exposed files, techstack deep audit (WordPress/Drupal/Joomla/Magento/Ghost/Moodle/MediaWiki/Laravel + plugins/themes + CVE matching), takeover detection, osint, chain analysis (exploit paths)
- **Exploitation/Validation:** exploit phase with 8 built-in modules (web/http-trace, web/http-methods, web/path-traversal, web/open-redirect, web/reflected-input, web/directory-listing), lifecycle/state machine, evidence capture, safety gates, `--authorized`, `--dry-run`
- **Operations:** interactive console (REPL), scripting via qyvora-script, self-update (`anansi updates`/`update`), multiple output formats (terminal/json/markdown/html)
- **Infrastructure:** shared HTTP client with connection pooling, DNS cache, worker pools, robots.txt mining, version reuse

## 4. Capability status matrix (capability | status | evidence file:line)
| Capability | Status | Evidence |
|-----------|--------|----------|
| discovery/probe/tls/headers/paths/tech/takeover/osint/chain | IMPLEMENTED | README:82-94, project structure shows modules under internal/ |
| exploit phase (PoC validation) | IMPLEMENTED | README:144-186, cmd/exploit.go exists |
| Interactive console (REPL) | IMPLEMENTED | README:383-448, cmd/console.go exists |
| Scripting (qyvora-script integration) | IMPLEMENTED | go.mod has qyvora-script v0.1.0, cmd/script.go exists |
| Self-update | IMPLEMENTED | README:281-313, internal/selfupdate/ implied, `anansi updates` command |
| Output formats (terminal/json/md/html) | IMPLEMENTED | README:472-508, internal/output/ |
| JSONL events stream | IMPLEMENTED (designed) | README:174-176 mentions exploit lifecycle events on shared JSONL stream with same schema as every QYVORA framework |
| `capabilities` command | MISSING | `bin/anansi capabilities` returns "unknown command"; not found in cmd/root.go; conformance runner notes Anansi must not be probed for capabilities (shared/qyvora-common/README.md:107-112) |
| Machine-readable capability manifest | MISSING | No capabilities command/manifest found in source |
| Tier grammar in root help | UNVERIFIED in binary help shown | HELP-AUDIT-REPORT says anansi has "No" for tier/tier grammar in root help; root help shows cobra-style usage |

## 5. Reconnaissance and discovery findings
- **Web-focused discovery:** Subdomain enumeration via crt.sh CT logs + DNS brute-force, HTTP(S) probing, TLS analysis (expiry/SANs/protocol/cipher/self-signed), security headers, exposed paths/files, tech fingerprinting, takeover detection, OSINT, exploit chain assembly.
- **Performance features:** Native Go DNS resolver, shared connection pool, TTL DNS cache, fixed worker pools, parallel probing, smart takeover filtering, robots.txt mining, version reuse from homepage assets.
- **Scope control:** Verbose/clean modes, module selection, depth via wordlists, rate limiting/delays, stealth mode options.

## 6. Analysis and assessment findings
- **Techstack deep audit:** Platform-specific probes, version detection from multiple sources, plugin/theme enumeration, known-vulnerable version matching against curated CVE table.
- **Chain analysis:** 30 vulnerability classes, kill-path templates, generic escalation, ranked scoring.
- **Exploit validation:** Evidence capture (request/response), state machine, honest success/failure reporting, cleanup.

## 7. Exploitation-related capability findings
- **Active PoC validation present:** Phase 10 EXPLOIT with modules and safety gates (README:144-186). Requires authorization for high-risk modules, supports dry-run, no process spawning/payload delivery as stated. This is controlled validation/proofing within web app pentesting domain - appropriate if gated.
- **Evidence-based:** Captures request/response pairs as evidence.
- **Safety conscious:** "Honest-by-default", lifecycle states, disabled high-risk without `--authorized`.

## 8. High-level implementation candidates (P0–P3 with rationale)
| Priority | Candidate | Rationale (evidence) | Feasibility |
|----------|-----------|----------------------|-------------|
| P0 | Add `capabilities` command (or equivalent discovery) | Conformance runner expects capabilities for most frameworks; Anansi is explicitly skipped due to root taking positional target causing issues (shared/qyvora-common/README.md:107-112). Need safe implementation that doesn't trigger scans. | High (careful design needed) |
| P1 | Ensure version output is clean semver for conformance | Binary reports `version":"0.1.0"` (no leading v). Contract says "framework must report a semantic version" - `0.1.0` is semver; `IsSemverVersion` in contract accepts `v?` prefix. Should be fine. |
| P1 | Add safe machine-readable capability manifest | Orchestrators need discovery without guessing CLI structure. Must not interfere with positional target parsing. | High |
| P2 | Standardize exit codes for unknown command/flag | Cobra-based CLI needs to ensure unknown flag → exit 2, unknown command → exit 2 per contract expectations. | Medium |
| P3 | Document/expose events schema | Events mentioned for exploit phase; full schema would help orchestration. | Low/Medium |

## 9. Low-level deferred technique inventory (DEFERRED — SPECIALISED PREREQUISITES; prerequisites, feasibility, why deferred)
| Technique | Prerequisites | Feasibility | Why deferred |
|-----------|---------------|-------------|--------------|
| Advanced exploitation (RCE shells, post-exploitation) | Authorization, safe lab, careful implementation | Medium but high risk | Current exploit modules are limited HTTP checks; full exploitation framework needs extensive safety controls/lab validation. |
| Browser-based attacks/DOM XSS exploitation | Browser automation, headless browser | Low now | Complex, heavier dependencies. |
| Authenticated scanning at scale with complex flows | Session management, CSRF handling | Medium | Partially addressed but complex flows need more work. |
| Network-level attacks (MITM beyond HTTP) | Raw sockets, privileges | Low | Different domain from web app focus; other frameworks (TOHA3EE) cover network. |

## 10. Common-layer conformance (SHARED / FRAMEWORK-SPECIFIC / DUPLICATED / INCONSISTENT / MISSING / UNVERIFIED decisions)
| Component | Decision | Evidence/Rationale |
|-----------|----------|-------------------|
| Exit codes (0/1/2/130) | SHARED (adopts pattern) | root.go error handling follows pattern; needs verification against full contract |
| Semver identity | SHARED (adopts) | version command returns framework/version |
| Capability discovery | MISSING | No capabilities command; explicitly problematic for orchestration/conformance |
| JSONL events | SHARED (designed) | README says "same schema as every QYVORA framework" for exploit events |
| JSON output formats | SHARED | Uses `-o json`/`--output json` pattern consistent with ecosystem |
| TUI integration | SHARED dependency | Uses qyvora-tui v0.11.0 |
| Scripting | SHARED dependency | Uses qyvora-script v0.1.0 |
| CLI style (cobra) | SHARED pattern | Consistent with other Go frameworks |

## 11. AI orchestration readiness (per-requirement statuses)
| Requirement | Status | Evidence |
|-------------|--------|----------|
| Stable framework identity/version | CONFORMANT | version -o json works |
| Machine-readable capability descriptions | NONCONFORMANT | No capabilities command/manifest found |
| Explicit operation inputs/outputs | PARTIALLY CONFORMANT | Flags documented; modules have structure but not exposed as machine-readable operation catalog |
| Predictable exit codes | UNVERIFIED | Needs testing of unknown flag/command cases |
| Structured results/findings | CONFORMANT | Rich output types, JSON/HTML/MD formats |
| Prerequisite declarations | UNVERIFIED | Not explicitly exposed |
| Permission/authorization requirements | CONFORMANT | Exploit requires --authorized for high-risk; clear warnings |
| Timeouts/cancellation | PARTIALLY CONFORMANT | --timeout flag exists; signal handling present |
| Risk classification/confirmation | CONFORMANT | Chain scoring, exploit safety gates |
| Safe execution defaults | CONFORMANT | Verbose/default behavior reasonable; explicit warnings about authorization |
| Distinction read-only vs state-changing | PARTIALLY CONFORMANT | Most recon is read-only; exploit does active requests (validation) - needs clear classification |
| Orchestrator can discover unsupported capabilities honestly | UNVERIFIED | No capability discovery mechanism |

## 12. CLI, repository-layout, and documentation findings (exact paths; no file moves)
- **CLI:** Cobra-based with subcommands (recon, exploit, report, script, updates, version). Root accepts positional target `[target]` - this is the special case noted (anansi example.com works directly). Console mode when no args. Tier grammar not prominent in root help per audit report.
- **Binaries:** `bin/anansi` exists. git history had binary removal note in other frameworks? Not obvious here.
- **Assets:** `assets/` directory present with banners/logos.
- **Root files:** Has `security_test.go` at root (noted in PROMPT.md as something to check - anansi has it). PROMPT says "anansi has security_test.go at root" - confirmed present.
- **Docs:** Comprehensive README, docs/ directory, examples/, CHANGELOG.md.
- **Scripts:** install.sh/install.ps1 present.
- **Structure:** Clean Go project layout with cmd/, internal/ packages.

## 13. Testing and verification findings (only checks actually run)
- **Git:** Clean working tree. Recent commit about correcting framework identities.
- **Binary execution (non-destructive):**
  - `bin/anansi version -o json` → OK, returns framework/version/commit info
  - `bin/anansi capabilities` → Returns "Error: unknown command \"capabilities\" for \"anansi\"" (exit code behavior not captured but command fails as expected)
- **Tests:** Not executed in this pass. README mentions `make verify` runs lint/vet/race tests. security_test.go exists at root.

## 14. Prioritized gaps and recommendations (P0–P3; recommendations, not authorization)
| Priority | Gap | Recommendation | Notes |
|----------|-----|---------------|-------|
| P0 | Missing capabilities command/manifest | Add safe `capabilities` command that doesn't trigger scans; follow shared contract shape or provide compatible format. Must handle positional target parsing carefully. | Critical for orchestration/conformance. Shared codebase notes special handling needed. |
| P0 | Orchestration discoverability | Implement capability discovery mechanism compatible with orchestrator expectations. | Blocks AI orchestration readiness. |
| P1 | Exit code consistency | Verify and fix unknown flag/command return exit code 2 per contract. | Important for automation. |
| P1 | Version format consistency | Ensure version string is clearly parseable as semver (current `0.1.0` is fine). | Minor. |
| P2 | Operation catalog exposure | Expose available modules/operations as machine-readable data. | Would improve orchestration. |
| P3 | Events schema documentation | Document full JSONL event schema. | Nice to have. |

## 15. Dependencies, prerequisites, unresolved questions
- **Dependencies:** Go 1.26.5, cobra, fatih/color, muesli/termenv, qyvora-tui v0.11.0, qyvora-script v0.1.0 (go.mod). External libs minimal.
- **Prerequisites:** Network access for discovery/exploitation against targets; DNS resolution; no special privileges mentioned for basic recon (some operations may need privileges).
- **Unresolved questions:**
  - How should capabilities be implemented given root takes positional target? (shared README says "Anansi must not be given a capabilities probe" and explains why - need alternative approach)
  - What is the exact expected capabilities manifest format for conformance?
  - Is the root's positional target parsing compatible with subcommand-style capability discovery?
- **Safety:** Explicit warnings about authorization required; exploit phase gated.

## 16. Explicit statement: "No feature implementation was performed during this audit."
No feature implementation was performed during this audit.
