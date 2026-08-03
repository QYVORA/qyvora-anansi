<div align="center">
  <br/>

  <pre style="color: #66B870; font-family: 'JetBrains Mono', monospace; font-weight: bold; line-height: 1.3; font-size: 0.85rem;">
             ;                  &              
           ;;                    ;&            
          ;;;                    ;;;           
     ;    ;;;                    ;;;    ;      
     ;;;  ;;;        ;   ;;      ;;;   ;;;     
     ;;;;  ;;;;   ;;; && ;;;   ;;;;   ;;;;     
      ;;;;   ;;;; ;;;;;;;;;; ;;;;    ;;;;      
        ;;;;;;;;; ;;;;;;;;;;;;;;;; ;;;;;;;;;    
            &;;;;;;;;;;;;$x;;;;;;;;;;;;         
           ;;;;;;;;;;&&&+++&&&;;;;;;;;;;;       
     ;;;;;;;;;  ;;;&&+&&&&&+&&;;;  ;;;;;;;;;;  
     ;;;&    ;; ;;;&+&&&&&&&+&&;;; ;;    &;;;  
     ;;;   ;;;;  ;;;&&+&&&&&&+&;;; ;;;;   ;;;  
     ;;;   ;;;   ;;;;&&++&++++&&;;  ;;;   ;;;  
      ;;   ;;;    ;;;;;;;;;;;&&&&;  ;;;   ;;   
      ;;   ;;;      ;;;;;;;;;;;;;;  ;;;   ;;   
       ;   ;;;        ;;;;;;;;;;    ;;;   ;    
           &;;           ;;;;       ;;&        
             ;;           ;;       ;;;          
               ;                 ;             
  </pre>

  <h1 style="color: #FFFFFF; font-family: 'JetBrains Mono', monospace; font-weight: 700; font-size: 2.2rem; letter-spacing: -0.04em; margin: 0.5rem 0 0.2rem;">
    ANANSI CLI
  </h1>

  <p style="color: rgba(238, 240, 238, 0.70); font-family: 'JetBrains Mono', monospace; font-size: 0.95rem; margin-top: 0;">
    <strong style="color: #66B870;">Attack Surface Intelligence Engine</strong> — Terminal Edition
  </p>

  <br/>

  <p style="color: rgba(238, 240, 238, 0.40); font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;">
    Built by <a href="https://qyvora.netlify.app" style="color: #66B870; text-decoration: none; border-bottom: 1px dotted rgba(102, 184, 112, 0.3);">QYVORA OffSec</a>
    — Tamale, Ghana
  </p>

  <br/>

  <a href="https://github.com/QYVORA/qyvora-anansi-cli/releases">
    <img src="https://img.shields.io/github/v/release/QYVORA/qyvora-anansi-cli?style=flat&label=Release&color=66B870" alt="Release"/>
  </a>
  <a href="https://github.com/QYVORA/qyvora-anansi-cli/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-66B870?style=flat" alt="License"/>
  </a>
  <a href="https://go.dev">
    <img src="https://img.shields.io/badge/Go-1.22+-66B870?style=flat&logo=go" alt="Go"/>
  </a>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-66B870?style=flat" alt="Platform"/>

  <br/>
  <br/>

  <pre style="background: #0d0d0d; border: 1px solid rgba(102, 184, 112, 0.18); border-radius: 8px; padding: 1rem 1.5rem; display: inline-block; text-align: left; color: #EEF0EE; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; line-height: 1.6;">
<span style="color: #66B870;">anansi</span> target.com
<span style="color: #66B870;">anansi</span> target.com <span style="color: #60a5fa;">--verbose</span>
<span style="color: #66B870;">anansi</span> target.com <span style="color: #60a5fa;">--deep</span>
<span style="color: #66B870;">anansi</span> target.com <span style="color: #60a5fa;">--out</span> json &gt; results.json
<span style="color: #66B870;">anansi</span> target.com <span style="color: #60a5fa;">--modules</span> discovery,tls,takeover
  </pre>

  <br/>

  <blockquote style="border-left: 3px solid #66B870; color: rgba(238, 240, 238, 0.40); font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; padding: 0.5rem 1rem; text-align: left; max-width: 500px;">
    Only scan targets you own or have explicit written permission to test.
  </blockquote>
</div>

---

## What it does

ANANSI CLI is a terminal-first attack surface recon tool for pentesters and bug bounty hunters. Give it a domain — it runs a full six-phase intelligence pipeline and prints raw technical output you can act on immediately.

By default, ANANSI filters out the noise and only displays **found** assets (e.g., live subdomains, active HTTP/HTTPS hosts, successful TLS certificates, missing security headers on live URLs, exposed paths, and confirmed takeovers). This keeps your terminal clean. If you want to see all attempted checks, including dead subdomains, failed connections, and unchecked endpoints, simply enable the **verbose** flag (`-v`/`--verbose`).

| <span style="color:#66B870;">Phase</span> | <span style="color:#66B870;">Module</span> | <span style="color:#66B870;">What it finds</span> |
|-------|--------|---------------|
| 01 | **DISCOVERY** | Subdomains via crt.sh CT logs + DNS brute-force wordlist |
| 02 | **PROBE** | Live HTTP/HTTPS hosts — status codes, servers, redirect chains, titles |
| 03 | **TLS** | Certificate expiry, SANs, protocol version, cipher, self-signed detection |
| 04 | **HEADERS** | Missing security headers, CORS misconfigurations |
| 05 | **PATHS** | Exposed files — `.env`, `.git`, configs, admin panels, backups, API docs |
| 06 | **TECH-STACK** | Deep audit of detected platforms — version detection, WordPress plugins/themes, XML-RPC, user enumeration, config backups, known-vulnerable version matching |
| 07 | **TAKEOVER** | Dangling CNAMEs pointing to unclaimed cloud services |
| 08 | **OSINT** | Emails, phone numbers, employees, WHOIS registrant data |

---

## Performance & Architecture

- **Native Go DNS Resolver**: Bypasses slow `cgo`-blocked system lookups using pure Go goroutines.
- **Shared Connection Pool**: A single process-wide HTTP transport with keep-alives is reused across every phase and every module, so TCP + TLS handshakes happen once per host instead of once per request.
- **TTL DNS Cache**: Resolved subdomains are cached for 60s, so recursive/mutation/TLS-SAN phases never re-query the resolver for the same name.
- **Fixed Worker Pools**: Paths, discovery, probe, and techstack all run on fixed worker pools (one goroutine per `--threads`, jobs pulled from a channel). No goroutine-per-job churn — even an 8,000+ rule path sweep stays at stable concurrency.
- **Concurrent Probing**: HTTP Probes, TLS analyses, and Security Header checks are fully parallelized.
- **Smart Takeover Filtering**: Targets only subdomains with verified dead CNAME records.
- **Parallel Exposed Path Probing**: Custom 404 baselines fetched concurrently; the deep-audit module adds a soft-404 baseline so catch-all servers don't produce false positives.
- **Version reuse**: the tech-stack module reads CMS versions from generator meta tags and static-asset query strings already present in the homepage body, and discovers WordPress plugins from the same body — minimising extra requests.
- **robots.txt mining**: every live host's `robots.txt` Allow/Disallow entries are turned into extra path probes, surfacing intentionally-hidden directories for one extra request per host.

## Tech-Stack Deep Audit

When a host is fingerprinted as **WordPress, Drupal, Joomla, Magento, Ghost, Moodle, MediaWiki, Laravel**, or another platform, ANANSI descends that stack instead of stopping at the surface:

- **Version detection** — generator meta tags, `/wp-links-opml.php`, `/feed/`, `/CHANGELOG.txt`, `joomla.xml`, `/magento_version`, MediaWiki `/api.php` siteinfo, Moodle `/login/index.php`, and static-asset `?ver=` strings.
- **WordPress plugin/theme enumeration** — plugins are discovered from the homepage body and their stable versions read from `readme.txt`; Drupal modules, Joomla components, and MediaWiki extensions are enumerated the same way.
- **Stack-specific probes** — `/xmlrpc.php`, `/?author=1` and REST user enumeration, `debug.log`, config backups (`wp-config.php.bak`, `settings.php.bak`, `configuration.php.bak`), Magento `app/etc/env.php`, Ghost admin API, Laravel Telescope/Horizon/Ignition RCE (CVE-2021-3129), MediaWiki `LocalSettings.php`, directory listings, login/admin panels.
- **Known-vulnerable version matching** — detected versions are matched against a curated, CVE-backed table (`wordlists/tech/vulns.txt`) covering WordPress core, Drupal (Drupalgeddon), Joomla, Magento, Ghost, MediaWiki, Moodle, and high-value WordPress plugins such as Elementor, WP File Manager, Duplicator, Contact Form 7, Revolution Slider, and WooCommerce.

Add your own fingerprints, path rules, and version ranges by editing the files under `wordlists/tech/`.

---

## Install

### Option 1 — Download binary (no Go required)

```bash
# Linux x86_64
curl -L https://github.com/QYVORA/qyvora-anansi-cli/releases/latest/download/anansi-linux-amd64 -o anansi
chmod +x anansi
sudo mv anansi /usr/local/bin/

# Linux arm64 (Raspberry Pi, etc.)
curl -L https://github.com/QYVORA/qyvora-anansi-cli/releases/latest/download/anansi-linux-arm64 -o anansi
chmod +x anansi
sudo mv anansi /usr/local/bin/

# macOS (Apple Silicon)
curl -L https://github.com/QYVORA/qyvora-anansi-cli/releases/latest/download/anansi-macos-arm64 -o anansi
chmod +x anansi
sudo mv anansi /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/QYVORA/qyvora-anansi-cli/releases/latest/download/anansi-macos-amd64 -o anansi
chmod +x anansi
sudo mv anansi /usr/local/bin/
```

### Option 2 — Build from source (automated)

**Requirements:** Go 1.22+ and active internet connection.

```bash
git clone https://github.com/QYVORA/qyvora-anansi-cli
cd qyvora-anansi-cli
./install.sh
```

The installer verifies your dependencies, downloads packages, builds the stripped binary, and configures it in your environment path automatically. The binary has **zero runtime dependencies**.

---

## Usage

```bash
# Clean scan — only show found assets (default)
anansi target.com

# Recursive subdomain brute-force on resolved subdomains
anansi target.com -r

# Verbose scan — show all found and not-found outputs
anansi target.com -v

# Subdomain mutation scan
anansi target.com -m

# Scan alternative ports (default: 80,443)
anansi target.com -p 80,443,8080,8443

# Rate limit with delay in milliseconds
anansi target.com --delay 100

# Deep scan — larger wordlist, extended path rules
anansi target.com --deep

# Run specific modules
anansi target.com --modules discovery,probe,takeover

# Custom per-request timeout (default: 5s)
anansi target.com --timeout 10

# Configure concurrent thread pool (default: 50)
anansi target.com --threads 100

# JSON output
anansi target.com --out json > results.json
anansi target.com --out json | jq '.Findings[] | select(.Severity == "CRITICAL")'

# Markdown output
anansi target.com --out markdown > recon.md

# HTML output — premium dark mode report
anansi target.com --out html > report.html
```

### Flags

| <span style="color:#66B870;">Flag</span> | <span style="color:#66B870;">Shorthand</span> | <span style="color:#66B870;">Default</span> | <span style="color:#66B870;">Description</span> |
|------|-----------|---------|-------------|
| `--recursive` | `-r` | false | Enable recursive subdomain brute-forcing on resolved subdomains |
| `--verbose` | `-v` | false | Enable verbose output (shows all found and not found/failed assets) |
| `--mutate` | `-m` | false | Enable subdomain mutation brute-forcing based on resolved prefixes |
| `--ports` | `-p` | 80,443 | Alternative ports to probe (comma-separated list) |
| `--delay` | | 0 | Delay between requests in milliseconds for rate limiting |
| `--deep` | | false | Larger subdomain wordlist + more path probing rules |
| `--out` | | terminal | Output format: `terminal` \| `json` \| `markdown` \| `html` |
| `--timeout` | | 5 | Per-request timeout in seconds |
| `--threads` | `-t` | 100 | Number of concurrent threads to use for scanning |
| `--stealth` | | false | Enable stealth mode: random User-Agent, jitter, skip crt.sh, reduce noise |
| `--modules` | | all | Comma-separated list of modules to run |

### Module names for `--modules`

`discovery` `probe` `tls` `headers` `paths` `tech` `takeover` `osint`

---

## Output

<div align="center">
  <pre style="background: #0d0d0d; border: 1px solid rgba(102, 184, 112, 0.18); border-radius: 8px; padding: 1rem 1.5rem; display: inline-block; text-align: left; color: #EEF0EE; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; line-height: 1.5;">
  <span style="color: #66B870;">┌─────────────────────────────────────────────────────────┐</span>
  <span style="color: #66B870;">│</span>  ANANSI  Attack Surface Intelligence Engine             <span style="color: #66B870;">│</span>
  <span style="color: #66B870;">│</span>  TARGET  target.com                                     <span style="color: #66B870;">│</span>
  <span style="color: #66B870;">│</span>  TIME    2025-06-01 14:22:01 UTC                        <span style="color: #66B870;">│</span>
  <span style="color: #66B870;">│</span>  BY      QYVORA OffSec // qyvora.netlify.app            <span style="color: #66B870;">│</span>
  <span style="color: #66B870;">└─────────────────────────────────────────────────────────┘</span>

  <span style="color: #66B870;">══ PHASE 01 ── DISCOVERY</span> <span style="color: rgba(238, 240, 238, 0.40);">// subdomain enumeration + DNS resolution</span>
  <span style="color: rgba(238, 240, 238, 0.40);">────────────────────────────────────────────────────────────────</span>
  sources: crt.sh=12  wordlist=3  san=2

  api.target.com              104.21.44.12    crt.sh    <span style="color: #66B870;">LIVE</span>
  dev.target.com              104.21.44.13    crt.sh    <span style="color: #66B870;">LIVE</span>
  old.target.com              —               wordlist  DEAD
                              CNAME → target.herokuapp.com

  <span style="color: #66B870;">══ PHASE 05 ── PATHS</span> <span style="color: rgba(238, 240, 238, 0.40);">// exposed endpoint + file detection</span>
  <span style="color: rgba(238, 240, 238, 0.40);">────────────────────────────────────────────────────────────────</span>

  [CRITICAL] Exposed .env File
  ASSET:     https://api.target.com/.env
  FIX:       Restrict or remove /.env from public access.

  <span style="color: #66B870;">══ PHASE 06 ── TAKEOVER</span> <span style="color: rgba(238, 240, 238, 0.40);">// dangling CNAME detection</span>
  <span style="color: rgba(238, 240, 238, 0.40);">────────────────────────────────────────────────────────────────</span>

  [CRITICAL] Subdomain Takeover — Heroku
  ASSET:     old.target.com
  FIX:       Remove the dangling CNAME or claim the Heroku resource.

  <span style="color: #66B870;">══ SUMMARY</span> <span style="color: rgba(238, 240, 238, 0.40);">──────────────────────────────────────────────────────</span>
  target      target.com
  duration    1m43s
  subdomains  17 discovered, 11 live
  risk score  74/100

  findings    CRIT:3  HIGH:7  MED:4  LOW:6  INFO:2
  </pre>
</div>

---

## Project structure

```
anansi-cli/
├── main.go                      # Entry point
├── go.mod                       # Go module + dependencies
├── cmd/
│   └── root.go                  # CLI command, flags, phase orchestration
└── internal/
    ├── output/
    │   ├── types.go             # Shared data structures
    │   └── terminal.go          # Terminal/JSON/HTML/Markdown renderer
    ├── discovery/
    │   └── discovery.go         # crt.sh + DNS brute-force enumeration
    ├── probe/
    │   └── probe.go             # HTTP/HTTPS surface probing
    ├── tls/
    │   └── tls.go               # TLS certificate analysis + SAN discovery
    ├── headers/
    │   └── headers.go           # Security header audit + CORS check
    ├── paths/
    │   └── paths.go             # Exposed path + file detection
    ├── techstack/
    │   └── techstack.go         # Deep CMS/framework audit + CVE version matching
    ├── takeover/
    │   └── takeover.go          # Subdomain takeover detection
    ├── httpclient/
    │   └── httpclient.go        # Shared connection-pooled HTTP client
    └── dnscache/
        └── dnscache.go          # TTL-based DNS resolver cache
```

---

## Why

The pentesting and bug bounty community runs on Linux terminals. Tools should be single binaries that do one thing well and get out of the way. No web UI, no cloud account, no API key required.

ANANSI CLI is the portable companion to the full ANANSI platform — the API-powered attack surface intelligence service built into the QYVORA OffSec ecosystem. Same detection logic. Same output philosophy. CLI is for your laptop. The API is for your pipeline.

---

## Legal

Only scan targets you own or have explicit written authorization to test. Unauthorized scanning is illegal in most jurisdictions. QYVORA OffSec accepts no responsibility for misuse of this tool.

---

## License

MIT — fork it, extend it, integrate it. Attribution appreciated.

---

## Contributing

PRs welcome. Open an issue first for major changes. If you add a new path rule, takeover fingerprint, or detection module — open a PR. The goal is to keep the binary small and the signal high.

---

<div align="center">
  <p style="color: #66B870; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;">
    <strong>QYVORA // Tamale, Ghana</strong>
  </p>
  <p style="color: rgba(238, 240, 238, 0.40); font-family: 'JetBrains Mono', monospace; font-size: 0.7rem;">
    Cybersecurity in Africa is booming. We are building the people behind it.
  </p>
</div>
