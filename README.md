# CS-Tool

<div align="center">

### 🔧 Comprehensive Website Measurement & Analysis Toolkit

**19 specialized tools. One unified CLI. Complete website analysis.**

![Python](https://img.shields.io/badge/Python-3.7%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-1.3.0-FF6B6B?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-4C1?style=for-the-badge)
![Tools](https://img.shields.io/badge/Tools-19-FF6B6B?style=for-the-badge)
![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)
![Status](https://img.shields.io/badge/Status-Stable-brightgreen?style=for-the-badge)

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://www.buymeacoffee.com/tahsan2544)
[![Star on GitHub](https://img.shields.io/github/stars/tahsan2544/CS-tool?style=for-the-badge&logo=github)](https://github.com/tahsan2544/CS-tool)

**[Quick Start](#-quick-start)** · **[All Tools](#️-available-tools-19)** · **[Scoring](#-how-scoring-works)** · **[Full Scan](#-full-scan)** · **[Upgrade Roadmap](#️-upgrade-roadmap)** · **[Contributing](#-contributing)**

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Available Tools](#-available-tools)
- [Usage Examples](#-usage-examples)
- [Full Scan](#-full-scan)
- [How Scoring Works](#-how-scoring-works)
- [Upgrade Roadmap](#️-upgrade-roadmap)
- [Export Formats](#-export-formats)
- [Reliability](#-reliability--timeouts)
- [Tool Details](#-tool-details)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [Changelog](CHANGELOG.md)
- [Security Policy](SECURITY.md)
- [License](#-license)

---

## 🎯 Overview

CS-Tool is a unified suite of **19 specialized tools** for analyzing websites from every angle. Whether you're a developer, security researcher, SEO specialist, or system administrator, CS-Tool provides everything you need to measure, audit, and optimize any website.

Every full `scan` ends with a weighted **overall site rating** (0–100 + letter grade) and a prioritized **what-to-do** list drawn from live tool issues — no second command required.

### What Can You Analyze?

| Domain | Tools | What You Get |
|--------|-------|--------------|
| ⚡ **Performance** | PerfAnalyzer, LoadStorm | Core Web Vitals, stress testing, optimization |
| 🔒 **Security** | SecurityChecker | Vulnerability detection, CVSS scoring, compliance |
| 🔍 **SEO** | SEOChecker, SchemaAnalyzer, SitemapAnalyzer | Search visibility, structured data, crawlability |
| 📱 **Mobile** | MobileAnalyzer | PWA detection, touch optimization, responsive design |
| ♿ **Accessibility** | AccessibilityAnalyzer | WCAG 2.1/2.2 compliance, screen reader simulation |
| 🌐 **Network** | NetworkAnalyzer, CDNAnalyzer | DNS, SSL, CDN, latency, port scanning |
| 📝 **Content** | ContentAnalyzer, HTMLValidator | Readability, quality, HTML validation |
| 🖼️ **Media** | ImageAnalyzer, VideoAnalyzer | Image/video optimization, SEO, accessibility |
| 📧 **Email** | EmailAnalyzer | SPF, DKIM, DMARC, deliverability |
| 🍪 **Privacy** | CookieAnalyzer | GDPR, CCPA, consent management |
| 🔌 **API** | APIAnalyzer | REST/GraphQL testing, authentication |
| 📊 **Monitoring** | UptimeChecker | Multi-protocol monitoring, SLO tracking |
| 🗺️ **Upgrade Planning** | UpgradeAdvisor | Prioritized what-to-upgrade roadmap for a better rating |

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/tahsan2544/CS-tool.git
cd CS-tool
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run Your First Analysis

```bash
# Analyze SEO of any website
python cstools.py seo -u https://example.com

# Run a full security audit
python cstools.py security -u https://example.com

# Run all analysis tools at once (ends with overall rating + what-to-do)
python cstools.py scan -u https://example.com --export all

# Get a prioritized upgrade roadmap (what to fix for a better rating)
python cstools.py upgrade -u https://example.com --export all
```

### One-line install (from GitHub)

```bash
pip install "git+https://github.com/tahsan2544/CS-tool.git" && cstools list
```

---

## 📁 Repository Layout

```
CS-tool/
├── cstools.py              # Unified CLI (entry point)
├── README.md               # This file
├── CHANGELOG.md            # Release history
├── CONTRIBUTING.md         # How to add/upgrade tools
├── SECURITY.md             # Vulnerability reporting
├── LICENSE                 # MIT
├── pyproject.toml          # Modern packaging
├── setup.py                # Setuptools packaging
├── requirements.txt        # Runtime dependencies
├── .github/
│   ├── workflows/ci.yml    # Compile + smoke-test CI
│   ├── ISSUE_TEMPLATE/     # Bug / feature templates
│   └── PULL_REQUEST_TEMPLATE.md
└── <ToolName>/             # One directory per tool (19)
    ├── <toolname>.py       # Main analyzer
    ├── setup.py
    └── requirements.txt
```

---

## 📦 Installation

### Prerequisites

- **Python 3.7 or higher** ([Download Python](https://www.python.org/downloads/))
- **pip** (comes with Python)
- **Git** (optional, for cloning)

### Method 1: Clone from GitHub (Recommended)

```bash
git clone https://github.com/tahsan2544/CS-tool.git
cd CS-tool
pip install -r requirements.txt
```

### Method 2: Download ZIP

1. Download the ZIP from [GitHub](https://github.com/tahsan2544/CS-tool)
2. Extract the folder
3. Open terminal in the folder
4. Run: `pip install -r requirements.txt`

### Method 3: Install as Package

```bash
pip install .
```

Then use `cstools` command directly:

```bash
cstools seo -u https://example.com
```

---

## 🛠️ Available Tools (19)

| # | Tool | Command | Category | Description |
|---|------|---------|----------|-------------|
| 1 | **LoadStorm** | `loadstorm` | ⚡ Performance | Load & stress testing with 20+ attack patterns |
| 2 | **SEOChecker** | `seo` | 🔍 SEO | Deep SEO analysis with search visibility scoring |
| 3 | **SecurityChecker** | `security` | 🔒 Security | Comprehensive security audit with CVSS scoring |
| 4 | **PerfAnalyzer** | `perf` | ⚡ Performance | Core Web Vitals, Lighthouse simulation, optimization |
| 5 | **UptimeChecker** | `uptime` | 📊 Monitoring | Multi-protocol monitoring with SLO tracking |
| 6 | **MobileAnalyzer** | `mobile` | 📱 Mobile | Mobile-friendliness, PWA, touch optimization |
| 7 | **ContentAnalyzer** | `content` | 📝 Content | Content quality, readability, multilingual support |
| 8 | **NetworkAnalyzer** | `network` | 🌐 Network | DNS, TCP, SSL, CDN, latency, port scanning |
| 9 | **AccessibilityAnalyzer** | `access` | ♿ Accessibility | WCAG 2.1/2.2 compliance, screen reader simulation |
| 10 | **ImageAnalyzer** | `image` | 🖼️ Media | Image optimization, format, lazy loading |
| 11 | **APIAnalyzer** | `api` | 🔌 API | REST/GraphQL API testing, auth, rate limits |
| 12 | **VideoAnalyzer** | `video` | 🎬 Media | Video SEO, accessibility, streaming analysis |
| 13 | **SchemaAnalyzer** | `schema` | 🔍 SEO | Structured data, JSON-LD, Schema.org validation |
| 14 | **EmailAnalyzer** | `email` | 📧 Email | SPF, DKIM, DMARC, MX, BIMI deliverability |
| 15 | **SitemapAnalyzer** | `sitemap` | 🔍 SEO | robots.txt, sitemaps, crawlability, indexability |
| 16 | **HTMLValidator** | `html` | 📝 Content | HTML standards, semantic, best practices validation |
| 17 | **CDNAnalyzer** | `cdn` | 🌐 Network | CDN detection, caching, edge performance |
| 18 | **CookieAnalyzer** | `cookies` | 🍪 Privacy | Cookie privacy, GDPR, CCPA, consent management |
| 19 | **UpgradeAdvisor** | `upgrade` | 🗺️ Upgrade Planning | Prioritized what-to-upgrade roadmap for better rating |

CLI groups (`cstools list`):

| Group | Commands |
|-------|----------|
| **meta** | `scan` · `upgrade` · `list` |
| **core** | `seo` · `security` · `perf` · `uptime` · `loadstorm` |
| **content** | `content` · `html` · `schema` · `sitemap` · `image` · `video` |
| **platform** | `mobile` · `access` · `network` · `cdn` · `api` · `email` · `cookies` |

---

## 💡 Usage Examples

### Basic Usage

```bash
# Show all available commands
python cstools.py --help

# List all tools
python cstools.py list
```

### Single Tool Analysis

```bash
# 🔍 SEO Analysis
python cstools.py seo -u https://example.com

# 🔒 Security Audit
python cstools.py security -u https://example.com

# ⚡ Performance Analysis
python cstools.py perf -u https://example.com

# 📱 Mobile-Friendliness Check
python cstools.py mobile -u https://example.com

# ♿ Accessibility Compliance (WCAG AA)
python cstools.py access -u https://example.com --level AA

# 🌐 Network Diagnostics
python cstools.py network -u https://example.com

# 📝 Content Quality
python cstools.py content -u https://example.com

# 📧 Email Deliverability
python cstools.py email -u example.com

# 🔌 API Testing
python cstools.py api -u https://api.example.com --auth-type bearer --api-key YOUR_KEY

# 🍪 Cookie Privacy (GDPR/CCPA)
python cstools.py cookies -u https://example.com

# 🗺️ Upgrade Roadmap (what to fix for a better rating)
python cstools.py upgrade -u https://example.com --export all

# 🗺️ Upgrade Roadmap — only specific areas
python cstools.py upgrade -u https://example.com --only security seo content
```

### Advanced Usage

```bash
# Custom timeout
python cstools.py seo -u https://example.com -t 30

# Export results to all formats
python cstools.py security -u https://example.com --export all

# Export to specific format
python cstools.py perf -u https://example.com --export html

# Disable colors (for piping to file)
python cstools.py seo -u https://example.com --no-color > results.txt

# Verbose output
python cstools.py network -u https://example.com -v

# Load testing with 100 concurrent users
python cstools.py loadstorm -u https://example.com -c 100 -d 30

# Accessibility at AAA level
python cstools.py access -u https://example.com --level AAA
```

---

## 🔍 Full Scan

Run **all analysis tools** (17 scanners) on a single URL with one command:

```bash
python cstools.py scan -u https://example.com --export all
```

### What the Scan Does

```
[1/17]  Running SEO Analysis...
[2/17]  Running Security Analysis...
[3/17]  Running Performance Analysis...
[4/17]  Running Uptime Check...
[5/17]  Running Mobile Analysis...
[6/17]  Running Content Analysis...
[7/17]  Running Network Diagnostics...
[8/17]  Running Accessibility Analysis...
[9/17]  Running Image Analysis...
[10/17] Running API Analysis...
[11/17] Running Video Analysis...
[12/17] Running Schema Analysis...
[13/17] Running Email Deliverability...
[14/17] Running Sitemap & Crawlability...
[15/17] Running HTML Validation...
[16/17] Running CDN Analysis...
[17/17] Running Cookie Privacy...

======================================================================
  COMBINED SCAN RESULTS
======================================================================
  Target:   https://tahsan-portfolio.ai.studio/
  Time:     2026-09-24 16:31:27
──────────────────────────────────────────────────────────────────────

  SEO Analysis
    Score: 35.7/100
    Grade: D
    Status: Completed
  ...

  Network Diagnostics
    Score: 48.5/100
    Grade: D
    Status: Completed
  ...

══════════════════════════════════════════════════════════════════════
  OVERALL SITE RATING
══════════════════════════════════════════════════════════════════════
  Target:   https://tahsan-portfolio.ai.studio/
  Coverage: 16/16 tools scored · weight 100/100

  Overall:   48.3 / 100   Grade F
           ███████████████████░░░░░░░░░░░░░░░░░░░░░  48%
  Distance to A (90): 41.7 points

  WHAT TO DO (prioritized — biggest rating gain first)
──────────────────────────────────────────────────────────────────────
  #   Area           Now Grade    Gain  Effort     Pri  First fix
  ──────────────────────────────────────────────────────────────────
  1   security     17.0     F  +  9.5  High     2.38  Missing X-Frame-Options FAIL
  2   perf         72.0     C  +  2.3  Low      2.30  close score gap to 90
  3   seo          35.7     F  +  7.1  High     1.77  Add an H1 tag
  ...

    QUICK WINS (do these first)
    + perf: 72 → +2.3 overall if brought to 90
    + access: 74 → +1.1 overall if brought to 90
    ...

    BIGGEST RATING MOVES
    ▸ security: +9.5 overall  (now 17, High effort)
    ▸ seo: +7.1 overall  (now 36, High effort)
    ...

    POTENTIAL: fixing the list above ≈ +42.1 weighted points
    Projected overall if fixed: 77.8 (C)
    Order matters: work top-down in the table. No second command needed.
```

> Sample above is a **live run** against `https://tahsan-portfolio.ai.studio/` (CS-Tool 1.3.0). Scores change with the target.

Notes:

- **LoadStorm is intentionally excluded** from `scan` (it generates traffic). Run it separately: `cstools loadstorm`.
- **Email** is reported in the scorecard but is **not weighted** into the overall rating (SPF/DKIM depend on the mail host, not the site under test).
- Every tool score is printed as **`n/100`** after normalization (raw ratios like `201/563` or `65/130` are converted).
- SPA / client-rendered sites: tools analyze the **server HTML shell**. Empty `<div id="root">` content means SEO/content scores reflect SSR output only.

---

## ⚖️ How Scoring Works

### Normalization

Each tool emits a raw score in its own format. Before display and aggregation, `normalize_score_100` coerces it to **0–100**:

| Raw form | Example | Normalized |
|----------|---------|------------|
| Plain number | `72` | `72` |
| Decimal | `30.6` | `30.6` |
| Ratio | `201/563` | `35.7` |
| Network TOTAL | `65/130` | `50` |
| Percent-style | `85%` | `85` |

### Letter grades (overall rating)

| Score | Grade |
|------:|:-----:|
| ≥ 95 | A+ |
| ≥ 90 | A |
| ≥ 80 | B |
| ≥ 70 | C |
| ≥ 60 | D |
| < 60 | F |

Individual tools may print their own grade letter under their score (e.g. PerfAnalyzer `Grade: B` for 72). The **overall** grade always uses the table above.

### Weights (`SCORE_WEIGHTS`, sum = 100)

| Area | Weight | Area | Weight |
|------|-------:|------|-------:|
| seo | 13 | network | 5 |
| security | 13 | uptime | 4 |
| perf | 13 | image | 4 |
| mobile | 8 | api | 4 |
| content | 8 | sitemap | 4 |
| access | 7 | video | 3 |
| schema | 6 | html | 3 |
| | | cdn | 3 |
| | | cookies | 2 |
| | | **email** | **0** (reported, not weighted) |
| | | **Total** | **100** |

`overall = Σ (tool_score × weight) / 100` over tools that produced a score. Coverage shows **tools scored** and **weight covered** (e.g. `16/16 tools scored · weight 100/100`).

---

## 🗺️ Upgrade Roadmap

The `upgrade` command is the **"what should I improve"** section. It:

1. Runs the scoring tools and collects every score
2. Computes one **overall site rating** (weighted across tools)
3. Prints a **prioritized upgrade list** — biggest rating gain first
4. Separates **quick wins** (low effort) from **biggest moves** (plan these)
5. Projects your rating if you complete the roadmap

```bash
python cstools.py upgrade -u https://example.com --export all
```

**Sample output:**

```
  OVERALL SITE RATING
  48.3 / 100   Grade F
    Distance to A (90): 41.7 points

  WHAT TO UPGRADE (prioritized — biggest rating gain first)
  #   Upgrade area      Now   Gain Effort  Priority  Why
  1   security         17.0 +  9.5 High        2.38  Missing X-Frame-Options
  2   perf             72.0 +  2.3 Low         2.30  close score gap to 90
  ...
  QUICK WINS (low effort, do these first)
  BIGGEST RATING MOVES (plan these)
  POTENTIAL: projected rating → 77.8 (C)
```

---

## 📁 Export Formats

All tools support **4 export formats**:

| Format | Flag | Best For |
|--------|------|----------|
| **JSON** | `--export json` | Data processing, APIs, dashboards |
| **CSV** | `--export csv` | Spreadsheets, data analysis |
| **HTML** | `--export html` | Reports, sharing, viewing |
| **All** | `--export all` | Complete documentation |

### Examples

```bash
# Export to all formats
python cstools.py seo -u https://example.com --export all

# Export only HTML report
python cstools.py security -u https://example.com --export html

# Export only JSON for automation
python cstools.py perf -u https://example.com --export json
```

### Output Files

Exported files are saved with timestamps:

```
seo_report_20260923_143022.json
seo_report_20260923_143022.csv
seo_report_20260923_143022.html
```

Full `scan` JSON also includes `overall_rating`, `overall_grade`, `scored_tools`, `scores_normalized`, and `what_to_do`.

---

## 🛡️ Reliability & Timeouts

A hung sub-tool must not stall the whole scan. Guards in place:

| Guard | Behavior |
|-------|----------|
| **Per-tool timeout** | Every scan runner uses `_run_capture(..., timeout=180)`. On timeout the CLI keeps **partial stdout/stderr**, appends `[ERROR] tool timed out after 180s`, and continues (exit code 124). |
| **Unbuffered children** | Sub-processes run with `PYTHONUNBUFFERED=1` so pipe output is not block-buffered and lost on kill. |
| **NetworkAnalyzer budget** | Internal **100s** time budget (`run(max_seconds=100)`). Remaining phases are skipped with a warning; summary still prints `TOTAL n/m` from completed phases. Scan wrapper allows **150s** for network. |
| **Score fallbacks** | Headline patterns first (`Overall Score`, `Score: … Grade`, `TOTAL n/m`), then generic fallbacks — ANSI stripped before match. |
| **Display normalization** | Combined results always print `n/100` (never `65/130/100` or raw `201/563`). |

Typical full scan wall time on a healthy network: **~3–4 minutes** (network phase ~100s of that).

---

## 📊 Tool Details

### ⚡ LoadStorm — Load & Stress Testing

Simulate traffic to test your website's limits.

```bash
python cstools.py loadstorm -u https://example.com -c 100 -d 60
```

**Features:**
- 20+ attack patterns (ramp, spike, stress, slowloris, etc.)
- WebSocket load testing
- HTTP/2 flood support
- Real-time dashboard with live statistics
- Response time histograms
- Error rate tracking

**Key Options:**
- `-c, --clients` — Number of concurrent users
- `-d, --duration` — Test duration in seconds
- `--pattern` — Attack pattern (ramp, spike, stress, etc.)

---

### 🔍 SEOChecker — Search Engine Optimization

Deep analysis of your website's SEO health.

```bash
python cstools.py seo -u https://example.com --export all
```

**Checks Include:**
- Meta tags (title, description, keywords)
- Heading hierarchy (H1-H6)
- Internal/external linking
- Image SEO (alt text, file names)
- Structured data (JSON-LD, Microdata)
- Core Web Vitals estimation
- Mobile-first indexing readiness
- Voice search optimization
- E-E-A-T signals
- Content quality index

**Scoring:** 0-100 with A-F grades and category breakdowns (raw final score may print as `201/563` → normalized to `35.7/100` in `scan`)

---

### 🔒 SecurityChecker — Security Audit

Comprehensive security analysis of your website.

```bash
python cstools.py security -u https://example.com
```

**Checks Include:**
- SSL/TLS configuration
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- Cookie security
- CORS configuration
- Vulnerability detection (XSS, SQLi, CSRF, etc.)
- Information disclosure
- OWASP Top 10 compliance
- NIST compliance
- API security testing
- Container/cloud detection

**Output:** CVSS-like scoring, risk heat map, remediation roadmap  
**Scan extraction:** prefers the headline `Overall Score: n/100` (not residual-risk subscores)

---

### ⚡ PerfAnalyzer — Performance Analysis

Measure and optimize your website's performance.

```bash
python cstools.py perf -u https://example.com -v
```

**Metrics Analyzed:**
- Core Web Vitals (LCP, CLS, INP, FCP, TTFB)
- Resource loading (CSS, JS, images, fonts)
- Caching configuration
- Compression (gzip, Brotli)
- HTTP/2 and HTTP/3 support
- Lighthouse score simulation
- PageSpeed Insights approximation
- Performance budget compliance

**Output:** ASCII waterfall, optimization priority matrix, budget dashboard  
**Scan extraction:** matches `Score: ███ 72/100` (bar meters and no-colon variants)

---

### 📱 MobileAnalyzer — Mobile Analysis

Ensure your website works perfectly on mobile devices.

```bash
python cstools.py mobile -u https://example.com
```

**Checks Include:**
- Viewport meta tag
- Responsive design detection
- Touch target sizes
- PWA (Progressive Web App) detection
- Service Worker analysis
- Mobile performance budgets
- Dark mode support
- Foldable device support

**Output:** Mobile readiness score, PWA capability score, optimization roadmap

---

### ♿ AccessibilityAnalyzer — Accessibility Compliance

Test your website against WCAG guidelines.

```bash
python cstools.py access -u https://example.com --level AA
```

**WCAG Levels Supported:**
- **A** — Basic accessibility
- **AA** — Standard compliance (recommended)
- **AAA** — Highest compliance

**Checks Include:**
- Text alternatives (alt text)
- Keyboard navigation
- Screen reader compatibility
- Color contrast
- ARIA attributes
- Cognitive accessibility
- Motor/visual/hearing accommodations

**Output:** WCAG compliance level, issue severity, remediation roadmap

---

### 🌐 NetworkAnalyzer — Network Diagnostics

Deep network analysis of your website.

```bash
python cstools.py network -u https://example.com
```

**Checks Include:**
- DNS records (A, AAAA, NS, MX, TXT, CNAME)
- TCP connection analysis
- SSL/TLS configuration
- CDN detection (27+ providers)
- Server technology fingerprinting
- Latency and routing analysis
- Port scanning (24 ports)
- Protocol support (WebSocket, FTP, SMTP, SSH)

**Output:** Network topology, security assessment, optimization recommendations  
**Time budget:** finishes within **100s** even if later phases are skipped; summary always includes `TOTAL n/m`

---

### 📧 EmailAnalyzer — Email Deliverability

Ensure your emails reach the inbox.

```bash
python cstools.py email -u example.com
```

**Checks Include:**
- MX records
- SPF record validation
- DKIM key detection
- DMARC policy analysis
- DNSSEC validation
- MTA-STS support
- BIMI (Brand Indicators)

**Output:** Email deliverability score, configuration recommendations  
**Note:** shown in the scan scorecard but **not weighted** into the overall site rating

---

### 🔌 APIAnalyzer — API Testing

Test and analyze REST and GraphQL APIs.

```bash
python cstools.py api -u https://api.example.com --auth-type bearer --api-key YOUR_KEY
```

**Checks Include:**
- Endpoint discovery
- HTTP method support
- Authentication (Bearer, API key, OAuth)
- Rate limiting detection
- Input validation
- Response quality
- Security headers
- Documentation quality

**Output:** API quality dashboard, security assessment, recommendations

---

### 🍪 CookieAnalyzer — Cookie Privacy

Ensure GDPR and CCPA compliance.

```bash
python cstools.py cookies -u https://example.com
```

**Checks Include:**
- Cookie inventory and classification
- Cookie security flags (Secure, HttpOnly, SameSite)
- Consent management detection
- GDPR compliance
- CCPA compliance
- Third-party cookie analysis

**Output:** Privacy compliance assessment, recommendations

---

### 🗺️ UpgradeAdvisor — What to Upgrade for a Better Rating

Aggregates scores from the other tools into one overall site rating and a prioritized upgrade roadmap.

```bash
python cstools.py upgrade -u https://example.com --export all

# Only specific areas
python cstools.py upgrade -u https://example.com --only security seo content
```

**What it does:**
- Runs the scoring tools and collects each score
- Computes a **weighted overall site rating** (0–100 + letter grade)
- Builds a **prioritized upgrade list** (biggest rating gain first)
- Splits items into **Quick Wins** (low effort) vs **Biggest Moves** (plan these)
- Shows estimated **+points** each fix contributes to the overall rating
- Projects your rating if the full roadmap is completed

**Output sections:**
- Overall site rating + distance to grade A
- Scorecard by tool (score, grade, status bar)
- Prioritized “What to Upgrade” table (Now / Gain / Effort / Priority / Why)
- Quick wins and biggest rating moves with sample issues
- Exportable JSON + HTML roadmap report

---

## 🔧 Troubleshooting

### Common Issues

**`ModuleNotFoundError: No module named 'requests'`**
```bash
pip install requests beautifulsoup4 colorama
```

**`command not found: python`**
```bash
# Try python3 instead
python3 cstools.py --help
```

**`Permission denied`**
```bash
chmod +x cstools.py
python cstools.py --help
```

**SSL Certificate Errors**
```bash
pip install --upgrade certifi
```

**Timeout Errors**
```bash
# Increase timeout for a single tool
python cstools.py seo -u https://example.com -t 60
```

**Scan says a tool timed out (`rc 124` / `[ERROR] tool timed out`)**
- The CLI kept partial output and continued; check that tool's section for a partial score or `?`.
- NetworkAnalyzer always finishes within its 100s budget and prints `TOTAL` even if phases were skipped.

**Overall rating lower than expected on a React/Vue SPA**
- `scan` analyzes the **server-rendered HTML**. Client-only content is invisible to SEO/content tools until you enable SSR/prerender or point the tools at a prerendered URL.

### Getting Help

```bash
# Show help for main CLI
python cstools.py --help

# Show help for specific tool
python cstools.py seo --help
python cstools.py loadstorm --help
```

---

## 🤝 Contributing

Full guidelines live in **[CONTRIBUTING.md](CONTRIBUTING.md)**.

Quick version:

1. Fork and create a feature branch (`git checkout -b feat/my-tool`)
2. Match existing tool layout (`YourTool/yourtool.py` + `setup.py` + `requirements.txt`)
3. Wire it into `cstools.py` (path, TOOLS, `cmd_*`, subparser, banner)
4. If the tool feeds `scan`, add a score pattern + `SCORE_WEIGHTS` entry (keep sum = 100) and a `normalize_score_100`-compatible final score line
5. `python -m py_compile` your files and smoke-test `--help` / `list`
6. Open a PR using the template

**Please read [SECURITY.md](SECURITY.md) before reporting vulnerabilities in this codebase.**

### Adding a New Tool

1. Create a new directory: `YourTool/`
2. Add `yourtool.py`, `setup.py`, `requirements.txt`
3. Update `cstools.py` with the new tool
4. Update `README.md` and `CHANGELOG.md`

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**tahsan2544**

- GitHub: [@tahsan2544](https://github.com/tahsan2544)
- Repository: [CS-Tool](https://github.com/tahsan2544/CS-tool)
- Changelog: [CHANGELOG.md](CHANGELOG.md)
- Security: [SECURITY.md](SECURITY.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)

---

<div align="center">

### If CS-Tool helps you, star the repo ⭐

[![Star History Chart](https://api.star-history.com/svg?repos=tahsan2544/CS-tool&type=Date)](https://star-history.com/#tahsan2544/CS-tool&Date)

**MIT License** · Built for the web development community

</div>
