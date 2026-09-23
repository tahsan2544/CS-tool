# CS Tools

<div align="center">

### 🔧 Comprehensive Website Measurement & Analysis Toolkit

**18 specialized tools. One unified CLI. Complete website analysis.**

![Python](https://img.shields.io/badge/Python-3.7%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-4C1?style=for-the-badge)
![Tools](https://img.shields.io/badge/Tools-18-FF6B6B?style=for-the-badge)
![Lines](https://img.shields.io/badge/Code-71%2C666%20lines-FFA500?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Stable-brightgreen?style=for-the-badge)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Available Tools](#-available-tools)
- [Usage Examples](#-usage-examples)
- [Full Scan](#-full-scan)
- [Export Formats](#-export-formats)
- [Tool Details](#-tool-details)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

CS Tools is a unified suite of **18 specialized tools** for analyzing websites from every angle. Whether you're a developer, security researcher, SEO specialist, or system administrator, CS Tools provides everything you need to measure, audit, and optimize any website.

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

# Run ALL 18 tools at once
python cstools.py scan -u https://example.com --export all
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

## 🛠️ Available Tools (18)

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

Run **ALL 18 tools** on a single URL with one command:

```bash
python cstools.py scan -u https://example.com --export all
```

### What the Scan Does

```
[1/18]  Running SEO Analysis...
[2/18]  Running Security Analysis...
[3/18]  Running Performance Analysis...
[4/18]  Running Uptime Check...
[5/18]  Running Mobile Analysis...
[6/18]  Running Content Analysis...
[7/18]  Running Network Diagnostics...
[8/18]  Running Accessibility Analysis...
[9/18]  Running Image Analysis...
[10/18] Running API Analysis...
[11/18] Running Video Analysis...
[12/18] Running Schema Analysis...
[13/18] Running Email Deliverability...
[14/18] Running Sitemap & Crawlability...
[15/18] Running HTML Validation...
[16/18] Running CDN Analysis...
[17/18] Running Cookie Privacy...
[18/18] Running Load Testing...

==========================================
         COMBINED SCAN RESULTS
==========================================
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

**Scoring:** 0-100 with A-F grades and category breakdowns

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
# Increase timeout
python cstools.py seo -u https://example.com -t 60
```

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

Contributions are welcome! Here's how:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup

```bash
git clone https://github.com/tahsan2544/CS-tool.git
cd CS-tool
pip install -r requirements.txt
```

### Adding a New Tool

1. Create a new directory: `YourTool/`
2. Add `yourtool.py`, `setup.py`, `requirements.txt`
3. Update `cstools.py` with the new tool
4. Update `README.md`

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**tahsan2544**

- GitHub: [@tahsan2544](https://github.com/tahsan2544)
- Repository: [CS-Tool](https://github.com/tahsan2544/CS-tool)

---

<div align="center">

**⭐ Star this repo if you find it useful!**

Made with ❤️ for the web development community

</div>
