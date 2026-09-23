# CS Tools

**Comprehensive Website Measurement & Analysis Toolkit**

A unified suite of 18 specialized tools for analyzing websites from every angle — performance, security, SEO, accessibility, networking, content, and more.

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Tools](https://img.shields.io/badge/Tools-18-brightgreen)
![Lines](https://img.shields.io/badge/Code-70%2C000%2B%20lines-orange)

## Installation

```bash
git clone https://github.com/tahsan2544/CS-Tools.git
cd CS-Tools
pip install -r requirements.txt
```

## Usage

```bash
# Run a single tool
python cstools.py seo -u https://example.com
python cstools.py security -u https://example.com
python cstools.py perf -u https://example.com --export all

# Run ALL tools on a URL
python cstools.py scan -u https://example.com --export all

# List all available tools
python cstools.py list
```

## Available Tools (18)

| # | Tool | Command | Description |
|---|------|---------|-------------|
| 1 | **LoadStorm** | `loadstorm` | Load & stress testing with 20+ attack patterns |
| 2 | **SEOChecker** | `seo` | Deep SEO analysis with search visibility scoring |
| 3 | **SecurityChecker** | `security` | Comprehensive security audit with CVSS scoring |
| 4 | **PerfAnalyzer** | `perf` | Core Web Vitals, Lighthouse simulation, optimization |
| 5 | **UptimeChecker** | `uptime` | Multi-protocol monitoring with SLO tracking |
| 6 | **MobileAnalyzer** | `mobile` | Mobile-friendliness, PWA, touch optimization |
| 7 | **ContentAnalyzer** | `content` | Content quality, readability, multilingual support |
| 8 | **NetworkAnalyzer** | `network` | DNS, TCP, SSL, CDN, latency, port scanning |
| 9 | **AccessibilityAnalyzer** | `access` | WCAG 2.1/2.2 compliance, screen reader simulation |
| 10 | **ImageAnalyzer** | `image` | Image optimization, format, lazy loading |
| 11 | **APIAnalyzer** | `api` | REST/GraphQL API testing, auth, rate limits |
| 12 | **VideoAnalyzer** | `video` | Video SEO, accessibility, streaming analysis |
| 13 | **SchemaAnalyzer** | `schema` | Structured data, JSON-LD, Schema.org validation |
| 14 | **EmailAnalyzer** | `email` | SPF, DKIM, DMARC, MX, BIMI deliverability |
| 15 | **SitemapAnalyzer** | `sitemap` | robots.txt, sitemaps, crawlability, indexability |
| 16 | **HTMLValidator** | `html` | HTML standards, semantic, best practices validation |
| 17 | **CDNAnalyzer** | `cdn` | CDN detection, caching, edge performance |
| 18 | **CookieAnalyzer** | `cookies` | Cookie privacy, GDPR, CCPA, consent management |

## Export Formats

All tools support exporting results:

```bash
python cstools.py seo -u https://example.com --export all    # JSON + CSV + HTML
python cstools.py seo -u https://example.com --export json   # JSON only
python cstools.py seo -u https://example.com --export csv    # CSV only
python cstools.py seo -u https://example.com --export html   # HTML only
```

## Full Scan Example

```bash
python cstools.py scan -u https://example.com --export all
```

Runs all 18 tools sequentially and produces a combined summary report.

## Requirements

- Python 3.7+
- See `requirements.txt` for dependencies

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**tahsan2544** - [GitHub](https://github.com/tahsan2544)
