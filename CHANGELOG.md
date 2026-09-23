# Changelog

All notable changes to CS Tools are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/) where practical; individual tools keep their own `VERSION` strings.

## [1.1.0] — tool upgrades + professional repo

### Added
- **UpgradeAdvisor** (`upgrade` command): weighted overall site rating, prioritized what-to-upgrade roadmap, quick wins vs biggest moves, JSON/HTML export
- `html`, `cdn`, `cookies` commands wired into the unified CLI
- Scan extended to 17 analysis tools (HTML, CDN, Cookie steps)
- Professional repo scaffolding: GitHub Actions CI, issue/PR templates, CONTRIBUTING.md, SECURITY.md, CHANGELOG.md, pyproject.toml
- README: 19-tool catalog, Upgrade Roadmap section, repository layout

### Upgraded tools
| Tool | From → To | Highlights |
|------|-----------|------------|
| ImageAnalyzer | 2.0 → **3.0** | Intrinsic dimension vs CSS, CDN transform params, LCP hero preload, ≥2000px resize hints |
| APIAnalyzer | 2.0 → **3.0** | OpenAPI/Swagger probe, GraphQL endpoint signals, API version headers, RateLimit headers |
| VideoAnalyzer | 2.0 → **3.0** | twitter:player, VideoObject contentUrl/embedUrl, preload/poster, HLS/DASH source types |
| SchemaAnalyzer | 1.0 → **2.0** | FAQPage, BreadcrumbList, HowTo, VideoObject, speakable, @id/sameAs graph |
| EmailAnalyzer | 1.0 → **2.0** | DANE TLSA on MX hosts (MTA-STS/TLS-RPT already present) |
| SitemapAnalyzer | 1.0 → **2.0** | News namespace, image/video tags, lastmod freshness, hreflang alternates |
| CDNAnalyzer | 1.0 → **2.0** | Cache-Control deep parse, Age HIT evidence, ETag/Last-Modified, Vary, Brotli, edge trace headers |
| CookieAnalyzer | 1.0 → **2.0** | SameSite=None+Secure, CHIPS/Partitioned, long-lived cookies, 1P/3P session split, consent banner signals |

### Fixed
- SchemaAnalyzer crash: `colors.dim` string called as a function
- SecurityChecker false FAIL on valid SSL certificates (`CERT_NONE` returned empty peer cert)
- SecurityChecker false positive on Weak SSL Protocols (now real TLS handshakes)
- Security score calibration: informational checks contribute points; risk index no longer saturates instantly
- UpgradeAdvisor `Fore.DIM` → `Style.DIM`
- Scan step counters corrected (`[N/17]`)
- setup.py repository URL corrected (`CS-tool`)

## [1.0.0] — initial public release

### Added
- Unified CLI `cstools.py` with 18 analysis tools
- LoadStorm, SEOChecker, SecurityChecker, PerfAnalyzer, UptimeChecker
- MobileAnalyzer, ContentAnalyzer, NetworkAnalyzer, AccessibilityAnalyzer
- ImageAnalyzer, APIAnalyzer, VideoAnalyzer, SchemaAnalyzer
- EmailAnalyzer, SitemapAnalyzer, HTMLValidator, CDNAnalyzer, CookieAnalyzer
- Per-tool `setup.py` + `requirements.txt`, MIT license, root README
