# Changelog

All notable changes to CS-Tool are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/) where practical; individual tools keep their own `VERSION` strings.

## [1.3.0] — overall site rating + what-to-do at end of scan

### Added
- **End-of-scan `OVERALL SITE RATING`**: weighted 0–100 score across all 16 scored tools (`SCORE_WEIGHTS` sums to 100), letter grade, distance to A, coverage (tools scored + weight covered)
- **`WHAT TO DO` table** printed automatically at the end of `scan` (no second command): per-area gap to 90, weighted rating gain, effort, priority, first fix drawn from live tool issues
- Quick wins (Low effort first) + biggest rating moves + projected overall if the list is fixed
- Normalized every tool's raw score to /100 via `normalize_score_100` (handles `201/563`, decimals, percent)
- Scan JSON export now includes `overall_rating`, `overall_grade`, `scored_tools`, `scores_normalized`, `what_to_do`, and previously missing `html_*`/`cdn_*`/`cookies_*` score+grade fields

### Changed
- All 17 scan tool runners use `_run_capture` with a **180s timeout** (per-tool hangs no longer stall the whole scan; timed-out tools report rc 124)
- `UpgradeAdvisor` v1.0 → **v1.1**: same ANSI-stripping + real score patterns as the unified CLI; weights aligned to sum 100

### Fixed
- Score extraction strips ANSI and matches each tool's real final score/grade format (SEO ratio, bar meters, decimal composites, etc.)

### Bumped
- Package version `1.2.0` → `1.3.0` (setup.py, pyproject.toml)

## [1.2.0] — CS-Tool rebrand + CLI UI refresh

### Changed
- Project display name **CS Tools → CS-Tool** (`APP_NAME`, packaging descriptions, README title)
- New multi-color banner (brand box art, grouped command sections)
- Palette + helpers for consistent CLI chrome (`C`, `_rule`, `_tag`, `_cmd`, `_dim`)
- `list` command grouped by meta/core/content/platform with aligned tool columns
- `--help` epilog: examples + command groups + docs links
- Scan headers and combined-results frame restyled

### Bumped
- Package version `1.1.0` → `1.2.0` (setup.py, pyproject.toml)

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
- Unified CLI `cstools.py` with 18 analysis tools (originally released as CS Tools)
- LoadStorm, SEOChecker, SecurityChecker, PerfAnalyzer, UptimeChecker
- MobileAnalyzer, ContentAnalyzer, NetworkAnalyzer, AccessibilityAnalyzer
- ImageAnalyzer, APIAnalyzer, VideoAnalyzer, SchemaAnalyzer
- EmailAnalyzer, SitemapAnalyzer, HTMLValidator, CDNAnalyzer, CookieAnalyzer
- Per-tool `setup.py` + `requirements.txt`, MIT license, root README
