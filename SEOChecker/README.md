# SEOChecker v2.0

### Ultimate Website SEO Quality Analyzer

> Comprehensive SEO analysis with structured data, sitemap, robots.txt, broken links, readability, and more.

---

## Features

### Core Checks (v1.0)
- **SSL/HTTPS** - Security verification
- **Meta Tags** - Title, description, keywords, robots, canonical
- **Headings** - H1-H6 structure analysis
- **Images** - Alt text and size checks
- **Links** - Internal/external link analysis
- **Performance** - Page size, load time
- **Mobile** - Viewport meta tag check
- **Social** - Open Graph and Twitter Card tags
- **Content** - Word count, quality metrics

### New in v2.0
- **Structured Data** - JSON-LD and Microdata validation
- **XML Sitemap** - Sitemap detection and URL count
- **robots.txt** - Robots file validation
- **HTTPS Redirect** - HTTP to HTTPS redirect check
- **Broken Link Detection** - Parallel broken link checking (optional)
- **Readability Score** - Flesch Reading Ease analysis
- **Keyword Density** - Top keyword frequency analysis
- **HTML Validation** - Unclosed tag detection
- **Hreflang Tags** - Internationalization support check
- **AMP Detection** - Accelerated Mobile Pages detection
- **Batch URL Analysis** - Analyze multiple URLs at once
- **Category Scoring** - Scores broken down by category
- **HTML Reports** - Beautiful browser-viewable reports

---

## Install

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
# Basic check
python seocheck.py -u https://example.com

# Check with broken link detection
python seocheck.py -u https://example.com --check-links

# Export reports
python seocheck.py -u https://example.com --export all

# Batch analysis
python seocheck.py -u https://example.com --batch urls.txt --export all

# Custom timeout
python seocheck.py -u https://example.com -t 30

# No colors
python seocheck.py -u https://example.com --no-color
```

---

## Report Output

### Console Output
The tool gives a score out of 100 with grade and category breakdown:
- **A (80-100)** - Excellent SEO
- **B (60-79)** - Good, minor improvements
- **C (40-59)** - Fair, needs work
- **D (20-39)** - Poor, major issues
- **F (0-19)** - Failing, critical problems

### Category Breakdown
- **SECURITY** - SSL, HTTPS redirect
- **META** - Title, description, keywords
- **CONTENT** - Headings, images, word count, readability
- **TECHNICAL** - Sitemap, robots.txt, canonical, structured data
- **MOBILE** - Viewport, AMP
- **SOCIAL** - Open Graph, Twitter Cards
- **PERFORMANCE** - Page size, load time
- **LINKS** - Internal/external links, broken links

---

## Export Formats

| Format | Command | Description |
|--------|---------|-------------|
| JSON | `--export json` | Machine-readable data |
| CSV | `--export csv` | Spreadsheet analysis |
| HTML | `--export html` | Browser-viewable report |
| All | `--export all` | All formats at once |

---

## Batch Analysis

Create a file with URLs (one per line):

```bash
# urls.txt
https://example.com
https://example.com/about
https://example.com/contact

python seocheck.py -u https://example.com --batch urls.txt --export all
```

---

## Requirements

| Package | Version | Purpose |
|---------|---------|---------|
| Python | 3.7+ | Runtime |
| requests | >=2.31.0 | HTTP client |
| beautifulsoup4 | >=4.12.0 | HTML parsing |
| colorama | >=0.4.6 | Terminal colors |

---

## License

MIT License
