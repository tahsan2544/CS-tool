# PerfAnalyzer v1.0

### Website Performance Analyzer

> Measure Core Web Vitals, TTFB, Resources, Caching, Compression and more.

---

## Features

### Core Web Vitals (Estimated)
- **LCP** - Largest Contentful Paint estimation
- **CLS** - Cumulative Layout Shift detection
- **INP** - Interaction to Next Paint estimation

### Time Metrics
- **TTFB** - Time to First Byte
- **Server Response Time** - Server processing time
- **Total Load Time** - Full page download
- **DOM Parse Time** - HTML parsing estimate
- **Time to Interactive** - JS execution estimate

### Resource Analysis
- **Total Page Size** - All resources combined
- **CSS** - Count, size, render-blocking detection
- **JS** - Count, size, async/defer detection
- **Images** - Count, size, format analysis
- **Fonts** - Count, size, font-display detection
- **Third-party** - External domain resources

### Caching Analysis
- **Cache-Control** - max-age, no-cache, private/public
- **ETag** - Conditional request support
- **Last-Modified** - Last update timestamp
- **Cache Score** - Overall caching rating

### Compression
- **Content-Encoding** - gzip, brotli, deflate
- **Compression Ratio** - Size savings
- **Text Compression** - HTML/CSS/JS compression

### Redirect Analysis
- **Redirect Chain** - All hops tracked
- **HTTP to HTTPS** - Security redirect
- **WWW Redirect** - Canonical redirect

### Protocol Analysis
- **HTTP Version** - HTTP/1.1, HTTP/2, HTTP/3
- **Keep-Alive** - Connection reuse
- **TLS Version** - SSL/TLS protocol

### Critical Rendering Path
- **Render-blocking Resources** - CSS/JS in head
- **Preload/Prefetch** - Resource hints
- **DNS Prefetch** - DNS optimization

### Image Optimization
- **Modern Formats** - WebP, AVIF usage
- **Lazy Loading** - loading="lazy" attribute
- **Responsive Images** - srcset support
- **Dimensions** - Width/height attributes

---

## Install

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
# Basic analysis
python perfanalyzer.py -u https://example.com

# Verbose with all reports
python perfanalyzer.py -u https://example.com -v --export all

# HTML report only
python perfanalyzer.py -u https://example.com --export html

# No colors
python perfanalyzer.py -u https://example.com --no-color
```

---

## Score Guide

| Score | Rating | Description |
|-------|--------|-------------|
| 90-100 | Excellent | Fast, well-optimized site |
| 50-89 | Needs Work | Some optimizations needed |
| 0-49 | Poor | Major performance issues |

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
