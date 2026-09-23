# SecurityChecker v1.0

### Ultimate Website Security Analyzer

> Comprehensive security analysis: SSL/TLS, HTTP headers, vulnerabilities, DNS, compliance.

---

## Features

### SSL/TLS Analysis
- **Certificate Validation** - Expiry, issuer, SAN verification
- **Protocol Detection** - SSLv2/v3, TLS 1.0/1.1/1.2/1.3 support
- **Cipher Analysis** - Weak cipher detection (RC4, DES, NULL, EXPORT)
- **HSTS Check** - max-age, includeSubDomains, preload

### HTTP Security Headers
- **Content-Security-Policy** - XSS and injection prevention
- **Strict-Transport-Security** - HTTPS enforcement
- **X-Frame-Options** - Clickjacking protection
- **X-Content-Type-Options** - MIME sniffing prevention
- **Referrer-Policy** - Information leakage control
- **Permissions-Policy** - Browser feature control
- **Cross-Origin Policies** - COEP, COOP, CORP

### Vulnerability Detection
- **Clickjacking** - Missing frame protection
- **XSS Protection** - No CSP or X-XSS-Protection
- **Mixed Content** - HTTP resources on HTTPS pages
- **Open Redirect** - Cross-domain redirects
- **SRI** - Missing subresource integrity
- **Directory Listing** - Exposed directories
- **Admin Panels** - wp-admin, phpmyadmin, cpanel
- **Backup Files** - .zip, .sql, .env exposure
- **Debug Endpoints** - /debug, /actuator, /phpinfo

### DNS Security
- **SPF Record** - Email spoofing prevention
- **DMARC Record** - Email authentication
- **DNSSEC** - DNS security extensions

### Compliance
- **Privacy Policy** - Link detection
- **Cookie Consent** - Consent mechanism detection
- **Terms of Service** - Link detection

---

## Install

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
# Basic security check
python securitycheck.py -u https://example.com

# Export all reports
python securitycheck.py -u https://example.com --export all

# Export HTML report only
python securitycheck.py -u https://example.com --export html

# Custom timeout
python securitycheck.py -u https://example.com -t 30

# No colors
python securitycheck.py -u https://example.com --no-color
```

---

## Report Output

### Score Summary
- **A (80-100)** - Secure - Excellent security posture
- **B (60-79)** - Good - Minor improvements needed
- **C (40-59)** - Fair - Significant security gaps
- **D (20-39)** - Poor - Major security issues
- **F (0-19)** - Critical - Severe vulnerabilities!

### Severity Levels
- **CRITICAL** - Immediate action required
- **HIGH** - Should be fixed urgently
- **MEDIUM** - Should be addressed
- **LOW** - Minor improvement
- **INFO** - Informational

### Categories
- **SSL** - Certificate, protocol, cipher, HSTS
- **HEADERS** - Security headers
- **DISCLOSURE** - Information leakage
- **COOKIES** - Cookie security flags
- **CORS** - Cross-origin configuration
- **CONTENT** - Mixed content, forms, scripts
- **VULN** - Known vulnerability patterns
- **DNS** - Email and DNS security
- **COMPLIANCE** - Privacy and legal

---

## Export Formats

| Format | Command | Description |
|--------|---------|-------------|
| JSON | `--export json` | Machine-readable data |
| CSV | `--export csv` | Spreadsheet analysis |
| HTML | `--export html` | Styled security report |
| All | `--export all` | All formats at once |

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
