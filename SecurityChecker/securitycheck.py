#!/usr/bin/env python3

import sys
import os
import argparse
import json
import csv
import re
import ssl
import socket
import subprocess
import warnings
import datetime
import time
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote

try:
    import requests
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

try:
    from bs4 import BeautifulSoup
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "beautifulsoup4"])
    from bs4 import BeautifulSoup

try:
    from colorama import init, Fore, Style
    init()
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama"])
    from colorama import init, Fore, Style
    init()

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

VERSION = "7.0"
CRLF = "\r\n"

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║{Fore.WHITE}  ███████╗███████╗ ██████╗ ██╗   ██╗███████╗███████╗ ██████╗  {Fore.CYAN}║
║{Fore.WHITE}  ██╔════╝██╔════╝██╔═══██╗██║   ██║██╔════╝██╔════╝██╔════╝  {Fore.CYAN}║
║{Fore.WHITE}  ███████╗█████╗  ██║   ██║██║   ██║███████╗█████╗  ██║  ███╗ {Fore.CYAN}║
║{Fore.WHITE}  ╚════██║██╔══╝  ██║   ██║██║   ██║╚════██║██╔══╝  ██║   ██║ {Fore.CYAN}║
║{Fore.WHITE}  ███████║███████╗╚██████╔╝╚██████╔╝███████║███████╗╚██████╔╝ {Fore.CYAN}║
║{Fore.WHITE}  ╚══════╝╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝╚══════╝ ╚═════╝  {Fore.CYAN}║
 ║{Fore.YELLOW}              Website Security Analyzer v{VERSION}                    {Fore.CYAN}║
 ║{Fore.WHITE}   Browser Policy / SRI / Fetch Metadata / Threat Modeling / CVSS    {Fore.CYAN}║
 ║{Fore.WHITE}   WAF / Bot / RateLimit / Lockout / MFA / Password / AuthN         {Fore.CYAN}║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

SEVERITY_COLORS = {
    "critical": Fore.RED + Style.BRIGHT,
    "high": Fore.LIGHTRED_EX,
    "medium": Fore.YELLOW,
    "low": Fore.CYAN,
    "info": Fore.WHITE,
}

SEVERITY_POINTS = {"critical": 25, "high": 15, "medium": 10, "low": 5, "info": 1}

CVSS_WEIGHTS = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.0,
}

OWASP_TOP10 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

NIST_CATEGORIES = {
    "AC": "Access Control",
    "AU": "Audit and Accountability",
    "CA": "Security Assessment and Authorization",
    "CM": "Configuration Management",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "RA": "Risk Assessment",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}

PCI_DSS_REQUIREMENTS = {
    "PCI-1": "Install and maintain network security controls",
    "PCI-2": "Apply secure configurations to all system components",
    "PCI-3": "Protect stored account data",
    "PCI-4": "Protect cardholder data with strong cryptography during transmission",
    "PCI-5": "Protect all systems and networks from malicious software",
    "PCI-6": "Develop and maintain secure systems and software",
    "PCI-7": "Restrict access to system components by business need-to-know",
    "PCI-8": "Identify users and authenticate access to system components",
    "PCI-9": "Restrict physical access to cardholder data",
    "PCI-10": "Log and monitor all access to system components and cardholder data",
    "PCI-11": "Test security of systems and networks regularly",
    "PCI-12": "Support information security with organizational policies and programs",
}

HIPAA_SAFEGUARDS = {
    "HIPAA-AC": "Access Control",
    "HIPAA-AU": "Audit Controls",
    "HIPAA-CE": "Integrity Controls",
    "HIPAA-TX": "Transmission Security",
    "HIPAA-PS": "Person or Entity Authentication",
    "HIPAA-SI": "Information System Activity Review",
    "HIPAA-RS": "Response and Reporting",
}

SECURITY_MATURITY_LEVELS = {
    0: {"level": "Initial",
        "description": "Ad-hoc security processes, reactive firefighting with no consistent preventive controls",
        "focus": "Establish asset inventory, TLS, and critical exposure baseline"},
    1: {"level": "Developing",
        "description": "Core controls documented and partially deployed; outcomes vary by system and team",
        "focus": "Standardize headers, transport security, and authentication hardening"},
    2: {"level": "Defined",
        "description": "Organization-wide policies and standards in place with consistent implementation",
        "focus": "Close residual authentication, session, and injection gaps"},
    3: {"level": "Managed",
        "description": "Security metrics tracked continuously; risk and compliance measured with evidence",
        "focus": "Automate detection/response and software supply-chain assurance"},
    4: {"level": "Optimized",
        "description": "Continuous improvement, automated preventive controls, threat-informed defense",
        "focus": "Sustain purple-team feedback loops and adaptive policy tuning"},
}

STRIDE_THEATS = {
    "spoofing": {"label": "Spoofing", "desc": "Identity and authentication bypass"},
    "tampering": {"label": "Tampering", "desc": "Malicious modification of data or code"},
    "repudiation": {"label": "Repudiation", "desc": "Actions denied without credible proof"},
    "information_disclosure": {"label": "Information Disclosure", "desc": "Unauthorized data exposure"},
    "denial_of_service": {"label": "Denial of Service", "desc": "Availability degradation or outage"},
    "elevation_of_privilege": {"label": "Elevation of Privilege", "desc": "Gaining unauthorized capabilities"},
}

OWASP_TO_STRIDE = {
    "A01": "elevation_of_privilege",
    "A02": "information_disclosure",
    "A03": "tampering",
    "A04": "tampering",
    "A05": "elevation_of_privilege",
    "A06": "tampering",
    "A07": "spoofing",
    "A08": "tampering",
    "A09": "repudiation",
    "A10": "information_disclosure",
}

CATEGORY_TO_STRIDE = {
    "ssl": "information_disclosure",
    "headers": "elevation_of_privilege",
    "disclosure": "information_disclosure",
    "cookies": "spoofing",
    "cors": "information_disclosure",
    "content": "tampering",
    "vuln": "tampering",
    "advanced_vuln": "tampering",
    "cache": "tampering",
    "wasm": "tampering",
    "privacy": "information_disclosure",
    "supply_chain": "tampering",
    "sri": "tampering",
    "browser_policy": "elevation_of_privilege",
    "api": "elevation_of_privilege",
    "container": "elevation_of_privilege",
    "dns": "spoofing",
    "compliance": "repudiation",
    "scoring": "denial_of_service",
    "waf": "tampering",
    "bot_protection": "spoofing",
    "rate_limiting": "denial_of_service",
    "account_lockout": "spoofing",
    "mfa": "spoofing",
    "password_policy": "spoofing",
    "auth_security": "elevation_of_privilege",
}

CATEGORY_ORDER = [
    "ssl", "headers", "disclosure", "cookies", "cors", "content",
    "vuln", "advanced_vuln", "cache", "wasm", "privacy", "supply_chain",
    "sri", "browser_policy",
    "waf", "bot_protection", "rate_limiting", "account_lockout",
    "mfa", "password_policy", "auth_security",
    "api", "container", "dns", "compliance", "scoring",
]

CATEGORY_SHORT_NAMES = {
    "ssl": "SSL/TLS", "headers": "Headers", "disclosure": "Disclosure",
    "cookies": "Cookies", "cors": "CORS", "content": "Content",
    "vuln": "Vulns", "advanced_vuln": "Adv Vulns", "cache": "Cache",
    "wasm": "WASM", "privacy": "Privacy", "supply_chain": "SupplyChain",
    "sri": "SRI", "browser_policy": "BrowserPolicy",
    "waf": "WAF", "bot_protection": "BotProtect",
    "rate_limiting": "RateLimit", "account_lockout": "Lockout",
    "mfa": "MFA", "password_policy": "PwdPolicy",
    "auth_security": "AuthSecurity",
    "api": "API", "container": "Container", "dns": "DNS",
    "compliance": "Compliance", "scoring": "Scoring",
}

CVSS_V31_AV = {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.20}
CVSS_V31_AC = {"low": 0.77, "high": 0.44}
CVSS_V31_PR = {"none": 0.85, "low": 0.62, "high": 0.27}
CVSS_V31_UI = {"none": 0.85, "required": 0.62}
CVSS_V31_CIA = {"high": 0.56, "low": 0.22, "none": 0.0}

SEVERITY_CIA = {
    "critical": ("high", "high", "high"),
    "high": ("high", "high", "none"),
    "medium": ("low", "low", "none"),
    "low": ("low", "none", "none"),
    "info": ("none", "none", "none"),
}

SEVERITY_AC_PR_UI = {
    "critical": ("low", "none", "none"),
    "high": ("low", "low", "none"),
    "medium": ("low", "high", "none"),
    "low": ("high", "high", "required"),
    "info": ("high", "high", "required"),
}

BUSINESS_IMPACT_DOMAINS = {
    "ssl": "Transport & session confidentiality",
    "headers": "Browser-side exploit exposure",
    "disclosure": "Information disclosure",
    "cookies": "Session & credential exposure",
    "cors": "Cross-origin data exposure",
    "content": "Content integrity",
    "vuln": "Application integrity & data theft",
    "advanced_vuln": "Application integrity & data theft",
    "cache": "Content integrity & cache trust",
    "wasm": "Client-side code integrity",
    "privacy": "User privacy & regulatory exposure",
    "supply_chain": "Build & third-party trust",
    "sri": "Third-party code integrity",
    "browser_policy": "Browser isolation & API abuse resistance",
    "api": "API data exposure",
    "container": "Infrastructure compromise",
    "dns": "Domain & email trust",
    "waf": "Edge filtering & exploit suppression",
    "bot_protection": "Automated abuse resistance",
    "rate_limiting": "Brute-force & resource abuse control",
    "account_lockout": "Credential stuffing resistance",
    "mfa": "Account takeover resistance",
    "password_policy": "Credential strength assurance",
    "auth_security": "Session & authorization integrity",
    "compliance": "Regulatory & audit exposure",
    "scoring": "Aggregate business risk",
}

KNOWN_CDN_HOSTS = [
    "cdnjs.cloudflare.com", "ajax.googleapis.com", "code.jquery.com",
    "cdn.jsdelivr.net", "unpkg.com", "use.typekit.net", "fonts.googleapis.com",
    "fonts.gstatic.com", "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com", "bootstrapcdn.com", "kit.fontawesome.com",
    "player.vimeo.com", "www.youtube.com", "s.yimg.com", "static.hotjar.com",
    "cdn.iframe.ly", "assets.adobedtm.com", "tags.tiqcdn.com",
]

SUSPICIOUS_SCRIPT_HOSTS = [
    "pastebin.com", "hastebin.com", "rentry.co", "paste.ee", "bit.ly",
    "tinyurl.com", "goo.gl", "raw.githubusercontent.com", "transfer.sh",
    "discordapp.com", "cdn.discordapp.com", "termbin.com",
]

VULNERABLE_DEPENDENCIES = [
    {"name": "jquery", "ranges": [((0, 0, 0), (3, 5, 0))],
     "cve": "CVE-2020-11022, CVE-2020-11023",
     "severity": "high", "fix": "3.5.0",
     "note": "XSS via HTML preprocessing of untrusted input"},
    {"name": "jquery", "ranges": [((0, 0, 0), (3, 4, 0))],
     "cve": "CVE-2019-11358", "severity": "medium", "fix": "3.4.0",
     "note": "Prototype pollution in jQuery.extend"},
    {"name": "lodash", "ranges": [((0, 0, 0), (4, 17, 21))],
     "cve": "CVE-2021-23337, CVE-2020-8203",
     "severity": "high", "fix": "4.17.21",
     "note": "Command injection and prototype pollution"},
    {"name": "bootstrap", "ranges": [((0, 0, 0), (3, 4, 1)), ((4, 0, 0), (4, 3, 1))],
     "cve": "CVE-2019-8331", "severity": "medium", "fix": "3.4.1 / 4.3.1",
     "note": "XSS in tooltip and popover components"},
    {"name": "underscore", "ranges": [((0, 0, 0), (1, 12, 4))],
     "cve": "CVE-2021-23358", "severity": "high", "fix": "1.12.4",
     "note": "Command injection via template settings"},
    {"name": "handlebars", "ranges": [((0, 0, 0), (4, 7, 7))],
     "cve": "CVE-2021-23369, CVE-2021-23383",
     "severity": "critical", "fix": "4.7.7",
     "note": "Remote code execution through template compilation"},
    {"name": "moment", "ranges": [((0, 0, 0), (2, 29, 4))],
     "cve": "CVE-2022-31129", "severity": "medium", "fix": "2.29.4",
     "note": "Regular expression denial of service"},
    {"name": "angularjs", "ranges": [((0, 0, 0), (1, 7, 9))],
     "cve": "CVE-2019-10769, CVE-2018-1000003",
     "severity": "high", "fix": "1.7.9 (or migrate off AngularJS)",
     "note": "Prototype pollution; AngularJS is end-of-life"},
]

LIBRARY_PATTERNS = [
    ("jquery", re.compile(r"jquery[-.](\d+(?:\.\d+)*)", re.I)),
    ("lodash", re.compile(r"lodash[.-](\d+(?:\.\d+)*)", re.I)),
    ("bootstrap", re.compile(r"bootstrap[-.](\d+(?:\.\d+)*)", re.I)),
    ("underscore", re.compile(r"underscore[.-](\d+(?:\.\d+)*)", re.I)),
    ("handlebars", re.compile(r"handlebars[.-](\d+(?:\.\d+)*)", re.I)),
    ("moment", re.compile(r"moment[-.](\d+(?:\.\d+)*)", re.I)),
    ("angularjs", re.compile(r"angular[-.](\d+(?:\.\d+)*)", re.I)),
    ("react", re.compile(r"react[-.](\d+(?:\.\d+)*)", re.I)),
    ("vue", re.compile(r"vue[.-](\d+(?:\.\d+)*)", re.I)),
    ("ember", re.compile(r"ember[.-](\d+(?:\.\d+)*)", re.I)),
    ("backbone", re.compile(r"backbone[.-](\d+(?:\.\d+)*)", re.I)),
]

NPM_PATTERNS = [
    re.compile(r"/npm/(@?[a-z0-9._-]+)@(\d+(?:\.\d+)*)", re.I),
    re.compile(r"unpkg\.com/(@?[a-z0-9._-]+)@(\d+(?:\.\d+)*)", re.I),
    re.compile(r"cdn\.jsdelivr\.net/npm/(@?[a-z0-9._-]+)@(\d+(?:\.\d+)*)", re.I),
]

CRYPTO_MINER_INDICATORS = [
    "coinhive", "coin-hive", "coinhive.com", "cryptonight", "cryptoloot",
    "coinimp", "webmine", "webminerpool", "jsecoin", "authedmine",
    "deepminer", "coinerra", "minero", "nicehash", "cn.pool",
    "hashrate", "totalhashes", "coin-have", "ppoi.org", "wasmminer",
    "crypto-loot", "freeloader", "ppoliner",
]

FINGERPRINTING_LIBRARIES = [
    "fingerprintjs", "fingerprintjs2", "fingerprintjs-pro", "fingerprintjs3",
    "evercookie", "canvas-fingerprint", "canvasfp", "webgl-fingerprint",
    "clientjs", "fingerprint2", "jstrek", "abraham", "fingerprint kit",
]

DOM_XSS_SOURCES = [
    "location.hash", "location.search", "location.href", "location.assign",
    "document.url", "document.referrer", "window.name", "document.cookie",
]

DOM_XSS_SINKS = [
    "innerhtml", "outerhtml", "document.write", "document.writeln",
    "insertadjacenthtml", "eval(", "new function(", "settimeout(",
    "setinterval(", "$.parsehtml", "dangerouslysetinnerhtml",
    "javascript:",
]

DOM_XSS_DANGEROUS_SINKS = [
    "eval(", "new function(", "document.write", "document.writeln",
    "insertadjacenthtml", "dangerouslysetinnerhtml",
]

CSRF_TOKEN_NAME_RE = re.compile(
    r"(csrf|xsrf|_token|authenticity_token|__requestverificationtoken|"
    r"antiforgery|nonce|verification)",
    re.I,
)


# ---------------------------------------------------------------------------
# SecurityChecker v7.0 - detection signatures and scoring helpers
# ---------------------------------------------------------------------------

WAF_HEADER_SIGNATURES = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "cf-request-id": "Cloudflare",
    "x-sucuri-id": "Sucuri WAF",
    "x-sucuri-cache": "Sucuri WAF",
    "x-iinfo": "Imperva/Incapsula",
    "x-cdn": "Imperva/Incapsula",
    "x-akamai-transformed": "Akamai",
    "akamai-grn": "Akamai",
    "x-akamai-staging": "Akamai (staging)",
    "x-amz-cf-id": "AWS CloudFront",
    "x-amz-cf-pop": "AWS CloudFront",
    "x-azure-ref": "Azure Front Door",
    "x-msedge-ref": "Azure Front Door",
    "x-fastly-request-id": "Fastly",
    "x-varnish": "Varnish",
    "x-firewall": "Generic WAF",
    "x-waf-event": "Generic WAF",
    "x-blocked-by": "Generic WAF",
    "x-security-check": "Generic WAF",
}

WAF_SERVER_HINTS = [
    "cloudflare", "akamaighost", "akamai", "fastly", "varnish", "awselb",
    "elasticloadbalancing", "sucuri", "incapsula", "imperva", "barracuda",
    "bigip", "fortiweb", "mod_security", "modsecurity", "wordfence",
    "radware", "denycustom",
]

WAF_BODY_SIGNATURES = {
    "attention required! | cloudflare": "Cloudflare",
    "enable javascript and cookies to continue": "Cloudflare js-challenge",
    "just a moment...": "Cloudflare challenge",
    "why have i been blocked": "Cloudflare block page",
    "the requested url was rejected": "AWS WAF block page",
    "request rejected by modsecurity": "ModSecurity",
    "sucuri website firewall": "Sucuri",
    "incapsula incident": "Imperva/Incapsula",
    "protected by imunify360": "Imunify360",
    "ddos protection by": "Generic DDoS protection",
}

WAF_BODY_BLOCK_INDICATORS = [
    "access denied", "request rejected", "blocked by", "attention required",
    "just a moment", "checking your browser", "security check",
    "the requested url was rejected", "mod_security", "incident id",
    "enable javascript and cookies to continue", "ddos protection",
]

WAF_PROBE_PAYLOADS = [
    "<script>alert(1)</script>",
    "' OR '1'='1",
    "../../../etc/passwd",
    "{{7*7}}",
]

BOT_PROTECTION_SIGNATURES = {
    "Google reCAPTCHA": ["recaptcha", "g-recaptcha", "www.google.com/recaptcha"],
    "hCaptcha": ["hcaptcha", "h-captcha", "newassets.hcaptcha.com"],
    "Cloudflare Turnstile": ["challenges.cloudflare.com/turnstile", "cf-turnstile", "turnstile"],
    "FunCaptcha/Arkose": ["funcaptcha", "arkoselabs", "arkose"],
    "GeeTest": ["geetest"],
    "ALTCHA": ["altcha"],
    "Friendly Captcha": ["friendlycaptcha", "frc-captcha"],
    "Cloudflare Challenge": ["cf-chl-", "cdn-cgi/challenge-platform", "challenge-platform"],
    "Generic CAPTCHA": ["captcha", "grecaptcha"],
}

BOT_COOKIE_SIGNATURES = {
    "cf_clearance": "Cloudflare clearance cookie",
    "__cf_bm": "Cloudflare bot management",
    "__cflb": "Cloudflare load balancer",
    "incap_ses": "Imperva session",
    "visid_incap": "Imperva visitor",
}

RATE_LIMIT_HEADERS = [
    "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset",
    "X-RateLimit-Policy", "RateLimit-Limit", "RateLimit-Remaining",
    "RateLimit-Reset", "RateLimit-Policy", "Retry-After",
    "X-Rate-Limit-Limit", "X-Rate-Limit-Remaining", "X-Rate-Limit-Reset",
    "X-Quota-Limit", "X-Quota-Remaining", "X-Quota-Reset",
]

LOCKOUT_MESSAGES = [
    "account locked", "too many failed", "failed attempts", "temporarily locked",
    "try again later", "login attempts", "locked out", "lockout",
    "suspended due to", "too many login", "incorrect password attempts",
    "brute force", "wait before trying",
]

MFA_KEYWORDS = [
    "mfa", "2fa", "two-factor", "twofactor", "two factor", "otp", "totp",
    "verification code", "authenticator", "security code", "one-time code",
    "onetime code", "backup code", "sms code", "enter the code",
    "scan the qr code",
]

MFA_PATHS = [
    "/mfa", "/2fa", "/verify", "/otp", "/totp", "/two-factor", "/twofactor",
]

PASSWORD_POLICY_PATTERNS = [
    ("min_length", r"at least\s+\d+\s+char|min(?:imum)?\s+(?:of\s+)?\d+\s+char"),
    ("uppercase", r"upper\s*case|capital\s+letter"),
    ("lowercase", r"lower\s*case"),
    ("digit", r"\bnumber\b|\bdigit\b|numeric"),
    ("special", r"special\s+char|symbol|non-alphanumeric"),
    ("history", r"must not match|different from (?:your )?previous|password history"),
    ("breach_check", r"breached|compromised password|known password"),
    ("passphrase", r"passphrase"),
]

THREAT_TECHNIQUE_MAP = {
    "A01": "TA0001 Valid account / access manipulation",
    "A02": "TA0009 Credential capture over transport",
    "A03": "TA0002 Command and query injection",
    "A04": "TA0003 Abuse of edge and validation gaps",
    "A05": "TA0004 Security feature bypass",
    "A06": "TA0005 Software supply chain compromise",
    "A07": "TA0006 Valid accounts abuse",
    "A08": "TA0007 Tampered artifacts and unsafe deserialization",
    "A09": "TA0008 Impair defensive monitoring",
    "A10": "TA0010 Server-side request forgery",
    "waf": "TA0004 Edge control circumvention",
    "bot_protection": "TA0006 Automated credential abuse",
    "rate_limiting": "TA0006 Brute-force amplification",
    "account_lockout": "TA0006 Credential stuffing enablement",
    "mfa": "TA0006 MFA bypass / account takeover",
    "password_policy": "TA0006 Weak credential exploitation",
    "auth_security": "TA0001 Session fixation and privilege abuse",
    "supply_chain": "TA0005 Third-party artifact tampering",
    "cache": "TA0009 Cache deception / poisoning",
    "cookies": "TA0006 Session token theft",
    "cors": "TA0010 Cross-origin data exposure",
    "ssl": "TA0009 Transport interception",
}

EFFORT_BY_CATEGORY = {
    "ssl": "S", "headers": "S", "cookies": "S", "cors": "S", "disclosure": "S",
    "content": "M", "vuln": "M", "advanced_vuln": "L", "cache": "M",
    "wasm": "M", "privacy": "M", "supply_chain": "L", "sri": "S",
    "browser_policy": "M", "waf": "M", "bot_protection": "S",
    "rate_limiting": "M", "account_lockout": "M", "mfa": "L",
    "password_policy": "S", "auth_security": "M", "api": "M",
    "container": "L", "dns": "S", "compliance": "M", "scoring": "S",
}


def cvss_roundup(value):
    if value <= 0:
        return 0.0
    if value >= 10:
        return 10.0
    import math
    return math.ceil(round(value, 4) * 10) / 10.0


def approximate_cvss_v31(severity, attack_vector=None, exploitability=None,
                         impact=None, passed=False):
    """Approximate a CVSS v3.1 base score/vector from check metadata."""
    if passed or severity == "info":
        return {
            "score": 0.0, "vector": "",
            "exploitability_score": 0.0, "impact_score": 0.0,
            "av": "N", "ac": "L", "pr": "N", "ui": "N",
            "s": "U", "c": "N", "i": "N", "a": "N",
        }

    av_key = (attack_vector or "Network").strip().lower()
    if av_key not in CVSS_V31_AV:
        av_key = "network"
    av_letter = {"network": "N", "adjacent": "A", "local": "L", "physical": "P"}[av_key]

    ac_key, pr_key, ui_key = SEVERITY_AC_PR_UI.get(severity, ("low", "low", "none"))
    if exploitability is not None:
        if exploitability >= 2.0:
            ac_key, pr_key, ui_key = "low", "none", "none"
        elif exploitability >= 1.5:
            ac_key, pr_key, ui_key = "low", "low", "none"
        elif exploitability < 1.0:
            ac_key, pr_key, ui_key = "high", "high", "required"

    c_key, i_key, a_key = SEVERITY_CIA.get(severity, ("low", "low", "none"))
    if impact is not None:
        if impact >= 2.0:
            c_key, i_key, a_key = "high", "high", "high"
        elif impact >= 1.5:
            c_key, i_key, a_key = "high", "high", "none"

    isc = 1.0 - ((1.0 - CVSS_V31_CIA[c_key])
                 * (1.0 - CVSS_V31_CIA[i_key])
                 * (1.0 - CVSS_V31_CIA[a_key]))
    impact_score = cvss_roundup(max(0.0, 6.42 * isc))
    exploitability_score = cvss_roundup(
        8.22 * CVSS_V31_AV[av_key] * CVSS_V31_AC[ac_key]
        * CVSS_V31_PR[pr_key] * CVSS_V31_UI[ui_key]
    )
    raw = min(impact_score + 8.22 * CVSS_V31_AV[av_key] * CVSS_V31_AC[ac_key]
              * CVSS_V31_PR[pr_key] * CVSS_V31_UI[ui_key], 10.0)
    score = cvss_roundup(raw)

    vector = (
        "CVSS:3.1/AV:" + av_letter
        + "/AC:" + ac_key[0].upper()
        + "/PR:" + pr_key[0].upper()
        + "/UI:" + ("N" if ui_key == "none" else "R")
        + "/S:U/C:" + c_key[0].upper()
        + "/I:" + i_key[0].upper()
        + "/A:" + a_key[0].upper()
    )
    return {
        "score": score, "vector": vector,
        "exploitability_score": exploitability_score,
        "impact_score": impact_score,
        "av": av_letter, "ac": ac_key[0].upper(),
        "pr": pr_key[0].upper(), "ui": ("N" if ui_key == "none" else "R"),
        "s": "U", "c": c_key[0].upper(), "i": i_key[0].upper(),
        "a": a_key[0].upper(),
    }


class SecurityCheck:
    def __init__(self, name, severity, passed, details, category, cve=None,
                 remediation=None, owasp=None, nist=None, pci_dss=None,
                 hipaa=None, cvss_base=None, attack_vector=None,
                 exploitability=None, impact=None, business_impact=None):
        self.name = name
        self.severity = severity
        self.passed = passed
        self.details = details
        self.category = category
        self.cve = cve
        self.remediation = remediation
        self.owasp = owasp
        self.nist = nist
        self.pci_dss = pci_dss
        self.hipaa = hipaa
        self.cvss_base = cvss_base
        self.attack_vector = attack_vector
        self.exploitability = exploitability
        self.impact = impact
        self.business_impact = business_impact or BUSINESS_IMPACT_DOMAINS.get(category, "General operational risk")
        self.max_points = SEVERITY_POINTS.get(severity, 0)
        self.points = self.max_points if passed else 0
        self.cvss_score = CVSS_WEIGHTS.get(severity, 0.0)
        self.cvss31 = approximate_cvss_v31(
            severity, attack_vector=attack_vector,
            exploitability=exploitability, impact=impact, passed=passed,
        )

    def calculate_risk_score(self):
        base = self.cvss_score
        if self.exploitability:
            base *= self.exploitability
        if self.impact:
            base *= self.impact
        return min(base, 10.0)


class SecurityAnalyzer:
    def __init__(self, url, timeout=10, no_color=False, api_depth=False,
                 container_scan=False, verbose=False):
        self.url = url if url.startswith(("http://", "https://")) else "https://" + url
        self.timeout = timeout
        self.no_color = no_color
        self.verbose = verbose
        self.api_depth = api_depth
        self.container_scan = container_scan
        self.parsed = urlparse(self.url)
        self.domain = self.parsed.netloc
        self.scheme = self.parsed.scheme
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SecurityChecker/" + VERSION})
        self.session.verify = False
        self.findings = []
        self.response = None
        self.soup = None
        self.html_content = ""
        self.api_endpoints_found = []
        self.graphql_detected = False
        self.cloud_provider = None
        self.container_hints = []
        self.assets = {
            "scripts": 0, "external_scripts": 0, "inline_scripts": 0,
            "stylesheets": 0, "forms": 0, "frames": 0, "links": 0,
            "wasm_modules": [], "external_hosts": [], "cdn_hosts": [],
            "libraries": [],
        }
        self.cvss31_metrics = {}
        self.attack_vector_analysis = {}
        self.exploitability_metrics = {}
        self.business_impact_summary = {}
        self.posture = {}
        self.roadmap = []
        self.threat_model = {}
        self.threat_landscape = {}
        self.recommendations = []
        self.dashboard = {}
        self.compliance_weighted = {}
        self._weighted_buckets = {}
        self.waf_products = []
        self.bot_protection_found = []
        self.rate_limit_signals = []
        self.lockout_signals = []
        self.mfa_signals = []
        self.password_policy_signals = []
        self.defense_layers = {}
        self.risk_matrix = {}
        self.compliance_effectiveness = {}
        self.category_names = {
            "ssl": "SSL/TLS Security",
            "headers": "HTTP Security Headers",
            "disclosure": "Information Disclosure",
            "cookies": "Cookie Security",
            "cors": "Cross-Origin Resource Sharing",
            "content": "Content Security",
            "vuln": "Vulnerability Assessment",
            "dns": "DNS Security",
            "compliance": "Compliance & Privacy",
            "api": "API Security",
            "container": "Container & Cloud Security",
            "advanced_vuln": "Advanced Vulnerability Detection",
            "cache": "Web Cache Security",
            "wasm": "WebAssembly Security",
            "privacy": "Privacy & Client-Side Threats",
            "supply_chain": "Supply Chain Security",
            "sri": "Subresource Integrity Validation",
            "browser_policy": "Browser Policy & Fetch Metadata",
            "scoring": "Risk Assessment & Scoring",
            "waf": "Web Application Firewall",
            "bot_protection": "Bot Protection",
            "rate_limiting": "Rate Limiting",
            "account_lockout": "Account Lockout",
            "mfa": "Multi-Factor Authentication",
            "password_policy": "Password Policy",
            "auth_security": "Authentication & Session Security",
        }

    def color(self, severity):
        if self.no_color:
            return ""
        return SEVERITY_COLORS.get(severity, "")

    def reset(self):
        if self.no_color:
            return ""
        return Style.RESET_ALL

    def add_finding(self, name, severity, passed, details, category, cve=None,
                    remediation=None, owasp=None, nist=None, pci_dss=None,
                    hipaa=None, cvss_base=None, attack_vector=None,
                    exploitability=None, impact=None, business_impact=None):
        self.findings.append(
            SecurityCheck(name, severity, passed, details, category, cve,
                          remediation, owasp, nist, pci_dss, hipaa,
                          cvss_base, attack_vector, exploitability, impact,
                          business_impact)
        )

    def fetch_page(self):
        try:
            self.response = self.session.get(self.url, timeout=self.timeout, allow_redirects=True)
            self.html_content = self.response.text
            self.soup = BeautifulSoup(self.html_content, "html.parser")
            return True
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[ERROR] Failed to fetch {self.url}: {e}{Style.RESET_ALL}")
            return False

    def run_all_checks(self):
        if not self.fetch_page():
            return
        self.collect_asset_surface()
        self.check_ssl()
        self.check_headers()
        self.check_disclosure()
        self.check_cookies()
        self.check_cors()
        self.check_csp_analysis()
        self.check_content_security()
        self.check_vulnerabilities()
        self.check_request_smuggling()
        self.check_ssrf_hints()
        self.check_open_redirect()
        self.check_directory_traversal()
        self.check_sql_injection()
        self.check_xss_reflection()
        self.check_sensitive_paths()
        self.check_cookie_prefix()
        self.check_dns()
        self.check_certificate_transparency()
        self.check_ocsp_stapling()
        self.check_dns_caa()
        self.check_bounce_clickjacking()
        self.check_compliance()
        self.check_wasm_security()
        self.check_webrtc_leak()
        self.check_fingerprinting()
        self.check_crypto_mining()
        self.check_supply_chain()
        self.check_dependency_vulnerabilities()
        self.check_cache_poisoning()
        self.check_sri_validation()
        self.check_trusted_types()
        self.check_csp_report_uri()
        self.check_permissions_policy_analysis()
        self.check_isolation_policies()
        self.check_fetch_metadata()
        self.check_waf_detection()
        self.check_bot_protection()
        self.check_rate_limiting()
        self.check_account_lockout()
        self.check_mfa_detection()
        self.check_password_policy()
        if self.api_depth:
            self.check_api_endpoints()
            self.check_graphql()
            self.check_api_versioning()
            self.check_api_rate_limiting()
            self.check_api_auth_bypass()
            self.check_api_input_validation()
            self.check_api_response_analysis()
        if self.container_scan:
            self.check_container_security()
        self.check_advanced_vulnerabilities()
        self.check_advanced_injection_testing()
        self.check_authentication_bypass()
        self.check_session_fixation()
        self.check_privilege_escalation_hints()
        self.calculate_risk_assessment()

    def check_ssl(self):
        category = "ssl"
        if self.scheme != "https":
            self.add_finding("HTTPS Not Used", "critical", False,
                             "Site does not use HTTPS",
                             category, cve="CVE-2014-3566",
                             remediation="Configure TLS on your web server and redirect all HTTP to HTTPS.",
                             owasp="A02", nist="SC", pci_dss="PCI-4", hipaa="HIPAA-TX")
            self.add_finding("SSL Certificate", "critical", False,
                             "Cannot check certificate without HTTPS",
                             category,
                             remediation="Install a valid SSL/TLS certificate from a trusted CA.",
                             owasp="A02", nist="SC", pci_dss="PCI-4")
            self.add_finding("HSTS Header", "critical", False,
                             "HSTS requires HTTPS",
                             category,
                             remediation="Enable HTTPS first, then add the Strict-Transport-Security header.",
                             owasp="A05", nist="SC", pci_dss="PCI-4")
            return

        hostname = self.domain.split(":")[0]
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        not_after = cert.get("notAfter", "")
                        try:
                            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days_left = (expiry - datetime.datetime.utcnow()).days
                            if days_left < 0:
                                self.add_finding("SSL Certificate Expired", "critical", False,
                                                 "Certificate expired " + str(abs(days_left)) + " days ago",
                                                 category, cve="CVE-2023-XXXX",
                                                 remediation="Renew your SSL certificate immediately.",
                                                 owasp="A02", nist="SC", pci_dss="PCI-4")
                            elif days_left < 30:
                                self.add_finding("SSL Certificate Expiring Soon", "high", False,
                                                 "Certificate expires in " + str(days_left) + " days",
                                                 category,
                                                 remediation="Renew your SSL certificate before expiration.",
                                                 owasp="A02", nist="SC", pci_dss="PCI-4")
                            else:
                                self.add_finding("SSL Certificate Valid", "info", True,
                                                 "Valid until " + not_after + " (" + str(days_left) + " days remaining)",
                                                 category, owasp="A02", nist="SC", pci_dss="PCI-4")
                        except ValueError:
                            self.add_finding("SSL Certificate", "info", True,
                                             "Certificate valid, expiry: " + not_after,
                                             category, owasp="A02", nist="SC", pci_dss="PCI-4")
                    else:
                        self.add_finding("SSL Certificate", "high", False,
                                         "Could not retrieve certificate details",
                                         category,
                                         remediation="Verify your SSL certificate is properly installed.",
                                         owasp="A02", nist="SC", pci_dss="PCI-4")
        except ssl.SSLCertVerificationError as e:
            self.add_finding("SSL Certificate", "critical", False,
                             "Certificate verification failed: " + str(e.verify_message),
                             category,
                             remediation="Install a valid SSL/TLS certificate from a trusted CA.",
                             owasp="A02", nist="SC", pci_dss="PCI-4")
        except Exception as e:
            self.add_finding("SSL Connection", "high", False,
                             "SSL connection failed: " + str(e),
                             category,
                             remediation="Check your SSL certificate configuration and firewall rules.",
                             owasp="A02", nist="SC", pci_dss="PCI-4")

        try:
            weak_protocols = []
            tls_versions = []
            if hasattr(ssl, "TLSVersion"):
                tls_versions = [
                    ("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)),
                    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
                ]
            legacy_protocols = [
                ("SSLv2", getattr(ssl, "PROTOCOL_SSLv2", None)),
                ("SSLv3", getattr(ssl, "PROTOCOL_SSLv3", None)),
            ]
            for pname, pval in legacy_protocols:
                if pval is None:
                    continue
                try:
                    test_ctx = ssl.SSLContext(pval)
                    test_ctx.check_hostname = False
                    test_ctx.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                        with test_ctx.wrap_socket(sock, server_hostname=hostname):
                            weak_protocols.append(pname)
                except (ssl.SSLError, OSError, ValueError):
                    pass
            for pname, tver in tls_versions:
                if tver is None:
                    continue
                try:
                    test_ctx = ssl.create_default_context()
                    test_ctx.check_hostname = False
                    test_ctx.verify_mode = ssl.CERT_NONE
                    test_ctx.minimum_version = tver
                    test_ctx.maximum_version = tver
                    with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                        with test_ctx.wrap_socket(sock, server_hostname=hostname):
                            weak_protocols.append(pname)
                except (ssl.SSLError, OSError, ValueError):
                    pass
            if weak_protocols:
                self.add_finding("Weak SSL Protocols", "high", False,
                                 "Supported weak protocols: " + ", ".join(weak_protocols),
                                 category, cve="CVE-2014-3566",
                                 remediation="Disable SSLv2, SSLv3, TLSv1, and TLSv1.1. Use TLSv1.2+ only.",
                                 owasp="A02", nist="SC", pci_dss="PCI-4")
            else:
                self.add_finding("SSL Protocol Versions", "info", True,
                                 "No weak protocols detected",
                                 category, owasp="A02", nist="SC", pci_dss="PCI-4")
        except Exception:
            self.add_finding("SSL Protocol Check", "info", True,
                             "Could not fully test protocol versions",
                             category)

        weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "aNULL", "eNULL", "DES-CBC3"]
        try:
            ctx_c = ssl.create_default_context()
            ctx_c.check_hostname = False
            ctx_c.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with ctx_c.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0].upper()
                        found_weak = [w for w in weak_ciphers if w in cipher_name]
                        if found_weak:
                            self.add_finding("Weak Cipher Suite", "high", False,
                                             "Weak cipher detected: " + cipher_name,
                                             category,
                                             remediation="Configure your server to use strong cipher suites only.",
                                             owasp="A02", nist="SC", pci_dss="PCI-4")
                        else:
                            self.add_finding("Cipher Suite", "info", True,
                                             "Using cipher: " + cipher_name,
                                             category, owasp="A02", nist="SC", pci_dss="PCI-4")
        except Exception:
            self.add_finding("Cipher Check", "info", True,
                             "Could not test cipher strength",
                             category)

        hsts_header = self.response.headers.get("Strict-Transport-Security", "")
        if hsts_header:
            max_age_match = re.search(r"max-age=(\d+)", hsts_header)
            max_age = int(max_age_match.group(1)) if max_age_match else 0
            has_subdomains = "includeSubDomains" in hsts_header
            has_preload = "preload" in hsts_header
            if max_age < 31536000:
                self.add_finding("HSTS Weak Max-Age", "medium", False,
                                 "max-age=" + str(max_age) + " (recommended >= 31536000)",
                                 category,
                                 remediation="Set HSTS max-age to at least 31536000 (1 year).",
                                 owasp="A05", nist="SC", pci_dss="PCI-4")
            else:
                self.add_finding("HSTS Max-Age", "info", True,
                                 "max-age=" + str(max_age),
                                 category, owasp="A05", nist="SC", pci_dss="PCI-4")
            if not has_subdomains:
                self.add_finding("HSTS Missing includeSubDomains", "medium", False,
                                 "HSTS header missing includeSubDomains directive",
                                 category,
                                 remediation="Add includeSubDomains to your HSTS header.",
                                 owasp="A05", nist="SC", pci_dss="PCI-4")
            else:
                self.add_finding("HSTS includeSubDomains", "info", True,
                                 "HSTS includes subdomains",
                                 category, owasp="A05", nist="SC", pci_dss="PCI-4")
            if not has_preload:
                self.add_finding("HSTS Missing preload", "low", False,
                                 "HSTS header missing preload directive",
                                 category,
                                 remediation="Consider adding preload to your HSTS header for browser preload list submission.",
                                 owasp="A05", nist="SC", pci_dss="PCI-4")
            else:
                self.add_finding("HSTS preload", "info", True,
                                 "HSTS includes preload directive",
                                 category, owasp="A05", nist="SC", pci_dss="PCI-4")
        else:
            self.add_finding("HSTS Header Missing", "critical", False,
                             "Strict-Transport-Security header is not set",
                             category,
                             remediation="Add the Strict-Transport-Security header with max-age >= 31536000.",
                             owasp="A05", nist="SC", pci_dss="PCI-4")

    def check_headers(self):
        category = "headers"
        headers = self.response.headers

        hdr = headers.get("X-Frame-Options", "")
        if not hdr:
            self.add_finding("Missing X-Frame-Options", "high", False,
                             "X-Frame-Options header is not set",
                             category,
                             remediation="Add X-Frame-Options: DENY or SAMEORIGIN header.",
                             owasp="A05", nist="SC", pci_dss="PCI-6")
        else:
            self.add_finding("X-Frame-Options Present", "info", True,
                             "X-Frame-Options: " + hdr,
                             category, owasp="A05", nist="SC", pci_dss="PCI-6")

        hdr = headers.get("X-Content-Type-Options", "")
        if not hdr:
            self.add_finding("Missing X-Content-Type-Options", "medium", False,
                             "X-Content-Type-Options header is not set",
                             category,
                             remediation="Add X-Content-Type-Options: nosniff header.",
                             owasp="A05", nist="SC", pci_dss="PCI-6")
        else:
            self.add_finding("X-Content-Type-Options Present", "info", True,
                             "X-Content-Type-Options: " + hdr,
                             category, owasp="A05", nist="SC", pci_dss="PCI-6")

        hdr = headers.get("X-XSS-Protection", "")
        if not hdr:
            self.add_finding("Missing X-XSS-Protection", "low", False,
                             "X-XSS-Protection header is not set",
                             category,
                             remediation="Add X-XSS-Protection: 1; mode=block header.",
                             owasp="A05", nist="SC", pci_dss="PCI-6")
        else:
            self.add_finding("X-XSS-Protection Present", "info", True,
                             "X-XSS-Protection: " + hdr,
                             category, owasp="A05", nist="SC", pci_dss="PCI-6")

        hdr = headers.get("Referrer-Policy", "")
        if not hdr:
            self.add_finding("Missing Referrer-Policy", "medium", False,
                             "Referrer-Policy header is not set",
                             category,
                             remediation="Add Referrer-Policy: strict-origin-when-cross-origin header.",
                             owasp="A05", nist="SC", pci_dss="PCI-6")
        else:
            self.add_finding("Referrer-Policy Present", "info", True,
                             "Referrer-Policy: " + hdr,
                             category, owasp="A05", nist="SC", pci_dss="PCI-6")

        hdr = headers.get("Permissions-Policy", "")
        if not hdr:
            self.add_finding("Missing Permissions-Policy", "medium", False,
                             "Permissions-Policy header is not set",
                             category,
                             remediation="Add Permissions-Policy header to restrict browser features.",
                             owasp="A05", nist="SC", pci_dss="PCI-6")
        else:
            self.add_finding("Permissions-Policy Present", "info", True,
                             "Permissions-Policy: " + hdr,
                             category, owasp="A05", nist="SC", pci_dss="PCI-6")

        hdr = headers.get("Cross-Origin-Embedder-Policy", "")
        if not hdr:
            self.add_finding("Missing COEP", "low", False,
                             "Cross-Origin-Embedder-Policy header is not set",
                             category,
                             remediation="Add Cross-Origin-Embedder-Policy: require-corp header.",
                             owasp="A05", nist="SC", pci_dss="PCI-6")
        else:
            self.add_finding("COEP Present", "info", True,
                             "Cross-Origin-Embedder-Policy: " + hdr,
                             category, owasp="A05", nist="SC", pci_dss="PCI-6")

        hdr = headers.get("Cross-Origin-Opener-Policy", "")
        if not hdr:
            self.add_finding("Missing COOP", "low", False,
                             "Cross-Origin-Opener-Policy header is not set",
                             category,
                             remediation="Add Cross-Origin-Opener-Policy: same-origin header.",
                             owasp="A05", nist="SC", pci_dss="PCI-6")
        else:
            self.add_finding("COOP Present", "info", True,
                             "Cross-Origin-Opener-Policy: " + hdr,
                             category, owasp="A05", nist="SC", pci_dss="PCI-6")

        hdr = headers.get("Cross-Origin-Resource-Policy", "")
        if not hdr:
            self.add_finding("Missing CORP", "low", False,
                             "Cross-Origin-Resource-Policy header is not set",
                             category,
                             remediation="Add Cross-Origin-Resource-Policy: same-origin header.",
                             owasp="A05", nist="SC", pci_dss="PCI-6")
        else:
            self.add_finding("CORP Present", "info", True,
                             "Cross-Origin-Resource-Policy: " + hdr,
                             category, owasp="A05", nist="SC", pci_dss="PCI-6")

        xfo = headers.get("X-Frame-Options", "").upper()
        if xfo and xfo not in ("DENY", "SAMEORIGIN"):
            self.add_finding("Invalid X-Frame-Options", "high", False,
                             "Value '" + xfo + "' is not valid (must be DENY or SAMEORIGIN)",
                             category,
                             remediation="Set X-Frame-Options to DENY or SAMEORIGIN.",
                             owasp="A05", nist="SC", pci_dss="PCI-6")

        xcto = headers.get("X-Content-Type-Options", "").lower()
        if xcto and xcto != "nosniff":
            self.add_finding("Invalid X-Content-Type-Options", "high", False,
                             "Value '" + xcto + "' is not valid (must be nosniff)",
                             category,
                             remediation="Set X-Content-Type-Options to nosniff.",
                             owasp="A05", nist="SC", pci_dss="PCI-6")

        rp = headers.get("Referrer-Policy", "").lower()
        unsafe_values = ["unsafe-url", "no-referrer-when-downgrade", ""]
        if rp in unsafe_values:
            self.add_finding("Unsafe Referrer-Policy", "medium", False,
                             "Value '" + rp + "' may leak referrer information",
                             category,
                             remediation="Use strict-origin-when-cross-origin or no-referrer policy.",
                             owasp="A05", nist="SC", pci_dss="PCI-6")

    def check_disclosure(self):
        category = "disclosure"
        server = self.response.headers.get("Server", "")
        if server:
            version_pattern = re.search(r"[\d]+\.[\d]+", server)
            if version_pattern:
                self.add_finding("Server Version Disclosure", "medium", False,
                                 "Server header reveals version: " + server,
                                 category,
                                 remediation="Remove or obfuscate the Server header version information.",
                                 owasp="A05", nist="CM", pci_dss="PCI-2")
            else:
                self.add_finding("Server Header Present", "low", True,
                                 "Server header present (no version): " + server,
                                 category, owasp="A05", nist="CM", pci_dss="PCI-2")
        else:
            self.add_finding("No Server Header", "info", True,
                             "Server header is not disclosed",
                             category, owasp="A05", nist="CM", pci_dss="PCI-2")

        powered_by = self.response.headers.get("X-Powered-By", "")
        if powered_by:
            self.add_finding("X-Powered-By Disclosure", "medium", False,
                             "X-Powered-By: " + powered_by,
                             category,
                             remediation="Remove the X-Powered-By header.",
                             owasp="A05", nist="CM", pci_dss="PCI-2")
        else:
            self.add_finding("No X-Powered-By Header", "info", True,
                             "X-Powered-By header is not disclosed",
                             category, owasp="A05", nist="CM", pci_dss="PCI-2")

        asp_version = self.response.headers.get("X-AspNet-Version", "")
        if asp_version:
            self.add_finding("ASP.NET Version Disclosure", "medium", False,
                             "X-AspNet-Version: " + asp_version,
                             category,
                             remediation="Remove the X-AspNet-Version header.",
                             owasp="A05", nist="CM", pci_dss="PCI-2")

        asp_mvc = self.response.headers.get("X-AspNetMvc-Version", "")
        if asp_mvc:
            self.add_finding("ASP.NET MVC Version Disclosure", "medium", False,
                             "X-AspNetMvc-Version: " + asp_mvc,
                             category,
                             remediation="Remove the X-AspNetMvc-Version header.",
                             owasp="A05", nist="CM", pci_dss="PCI-2")

    def check_cookies(self):
        category = "cookies"
        cookies = self.session.cookies
        if not cookies:
            self.add_finding("No Cookies Set", "info", True,
                             "No cookies were set during the request",
                             category)
            return

        for cookie in cookies:
            name = cookie.name
            secure = cookie.secure
            httponly = hasattr(cookie, "_rest") and "HttpOnly" in cookie._rest
            samesite = cookie._rest.get("SameSite", "") if hasattr(cookie, "_rest") else ""
            if not hasattr(cookie, "_rest"):
                samesite = ""

            if self.scheme == "https" and not secure:
                self.add_finding("Cookie '" + name + "' Missing Secure Flag", "medium", False,
                                 "Cookie '" + name + "' does not have the Secure flag",
                                 category,
                                 remediation="Set the Secure flag on cookie '" + name + "'.",
                                 owasp="A05", nist="SC", pci_dss="PCI-4", hipaa="HIPAA-TX")
            elif self.scheme == "https":
                self.add_finding("Cookie '" + name + "' Secure Flag", "info", True,
                                 "Cookie '" + name + "' has Secure flag",
                                 category, owasp="A05", nist="SC", pci_dss="PCI-4")

            if not httponly:
                self.add_finding("Cookie '" + name + "' Missing HttpOnly", "medium", False,
                                 "Cookie '" + name + "' does not have the HttpOnly flag",
                                 category,
                                 remediation="Set the HttpOnly flag on cookie '" + name + "'.",
                                 owasp="A05", nist="SC", pci_dss="PCI-6")
            else:
                self.add_finding("Cookie '" + name + "' HttpOnly", "info", True,
                                 "Cookie '" + name + "' has HttpOnly flag",
                                 category, owasp="A05", nist="SC", pci_dss="PCI-6")

            if not samesite:
                self.add_finding("Cookie '" + name + "' Missing SameSite", "low", False,
                                 "Cookie '" + name + "' does not have SameSite attribute",
                                 category,
                                 remediation="Set SameSite=Lax or SameSite=Strict on cookie '" + name + "'.",
                                 owasp="A05", nist="SC", pci_dss="PCI-6")
            else:
                self.add_finding("Cookie '" + name + "' SameSite", "info", True,
                                 "Cookie '" + name + "' has SameSite=" + samesite,
                                 category, owasp="A05", nist="SC", pci_dss="PCI-6")

    def check_cookie_prefix(self):
        category = "cookies"
        cookies = self.session.cookies
        for cookie in cookies:
            name = cookie.name
            if name.startswith("__Host-"):
                if not cookie.secure:
                    self.add_finding("__Host- Cookie Missing Secure", "high", False,
                                     "__Host- prefixed cookie '" + name + "' must have Secure flag",
                                     category, cve="CVE-2023-XXXX",
                                     remediation="__Host- cookies require the Secure flag.",
                                     owasp="A05", nist="SC", pci_dss="PCI-4")
                if self.domain not in (cookie.domain or self.domain):
                    self.add_finding("__Host- Cookie Domain Mismatch", "high", False,
                                     "__Host- prefixed cookie '" + name + "' must be set on the exact host",
                                     category,
                                     remediation="__Host- cookies must not have a Domain attribute.",
                                     owasp="A05", nist="SC", pci_dss="PCI-4")
                self.add_finding("__Host- Cookie Prefix", "info", True,
                                 "Cookie '" + name + "' uses __Host- prefix (enhanced security)",
                                 category, owasp="A05", nist="SC", pci_dss="PCI-4")
            elif name.startswith("__Secure-"):
                if not cookie.secure:
                    self.add_finding("__Secure- Cookie Missing Secure", "high", False,
                                     "__Secure- prefixed cookie '" + name + "' must have Secure flag",
                                     category,
                                     remediation="__Secure- cookies require the Secure flag.",
                                     owasp="A05", nist="SC", pci_dss="PCI-4")
                self.add_finding("__Secure- Cookie Prefix", "info", True,
                                 "Cookie '" + name + "' uses __Secure- prefix (enhanced security)",
                                 category, owasp="A05", nist="SC", pci_dss="PCI-4")

    def check_cors(self):
        category = "cors"
        acao = self.response.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*":
            self.add_finding("CORS Wildcard Origin", "high", False,
                             "Access-Control-Allow-Origin is set to wildcard '*'",
                             category,
                             remediation="Replace wildcard with specific trusted origins.",
                             owasp="A05", nist="SC", pci_dss="PCI-6")
        elif acao:
            self.add_finding("CORS Origin Configured", "info", True,
                             "Access-Control-Allow-Origin: " + acao,
                             category, owasp="A05", nist="SC", pci_dss="PCI-6")
        else:
            self.add_finding("No CORS Headers", "info", True,
                             "No Access-Control-Allow-Origin header present",
                             category, owasp="A05", nist="SC", pci_dss="PCI-6")

        acac = self.response.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acac == "true" and acao == "*":
            self.add_finding("CORS Credentials with Wildcard", "critical", False,
                             "Access-Control-Allow-Credentials is true with wildcard origin",
                             category,
                             remediation="Never combine credentials=true with wildcard origin.",
                             owasp="A05", nist="SC", pci_dss="PCI-6")
        elif acac == "true":
            self.add_finding("CORS Credentials Allowed", "info", True,
                             "Access-Control-Allow-Credentials is true",
                             category, owasp="A05", nist="SC", pci_dss="PCI-6")

    def check_csp_analysis(self):
        category = "headers"
        csp = self.response.headers.get("Content-Security-Policy", "")
        if not csp:
            self.add_finding("Missing Content-Security-Policy", "critical", False,
                             "No CSP header - site lacks XSS and data injection protection",
                             category,
                             remediation="Implement a Content-Security-Policy header.",
                             owasp="A05", nist="SC", pci_dss="PCI-6")
            return

        self.add_finding("Content-Security-Policy Present", "info", True,
                         "CSP header is configured",
                         category, owasp="A05", nist="SC", pci_dss="PCI-6")

        directives = csp.split(";")
        issues = []
        for d in directives:
            d = d.strip()
            if not d:
                continue
            parts = d.split()
            if not parts:
                continue
            directive = parts[0].lower()
            values = parts[1:] if len(parts) > 1 else []

            if "unsafe-inline" in values:
                issues.append("unsafe-inline in " + directive)
            if "unsafe-eval" in values:
                issues.append("unsafe-eval in " + directive)
            if "'unsafe-hashes'" in values:
                issues.append("unsafe-hashes in " + directive)
            if "'unsafe-redirect'" in values:
                issues.append("unsafe-redirect in " + directive)
            if directive == "default-src" and "*" in values:
                issues.append("wildcard default-src")

        if issues:
            self.add_finding("CSP Weak Directives", "high", False,
                             "CSP has weak directives: " + "; ".join(issues),
                             category,
                             remediation="Remove unsafe-inline, unsafe-eval, and wildcard sources from CSP.",
                             owasp="A05", nist="SC", pci_dss="PCI-6")
        else:
            self.add_finding("CSP Strong Directives", "info", True,
                             "CSP directives appear properly configured",
                             category, owasp="A05", nist="SC", pci_dss="PCI-6")

        if "frame-ancestors" not in csp.lower():
            self.add_finding("CSP Missing frame-ancestors", "medium", False,
                             "CSP does not include frame-ancestors directive",
                             category,
                             remediation="Add frame-ancestors directive to CSP.",
                             owasp="A05", nist="SC", pci_dss="PCI-6")
        else:
            self.add_finding("CSP frame-ancestors", "info", True,
                             "CSP includes frame-ancestors directive",
                             category, owasp="A05", nist="SC", pci_dss="PCI-6")

        if "upgrade-insecure-requests" not in csp.lower():
            self.add_finding("CSP Missing upgrade-insecure-requests", "low", False,
                             "CSP does not include upgrade-insecure-requests directive",
                             category,
                             remediation="Add upgrade-insecure-requests directive to CSP.",
                             owasp="A02", nist="SC", pci_dss="PCI-4")
        else:
            self.add_finding("CSP upgrade-insecure-requests", "info", True,
                             "CSP includes upgrade-insecure-requests directive",
                             category, owasp="A02", nist="SC", pci_dss="PCI-4")

        if "require-sri-for" not in csp.lower():
            self.add_finding("CSP Missing require-sri-for", "low", False,
                             "CSP does not enforce Subresource Integrity",
                             category,
                             remediation="Add require-sri-for 'script' 'style' to CSP.",
                             owasp="A08", nist="SC", pci_dss="PCI-6")
        else:
            self.add_finding("CSP require-sri-for", "info", True,
                             "CSP enforces Subresource Integrity",
                             category, owasp="A08", nist="SC", pci_dss="PCI-6")

    def check_content_security(self):
        category = "content"
        if not self.soup:
            return

        http_resources = []
        for tag in self.soup.find_all(["script", "link", "img", "iframe", "video", "audio", "source", "form"]):
            attrs = ["src", "href", "action", "poster", "data"]
            for attr in attrs:
                val = tag.get(attr, "")
                if val.startswith("http://"):
                    http_resources.append(tag.name + "[" + attr + "]=" + val)

        if http_resources:
            self.add_finding("Mixed Content Detected", "high", False,
                             "Found " + str(len(http_resources)) + " HTTP resource(s) on HTTPS page",
                             category, cve="CVE-2018-XXXX",
                             remediation="Replace all HTTP resources with HTTPS equivalents.",
                             owasp="A02", nist="SC", pci_dss="PCI-4")
        else:
            self.add_finding("No Mixed Content", "info", True,
                             "No HTTP resources found on HTTPS page",
                             category, owasp="A02", nist="SC", pci_dss="PCI-4")

        insecure_forms = []
        for form in self.soup.find_all("form"):
            action = form.get("action", "")
            if action.startswith("http://"):
                insecure_forms.append(action)
        if insecure_forms:
            self.add_finding("Insecure Form Actions", "high", False,
                             "Found " + str(len(insecure_forms)) + " form(s) with HTTP actions",
                             category,
                             remediation="Use HTTPS for all form action URLs.",
                             owasp="A02", nist="SC", pci_dss="PCI-4")
        else:
            self.add_finding("Form Actions", "info", True,
                             "No insecure form actions found",
                             category, owasp="A02", nist="SC", pci_dss="PCI-4")

        inline_scripts = []
        for script in self.soup.find_all("script"):
            if script.string and script.string.strip():
                inline_scripts.append(script.string.strip()[:80])
        if inline_scripts:
            self.add_finding("Inline Scripts Detected", "medium", False,
                             "Found " + str(len(inline_scripts)) + " inline script(s)",
                             category,
                             remediation="Move inline scripts to external files and use CSP nonces or hashes.",
                             owasp="A03", nist="SC", pci_dss="PCI-6")
        else:
            self.add_finding("No Inline Scripts", "info", True,
                             "No inline scripts detected",
                             category, owasp="A03", nist="SC", pci_dss="PCI-6")

    def check_vulnerabilities(self):
        category = "vuln"
        headers = self.response.headers
        csp = headers.get("Content-Security-Policy", "")
        xfo = headers.get("X-Frame-Options", "")
        has_frame_protection = bool(xfo) or ("frame-ancestors" in csp)
        if not has_frame_protection:
            self.add_finding("Clickjacking Vulnerable", "high", False,
                             "No X-Frame-Options or CSP frame-ancestors directive",
                             category, cve="CVE-2022-XXXX",
                             remediation="Add X-Frame-Options: DENY or CSP frame-ancestors directive.",
                             owasp="A04", nist="SC", pci_dss="PCI-6")
        else:
            self.add_finding("Clickjacking Protected", "info", True,
                             "Frame protection is in place",
                             category, owasp="A04", nist="SC", pci_dss="PCI-6")

        xss_protection = headers.get("X-XSS-Protection", "")
        has_xss_protection = bool(xss_protection) or bool(csp)
        if not has_xss_protection:
            self.add_finding("XSS Protection Missing", "medium", False,
                             "No X-XSS-Protection header or CSP configured",
                             category,
                             remediation="Add X-XSS-Protection header and implement CSP.",
                             owasp="A03", nist="SC", pci_dss="PCI-6")
        else:
            self.add_finding("XSS Protection", "info", True,
                             "XSS protection is configured",
                             category, owasp="A03", nist="SC", pci_dss="PCI-6")

        xcto = headers.get("X-Content-Type-Options", "")
        if not xcto:
            self.add_finding("MIME Sniffing Vulnerable", "medium", False,
                             "No X-Content-Type-Options header",
                             category,
                             remediation="Add X-Content-Type-Options: nosniff header.",
                             owasp="A05", nist="SC", pci_dss="PCI-6")
        else:
            self.add_finding("MIME Sniffing Protected", "info", True,
                             "X-Content-Type-Options is set",
                             category, owasp="A05", nist="SC", pci_dss="PCI-6")

        if self.soup:
            external_scripts = []
            for script in self.soup.find_all("script", src=True):
                src = script["src"]
                if src.startswith("http://") or src.startswith("//"):
                    has_integrity = bool(script.get("integrity"))
                    external_scripts.append((src, has_integrity))
            insecure_ext = [(s, i) for s, i in external_scripts if not i]
            if insecure_ext:
                self.add_finding("Missing SRI on External Scripts", "medium", False,
                                 str(len(insecure_ext)) + " external script(s) lack SRI: " + insecure_ext[0][0],
                                 category, cve="CVE-2019-XXXX",
                                 remediation="Add integrity attributes to all external scripts.",
                                 owasp="A08", nist="SC", pci_dss="PCI-6")
            else:
                if external_scripts:
                    self.add_finding("Subresource Integrity", "info", True,
                                     "External scripts have SRI attributes",
                                     category, owasp="A08", nist="SC", pci_dss="PCI-6")

            external_styles = []
            for link in self.soup.find_all("link", rel="stylesheet", href=True):
                href = link["href"]
                if href.startswith("http://") or href.startswith("//"):
                    has_integrity = bool(link.get("integrity"))
                    external_styles.append((href, has_integrity))
            insecure_css = [(s, i) for s, i in external_styles if not i]
            if insecure_css:
                self.add_finding("Missing SRI on External Stylesheets", "medium", False,
                                 str(len(insecure_css)) + " external stylesheet(s) lack SRI: " + insecure_css[0][0],
                                 category,
                                 remediation="Add integrity attributes to all external stylesheets.",
                                 owasp="A08", nist="SC", pci_dss="PCI-6")

    def check_request_smuggling(self):
        category = "vuln"
        headers = self.response.headers
        te = headers.get("Transfer-Encoding", "")
        cl = headers.get("Content-Length", "")
        if te.lower() == "chunked" and cl:
            self.add_finding("Potential HTTP Request Smuggling", "high", False,
                             "Response has both Transfer-Encoding: chunked and Content-Length headers",
                             category,
                             remediation="Ensure proxy and backend agree on framing. Remove ambiguous headers.",
                             owasp="A04", nist="SC", pci_dss="PCI-6")
        elif te:
            te_variants = ["chunked", "Identity", "gzip, chunked"]
            te_lower = te.lower()
            has_obfuscation = any(v.lower() != te_lower for v in te_variants if v.lower() in te_lower)
            if has_obfuscation or " " in te or "\t" in te:
                self.add_finding("Transfer-Encoding Obfuscation", "medium", False,
                                 "Transfer-Encoding header may contain obfuscated values: " + te,
                                 category,
                                 remediation="Standardize Transfer-Encoding header format.",
                                 owasp="A04", nist="SC", pci_dss="PCI-6")

        te_header = te.lower()
        if "chunked" in te_header and "identity" in te_header:
            self.add_finding("Transfer-Encoding Conflict", "high", False,
                             "Transfer-Encoding contains both chunked and identity",
                             category,
                             remediation="Use a single, standard Transfer-Encoding value.",
                             owasp="A04", nist="SC", pci_dss="PCI-6")

    def check_ssrf_hints(self):
        category = "vuln"
        if not self.parsed.query:
            return

        params = parse_qs(self.parsed.query, keep_blank_values=True)
        ssrf_params = ["url", "uri", "path", "redirect", "return", "next", "continue",
                       "dest", "destination", "redir", "redirect_uri", "callback",
                       "feed", "link", "goto", "image", "img", "src", "file", "page"]
        found_ssrf = []
        for param in params:
            if param.lower() in ssrf_params:
                for val in params[param]:
                    if val.startswith("http://") or val.startswith("https://"):
                        found_ssrf.append(param)

        if found_ssrf:
            self.add_finding("Potential SSRF Vector", "high", False,
                             "URL parameters that accept URLs detected: " + ", ".join(found_ssrf),
                             category,
                             remediation="Validate and whitelist allowed URLs/destinations for these parameters.",
                             owasp="A10", nist="SC", pci_dss="PCI-6")

        forms = self.soup.find_all("form") if self.soup else []
        for form in forms:
            for inp in form.find_all("input"):
                name = inp.get("name", "").lower()
                if name in ssrf_params:
                    self.add_finding("Form SSRF Vector", "medium", False,
                                     "Form input '" + name + "' may accept URL values",
                                     category,
                                     remediation="Validate form inputs that accept URLs server-side.",
                                     owasp="A10", nist="SC", pci_dss="PCI-6")

    def check_open_redirect(self):
        category = "vuln"
        if not self.parsed.query:
            return

        params = parse_qs(self.parsed.query, keep_blank_values=True)
        redirect_params = ["url", "redirect", "return", "next", "continue", "dest",
                           "destination", "redir", "redirect_uri", "callback", "go",
                           "goto", "link", "out", "view", "to", "path", "ref"]
        for param in params:
            if param.lower() in redirect_params:
                for val in params[param]:
                    if val.startswith("http://") or val.startswith("https://"):
                        parsed_val = urlparse(val)
                        current_domain = self.domain.split(":")[0]
                        target_domain = parsed_val.netloc.split(":")[0]
                        if target_domain and target_domain != current_domain:
                            self.add_finding("Potential Open Redirect", "high", False,
                                             "Parameter '" + param + "' redirects to external domain: " + val,
                                             category,
                                             remediation="Validate redirect targets against a whitelist of allowed domains.",
                                             owasp="A01", nist="AC", pci_dss="PCI-6")

    def check_directory_traversal(self):
        category = "vuln"
        traversal_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "..\\..\\..\\etc\\passwd",
            "%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd",
            "../../../etc/shadow",
            "..%2f..%2f..%2fetc/passwd",
        ]
        traversal_indicators = [
            "root:", "daemon:", "nobody:", "/bin/bash", "/bin/sh",
            "[boot loader]", "[operating systems]",
        ]

        base_url = self.scheme + "://" + self.domain
        test_params = ["file", "path", "page", "include", "doc", "template", "dir"]
        vulnerable_params = []

        for param in test_params:
            for payload in traversal_payloads:
                test_url = base_url + "?" + param + "=" + payload
                try:
                    resp = self.session.get(test_url, timeout=self.timeout // 2, allow_redirects=False, verify=False)
                    body = resp.text.lower()
                    for indicator in traversal_indicators:
                        if indicator in body:
                            vulnerable_params.append(param)
                            break
                    if vulnerable_params:
                        break
                except requests.exceptions.RequestException:
                    pass
            if vulnerable_params:
                break

        if vulnerable_params:
            self.add_finding("Directory Traversal Vulnerable", "critical", False,
                             "Parameter(s) vulnerable to path traversal: " + ", ".join(vulnerable_params),
                             category, cve="CVE-2024-XXXX",
                             remediation="Validate and sanitize file path inputs. Use parameterized file access.",
                             owasp="A01", nist="AC", pci_dss="PCI-6")
        else:
            self.add_finding("Directory Traversal Test", "info", True,
                             "No obvious directory traversal vulnerabilities detected",
                             category, owasp="A01", nist="AC", pci_dss="PCI-6")

    def check_sql_injection(self):
        category = "vuln"
        sql_error_patterns = [
            "you have an error in your sql syntax",
            "warning: mysql_", "unclosed quotation mark",
            "microsoft ole db provider for odbc drivers",
            "microsoft ole db provider for sql server",
            "incorrect syntax near", "unterminated quoted string",
            "ora-00933", "ora-00921", "ora-01756",
            "postgresql", "sqlite3", "sqlcommand",
            "syntax error at or near", "pg_query", "pg_exec",
            "supplied argument is not a valid mysql",
            "mysql_num_rows", "mysql_fetch",
            "database error", "query failed", "sql error",
        ]

        response_text = self.response.text.lower()
        sql_errors_found = [p for p in sql_error_patterns if p in response_text]

        if sql_errors_found:
            self.add_finding("SQL Error Messages Detected", "high", False,
                             "Response contains SQL error messages: " + sql_errors_found[0],
                             category,
                             remediation="Disable detailed database error messages in production. Use parameterized queries.",
                             owasp="A03", nist="SI", pci_dss="PCI-6")

        test_payloads = ["'", "1' OR '1'='1", "1' AND '1'='1", "' OR 1=1--", "1; SELECT 1"]
        base_url = self.scheme + "://" + self.domain
        injectable = False

        for payload in test_payloads:
            test_url = base_url + "?id=" + payload
            try:
                resp = self.session.get(test_url, timeout=self.timeout // 2, allow_redirects=False, verify=False)
                body = resp.text.lower()
                for indicator in sql_error_patterns:
                    if indicator in body:
                        injectable = True
                        break
            except requests.exceptions.RequestException:
                pass
            if injectable:
                break

        if injectable:
            self.add_finding("Potential SQL Injection", "critical", False,
                             "Application may be vulnerable to SQL injection based on error response",
                             category, cve="CVE-2024-XXXX",
                             remediation="Use parameterized queries/prepared statements. Validate all user input.",
                             owasp="A03", nist="SI", pci_dss="PCI-6")

    def check_xss_reflection(self):
        category = "vuln"
        test_payload = "CSSTestXSS123"
        test_url = self.scheme + "://" + self.domain + "?" + "q=" + test_payload

        try:
            resp = self.session.get(test_url, timeout=self.timeout // 2, allow_redirects=False, verify=False)
            if test_payload in resp.text:
                in_html = test_payload in resp.text
                in_tags = ("<" + test_payload) in resp.text
                in_attrs = ("'" + test_payload) in resp.text or ('"' + test_payload) in resp.text

                if in_attrs:
                    self.add_finding("XSS Reflection in Attributes", "critical", False,
                                     "User input reflected in HTML attributes without encoding",
                                     category,
                                     remediation="HTML-encode all user input before rendering in attributes.",
                                     owasp="A03", nist="SC", pci_dss="PCI-6")
                elif in_tags:
                    self.add_finding("XSS Reflection in Tags", "high", False,
                                     "User input reflected inside HTML tags",
                                     category,
                                     remediation="HTML-encode all user input before rendering.",
                                     owasp="A03", nist="SC", pci_dss="PCI-6")
                elif in_html:
                    self.add_finding("XSS Reflection Detected", "medium", False,
                                     "User input reflected in page content",
                                     category,
                                     remediation="Sanitize and encode all user-supplied data before rendering.",
                                     owasp="A03", nist="SC", pci_dss="PCI-6")
        except requests.exceptions.RequestException:
            pass

    def check_sensitive_paths(self):
        category = "vuln"
        base_url = self.scheme + "://" + self.domain

        admin_paths = [
            "/admin/", "/admin/login", "/administrator/", "/wp-admin/",
            "/cpanel/", "/phpmyadmin/", "/pma/", "/adminer.php",
            "/console", "/manager/", "/backoffice/", "/dashboard/",
            "/_admin/", "/secure/", "/webadmin/", "/siteadmin/",
        ]

        backup_paths = [
            "/backup/", "/backup.zip", "/backup.sql", "/backup.tar.gz",
            "/db.sql", "/database.sql", "/dump.sql", "/data.sql",
            "/.bak", "/index.php.bak", "/config.php.bak",
            "/index.php.old", "/config.php.old",
            "/index.php.swp", "/.config.php.swp",
            "/backup.tar", "/backup.gz", "/site.zip", "/www.zip",
            "/public_html.zip", "/html.zip", "/web.zip",
        ]

        debug_paths = [
            "/debug", "/trace", "/actuator", "/actuator/health",
            "/actuator/env", "/actuator/info", "/actuator/beans",
            "/actuator/mappings", "/actuator/configprops",
            "/env", "/info", "/phpinfo.php", "/phpinfo",
            "/server-status", "/server-info", "/server-status?auto",
            "/_profiler", "/_wdt", "/debug/vars", "/debug/pprof",
            "/metrics", "/prometheus", "/manage", "/management",
        ]

        all_paths = (
            [(p, "Admin Panel") for p in admin_paths] +
            [(p, "Backup File") for p in backup_paths] +
            [(p, "Debug Endpoint") for p in debug_paths]
        )

        exposed = []
        for path, name in all_paths:
            try:
                check_url = base_url + path
                resp = self.session.head(check_url, timeout=self.timeout // 2, allow_redirects=False, verify=False)
                if resp.status_code == 200:
                    exposed.append(name + " (" + path + ")")
                elif resp.status_code in (301, 302, 303, 307, 308):
                    exposed.append(name + " (" + path + ") [redirect]")
                elif resp.status_code in (401, 403):
                    exposed.append(name + " (" + path + ") [auth required]")
            except requests.exceptions.RequestException:
                pass

        admin_found = [e for e in exposed if "Admin" in e]
        backup_found = [e for e in exposed if "Backup" in e]
        debug_found = [e for e in exposed if "Debug" in e]

        if admin_found:
            self.add_finding("Admin Panel Detected", "high", False,
                             "Accessible admin panels: " + "; ".join(admin_found[:5]),
                             category,
                             remediation="Restrict admin panels to internal networks or VPN.",
                             owasp="A01", nist="AC", pci_dss="PCI-7")
        if backup_found:
            self.add_finding("Backup Files Exposed", "high", False,
                             "Accessible backup files: " + "; ".join(backup_found[:5]),
                             category,
                             remediation="Remove backup files from production.",
                             owasp="A05", nist="CM", pci_dss="PCI-2")
        if debug_found:
            self.add_finding("Debug Endpoints Exposed", "high", False,
                             "Accessible debug endpoints: " + "; ".join(debug_found[:5]),
                             category,
                             remediation="Disable debug endpoints in production.",
                             owasp="A05", nist="CM", pci_dss="PCI-2")

        if not exposed:
            self.add_finding("Sensitive Paths", "info", True,
                             "No common sensitive paths exposed",
                             category, owasp="A05", nist="CM", pci_dss="PCI-2")
        elif not admin_found and not backup_found and not debug_found:
            self.add_finding("Sensitive Paths", "info", True,
                             "Some sensitive paths responded (auth required): " + "; ".join(exposed[:3]),
                             category)

    def check_dns(self):
        category = "dns"
        hostname = self.domain.split(":")[0]

        try:
            result = subprocess.run(
                ["nslookup", "-type=TXT", hostname],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout.lower()
            if "v=spf1" in output:
                self.add_finding("SPF Record Found", "info", True,
                                 "SPF record is configured",
                                 category, owasp="A05", nist="SC", pci_dss="PCI-12")
            else:
                self.add_finding("No SPF Record", "medium", False,
                                 "No SPF record found - email spoofing risk",
                                 category,
                                 remediation="Configure an SPF record to prevent email spoofing.",
                                 owasp="A05", nist="SC", pci_dss="PCI-12")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.add_finding("SPF Record Check", "info", True,
                             "Could not check SPF record (nslookup unavailable)",
                             category)

        try:
            result = subprocess.run(
                ["nslookup", "-type=TXT", "_dmarc." + hostname],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout.lower()
            if "v=dmarc1" in output:
                self.add_finding("DMARC Record Found", "info", True,
                                 "DMARC record is configured",
                                 category, owasp="A05", nist="SC", pci_dss="PCI-12")
            else:
                self.add_finding("No DMARC Record", "medium", False,
                                 "No DMARC record found - email spoofing risk",
                                 category,
                                 remediation="Configure a DMARC record to protect against email spoofing.",
                                 owasp="A05", nist="SC", pci_dss="PCI-12")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.add_finding("DMARC Record Check", "info", True,
                             "Could not check DMARC record (nslookup unavailable)",
                             category)

        try:
            result = subprocess.run(
                ["nslookup", "-type=DNSKEY", hostname],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout.lower()
            if "dnskey" in output:
                self.add_finding("DNSSEC Enabled", "info", True,
                                 "DNSSEC is configured",
                                 category, owasp="A05", nist="SC", pci_dss="PCI-12")
            else:
                self.add_finding("No DNSSEC", "low", False,
                                 "DNSSEC not detected - DNS responses may be spoofed",
                                 category,
                                 remediation="Enable DNSSEC to protect against DNS spoofing attacks.",
                                 owasp="A05", nist="SC", pci_dss="PCI-12")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.add_finding("DNSSEC Check", "info", True,
                             "Could not check DNSSEC (nslookup unavailable)",
                             category)

    def check_dns_caa(self):
        category = "dns"
        hostname = self.domain.split(":")[0]
        try:
            result = subprocess.run(
                ["nslookup", "-type=257", hostname],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout.lower()
            if "0 issue" in output or "0 issuewild" in output:
                self.add_finding("DNS CAA Record Found", "info", True,
                                 "CAA record restricts certificate issuance",
                                 category, owasp="A05", nist="SC", pci_dss="PCI-12")
            else:
                self.add_finding("No DNS CAA Record", "low", False,
                                 "No CAA record - any CA can issue certificates for this domain",
                                 category,
                                 remediation="Add a CAA record to restrict which CAs can issue certificates.",
                                 owasp="A05", nist="SC", pci_dss="PCI-12")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.add_finding("DNS CAA Check", "info", True,
                             "Could not check CAA record (nslookup unavailable)",
                             category)

    def check_certificate_transparency(self):
        category = "ssl"
        if self.scheme != "https":
            return

        hostname = self.domain.split(":")[0]
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    if cert:
                        sct_present = b"\x04\x00\x00" in cert
                        if sct_present:
                            self.add_finding("Certificate Transparency", "info", True,
                                             "Certificate contains SCT (Certificate Transparency)",
                                             category, owasp="A02", nist="SC", pci_dss="PCI-4")
                        else:
                            self.add_finding("Certificate Transparency", "low", False,
                                             "Certificate does not contain SCT",
                                             category,
                                             remediation="Use a CA that supports Certificate Transparency.",
                                             owasp="A02", nist="SC", pci_dss="PCI-4")
        except Exception:
            self.add_finding("Certificate Transparency Check", "info", True,
                             "Could not check certificate transparency",
                             category)

    def check_ocsp_stapling(self):
        category = "ssl"
        if self.scheme != "https":
            return

        hostname = self.domain.split(":")[0]
        try:
            result = subprocess.run(
                ["openssl", "s_client", "-connect", hostname + ":443", "-status", "-servername", hostname],
                input="", capture_output=True, text=True, timeout=self.timeout
            )
            output = result.stdout
            if "OCSP Response Status: successful" in output:
                self.add_finding("OCSP Stapling Enabled", "info", True,
                                 "OCSP stapling is configured",
                                 category, owasp="A02", nist="SC", pci_dss="PCI-4")
            elif "OCSP response: no response sent" in output:
                self.add_finding("OCSP Stapling Disabled", "low", False,
                                 "OCSP stapling is not enabled",
                                 category,
                                 remediation="Enable OCSP stapling on your web server.",
                                 owasp="A02", nist="SC", pci_dss="PCI-4")
            else:
                self.add_finding("OCSP Stapling Check", "info", True,
                                 "Could not determine OCSP stapling status",
                                 category)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.add_finding("OCSP Stapling Check", "info", True,
                             "Could not check OCSP stapling (openssl unavailable)",
                             category)

    def check_bounce_clickjacking(self):
        category = "vuln"
        base_url = self.scheme + "://" + self.domain
        test_paths = [
            "/redirect", "/bounce", "/url", "/link", "/out",
            "/goto", "/forward", "/redir", "/external",
        ]
        params_to_test = ["url", "redirect", "next", "return", "dest", "goto"]

        for path in test_paths:
            for param in params_to_test:
                test_url = base_url + path + "?" + param + "=https://evil.example.com"
                try:
                    resp = self.session.get(test_url, timeout=self.timeout // 2, allow_redirects=False, verify=False)
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("Location", "")
                        if "evil.example.com" in location:
                            self.add_finding("Open Redirect Endpoint", "high", False,
                                             "Endpoint " + path + " redirects to unvalidated URL via " + param,
                                             category,
                                             remediation="Validate redirect targets against a whitelist.",
                                             owasp="A01", nist="AC", pci_dss="PCI-6")
                            return
                except requests.exceptions.RequestException:
                    pass

        self.add_finding("Bounce/Redirect Test", "info", True,
                         "No open redirect endpoints found in common paths",
                         category, owasp="A01", nist="AC", pci_dss="PCI-6")

    def check_compliance(self):
        category = "compliance"
        if not self.soup:
            return

        body_text = self.soup.get_text().lower()
        links = self.soup.find_all("a", href=True)
        link_texts = [a.get_text().lower() for a in links]
        link_hrefs = [a["href"].lower() for a in links]

        privacy_keywords = ["privacy", "privacy policy", "data protection"]
        has_privacy = any(kw in body_text for kw in privacy_keywords) or any(
            kw in "".join(link_texts) for kw in privacy_keywords
        ) or any("privacy" in h for h in link_hrefs)
        if has_privacy:
            self.add_finding("Privacy Policy Link", "info", True,
                             "Privacy policy link detected",
                             category, owasp="A01", nist="AC", pci_dss="PCI-12")
        else:
            self.add_finding("No Privacy Policy", "medium", False,
                             "No privacy policy link detected",
                             category,
                             remediation="Add a privacy policy page and link it prominently.",
                             owasp="A01", nist="AC", pci_dss="PCI-12")

        cookie_keywords = ["cookie", "cookie consent", "cookie policy", "accept cookies",
                           "we use cookies", "cookie notice"]
        has_cookie_notice = any(kw in body_text for kw in cookie_keywords)
        if has_cookie_notice:
            self.add_finding("Cookie Consent Mechanism", "info", True,
                             "Cookie consent mechanism detected",
                             category, owasp="A01", nist="AC", pci_dss="PCI-12")
        else:
            self.add_finding("No Cookie Consent", "medium", False,
                             "No cookie consent mechanism detected",
                             category,
                             remediation="Implement a cookie consent banner for GDPR/ePrivacy compliance.",
                             owasp="A01", nist="AC", pci_dss="PCI-12")

        tos_keywords = ["terms", "terms of service", "terms and conditions", "tos"]
        has_tos = any(kw in body_text for kw in tos_keywords) or any(
            kw in "".join(link_texts) for kw in tos_keywords
        ) or any("terms" in h for h in link_hrefs)
        if has_tos:
            self.add_finding("Terms of Service Link", "info", True,
                             "Terms of service link detected",
                             category, owasp="A01", nist="AC", pci_dss="PCI-12")
        else:
            self.add_finding("No Terms of Service", "low", False,
                             "No terms of service link detected",
                             category,
                             remediation="Add a terms of service page.",
                             owasp="A01", nist="AC", pci_dss="PCI-12")

    # ──────────────────────────────────────────────────────────────────
    # API Security Checks (v4.0)
    # ──────────────────────────────────────────────────────────────────

    def check_api_endpoints(self):
        category = "api"
        base_url = self.scheme + "://" + self.domain
        api_paths = [
            "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
            "/rest/", "/rest/v1/", "/rest/v2/",
            "/graphql", "/graphiql", "/v1/", "/v2/",
            "/swagger/", "/swagger.json", "/swagger-ui/",
            "/openapi.json", "/openapi.yaml", "/api-docs/",
            "/.well-known/openapi.json",
            "/api/health", "/api/status", "/api/info",
            "/api/config", "/api/users", "/api/auth",
            "/api/login", "/api/register", "/api/signup",
            "/api/search", "/api/admin",
        ]

        found_endpoints = []
        for path in api_paths:
            try:
                check_url = base_url + path
                resp = self.session.get(check_url, timeout=self.timeout // 2, allow_redirects=False, verify=False)
                if resp.status_code in (200, 201, 204, 400, 401, 403, 405, 422):
                    content_type = resp.headers.get("Content-Type", "")
                    if any(ct in content_type for ct in ["json", "xml", "yaml", "openapi"]):
                        found_endpoints.append(path)
                        self.api_endpoints_found.append(path)
                    elif resp.status_code in (200, 201) and len(resp.text) > 10:
                        found_endpoints.append(path)
                        self.api_endpoints_found.append(path)
            except requests.exceptions.RequestException:
                pass

        if found_endpoints:
            self.add_finding("API Endpoints Discovered", "info", True,
                             "Found " + str(len(found_endpoints)) + " API endpoint(s): " + "; ".join(found_endpoints[:5]),
                             category,
                             remediation="Ensure all API endpoints require authentication and rate limiting.",
                             owasp="A01", nist="AC", pci_dss="PCI-7")
        else:
            self.add_finding("API Endpoints", "info", True,
                             "No common API endpoints discovered",
                             category)

    def check_graphql(self):
        category = "api"
        base_url = self.scheme + "://" + self.domain
        graphql_paths = ["/graphql", "/graphiql", "/api/graphql", "/query"]
        graphql_detected = False

        for path in graphql_paths:
            try:
                check_url = base_url + path
                introspection_query = '{"query":"{ __schema { types { name } } }"}'
                resp = self.session.post(
                    check_url,
                    data=introspection_query,
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout // 2,
                    verify=False
                )
                if resp.status_code == 200:
                    resp_text = resp.text.lower()
                    if "__schema" in resp_text or "types" in resp_text:
                        self.graphql_detected = True
                        graphql_detected = True
                        self.add_finding("GraphQL Introspection Enabled", "high", False,
                                         "GraphQL introspection is enabled at " + path,
                                         category,
                                         remediation="Disable GraphQL introspection in production.",
                                         owasp="A01", nist="AC", pci_dss="PCI-7")
                        break
            except requests.exceptions.RequestException:
                pass

        if not graphql_detected:
            self.add_finding("GraphQL Check", "info", True,
                             "No GraphQL endpoints detected",
                             category)

    def check_api_versioning(self):
        category = "api"
        if not self.api_endpoints_found:
            return

        version_patterns = [
            (r"/v(\d+)/", "URL path versioning"),
            (r"/api/v(\d+)/", "URL path API versioning"),
        ]

        headers_to_check = ["X-API-Version", "Api-Version", "X-Version",
                            "Accept-Version", "X-Api-Version"]

        detected_methods = []
        for endpoint in self.api_endpoints_found[:3]:
            for pattern, method_name in version_patterns:
                if re.search(pattern, endpoint):
                    if method_name not in detected_methods:
                        detected_methods.append(method_name)

        for header in headers_to_check:
            if header.lower() in [h.lower() for h in self.response.headers.keys()]:
                detected_methods.append("Header: " + header)

        if detected_methods:
            self.add_finding("API Versioning Detected", "info", True,
                             "API versioning methods: " + ", ".join(detected_methods),
                             category,
                             remediation="Use consistent API versioning strategy.",
                             owasp="A05", nist="SC")
        else:
            self.add_finding("No API Versioning Detected", "medium", False,
                             "No API versioning strategy detected",
                             category,
                             remediation="Implement API versioning to manage breaking changes.",
                             owasp="A05", nist="SC")

    def check_api_rate_limiting(self):
        category = "api"
        base_url = self.scheme + "://" + self.domain

        rate_limit_headers = ["X-RateLimit-Limit", "X-RateLimit-Remaining",
                              "X-RateLimit-Reset", "Retry-After",
                              "X-Rate-Limit-Limit", "X-Rate-Limit-Remaining"]
        found_headers = []
        for header in rate_limit_headers:
            if header.lower() in [h.lower() for h in self.response.headers.keys()]:
                found_headers.append(header)

        if found_headers:
            self.add_finding("Rate Limiting Headers Present", "info", True,
                             "Rate limiting headers detected: " + ", ".join(found_headers),
                             category,
                             remediation="Ensure rate limits are properly configured.",
                             owasp="A05", nist="SC")
        else:
            self.add_finding("No Rate Limiting Headers", "medium", False,
                             "No rate limiting headers detected",
                             category,
                             remediation="Implement rate limiting with appropriate headers.",
                             owasp="A05", nist="SC")

        test_url = base_url + "/api/"
        if self.api_endpoints_found:
            test_url = base_url + self.api_endpoints_found[0]

        rapid_requests = 5
        fast_responses = 0
        for _ in range(rapid_requests):
            try:
                resp = self.session.get(test_url, timeout=self.timeout // 2, verify=False)
                if resp.status_code not in (429, 503):
                    fast_responses += 1
            except requests.exceptions.RequestException:
                pass

        if fast_responses == rapid_requests:
            self.add_finding("No Rate Limiting Enforced", "medium", False,
                             "Sent " + str(rapid_requests) + " rapid requests without rate limiting (no 429/503)",
                             category,
                             remediation="Implement server-side rate limiting to prevent abuse.",
                             owasp="A05", nist="SC")

    def check_api_auth_bypass(self):
        category = "api"
        base_url = self.scheme + "://" + self.domain

        auth_bypass_paths = [
            "/api/admin", "/api/users", "/api/config",
            "/api/internal", "/api/debug", "/api/metrics",
        ]

        for path in auth_bypass_paths:
            check_url = base_url + path
            try:
                resp = self.session.get(check_url, timeout=self.timeout // 2, verify=False)
                if resp.status_code == 200:
                    content = resp.text.lower()
                    sensitive_indicators = ["password", "token", "secret", "api_key",
                                            "database", "config", "admin", "user"]
                    found_sensitive = [ind for ind in sensitive_indicators if ind in content]
                    if found_sensitive:
                        self.add_finding("API Authentication Bypass", "critical", False,
                                         "Endpoint " + path + " accessible without auth, exposes: " + ", ".join(found_sensitive[:3]),
                                         category,
                                         remediation="Implement proper authentication and authorization on all API endpoints.",
                                         owasp="A01", nist="AC", pci_dss="PCI-7", hipaa="HIPAA-AC")
            except requests.exceptions.RequestException:
                pass

        self.add_finding("API Auth Bypass Test", "info", True,
                         "Tested " + str(len(auth_bypass_paths)) + " paths for auth bypass",
                         category)

    def check_api_input_validation(self):
        category = "api"
        base_url = self.scheme + "://" + self.domain

        ssti_payloads = [
            "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
        ]

        for payload in ssti_payloads:
            try:
                test_url = base_url + "?q=" + payload
                resp = self.session.get(test_url, timeout=self.timeout // 2, verify=False)
                if "49" in resp.text and payload not in resp.text:
                    self.add_finding("Server-Side Template Injection", "critical", False,
                                     "SSTI payload executed: " + payload + " produced 49",
                                     category,
                                     remediation="Use sandboxed template engines. Avoid rendering user input in templates.",
                                     owasp="A03", nist="SI", pci_dss="PCI-6")
                    break
            except requests.exceptions.RequestException:
                pass

        deserialization_payloads = [
            "rO0ABXNyABNqYXZhLnV0aWwuSGFzaE1hcA==" + "=" * 40,
            "eyJtZXRob2QiOiAidGVzdCJ9",
        ]

        for payload in deserialization_payloads:
            try:
                test_url = base_url + "?data=" + payload
                resp = self.session.get(test_url, timeout=self.timeout // 2, verify=False)
                if resp.status_code == 500:
                    error_content = resp.text.lower()
                    if "deserializ" in error_content or "invalid" in error_content:
                        self.add_finding("Deserialization Vulnerability Hint", "high", False,
                                         "Deserialization payload triggered error response",
                                         category,
                                         remediation="Avoid deserializing untrusted data. Use safe serialization formats.",
                                         owasp="A08", nist="SI", pci_dss="PCI-6")
                        break
            except requests.exceptions.RequestException:
                pass

        nosql_payloads = [
            '{"$gt": ""}', '{"$ne": ""}',
            '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
        ]

        for payload in nosql_payloads:
            try:
                resp = self.session.post(
                    base_url + "/api/login",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout // 2,
                    verify=False
                )
                if resp.status_code == 200:
                    self.add_finding("NoSQL Injection Vector", "high", False,
                                     "NoSQL injection payload accepted at /api/login",
                                     category,
                                     remediation="Validate input types. Use ORM/ODM with strict schema validation.",
                                     owasp="A03", nist="SI", pci_dss="PCI-6")
                    break
            except requests.exceptions.RequestException:
                pass

        self.add_finding("Advanced Input Validation Test", "info", True,
                         "Tested SSTI, deserialization, and NoSQL injection vectors",
                         category)

    def check_api_response_analysis(self):
        category = "api"
        if not self.response:
            return

        headers = self.response.headers

        server_timing = headers.get("Server-Timing", "")
        if server_timing:
            self.add_finding("Server-Timing Header Exposed", "low", False,
                             "Server-Timing header may leak internal details: " + server_timing[:100],
                             category,
                             remediation="Remove or restrict Server-Timing header in production.",
                             owasp="A05", nist="CM")

        x_powered = headers.get("X-Powered-By", "")
        x_runtime = headers.get("X-Runtime", "")

        if x_powered or x_runtime:
            self.add_finding("API Implementation Disclosure", "medium", False,
                             "Headers reveal implementation details: " + (x_powered or "") + " " + (x_runtime or ""),
                             category,
                             remediation="Remove implementation-revealing headers.",
                             owasp="A05", nist="CM")

        x_request_id = headers.get("X-Request-Id", "")
        if x_request_id:
            self.add_finding("X-Request-Id Header Present", "info", True,
                             "Request ID tracking is configured",
                             category, owasp="A09", nist="AU")

        if self.soup:
            error_indicators = ["stack trace", "exception", "traceback",
                                "debug", "internal server error"]
            page_text = self.soup.get_text().lower()
            found_debug = [ind for ind in error_indicators if ind in page_text]
            if found_debug:
                self.add_finding("Debug Information Exposed", "high", False,
                                 "Page contains debug information: " + ", ".join(found_debug[:3]),
                                 category,
                                 remediation="Disable debug mode and error display in production.",
                                 owasp="A05", nist="CM")

    # ──────────────────────────────────────────────────────────────────
    # Container & Cloud Security (v4.0)
    # ──────────────────────────────────────────────────────────────────

    def check_container_security(self):
        category = "container"
        headers = self.response.headers

        docker_indicators = []
        if "Docker" in headers.get("Server", ""):
            docker_indicators.append("Docker in Server header")
        if headers.get("X-Docker-Endpoints"):
            docker_indicators.append("X-Docker-Endpoints header")
        if "docker" in self.response.text.lower():
            docker_indicators.append("Docker mentioned in page")

        if docker_indicators:
            self.add_finding("Docker Detected", "medium", False,
                             "Docker indicators found: " + ", ".join(docker_indicators),
                             category,
                             remediation="Ensure Docker configurations follow security best practices.",
                             owasp="A05", nist="CM")
            self.container_hints.append("docker")
        else:
            self.add_finding("No Docker Indicators", "info", True,
                             "No Docker-specific indicators detected",
                             category)

        k8s_paths = [
            "/api/v1/namespaces", "/api/v1/pods", "/api/v1/services",
            "/apis", "/healthz", "/version",
        ]
        k8s_found = []
        base_url = self.scheme + "://" + self.domain
        for path in k8s_paths:
            try:
                resp = self.session.get(base_url + path, timeout=self.timeout // 2, verify=False)
                if resp.status_code in (200, 401, 403):
                    try:
                        data = resp.json()
                        if "kind" in data or "apiVersion" in data:
                            k8s_found.append(path)
                    except (json.JSONDecodeError, ValueError):
                        pass
            except requests.exceptions.RequestException:
                pass

        if k8s_found:
            self.add_finding("Kubernetes API Detected", "high", False,
                             "Kubernetes API endpoints accessible: " + ", ".join(k8s_found),
                             category,
                             remediation="Restrict Kubernetes API access. Use RBAC and network policies.",
                             owasp="A01", nist="AC")
            self.container_hints.append("kubernetes")
        else:
            self.add_finding("No Kubernetes Indicators", "info", True,
                             "No Kubernetes API endpoints detected",
                             category)

        cloud_indicators = {
            "aws": [
                ("Server", "AmazonS3"), ("Server", "CloudFront"),
                ("x-amz", headers.get("x-amz-request-id", "")),
            ],
            "gcp": [
                ("Server", "Google"), ("Server", "gcloud"),
            ],
            "azure": [
                ("Server", "Microsoft-IIS"), ("Server", "Azure"),
                ("x-ms", headers.get("x-ms-request-id", "")),
            ],
        }

        for provider, indicators in cloud_indicators.items():
            for header_name, header_val in indicators:
                if header_val:
                    if isinstance(header_val, str) and header_val:
                        self.add_finding(
                            provider.upper() + " Cloud Detected", "info", True,
                            provider.upper() + " indicator: " + header_name + " header present",
                            category, owasp="A05", nist="CM"
                        )
                        self.cloud_provider = provider
                        break

        serverless_indicators = []
        server = headers.get("Server", "")
        if "CloudFront" in server:
            serverless_indicators.append("CloudFront (possible Lambda@Edge)")
        if headers.get("x-amz-invocation-type"):
            serverless_indicators.append("Lambda invocation header")

        if serverless_indicators:
            self.add_finding("Serverless Infrastructure Detected", "info", True,
                             "Serverless indicators: " + ", ".join(serverless_indicators),
                             category,
                             remediation="Review serverless function permissions and cold start security.",
                             owasp="A05", nist="CM")
        else:
            self.add_finding("No Serverless Indicators", "info", True,
                             "No serverless infrastructure indicators detected",
                             category)

        escape_hints = []
        if docker_indicators:
            escape_hints.append("Docker environment - check for privileged containers")
        if k8s_found:
            escape_hints.append("Kubernetes - verify Pod Security Policies/Standards")
        if self.cloud_provider:
            escape_hints.append("Cloud provider - review IAM roles and instance metadata")

        if escape_hints:
            self.add_finding("Container Escape Considerations", "low", False,
                             "Container/cloud environment detected. Review: " + "; ".join(escape_hints),
                             category,
                             remediation="Apply principle of least privilege. Use Pod Security Standards.",
                             owasp="A05", nist="AC")

    # ──────────────────────────────────────────────────────────────────
    # Advanced Vulnerability Detection (v4.0 / v5.0)
    # ──────────────────────────────────────────────────────────────────

    def check_advanced_vulnerabilities(self):
        category = "advanced_vuln"
        self.check_ssrf_internal(category)
        self.check_xxe(category)
        self.check_template_injection(category)
        self.check_deserialization(category)
        self.check_ldap_injection(category)
        self.check_nosql_injection(category)
        self.check_prototype_pollution(category)
        self.check_advanced_sqli(category)
        self.check_advanced_xss_dom(category)
        self.check_advanced_csrf(category)
        self.check_advanced_ssrf_rebinding(category)
        self.check_advanced_prototype_pollution(category)
        self.check_dom_clobbering(category)
        self.check_css_injection(category)
        self.check_html_injection(category)
        self.check_header_injection(category)

    def check_ssrf_internal(self, category):
        base_url = self.scheme + "://" + self.domain
        internal_targets = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/",
            "http://localhost:8080/", "http://127.0.0.1:8080/",
        ]

        ssrf_params = ["url", "uri", "path", "src", "dest", "redirect",
                       "fetch", "load", "include", "file", "page"]
        found_ssrf = False

        for param in ssrf_params:
            for target in internal_targets:
                test_url = base_url + "?" + param + "=" + target
                try:
                    resp = self.session.get(test_url, timeout=self.timeout // 2, allow_redirects=False, verify=False)
                    body = resp.text.lower()
                    internal_indicators = ["ami-id", "instance-id", "iam/",
                                           "metadata", "credentials",
                                           "hostname", "local-ipv4"]
                    if any(ind in body for ind in internal_indicators):
                        self.add_finding("SSRF to Internal Metadata", "critical", False,
                                         "Parameter '" + param + "' can access internal metadata: " + target,
                                         category, cve="CVE-2024-SSRF",
                                         remediation="Validate and whitelist URLs. Block access to internal IP ranges.",
                                         owasp="A10", nist="SC", pci_dss="PCI-6",
                                         attack_vector="Network", exploitability=2.0, impact=1.5)
                        found_ssrf = True
                        break
                except requests.exceptions.RequestException:
                    pass
            if found_ssrf:
                break

        if not found_ssrf:
            self.add_finding("SSRF Internal Access Test", "info", True,
                             "No SSRF to internal metadata detected",
                             category, owasp="A10", nist="SC")

    def check_xxe(self, category):
        base_url = self.scheme + "://" + self.domain
        xxe_payloads = [
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><root>&xxe;</root>',
        ]

        xxe_indicators = ["root:", "daemon:", "nobody:", "/bin/bash",
                          "ami-id", "instance-id"]

        for payload in xxe_payloads:
            try:
                resp = self.session.post(
                    base_url,
                    data=payload,
                    headers={"Content-Type": "application/xml"},
                    timeout=self.timeout // 2,
                    verify=False
                )
                body = resp.text.lower()
                if any(ind in body for ind in xxe_indicators):
                    self.add_finding("XXE Vulnerability", "critical", False,
                                     "XML External Entity injection possible",
                                     category, cve="CVE-2024-XXE",
                                     remediation="Disable XML external entity processing. Use JSON instead of XML where possible.",
                                     owasp="A05", nist="SC", pci_dss="PCI-6",
                                     attack_vector="Network", exploitability=1.5, impact=2.0)
                    return
            except requests.exceptions.RequestException:
                pass

        self.add_finding("XXE Test", "info", True,
                         "No XXE vulnerability detected",
                         category, owasp="A05", nist="SC")

    def check_template_injection(self, category):
        base_url = self.scheme + "://" + self.domain
        ssti_payloads = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("#{7*7}", "49"),
        ]

        for payload, expected in ssti_payloads:
            try:
                test_url = base_url + "?q=" + payload
                resp = self.session.get(test_url, timeout=self.timeout // 2, verify=False)
                if expected.lower() in resp.text.lower():
                    self.add_finding("Server-Side Template Injection", "critical", False,
                                     "SSTI payload executed: " + payload,
                                     category, cve="CVE-2024-SSTI",
                                     remediation="Use sandboxed template engines. Avoid rendering user input in templates.",
                                     owasp="A03", nist="SI", pci_dss="PCI-6",
                                     attack_vector="Network", exploitability=2.0, impact=1.5)
                    return
            except requests.exceptions.RequestException:
                pass

        self.add_finding("SSTI Test", "info", True,
                         "No server-side template injection detected",
                         category, owasp="A03", nist="SI")

    def check_deserialization(self, category):
        base_url = self.scheme + "://" + self.domain
        deser_payloads = [
            "rO0ABXNyABNqYXZhLnV0aWwuSGFzaE1hcA==" + "=" * 40,
            "eyJtZXRob2QiOiAidGVzdCJ9",
            "gAN9cQo=",
        ]

        for payload in deser_payloads:
            try:
                test_url = base_url + "?data=" + payload
                resp = self.session.get(test_url, timeout=self.timeout // 2, verify=False)
                if resp.status_code == 500:
                    error_content = resp.text.lower()
                    deser_errors = ["deserializ", "invalid", "corrupt",
                                    "stream", "classnotfound", "readobject"]
                    if any(err in error_content for err in deser_errors):
                        self.add_finding("Deserialization Vulnerability Hint", "high", False,
                                         "Deserialization payload triggered error: " + payload[:20],
                                         category,
                                         remediation="Avoid deserializing untrusted data. Use safe serialization formats like JSON.",
                                         owasp="A08", nist="SI", pci_dss="PCI-6",
                                         attack_vector="Network", exploitability=1.5, impact=1.5)
                        return
            except requests.exceptions.RequestException:
                pass

        self.add_finding("Deserialization Test", "info", True,
                         "No deserialization vulnerability detected",
                         category, owasp="A08", nist="SI")

    def check_ldap_injection(self, category):
        base_url = self.scheme + "://" + self.domain
        ldap_payloads = [
            "*)(objectClass=*",
            "*()|&'",
            "admin*)(&)",
            "*)(cn=*)",
        ]

        ldap_indicators = ["ldap", "distinguished name", "naming context",
                           "objectclass", "invalid dn"]

        for payload in ldap_payloads:
            try:
                test_url = base_url + "?user=" + payload
                resp = self.session.get(test_url, timeout=self.timeout // 2, verify=False)
                body = resp.text.lower()
                if any(ind in body for ind in ldap_indicators):
                    self.add_finding("LDAP Injection Vulnerability", "high", False,
                                     "LDAP injection payload triggered response: " + payload,
                                     category,
                                     remediation="Use parameterized LDAP queries. Validate and sanitize LDAP input.",
                                     owasp="A03", nist="SI", pci_dss="PCI-6",
                                     attack_vector="Network", exploitability=1.5, impact=1.0)
                    return
            except requests.exceptions.RequestException:
                pass

        self.add_finding("LDAP Injection Test", "info", True,
                         "No LDAP injection vulnerability detected",
                         category, owasp="A03", nist="SI")

    def check_nosql_injection(self, category):
        base_url = self.scheme + "://" + self.domain
        nosql_payloads = [
            '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
            '{"$gt": ""}',
            '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}',
        ]

        for payload in nosql_payloads:
            try:
                resp = self.session.post(
                    base_url + "/api/login",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout // 2,
                    verify=False
                )
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, dict) and ("token" in data or "user" in data):
                            self.add_finding("NoSQL Injection Vulnerability", "critical", False,
                                             "NoSQL injection bypasses authentication at /api/login",
                                             category,
                                             remediation="Validate input types. Use ORM/ODM with strict schema validation.",
                                             owasp="A03", nist="SI", pci_dss="PCI-6",
                                             attack_vector="Network", exploitability=2.0, impact=1.5)
                            return
                    except (json.JSONDecodeError, ValueError):
                        pass
            except requests.exceptions.RequestException:
                pass

        self.add_finding("NoSQL Injection Test", "info", True,
                         "No NoSQL injection vulnerability detected",
                         category, owasp="A03", nist="SI")

    def check_prototype_pollution(self, category):
        base_url = self.scheme + "://" + self.domain
        pollution_payloads = [
            '{"__proto__": {"isAdmin": true}}',
            '{"constructor": {"prototype": {"isAdmin": true}}}',
        ]

        for payload in pollution_payloads:
            try:
                resp = self.session.post(
                    base_url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout // 2,
                    verify=False
                )
                body = resp.text.lower()
                if "polluted" in body or "isadmin" in body:
                    self.add_finding("Prototype Pollution Vulnerability", "high", False,
                                     "Prototype pollution payload accepted and reflected",
                                     category,
                                     remediation="Use Object.create(null) for maps. Validate and sanitize object keys.",
                                     owasp="A03", nist="SI", pci_dss="PCI-6",
                                     attack_vector="Network", exploitability=1.5, impact=1.0)
                    return
            except requests.exceptions.RequestException:
                pass

        self.add_finding("Prototype Pollution Test", "info", True,
                         "No prototype pollution vulnerability detected",
                         category, owasp="A03", nist="SI")

    # ──────────────────────────────────────────────────────────────────
    # SecurityChecker v5.0 — New Security Checks
    # ──────────────────────────────────────────────────────────────────

    def collect_asset_surface(self):
        if not self.soup:
            return
        scripts = self.soup.find_all("script")
        external = 0
        inline = 0
        hosts = []
        for script in scripts:
            src = script.get("src", "")
            if src:
                external += 1
                if src.startswith("//"):
                    src = "https:" + src
                parsed_src = urlparse(src)
                if parsed_src.netloc and parsed_src.netloc != self.domain:
                    if parsed_src.netloc not in hosts:
                        hosts.append(parsed_src.netloc)
            elif script.string and script.string.strip():
                inline += 1

        links = self.soup.find_all("link")
        for link in links:
            href = link.get("href", "")
            if href.startswith("//"):
                href = "https:" + href
            parsed_href = urlparse(href)
            if parsed_href.netloc and parsed_href.netloc != self.domain:
                if parsed_href.netloc not in hosts:
                    hosts.append(parsed_href.netloc)

        frames = self.soup.find_all(["iframe", "frame", "object", "embed"])
        for frame in frames:
            src = frame.get("src", "") or frame.get("data", "")
            if src.startswith("//"):
                src = "https:" + src
            parsed_src = urlparse(src)
            if parsed_src.netloc and parsed_src.netloc != self.domain:
                if parsed_src.netloc not in hosts:
                    hosts.append(parsed_src.netloc)

        wasm_modules = list(dict.fromkeys(
            re.findall(r"[\w./@-]+\.wasm", self.html_content, flags=re.IGNORECASE)
        ))

        cdn_hosts = [h for h in hosts if any(c in h for c in KNOWN_CDN_HOSTS)]

        self.assets["scripts"] = len(scripts)
        self.assets["external_scripts"] = external
        self.assets["inline_scripts"] = inline
        self.assets["stylesheets"] = len(self.soup.find_all("link", rel="stylesheet"))
        self.assets["forms"] = len(self.soup.find_all("form"))
        self.assets["frames"] = len(frames)
        self.assets["links"] = len(self.soup.find_all("a"))
        self.assets["wasm_modules"] = wasm_modules
        self.assets["external_hosts"] = hosts
        self.assets["cdn_hosts"] = cdn_hosts

    def check_wasm_security(self):
        category = "wasm"
        text_lower = self.html_content.lower()
        wasm_modules = list(dict.fromkeys(
            re.findall(r"[\w./@-]+\.wasm", self.html_content, flags=re.IGNORECASE)
        ))
        self.assets["wasm_modules"] = wasm_modules
        uses_api = ("webassembly.instantiate" in text_lower
                    or "webassembly.module" in text_lower
                    or "webassembly.compile" in text_lower)
        streaming = "instantiatestreaming" in text_lower

        if not wasm_modules and not uses_api:
            self.add_finding("No WebAssembly Detected", "info", True,
                             "Page does not appear to load WebAssembly modules",
                             category)
            return

        detail_bits = []
        if wasm_modules:
            detail_bits.append(str(len(wasm_modules)) + " module(s): " + ", ".join(wasm_modules[:3]))
        if uses_api:
            detail_bits.append("WebAssembly JavaScript API usage")
        if streaming:
            detail_bits.append("streaming compilation via instantiateStreaming")
        self.add_finding("WebAssembly In Use", "info", True,
                         "; ".join(detail_bits) if detail_bits else "WebAssembly usage detected",
                         category, owasp="A08", nist="SC")

        http_wasm = [m for m in wasm_modules if m.lower().startswith("http://")]
        if http_wasm:
            self.add_finding("WASM Loaded Over HTTP", "high", False,
                             "WebAssembly module(s) fetched insecurely: " + ", ".join(http_wasm[:3]),
                             category,
                             remediation="Serve .wasm modules over HTTPS only.",
                             owasp="A02", nist="SC", pci_dss="PCI-4")

        csp = self.response.headers.get("Content-Security-Policy", "") if self.response else ""
        if not csp:
            if wasm_modules or uses_api:
                self.add_finding("WASM Without CSP Isolation", "low", False,
                                 "WebAssembly present but no Content-Security-Policy constrains script execution",
                                 category,
                                 remediation="Deploy a CSP that limits script-src and uses 'wasm-unsafe-eval' only where required.",
                                 owasp="A05", nist="SC", pci_dss="PCI-6")
        else:
            if "unsafe-eval" in csp:
                self.add_finding("CSP unsafe-eval With WebAssembly", "high", False,
                                 "CSP allows unsafe-eval while WebAssembly is in use, weakening script isolation",
                                 category,
                                 remediation="Replace unsafe-eval with 'wasm-unsafe-eval' in script-src where possible.",
                                 owasp="A03", nist="SC", pci_dss="PCI-6")
            elif "wasm-unsafe-eval" not in csp and ("script-src" in csp or "default-src" in csp):
                self.add_finding("CSP Missing wasm-unsafe-eval", "info", True,
                                 "CSP does not grant wasm-unsafe-eval (WASM may be blocked or handled via hashes/nonces)",
                                 category, owasp="A05", nist="SC")

        if streaming and not self.response.headers.get("X-Content-Type-Options", ""):
            self.add_finding("WASM Streaming Without nosniff", "low", False,
                             "Streaming WASM compilation without X-Content-Type-Options: nosniff",
                             category,
                             remediation="Add X-Content-Type-Options: nosniff for streamed .wasm responses.",
                             owasp="A05", nist="SC", pci_dss="PCI-6")

    def check_webrtc_leak(self):
        category = "privacy"
        text_lower = self.html_content.lower()
        webrtc_patterns = [
            "rtcpeerconnection", "webrtc", "icecandidate", "createoffer",
            "createsdp", "addicecandidate", "getusermedia", "enumeratedevices",
        ]
        found = [p for p in webrtc_patterns if p in text_lower]
        stun_servers = list(dict.fromkeys(re.findall(r"stun:[a-z0-9.:-]+", self.html_content, flags=re.I)))
        turn_servers = list(dict.fromkeys(re.findall(r"turns?:[a-z0-9.:-]+", self.html_content, flags=re.I)))

        if not found and not stun_servers and not turn_servers:
            self.add_finding("No WebRTC Usage Detected", "info", True,
                             "No WebRTC peer connection or ICE configuration found in page source",
                             category)
        else:
            detail = "WebRTC indicators: " + ", ".join(found[:5]) if found else "STUN/TURN references found"
            self.add_finding("WebRTC In Use", "low", False,
                             detail,
                             category,
                             remediation="Restrict WebRTC with Permissions-Policy and verify ICE candidates do not leak host IPs.",
                             owasp="A01", nist="SC")

        if stun_servers or turn_servers:
            servers = stun_servers + turn_servers
            self.add_finding("WebRTC ICE Servers Exposed", "medium", False,
                             "Public ICE endpoints in page source: " + ", ".join(servers[:4]),
                             category,
                             remediation="Avoid hardcoding STUN/TURN endpoints client-side; relay through your own servers where possible.",
                             owasp="A01", nist="SC")

        if found:
            self.add_finding("WebRTC Local IP Leak Risk", "medium", False,
                             "WebRTC APIs present can expose local/public IP addresses via ICE candidates to scripts",
                             category,
                             remediation="Use PrivacyGuard/iceTransportPolicy='relay' or disable WebRTC when not needed.",
                             owasp="A01", nist="SC")

        permissions_policy = ""
        if self.response:
            permissions_policy = self.response.headers.get("Permissions-Policy", "")
        if not permissions_policy and found:
            self.add_finding("Permissions-Policy Missing for Media APIs", "medium", False,
                             "No Permissions-Policy header to gate camera/microphone/geolocation used alongside WebRTC",
                             category,
                             remediation="Add Permissions-Policy: camera=(), microphone=(), geolocation=() (allow only trusted origins).",
                             owasp="A05", nist="SC", pci_dss="PCI-6")
        elif permissions_policy:
            risky = []
            for feature in ("camera", "microphone", "geolocation", "display-capture"):
                if feature + "=" not in permissions_policy:
                    risky.append(feature)
            if risky and found:
                self.add_finding("Permissions-Policy Incomplete", "low", False,
                                 "Permissions-Policy does not clearly restrict: " + ", ".join(risky),
                                 category,
                                 remediation="Explicitly allow or deny camera, microphone, geolocation and display-capture.",
                                 owasp="A05", nist="SC")

        if not found and (stun_servers or turn_servers):
            self.add_finding("Orphaned ICE Configuration", "low", False,
                             "STUN/TURN strings present without obvious RTCPeerConnection usage",
                             category,
                             remediation="Remove unused ICE server configuration from shipped JavaScript.",
                             owasp="A05", nist="CM")

    def check_fingerprinting(self):
        category = "privacy"
        text_lower = self.html_content.lower()

        lib_hits = [lib for lib in FINGERPRINTING_LIBRARIES if lib in text_lower]
        if lib_hits:
            self.add_finding("Browser Fingerprinting Library Detected", "medium", False,
                             "Fingerprinting library reference(s): " + ", ".join(lib_hits[:4]),
                             category,
                             remediation="Remove fingerprinting scripts or disclose them in your privacy policy; obtain consent.",
                             owasp="A01", nist="AC", hipaa="HIPAA-PS")

        heuristics = []
        if "canvas" in text_lower and "todataurl" in text_lower and "getimagedata" in text_lower:
            heuristics.append("Canvas fingerprinting pattern (toDataURL + getImageData)")
        if "webgl" in text_lower and ("getparameter" in text_lower or "readpixels" in text_lower):
            heuristics.append("WebGL fingerprinting pattern")
        if "audiocontext" in text_lower and ("createoscillator" in text_lower or "createanalyser" in text_lower):
            heuristics.append("AudioContext fingerprinting pattern")
        if "document.fonts" in text_lower and ".check(" in text_lower:
            heuristics.append("Font enumeration pattern")
        if "getbattery" in text_lower:
            heuristics.append("Battery API access")
        if "hardwareconcurrency" in text_lower and "devicememory" in text_lower:
            heuristics.append("High-entropy hardware fingerprinting (hardwareConcurrency + deviceMemory)")

        if heuristics:
            self.add_finding("Fingerprinting Techniques Detected", "medium", False,
                             "Client-side fingerprinting heuristics: " + "; ".join(heuristics[:4]),
                             category,
                             remediation="Minimize high-entropy API reads or gate them behind user consent.",
                             owasp="A01", nist="AC")

        if lib_hits or heuristics:
            self.add_finding("Fingerprinting Exposure", "low", False,
                             "Combined fingerprinting signals can uniquely identify visitors without cookies",
                             category,
                             remediation="Review third-party scripts and privacy policy; consider fingerprint-resistant headers.",
                             owasp="A01", nist="AC")
        elif not lib_hits and not heuristics:
            self.add_finding("No Fingerprinting Indicators", "info", True,
                             "No known fingerprinting libraries or common techniques detected",
                             category, owasp="A01", nist="AC")

    def check_crypto_mining(self):
        category = "privacy"
        text_lower = self.html_content.lower()

        miner_hits = [ind for ind in CRYPTO_MINER_INDICATORS if ind in text_lower]
        stratum_hits = list(dict.fromkeys(
            re.findall(r"stratum\+?(?:tcp|ssl)://[a-z0-9.:/-]+", self.html_content, flags=re.I)
        ))
        script_miners = []
        if self.soup:
            for script in self.soup.find_all("script", src=True):
                src = script.get("src", "").lower()
                if any(ind in src for ind in CRYPTO_MINER_INDICATORS):
                    script_miners.append(script.get("src", ""))

        if script_miners or any(h in ("coinhive", "cryptonight", "coinimp", "cryptoloot", "webmine") for h in miner_hits):
            self.add_finding("Cryptocurrency Miner Detected", "critical", False,
                             "Mining indicators: " + ", ".join((script_miners or miner_hits)[:4]),
                             category, cve="CVE-2018-9989",
                             remediation="Remove unauthorized mining scripts immediately and audit all third-party includes.",
                             owasp="A08", nist="SI", pci_dss="PCI-6",
                             attack_vector="Network", exploitability=2.0, impact=2.0)
        elif stratum_hits:
            self.add_finding("Mining Pool Connection Hints", "high", False,
                             "Stratum pool endpoint(s) referenced: " + ", ".join(stratum_hits[:3]),
                             category,
                             remediation="Remove stratum/pool references from client-side code.",
                             owasp="A08", nist="SI",
                             attack_vector="Network", exploitability=1.5, impact=1.5)
        elif any(h in miner_hits for h in ("hashrate", "totalhashes", "jsecoin", "deepminer", "nicehash", "ppoi.org")):
            self.add_finding("Crypto Mining Heuristics", "medium", False,
                             "Mining-related keywords found: " + ", ".join([h for h in miner_hits if h in ("hashrate", "totalhashes", "jsecoin", "deepminer", "nicehash", "ppoi.org")][:4]),
                             category,
                             remediation="Audit scripts containing hashing/worker pool references.",
                             owasp="A08", nist="SI")
        else:
            self.add_finding("No Crypto Mining Indicators", "info", True,
                             "No known coinhive-style miner or stratum pool references detected",
                             category, owasp="A08", nist="SI")

        if "worker" in text_lower and "postmessage" in text_lower and miner_hits:
            self.add_finding("Web Worker Mining Suspicion", "low", False,
                             "Web Workers combined with hashing-related keywords may indicate background mining",
                             category,
                             remediation="Inspect worker scripts for hash-rate loops.",
                             owasp="A08", nist="SI")

    def check_supply_chain(self):
        category = "supply_chain"
        if not self.soup:
            return

        external_scripts = []
        external_styles = []
        suspicious = []
        unpinned = []

        for script in self.soup.find_all("script", src=True):
            src = script.get("src", "")
            if src.startswith("//"):
                src = "https:" + src
            parsed_src = urlparse(src)
            if not parsed_src.netloc or parsed_src.netloc == self.domain:
                continue
            external_scripts.append((src, bool(script.get("integrity"))))
            host = parsed_src.netloc
            if any(s in src for s in SUSPICIOUS_SCRIPT_HOSTS):
                suspicious.append(src)
            try:
                import ipaddress
                ipaddress.ip_address(host.split(":")[0])
                suspicious.append(src)
            except ValueError:
                pass
            if ("unpkg.com" in src or "jsdelivr.net" in src) and "@" not in parsed_src.path:
                unpinned.append(src)
            if host not in self.assets["cdn_hosts"] and any(c in host for c in KNOWN_CDN_HOSTS):
                self.assets["cdn_hosts"].append(host)

        for link in self.soup.find_all("link", href=True):
            href = link.get("href", "")
            if href.startswith("//"):
                href = "https:" + href
            parsed_href = urlparse(href)
            if parsed_href.netloc and parsed_href.netloc != self.domain:
                rel = link.get("rel", [])
                if isinstance(rel, str):
                    rel = [rel]
                if "stylesheet" in rel:
                    external_styles.append((href, bool(link.get("integrity"))))

        if self.assets["cdn_hosts"]:
            self.add_finding("Third-Party CDN Dependencies", "info", True,
                             "CDN host(s): " + ", ".join(self.assets["cdn_hosts"][:5]),
                             category, owasp="A08", nist="SC")

        missing_sri = [s for s, has_sri in external_scripts if not has_sri]
        if missing_sri:
            self.add_finding("Supply Chain: Missing SRI on Scripts", "high", False,
                             str(len(missing_sri)) + " cross-origin script(s) lack Subresource Integrity: " + missing_sri[0][:80],
                             category, owasp="A08", nist="SC", pci_dss="PCI-6",
                             remediation="Pin SRI integrity hashes for every third-party script (integrity= attribute).",
                             attack_vector="Network", exploitability=1.5, impact=1.5)
        elif external_scripts:
            self.add_finding("Supply Chain: SRI Coverage", "info", True,
                             "All " + str(len(external_scripts)) + " cross-origin script(s) carry SRI hashes",
                             category, owasp="A08", nist="SC")

        missing_sri_css = [s for s, has_sri in external_styles if not has_sri]
        if missing_sri_css:
            self.add_finding("Supply Chain: Missing SRI on Stylesheets", "medium", False,
                             str(len(missing_sri_css)) + " cross-origin stylesheet(s) lack SRI: " + missing_sri_css[0][:80],
                             category, owasp="A08", nist="SC",
                             remediation="Add integrity attributes to cross-origin stylesheets.",
                             attack_vector="Network", exploitability=1.2, impact=1.0)

        if unpinned:
            self.add_finding("Supply Chain: Unpinned CDN Versions", "high", False,
                             "Floating (unversioned) CDN URL(s): " + "; ".join(unpinned[:3]),
                             category, owasp="A08", nist="SC",
                             remediation="Pin exact package versions (e.g. /npm/pkg@1.2.3/) to prevent tampered 'latest' delivery.",
                             attack_vector="Network", exploitability=1.5, impact=1.5)

        if suspicious:
            self.add_finding("Supply Chain: Suspicious Script Sources", "critical", False,
                             "Scripts hosted on risky origins: " + "; ".join(suspicious[:3]),
                             category, owasp="A08", nist="SC",
                             remediation="Self-host or pin trusted CDN sources; never load code from paste sites or raw IPs.",
                             attack_vector="Network", exploitability=2.0, impact=2.0)

        dynamic_loaders = []
        text_lower = self.html_content.lower()
        for pattern, label in [
            ("createelement('script')", "Dynamic script injection"),
            ('createelement("script")', "Dynamic script injection"),
            ("appendchild", "Dynamic DOM script append"),
            ("import(", "Dynamic import() of remote module"),
        ]:
            if pattern in text_lower and ("http" in text_lower or "//" in text_lower):
                dynamic_loaders.append(label)
        if dynamic_loaders:
            self.add_finding("Supply Chain: Dynamic Script Loading", "medium", False,
                             "Runtime script loading patterns: " + ", ".join(sorted(set(dynamic_loaders))),
                             category, owasp="A08", nist="SC",
                             remediation="Avoid runtime-built script URLs; use nonce-based CSP and pinned sources.")

        if not external_scripts and not external_styles:
            self.add_finding("Supply Chain: No External Dependencies", "info", True,
                             "No cross-origin scripts or stylesheets detected",
                             category, owasp="A08", nist="SC")

    @staticmethod
    def _parse_version_tuple(text):
        parts = re.findall(r"\d+", text or "")
        if not parts:
            return None
        nums = [int(p) for p in parts[:3]]
        while len(nums) < 3:
            nums.append(0)
        return tuple(nums)

    @staticmethod
    def _version_in_ranges(version, ranges):
        for low, high in ranges:
            if version >= low and version < high:
                return True
        return False

    def check_dependency_vulnerabilities(self):
        category = "supply_chain"
        haystack = self.html_content
        detected = {}

        for name, pattern in LIBRARY_PATTERNS:
            for match in pattern.finditer(haystack):
                ver = self._parse_version_tuple(match.group(1))
                if ver:
                    detected[name] = ver
                    break

        for pattern in NPM_PATTERNS:
            for match in pattern.finditer(haystack):
                pkg = match.group(1).split("/")[-1].lower()
                ver = self._parse_version_tuple(match.group(2))
                if ver and pkg in ("jquery", "lodash", "bootstrap", "underscore",
                                   "handlebars", "moment", "angular"):
                    key = "angularjs" if pkg == "angular" else pkg
                    if key not in detected:
                        detected[key] = ver
                elif ver:
                    label = pkg + " " + ".".join(str(x) for x in ver)
                    if label not in self.assets["libraries"]:
                        self.assets["libraries"].append(label)

        for name, ver in detected.items():
            label = name + " " + ".".join(str(x) for x in ver)
            if label not in self.assets["libraries"]:
                self.assets["libraries"].append(label)

        if not detected and not self.assets["libraries"]:
            self.add_finding("Dependency Vulnerability Hints", "info", True,
                             "No versioned client-side libraries detected in page source",
                             category, owasp="A06", nist="RA")
            return

        matches_by_name = {}
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        for entry in VULNERABLE_DEPENDENCIES:
            name = entry["name"]
            if name not in detected:
                continue
            version = detected[name]
            if not self._version_in_ranges(version, entry["ranges"]):
                continue
            bucket = matches_by_name.setdefault(name, {
                "version": version, "cves": [], "notes": [],
                "severity": "info", "fix": entry["fix"],
            })
            if entry["cve"] not in bucket["cves"]:
                bucket["cves"].append(entry["cve"])
            if entry["note"] not in bucket["notes"]:
                bucket["notes"].append(entry["note"])
            if severity_rank.get(entry["severity"], 0) > severity_rank.get(bucket["severity"], 0):
                bucket["severity"] = entry["severity"]
                bucket["fix"] = entry["fix"]

        for name, bucket in matches_by_name.items():
            version_str = ".".join(str(x) for x in bucket["version"])
            self.add_finding(
                "Vulnerable Dependency: " + name + " " + version_str,
                bucket["severity"], False,
                name + " " + version_str + " — " + "; ".join(bucket["notes"])
                + " (upgrade to " + bucket["fix"] + ")",
                category, cve=", ".join(bucket["cves"]),
                remediation="Upgrade " + name + " to " + bucket["fix"]
                + " or later; run npm audit / Snyk on the full dependency tree.",
                owasp="A06", nist="RA", pci_dss="PCI-6",
                attack_vector="Network", exploitability=1.5, impact=1.5,
            )

        unversioned = [lib for lib in self.assets["libraries"]
                       if not any(lib.startswith(d + " ") for d in detected)]
        if unversioned:
            self.add_finding("Detected Client Libraries", "info", True,
                             "Libraries observed (audit for known CVEs): " + ", ".join(unversioned[:6]),
                             category, owasp="A06", nist="RA",
                             remediation="Track dependencies in a lockfile and scan with npm audit, Snyk or Dependabot.")

        if detected and not matches_by_name:
            versioned = [n + " " + ".".join(str(x) for x in v) for n, v in detected.items()]
            self.add_finding("Dependency Versions Clean", "info", True,
                             "No known vulnerable versions matched for: " + ", ".join(versioned[:6]),
                             category, owasp="A06", nist="RA")

    def check_cache_poisoning(self):
        category = "cache"
        headers = self.response.headers if self.response else {}

        cache_control = headers.get("Cache-Control", "")
        vary = headers.get("Vary", "")
        age = headers.get("Age", "")
        cdn_header_names = ["CF-Cache-Status", "X-Cache", "X-Cache-Status",
                            "X-Served-By", "X-Drupal-Cache", "X-Varnish",
                            "X-Fastly-Request-ID", "Server-Timing"]
        found_cdn = {h: headers.get(h, "") for h in cdn_header_names if headers.get(h, "")}

        if found_cdn:
            cdn_detail = "; ".join(k + "=" + v for k, v in list(found_cdn.items())[:3])
            self.add_finding("CDN / Edge Cache Active", "info", True,
                             "Caching layer detected: " + cdn_detail,
                             category, owasp="A05", nist="SC")

        if age:
            self.add_finding("Cached Response Served", "info", True,
                             "Age header present (response served from cache): Age=" + age,
                             category)

        probe_marker = "securitychecker-cache-probe"
        probe_headers = ["X-Forwarded-Host", "X-Host", "X-Original-URL",
                         "X-Rewrite-URL", "X-Forwarded-Scheme", "Forwarded"]
        reflected = []
        for header_name in probe_headers:
            try:
                probe_value = probe_marker + ".invalid"
                resp = self.session.get(
                    self.url,
                    headers={header_name: probe_value},
                    timeout=max(2, self.timeout // 2),
                    allow_redirects=False,
                    verify=False,
                )
                location = resp.headers.get("Location", "")
                if probe_marker in resp.text or probe_marker in location:
                    reflected.append(header_name)
            except requests.exceptions.RequestException:
                continue

        if reflected:
            self.add_finding("Web Cache Poisoning Vector", "high", False,
                             "Unkeyed header(s) reflected in response: " + ", ".join(reflected),
                             category,
                             remediation="Add these headers to the cache key or reject requests carrying them at the edge.",
                             owasp="A05", nist="SC", pci_dss="PCI-6",
                             attack_vector="Network", exploitability=1.5, impact=1.5)
        else:
            self.add_finding("Unkeyed Header Reflection Test", "info", True,
                             "Tested " + str(len(probe_headers)) + " unkeyed header probes with no reflection detected",
                             category, owasp="A05", nist="SC")

        has_set_cookie = bool(self.session.cookies) or bool(headers.get("Set-Cookie", ""))
        if "public" in cache_control.lower() and has_set_cookie:
            self.add_finding("Cacheable Response With Cookies", "high", False,
                             "Cache-Control: public combined with Set-Cookie risks serving one user's session to another",
                             category,
                             remediation="Use Cache-Control: private, no-store for authenticated or cookie-bearing responses.",
                             owasp="A04", nist="SC", pci_dss="PCI-6")

        if found_cdn and not vary:
            self.add_finding("CDN Cache Missing Vary", "medium", False,
                             "CDN caching observed but no Vary header on the response",
                             category,
                             remediation="Set Vary (at least Accept-Encoding, Origin) so the edge does not mix representations.",
                             owasp="A05", nist="SC")

        if "no-store" in cache_control.lower() or "private" in cache_control.lower():
            self.add_finding("Response Properly Non-Cacheable", "info", True,
                             "Cache-Control discourages shared caching: " + cache_control,
                             category, owasp="A05", nist="SC")
        elif not cache_control:
            self.add_finding("No Cache-Control Header", "low", False,
                             "Response has no Cache-Control directive; intermediaries may cache arbitrarily",
                             category,
                             remediation="Explicitly set Cache-Control on every response class.",
                             owasp="A05", nist="SC")

    # ──────────────────────────────────────────────────────────────────
    # SecurityChecker v5.0 — Advanced Vulnerability Detection
    # ──────────────────────────────────────────────────────────────────

    def check_advanced_sqli(self, category):
        base_url = self.scheme + "://" + self.domain
        param = "id"
        if self.parsed.query:
            existing = parse_qs(self.parsed.query, keep_blank_values=True)
            if existing:
                param = list(existing.keys())[0]

        client_ceiling = float(self.timeout + 6)

        def timed_get(payload_value):
            test_url = base_url + "?" + param + "=" + quote(payload_value, safe="")
            start = time.time()
            try:
                self.session.get(
                    test_url, timeout=client_ceiling,
                    allow_redirects=False, verify=False,
                )
            except requests.exceptions.Timeout:
                return time.time() - start
            except requests.exceptions.RequestException:
                return 0.0
            return time.time() - start

        baseline = timed_get("1")
        time_payloads = [
            ("1' AND SLEEP(4)-- -", "MySQL"),
            ("1'; SELECT pg_sleep(4)-- -", "PostgreSQL"),
            ("1'; WAITFOR DELAY '0:0:4'-- -", "MSSQL"),
        ]

        for payload, engine in time_payloads:
            elapsed = timed_get(payload)
            if baseline > 0 and elapsed >= baseline + 3.5:
                self.add_finding("Time-Based SQL Injection", "critical", False,
                                 engine + " time-delay payload delayed the response by "
                                 + str(round(elapsed - baseline, 1)) + "s",
                                 category, cve="CVE-2024-XXXX",
                                 remediation="Use parameterized queries; never interpolate user input into SQL.",
                                 owasp="A03", nist="SI", pci_dss="PCI-6",
                                 attack_vector="Network", exploitability=2.0, impact=2.0)
                return

        def body_for(payload_value):
            test_url = base_url + "?" + param + "=" + quote(payload_value, safe="")
            try:
                resp = self.session.get(
                    test_url, timeout=max(2, self.timeout // 2),
                    allow_redirects=False, verify=False,
                )
                return resp.status_code, resp.text
            except requests.exceptions.RequestException:
                return 0, ""

        status_true, body_true = body_for("1' AND '1'='1")
        status_false, body_false = body_for("1' AND '1'='2")
        if status_true == 200 and status_false == 200 and body_true and body_false:
            diff = abs(len(body_true) - len(body_false))
            larger = max(len(body_true), len(body_false))
            if larger > 0 and diff > 50 and (diff / larger) > 0.05:
                self.add_finding("Boolean-Based SQL Injection Hint", "high", False,
                                 "True/false payloads returned responses differing by " + str(diff) + " bytes",
                                 category,
                                 remediation="Use parameterized queries and generic error pages.",
                                 owasp="A03", nist="SI", pci_dss="PCI-6",
                                 attack_vector="Network", exploitability=1.5, impact=1.5)
                return

        self.add_finding("Advanced SQLi Probes", "info", True,
                         "Time-based and boolean-based SQLi probes did not alter responses",
                         category, owasp="A03", nist="SI")

    def check_advanced_xss_dom(self, category):
        script_blobs = []
        if self.soup:
            for script in self.soup.find_all("script"):
                if not script.get("src") and script.string and script.string.strip():
                    script_blobs.append(script.string)

        if not script_blobs:
            inline_matches = re.findall(
                r"<script(?![^>]*\ssrc=)[^>]*>(.*?)</script>",
                self.html_content, flags=re.I | re.S,
            )
            script_blobs = [m for m in inline_matches if m.strip()]

        blob = "\n".join(script_blobs)
        blob_lower = blob.lower()

        if not blob_lower:
            self.add_finding("DOM XSS Analysis", "info", True,
                             "No inline JavaScript available for DOM XSS analysis",
                             category, owasp="A03", nist="SC")
            return

        found_sources = [s for s in DOM_XSS_SOURCES if s in blob_lower]
        found_sinks = [s for s in DOM_XSS_SINKS if s in blob_lower]
        dangerous = [s for s in DOM_XSS_DANGEROUS_SINKS if s in blob_lower]

        paired_scripts = 0
        for script_text in script_blobs:
            low = script_text.lower()
            if any(s in low for s in DOM_XSS_SOURCES) and any(s in low for s in DOM_XSS_SINKS):
                paired_scripts += 1

        if paired_scripts:
            self.add_finding("DOM-Based XSS Pattern", "high", False,
                             str(paired_scripts) + " inline script(s) read location/URL sources and write to HTML sinks",
                             category,
                             remediation="Use textContent/setAttribute with encoding; never assign location data to innerHTML/eval.",
                             owasp="A03", nist="SC", pci_dss="PCI-6",
                             attack_vector="Network", exploitability=1.5, impact=1.5)

        if dangerous:
            self.add_finding("Dangerous DOM Sinks", "medium", False,
                             "Risky sinks in inline code: " + ", ".join(dangerous[:5]),
                             category,
                             remediation="Replace eval/document.write/innerHTML with safe DOM APIs and CSP nonces.",
                             owasp="A03", nist="SC", pci_dss="PCI-6")

        if found_sources:
            self.add_finding("DOM XSS Sources Read", "low", False,
                             "Attacker-influenced sources referenced: " + ", ".join(found_sources[:5]),
                             category,
                             remediation="Validate and encode all values derived from URL fragments/query strings.",
                             owasp="A03", nist="SC")

        if not paired_scripts and not dangerous and not found_sources:
            self.add_finding("DOM XSS Patterns", "info", True,
                             "No dangerous source-to-sink DOM XSS patterns found in inline scripts",
                             category, owasp="A03", nist="SC")

    def check_advanced_csrf(self, category):
        if not self.soup:
            return

        forms = self.soup.find_all("form")
        meta_token = self.soup.find_all("meta", attrs={"name": re.compile(r"csrf|xsrf", re.I)})
        state_changing = []
        missing_token = []
        weak_tokens = []
        sensitive_get = []

        for form in forms:
            method = (form.get("method") or "get").upper()
            action = form.get("action", "") or ""
            if method == "GET" and any(k in action.lower() for k in
                                       ("delete", "remove", "logout", "admin", "reset", "destroy")):
                sensitive_get.append(action or "(current page)")
            if method not in ("POST", "PUT", "PATCH", "DELETE"):
                continue
            state_changing.append(form)
            token_fields = []
            for inp in form.find_all("input"):
                name = inp.get("name", "") or ""
                value = inp.get("value", "") or ""
                if CSRF_TOKEN_NAME_RE.search(name):
                    token_fields.append((name, value))
            if not token_fields and not meta_token:
                missing_token.append(action or "(current page)")
            for name, value in token_fields:
                if value and (len(value) < 8 or value.isdigit()
                              or value.lower() in ("test", "changeme", "null", "undefined", "0", "1")):
                    weak_tokens.append(name)

        if missing_token:
            self.add_finding("CSRF Token Missing on Forms", "high", False,
                             str(len(missing_token)) + " state-changing form(s) without a CSRF token field: "
                             + "; ".join(missing_token[:3]),
                             category,
                             remediation="Add per-session CSRF tokens (or double-submit cookies) to all state-changing forms.",
                             owasp="A01", nist="AC", pci_dss="PCI-6",
                             attack_vector="Network", exploitability=1.5, impact=1.5)

        if weak_tokens:
            self.add_finding("Weak CSRF Token Detected", "medium", False,
                             "Predictable/short token field(s): " + ", ".join(weak_tokens[:3]),
                             category,
                             remediation="Use cryptographically random, per-session tokens of at least 128 bits.",
                             owasp="A01", nist="AC",
                             attack_vector="Network", exploitability=1.5, impact=1.0)

        if sensitive_get:
            self.add_finding("State Changes via GET", "medium", False,
                             "GET form(s) targeting destructive actions: " + "; ".join(sensitive_get[:3]),
                             category,
                             remediation="Use POST with CSRF protection for logout/delete/reset actions.",
                             owasp="A01", nist="AC")

        same_site_missing = False
        for cookie in self.session.cookies:
            rest = getattr(cookie, "_rest", {}) or {}
            if not rest.get("SameSite", ""):
                same_site_missing = True
                break
        if missing_token and same_site_missing:
            self.add_finding("CSRF Without SameSite Fallback", "high", False,
                             "Forms lack tokens and session cookies lack SameSite — no layered CSRF defense",
                             category,
                             remediation="Combine SameSite=Lax/Strict cookies with explicit CSRF tokens.",
                             owasp="A01", nist="AC", pci_dss="PCI-6")

        bypass_accepted = []
        for form in state_changing[:2]:
            action = form.get("action", "") or self.url
            if action.startswith("/"):
                action = self.scheme + "://" + self.domain + action
            elif not action.startswith("http://") and not action.startswith("https://"):
                action = urljoin(self.url, action)
            try:
                resp = self.session.post(
                    action,
                    data={"securitychecker_csrf_probe": "1"},
                    timeout=max(2, self.timeout // 2),
                    allow_redirects=False,
                    verify=False,
                )
                body_lower = resp.text.lower()
                rejected = resp.status_code in (401, 403) or "csrf" in body_lower \
                    or "invalid token" in body_lower or "forbidden" in body_lower
                if not rejected and resp.status_code in (200, 301, 302, 303, 307, 308):
                    bypass_accepted.append(action)
            except requests.exceptions.RequestException:
                continue

        if bypass_accepted:
            self.add_finding("CSRF Token Not Enforced", "high", False,
                             "Token-less POST accepted by: " + "; ".join(bypass_accepted[:2]),
                             category,
                             remediation="Reject state-changing requests missing a valid CSRF token (403).",
                             owasp="A01", nist="AC", pci_dss="PCI-6",
                             attack_vector="Network", exploitability=1.5, impact=1.5)

        if state_changing and not missing_token and not weak_tokens and not bypass_accepted:
            self.add_finding("CSRF Defenses Present", "info", True,
                             str(len(state_changing)) + " state-changing form(s) carry CSRF token(s)",
                             category, owasp="A01", nist="AC")
        elif not state_changing:
            self.add_finding("No State-Changing Forms", "info", True,
                             "No POST/PUT/PATCH/DELETE forms found on the page",
                             category, owasp="A01", nist="AC")

    def check_advanced_ssrf_rebinding(self, category):
        base_url = self.scheme + "://" + self.domain
        ssrf_params = ["url", "uri", "path", "src", "dest", "redirect",
                       "fetch", "load", "include", "file", "page", "callback"]
        params_present = []
        if self.parsed.query:
            for param in parse_qs(self.parsed.query, keep_blank_values=True):
                if param.lower() in ssrf_params:
                    params_present.append(param)
        if self.soup:
            for form in self.soup.find_all("form"):
                for inp in form.find_all("input"):
                    name = (inp.get("name", "") or "").lower()
                    if name in ssrf_params and name not in params_present:
                        params_present.append(name)

        probes = [
            ("http://127.0.0.1.nip.io/", "nip.io loopback alias"),
            ("http://localtest.me/", "localtest.me loopback alias"),
            ("http://2130706433/", "decimal-encoded 127.0.0.1"),
            ("http://0x7f000001/", "hex-encoded 127.0.0.1"),
        ]
        internal_indicators = ["ami-id", "instance-id", "iam/", "metadata",
                               "credentials", "local-ipv4", "root:", "/bin/bash"]

        hit = None
        tested = 0
        for param in params_present[:2]:
            for target, label in probes:
                if tested >= 4:
                    break
                tested += 1
                test_url = base_url + "?" + param + "=" + quote(target, safe="")
                try:
                    resp = self.session.get(
                        test_url, timeout=max(2, self.timeout // 2),
                        allow_redirects=False, verify=False,
                    )
                    body = resp.text.lower()
                    if any(ind in body for ind in internal_indicators):
                        hit = (param, target, label)
                        break
                except requests.exceptions.RequestException:
                    continue
            if hit:
                break

        if hit:
            param, target, label = hit
            self.add_finding("SSRF via Rebinding/Encoding Bypass", "critical", False,
                             "Parameter '" + param + "' fetched internal content through " + label + " (" + target + ")",
                             category, cve="CVE-2024-SSRF",
                             remediation="Resolve DNS once, pin the IP, and enforce an allowlist of outbound destinations.",
                             owasp="A10", nist="SC", pci_dss="PCI-6",
                             attack_vector="Network", exploitability=2.0, impact=2.0)
        elif params_present and tested:
            self.add_finding("SSRF Rebinding/Encoding Probes", "info", True,
                             "Tested " + str(tested) + " rebinding/encoding payload(s) on parameter(s): " + ", ".join(params_present[:2]),
                             category, owasp="A10", nist="SC")

        if params_present:
            self.add_finding("DNS Rebinding Exposure Hint", "medium", False,
                             "URL-accepting parameter(s) (" + ", ".join(params_present[:4])
                             + ") fetch remote hosts — vulnerable to DNS rebinding unless the resolved IP is pinned and allowlisted",
                             category,
                             remediation="Pin DNS resolution to a single IP per request and block private/link-local ranges.",
                             owasp="A10", nist="SC", pci_dss="PCI-6",
                             attack_vector="Network", exploitability=1.2, impact=1.2)
        else:
            self.add_finding("SSRF Attack Surface", "info", True,
                             "No URL-accepting parameters identified for SSRF rebinding tests",
                             category, owasp="A10", nist="SC")

    # ──────────────────────────────────────────────────────────────────
    # SecurityChecker v6.0 — Subresource Integrity & Browser Policy
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _analyze_sri_value(integrity):
        tokens = [t.strip() for t in (integrity or "").split() if t.strip()]
        if not tokens:
            return "malformed"
        strong = False
        weak = False
        malformed = False
        for token in tokens:
            if "-" not in token:
                malformed = True
                continue
            algo, _, digest = token.partition("-")
            algo = algo.lower()
            if algo in ("md5", "sha1"):
                weak = True
            elif algo in ("sha256", "sha384", "sha512"):
                if digest and len(digest) >= 32:
                    strong = True
                else:
                    malformed = True
            else:
                malformed = True
        if strong and not malformed:
            return "ok"
        if weak and not strong:
            return "weak"
        return "malformed"

    def check_sri_validation(self):
        category = "sri"
        if not self.soup:
            return

        external_scripts = []
        external_styles = []
        without_sri = []
        weak_hash = []
        malformed = []
        missing_crossorigin = []

        for script in self.soup.find_all("script", src=True):
            src = script.get("src", "")
            if src.startswith("//"):
                src = "https:" + src
            parsed_src = urlparse(src)
            if not parsed_src.netloc or parsed_src.netloc == self.domain:
                continue
            external_scripts.append(src)
            integrity = script.get("integrity", "")
            crossorigin = script.get("crossorigin", "")
            if not integrity:
                without_sri.append(src)
                continue
            status = self._analyze_sri_value(integrity)
            if status == "weak":
                weak_hash.append(src)
            elif status == "malformed":
                malformed.append(src)
            if not crossorigin:
                missing_crossorigin.append(src)

        for link in self.soup.find_all("link", href=True):
            rel = link.get("rel", [])
            if isinstance(rel, str):
                rel = [rel]
            if "stylesheet" not in rel:
                continue
            href = link.get("href", "")
            if href.startswith("//"):
                href = "https:" + href
            parsed_href = urlparse(href)
            if not parsed_href.netloc or parsed_href.netloc == self.domain:
                continue
            external_styles.append(href)
            integrity = link.get("integrity", "")
            crossorigin = link.get("crossorigin", "")
            if not integrity:
                without_sri.append(href)
                continue
            status = self._analyze_sri_value(integrity)
            if status == "weak":
                weak_hash.append(href)
            elif status == "malformed":
                malformed.append(href)
            if not crossorigin:
                missing_crossorigin.append(href)

        if not external_scripts and not external_styles:
            self.add_finding("SRI Attack Surface", "info", True,
                             "No cross-origin scripts or stylesheets require Subresource Integrity",
                             category, owasp="A08", nist="SC")
            return

        csp = self.response.headers.get("Content-Security-Policy", "") if self.response else ""
        if "require-sri-for" in csp.lower():
            self.add_finding("CSP require-sri-for Enforced", "info", True,
                             "CSP mandates SRI for resource types via require-sri-for",
                             category, owasp="A08", nist="SC")
        else:
            self.add_finding("CSP require-sri-for Absent", "low", False,
                             "CSP does not enforce require-sri-for; SRI relies solely on integrity attributes",
                             category,
                             remediation="Add require-sri-for 'script' 'style' to CSP once all assets carry integrity hashes.",
                             owasp="A08", nist="SC", pci_dss="PCI-6")

        if without_sri:
            self.add_finding("SRI Missing on Cross-Origin Resources", "high", False,
                             str(len(without_sri)) + " cross-origin resource(s) lack integrity hashes: "
                             + without_sri[0][:100],
                             category, owasp="A08", nist="SC", pci_dss="PCI-6",
                             remediation="Compute sha384/sha512 hashes and add integrity + crossorigin to every cross-origin script and stylesheet.",
                             attack_vector="Network", exploitability=1.5, impact=1.5)

        if weak_hash:
            self.add_finding("SRI Weak Hash Algorithm", "high", False,
                             "MD5/SHA-1 SRI hashes detected (collision-prone): " + "; ".join(weak_hash[:3]),
                             category, owasp="A08", nist="SC",
                             remediation="Replace md5/sha1 integrity tokens with sha384 or sha512.",
                             attack_vector="Network", exploitability=1.5, impact=1.5)

        if malformed:
            self.add_finding("SRI Malformed Integrity Value", "medium", False,
                             "Unparseable or truncated integrity attribute(s): " + "; ".join(malformed[:3]),
                             category, owasp="A08", nist="SC",
                             remediation="Use full base64 digests in the form sha384-<base64digest>.")

        if missing_crossorigin:
            self.add_finding("SRI Missing crossorigin Attribute", "medium", False,
                             str(len(missing_crossorigin)) + " SRI resource(s) omit crossorigin and will fail CORS checks: "
                             + missing_crossorigin[0][:100],
                             category, owasp="A08", nist="SC",
                             remediation='Add crossorigin="anonymous" alongside integrity on cross-origin resources.')

        total_ext = len(external_scripts) + len(external_styles)
        covered = total_ext - len(without_sri)
        if covered > 0 and not without_sri and not weak_hash and not malformed and not missing_crossorigin:
            self.add_finding("SRI Coverage Complete", "info", True,
                             "All " + str(covered) + " cross-origin script/stylesheet resource(s) carry valid strong SRI hashes",
                             category, owasp="A08", nist="SC")
        elif covered > 0:
            self.add_finding("SRI Partial Coverage", "info", True,
                             str(covered) + " of " + str(total_ext)
                             + " cross-origin resource(s) have integrity attributes",
                             category, owasp="A08", nist="SC")

    # ──────────────────────────────────────────────────────────────────
    # SecurityChecker v6.0 — Trusted Types / CSP Reporting
    # ──────────────────────────────────────────────────────────────────

    def check_trusted_types(self):
        category = "browser_policy"
        csp = self.response.headers.get("Content-Security-Policy", "") if self.response else ""
        csp_lower = csp.lower()
        text_lower = self.html_content.lower()

        uses_tt_api = ("trustedtypes.createpolicy" in text_lower
                       or "trustedtypes.defaultpolicy" in text_lower
                       or "trustedtypes.emptyshim" in text_lower)
        header_enforced = "require-trusted-types-for" in csp_lower
        policy_dir = re.search(r"trusted-types\s+([^;]*)", csp, flags=re.I)

        sinks = [s for s in ("innerhtml", "outerhtml", "insertadjacenthtml",
                             "document.write", "eval(", "javascript:")
                 if s in text_lower]

        if header_enforced:
            policy_names = policy_dir.group(1).strip() if policy_dir else ""
            detail = "CSP require-trusted-types-for is active"
            if policy_names:
                detail += " (trusted-types: " + policy_names + ")"
            self.add_finding("Trusted Types Enforced", "info", True,
                             detail,
                             category, owasp="A03", nist="SC", pci_dss="PCI-6")
            if sinks:
                self.add_finding("Trusted Types Gates HTML Sinks", "info", True,
                                 "HTML/JS sinks present but constrained by Trusted Types: " + ", ".join(sinks[:4]),
                                 category, owasp="A03", nist="SC")
        elif sinks:
            self.add_finding("Trusted Types Not Enforced", "medium", False,
                             "HTML/JS sinks present without CSP require-trusted-types-for: " + ", ".join(sinks[:4]),
                             category,
                             remediation="Add require-trusted-types-for 'script' to CSP and create policies via trustedTypes.createPolicy.",
                             owasp="A03", nist="SC", pci_dss="PCI-6",
                             attack_vector="Network", exploitability=1.2, impact=1.2)
        elif uses_tt_api:
            self.add_finding("Trusted Types API Without Enforcement", "low", False,
                             "Page references Trusted Types APIs but CSP does not require them",
                             category,
                             remediation="Enforce require-trusted-types-for 'script' so Trusted Types usage is mandatory.",
                             owasp="A03", nist="SC")
        else:
            self.add_finding("Trusted Types Not Detected", "low", False,
                             "No Trusted Types enforcement or client-side usage detected",
                             category,
                             remediation="Adopt Trusted Types to make DOM XSS sinks type-safe against injection.",
                             owasp="A03", nist="SC", pci_dss="PCI-6")

        if policy_dir:
            values = policy_dir.group(1).strip()
            if "*" in values.split():
                self.add_finding("Trusted Types Wildcard Policy", "medium", False,
                                 "trusted-types directive allows arbitrary policy names: " + values,
                                 category,
                                 remediation="Enumerate explicit policy names instead of '*' in trusted-types.",
                                 owasp="A03", nist="SC",
                                 attack_vector="Network", exploitability=1.2, impact=1.2)

    def check_csp_report_uri(self):
        category = "browser_policy"
        headers = self.response.headers if self.response else {}
        csp = headers.get("Content-Security-Policy", "")
        report_only = headers.get("Content-Security-Policy-Report-Only", "")
        report_to_header = headers.get("Report-To", "")
        reporting_endpoints = headers.get("Reporting-Endpoints", "")

        if not csp and not report_only:
            self.add_finding("CSP Reporting Not Configured", "medium", False,
                             "No CSP or Report-Only header, so policy violations cannot be reported",
                             category,
                             remediation="Deploy a CSP with report-uri/report-to, or start with Content-Security-Policy-Report-Only.",
                             owasp="A05", nist="AU", pci_dss="PCI-10")
            return

        combined = csp + ";" + report_only
        report_uri_match = re.search(r"report-uri\s+([^\s;]+)", combined, flags=re.I)
        report_to_match = re.search(r"report-to\s+([^\s;]+)", combined, flags=re.I)
        endpoint_group = bool(report_to_header or reporting_endpoints)

        if report_uri_match:
            endpoint = report_uri_match.group(1).strip()
            if "://" in endpoint:
                parsed_ep = urlparse(endpoint)
            elif endpoint.startswith("/"):
                parsed_ep = urlparse(self.scheme + "://" + self.domain + endpoint)
            else:
                parsed_ep = urlparse(self.scheme + "://" + self.domain + "/" + endpoint)
            if not parsed_ep.netloc or parsed_ep.netloc == self.domain:
                self.add_finding("CSP report-uri Configured", "info", True,
                                 "CSP report-uri endpoint: " + endpoint,
                                 category, owasp="A05", nist="AU")
            else:
                self.add_finding("CSP report-uri Third-Party Endpoint", "low", False,
                                 "CSP violations are reported to external host: " + parsed_ep.netloc,
                                 category,
                                 remediation="Confirm the third-party CSP collector is trusted; reports may contain sensitive URLs.",
                                 owasp="A05", nist="AU")
            if not report_to_match and not endpoint_group:
                self.add_finding("CSP Reporting Uses Legacy report-uri Only", "low", False,
                                 "Only deprecated report-uri is configured; report-to / Reporting-Endpoints are not set",
                                 category,
                                 remediation="Migrate to report-to with a Reporting-Endpoints header.",
                                 owasp="A05", nist="AU", pci_dss="PCI-10")
        elif report_to_match and endpoint_group:
            self.add_finding("CSP report-to Configured", "info", True,
                             "CSP report-to group '" + report_to_match.group(1).strip()
                             + "' is backed by Report-To/Reporting-Endpoints",
                             category, owasp="A05", nist="AU")
        else:
            self.add_finding("CSP Missing Reporting Directive", "medium", False,
                             "CSP present but no report-uri/report-to directive - violations fail silently",
                             category,
                             remediation="Add report-uri (and prefer report-to) pointing at your violation collector.",
                             owasp="A05", nist="AU", pci_dss="PCI-10")

        if report_only and not csp:
            self.add_finding("CSP Report-Only Mode", "info", True,
                             "Content-Security-Policy-Report-Only active - monitor reports before enforcing",
                             category, owasp="A05", nist="AU")
        elif report_only and csp:
            self.add_finding("CSP Report-Only Companion Policy", "info", True,
                             "A Report-Only policy runs alongside the enforcing CSP for staged rollout",
                             category, owasp="A05", nist="AU")

    # ──────────────────────────────────────────────────────────────────
    # SecurityChecker v6.0 — Permissions-Policy / Isolation / Fetch Metadata
    # ──────────────────────────────────────────────────────────────────

    def check_permissions_policy_analysis(self):
        category = "browser_policy"
        headers = self.response.headers if self.response else {}
        pp = headers.get("Permissions-Policy", "")
        legacy = headers.get("Feature-Policy", "")

        if not pp and not legacy:
            self.add_finding("Permissions-Policy Feature Analysis", "info", True,
                             "No Permissions-Policy header - feature restrictions tracked under HTTP Headers",
                             category, owasp="A05", nist="SC")
            return

        if legacy and not pp:
            self.add_finding("Legacy Feature-Policy Header", "low", False,
                             "Feature-Policy is deprecated; browsers expect Permissions-Policy",
                             category,
                             remediation="Replace Feature-Policy with Permissions-Policy.",
                             owasp="A05", nist="SC")
            return

        if legacy:
            self.add_finding("Redundant Legacy Feature-Policy", "low", False,
                             "Both Feature-Policy and Permissions-Policy are set; Feature-Policy is redundant",
                             category,
                             remediation="Remove Feature-Policy and keep only Permissions-Policy.",
                             owasp="A05", nist="SC")

        if not pp:
            return

        risky_features = [
            "camera", "microphone", "geolocation", "payment", "usb",
            "display-capture", "screen-wake-lock", "web-share", "autoplay",
            "midi", "serial", "hid", "bluetooth", "encrypted-media",
        ]
        sensitive_features = ("camera", "microphone", "geolocation", "display-capture")
        parsed_features = {}
        for part in pp.split(","):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name, _, value = part.partition("=")
            parsed_features[name.strip().lower()] = value.strip()

        if not parsed_features:
            self.add_finding("Permissions-Policy Unparseable", "low", False,
                             "Permissions-Policy header present but no feature directives could be parsed: " + pp[:120],
                             category,
                             remediation="Use the format: camera=(), geolocation=(self), ...",
                             owasp="A05", nist="SC")
            return

        open_features = []
        restricted_features = []
        for feat in risky_features:
            if feat not in parsed_features:
                open_features.append(feat)
                continue
            value = parsed_features[feat].replace(" ", "")
            if value == "*":
                open_features.append(feat)
            else:
                restricted_features.append(feat)

        sensitive_open = [f for f in open_features if f in sensitive_features]
        other_open = [f for f in open_features if f not in sensitive_features]

        if sensitive_open:
            self.add_finding("Permissions-Policy Sensitive Features Open", "medium", False,
                             "Sensitive browser features not restricted: " + ", ".join(sensitive_open),
                             category,
                             remediation="Deny or allowlist these in Permissions-Policy: "
                             + ", ".join(sensitive_open) + " = () or (self).",
                             owasp="A05", nist="SC", pci_dss="PCI-6")
        if other_open:
            self.add_finding("Permissions-Policy Additional Features Open", "low", False,
                             "Powerful features without explicit restriction: " + ", ".join(other_open[:6]),
                             category,
                             remediation="Explicitly allow or deny remaining powerful features.",
                             owasp="A05", nist="SC")
        if restricted_features and not open_features:
            self.add_finding("Permissions-Policy Feature Restrictions", "info", True,
                             "Risky features explicitly restricted: " + ", ".join(restricted_features[:8]),
                             category, owasp="A05", nist="SC")
        elif restricted_features:
            self.add_finding("Permissions-Policy Partial Restrictions", "info", True,
                             "Restricted: " + ", ".join(restricted_features[:6])
                             + (("; open: " + ", ".join(other_open[:4])) if other_open else ""),
                             category, owasp="A05", nist="SC")

        for privacy_feat in ("interest-cohort", "browsing-topics"):
            if privacy_feat in parsed_features and parsed_features[privacy_feat].replace(" ", "") == "()":
                self.add_finding("Permissions-Policy Topics Opt-Out", "info", True,
                                 "Permissions-Policy disables " + privacy_feat + " (ad-topic tracking)",
                                 category, owasp="A01", nist="AC")

    def check_isolation_policies(self):
        category = "browser_policy"
        headers = self.response.headers if self.response else {}
        coop = headers.get("Cross-Origin-Opener-Policy", "")
        coep = headers.get("Cross-Origin-Embedder-Policy", "")
        corp = headers.get("Cross-Origin-Resource-Policy", "")
        coop_lower = coop.lower()
        coep_lower = coep.lower()
        corp_lower = corp.lower()

        if not coop and not coep and not corp:
            self.add_finding("Isolation Policies Not Configured", "info", True,
                             "No COOP/COEP/CORP headers - individual gaps tracked under HTTP Headers",
                             category, owasp="A05", nist="SC")
            return

        if coop:
            if coop_lower in ("same-origin", "same-origin-allow-popups"):
                self.add_finding("COOP Value Strong", "info", True,
                                 "Cross-Origin-Opener-Policy: " + coop + " isolates the browsing context group",
                                 category, owasp="A05", nist="SC")
            elif coop_lower == "unsafe-none":
                self.add_finding("COOP unsafe-none", "medium", False,
                                 "Cross-Origin-Opener-Policy is unsafe-none - window.opener references remain reachable",
                                 category,
                                 remediation="Set Cross-Origin-Opener-Policy: same-origin.",
                                 owasp="A05", nist="SC", pci_dss="PCI-6")
            else:
                self.add_finding("COOP Non-Standard Value", "low", False,
                                 "Unrecognized Cross-Origin-Opener-Policy value: " + coop,
                                 category,
                                 remediation="Use same-origin or same-origin-allow-popups.",
                                 owasp="A05", nist="SC")

        if coep:
            if coep_lower in ("require-corp", "credentialless"):
                self.add_finding("COEP Value Strong", "info", True,
                                 "Cross-Origin-Embedder-Policy: " + coep + " enables cross-origin isolation",
                                 category, owasp="A05", nist="SC")
            elif coep_lower == "unsafe-none":
                self.add_finding("COEP unsafe-none", "low", False,
                                 "Cross-Origin-Embedder-Policy is unsafe-none",
                                 category,
                                 remediation="Set Cross-Origin-Embedder-Policy: require-corp (or credentialless).",
                                 owasp="A05", nist="SC")
            else:
                self.add_finding("COEP Non-Standard Value", "low", False,
                                 "Unrecognized Cross-Origin-Embedder-Policy value: " + coep,
                                 category,
                                 remediation="Use require-corp or credentialless.",
                                 owasp="A05", nist="SC")

        if corp:
            if corp_lower == "same-origin":
                self.add_finding("CORP Value Strong", "info", True,
                                 "Cross-Origin-Resource-Policy: same-origin blocks all cross-origin embedding",
                                 category, owasp="A05", nist="SC")
            elif corp_lower == "same-site":
                self.add_finding("CORP same-site", "low", False,
                                 "Cross-Origin-Resource-Policy allows sibling subdomains (same-site) to embed this resource",
                                 category,
                                 remediation="Prefer Cross-Origin-Resource-Policy: same-origin for sensitive responses.",
                                 owasp="A05", nist="SC")
            elif corp_lower == "cross-origin":
                self.add_finding("CORP cross-origin", "low", False,
                                 "Cross-Origin-Resource-Policy permits embedding by any site",
                                 category,
                                 remediation="Set Cross-Origin-Resource-Policy: same-origin or same-site.",
                                 owasp="A05", nist="SC")
            else:
                self.add_finding("CORP Non-Standard Value", "low", False,
                                 "Unrecognized Cross-Origin-Resource-Policy value: " + corp,
                                 category,
                                 remediation="Use same-origin, same-site, or cross-origin.",
                                 owasp="A05", nist="SC")

        isolated = (coop_lower == "same-origin"
                    and coep_lower in ("require-corp", "credentialless"))
        if isolated:
            self.add_finding("Cross-Origin Isolation Ready", "info", True,
                             "COOP same-origin + COEP " + coep + " enable crossOriginIsolated APIs",
                             category, owasp="A05", nist="SC")
        elif coop or coep:
            missing_bits = []
            if coop_lower != "same-origin":
                missing_bits.append("COOP same-origin")
            if coep_lower not in ("require-corp", "credentialless"):
                missing_bits.append("COEP require-corp/credentialless")
            self.add_finding("Cross-Origin Isolation Incomplete", "low", False,
                             "To enable crossOriginIsolated, set: " + " and ".join(missing_bits),
                             category,
                             remediation="Align COOP and COEP to enable cross-origin isolation for SharedArrayBuffer and related APIs.",
                             owasp="A05", nist="SC")

    def check_fetch_metadata(self):
        category = "browser_policy"
        if not self.response:
            return

        probe_headers = {
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-User": "?1",
            "Origin": "https://securitychecker-fetch-probe.invalid",
        }
        probe_status = None
        same_content = False
        try:
            probe = self.session.get(
                self.url, headers=probe_headers,
                timeout=max(2, self.timeout // 2),
                allow_redirects=False, verify=False,
            )
            probe_status = probe.status_code
            baseline_len = len(self.response.content or b"")
            probe_len = len(probe.content or b"")
            tolerance = max(64, baseline_len // 20)
            if probe.status_code == 200 and abs(probe_len - baseline_len) <= tolerance:
                same_content = True
        except requests.exceptions.RequestException:
            self.add_finding("Fetch Metadata Probe", "info", True,
                             "Could not probe Sec-Fetch-* header handling",
                             category)
            return

        if same_content:
            self.add_finding("Fetch Metadata Not Enforced", "low", False,
                             "Server served identical content to a forged cross-site Sec-Fetch-Site/Origin request (status "
                             + str(probe_status) + ")",
                             category,
                             remediation="Enforce Sec-Fetch-Site allowlists at the edge for sensitive routes and validate Origin.",
                             owasp="A05", nist="SC", pci_dss="PCI-6",
                             attack_vector="Network", exploitability=1.0, impact=1.0)
        else:
            self.add_finding("Fetch Metadata Differentiated Response", "info", True,
                             "Server response varies for forged Sec-Fetch-Site/Origin requests (status "
                             + str(probe_status) + ")",
                             category, owasp="A05", nist="SC")

        vary = self.response.headers.get("Vary", "")
        if "sec-fetch" in vary.lower():
            self.add_finding("Vary Includes Sec-Fetch", "info", True,
                             "Vary header accounts for Sec-Fetch-*: " + vary,
                             category, owasp="A05", nist="SC")

        csp = self.response.headers.get("Content-Security-Policy", "")
        if csp:
            if "form-action" not in csp.lower():
                self.add_finding("CSP Missing form-action", "low", False,
                                 "CSP does not restrict form-action targets (cross-site form posting possible)",
                                 category,
                                 remediation="Add form-action 'self' to CSP.",
                                 owasp="A05", nist="SC")
            else:
                self.add_finding("CSP form-action Present", "info", True,
                                 "CSP restricts form-action targets",
                                 category, owasp="A05", nist="SC")
            if "base-uri" not in csp.lower():
                self.add_finding("CSP Missing base-uri", "low", False,
                                 "CSP does not restrict <base> injection (base-uri missing)",
                                 category,
                                 remediation="Add base-uri 'self' to CSP.",
                                 owasp="A03", nist="SC")
            else:
                self.add_finding("CSP base-uri Present", "info", True,
                                 "CSP restricts base-uri injection",
                                 category, owasp="A03", nist="SC")

    # ──────────────────────────────────────────────────────────────────
    # SecurityChecker v6.0 — Advanced Vulnerability Detection
    # ──────────────────────────────────────────────────────────────────

    def check_advanced_prototype_pollution(self, category):
        base_url = self.scheme + "://" + self.domain
        marker = "securitychecker_polluted"
        json_payloads = [
            '{"__proto__": {"' + marker + '": "yes"}}',
            '{"constructor": {"prototype": {"' + marker + '": "yes"}}}',
        ]

        for payload in json_payloads:
            try:
                resp = self.session.post(
                    base_url, data=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=max(2, self.timeout // 2), verify=False,
                )
                if marker in resp.text.lower():
                    self.add_finding("Prototype Pollution Via JSON Body", "high", False,
                                     "Prototype pollution payload accepted and its marker reflected in the response",
                                     category,
                                     remediation="Strip __proto__/constructor keys on parse; use Object.create(null) for maps.",
                                     owasp="A03", nist="SI", pci_dss="PCI-6",
                                     attack_vector="Network", exploitability=1.5, impact=1.5)
                    return
            except requests.exceptions.RequestException:
                pass

        query_payloads = [
            "__proto__[" + marker + "]=yes",
            "constructor[prototype][" + marker + "]=yes",
        ]
        for qp in query_payloads:
            try:
                resp = self.session.get(
                    base_url + "?" + qp,
                    timeout=max(2, self.timeout // 2),
                    allow_redirects=False, verify=False,
                )
                if marker in resp.text.lower():
                    self.add_finding("Prototype Pollution Via Query Parameters", "high", False,
                                     "Pollution key in query string reflected back: " + qp[:60],
                                     category,
                                     remediation="Reject __proto__/constructor keys in parameter parsers.",
                                     owasp="A03", nist="SI", pci_dss="PCI-6",
                                     attack_vector="Network", exploitability=1.5, impact=1.5)
                    return
            except requests.exceptions.RequestException:
                pass

        text_lower = self.html_content.lower()
        client_patterns = []
        for pattern, label in [
            ("__proto__", "literal __proto__ key handling"),
            ("constructor.prototype", "constructor.prototype access"),
            ('constructor["prototype"]', "constructor[prototype] access"),
            ("extend(true", "deep recursive object extend"),
            ("$.extend(true", "deep jQuery extend"),
            ("Object.assign(", "Object.assign merge of objects"),
        ]:
            if pattern in text_lower and label not in client_patterns:
                client_patterns.append(label)

        if client_patterns:
            self.add_finding("Prototype Pollution Primitives In Client Code", "medium", False,
                             "Merge/pollution-related patterns in shipped JavaScript: " + "; ".join(client_patterns[:4]),
                             category,
                             remediation="Avoid deep merges of untrusted objects; block __proto__/constructor keys and use Object.create(null) maps.",
                             owasp="A03", nist="SI", pci_dss="PCI-6",
                             attack_vector="Network", exploitability=1.2, impact=1.2)
        else:
            self.add_finding("Advanced Prototype Pollution Test", "info", True,
                             "No server-side or client-side prototype pollution primitives detected",
                             category, owasp="A03", nist="SI")

    def check_dom_clobbering(self, category):
        if not self.soup:
            return

        sensitive_targets = {
            "attributes", "cookie", "body", "head", "children", "firstchild",
            "getelementbyid", "forms", "elements", "defaultstatus", "referrer",
            "location", "opener", "parent", "top", "self", "document", "window",
            "nonce", "base", "src", "href", "action", "method", "sessionstorage",
            "localstorage", "caches", "navigator",
        }
        clobber_refs = []
        for tag in self.soup.find_all(True):
            tid = (tag.get("id") or "").lower()
            tname = (tag.get("name") or "").lower()
            if tid and tid in sensitive_targets:
                clobber_refs.append(tag.name + "#" + tid)
            if tname and tname in sensitive_targets and tag.name in (
                    "form", "input", "img", "a", "object", "embed", "button"):
                clobber_refs.append(tag.name + "[name=" + tname + "]")

        clobber_refs = list(dict.fromkeys(clobber_refs))
        script_text = self.html_content.lower()
        uses_document_props = bool(re.search(
            r"document\.(cookie|location|referrer|forms|body|domain)", script_text))

        if clobber_refs:
            sev = "medium" if uses_document_props else "low"
            self.add_finding("DOM Clobbering Vectors", sev, False,
                             "Elements shadow sensitive DOM properties: " + ", ".join(clobber_refs[:5]),
                             category,
                             remediation="Rename ids/names that shadow document/window properties; do not trust document.<name> for security decisions.",
                             owasp="A03", nist="SC",
                             attack_vector="Network", exploitability=1.0, impact=1.0)
            if uses_document_props:
                self.add_finding("DOM Clobbering Sink Usage", "medium", False,
                                 "Scripts read document.cookie/location/forms/body - clobbered globals can influence security checks",
                                 category,
                                 remediation="Avoid DOM property lookups for authz decisions; use hardened accessors and explicit parameters.",
                                 owasp="A03", nist="SC",
                                 attack_vector="Network", exploitability=1.2, impact=1.2)
        else:
            self.add_finding("No DOM Clobbering Vectors", "info", True,
                             "No ids/names found that shadow common sensitive DOM properties",
                             category, owasp="A03", nist="SC")

        if self.soup.find("base"):
            self.add_finding("HTML base Tag Present", "low", False,
                             "<base> element can clobber relative URL resolution if ever user-influenced",
                             category,
                             remediation="Constrain base-uri in CSP and avoid user-controlled <base> elements.",
                             owasp="A03", nist="SC")

    def check_css_injection(self, category):
        text_lower = self.html_content.lower()
        dangerous_css = []
        for pattern, label in [
            ("expression(", "CSS expression() script execution (legacy IE)"),
            ("behavior:", "CSS behavior property script execution (legacy IE)"),
            ("-moz-binding", "CSS -moz-binding XBL script binding"),
            ("javascript:", "javascript: URL reference in CSS/HTML"),
            ("@import", "dynamic @import of external stylesheet"),
        ]:
            if pattern in text_lower and label not in dangerous_css:
                dangerous_css.append(label)

        reflected = False
        marker = "cssinjectprobe7x91"
        base_url = self.scheme + "://" + self.domain
        try:
            payload = quote('";}</style><span id="' + marker + '">', safe="")
            resp = self.session.get(
                base_url + "?q=" + payload,
                timeout=max(2, self.timeout // 2),
                allow_redirects=False, verify=False,
            )
            if marker in resp.text and ('id="' + marker) in resp.text:
                reflected = True
        except requests.exceptions.RequestException:
            pass

        if reflected:
            self.add_finding("CSS/Style Breakout Injection", "high", False,
                             "Style-breakout payload reflected raw into the response body",
                             category,
                             remediation="Context-encode all reflected input; prevent </style> breakout via output encoding and CSP.",
                             owasp="A03", nist="SC", pci_dss="PCI-6",
                             attack_vector="Network", exploitability=1.5, impact=1.5)
            return

        if dangerous_css:
            self.add_finding("Dangerous CSS Patterns", "medium", False,
                             "Risky CSS constructs found: " + "; ".join(dangerous_css[:4]),
                             category,
                             remediation="Remove expression()/behavior/-moz-binding/javascript: URLs and restrict @import to trusted origins.",
                             owasp="A03", nist="SC",
                             attack_vector="Network", exploitability=1.0, impact=1.0)
        else:
            self.add_finding("CSS Injection Test", "info", True,
                             "No style-breakout reflection or dangerous CSS constructs detected",
                             category, owasp="A03", nist="SC")

    def check_html_injection(self, category):
        base_url = self.scheme + "://" + self.domain
        marker = "scHtmlInject918273"
        payloads = [
            ("<h1>" + marker + "</h1>", "element"),
            ('"><b id="' + marker + 'b">x</b>', "attribute-breakout"),
        ]
        detected = None
        for payload, kind in payloads:
            try:
                resp = self.session.get(
                    base_url + "?q=" + quote(payload, safe=""),
                    timeout=max(2, self.timeout // 2),
                    allow_redirects=False, verify=False,
                )
                if marker in resp.text:
                    detected = kind
                    break
            except requests.exceptions.RequestException:
                continue

        if detected:
            sev = "high" if detected == "attribute-breakout" else "medium"
            self.add_finding("HTML Injection Detected", sev, False,
                             "User input reflected as raw HTML (" + detected + " context)",
                             category,
                             remediation="HTML-encode all reflected input; use safe DOM APIs (textContent) on the client.",
                             owasp="A03", nist="SC", pci_dss="PCI-6",
                             attack_vector="Network", exploitability=1.5, impact=1.5)
            return

        raw_patterns = []
        if re.search(r"innerHTML\s*=\s*[\"'].*<", self.html_content):
            raw_patterns.append("innerHTML assigned literal HTML")
        if "document.write(" in self.html_content.lower():
            raw_patterns.append("document.write usage")
        if "insertadjacenthtml" in self.html_content.lower():
            raw_patterns.append("insertAdjacentHTML usage")

        if raw_patterns:
            self.add_finding("HTML Injection Primitives In Client Code", "low", False,
                             "Client-side HTML injection sinks: " + ", ".join(raw_patterns[:4]),
                             category,
                             remediation="Prefer textContent/setAttribute; sanitize any HTML with a vetted library if unavoidable.",
                             owasp="A03", nist="SC")
        else:
            self.add_finding("HTML Injection Test", "info", True,
                             "Reflection probes did not return raw HTML injections",
                             category, owasp="A03", nist="SC")

    def check_header_injection(self, category):
        base_url = self.scheme + "://" + self.domain
        injected_header_name = "X-SecurityChecker-Inject"
        crlf_payloads = [
            "%0d%0a" + injected_header_name + ":%20true",
            "%0a" + injected_header_name + ":%20true",
        ]
        found_header = False
        for encoded in crlf_payloads:
            try:
                resp = self.session.get(
                    base_url + "?q=" + encoded,
                    timeout=max(2, self.timeout // 2),
                    allow_redirects=False, verify=False,
                )
                if injected_header_name in resp.headers:
                    found_header = True
                    break
            except requests.exceptions.RequestException:
                continue

        if found_header:
            self.add_finding("HTTP Header Injection (CRLF)", "critical", False,
                             "CRLF payload in query parameter injected a custom response header",
                             category,
                             remediation="Reject CR/LF in all input; canonicalize and validate header values at output.",
                             owasp="A03", nist="SC", pci_dss="PCI-6",
                             attack_vector="Network", exploitability=2.0, impact=2.0)
        else:
            suspicious_headers = []
            if self.response:
                for name, value in self.response.headers.items():
                    if "\r" in value or "\n" in value:
                        suspicious_headers.append(name)
                    if re.search(r"<script|javascript:", value, re.I):
                        suspicious_headers.append(name)
            if suspicious_headers:
                self.add_finding("Suspicious Response Header Values", "high", False,
                                 "Header(s) contain CR/LF or active content: " + ", ".join(sorted(set(suspicious_headers))[:5]),
                                 category,
                                 remediation="Sanitize header values; never echo raw user input into response headers.",
                                 owasp="A03", nist="SC", pci_dss="PCI-6")
            else:
                self.add_finding("Header Injection Test", "info", True,
                                 "CRLF probes did not inject headers; no CR/LF found in response header values",
                                 category, owasp="A03", nist="SC")

        try:
            resp = self.session.get(
                base_url,
                headers={"X-Forwarded-Host": "sc-host-probe.invalid"},
                timeout=max(2, self.timeout // 2),
                allow_redirects=False, verify=False,
            )
            location = resp.headers.get("Location", "")
            body_head = resp.text[:4000]
            if "sc-host-probe.invalid" in location or "sc-host-probe.invalid" in body_head:
                self.add_finding("Host/Header Reflection", "medium", False,
                                 "X-Forwarded-Host value reflected in Location or response body",
                                 category,
                                 remediation="Ignore untrusted Host/X-Forwarded-Host inputs or validate against an allowlist.",
                                 owasp="A01", nist="AC", pci_dss="PCI-6")
        except requests.exceptions.RequestException:
            pass

    # -----------------------------------------------------------------
    # SecurityChecker v7.0 - New Security Checks
    # -----------------------------------------------------------------

    def check_waf_detection(self):
        category = "waf"
        headers = self.response.headers if self.response else {}
        header_keys_lower = {k.lower() for k in headers.keys()}
        products = []

        for hdr, product in WAF_HEADER_SIGNATURES.items():
            if hdr.lower() in header_keys_lower and product not in products:
                products.append(product)

        server = headers.get("Server", "").lower()
        powered = headers.get("X-Powered-By", "").lower()
        for hint in WAF_SERVER_HINTS:
            if hint in server or hint in powered:
                label = hint.upper()
                if label not in products:
                    products.append(label)

        body_lower = (self.html_content or "").lower()
        for marker, product in WAF_BODY_SIGNATURES.items():
            if marker in body_lower and product not in products:
                products.append(product)

        self.waf_products = list(dict.fromkeys(products))

        if self.waf_products:
            self.add_finding("Web Application Firewall Detected", "info", True,
                             "WAF/edge protection indicators: " + ", ".join(self.waf_products[:6]),
                             category, owasp="A05", nist="SC", pci_dss="PCI-1")
        else:
            self.add_finding("No Web Application Firewall Detected", "high", False,
                             "No WAF, CDN security or edge protection headers detected",
                             category,
                             remediation="Deploy a Web Application Firewall (Cloudflare, AWS WAF, ModSecurity) with managed rule sets.",
                             owasp="A05", nist="SC", pci_dss="PCI-1",
                             attack_vector="Network", exploitability=1.5, impact=1.5)

        probe_payloads = WAF_PROBE_PAYLOADS[:3]
        blocked = 0
        passed_payloads = 0
        for payload in probe_payloads:
            sep = "&" if self.parsed.query else "?"
            probe_url = self.url + sep + "scwafprobe=" + quote(payload, safe="")
            try:
                resp = self.session.get(
                    probe_url,
                    timeout=max(2, self.timeout // 2),
                    allow_redirects=False, verify=False,
                )
                body = resp.text.lower()
                if resp.status_code in (403, 406, 429, 451, 503) or any(
                        ind in body for ind in WAF_BODY_BLOCK_INDICATORS):
                    blocked += 1
                else:
                    passed_payloads += 1
            except requests.exceptions.RequestException:
                continue

        if probe_payloads:
            if blocked >= 1 and passed_payloads == 0:
                self.add_finding("WAF Blocks Attack Payloads", "info", True,
                                 "Blocked " + str(blocked) + "/" + str(len(probe_payloads))
                                 + " probe payloads (403/406/429/503 or block page)",
                                 category, owasp="A03", nist="SC", pci_dss="PCI-1")
            elif blocked == 0 and passed_payloads > 0:
                self.add_finding("WAF Not Blocking Attack Payloads", "medium", False,
                                 "All " + str(passed_payloads)
                                 + " probe payloads returned normal responses - no active request filtering observed",
                                 category,
                                 remediation="Enable managed SQLi/XSS rule sets and tune false-positive exclusions.",
                                 owasp="A03", nist="SC", pci_dss="PCI-1",
                                 attack_vector="Network", exploitability=1.2, impact=1.2)
            elif blocked > 0:
                self.add_finding("WAF Partial Request Filtering", "low", False,
                                 "Blocked " + str(blocked) + " of " + str(len(probe_payloads))
                                 + " probe payloads; some request classes appear unfiltered",
                                 category,
                                 remediation="Review WAF rule coverage for the unfiltered payload classes.",
                                 owasp="A03", nist="SC")

    def check_bot_protection(self):
        category = "bot_protection"
        text_lower = (self.html_content or "").lower()
        headers = self.response.headers if self.response else {}
        found = []

        for name, patterns in BOT_PROTECTION_SIGNATURES.items():
            for pat in patterns:
                if pat.lower() in text_lower:
                    found.append(name)
                    break

        cookie_names = [c.name.lower() for c in self.session.cookies]
        for cookie_name, label in BOT_COOKIE_SIGNATURES.items():
            if cookie_name in cookie_names and label not in found:
                found.append(label)

        for h in headers.keys():
            hl = h.lower()
            if any(k in hl for k in ("cf-chl", "cf-clearance", "x-captcha", "x-challenge")):
                found.append("Challenge header " + h)

        self.bot_protection_found = list(dict.fromkeys(found))

        if self.bot_protection_found:
            self.add_finding("Bot Protection Detected", "info", True,
                             "Bot/automation defenses: " + ", ".join(self.bot_protection_found[:6]),
                             category, owasp="A07", nist="AC", pci_dss="PCI-8")
        else:
            self.add_finding("No Bot Protection Detected", "medium", False,
                             "No CAPTCHA, challenge page, or bot-mitigation scripts detected",
                             category,
                             remediation="Add CAPTCHA or a managed challenge on sensitive flows (login, signup, contact).",
                             owasp="A07", nist="AC", pci_dss="PCI-8",
                             attack_vector="Network", exploitability=1.2, impact=1.0)

        scrape_indicators = []
        header_keys_lower = {k.lower() for k in headers.keys()}
        if "x-robots-tag" in header_keys_lower:
            scrape_indicators.append("X-Robots-Tag present")
        robots = None
        try:
            robots_url = self.scheme + "://" + self.domain + "/robots.txt"
            robots = self.session.get(robots_url, timeout=max(2, self.timeout // 2), verify=False)
        except requests.exceptions.RequestException:
            robots = None
        if robots is not None and robots.status_code == 200:
            rl = robots.text.lower()
            if "disallow" in rl:
                scrape_indicators.append("robots.txt Disallow rules present")
            if "crawl-delay" in rl:
                scrape_indicators.append("crawl-delay configured")
        if scrape_indicators:
            self.add_finding("Crawler Guidance Configured", "info", True,
                             "; ".join(scrape_indicators),
                             category, owasp="A05", nist="CM")

    def check_rate_limiting(self):
        category = "rate_limiting"
        headers = self.response.headers if self.response else {}
        header_keys_lower = {k.lower() for k in headers.keys()}
        found_headers = [h for h in RATE_LIMIT_HEADERS if h.lower() in header_keys_lower]
        self.rate_limit_signals = found_headers

        if found_headers:
            self.add_finding("Rate Limiting Headers Present", "info", True,
                             "Rate limit headers: " + ", ".join(found_headers[:6]),
                             category, owasp="A04", nist="SC", pci_dss="PCI-6")
        else:
            self.add_finding("No Rate Limiting Headers", "medium", False,
                             "Response omits RateLimit/X-RateLimit/Retry-After headers",
                             category,
                             remediation="Emit RateLimit-Limit/Remaining/Reset (or X-RateLimit-*) on API and form responses.",
                             owasp="A04", nist="SC", pci_dss="PCI-6",
                             attack_vector="Network", exploitability=1.2, impact=1.2)

        burst = 8
        limited = 0
        ok = 0
        for _ in range(burst):
            try:
                resp = self.session.get(
                    self.url, timeout=max(2, self.timeout // 2),
                    allow_redirects=False, verify=False,
                )
                if resp.status_code in (429, 503):
                    limited += 1
                elif resp.status_code < 500:
                    ok += 1
            except requests.exceptions.RequestException:
                continue

        if limited > 0:
            self.add_finding("Rate Limiting Enforced", "info", True,
                             str(limited) + " of " + str(burst) + " rapid requests returned 429/503",
                             category, owasp="A04", nist="SC", pci_dss="PCI-6")
        elif ok >= burst:
            self.add_finding("Rate Limiting Not Enforced", "medium", False,
                             "Sent " + str(burst) + " rapid requests with no 429/503 throttling",
                             category,
                             remediation="Apply per-IP and per-account rate limits with exponential backoff and Retry-After.",
                             owasp="A04", nist="SC", pci_dss="PCI-6",
                             attack_vector="Network", exploitability=1.5, impact=1.5)

    def check_account_lockout(self):
        category = "account_lockout"
        text_lower = (self.html_content or "").lower()
        found_msgs = [m for m in LOCKOUT_MESSAGES if m in text_lower]
        self.lockout_signals = found_msgs

        login_forms = []
        if self.soup:
            for form in self.soup.find_all("form"):
                inputs = [(i.get("type") or "").lower() for i in form.find_all("input")]
                if "password" in inputs:
                    login_forms.append(form)

        has_login_surface = bool(login_forms) or any(
            kw in text_lower for kw in ("sign in", "log in", "login", "password")
        )

        if not has_login_surface:
            self.add_finding("Account Lockout Surface", "info", True,
                             "No login form detected - account lockout not directly assessable",
                             category, owasp="A07", nist="AC")
            return

        if found_msgs:
            self.add_finding("Account Lockout Messaging Detected", "info", True,
                             "Lockout/throttle hints in page content: " + ", ".join(found_msgs[:4]),
                             category, owasp="A07", nist="AC", pci_dss="PCI-8", hipaa="HIPAA-PS")
        else:
            self.add_finding("No Account Lockout Indicators", "medium", False,
                             "Login surface found without visible lockout, delay, or failed-attempt messaging",
                             category,
                             remediation="Lock accounts or apply progressive delay after 5-10 failed logins; show clear lockout messaging.",
                             owasp="A07", nist="AC", pci_dss="PCI-8", hipaa="HIPAA-PS",
                             attack_vector="Network", exploitability=1.5, impact=1.5)

        probe_user = "sc_lockout_" + str(int(time.time()))[-6:]
        lockout_seen = False
        attempt = 0
        for attempt in range(3):
            try:
                resp = self.session.post(
                    self.url,
                    data={"username": probe_user, "email": probe_user + "@invalid.example",
                          "password": "WrongPass!23", "log": probe_user, "login": probe_user,
                          "user": probe_user, "pass": "WrongPass!23"},
                    timeout=max(2, self.timeout // 2),
                    allow_redirects=False, verify=False,
                )
                body = resp.text.lower()
                if resp.status_code == 429 or any(m in body for m in LOCKOUT_MESSAGES[:6]):
                    lockout_seen = True
                    break
            except requests.exceptions.RequestException:
                break

        if lockout_seen:
            self.add_finding("Login Throttling Active", "info", True,
                             "Failed-login probe triggered 429/lockout messaging on attempt "
                             + str(attempt + 1),
                             category, owasp="A07", nist="AC", pci_dss="PCI-8")
        else:
            self.add_finding("Login Throttling Not Observed", "low", False,
                             "Failed-login probes to a non-existent user produced no throttle or lockout response",
                             category,
                             remediation="Add IP and account-based failed-login throttling before enabling full lockout policies.",
                             owasp="A07", nist="AC", pci_dss="PCI-8",
                             attack_vector="Network", exploitability=1.5, impact=1.0)

    def check_mfa_detection(self):
        category = "mfa"
        text_lower = (self.html_content or "").lower()
        signals = []

        for kw in MFA_KEYWORDS:
            if kw in text_lower:
                signals.append(kw)

        if self.soup:
            for inp in self.soup.find_all("input"):
                name = (inp.get("name") or "").lower()
                placeholder = (inp.get("placeholder") or "").lower()
                autocomplete = (inp.get("autocomplete") or "").lower()
                joined = name + " " + placeholder
                if any(k in joined for k in ("otp", "totp", "mfa", "2fa", "verification_code", "one-time")):
                    signals.append("input:" + (name or placeholder))
                if autocomplete == "one-time-code":
                    signals.append("autocomplete=one-time-code")

        base_url = self.scheme + "://" + self.domain
        for path in MFA_PATHS:
            if len(signals) > 6:
                break
            try:
                resp = self.session.get(base_url + path, timeout=max(2, self.timeout // 2),
                                        allow_redirects=False, verify=False)
                if resp.status_code in (200, 401, 403):
                    body = resp.text.lower()
                    if any(k in body for k in MFA_KEYWORDS[:8]):
                        signals.append("path:" + path)
                    elif resp.status_code == 200 and len(resp.text) > 20:
                        signals.append("path:" + path)
            except requests.exceptions.RequestException:
                continue

        self.mfa_signals = list(dict.fromkeys(signals))
        has_login = bool(self.soup and self.soup.find("input", attrs={"type": "password"}))

        if self.mfa_signals:
            self.add_finding("Multi-Factor Authentication Detected", "info", True,
                             "MFA indicators: " + ", ".join(self.mfa_signals[:6]),
                             category, owasp="A07", nist="IA", pci_dss="PCI-8", hipaa="HIPAA-PS")
        elif has_login:
            self.add_finding("No Multi-Factor Authentication Detected", "high", False,
                             "Login surface present with no MFA/OTP/2FA indicators",
                             category,
                             remediation="Offer TOTP/WebAuthn MFA and require it for privileged accounts.",
                             owasp="A07", nist="IA", pci_dss="PCI-8", hipaa="HIPAA-PS",
                             attack_vector="Network", exploitability=1.5, impact=2.0)
        else:
            self.add_finding("MFA Assessment", "info", True,
                             "No login form or MFA endpoints discovered to assess",
                             category, owasp="A07", nist="IA")

    def check_password_policy(self):
        category = "password_policy"
        if not self.soup:
            return

        password_inputs = self.soup.find_all("input", attrs={"type": "password"})
        if not password_inputs:
            self.add_finding("Password Policy Surface", "info", True,
                             "No password input found - password policy not directly assessable",
                             category, owasp="A07", nist="IA")
            return

        text_lower = (self.html_content or "").lower()
        signals = []
        min_length = None
        autocomplete_values = []

        for inp in password_inputs:
            ml = inp.get("minlength")
            if ml:
                try:
                    val = int(ml)
                    if min_length is None or val < min_length:
                        min_length = val
                except (TypeError, ValueError):
                    pass
            ac = (inp.get("autocomplete") or "").lower()
            if ac:
                autocomplete_values.append(ac)
            if inp.get("required") is not None:
                signals.append("required attribute")
            if inp.get("pattern"):
                signals.append("pattern attribute")

        text_rules = []
        for label, rx in PASSWORD_POLICY_PATTERNS:
            if re.search(rx, text_lower):
                text_rules.append(label)
        if text_rules:
            signals.extend(text_rules)

        if "new-password" in autocomplete_values:
            signals.append("autocomplete=new-password")
        if "current-password" in autocomplete_values and len(password_inputs) >= 2:
            signals.append("change-password form (current + new)")

        self.password_policy_signals = list(dict.fromkeys(signals))

        issues = []
        if (min_length is None and "min_length" not in text_rules
                and not re.search(r"at least\s+\d+\s+char", text_lower)):
            issues.append("no minimum length requirement found")
        elif min_length is not None and min_length < 8:
            issues.append("minimum length " + str(min_length) + " is below 8 characters")
        complexity_advertised = any(
            r in text_rules for r in ("uppercase", "lowercase", "digit", "special"))
        if not complexity_advertised and not re.search(
                r"upper.?case|lower.?case|special|number|digit", text_lower):
            issues.append("no complexity requirements advertised")

        if issues:
            sev = "high" if (min_length is not None and min_length < 8) else "medium"
            self.add_finding("Weak or Undisclosed Password Policy", sev, False,
                             "Password policy gaps: " + "; ".join(issues),
                             category, owasp="A07", nist="IA", pci_dss="PCI-8", hipaa="HIPAA-PS",
                             remediation="Require at least 12 characters (or a passphrase), block common passwords, and check breach corpora.",
                             attack_vector="Network", exploitability=1.2, impact=1.5)
        else:
            detail = (", ".join(self.password_policy_signals[:8])
                      if self.password_policy_signals else "policy text detected")
            self.add_finding("Password Policy Indicators Present", "info", True,
                             "Signals: " + detail,
                             category, owasp="A07", nist="IA", pci_dss="PCI-8")

        if any(a == "on" for a in autocomplete_values):
            self.add_finding("Weak Password Autocomplete", "low", False,
                             "Password field uses autocomplete=on which can weaken credential hygiene",
                             category,
                             remediation="Use autocomplete=current-password/new-password only where appropriate; avoid autocomplete=on.",
                             owasp="A07", nist="IA")

    # -----------------------------------------------------------------
    # SecurityChecker v7.0 - Better Vulnerability Detection
    # -----------------------------------------------------------------

    def check_advanced_injection_testing(self):
        category = "advanced_vuln"
        base_url = self.scheme + "://" + self.domain

        cmd_marker = "scmd" + str(int(time.time()))[-5:]
        cmd_payloads = [
            "; echo " + cmd_marker,
            "| echo " + cmd_marker,
            "`echo " + cmd_marker + "`",
            "$(echo " + cmd_marker + ")",
        ]
        for payload in cmd_payloads:
            try:
                resp = self.session.get(
                    base_url + "?q=" + quote(payload, safe=""),
                    timeout=max(2, self.timeout // 2),
                    allow_redirects=False, verify=False,
                )
                if cmd_marker in resp.text and payload not in resp.text:
                    self.add_finding("OS Command Injection", "critical", False,
                                     "Shell command payload executed and marker reflected: " + payload[:40],
                                     category, cve="CVE-2024-CMDI",
                                     remediation="Never pass user input to a shell; use argument arrays and strict allowlists.",
                                     owasp="A03", nist="SI", pci_dss="PCI-6",
                                     attack_vector="Network", exploitability=2.0, impact=2.0)
                    return
            except requests.exceptions.RequestException:
                continue

        xpath_payloads = ["' or '1'='1", "1' or '1'='1' --", '" or "1"="1']
        xpath_indicators = ["xpath", "xml document", "invalid expression",
                            "error in xml document", "lxml", "simplexml"]
        for payload in xpath_payloads:
            try:
                resp = self.session.get(
                    base_url + "?id=" + quote(payload, safe=""),
                    timeout=max(2, self.timeout // 2),
                    allow_redirects=False, verify=False,
                )
                body = resp.text.lower()
                if any(ind in body for ind in xpath_indicators):
                    self.add_finding("XPath Injection Hint", "high", False,
                                     "XPath error pattern returned for payload: " + payload,
                                     category,
                                     remediation="Use parameterized XPath queries or avoid XPath over user input.",
                                     owasp="A03", nist="SI", pci_dss="PCI-6",
                                     attack_vector="Network", exploitability=1.5, impact=1.5)
                    return
            except requests.exceptions.RequestException:
                continue

        try:
            baseline = self.session.get(base_url, timeout=max(2, self.timeout // 2), verify=False)
            hpp = self.session.get(base_url + "?id=1&id=2", timeout=max(2, self.timeout // 2), verify=False)
            if baseline.status_code == 200 and hpp.status_code == 200:
                diff = abs(len(baseline.text) - len(hpp.text))
                if diff > max(100, len(baseline.text) // 10):
                    self.add_finding("HTTP Parameter Pollution Hint", "medium", False,
                                     "Duplicate parameter response differs from baseline by " + str(diff) + " bytes",
                                     category,
                                     remediation="Canonicalize and validate parameter arrays server-side; reject ambiguous duplicates.",
                                     owasp="A03", nist="SI", pci_dss="PCI-6",
                                     attack_vector="Network", exploitability=1.2, impact=1.2)
        except requests.exceptions.RequestException:
            pass

        self.add_finding("Advanced Injection Probes", "info", True,
                         "Tested OS command, XPath and HTTP parameter pollution vectors without confirmed execution",
                         category, owasp="A03", nist="SI")

    def check_authentication_bypass(self):
        category = "auth_security"
        base_url = self.scheme + "://" + self.domain
        protected_paths = [
            "/admin", "/admin/", "/dashboard", "/manage", "/management",
            "/console", "/wp-admin/", "/backend", "/internal", "/private",
        ]
        bypass_headers = [
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
        ]
        sensitive_markers = ["password", "secret", "api_key", "apikey", "token",
                             "admin panel", "user management", "database"]

        bypass_hits = []
        exposed = []
        for path in protected_paths:
            try:
                resp = self.session.get(base_url + path, timeout=max(2, self.timeout // 2),
                                        allow_redirects=False, verify=False)
                if resp.status_code == 200:
                    body = resp.text.lower()
                    hits = [m for m in sensitive_markers if m in body]
                    if hits:
                        exposed.append(path + " (" + ",".join(hits[:3]) + ")")
            except requests.exceptions.RequestException:
                continue

        for hdr_set in bypass_headers:
            try:
                resp = self.session.get(base_url + "/admin", headers=hdr_set,
                                        timeout=max(2, self.timeout // 2),
                                        allow_redirects=False, verify=False)
                if resp.status_code == 200:
                    body = resp.text.lower()
                    if any(m in body for m in sensitive_markers):
                        bypass_hits.append(list(hdr_set.keys())[0])
            except requests.exceptions.RequestException:
                continue

        if bypass_hits:
            self.add_finding("Authentication Bypass Via Headers", "critical", False,
                             "Privileged content served with spoofed header(s): " + ", ".join(bypass_hits),
                             category,
                             remediation="Ignore client-supplied routing/IP headers at the edge; enforce server-side authz on every request.",
                             owasp="A01", nist="AC", pci_dss="PCI-7", hipaa="HIPAA-AC",
                             attack_vector="Network", exploitability=2.0, impact=2.0)

        if exposed:
            self.add_finding("Unauthenticated Sensitive Page Content", "high", False,
                             "Protected-looking path(s) returned sensitive content without auth: "
                             + "; ".join(exposed[:4]),
                             category,
                             remediation="Require authentication and authorization before rendering any administrative content.",
                             owasp="A01", nist="AC", pci_dss="PCI-7", hipaa="HIPAA-AC",
                             attack_vector="Network", exploitability=1.5, impact=2.0)

        if not bypass_hits and not exposed:
            self.add_finding("Authentication Bypass Probes", "info", True,
                             "Tested " + str(len(protected_paths)) + " privileged paths and "
                             + str(len(bypass_headers)) + " spoofed-header bypasses with no confirmed bypass",
                             category, owasp="A01", nist="AC", pci_dss="PCI-7")

    def check_session_fixation(self):
        category = "auth_security"
        session_cookie_names = []
        for cookie in self.session.cookies:
            name_l = cookie.name.lower()
            if any(k in name_l for k in ("session", "sess", "sid", "jsessionid",
                                         "phpsessid", "asp.net_sessionid", "auth")):
                session_cookie_names.append(cookie.name)

        set_cookie_raw = self.response.headers.get("Set-Cookie", "") if self.response else ""

        fixation_params = ["sid", "sessionid", "session_id", "phpsessid", "jsessionid",
                           "sess", "session"]
        url_accepts_session = False
        if self.parsed.query:
            params = parse_qs(self.parsed.query, keep_blank_values=True)
            for p in params:
                if p.lower() in fixation_params:
                    url_accepts_session = True

        probe_value = "scfix" + str(int(time.time()))[-6:]
        accepted_via_url = False
        for p in ("sid", "sessionid"):
            if accepted_via_url:
                break
            try:
                probe_url = self.scheme + "://" + self.domain + "?" + p + "=" + probe_value
                resp = self.session.get(probe_url, timeout=max(2, self.timeout // 2),
                                        allow_redirects=False, verify=False)
                sc = resp.headers.get("Set-Cookie", "")
                if probe_value in sc or probe_value in resp.text:
                    accepted_via_url = True
            except requests.exceptions.RequestException:
                continue

        indicators = []
        if session_cookie_names:
            indicators.append("session cookie(s): " + ", ".join(session_cookie_names[:4]))
        if set_cookie_raw and "httponly" not in set_cookie_raw.lower():
            indicators.append("Set-Cookie lacks HttpOnly hint on main response")
        if url_accepts_session or accepted_via_url:
            indicators.append("session identifier accepted via URL parameter")

        if accepted_via_url or url_accepts_session:
            self.add_finding("Session Fixation Risk", "high", False,
                             "Session identifiers accepted from the URL: " + "; ".join(indicators),
                             category,
                             remediation="Never accept session IDs from the URL; regenerate session IDs after login and on privilege change.",
                             owasp="A07", nist="AC", pci_dss="PCI-8", hipaa="HIPAA-PS",
                             attack_vector="Network", exploitability=1.5, impact=1.5)
        elif session_cookie_names:
            self.add_finding("Session Cookie Baseline", "info", True,
                             "Session cookies observed; URL-based session IDs not accepted. Verify server regenerates IDs post-login.",
                             category, owasp="A07", nist="AC", pci_dss="PCI-8")
        else:
            self.add_finding("No Session Cookies Detected", "info", True,
                             "No session cookie observed on the initial response",
                             category, owasp="A07", nist="AC")

    def check_privilege_escalation_hints(self):
        category = "auth_security"
        text_lower = (self.html_content or "").lower()
        hints = []

        client_role_patterns = [
            ("isadmin", "client-side isAdmin flag"),
            ("is_admin", "client-side is_admin flag"),
            ("role=admin", "role=admin in client code"),
            ('"role":"admin"', "role:admin JSON literal"),
            ("'role':'admin'", "role:admin JSON literal"),
            ("userlevel", "userLevel privilege variable"),
            ("user_level", "user_level privilege variable"),
            ("permission=", "permission attribute in markup"),
            ("canedit", "canEdit capability flag"),
            ("superuser", "superuser flag"),
        ]
        for pat, label in client_role_patterns:
            if pat in text_lower and label not in hints:
                hints.append(label)

        hidden_priv_fields = []
        if self.soup:
            for inp in self.soup.find_all("input", attrs={"type": "hidden"}):
                name = (inp.get("name") or inp.get("id") or "").lower()
                value = (inp.get("value") or "").lower()
                if any(k in name for k in ("role", "admin", "privilege", "permission", "level")):
                    hidden_priv_fields.append(name or "(unnamed)")
                if value in ("admin", "true", "superuser") and any(
                        k in name for k in ("role", "admin", "priv", "level")):
                    hidden_priv_fields.append(name + "=" + value)

        params = parse_qs(self.parsed.query, keep_blank_values=True) if self.parsed.query else {}
        priv_params = [p for p in params if any(
            k in p.lower() for k in ("role", "admin", "priv", "isadmin", "userlevel", "permission"))]

        hidden_priv_fields = list(dict.fromkeys(hidden_priv_fields))

        if hidden_priv_fields:
            self.add_finding("Hidden Privilege Fields in Forms", "high", False,
                             "Hidden inputs carry role/privilege semantics: " + ", ".join(hidden_priv_fields[:5]),
                             category,
                             remediation="Derive privileges server-side from the authenticated identity; never trust hidden fields.",
                             owasp="A01", nist="AC", pci_dss="PCI-7", hipaa="HIPAA-AC",
                             attack_vector="Network", exploitability=1.5, impact=2.0)

        if priv_params:
            self.add_finding("Privilege Parameter in URL", "medium", False,
                             "Query parameters expose privilege semantics: " + ", ".join(priv_params[:5]),
                             category,
                             remediation="Remove privilege controls from client-visible parameters and enforce RBAC server-side.",
                             owasp="A01", nist="AC", pci_dss="PCI-7",
                             attack_vector="Network", exploitability=1.5, impact=1.5)

        if hints:
            self.add_finding("Client-Side Authorization Hints", "medium", False,
                             "Authorization-related patterns in shipped code: " + "; ".join(hints[:5]),
                             category,
                             remediation="Treat all client-side role checks as cosmetic; enforce authorization on every server request.",
                             owasp="A01", nist="AC", pci_dss="PCI-7",
                             attack_vector="Network", exploitability=1.2, impact=1.5)
        elif not hidden_priv_fields and not priv_params:
            self.add_finding("Privilege Escalation Hints", "info", True,
                             "No hidden privilege fields, privilege URL params, or client-side role flags detected",
                             category, owasp="A01", nist="AC", pci_dss="PCI-7")

    # ──────────────────────────────────────────────────────────────────
    # Risk Assessment & Scoring (v4.0 / v5.0)
    # ──────────────────────────────────────────────────────────────────

    def calculate_risk_assessment(self):
        category = "scoring"
        failed_findings = [f for f in self.findings if not f.passed]

        self.cvss31_metrics = {"average": 0.0, "maximum": 0.0, "top": []}
        self.attack_vector_analysis = {"counts": {}, "dominant": "", "detail": "No failed findings"}
        self.exploitability_metrics = {"average": 0.0, "maximum": 0.0, "top": []}
        self.business_impact_summary = {"score": 0, "level": "Minimal", "domains": {}, "detail": "No failed findings"}
        self._compute_threat_model(failed_findings)
        self._build_recommendations(failed_findings)
        self._compute_weighted_compliance()
        self._compute_compliance_effectiveness()
        self._compute_risk_matrix(failed_findings, category)
        self._compute_defense_layers()
        self.posture = self._compute_posture()
        self.roadmap = self._build_roadmap(failed_findings)

        if not failed_findings:
            self.add_finding("Risk Assessment", "info", True,
                             "No failed findings - minimal risk",
                             category)
            self.add_finding("Threat Model (STRIDE)", "info", True,
                             "Threat level " + self.threat_model.get("level", "Guarded")
                             + " (risk index " + str(self.threat_model.get("risk_index", 0)) + "/100)",
                             category, owasp="A04", nist="RA")
            self._compute_threat_landscape(failed_findings)
            self._compute_dashboard()
            return

        cvss_scores = []
        for f in failed_findings:
            risk = f.calculate_risk_score()
            cvss_scores.append({"name": f.name, "severity": f.severity, "risk": risk})

        cvss_scores.sort(key=lambda x: x["risk"], reverse=True)

        top_risks = cvss_scores[:5]
        if top_risks:
            risk_details = []
            for r in top_risks:
                risk_details.append(r["name"] + " (CVSS: " + str(round(r["risk"], 1)) + ")")
            self.add_finding("Top Risk Items", "info", False,
                             "Highest risk findings: " + "; ".join(risk_details),
                             category)

        total_risk = sum(r["risk"] for r in cvss_scores)
        avg_risk = total_risk / len(cvss_scores) if cvss_scores else 0

        if avg_risk >= 8.0:
            risk_level = "Critical"
        elif avg_risk >= 6.0:
            risk_level = "High"
        elif avg_risk >= 4.0:
            risk_level = "Medium"
        elif avg_risk >= 2.0:
            risk_level = "Low"
        else:
            risk_level = "Informational"

        self.add_finding("Overall Risk Level", "info", False,
                         "Risk level: " + risk_level + " (avg CVSS: " + str(round(avg_risk, 1)) + ")",
                         category)

        owasp_mapping = {}
        pci_mapping = {}
        hipaa_mapping = {}
        for f in failed_findings:
            if f.owasp:
                owasp_mapping[f.owasp] = owasp_mapping.get(f.owasp, 0) + 1
            if f.pci_dss:
                pci_mapping[f.pci_dss] = pci_mapping.get(f.pci_dss, 0) + 1
            if f.hipaa:
                hipaa_mapping[f.hipaa] = hipaa_mapping.get(f.hipaa, 0) + 1

        if owasp_mapping:
            top_owasp = sorted(owasp_mapping.items(), key=lambda x: x[1], reverse=True)[:3]
            owasp_details = [k + " (" + OWASP_TOP10.get(k, k) + "): " + str(v) + " issues" for k, v in top_owasp]
            self.add_finding("OWASP Risk Mapping", "info", False,
                             "Top OWASP categories with issues: " + "; ".join(owasp_details),
                             category)

        if pci_mapping:
            top_pci = sorted(pci_mapping.items(), key=lambda x: x[1], reverse=True)[:3]
            pci_details = [k + ": " + str(v) + " issues" for k, v in top_pci]
            self.add_finding("PCI-DSS Risk Mapping", "info", False,
                             "Top PCI-DSS requirements with issues: " + "; ".join(pci_details),
                             category)

        if hipaa_mapping:
            top_hipaa = sorted(hipaa_mapping.items(), key=lambda x: x[1], reverse=True)[:3]
            hipaa_details = [k + ": " + str(v) + " issues" for k, v in top_hipaa]
            self.add_finding("HIPAA Risk Mapping", "info", False,
                             "Top HIPAA safeguards with issues: " + "; ".join(hipaa_details),
                             category)

        maturity_score = self._compute_maturity()
        maturity = SECURITY_MATURITY_LEVELS[maturity_score]
        self.add_finding("Security Maturity Assessment", "info", False,
                         "Level " + str(maturity_score) + " - " + maturity["level"] + ": " + maturity["description"],
                         category)

        remediation_priorities = []
        critical_findings = [f for f in failed_findings if f.severity == "critical"]
        high_findings = [f for f in failed_findings if f.severity == "high"]
        medium_findings = [f for f in failed_findings if f.severity == "medium"]

        if critical_findings:
            remediation_priorities.append("IMMEDIATE: " + str(len(critical_findings)) + " critical issue(s)")
        if high_findings:
            remediation_priorities.append("URGENT: " + str(len(high_findings)) + " high issue(s)")
        if medium_findings:
            remediation_priorities.append("PLANNED: " + str(len(medium_findings)) + " medium issue(s)")

        if remediation_priorities:
            self.add_finding("Remediation Priority", "info", False,
                             "Priority: " + " | ".join(remediation_priorities),
                             category)

        self._score_cvss31(failed_findings, category)
        self._score_attack_vectors(failed_findings, category)
        self._score_exploitability(failed_findings, category)
        self._score_business_impact(failed_findings, category)
        self._compute_threat_model(failed_findings)
        self._compute_threat_landscape(failed_findings)
        self._build_recommendations(failed_findings)
        self._compute_weighted_compliance()
        self._compute_compliance_effectiveness()
        self._compute_risk_matrix(failed_findings, category)
        self._compute_defense_layers()

        threat = self.threat_model
        self.add_finding("Threat Model (STRIDE)", "info", False,
                         "Threat level " + threat.get("level", "Guarded")
                         + " (risk index " + str(threat.get("risk_index", 0)) + "/100). Dominant threat: "
                         + threat.get("dominant_label", "None") + ".",
                         category, owasp="A04", nist="RA", pci_dss="PCI-11")

        cw = self.compliance_weighted
        self.add_finding("Weighted Compliance Scoring", "info", False,
                         "Severity-weighted compliance - OWASP " + str(cw.get("owasp", 0))
                         + "%, NIST " + str(cw.get("nist", 0))
                         + "%, PCI-DSS " + str(cw.get("pci_dss", 0))
                         + "%, HIPAA " + str(cw.get("hipaa", 0)) + "%",
                         category, owasp="A04", nist="CA")

        ce = self.compliance_effectiveness or {}
        if ce:
            ce_bits = []
            for label in ("owasp", "nist", "pci_dss", "hipaa"):
                meta = ce.get(label)
                if meta:
                    ce_bits.append(label.upper() + " " + str(meta.get("score", 0))
                                   + "% (gap weight " + str(meta.get("critical_gap_weight", 0)) + ")")
            self.add_finding("Compliance Control Effectiveness", "info", False,
                             "Control effectiveness after critical-fail penalties: " + "; ".join(ce_bits),
                             category, owasp="A04", nist="CA")

        self._compute_dashboard()
        self.posture = self._compute_posture()
        self.roadmap = self._build_roadmap(failed_findings)

    def _score_cvss31(self, failed_findings, category):
        entries = []
        for f in failed_findings:
            info = f.cvss31
            entries.append({
                "name": f.name, "severity": f.severity,
                "score": info["score"], "vector": info["vector"],
            })
        entries.sort(key=lambda x: x["score"], reverse=True)
        scores = [e["score"] for e in entries]
        avg = sum(scores) / len(scores) if scores else 0.0
        top = entries[:3]
        self.cvss31_metrics = {
            "average": round(avg, 1),
            "maximum": round(max(scores), 1) if scores else 0.0,
            "top": top,
        }
        top_desc = "; ".join(
            e["name"] + " (" + str(e["score"]) + ") [" + e["vector"] + "]"
            for e in top
        )
        self.add_finding("CVSS v3.1 Approximation", "info", False,
                         "Avg base score " + str(round(avg, 1)) + "/10.0, max "
                         + str(self.cvss31_metrics["maximum"]) + "/10.0. Top: " + top_desc,
                         category)

    def _score_attack_vectors(self, failed_findings, category):
        counts = {}
        for f in failed_findings:
            if f.severity == "info":
                continue
            av = (f.attack_vector or "Network")
            counts[av] = counts.get(av, 0) + 1
        if not counts:
            return
        dominant = max(counts.items(), key=lambda x: x[1])
        detail = ", ".join(k + "=" + str(v) for k, v in sorted(counts.items()))
        self.attack_vector_analysis = {
            "counts": counts, "dominant": dominant[0], "detail": detail,
        }
        recommendations = {
            "Network": "Expose the service only behind authentication, WAF rules and strict input validation.",
            "Adjacent": "Segment the network and restrict LAN-facing services with host firewalls.",
            "Local": "Harden endpoint permissions and audit local privilege boundaries.",
            "Physical": "Enforce physical access controls and tamper protection.",
        }
        rec = recommendations.get(dominant[0], "Limit the dominant attack path through layered controls.")
        self.add_finding("Attack Vector Analysis", "info", False,
                         "Vector distribution: " + detail + ". Dominant: " + dominant[0] + ". " + rec,
                         category)

    def _score_exploitability(self, failed_findings, category):
        entries = []
        for f in failed_findings:
            if f.severity == "info":
                continue
            entries.append({
                "name": f.name,
                "score": f.cvss31["exploitability_score"],
            })
        if not entries:
            return
        entries.sort(key=lambda x: x["score"], reverse=True)
        scores = [e["score"] for e in entries]
        avg = sum(scores) / len(scores)
        top = entries[:3]
        self.exploitability_metrics = {
            "average": round(avg, 1),
            "maximum": round(max(scores), 1),
            "top": top,
        }
        top_desc = "; ".join(e["name"] + " (" + str(e["score"]) + ")" for e in top)
        if avg >= 7.0:
            band = "highly exploitable — treat as emergency"
        elif avg >= 5.0:
            band = "moderately exploitable — prioritize this sprint"
        elif avg >= 3.0:
            band = "limited exploitability — schedule remediation"
        else:
            band = "low exploitability — monitor and harden"
        self.add_finding("Exploitability Scoring", "info", False,
                         "Avg exploitability " + str(round(avg, 1)) + "/10.0 (" + band + "). Top: " + top_desc,
                         category)

    def _score_business_impact(self, failed_findings, category):
        domain_scores = {}
        weights = {"critical": 25.0, "high": 15.0, "medium": 8.0, "low": 3.0, "info": 0.0}
        for f in failed_findings:
            if f.severity == "info":
                continue
            domain = f.business_impact
            domain_scores[domain] = domain_scores.get(domain, 0.0) + weights.get(f.severity, 0.0)
        if not domain_scores:
            return
        total = sum(domain_scores.values())
        score = min(100, int(round(total * 2)))
        if score >= 80:
            level = "Severe"
        elif score >= 60:
            level = "High"
        elif score >= 40:
            level = "Moderate"
        elif score >= 20:
            level = "Low"
        else:
            level = "Minimal"
        ranked = sorted(domain_scores.items(), key=lambda x: x[1], reverse=True)[:3]
        detail = "; ".join(k + " (impact index " + str(int(v)) + ")" for k, v in ranked)
        self.business_impact_summary = {
            "score": score, "level": level,
            "domains": {k: int(v) for k, v in domain_scores.items()},
            "detail": detail,
        }
        self.add_finding("Business Impact Assessment", "info", False,
                         "Business impact level: " + level + " (index " + str(score) + "/100). "
                         + "Primary exposure: " + detail,
                         category)

    def _compute_posture(self):
        total_points = sum(f.points for f in self.findings)
        max_points = sum(f.max_points for f in self.findings)
        check_score = (total_points / max_points * 100) if max_points > 0 else 0.0
        failed = [f for f in self.findings if not f.passed]
        crit = sum(1 for f in failed if f.severity == "critical")
        high = sum(1 for f in failed if f.severity == "high")
        medium = sum(1 for f in failed if f.severity == "medium")
        low = sum(1 for f in failed if f.severity == "low")
        max_cvss = max((f.cvss31["score"] for f in failed), default=0.0)
        covered = len({f.category for f in self.findings})
        coverage_score = (covered / len(CATEGORY_ORDER) * 100.0) if CATEGORY_ORDER else 100.0
        risk_index = min(100.0, crit * 10 + high * 4 + medium * 1.5 + low * 0.5 + max_cvss * 1.5)
        threat_penalty = min(15.0, float((self.threat_model or {}).get("risk_index", 0)) * 0.15)
        risk_index = min(100.0, risk_index + threat_penalty)
        defense_penalty = 0.0
        for meta in (self.defense_layers or {}).values():
            sc = meta.get("score")
            if sc is not None and sc < 40:
                defense_penalty += 3.0
        risk_index = min(100.0, risk_index + min(12.0, defense_penalty))
        posture = int(round(0.50 * check_score + 0.40 * (100.0 - risk_index) + 0.10 * coverage_score))
        posture = max(0, min(100, posture))
        if posture >= 90:
            grade = "A"
        elif posture >= 80:
            grade = "B"
        elif posture >= 70:
            grade = "C"
        elif posture >= 55:
            grade = "D"
        else:
            grade = "F"
        return {
            "score": posture, "grade": grade,
            "check_score": round(check_score, 1),
            "risk_index": round(risk_index, 1),
            "coverage_score": round(coverage_score, 1),
            "criticals": crit, "highs": high, "mediums": medium, "lows": low,
            "defense_penalty": round(min(12.0, defense_penalty), 1),
        }

    def _build_roadmap(self, failed_findings):
        phases = [
            ("Phase 1 - Immediate (0-7 days)", "critical",
             "Stop active exploitation paths: injection, exposed secrets, cache/session leaks."),
            ("Phase 2 - Short term (7-30 days)", "high",
             "Close high-severity holes: headers, CSRF, SRI, SSRF and auth gaps."),
            ("Phase 3 - Medium term (30-90 days)", "medium",
             "Reduce attack surface: configuration, privacy, dependency upgrades."),
            ("Phase 4 - Hardening (90+ days)", "low",
             "Defense in depth: monitoring, least privilege, policy and process."),
        ]
        roadmap = []
        for title, severity, goal in phases:
            items = []
            for f in failed_findings:
                if f.severity != severity:
                    continue
                items.append({
                    "name": f.name,
                    "remediation": f.remediation or "Review and remediate this finding.",
                    "category": f.category,
                    "cvss31": f.cvss31["score"],
                    "effort": EFFORT_BY_CATEGORY.get(f.category, "M"),
                })
                if len(items) >= 6:
                    break
            roadmap.append({"phase": title, "severity": severity, "goal": goal, "items": items})
        return roadmap

    def _compute_risk_matrix(self, failed_findings, category):
        keys = [(l, i) for l in ("low", "medium", "high") for i in ("low", "medium", "high")]
        matrix = {k: 0 for k in keys}
        labeled = []
        for f in failed_findings:
            if f.severity == "info":
                continue
            expl = f.cvss31.get("exploitability_score", 0.0)
            imp = f.cvss31.get("impact_score", 0.0)
            likelihood = "high" if expl >= 7.0 else ("medium" if expl >= 4.0 else "low")
            impact_lvl = "high" if imp >= 7.0 else ("medium" if imp >= 4.0 else "low")
            matrix[(likelihood, impact_lvl)] = matrix.get((likelihood, impact_lvl), 0) + 1
            labeled.append({
                "name": f.name, "likelihood": likelihood, "impact": impact_lvl,
                "score": f.cvss31.get("score", 0.0),
            })
        weighted = (
            matrix[("high", "high")] * 9
            + matrix[("high", "medium")] * 6
            + matrix[("medium", "high")] * 6
            + matrix[("medium", "medium")] * 4
            + matrix[("high", "low")] * 3
            + matrix[("low", "high")] * 3
            + matrix[("medium", "low")] * 2
            + matrix[("low", "medium")] * 2
            + matrix[("low", "low")] * 1
        )
        if weighted >= 40:
            residual = "Critical"
        elif weighted >= 25:
            residual = "High"
        elif weighted >= 12:
            residual = "Moderate"
        elif weighted >= 4:
            residual = "Low"
        else:
            residual = "Minimal"
        self.risk_matrix = {
            "cells": {l + ":" + i: matrix[(l, i)] for (l, i) in keys},
            "weighted_index": weighted,
            "residual_risk": residual,
            "top_pairs": sorted(labeled, key=lambda x: x["score"], reverse=True)[:5],
        }
        if labeled:
            self.add_finding("Risk Matrix (Likelihood x Impact)", "info", False,
                             "Residual risk " + residual + " (weighted index " + str(weighted)
                             + "). High-likelihood/high-impact cells: "
                             + str(matrix[("high", "high")]),
                             category, owasp="A04", nist="RA")

    def _compute_defense_layers(self):
        layer_map = {
            "Perimeter & Edge": ["waf", "bot_protection", "rate_limiting", "cache", "dns"],
            "Identity & Access": ["account_lockout", "mfa", "password_policy",
                                  "auth_security", "cookies"],
            "Application Security": ["vuln", "advanced_vuln", "headers", "content",
                                     "sri", "browser_policy"],
            "Transport & Data": ["ssl", "cors", "disclosure", "privacy"],
            "Software Supply Chain": ["supply_chain", "wasm", "api", "container"],
            "Governance & Assurance": ["compliance", "scoring"],
        }
        layers = {}
        for layer_name, cats in layer_map.items():
            related = [f for f in self.findings if f.category in cats]
            if not related:
                layers[layer_name] = {"score": None, "passed": 0, "total": 0,
                                      "label": "not assessed"}
                continue
            passed = sum(1 for f in related if f.passed)
            total = len(related)
            failed_crit = sum(1 for f in related if not f.passed
                              and f.severity in ("critical", "high"))
            score = int(round(passed / total * 100)) if total else 0
            if failed_crit:
                score = max(0, score - min(20, failed_crit * 5))
            if score >= 85:
                label = "strong"
            elif score >= 65:
                label = "adequate"
            elif score >= 40:
                label = "weak"
            else:
                label = "critical gap"
            layers[layer_name] = {"score": score, "passed": passed, "total": total,
                                  "label": label}
        self.defense_layers = layers
        return layers

    def _compute_compliance_effectiveness(self):
        sev_w = {"critical": 5, "high": 3, "medium": 2, "low": 1, "info": 1}
        effectiveness = {}
        for attr, label in (("owasp", "owasp"), ("nist", "nist"),
                            ("pci_dss", "pci_dss"), ("hipaa", "hipaa")):
            total_w = 0
            pass_w = 0
            critical_fail_w = 0
            for f in self.findings:
                key = getattr(f, attr, None)
                if not key:
                    continue
                weight = sev_w.get(f.severity, 1)
                total_w += weight
                if f.passed:
                    pass_w += weight
                else:
                    if f.severity in ("critical", "high"):
                        critical_fail_w += weight
            if total_w <= 0:
                effectiveness[label] = {"score": 0, "critical_gap_weight": 0,
                                        "base_ratio": 0.0, "assessed": False}
                continue
            base = pass_w / total_w
            penalty = min(0.25, (critical_fail_w / total_w) * 0.5)
            eff = max(0.0, base - penalty)
            effectiveness[label] = {
                "score": int(round(eff * 100)),
                "critical_gap_weight": critical_fail_w,
                "base_ratio": round(base, 3),
                "assessed": True,
            }
        self.compliance_effectiveness = effectiveness
        return effectiveness

    # ──────────────────────────────────────────────────────────────────
    # Display & Export
    # ──────────────────────────────────────────────────────────────────

    def display_results(self):
        print(f"\n{'=' * 70}")
        print(f"{Fore.CYAN}  SECURITY SCAN RESULTS  v{VERSION}{Style.RESET_ALL}")
        print(f"{'=' * 70}")
        print(f"  Target:   {self.url}")
        print(f"  Status:   {self.response.status_code if self.response else 'N/A'}")
        print(f"  Scan at:  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if self.cloud_provider:
            print(f"  Cloud:    {self.cloud_provider.upper()}")
        if self.container_hints:
            print(f"  Container:{', '.join(self.container_hints)}")
        print(f"{'=' * 70}\n")

        categories = {}
        for f in self.findings:
            if f.category not in categories:
                categories[f.category] = []
            categories[f.category].append(f)

        cat_order = CATEGORY_ORDER

        for cat in cat_order:
            if cat not in categories:
                continue
            checks = categories[cat]
            c = Fore.CYAN if not self.no_color else ""
            print(f"{c}{'─' * 70}")
            print(f"  {self.category_names.get(cat, cat.upper())}")
            print(f"{c}{'─' * 70}{self.reset()}")

            for check in checks:
                color = self.color(check.severity)
                tag = "[" + check.severity.upper() + "]"
                status = "PASS" if check.passed else "FAIL"
                print(f"  {color}{tag:12s}{self.reset()} {check.name:45s} {status}")
                if check.details:
                    print(f"  {'':12s}   {Fore.LIGHTBLACK_EX}{check.details}{self.reset()}")
                if check.cve:
                    print(f"  {'':12s}   {Fore.MAGENTA}CVE: {check.cve}{self.reset()}")
                if check.remediation and not check.passed:
                    print(f"  {'':12s}   {Fore.GREEN}Fix: {check.remediation}{self.reset()}")

            print()

        self.display_attack_surface(categories)
        self.display_risk_heatmap(categories)
        self.display_posture_dashboard(categories)
        self.display_threat_landscape()
        self.display_summary(categories)
        self.display_remediation_roadmap_detail()
        self.display_security_recommendations()

    def display_attack_surface(self, categories):
        print(f"{'=' * 70}")
        print(f"{Fore.CYAN}  ATTACK SURFACE VISUALIZATION{Style.RESET_ALL}")
        print(f"{'=' * 70}")
        print(f"  Target:    {self.url}")
        assets = self.assets
        print(f"  Assets:    {assets['scripts']} scripts ({assets['external_scripts']} external, "
              f"{assets['inline_scripts']} inline), {assets['stylesheets']} stylesheets, "
              f"{assets['forms']} forms, {assets['frames']} frames")
        if assets["wasm_modules"]:
            print(f"  WASM:      {', '.join(assets['wasm_modules'][:3])}")
        if assets["cdn_hosts"]:
            print(f"  CDNs:      {', '.join(assets['cdn_hosts'][:5])}")
        elif assets["external_hosts"]:
            print(f"  3rd party: {', '.join(assets['external_hosts'][:5])}")
        if self.api_endpoints_found:
            print(f"  API paths: {', '.join(self.api_endpoints_found[:5])}")

        print(f"\n  Exposure by category (failed checks):")
        worst_colors = {
            "critical": Fore.RED + Style.BRIGHT,
            "high": Fore.LIGHTRED_EX,
            "medium": Fore.YELLOW,
            "low": Fore.CYAN,
            "info": Fore.WHITE,
        }
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_fail = 1
        fail_counts = {}
        for cat in CATEGORY_ORDER:
            if cat not in categories:
                continue
            failed = [f for f in categories[cat] if not f.passed and f.severity != "info"]
            fail_counts[cat] = failed
            if len(failed) > max_fail:
                max_fail = len(failed)

        any_rows = False
        for cat in CATEGORY_ORDER:
            failed = fail_counts.get(cat)
            if failed is None:
                continue
            any_rows = True
            worst = max((f.severity for f in failed),
                        key=lambda s: severity_rank.get(s, 0), default="info")
            bar_len = 24
            filled = int(round(len(failed) / max_fail * bar_len))
            bar = "█" * filled + "·" * (bar_len - filled)
            label = CATEGORY_SHORT_NAMES.get(cat, cat)
            col = worst_colors.get(worst, "")
            print(f"    {label:14s} {col}{bar} {len(failed):3d} open{self.reset()}")

        if not any_rows:
            print(f"    {Fore.GREEN}No open findings across categories{self.reset()}")
        print()

    def display_risk_heatmap(self, categories):
        print(f"{'=' * 70}")
        print(f"{Fore.CYAN}  RISK HEAT MAP{Style.RESET_ALL}")
        print(f"{'=' * 70}")
        header = f"  {'Category':14s} {'CRIT':>6s} {'HIGH':>6s} {'MED':>6s} {'LOW':>6s} {'TOTAL':>7s}"
        print(header)
        sev_colors = {
            "critical": Fore.RED + Style.BRIGHT,
            "high": Fore.LIGHTRED_EX,
            "medium": Fore.YELLOW,
            "low": Fore.CYAN,
        }
        any_rows = False
        for cat in CATEGORY_ORDER:
            if cat not in categories:
                continue
            failed = [f for f in categories[cat] if not f.passed and f.severity != "info"]
            if not failed:
                continue
            any_rows = True
            counts = {s: sum(1 for f in failed if f.severity == s)
                      for s in ("critical", "high", "medium", "low")}
            cells = []
            for s in ("critical", "high", "medium", "low"):
                n = counts[s]
                if n == 0:
                    cells.append(f"{'·':>6s}")
                else:
                    intensity = "▓" if n == 1 else ("▒" if n <= 3 else "█")
                    cells.append(f"{intensity}{n:>5d}")
            label = CATEGORY_SHORT_NAMES.get(cat, cat)
            hottest = max(counts, key=lambda s: counts[s]) if any(counts.values()) else "low"
            col = sev_colors.get(hottest, "")
            total = sum(counts.values())
            print(f"  {label:14s} {col}{''.join(cells)} {total:>5d}{self.reset()}")
        if not any_rows:
            print(f"  {Fore.GREEN}No risk cells — surface is clear{self.reset()}")
        print()

    def display_posture_dashboard(self, categories):
        print(f"{'=' * 70}")
        print(f"{Fore.CYAN}  SECURITY POSTURE DASHBOARD{Style.RESET_ALL}")
        print(f"{'=' * 70}")
        score, grade = self._compute_score_and_grade()
        maturity = self._compute_maturity()
        maturity_meta = SECURITY_MATURITY_LEVELS[maturity]
        posture = self.posture or {}
        tm = self.threat_model or {}
        tl = self.threat_landscape or {}
        failed = [f for f in self.findings if not f.passed]
        crit = sum(1 for f in failed if f.severity == "critical")
        high = sum(1 for f in failed if f.severity == "high")
        medium = sum(1 for f in failed if f.severity == "medium")
        low = sum(1 for f in failed if f.severity == "low")
        passed = sum(1 for f in self.findings if f.passed)
        total = len(self.findings)
        pass_pct = int(passed / total * 100) if total else 0

        if score >= 90:
            score_color = Fore.GREEN + Style.BRIGHT
        elif score >= 80:
            score_color = Fore.GREEN
        elif score >= 70:
            score_color = Fore.LIGHTGREEN_EX
        elif score >= 60:
            score_color = Fore.YELLOW
        else:
            score_color = Fore.LIGHTRED_EX

        threat_level = tm.get("level", "n/a")
        if threat_level in ("Severe", "High"):
            threat_color = Fore.RED + Style.BRIGHT
        elif threat_level in ("Moderate", "Elevated"):
            threat_color = Fore.YELLOW
        else:
            threat_color = Fore.GREEN

        def mini_bar(pct, width=20):
            filled = int(round(max(0, min(100, pct)) / 100.0 * width))
            return "#" * filled + "-" * (width - filled)

        print(f"  Overall Score:   {score_color}{score}/100  Grade {grade}{self.reset()}")
        print(f"  Posture Index:   {posture.get('score', 0)}/100  Grade {posture.get('grade', '-')}"
              f"  (checks {posture.get('check_score', 0)}, risk {posture.get('risk_index', 0)},"
              f" coverage {posture.get('coverage_score', 0)},"
              f" defense penalty {posture.get('defense_penalty', 0)})")
        print(f"  Maturity:        Level {maturity} - {maturity_meta['level']}")
        if maturity_meta.get("focus"):
            print(f"  Maturity Focus:  {maturity_meta['focus']}")
        print(f"  Threat Level:    {threat_color}{threat_level}{self.reset()}"
              f"  (index {tm.get('risk_index', 0)}/100, dominant: {tm.get('dominant_label', 'n/a')})")
        if tl:
            active_phases = sum(1 for p in tl.get("kill_chain", []) if p.get("active"))
            residual = (self.risk_matrix or {}).get("residual_risk", "n/a")
            print(f"  Exposure:        {tl.get('exposure_score', 0)}/100"
                  f"  (kill-chain phases active: {active_phases}, residual risk: {residual})")
        print(f"  Checks Passed:   {Fore.GREEN}{passed}/{total}{self.reset()} ({pass_pct}%)")
        open_col = Fore.RED + Style.BRIGHT if crit else Fore.LIGHTRED_EX
        print(f"  Open Findings:   {open_col}C:{crit} H:{high}{self.reset()}"
              f"  {Fore.YELLOW}M:{medium}{self.reset()}  {Fore.CYAN}L:{low}{self.reset()}")

        cw = self.compliance_weighted or {}
        if cw:
            print(f"  Weighted Comp.:  OWASP {cw.get('owasp', 0)}% | NIST {cw.get('nist', 0)}%"
                  f" | PCI {cw.get('pci_dss', 0)}% | HIPAA {cw.get('hipaa', 0)}%")
        ce = self.compliance_effectiveness or {}
        if ce:
            print(f"  Control Eff.:    OWASP {ce.get('owasp', {}).get('score', 0)}%"
                  f" | NIST {ce.get('nist', {}).get('score', 0)}%"
                  f" | PCI {ce.get('pci_dss', {}).get('score', 0)}%"
                  f" | HIPAA {ce.get('hipaa', {}).get('score', 0)}%")

        layers = self.defense_layers or {}
        if layers:
            print(f"\n  Defense-in-Depth Layers:")
            for lname, meta in layers.items():
                sc = meta.get("score")
                if sc is None:
                    print(f"    {lname:26s} {Fore.WHITE}not assessed{self.reset()}")
                    continue
                if sc >= 85:
                    lc = Fore.GREEN
                elif sc >= 65:
                    lc = Fore.LIGHTGREEN_EX
                elif sc >= 40:
                    lc = Fore.YELLOW
                else:
                    lc = Fore.RED + Style.BRIGHT
                print(f"    {lname:26s} {lc}{sc:3d}% {meta.get('label', '')}{self.reset()}"
                      f" ({meta.get('passed', 0)}/{meta.get('total', 0)})")

        print(f"\n  Control Coverage:")
        any_rows = False
        for cat in CATEGORY_ORDER:
            if cat not in categories:
                continue
            any_rows = True
            checks = categories[cat]
            cat_passed = sum(1 for c in checks if c.passed)
            cat_total = len(checks)
            pct = int(cat_passed / cat_total * 100) if cat_total else 0
            label = CATEGORY_SHORT_NAMES.get(cat, cat)
            if pct >= 80:
                pcolor = Fore.GREEN
            elif pct >= 60:
                pcolor = Fore.LIGHTGREEN_EX
            elif pct >= 40:
                pcolor = Fore.YELLOW
            else:
                pcolor = Fore.LIGHTRED_EX
            print(f"    {label:14s} {pcolor}[{mini_bar(pct)}]{self.reset()} {pct:3d}% ({cat_passed}/{cat_total})")
        if not any_rows:
            print(f"    {Fore.YELLOW}No categories recorded{self.reset()}")
        print()

    def display_threat_landscape(self):
        print(f"{'=' * 70}")
        print(f"{Fore.CYAN}  THREAT LANDSCAPE ANALYSIS{Style.RESET_ALL}")
        print(f"{'=' * 70}")
        tm = self.threat_model or {}
        tl = self.threat_landscape or {}
        if not tm:
            print(f"  {Fore.YELLOW}Threat model unavailable (scoring pass did not run){self.reset()}\n")
            return

        print(f"  Overall Threat Level: {tm.get('level', 'n/a')}  (risk index {tm.get('risk_index', 0)}/100)")
        print(f"  Dominant STRIDE Threat: {tm.get('dominant_label', 'None')}")
        if tl:
            exposure = tl.get("exposure_score", 0)
            if exposure >= 60:
                exp_color = Fore.RED + Style.BRIGHT
            elif exposure >= 30:
                exp_color = Fore.YELLOW
            else:
                exp_color = Fore.GREEN
            print(f"  Exposure Score: {exp_color}{exposure}/100{self.reset()}"
                  f"  (residual risk: {(self.risk_matrix or {}).get('residual_risk', 'n/a')})")

        stride = tm.get("stride", {})
        max_risk = max([e.get("risk", 0) for e in stride.values()] or [1]) or 1
        print(f"\n  STRIDE Breakdown:")
        for key, meta in stride.items():
            filled = int(round(meta.get("risk", 0) / max_risk * 20))
            bar = "█" * filled + "·" * (20 - filled)
            print(f"    {meta['label']:24s} {bar} risk={meta.get('risk', 0):5.1f}  n={meta.get('count', 0)}")
            if meta.get("findings"):
                print(f"      {Fore.LIGHTBLACK_EX}e.g. " + "; ".join(meta["findings"][:3]) + self.reset())

        if tl.get("kill_chain"):
            print(f"\n  Attack Progression (Kill Chain):")
            for phase in tl["kill_chain"]:
                active = bool(phase.get("active"))
                if active:
                    state_color = Fore.RED + Style.BRIGHT
                    state = "ACTIVE"
                else:
                    state_color = Fore.GREEN
                    state = "clear"
                cats = ", ".join(phase.get("categories", [])) or "-"
                print(f"    {phase.get('phase', ''):26s} {state_color}{state}{self.reset()}  {cats}")

        if tl.get("techniques"):
            print(f"\n  Mapped Threat Techniques:")
            for tech in tl["techniques"][:6]:
                print(f"    - {tech}")

        if tl:
            print(f"\n  Plausible Threat Actors:")
            for actor in tl.get("plausible_actors", []):
                print(f"    - {actor}")
            if tl.get("entry_points"):
                print(f"  Entry Points: " + ", ".join(tl["entry_points"]))
            if tl.get("third_party_hosts"):
                print(f"  Third-Party Trust: " + ", ".join(tl["third_party_hosts"]))
            if tl.get("attack_vectors"):
                av_detail = ", ".join(k + "=" + str(v) for k, v in sorted(tl["attack_vectors"].items()))
                print(f"  Attack Vectors: {av_detail}")
            if tl.get("top_open_findings"):
                print(f"  Priority Exposure:")
                for name in tl["top_open_findings"]:
                    print(f"    * {name}")
            biz_exposure = tl.get("primary_business_exposure", "")
            if biz_exposure and biz_exposure != "n/a":
                print(f"  Business Exposure: {biz_exposure}")
        print()

    def display_remediation_roadmap_detail(self):
        if not self.roadmap:
            return
        print(f"{'=' * 70}")
        print(f"{Fore.CYAN}  REMEDIATION ROADMAP{Style.RESET_ALL}")
        print(f"{'=' * 70}")
        sev_colors_map = {
            "critical": Fore.RED + Style.BRIGHT,
            "high": Fore.LIGHTRED_EX,
            "medium": Fore.YELLOW,
            "low": Fore.CYAN,
        }
        effort_points = {"S": 1, "M": 3, "L": 8}
        any_items = False
        for phase in self.roadmap:
            items = phase.get("items", [])
            col = sev_colors_map.get(phase.get("severity", "low"), "")
            status = str(len(items)) + " item(s)" if items else "clear"
            phase_effort = sum(effort_points.get(i.get("effort", "M"), 3) for i in items)
            effort_label = ("~" + str(phase_effort) + " effort pts") if items else "clear"
            print(f"  {col}{phase.get('phase', '')}{self.reset()} — {status} ({effort_label})")
            print(f"    {Fore.LIGHTBLACK_EX}{phase.get('goal', '')}{self.reset()}")
            for item in items:
                any_items = True
                cat_label = self.category_names.get(item.get("category", ""), item.get("category", ""))
                effort = item.get("effort", "M")
                print(f"      * [{item.get('cvss31', 0)}] {item['name']}  (effort {effort})")
                print(f"        {Fore.GREEN}{item['remediation']}{self.reset()}  ({cat_label})")
        if not any_items:
            print(f"  {Fore.GREEN}All roadmap phases clear{self.reset()}")
        print()

    def display_security_recommendations(self):
        recs = self.recommendations or []
        print(f"{'=' * 70}")
        print(f"{Fore.CYAN}  SECURITY RECOMMENDATIONS{Style.RESET_ALL}")
        print(f"{'=' * 70}")
        if not recs:
            print(f"  {Fore.GREEN}No prioritized recommendations — maintain continuous monitoring.{self.reset()}\n")
            return
        pri_colors = {"P1": Fore.RED + Style.BRIGHT, "P2": Fore.LIGHTRED_EX,
                      "P3": Fore.YELLOW, "P4": Fore.CYAN}
        quick_wins = [r for r in recs if r.get("track") == "quick-win"]
        strategic = [r for r in recs if r.get("track") == "strategic"]
        if quick_wins:
            print(f"  {Fore.GREEN}Quick wins available: {len(quick_wins)} "
                  f"(low effort, high severity relief){self.reset()}")
        if strategic:
            print(f"  {Fore.YELLOW}Strategic items: {len(strategic)} "
                  f"(higher effort - schedule into roadmap){self.reset()}")
        print()
        for i, rec in enumerate(recs, 1):
            col = pri_colors.get(rec.get("priority", "P4"), "")
            effort = rec.get("effort", "M")
            track = rec.get("track", "standard")
            print(f"  {i:2d}. {col}{rec.get('priority', 'P4')}{self.reset()} {rec.get('title', '')}"
                  f"  {Fore.LIGHTBLACK_EX}(CVSS {rec.get('cvss', 0)}, effort {effort}, {track}){self.reset()}")
            print(f"      {Fore.GREEN}{rec.get('action', '')}{self.reset()}")
            if rec.get("category"):
                area = rec.get("owasp") or rec.get("category")
                print(f"      {Fore.LIGHTBLACK_EX}Area: {area}{self.reset()}")
        print()

    def display_summary(self, categories):
        total_points = sum(f.points for f in self.findings)
        max_points = sum(f.max_points for f in self.findings)
        score = int((total_points / max_points * 100)) if max_points > 0 else 0

        critical = sum(1 for f in self.findings if f.severity == "critical" and not f.passed)
        high = sum(1 for f in self.findings if f.severity == "high" and not f.passed)
        medium = sum(1 for f in self.findings if f.severity == "medium" and not f.passed)
        low = sum(1 for f in self.findings if f.severity == "low" and not f.passed)
        info = sum(1 for f in self.findings if f.severity == "info")
        passed = sum(1 for f in self.findings if f.passed)
        total = len(self.findings)

        if score >= 95:
            grade = "A+"
            grade_color = Fore.GREEN + Style.BRIGHT
        elif score >= 90:
            grade = "A"
            grade_color = Fore.GREEN
        elif score >= 80:
            grade = "B+"
            grade_color = Fore.LIGHTGREEN_EX
        elif score >= 70:
            grade = "B"
            grade_color = Fore.LIGHTGREEN_EX
        elif score >= 60:
            grade = "C"
            grade_color = Fore.YELLOW
        elif score >= 50:
            grade = "D"
            grade_color = Fore.LIGHTRED_EX
        elif score >= 40:
            grade = "D-"
            grade_color = Fore.LIGHTRED_EX
        else:
            grade = "F"
            grade_color = Fore.RED + Style.BRIGHT

        cat_order = CATEGORY_ORDER

        print(f"{'=' * 70}")
        print(f"{Fore.CYAN}  SECURITY SCORE SUMMARY{Style.RESET_ALL}")
        print(f"{'=' * 70}")
        print(f"  Score:      {grade_color}{score}/100  Grade: {grade}{self.reset()}")
        if self.posture:
            posture_color = Fore.GREEN if self.posture.get("score", 0) >= 80 else (
                Fore.YELLOW if self.posture.get("score", 0) >= 60 else Fore.LIGHTRED_EX)
            print(f"  Posture:    {posture_color}{self.posture.get('score', 0)}/100 "
                  f"Grade {self.posture.get('grade', 'F')}{self.reset()} "
                  f"(check score {self.posture.get('check_score', 0)}, risk index {self.posture.get('risk_index', 0)})")
        print(f"  Passed:     {Fore.GREEN}{passed}/{total} checks{self.reset()}")
        print(f"  Findings:")
        if critical > 0:
            print(f"    {Fore.RED + Style.BRIGHT}Critical: {critical}{self.reset()}")
        if high > 0:
            print(f"    {Fore.LIGHTRED_EX}High:     {high}{self.reset()}")
        if medium > 0:
            print(f"    {Fore.YELLOW}Medium:   {medium}{self.reset()}")
        if low > 0:
            print(f"    {Fore.CYAN}Low:      {low}{self.reset()}")
        if info > 0:
            print(f"    {Fore.WHITE}Info:     {info}{self.reset()}")
        if critical == 0 and high == 0 and medium == 0 and low == 0:
            print(f"    {Fore.GREEN}No issues found{self.reset()}")

        print(f"\n  Category Breakdown:")
        cat_names_short = CATEGORY_SHORT_NAMES
        for cat in cat_order:
            if cat not in categories:
                continue
            checks = categories[cat]
            cat_passed = sum(1 for c in checks if c.passed)
            cat_total = len(checks)
            pct = int(cat_passed / cat_total * 100) if cat_total > 0 else 0
            bar_len = 20
            filled = int(bar_len * cat_passed / cat_total) if cat_total > 0 else 0
            bar = "#" * filled + "-" * (bar_len - filled)
            if pct >= 80:
                bcolor = Fore.GREEN
            elif pct >= 60:
                bcolor = Fore.LIGHTGREEN_EX
            elif pct >= 40:
                bcolor = Fore.YELLOW
            elif pct >= 20:
                bcolor = Fore.LIGHTRED_EX
            else:
                bcolor = Fore.RED
            print(f"    {cat_names_short.get(cat, cat):12s} {bcolor}{bar} {pct:3d}%{self.reset()} ({cat_passed}/{cat_total})")

        print(f"\n  Risk Assessment Matrix:")
        risk_items = [
            ("Critical", critical, 25, Fore.RED + Style.BRIGHT),
            ("High", high, 15, Fore.LIGHTRED_EX),
            ("Medium", medium, 10, Fore.YELLOW),
            ("Low", low, 5, Fore.CYAN),
        ]
        for label, count, weight, col in risk_items:
            pts = count * weight
            print(f"    {col}{label:10s}{self.reset()}  x{weight:2d} pts each  =  {pts:4d} pts impact")

        failed_findings = [f for f in self.findings if not f.passed]
        if failed_findings:
            cvss_scores = [f.calculate_risk_score() for f in failed_findings]
            avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
            max_cvss = max(cvss_scores) if cvss_scores else 0
            print(f"\n  CVSS Risk Metrics:")
            print(f"    Average CVSS Score:  {Fore.YELLOW}{round(avg_cvss, 1)}/10.0{self.reset()}")
            print(f"    Maximum CVSS Score:  {Fore.RED}{round(max_cvss, 1)}/10.0{self.reset()}")

        if self.cvss31_metrics and self.cvss31_metrics.get("top"):
            print(f"\n  CVSS v3.1 Approximation:")
            print(f"    Average Base Score:  {Fore.YELLOW}{self.cvss31_metrics.get('average', 0)}/10.0{self.reset()}")
            print(f"    Maximum Base Score:  {Fore.RED}{self.cvss31_metrics.get('maximum', 0)}/10.0{self.reset()}")
            for entry in self.cvss31_metrics.get("top", []):
                print(f"      - {entry['name']}  {entry['score']}  {entry['vector']}")

        if self.attack_vector_analysis and self.attack_vector_analysis.get("counts"):
            print(f"\n  Attack Vector Analysis:")
            print(f"    Distribution: {self.attack_vector_analysis.get('detail', 'n/a')}")
            print(f"    Dominant vector: {Fore.YELLOW}{self.attack_vector_analysis.get('dominant', 'n/a')}{self.reset()}")

        if self.exploitability_metrics and self.exploitability_metrics.get("top"):
            print(f"\n  Exploitability Scoring:")
            print(f"    Average: {Fore.YELLOW}{self.exploitability_metrics.get('average', 0)}/10.0{self.reset()}"
                  f"   Maximum: {Fore.RED}{self.exploitability_metrics.get('maximum', 0)}/10.0{self.reset()}")
            for entry in self.exploitability_metrics.get("top", []):
                print(f"      - {entry['name']}  {entry['score']}")

        if self.business_impact_summary and self.business_impact_summary.get("domains"):
            bi = self.business_impact_summary
            bi_color = Fore.RED + Style.BRIGHT if bi.get("score", 0) >= 80 else (
                Fore.YELLOW if bi.get("score", 0) >= 40 else Fore.CYAN)
            print(f"\n  Business Impact Assessment:")
            print(f"    Level: {bi_color}{bi.get('level', 'Minimal')} "
                  f"(index {bi.get('score', 0)}/100){self.reset()}")
            print(f"    {bi.get('detail', '')}")

        if self.posture:
            print(f"\n  Security Posture Score:")
            p_color = Fore.GREEN if self.posture.get("score", 0) >= 80 else (
                Fore.YELLOW if self.posture.get("score", 0) >= 60 else Fore.LIGHTRED_EX)
            print(f"    {p_color}{self.posture.get('score', 0)}/100  Grade {self.posture.get('grade', 'F')}{self.reset()}"
                  f"  (checks {self.posture.get('check_score', 0)} + risk penalty index {self.posture.get('risk_index', 0)})")

        if self.roadmap:
            print(f"\n  Remediation Roadmap:")
            sev_colors_map = {
                "critical": Fore.RED + Style.BRIGHT,
                "high": Fore.LIGHTRED_EX,
                "medium": Fore.YELLOW,
                "low": Fore.CYAN,
            }
            for phase in self.roadmap:
                items = phase.get("items", [])
                phase_color = sev_colors_map.get(phase.get("severity", "low"), "")
                if items:
                    print(f"    {phase_color}{phase.get('phase', '')}{self.reset()} — {len(items)} item(s)")
                    print(f"      {Fore.LIGHTBLACK_EX}{phase.get('goal', '')}{self.reset()}")
                    for item in items[:4]:
                        print(f"        * {item['name']}")
                        print(f"          {Fore.GREEN}{item['remediation']}{self.reset()}")
                else:
                    print(f"    {Fore.GREEN}{phase.get('phase', '')}{self.reset()} — clear")

        print(f"\n  Compliance Checklist:")
        owasp_cats = {}
        nist_cats = {}
        pci_cats = {}
        hipaa_cats = {}
        for f in self.findings:
            if f.owasp:
                if f.owasp not in owasp_cats:
                    owasp_cats[f.owasp] = {"passed": 0, "failed": 0}
                if f.passed:
                    owasp_cats[f.owasp]["passed"] += 1
                else:
                    owasp_cats[f.owasp]["failed"] += 1
            if f.nist:
                if f.nist not in nist_cats:
                    nist_cats[f.nist] = {"passed": 0, "failed": 0}
                if f.passed:
                    nist_cats[f.nist]["passed"] += 1
                else:
                    nist_cats[f.nist]["failed"] += 1
            if f.pci_dss:
                if f.pci_dss not in pci_cats:
                    pci_cats[f.pci_dss] = {"passed": 0, "failed": 0}
                if f.passed:
                    pci_cats[f.pci_dss]["passed"] += 1
                else:
                    pci_cats[f.pci_dss]["failed"] += 1
            if f.hipaa:
                if f.hipaa not in hipaa_cats:
                    hipaa_cats[f.hipaa] = {"passed": 0, "failed": 0}
                if f.passed:
                    hipaa_cats[f.hipaa]["passed"] += 1
                else:
                    hipaa_cats[f.hipaa]["failed"] += 1

        owasp_total_checks = sum(v["passed"] + v["failed"] for v in owasp_cats.values())
        owasp_passed_checks = sum(v["passed"] for v in owasp_cats.values())
        owasp_pct = int(owasp_passed_checks / owasp_total_checks * 100) if owasp_total_checks > 0 else 0

        nist_total_checks = sum(v["passed"] + v["failed"] for v in nist_cats.values())
        nist_passed_checks = sum(v["passed"] for v in nist_cats.values())
        nist_pct = int(nist_passed_checks / nist_total_checks * 100) if nist_total_checks > 0 else 0

        pci_total_checks = sum(v["passed"] + v["failed"] for v in pci_cats.values())
        pci_passed_checks = sum(v["passed"] for v in pci_cats.values())
        pci_pct = int(pci_passed_checks / pci_total_checks * 100) if pci_total_checks > 0 else 0

        hipaa_total_checks = sum(v["passed"] + v["failed"] for v in hipaa_cats.values())
        hipaa_passed_checks = sum(v["passed"] for v in hipaa_cats.values())
        hipaa_pct = int(hipaa_passed_checks / hipaa_total_checks * 100) if hipaa_total_checks > 0 else 0

        print(f"    OWASP Top 10 Compliance:  {Fore.GREEN if owasp_pct >= 70 else Fore.YELLOW}{owasp_pct}%{self.reset()}")
        for key in sorted(owasp_cats.keys()):
            v = owasp_cats[key]
            name = OWASP_TOP10.get(key, key)
            status = Fore.GREEN + "PASS" if v["failed"] == 0 else Fore.RED + "FAIL"
            print(f"      {key} {name:40s} {status}{self.reset()} ({v['passed']}/{v['passed'] + v['failed']})")

        print(f"\n    NIST SP 800-53 Compliance: {Fore.GREEN if nist_pct >= 70 else Fore.YELLOW}{nist_pct}%{self.reset()}")
        for key in sorted(nist_cats.keys()):
            v = nist_cats[key]
            name = NIST_CATEGORIES.get(key, key)
            status = Fore.GREEN + "PASS" if v["failed"] == 0 else Fore.RED + "FAIL"
            print(f"      {key}  {name:40s} {status}{self.reset()} ({v['passed']}/{v['passed'] + v['failed']})")

        if pci_cats:
            print(f"\n    PCI-DSS Compliance:        {Fore.GREEN if pci_pct >= 70 else Fore.YELLOW}{pci_pct}%{self.reset()}")
            for key in sorted(pci_cats.keys()):
                v = pci_cats[key]
                name = PCI_DSS_REQUIREMENTS.get(key, key)
                status = Fore.GREEN + "PASS" if v["failed"] == 0 else Fore.RED + "FAIL"
                print(f"      {key:8s} {name:40s} {status}{self.reset()} ({v['passed']}/{v['passed'] + v['failed']})")

        if hipaa_cats:
            print(f"\n    HIPAA Safeguards:          {Fore.GREEN if hipaa_pct >= 70 else Fore.YELLOW}{hipaa_pct}%{self.reset()}")
            for key in sorted(hipaa_cats.keys()):
                v = hipaa_cats[key]
                name = HIPAA_SAFEGUARDS.get(key, key)
                status = Fore.GREEN + "PASS" if v["failed"] == 0 else Fore.RED + "FAIL"
                print(f"      {key:10s} {name:40s} {status}{self.reset()} ({v['passed']}/{v['passed'] + v['failed']})")

        maturity_score = self._compute_maturity()
        maturity = SECURITY_MATURITY_LEVELS[maturity_score]
        print(f"\n  Security Maturity: {Fore.CYAN}Level {maturity_score} - {maturity['level']}{self.reset()}")
        print(f"  {maturity['description']}")

        print(f"\n{'=' * 70}\n")

    def _compute_score_and_grade(self):
        total_points = sum(f.points for f in self.findings)
        max_points = sum(f.max_points for f in self.findings)
        score = int((total_points / max_points * 100)) if max_points > 0 else 0
        if score >= 95:
            grade = "A+"
        elif score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B+"
        elif score >= 70:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 50:
            grade = "D"
        elif score >= 40:
            grade = "D-"
        else:
            grade = "F"
        return score, grade

    def _compute_compliance(self):
        owasp_cats = {}
        nist_cats = {}
        pci_cats = {}
        hipaa_cats = {}
        for f in self.findings:
            if f.owasp:
                if f.owasp not in owasp_cats:
                    owasp_cats[f.owasp] = {"passed": 0, "failed": 0}
                if f.passed:
                    owasp_cats[f.owasp]["passed"] += 1
                else:
                    owasp_cats[f.owasp]["failed"] += 1
            if f.nist:
                if f.nist not in nist_cats:
                    nist_cats[f.nist] = {"passed": 0, "failed": 0}
                if f.passed:
                    nist_cats[f.nist]["passed"] += 1
                else:
                    nist_cats[f.nist]["failed"] += 1
            if f.pci_dss:
                if f.pci_dss not in pci_cats:
                    pci_cats[f.pci_dss] = {"passed": 0, "failed": 0}
                if f.passed:
                    pci_cats[f.pci_dss]["passed"] += 1
                else:
                    pci_cats[f.pci_dss]["failed"] += 1
            if f.hipaa:
                if f.hipaa not in hipaa_cats:
                    hipaa_cats[f.hipaa] = {"passed": 0, "failed": 0}
                if f.passed:
                    hipaa_cats[f.hipaa]["passed"] += 1
                else:
                    hipaa_cats[f.hipaa]["failed"] += 1
        return owasp_cats, nist_cats, pci_cats, hipaa_cats

    def _compute_pct(self, cats):
        total = sum(v["passed"] + v["failed"] for v in cats.values())
        passed = sum(v["passed"] for v in cats.values())
        return int(passed / total * 100) if total > 0 else 0

    def _compute_maturity(self):
        total = len(self.findings)
        if total == 0:
            return 0
        passed = sum(1 for f in self.findings if f.passed)
        pass_rate = passed / total
        failed = [f for f in self.findings if not f.passed and f.severity != "info"]
        crit = sum(1 for f in failed if f.severity == "critical")
        high = sum(1 for f in failed if f.severity == "high")
        covered = len({f.category for f in self.findings})
        coverage = covered / len(CATEGORY_ORDER) if CATEGORY_ORDER else 1.0

        pillar_names = [
            "ssl", "headers", "cookies", "vuln", "advanced_vuln",
            "auth_security", "mfa", "password_policy", "waf", "rate_limiting",
            "account_lockout", "bot_protection", "supply_chain", "compliance",
        ]
        pillar_scores = []
        for cat in pillar_names:
            rel = [f for f in self.findings if f.category == cat]
            if not rel:
                pillar_scores.append(0.0)
                continue
            pillar_scores.append(sum(1 for f in rel if f.passed) / len(rel))
        pillar_rate = sum(pillar_scores) / len(pillar_scores) if pillar_scores else 0.0

        combined = 0.55 * pass_rate + 0.45 * pillar_rate

        if combined >= 0.92 and crit == 0 and high <= 2 and coverage >= 0.75:
            score = 4
        elif combined >= 0.80 and crit <= 1 and coverage >= 0.60:
            score = 3
        elif combined >= 0.60 and crit <= 3:
            score = 2
        elif combined >= 0.40:
            score = 1
        else:
            score = 0
        if crit >= 5 and score > 1:
            score = 1
        if high >= 10 and score > 2:
            score = 2
        if coverage < 0.35 and score > 2:
            score = 2
        return score

    def _compute_threat_model(self, failed_findings):
        model = {key: {"label": meta["label"], "desc": meta["desc"],
                       "count": 0, "max_cvss": 0.0, "risk": 0.0, "findings": []}
                 for key, meta in STRIDE_THEATS.items()}
        weights = {"spoofing": 1.2, "tampering": 1.3, "repudiation": 0.8,
                   "information_disclosure": 1.1, "denial_of_service": 0.9,
                   "elevation_of_privilege": 1.4}
        for f in failed_findings:
            if f.severity == "info":
                continue
            stride_key = None
            if f.owasp:
                stride_key = OWASP_TO_STRIDE.get(f.owasp)
            if not stride_key:
                stride_key = CATEGORY_TO_STRIDE.get(f.category, "tampering")
            entry = model[stride_key]
            entry["count"] += 1
            score = f.cvss31["score"]
            if score > entry["max_cvss"]:
                entry["max_cvss"] = score
            if len(entry["findings"]) < 3:
                entry["findings"].append(f.name)

        total_risk = 0.0
        for key, entry in model.items():
            entry["risk"] = round(entry["count"] * entry["max_cvss"] * weights.get(key, 1.0) / 3.0, 1)
            total_risk += entry["risk"]
        threat_index = min(100.0, total_risk)
        if threat_index >= 60:
            level = "Severe"
        elif threat_index >= 40:
            level = "High"
        elif threat_index >= 25:
            level = "Moderate"
        elif threat_index >= 10:
            level = "Elevated"
        else:
            level = "Guarded"
        dominant = max(model.items(), key=lambda kv: kv[1]["risk"])
        self.threat_model = {
            "stride": model,
            "risk_index": round(threat_index, 1),
            "level": level,
            "dominant_threat": dominant[0] if dominant[1]["risk"] > 0 else "none",
            "dominant_label": dominant[1]["label"] if dominant[1]["risk"] > 0 else "None",
        }
        return self.threat_model

    def _compute_threat_landscape(self, failed_findings):
        vectors = {}
        if self.attack_vector_analysis:
            vectors = self.attack_vector_analysis.get("counts", {})
        external = self.assets.get("external_hosts", [])
        cdns = self.assets.get("cdn_hosts", [])
        bi = self.business_impact_summary or {}
        tm = self.threat_model or {}

        entry_points = []
        if self.assets.get("forms"):
            entry_points.append(str(self.assets["forms"]) + " form(s)")
        if self.api_endpoints_found:
            entry_points.append(str(len(self.api_endpoints_found)) + " API endpoint(s)")
        if self.assets.get("frames"):
            entry_points.append(str(self.assets["frames"]) + " frame(s)")
        if self.parsed.query:
            entry_points.append("query-string parameters")

        threat_actors = []
        if any((not f.passed) and f.category in ("supply_chain", "sri", "wasm") for f in failed_findings):
            threat_actors.append("Supply-chain / CDN compromise")
        if any((not f.passed) and f.category in ("cors", "cookies", "ssl") for f in failed_findings):
            threat_actors.append("Network attacker (MITM / session theft)")
        if any((not f.passed) and f.owasp in ("A03", "A10") for f in failed_findings):
            threat_actors.append("Web application attacker (injection / SSRF)")
        if any((not f.passed) and f.category in ("privacy", "disclosure") for f in failed_findings):
            threat_actors.append("Data broker / opportunistic scraper")
        if any((not f.passed) and f.category in ("api", "container") for f in failed_findings):
            threat_actors.append("Credential abuse / insider API misuse")
        if any((not f.passed) and f.category in ("mfa", "password_policy", "account_lockout",
                                                 "auth_security", "rate_limiting")
               for f in failed_findings):
            threat_actors.append("Credential stuffing / account takeover operator")
        if any((not f.passed) and f.category in ("waf", "bot_protection") for f in failed_findings):
            threat_actors.append("Automated scanner / evasion-capable attacker")
        if not threat_actors:
            threat_actors.append("Opportunistic scanner")

        techniques = []
        for f in failed_findings:
            if f.severity == "info":
                continue
            tech = THREAT_TECHNIQUE_MAP.get(f.owasp or "") or THREAT_TECHNIQUE_MAP.get(f.category)
            if tech and tech not in techniques:
                techniques.append(tech)

        failed_cats = {f.category for f in failed_findings if f.severity != "info"}
        phase_defs = [
            ("Reconnaissance", ["disclosure", "dns", "privacy"]),
            ("Initial Access", ["ssl", "headers", "waf", "bot_protection", "vuln"]),
            ("Execution", ["advanced_vuln", "content", "wasm"]),
            ("Persistence", ["cookies", "auth_security", "cache"]),
            ("Privilege Escalation", ["account_lockout", "mfa", "password_policy",
                                      "auth_security", "rate_limiting"]),
            ("Exfiltration / Impact", ["cors", "supply_chain", "api", "container", "compliance"]),
        ]
        kill_chain = []
        active_phases = 0
        for phase_name, cats in phase_defs:
            hits = sorted(failed_cats.intersection(cats))
            active = bool(hits)
            if active:
                active_phases += 1
            kill_chain.append({"phase": phase_name, "categories": hits, "active": active})

        active_findings = [f for f in failed_findings if f.severity != "info"]
        crit = sum(1 for f in active_findings if f.severity == "critical")
        high = sum(1 for f in active_findings if f.severity == "high")
        exposure_score = min(100, active_phases * 10 + crit * 12 + high * 6)

        self.threat_landscape = {
            "threat_level": tm.get("level", "Guarded"),
            "dominant_threat": tm.get("dominant_label", "None"),
            "risk_index": tm.get("risk_index", 0),
            "attack_vectors": vectors,
            "entry_points": entry_points[:6],
            "third_party_hosts": (cdns or external)[:6],
            "plausible_actors": threat_actors[:6],
            "primary_business_exposure": bi.get("detail", "n/a"),
            "top_open_findings": [f.name for f in failed_findings
                                  if f.severity in ("critical", "high")][:5],
            "techniques": techniques[:8],
            "kill_chain": kill_chain,
            "exposure_score": exposure_score,
        }
        return self.threat_landscape

    def _build_recommendations(self, failed_findings):
        sev_priority = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}
        actionable = [f for f in failed_findings if f.severity in ("critical", "high", "medium", "low")]
        actionable.sort(key=lambda f: (f.cvss31["score"], SEVERITY_POINTS.get(f.severity, 0)),
                        reverse=True)
        recs = []
        seen = set()
        for f in actionable:
            if f.name in seen:
                continue
            seen.add(f.name)
            owasp_label = OWASP_TOP10.get(f.owasp, f.owasp) if f.owasp else ""
            effort = EFFORT_BY_CATEGORY.get(f.category, "M")
            track = "quick-win" if (f.severity in ("critical", "high") and effort in ("S", "M")) else (
                "strategic" if effort == "L" else "standard")
            recs.append({
                "priority": sev_priority.get(f.severity, "P4"),
                "title": f.name,
                "action": f.remediation or "Review and remediate this finding.",
                "category": self.category_names.get(f.category, f.category),
                "severity": f.severity,
                "cvss": f.cvss31["score"],
                "owasp": owasp_label,
                "effort": effort,
                "track": track,
            })
            if len(recs) >= 12:
                break

        if len(recs) < 5:
            quick_wins = [
                {"priority": "P2", "title": "Harden Content-Security-Policy",
                 "action": "Remove unsafe-inline/unsafe-eval, add nonces/hashes and a report-uri endpoint.",
                 "category": "Browser Policy & Fetch Metadata", "severity": "medium",
                 "cvss": 5.0, "owasp": "Security Misconfiguration",
                 "effort": "M", "track": "standard"},
                {"priority": "P2", "title": "Pin SRI hashes on third-party assets",
                 "action": "Add integrity + crossorigin to every cross-origin script and stylesheet.",
                 "category": "Subresource Integrity Validation", "severity": "medium",
                 "cvss": 5.0, "owasp": "Software and Data Integrity Failures",
                 "effort": "S", "track": "quick-win"},
                {"priority": "P2", "title": "Enable MFA for privileged accounts",
                 "action": "Require TOTP or WebAuthn for admin and billing roles at first privileged login.",
                 "category": "Multi-Factor Authentication", "severity": "high",
                 "cvss": 7.0, "owasp": "Identification and Authentication Failures",
                 "effort": "L", "track": "strategic"},
                {"priority": "P2", "title": "Deploy WAF managed rulesets",
                 "action": "Turn on managed SQLi/XSS rules and tune exclusions for legitimate traffic.",
                 "category": "Web Application Firewall", "severity": "high",
                 "cvss": 7.0, "owasp": "Security Misconfiguration",
                 "effort": "M", "track": "quick-win"},
                {"priority": "P3", "title": "Enforce rate limiting on auth endpoints",
                 "action": "Apply per-IP and per-account limits with Retry-After on login and password reset.",
                 "category": "Rate Limiting", "severity": "medium",
                 "cvss": 5.0, "owasp": "Identification and Authentication Failures",
                 "effort": "M", "track": "standard"},
                {"priority": "P3", "title": "Restrict powerful browser features",
                 "action": "Ship Permissions-Policy denying camera/microphone/geolocation by default.",
                 "category": "Browser Policy & Fetch Metadata", "severity": "low",
                 "cvss": 3.0, "owasp": "Security Misconfiguration",
                 "effort": "S", "track": "quick-win"},
                {"priority": "P3", "title": "Enable cross-origin isolation",
                 "action": "Set COOP: same-origin and COEP: require-corp where compatible.",
                 "category": "Browser Policy & Fetch Metadata", "severity": "low",
                 "cvss": 3.0, "owasp": "Security Misconfiguration",
                 "effort": "M", "track": "standard"},
                {"priority": "P3", "title": "Adopt Trusted Types",
                 "action": "Enforce require-trusted-types-for 'script' and audit DOM sinks.",
                 "category": "Browser Policy & Fetch Metadata", "severity": "medium",
                 "cvss": 5.0, "owasp": "Injection",
                 "effort": "M", "track": "standard"},
            ]
            existing_titles = {r["title"] for r in recs}
            for qw in quick_wins:
                if qw["title"] not in existing_titles:
                    recs.append(qw)
                if len(recs) >= 10:
                    break

        self.recommendations = recs
        return recs

    def _compute_weighted_compliance(self):
        sev_w = {"critical": 5, "high": 3, "medium": 2, "low": 1, "info": 1}
        result_pct = {}
        buckets_out = {}
        for attr, label in (("owasp", "owasp"), ("nist", "nist"),
                            ("pci_dss", "pci_dss"), ("hipaa", "hipaa")):
            buckets = {}
            for f in self.findings:
                key = getattr(f, attr, None)
                if not key:
                    continue
                b = buckets.setdefault(key, {"w_pass": 0, "w_fail": 0, "passed": 0, "failed": 0})
                weight = sev_w.get(f.severity, 1)
                if f.passed:
                    b["w_pass"] += weight
                    b["passed"] += 1
                else:
                    b["w_fail"] += weight
                    b["failed"] += 1
            total_w = sum(v["w_pass"] + v["w_fail"] for v in buckets.values())
            pass_w = sum(v["w_pass"] for v in buckets.values())
            pct = int(round(pass_w / total_w * 100)) if total_w > 0 else 0
            result_pct[label] = pct
            buckets_out[label] = buckets
        self.compliance_weighted = result_pct
        self._weighted_buckets = buckets_out
        return result_pct

    def _compute_dashboard(self):
        score, grade = self._compute_score_and_grade()
        owasp_cats, nist_cats, pci_cats, hipaa_cats = self._compute_compliance()
        failed = [f for f in self.findings if not f.passed]
        maturity = self._compute_maturity()
        tm = self.threat_model or {}
        tl = self.threat_landscape or {}
        self.dashboard = {
            "score": score,
            "grade": grade,
            "posture": self.posture or {},
            "maturity_level": maturity,
            "maturity_label": SECURITY_MATURITY_LEVELS[maturity]["level"],
            "maturity_focus": SECURITY_MATURITY_LEVELS[maturity].get("focus", ""),
            "threat_level": tm.get("level", "n/a"),
            "threat_index": tm.get("risk_index", 0),
            "dominant_threat": tm.get("dominant_label", "None"),
            "exposure_score": tl.get("exposure_score", 0),
            "kill_chain_active_phases": sum(
                1 for p in tl.get("kill_chain", []) if p.get("active")),
            "compliance": {
                "owasp": self._compute_pct(owasp_cats),
                "nist": self._compute_pct(nist_cats),
                "pci_dss": self._compute_pct(pci_cats),
                "hipaa": self._compute_pct(hipaa_cats),
            },
            "compliance_weighted": dict(self.compliance_weighted),
            "compliance_effectiveness": dict(self.compliance_effectiveness),
            "defense_layers": dict(self.defense_layers),
            "risk_residual": (self.risk_matrix or {}).get("residual_risk", "n/a"),
            "risk_weighted_index": (self.risk_matrix or {}).get("weighted_index", 0),
            "open_findings": len(failed),
            "critical": sum(1 for f in failed if f.severity == "critical"),
            "high": sum(1 for f in failed if f.severity == "high"),
            "medium": sum(1 for f in failed if f.severity == "medium"),
            "low": sum(1 for f in failed if f.severity == "low"),
            "passed": sum(1 for f in self.findings if f.passed),
            "total": len(self.findings),
            "categories_covered": len({f.category for f in self.findings}),
            "recommendation_count": len(self.recommendations or []),
        }
        return self.dashboard

    def export_json(self, filepath):
        score, grade = self._compute_score_and_grade()
        owasp_cats, nist_cats, pci_cats, hipaa_cats = self._compute_compliance()

        failed_findings = [f for f in self.findings if not f.passed]
        cvss_vals = [f.cvss_score for f in failed_findings]
        avg_cvss = round(sum(cvss_vals) / max(1, len(cvss_vals)), 1) if cvss_vals else 0.0
        max_cvss = round(max(cvss_vals), 1) if cvss_vals else 0.0

        data = {
            "version": VERSION,
            "target": self.url,
            "scan_time": datetime.datetime.now().isoformat(),
            "score": score,
            "grade": grade,
            "cloud_provider": self.cloud_provider,
            "container_hints": self.container_hints,
            "owasp_compliance_pct": self._compute_pct(owasp_cats),
            "nist_compliance_pct": self._compute_pct(nist_cats),
            "pci_dss_compliance_pct": self._compute_pct(pci_cats),
            "hipaa_compliance_pct": self._compute_pct(hipaa_cats),
            "security_maturity_level": self._compute_maturity(),
            "total_points": sum(f.points for f in self.findings),
            "max_points": sum(f.max_points for f in self.findings),
            "security_posture": self.posture,
            "threat_model": self.threat_model,
            "threat_landscape": self.threat_landscape,
            "recommendations": self.recommendations,
            "dashboard": self.dashboard,
            "compliance_weighted": self.compliance_weighted,
            "cvss_v31_metrics": self.cvss31_metrics,
            "attack_vector_analysis": self.attack_vector_analysis,
            "exploitability_metrics": self.exploitability_metrics,
            "business_impact": self.business_impact_summary,
            "remediation_roadmap": self.roadmap,
            "defense_layers": self.defense_layers,
            "risk_matrix": self.risk_matrix,
            "compliance_effectiveness": self.compliance_effectiveness,
            "waf_products": self.waf_products,
            "bot_protection": self.bot_protection_found,
            "rate_limit_signals": self.rate_limit_signals,
            "lockout_signals": self.lockout_signals,
            "mfa_signals": self.mfa_signals,
            "password_policy_signals": self.password_policy_signals,
            "attack_surface": self.assets,
            "summary": {
                "critical": sum(1 for f in self.findings if f.severity == "critical" and not f.passed),
                "high": sum(1 for f in self.findings if f.severity == "high" and not f.passed),
                "medium": sum(1 for f in self.findings if f.severity == "medium" and not f.passed),
                "low": sum(1 for f in self.findings if f.severity == "low" and not f.passed),
                "info": sum(1 for f in self.findings if f.severity == "info"),
                "passed": sum(1 for f in self.findings if f.passed),
                "total": len(self.findings),
            },
            "cvss_risk_metrics": {
                "average": avg_cvss,
                "maximum": max_cvss,
            },
            "compliance": {
                "owasp_top10": {k: {"passed": v["passed"], "failed": v["failed"],
                                    "name": OWASP_TOP10.get(k, k)}
                                for k, v in owasp_cats.items()},
                "nist_800_53": {k: {"passed": v["passed"], "failed": v["failed"],
                                     "name": NIST_CATEGORIES.get(k, k)}
                                 for k, v in nist_cats.items()},
                "pci_dss": {k: {"passed": v["passed"], "failed": v["failed"],
                                 "name": PCI_DSS_REQUIREMENTS.get(k, k)}
                             for k, v in pci_cats.items()},
                "hipaa": {k: {"passed": v["passed"], "failed": v["failed"],
                               "name": HIPAA_SAFEGUARDS.get(k, k)}
                           for k, v in hipaa_cats.items()},
            },
            "findings": [
                {
                    "name": f.name,
                    "severity": f.severity,
                    "passed": f.passed,
                    "details": f.details,
                    "category": f.category,
                    "cve": f.cve,
                    "remediation": f.remediation,
                    "owasp": f.owasp,
                    "nist": f.nist,
                    "pci_dss": f.pci_dss,
                    "hipaa": f.hipaa,
                    "cvss_score": f.cvss_score,
                    "cvss_v31_score": f.cvss31.get("score", 0.0),
                    "cvss_v31_vector": f.cvss31.get("vector", ""),
                    "exploitability_score": f.cvss31.get("exploitability_score", 0.0),
                    "impact_score": f.cvss31.get("impact_score", 0.0),
                    "business_impact": f.business_impact,
                    "attack_vector": f.attack_vector or "Network",
                }
                for f in self.findings
            ],
        }
        with open(filepath, "w") as fh:
            json.dump(data, fh, indent=2)
        print(f"{Fore.GREEN}Exported JSON to {filepath}{Style.RESET_ALL}")

    def export_csv(self, filepath):
        with open(filepath, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["Name", "Severity", "Passed", "Category", "CVE",
                             "Remediation", "OWASP", "NIST", "PCI-DSS", "HIPAA",
                             "CVSS Score", "CVSS v3.1 Score", "CVSS v3.1 Vector",
                             "Exploitability", "Business Impact", "Details"])
            for finding in self.findings:
                writer.writerow([
                    finding.name, finding.severity, finding.passed,
                    finding.category, finding.cve or "",
                    finding.remediation or "", finding.owasp or "",
                    finding.nist or "", finding.pci_dss or "",
                    finding.hipaa or "", finding.cvss_score,
                    finding.cvss31.get("score", 0.0),
                    finding.cvss31.get("vector", ""),
                    finding.cvss31.get("exploitability_score", 0.0),
                    finding.business_impact,
                    finding.details,
                ])
        print(f"{Fore.GREEN}Exported CSV to {filepath}{Style.RESET_ALL}")

    def export_html(self, filepath):
        score, grade = self._compute_score_and_grade()
        owasp_cats, nist_cats, pci_cats, hipaa_cats = self._compute_compliance()
        owasp_pct = self._compute_pct(owasp_cats)
        nist_pct = self._compute_pct(nist_cats)
        pci_pct = self._compute_pct(pci_cats)
        hipaa_pct = self._compute_pct(hipaa_cats)

        if not self.dashboard:
            self._compute_dashboard()

        if score >= 95:
            grade_color = "#2ecc71"
        elif score >= 90:
            grade_color = "#27ae60"
        elif score >= 80:
            grade_color = "#2ecc71"
        elif score >= 70:
            grade_color = "#27ae60"
        elif score >= 60:
            grade_color = "#f39c12"
        elif score >= 50:
            grade_color = "#e67e22"
        elif score >= 40:
            grade_color = "#e74c3c"
        else:
            grade_color = "#c0392b"

        severity_styles = {
            "critical": "background:#e74c3c;color:#fff",
            "high": "background:#e67e22;color:#fff",
            "medium": "background:#f1c40f;color:#000",
            "low": "background:#3498db;color:#fff",
            "info": "background:#95a5a6;color:#fff",
        }

        cat_order = CATEGORY_ORDER

        categories = {}
        for f in self.findings:
            if f.category not in categories:
                categories[f.category] = []
            categories[f.category].append(f)

        rows_html = ""
        for cat in cat_order:
            if cat not in categories:
                continue
            cat_display = self.category_names.get(cat, cat)
            rows_html += '<tr class="cat-row"><td colspan="5">' + cat_display + "</td></tr>\n"
            for f in categories[cat]:
                if f.passed:
                    status = '<span style="color:#2ecc71">&#10003;</span>'
                else:
                    status = '<span style="color:#e74c3c">&#10007;</span>'
                style = severity_styles.get(f.severity, "")
                cve_cell = f.cve if f.cve else ""
                rem_cell = f.remediation if f.remediation and not f.passed else ""
                rows_html += (
                    "<tr>"
                    "<td>" + status + "</td>"
                    '<td><span class="badge" style="' + style + '">' + f.severity.upper() + "</span></td>"
                    "<td>" + f.name + "</td>"
                    "<td>" + cve_cell + "</td>"
                    "<td>" + f.details + "</td>"
                    "</tr>\n"
                )
                if rem_cell:
                    rows_html += (
                        '<tr><td colspan="2"></td>'
                        '<td colspan="3" style="color:#2ecc71;font-size:12px;padding-left:30px;">'
                        "Fix: " + rem_cell + "</td></tr>\n"
                    )

        owasp_rows = ""
        for key in sorted(owasp_cats.keys()):
            v = owasp_cats[key]
            name = OWASP_TOP10.get(key, key)
            badge = '<span style="color:#2ecc71">PASS</span>' if v["failed"] == 0 else '<span style="color:#e74c3c">FAIL</span>'
            owasp_rows += (
                "<tr><td>" + key + "</td><td>" + name + "</td><td>" + badge + "</td>"
                "<td>" + str(v["passed"]) + "/" + str(v["passed"] + v["failed"]) + "</td></tr>\n"
            )

        nist_rows = ""
        for key in sorted(nist_cats.keys()):
            v = nist_cats[key]
            name = NIST_CATEGORIES.get(key, key)
            badge = '<span style="color:#2ecc71">PASS</span>' if v["failed"] == 0 else '<span style="color:#e74c3c">FAIL</span>'
            nist_rows += (
                "<tr><td>" + key + "</td><td>" + name + "</td><td>" + badge + "</td>"
                "<td>" + str(v["passed"]) + "/" + str(v["passed"] + v["failed"]) + "</td></tr>\n"
            )

        pci_rows = ""
        for key in sorted(pci_cats.keys()):
            v = pci_cats[key]
            name = PCI_DSS_REQUIREMENTS.get(key, key)
            badge = '<span style="color:#2ecc71">PASS</span>' if v["failed"] == 0 else '<span style="color:#e74c3c">FAIL</span>'
            pci_rows += (
                "<tr><td>" + key + "</td><td>" + name + "</td><td>" + badge + "</td>"
                "<td>" + str(v["passed"]) + "/" + str(v["passed"] + v["failed"]) + "</td></tr>\n"
            )

        hipaa_rows = ""
        for key in sorted(hipaa_cats.keys()):
            v = hipaa_cats[key]
            name = HIPAA_SAFEGUARDS.get(key, key)
            badge = '<span style="color:#2ecc71">PASS</span>' if v["failed"] == 0 else '<span style="color:#e74c3c">FAIL</span>'
            hipaa_rows += (
                "<tr><td>" + key + "</td><td>" + name + "</td><td>" + badge + "</td>"
                "<td>" + str(v["passed"]) + "/" + str(v["passed"] + v["failed"]) + "</td></tr>\n"
            )

        maturity = SECURITY_MATURITY_LEVELS[self._compute_maturity()]
        scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_failed = sum(1 for f in self.findings if not f.passed)
        total_passed = sum(1 for f in self.findings if f.passed)
        cloud_info = self.cloud_provider.upper() if self.cloud_provider else "N/A"
        container_info = ", ".join(self.container_hints) if self.container_hints else "N/A"

        posture_score = self.posture.get("score", 0) if self.posture else 0
        posture_grade = self.posture.get("grade", "-") if self.posture else "-"
        posture_detail = ""
        if self.posture:
            posture_detail = ("checks " + str(self.posture.get("check_score", 0))
                              + ", risk index " + str(self.posture.get("risk_index", 0)))

        heatmap_html = '<table><thead><tr><th>Category</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr></thead><tbody>'
        heat_colors = {"critical": "#e74c3c", "high": "#e67e22", "medium": "#f1c40f", "low": "#3498db"}
        heat_rows_any = False
        for cat in cat_order:
            if cat not in categories:
                continue
            failed = [f for f in categories[cat] if not f.passed and f.severity != "info"]
            if not failed:
                continue
            heat_rows_any = True
            counts = {s: sum(1 for f in failed if f.severity == s)
                      for s in ("critical", "high", "medium", "low")}
            cells = ""
            for s in ("critical", "high", "medium", "low"):
                n = counts[s]
                if n == 0:
                    cells += '<td style="color:#484f58;">&middot;</td>'
                else:
                    cells += ('<td><span class="badge" style="background:'
                              + heat_colors[s] + ';color:#fff;">' + str(n) + "</span></td>")
            label = self.category_names.get(cat, cat)
            heatmap_html += "<tr><td>" + label + "</td>" + cells + "<td>" + str(sum(counts.values())) + "</td></tr>"
        if not heat_rows_any:
            heatmap_html += '<tr><td colspan="6" style="color:#2ecc71;">No open risk cells</td></tr>'
        heatmap_html += "</tbody></table>"

        roadmap_html = ""
        for phase in (self.roadmap or []):
            items = phase.get("items", [])
            roadmap_html += (
                '<div style="margin-bottom:16px;">'
                "<h3 style=\"color:#58a6ff;font-size:15px;margin-bottom:4px;\">"
                + phase.get("phase", "") + " (" + str(len(items)) + " item(s))</h3>"
                '<p style="color:#8b949e;font-size:13px;margin-bottom:8px;">'
                + phase.get("goal", "") + "</p>"
            )
            if items:
                roadmap_html += "<ul>"
                for item in items:
                    roadmap_html += (
                        "<li><strong>" + item["name"] + "</strong> — "
                        '<span style="color:#2ecc71;">' + item["remediation"] + "</span>"
                        ' <span style="color:#8b949e;">(CVSS v3.1 ' + str(item["cvss31"])
                        + ", effort " + str(item.get("effort", "M")) + ")</span></li>"
                    )
                roadmap_html += "</ul>"
            else:
                roadmap_html += '<p style="color:#2ecc71;font-size:13px;">Clear</p>'
            roadmap_html += "</div>"

        bi = self.business_impact_summary or {}
        tm_export = self.threat_model or {}

        defense_html = ""
        if self.defense_layers:
            defense_html = (
                '<div class="section">\n<h2>Defense-in-Depth Layers</h2>\n'
                "<table>\n<thead><tr><th>Layer</th><th>Score</th><th>Status</th>"
                "<th>Checks</th></tr></thead><tbody>\n"
            )
            for lname, meta in self.defense_layers.items():
                sc = meta.get("score")
                sc_str = "n/a" if sc is None else str(sc) + "%"
                defense_html += (
                    "<tr><td>" + lname + "</td><td>" + sc_str + "</td><td>"
                    + str(meta.get("label", "")) + "</td><td>"
                    + str(meta.get("passed", 0)) + "/" + str(meta.get("total", 0))
                    + "</td></tr>\n"
                )
            defense_html += "</tbody></table>\n</div>\n"

        kill_chain_html = ""
        tl_export = self.threat_landscape or {}
        if tl_export.get("kill_chain"):
            kill_chain_html = (
                '<div class="section">\n<h2>Attack Progression (Kill Chain)</h2>\n'
                "<table>\n<thead><tr><th>Phase</th><th>Status</th>"
                "<th>Open Categories</th></tr></thead><tbody>\n"
            )
            for phase in tl_export["kill_chain"]:
                active = bool(phase.get("active"))
                state = "ACTIVE" if active else "clear"
                color = "#e74c3c" if active else "#2ecc71"
                cats = ", ".join(phase.get("categories", [])) or "-"
                kill_chain_html += (
                    "<tr><td>" + str(phase.get("phase", "")) + "</td>"
                    '<td style="color:' + color + ';">' + state + "</td><td>"
                    + cats + "</td></tr>\n"
                )
            kill_chain_html += "</tbody></table>\n</div>\n"

        threat_rows = ""
        for key, meta in (tm_export.get("stride") or {}).items():
            examples = "; ".join(meta.get("findings", [])[:3])
            threat_rows += (
                "<tr><td>" + meta.get("label", key) + "</td>"
                "<td>" + str(meta.get("count", 0)) + "</td>"
                "<td>" + str(meta.get("risk", 0)) + "</td>"
                "<td>" + examples + "</td></tr>\n"
            )
        if not threat_rows:
            threat_rows = '<tr><td colspan="4" style="color:#2ecc71;">No open STRIDE threats</td></tr>'

        recs_html = ""
        for rec in (self.recommendations or []):
            recs_html += (
                "<tr><td>" + str(rec.get("priority", "")) + "</td>"
                "<td>" + rec.get("title", "") + "</td>"
                "<td>" + rec.get("action", "") + "</td>"
                "<td>" + str(rec.get("cvss", 0)) + "</td></tr>\n"
            )
        if not recs_html:
            recs_html = '<tr><td colspan="4" style="color:#2ecc71;">No prioritized recommendations</td></tr>'

        metrics_html = (
            '<div class="section">\n'
            "<h2>Security Posture Score: " + str(posture_score) + "/100 (Grade " + posture_grade + ")</h2>\n"
            '<div class="compliance-bar"><div class="compliance-fill" style="width:' + str(posture_score) + '%;background:#58a6ff;"></div></div>\n'
            "<p style=\"color:#8b949e;\">" + posture_detail + "</p>\n"
            "</div>\n"
            '<div class="section">\n'
            "<h2>Risk Heat Map</h2>\n"
            + heatmap_html +
            "</div>\n"
            '<div class="section">\n'
            "<h2>CVSS v3.1 / Exploitability / Business Impact</h2>\n"
            "<p>Average CVSS v3.1 base: <strong>"
            + str(self.cvss31_metrics.get("average", 0)) + "</strong>, max <strong>"
            + str(self.cvss31_metrics.get("maximum", 0)) + "</strong></p>\n"
            "<p>Average exploitability: <strong>"
            + str(self.exploitability_metrics.get("average", 0)) + "</strong></p>\n"
            "<p>Business impact: <strong>"
            + str(bi.get("level", "Minimal")) + "</strong> (index "
            + str(bi.get("score", 0)) + "/100) — " + str(bi.get("detail", "")) + "</p>\n"
            "</div>\n"
            '<div class="section">\n'
            "<h2>Threat Landscape (STRIDE)</h2>\n"
            "<p>Threat level: <strong>" + str(tm_export.get("level", "n/a"))
            + "</strong> — dominant: <strong>" + str(tm_export.get("dominant_label", "None"))
            + "</strong> (index " + str(tm_export.get("risk_index", 0)) + "/100)</p>\n"
            "<table>\n"
            '<thead><tr><th>Threat</th><th>Findings</th><th>Risk</th><th>Examples</th></tr></thead>\n'
            "<tbody>" + threat_rows + "</tbody>\n</table>\n"
            "</div>\n"
            '<div class="section">\n'
            "<h2>Security Recommendations</h2>\n"
            "<table>\n"
            '<thead><tr><th>Priority</th><th>Recommendation</th><th>Action</th><th>CVSS</th></tr></thead>\n'
            "<tbody>" + recs_html + "</tbody>\n</table>\n"
            "</div>\n"
            '<div class="section">\n'
            "<h2>Remediation Roadmap</h2>\n"
            + roadmap_html +
            "</div>\n"
        )

        html = (
            "<!DOCTYPE html>\n"
            '<html lang="en">\n'
            "<head>\n"
            '<meta charset="UTF-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
            "<title>SecurityChecker Report - " + self.url + "</title>\n"
            "<style>\n"
            "* { margin: 0; padding: 0; box-sizing: border-box; }\n"
            "body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }\n"
            ".container { max-width: 1200px; margin: 0 auto; }\n"
            ".header { background: #161b22; border-radius: 8px; padding: 30px; margin-bottom: 24px; border: 1px solid #30363d; }\n"
            ".header h1 { color: #58a6ff; font-size: 28px; margin-bottom: 8px; }\n"
            ".header .meta { color: #8b949e; font-size: 14px; margin-top: 8px; }\n"
            ".score-card { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }\n"
            ".score-box { background: #161b22; border-radius: 8px; padding: 24px; flex: 1; text-align: center; border: 1px solid #30363d; min-width: 140px; }\n"
            ".score-box .number { font-size: 48px; font-weight: bold; color: " + grade_color + "; }\n"
            ".score-box .label { font-size: 13px; color: #8b949e; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }\n"
            ".grade { font-size: 36px; font-weight: bold; color: " + grade_color + "; }\n"
            ".badge { display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: bold; }\n"
            "table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; border: 1px solid #30363d; margin-bottom: 24px; }\n"
            "th { background: #21262d; padding: 14px 16px; text-align: left; font-size: 13px; color: #58a6ff; text-transform: uppercase; letter-spacing: 1px; }\n"
            "td { padding: 10px 16px; border-bottom: 1px solid #21262d; font-size: 14px; }\n"
            ".cat-row td { background: #21262d; font-weight: bold; color: #58a6ff; padding: 10px 16px; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }\n"
            "tr:hover { background: #21262d; }\n"
            ".section { background: #161b22; border-radius: 8px; padding: 24px; margin-bottom: 24px; border: 1px solid #30363d; }\n"
            ".section h2 { color: #58a6ff; margin-bottom: 16px; font-size: 18px; }\n"
            ".compliance-bar { height: 20px; background: #21262d; border-radius: 4px; overflow: hidden; margin: 8px 0; }\n"
            ".compliance-fill { height: 100%; background: #2ecc71; transition: width 0.3s; }\n"
            ".footer { text-align: center; color: #484f58; font-size: 12px; margin-top: 24px; padding: 16px; }\n"
            "</style>\n"
            "</head>\n"
            "<body>\n"
            '<div class="container">\n'
            '<div class="header">\n'
            "<h1>SecurityChecker v" + VERSION + " - Scan Report</h1>\n"
            '<div class="meta">Target: ' + self.url + " | Scanned: " + scan_time
            + " | Cloud: " + cloud_info + " | Container: " + container_info + "</div>\n"
            "</div>\n"
            '<div class="score-card">\n'
            '<div class="score-box"><div class="number">' + str(score) + '</div><div class="label">Score / 100</div></div>\n'
            '<div class="score-box"><div class="grade">' + grade + '</div><div class="label">Grade</div></div>\n'
            '<div class="score-box"><div class="number" style="color:#e74c3c">'
            + str(total_failed)
            + '</div><div class="label">Issues Found</div></div>\n'
            '<div class="score-box"><div class="number" style="color:#2ecc71">'
            + str(total_passed)
            + '</div><div class="label">Checks Passed</div></div>\n'
            '<div class="score-box"><div class="number" style="color:#58a6ff">'
            + str(posture_score)
            + '</div><div class="label">Posture / 100</div></div>\n'
            + "</div>\n"
            + defense_html
            + kill_chain_html
            + metrics_html
            + "<table>\n"
            '<thead><tr><th>Status</th><th>Severity</th><th>Check</th><th>CVE</th><th>Details</th></tr></thead>\n'
            "<tbody>\n"
            + rows_html
            + "</tbody>\n</table>\n"
            '<div class="section">\n'
            "<h2>OWASP Top 10 Compliance (" + str(owasp_pct) + "%)</h2>\n"
            '<div class="compliance-bar"><div class="compliance-fill" style="width:' + str(owasp_pct) + '%"></div></div>\n'
            "<table>\n"
            '<thead><tr><th>Category</th><th>Description</th><th>Status</th><th>Checks</th></tr></thead>\n'
            "<tbody>" + owasp_rows + "</tbody>\n</table>\n</div>\n"
            '<div class="section">\n'
            "<h2>NIST SP 800-53 Compliance (" + str(nist_pct) + "%)</h2>\n"
            '<div class="compliance-bar"><div class="compliance-fill" style="width:' + str(nist_pct) + '%"></div></div>\n'
            "<table>\n"
            '<thead><tr><th>Family</th><th>Description</th><th>Status</th><th>Checks</th></tr></thead>\n'
            "<tbody>" + nist_rows + "</tbody>\n</table>\n</div>\n"
            '<div class="section">\n'
            "<h2>PCI-DSS Compliance (" + str(pci_pct) + "%)</h2>\n"
            '<div class="compliance-bar"><div class="compliance-fill" style="width:' + str(pci_pct) + '%"></div></div>\n'
            "<table>\n"
            '<thead><tr><th>Requirement</th><th>Description</th><th>Status</th><th>Checks</th></tr></thead>\n'
            "<tbody>" + pci_rows + "</tbody>\n</table>\n</div>\n"
            '<div class="section">\n'
            "<h2>HIPAA Safeguards (" + str(hipaa_pct) + "%)</h2>\n"
            '<div class="compliance-bar"><div class="compliance-fill" style="width:' + str(hipaa_pct) + '%"></div></div>\n'
            "<table>\n"
            '<thead><tr><th>Safeguard</th><th>Description</th><th>Status</th><th>Checks</th></tr></thead>\n'
            "<tbody>" + hipaa_rows + "</tbody>\n</table>\n</div>\n"
            '<div class="section">\n'
            "<h2>Security Maturity: Level " + str(self._compute_maturity()) + " - " + maturity["level"] + "</h2>\n"
            "<p>" + maturity["description"] + "</p>\n"
            "</div>\n"
            '<div class="footer">Generated by SecurityChecker v' + VERSION + " on " + scan_time + "</div>\n"
            "</div>\n</body>\n</html>"
        )

        with open(filepath, "w") as fh:
            fh.write(html)
        print(f"{Fore.GREEN}Exported HTML report to {filepath}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description="SecurityChecker v" + VERSION + " - Comprehensive Website Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--export", choices=["all", "json", "csv", "html", "none"],
                        default="none", help="Export format (default: none)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--api-depth", action="store_true",
                        help="Enable deep API security testing (GraphQL, rate limiting, auth bypass)")
    parser.add_argument("--container-scan", action="store_true",
                        help="Enable container and cloud infrastructure detection")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    if not args.no_color:
        print(BANNER)

        print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Target: {args.url}")
        print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Timeout: {args.timeout}s")
        if args.api_depth:
            print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} API Deep Testing: Enabled")
        if args.container_scan:
            print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Container/Cloud Scan: Enabled")
        print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} v5 modules: WASM, WebRTC, fingerprinting, crypto-mining,")
        print(f"  {Fore.CYAN}    supply-chain, cache poisoning, advanced SQLi/XSS/CSRF/SSRF{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} v6 modules: SRI validation, Trusted Types, CSP reporting,")
        print(f"  {Fore.CYAN}    Permissions-Policy, COOP/CORP/COEP, Fetch Metadata, threat model,{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}    DOM clobbering, CSS/HTML/header injection, posture dashboard{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} v7 modules: WAF, bot protection, rate limiting,")
        print(f"  {Fore.CYAN}    account lockout, MFA, password policy, auth bypass,{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}    session fixation, privilege escalation, refined scoring{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Starting scan...\n")

    analyzer = SecurityAnalyzer(
        args.url, args.timeout, args.no_color,
        api_depth=args.api_depth,
        container_scan=args.container_scan,
        verbose=args.verbose
    )
    analyzer.run_all_checks()
    analyzer.display_results()

    if args.export != "none":
        base_name = "security_report_" + analyzer.domain.replace(".", "_")
        if args.export in ("all", "json"):
            analyzer.export_json(base_name + ".json")
        if args.export in ("all", "csv"):
            analyzer.export_csv(base_name + ".csv")
        if args.export in ("all", "html"):
            analyzer.export_html(base_name + ".html")


if __name__ == "__main__":
    main()
