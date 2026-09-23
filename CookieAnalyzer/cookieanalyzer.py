import sys
import os
import re
import json
import csv
import argparse
import time
import email.utils
import warnings
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, urljoin
from http.cookies import SimpleCookie, CookieError

try:
    import requests
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

try:
    from bs4 import BeautifulSoup
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "beautifulsoup4"])
    from bs4 import BeautifulSoup

VERSION = "2.0"
TOOL_NAME = "CookieAnalyzer"

BANNER_LINES = [
    r"  ____          _                    _       ",
    r" / ___|___   __| | ___ _ __ ___   __| |_   _ ",
    r"| |   / _ \ / _` |/ _ \ '_ ` _ \ / _` | | | |",
    r"| |__| (_) | (_| |  __/ | | | | | (_| | |_| |",
    r" \____\___/ \__,_|\___|_| |_| |_|\__,_|\__, |",
    r"                                         |___/ ",
]

CATEGORIES = [
    ("inventory", "Cookie Inventory", 15),
    ("security", "Cookie Security", 15),
    ("privacy", "Cookie Privacy", 15),
    ("consent", "Consent Management", 15),
    ("gdpr", "GDPR Compliance", 10),
    ("ccpa", "CCPA Compliance", 5),
    ("categories", "Cookie Categories", 10),
    ("thirdparty", "Third-Party Cookies", 10),
    ("policy", "Cookie Policy", 5),
    ("technical", "Technical Quality", 5),
]

CONSENT_TOOLS = {
    "OneTrust": ["onetrust", "otsdk", "cookielaw.com", "optanon"],
    "Cookiebot": ["cookiebot", "cybot"],
    "CookieYes": ["cookieyes"],
    "Quantcast Choice": ["quantcast", "quantmchoice"],
    "Didomi": ["didomi"],
    "TrustArc": ["trustarc", "truste.com"],
    "Osano": ["osano"],
    "Civic UK Cookie Control": ["cookiecontrol"],
    "Usercentrics": ["usercentrics"],
    "Termly": ["termly"],
    "Complianz": ["complianz"],
    "CookieFirst": ["cookiefirst"],
    "Borlabs Cookie": ["borlabs"],
    "Axeptio": ["axeptio"],
    "Consentmanager": ["consentmanager"],
    "Ketch": ["ketch.com", "ketch-tcf"],
    "Evidon": ["evidon"],
    "Sourcepoint": ["sourcepoint"],
    "Tarteaucitron": ["tarteaucitron"],
    "Iubenda": ["iubenda"],
    "Sirdata": ["sirdata"],
    "CookieScript": ["cookiescript"],
    "Policystat": ["policystat"],
}

STAT_TOKENS = [
    "_ga", "_gid", "_gat", "_gb", "__ut", "utma", "utmcontent", "utmsource",
    "utmterm", "utmmedium", "utmcampaign", "matomo", "_pk_", "piwik",
    "plausible", "analytics", "analytic", "hotjar", "_hj", "_clck", "_clsk",
    "clarity", "mixpanel", "amplitude", "segmentio", "segment", "chartbeat",
    "snowplow", "kissmetrics", "statistic", "stats", "perf", "pplr", "piano",
    "keen", "heap", "fullstory", "hotjar", "optimizely", "abtasty", "vwo",
    "crazyegg", "mouseflow", "pendo", "onium", "matomo",
]

MKT_TOKENS = [
    "_fbp", "_fbc", "doubleclick", "googlead", "gclid", "gcl_", "gbraid",
    "wbraid", "msclkid", "twclid", "bcookie", "bscookie", "muid", "uetsid",
    "uetvid", "pinterest", "pin_unauth", "ttclid", "snap", "sbjs",
    "affiliate", "advert", "marketing", "campaign", "retarget", "criteo",
    "taboola", "outbrain", "personalization_id", "visitor_id", "klaviyo",
    "mc_eid", "mkto_trk", "marketo", "pardot", "sailthru", "s_vi",
    "everest", "adroll", "perfectaudience", "demdex", "everesttech",
    "bluekai", "krxd", "rlsid", "test_cookie", "adsid", "lang_did",
    "yid", "ide_ds", "_lr_env", "cid", "partner", "referral", "tracking",
]

SOC_TOKENS = [
    "facebook", "twitter", "linkedin", "instagram", "youtube", "tiktok",
    "whatsapp", "sharethis", "addthis", "addtoany", "social", "fb_share",
    "snuuid", "lidc", "bcookie_social", "xs", "xsrf_social",
]

PREF_TOKENS = [
    "lang", "locale", "language", "currency", "country", "region", "theme",
    "darkmode", "displaymode", "pref", "setting", "timezone", "font",
    "layout", "homepage", "onboarding", "dismiss", "newsletter", "notif",
    "color", "style", "viewmode", "sortorder", "filter",
]

NEC_TOKENS = [
    "session", "sess", "csrf", "xsrf", "auth", "login", "token", "jwt",
    "phpsessid", "jsessionid", "asp.net_sessionid", "consent", "optanon",
    "cookieyes", "euconsent", "iab", "cf_bm", "cf_clearance", "akamai",
    "ak_bmsc", "bm_sz", "arraffinity", "server", "loadbalanc", "sticky",
    "route", "nonce", "__next", "nextjs", "started", "visited", "abck",
    "pass", "secure", "ident", "request", "gateway", "awselb", "cdn",
    "bot", "guard", "verify", "captcha", "reese",
]

PII_NAME_TOKENS = [
    "email", "e_mail", "uid", "user_id", "userid", "user-id", "username",
    "user_name", "phone", "mobile", "address", "firstname", "first_name",
    "lastname", "last_name", "fullname", "full_name", "birthday", "dob",
    "ssn", "passport", "customer", "account", "member_id", "memberid",
    "profile_id", "identity", "id_token", "auth_user", "telephone",
    "given_name", "family_name",
]

SENSITIVE_TOKENS = [
    "session", "sess", "auth", "token", "csrf", "xsrf", "login", "pwd",
    "password", "jwt", "secret", "credential", "bearer",
]

TRACKER_NAMES = [
    "_ga", "_gid", "_gat", "__utm", "_fbp", "_fbc", "fr", "ide", "muid",
    "bcookie", "_uetsid", "_uetvid", "personalization_id", "test_cookie",
    "nid", "_pin_unauth", "li_sugr", "dsid", "anj", "_pubcid", "criteo",
    "tc_id", "puid", "segs", "uuid", "tvid",
]

TRACKER_DOMAINS = [
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "google.com", "googleadservices.com", "facebook.net", "facebook.com",
    "fbcdn.net", "hotjar.com", "hotjar.io", "linkedin.com", "licdn.com",
    "twitter.com", "twimg.com", "criteo.com", "criteo.net", "taboola.com",
    "outbrain.com", "amazon-adsystem.com", "adnxs.com", "rubiconproject.com",
    "pubmatic.com", "casalemedia.com", "openx.net", "demdex.net",
    "krxd.net", "bluekai.com", "oracle.com", "scorecardresearch.com",
    "quantserve.com", "adsrvr.org", "matomo.cloud", "segment.com",
    "segment.io", "mixpanel.com", "amplitude.com", "clarity.ms",
    "snapchat.com", "pinterest.com", "tiktok.com", "adroll.com",
    "yandex.ru", "mc.yandex.ru", "bidswitch.net", "smartadserver.com",
]

JS_REQUIRED_TOKENS = [
    "_ga", "_gid", "_gat", "_fbp", "_fbc", "_hj", "_clck", "_clsk",
    "plausible", "_pk_", "sbjs", "_uetsid", "_uetvid", "clarity",
]

CONSENT_COOKIE_TOKENS = ["consent", "optanon", "cookieyes", "euconsent", "iabtcf", "cookieconsent", "usercentrics", "didomi", "cookiecontrol"]

CAT_DEFS = [
    ("Strictly necessary", ["strictly necessary", "essential cookies", "necessary cookies", "absolutely necessary", "strictly-necessary"], "necessary"),
    ("Functionality", ["functional cookies", "functionality cookies", "preference cookies", "preferences cookies", "functionality"], "preferences"),
    ("Analytics", ["analytics cookies", "analytics", "statistics cookies", "statistical", "performance cookies", "measuring"], "statistics"),
    ("Advertising", ["advertising cookies", "advertising", "marketing cookies", "targeted advertising", "ad cookies", "commercial"], "marketing"),
    ("Social media", ["social media", "social network", "social plugins", "social cookies"], "social"),
]

MAX_EXPIRY_DAYS = 400
RECOMMENDED_EXPIRY_DAYS = 365
IDEAL_COOKIE_COUNT = 20
IDEAL_COOKIE_BYTES = 4096


def base_domain(host):
    host = (host or "").lower().strip(".")
    if not host:
        return ""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) or ":" in host:
        return host
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def grade_for(score):
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def truncate(text, width):
    text = str(text)
    if len(text) <= width:
        return text
    if width <= 1:
        return text[:width]
    return text[: width - 1] + "…"


class Colors:
    def __init__(self, enabled=True):
        self.enabled = enabled

    def wrap(self, text, code):
        if not self.enabled:
            return str(text)
        return "\033[" + code + "m" + str(text) + "\033[0m"

    def bold(self, t):
        return self.wrap(t, "1")

    def dim(self, t):
        return self.wrap(t, "2")

    def red(self, t):
        return self.wrap(t, "31")

    def green(self, t):
        return self.wrap(t, "32")

    def yellow(self, t):
        return self.wrap(t, "33")

    def blue(self, t):
        return self.wrap(t, "34")

    def magenta(self, t):
        return self.wrap(t, "35")

    def cyan(self, t):
        return self.wrap(t, "36")

    def white(self, t):
        return self.wrap(t, "37")

    def bright_red(self, t):
        return self.wrap(t, "91")

    def bright_green(self, t):
        return self.wrap(t, "92")

    def bright_yellow(self, t):
        return self.wrap(t, "93")

    def bright_blue(self, t):
        return self.wrap(t, "94")

    def bright_magenta(self, t):
        return self.wrap(t, "95")

    def bright_cyan(self, t):
        return self.wrap(t, "96")

    def status(self, kind):
        if kind == "pass":
            return self.bright_green("[PASS]")
        if kind == "warn":
            return self.bright_yellow("[WARN]")
        if kind == "fail":
            return self.bright_red("[FAIL]")
        return self.bright_blue("[INFO]")

    def grade(self, g):
        if g in ("A+", "A"):
            return self.bright_green(g)
        if g == "B":
            return self.bright_cyan(g)
        if g == "C":
            return self.bright_yellow(g)
        if g == "D":
            return self.bright_magenta(g)
        return self.bright_red(g)


class CookieItem:
    def __init__(self, name, value, domain="", path="/", secure=False,
                 httponly=False, samesite="", expires=None, source="header",
                 partitioned=False):
        self.name = name
        self.value = value or ""
        self.domain = domain or ""
        self.path = path or "/"
        self.secure = bool(secure)
        self.httponly = bool(httponly)
        self.samesite = samesite or ""
        self.expires = expires
        self.source = source
        self.partitioned = bool(partitioned)

    @property
    def host_only(self):
        return not self.domain

    @property
    def is_session(self):
        return self.expires is None

    @property
    def days_left(self):
        if self.expires is None:
            return None
        return (self.expires - utc_now()).days

    @property
    def size(self):
        return len(self.name) + len(self.value)

    def to_dict(self):
        return {
            "name": self.name,
            "value": self.value[:120],
            "domain": self.domain,
            "path": self.path,
            "secure": self.secure,
            "httponly": self.httponly,
            "samesite": self.samesite,
            "expires": self.expires.isoformat() if self.expires else None,
            "lifetime": "session" if self.is_session else "persistent",
            "days_left": self.days_left,
            "source": self.source,
            "size": self.size,
            "partitioned": self.partitioned,
            "purpose": getattr(self, "purpose", "unknown"),
        }


def parse_expiry_from_morsel(morsel):
    max_age = morsel.get("max-age")
    if max_age:
        try:
            secs = int(str(max_age).strip())
            if secs > 0:
                return utc_now() + timedelta(seconds=secs)
            return datetime(1970, 1, 1)
        except ValueError:
            pass
    expires = morsel.get("expires")
    if not expires:
        return None
    expires = str(expires).strip()
    try:
        dt = email.utils.parsedate_to_datetime(expires)
        if dt is not None:
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
    except (TypeError, ValueError, IndexError):
        pass
    for fmt in ("%Y-%m-%d", "%Y%m%d", "%a, %d-%b-%Y %H:%M:%S",
                "%a, %d %b %Y %H:%M:%S", "%d-%b-%Y", "%m/%d/%Y", "%d/%m/%Y"):
        try:
            return datetime.strptime(expires, fmt)
        except ValueError:
            continue
    return None


def has_partitioned_attribute(raw):
    return any(p.strip().lower() == "partitioned" for p in (raw or "").split(";"))


def parse_set_cookie(raw, source="header"):
    items = []
    raw = (raw or "").strip()
    if not raw:
        return items
    partitioned = has_partitioned_attribute(raw)
    sc = SimpleCookie()
    try:
        sc.load(raw)
    except (CookieError, ValueError):
        sc = {}
    if sc:
        for name, morsel in sc.items():
            expires = parse_expiry_from_morsel(morsel)
            items.append(CookieItem(
                name=name,
                value=morsel.value or "",
                domain=(morsel.get("domain") or "").strip(),
                path=(morsel.get("path") or "/").strip() or "/",
                secure=bool(morsel.get("secure")),
                httponly=("httponly" in raw.lower()) if source == "header" else False,
                samesite=(morsel.get("samesite") or "").strip(),
                expires=expires,
                source=source,
                partitioned=partitioned,
            ))
        return items
    m = re.match(r"\s*([^=;\s]+)\s*=\s*([^;]*)", raw)
    if m:
        name = m.group(1)
        value = m.group(2)
        lower = raw.lower()
        domain_m = re.search(r"domain=([^;]+)", raw, re.I)
        path_m = re.search(r"path=([^;]+)", raw, re.I)
        ss_m = re.search(r"samesite=([^;]+)", raw, re.I)
        exp_m = re.search(r"expires=([^;]+)", raw, re.I)
        exp = None
        if exp_m:
            try:
                exp = email.utils.parsedate_to_datetime(exp_m.group(1).strip())
                if exp is not None and exp.tzinfo is not None:
                    exp = exp.astimezone(timezone.utc).replace(tzinfo=None)
            except (TypeError, ValueError, IndexError):
                exp = None
        items.append(CookieItem(
            name=name,
            value=value,
            domain=domain_m.group(1).strip() if domain_m else "",
            path=path_m.group(1).strip() if path_m else "/",
            secure="secure" in lower,
            httponly="httponly" in lower,
            samesite=ss_m.group(1).strip() if ss_m else "",
            expires=exp,
            source=source,
            partitioned=partitioned,
        ))
    return items


def classify_purpose(name, value=""):
    n = (name or "").lower()
    for token in STAT_TOKENS:
        if (len(token) >= 4 and token in n) or (len(token) < 4 and token == n):
            return "statistics"
    for token in MKT_TOKENS:
        if (len(token) >= 4 and token in n) or (len(token) < 4 and token == n):
            return "marketing"
    for token in SOC_TOKENS:
        if (len(token) >= 4 and token in n) or (len(token) < 4 and token == n):
            return "social"
    for token in PREF_TOKENS:
        if (len(token) >= 4 and token in n) or (len(token) < 4 and token == n):
            return "preferences"
    for token in NEC_TOKENS:
        if (len(token) >= 4 and token in n) or (len(token) < 4 and token == n):
            return "necessary"
    v = (value or "").lower()
    if re.match(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$", v):
        return "unknown"
    return "unknown"


def detect_pii(name, value=""):
    n = (name or "").lower()
    hits = []
    for token in PII_NAME_TOKENS:
        if (len(token) >= 4 and token in n) or (len(token) < 4 and token == n):
            hits.append("name:" + token)
    v = value or ""
    if re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", v):
        hits.append("value:email")
    if re.search(r"\+?\d[\d\s().-]{8,}\d", v):
        hits.append("value:phone")
    if re.match(r"^eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+$", v):
        hits.append("value:jwt")
    if re.search(r"\b\d{9,}\b", v):
        hits.append("value:numeric-id")
    return hits


def print_banner(c):
    colors = [c.cyan, c.bright_yellow, c.bright_green, c.bright_magenta, c.bright_red, c.bright_blue]
    for i, line in enumerate(BANNER_LINES):
        paint = colors[i % len(colors)]
        print(paint(line))
    print(c.bold(c.bright_cyan("        CookieAnalyzer v" + VERSION + "  -  Cookie Privacy & Compliance Auditor")))
    print(c.dim("        " + "=" * 60))
    print()


class CookieAnalyzer:
    def __init__(self, url, timeout=15, verbose=False, use_color=True):
        if not re.match(r"^https?://", url, re.I):
            url = "https://" + url
        self.url = url
        self.timeout = timeout
        self.verbose = verbose
        self.c = Colors(use_color)
        parsed = urlparse(self.url)
        self.page_host = parsed.hostname or ""
        self.base = base_domain(self.page_host)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 "
                           + TOOL_NAME + "/" + VERSION),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        })
        self.response = None
        self.final_url = self.url
        self.html = ""
        self.soup = None
        self.cookies = []
        self.header_cookies = []
        self.script_cookies = []
        self.first_party = []
        self.third_party = []
        self.tracker_cookies = []
        self.unknown_purpose = []
        self.links = {"privacy": None, "cookie_policy": None, "do_not_sell": None, "cookie_settings": None}
        self.privacy_html = ""
        self.policy_html = ""
        self.consent = {
            "banner": False,
            "tool": None,
            "accept_button": False,
            "granular": False,
            "opt_out": False,
            "consent_cookie": False,
            "nonessential": False,
            "scripts_before_banner": False,
            "posture": "none detected",
        }
        self.results = []
        self.recommendations = []
        self.started = datetime.now()
        self.elapsed = 0.0

    def log(self, message):
        if self.verbose:
            print(self.c.dim("      · " + message))

    def fetch(self, target):
        start = time.time()
        try:
            resp = self.session.get(target, timeout=self.timeout, allow_redirects=True, verify=True)
        except requests.exceptions.SSLError:
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass
            resp = self.session.get(target, timeout=self.timeout, allow_redirects=True, verify=False)
        elapsed = time.time() - start
        self.log("GET " + str(resp.url) + " -> " + str(resp.status_code) + " in " + format(elapsed, ".2f") + "s")
        return resp

    def collect_cookies(self, resp):
        raw_list = []
        try:
            raw_list = list(resp.raw.headers.getlist("Set-Cookie"))
        except Exception:
            header = resp.headers.get("Set-Cookie")
            if header:
                raw_list = [header]
        for raw in raw_list:
            for item in parse_set_cookie(raw, "header"):
                self.header_cookies.append(item)
            self.log("Set-Cookie: " + raw[:160])
        if not self.header_cookies:
            try:
                for jar_cookie in resp.cookies:
                    domain = (jar_cookie.domain or "").lstrip(".")
                    expires = None
                    if jar_cookie.expires:
                        expires = datetime.utcfromtimestamp(jar_cookie.expires)
                    rest = jar_cookie._rest if hasattr(jar_cookie, "_rest") else {}
                    self.header_cookies.append(CookieItem(
                        name=jar_cookie.name,
                        value=jar_cookie.value or "",
                        domain=domain,
                        path=jar_cookie.path or "/",
                        secure=bool(jar_cookie.secure),
                        httponly=("HttpOnly" in rest) or ("httponly" in {str(k).lower() for k in rest}),
                        samesite=str(rest.get("SameSite", "") or ""),
                        expires=expires,
                        source="header",
                        partitioned=any(str(k).lower() == "partitioned" for k in rest),
                    ))
            except Exception as exc:
                self.log("jar parse error: " + str(exc))
        self.cookies = list(self.header_cookies)

    def collect_script_cookies(self):
        if not self.html:
            return
        seen = {c.name.lower() for c in self.cookies}
        for m in re.finditer(r"document\.cookie\s*=\s*[\"']([^\"']+)[\"']", self.html, re.I):
            pair = m.group(1)
            name = pair.split("=")[0].strip()
            if not name or name.lower() in seen:
                continue
            seen.add(name.lower())
            value = pair.split("=", 1)[1] if "=" in pair else ""
            secure = "; secure" in pair.lower()
            ss_m = re.search(r"samesite=([^;]+)", pair, re.I)
            expires = None
            exp_m = re.search(r"expires=([^;]+)", pair, re.I)
            if exp_m:
                try:
                    expires = email.utils.parsedate_to_datetime(exp_m.group(1).strip())
                    if expires is not None and expires.tzinfo is not None:
                        expires = expires.astimezone(timezone.utc).replace(tzinfo=None)
                except (TypeError, ValueError, IndexError):
                    expires = None
            if expires is None:
                max_m = re.search(r"max-age=(-?\d+)", pair, re.I)
                if max_m and int(max_m.group(1)) > 0:
                    expires = utc_now() + timedelta(seconds=int(max_m.group(1)))
            item = CookieItem(
                name=name,
                value=value.split(";")[0],
                domain="",
                path="/",
                secure=secure,
                httponly=False,
                samesite=ss_m.group(1).strip() if ss_m else "",
                expires=expires,
                source="script",
                partitioned=has_partitioned_attribute(pair),
            )
            self.script_cookies.append(item)
            self.log("document.cookie: " + name)
        self.cookies = list(self.header_cookies) + list(self.script_cookies)

    def is_first_party_domain(self, cookie_domain):
        d = (cookie_domain or "").lstrip(".").lower()
        if not d:
            return True
        h = self.page_host.lower()
        if h == d:
            return True
        if h.endswith("." + d):
            return True
        if d == self.base:
            return True
        if self.base and d.endswith("." + self.base):
            return True
        if h.endswith("." + self.base) and d.endswith("." + self.base):
            return True
        return False

    def domain_scope_ok(self, cookie_domain):
        d = (cookie_domain or "").lstrip(".").lower()
        if not d:
            return True
        if len(d.split(".")) < 2:
            return False
        if not self.base:
            return True
        return d == self.base or d.endswith("." + self.base)

    def is_tracker_cookie(self, cookie):
        n = cookie.name.lower()
        for token in TRACKER_NAMES:
            if (len(token) >= 4 and token in n) or (len(token) < 4 and token == n):
                return True
        d = (cookie.domain or "").lstrip(".").lower()
        for td in TRACKER_DOMAINS:
            if d == td or d.endswith("." + td):
                return True
        return False

    def derive(self):
        for cookie in self.cookies:
            cookie_purpose = classify_purpose(cookie.name, cookie.value)
            cookie.purpose = cookie_purpose
            if self.is_first_party_domain(cookie.domain) and cookie.source != "script":
                self.first_party.append(cookie)
            elif cookie.source == "script":
                self.first_party.append(cookie)
            else:
                self.third_party.append(cookie)
            if cookie_purpose == "unknown":
                self.unknown_purpose.append(cookie)
            if self.is_tracker_cookie(cookie):
                self.tracker_cookies.append(cookie)
        nonessential = False
        for cookie in self.cookies:
            if cookie.purpose in ("statistics", "marketing", "social", "preferences"):
                nonessential = True
            if cookie in self.third_party:
                nonessential = True
        self.consent["nonessential"] = nonessential
        self.consent["consent_cookie"] = any(
            any(tok in c.name.lower() for tok in CONSENT_COOKIE_TOKENS)
            for c in self.cookies
        )
        self.log("cookies=" + str(len(self.cookies)) + " first=" + str(len(self.first_party)) +
                 " third=" + str(len(self.third_party)) + " trackers=" + str(len(self.tracker_cookies)))

    def find_link(self, patterns, exclude=None):
        if not self.soup:
            return None
        for a in self.soup.find_all("a", href=True):
            text = a.get_text(" ", strip=True).lower()
            href = a["href"].strip().lower()
            if exclude and any(x in text or x in href for x in exclude):
                continue
            for pat in patterns:
                if pat in text or pat in href:
                    return urljoin(self.final_url, a["href"])
        return None

    def detect_links(self):
        self.links["privacy"] = self.find_link(
            ["privacy policy", "privacy-policy", "privacy_policy"],
            exclude=["cookie"],
        )
        if not self.links["privacy"]:
            self.links["privacy"] = self.find_link(["privacy"])
        self.links["cookie_policy"] = self.find_link(
            ["cookie policy", "cookies policy", "cookie-policy", "cookies-policy", "policy#cookies"]
        )
        self.links["do_not_sell"] = self.find_link(
            ["do not sell", "do-not-sell", "do not sell my personal information",
             "your privacy choices", "privacy-choices"]
        )
        self.links["cookie_settings"] = self.find_link(
            ["cookie settings", "cookie preferences", "manage cookies", "cookie policy center",
             "cookie declaration"]
        )
        self.log("privacy=" + str(self.links["privacy"]) + " cookie_policy=" + str(self.links["cookie_policy"]))

    def detect_consent(self):
        lower = self.html.lower()
        banner_text = bool(re.search(
            r"(we|this site|this website|our site|we Collect|we use|uses|using)\s+cookies|"
            r"cookie\s+(banner|consent|notice|preferences|policy bar)|"
            r"this\s+website\s+uses|click\s+accept\s+to\s+continue",
            lower,
        ))
        banner_id = bool(re.search(
            r"(?:id|class)\s*=\s*[\"'][^\"']*(?:cookie[-_ ]?(?:consent|banner|notice|bar|wall)|"
            r"cookie-consent|cookieconsent|cc-window|onetrust|cookiebot)[^\"']*[\"']",
            lower,
        ))
        self.consent["banner"] = banner_text or banner_id
        if self.soup:
            accept_terms = {
                "accept", "accept all", "accept cookies", "accept all cookies", "allow",
                "allow all", "allow all cookies", "i agree", "agree", "agree all",
                "got it", "ok", "yes", "yes, i agree", "i consent", "continue",
            }
            for tag in self.soup.find_all(["button", "a", "input", "div", "span"]):
                text = tag.get_text(" ", strip=True).lower()
                if not text or len(text) > 70:
                    continue
                if tag.name == "input":
                    value = (tag.get("value") or "").lower()
                    text = value or text
                if text in accept_terms:
                    self.consent["accept_button"] = True
                if any(k in text for k in ("manage", "customi", "settings", "preferences", "options")) and (
                    "cookie" in text or "consent" in text or "privacy" in text
                ):
                    self.consent["granular"] = True
                if "necessary only" in text or "reject" in text or "decline" in text or "deny" in text:
                    self.consent["granular"] = True
                if "do not sell" in text:
                    self.consent["opt_out"] = True
                    if tag.name == "a" and tag.get("href") and not self.links["do_not_sell"]:
                        self.links["do_not_sell"] = urljoin(self.final_url, tag["href"])
                if "opt out" in text or "opt-out" in text or "global privacy control" in text:
                    self.consent["opt_out"] = True
        markers = [
            "googletagmanager.com/gtag", "google-analytics.com/analytics",
            "google-analytics.com/ga", "connect.facebook.net", "fbevents.js",
            "hotjar.com", "clarity.ms", "doubleclick.net", "scorecardresearch",
        ]
        banner_idx = -1
        for probe in ("we use cookies", "cookie consent", "cookie-banner", "cookiebanner", "onetrust", "cookiebot"):
            idx = lower.find(probe)
            if idx >= 0:
                banner_idx = idx if banner_idx < 0 else min(banner_idx, idx)
        first_script_idx = -1
        for marker in markers:
            idx = lower.find(marker)
            if idx >= 0:
                first_script_idx = idx if first_script_idx < 0 else min(first_script_idx, idx)
        if first_script_idx >= 0 and (banner_idx < 0 or first_script_idx < banner_idx):
            self.consent["scripts_before_banner"] = True
        if self.consent["banner"] and self.consent["granular"] and self.consent["accept_button"]:
            self.consent["posture"] = "opt-in with granular controls"
        elif self.consent["banner"] and self.consent["accept_button"]:
            self.consent["posture"] = "opt-in (accept-all only)"
        elif self.consent["banner"]:
            self.consent["posture"] = "consent banner detected"
        elif self.consent["opt_out"]:
            self.consent["posture"] = "opt-out only"
        else:
            self.consent["posture"] = "none detected"

    def detect_consent_tool(self):
        lower = self.html.lower()
        for name, tokens in CONSENT_TOOLS.items():
            for token in tokens:
                if token.lower() in lower:
                    self.consent["tool"] = name
                    return
        self.consent["tool"] = None

    def fetch_related(self):
        if self.links["privacy"]:
            try:
                resp = self.fetch(self.links["privacy"])
                if resp.status_code == 200:
                    self.privacy_html = resp.text or ""
            except requests.exceptions.RequestException as exc:
                self.log("privacy fetch failed: " + str(exc))
        if self.links["cookie_policy"]:
            try:
                resp = self.fetch(self.links["cookie_policy"])
                if resp.status_code == 200:
                    self.policy_html = resp.text or ""
            except requests.exceptions.RequestException as exc:
                self.log("cookie policy fetch failed: " + str(exc))

    def corpus(self):
        return (self.html + " " + self.privacy_html + " " + self.policy_html).lower()

    def finding(self, label, status, earned, maximum, detail="", rec=""):
        return {
            "label": label,
            "status": status,
            "earned": round(float(earned), 1),
            "max": float(maximum),
            "detail": detail,
            "rec": rec,
        }

    def check_inventory(self):
        findings = []
        count = len(self.cookies)
        if count == 0:
            findings.append(self.finding("Cookie count analysis", "pass", 5, 5,
                                         "No cookies detected on initial response"))
        elif count <= 10:
            findings.append(self.finding("Cookie count analysis", "pass", 5, 5,
                                         str(count) + " cookies (lean)"))
        elif count <= 25:
            findings.append(self.finding("Cookie count analysis", "pass", 4, 5,
                                         str(count) + " cookies (acceptable)",
                                         "Trim non-essential cookies to stay under " + str(IDEAL_COOKIE_COUNT)))
        elif count <= 50:
            findings.append(self.finding("Cookie count analysis", "warn", 2, 5,
                                         str(count) + " cookies (high)",
                                         "Reduce cookie count below " + str(IDEAL_COOKIE_COUNT) +
                                         " by consolidating or removing redundant cookies"))
        else:
            findings.append(self.finding("Cookie count analysis", "fail", 0, 5,
                                         str(count) + " cookies (excessive)",
                                         "Audit and remove unnecessary cookies; count is far above " +
                                         str(IDEAL_COOKIE_COUNT)))
        if count == 0:
            findings.append(self.finding("First-party vs third-party split", "pass", 5, 5,
                                         "No third-party exposure"))
        else:
            fp_items = [c for c in self.cookies if c not in self.third_party]
            fp_sess = sum(1 for c in fp_items if c.is_session)
            fp_pers = len(fp_items) - fp_sess
            tp_sess = sum(1 for c in self.third_party if c.is_session)
            tp_pers = len(self.third_party) - tp_sess
            split_detail = ("1P: " + str(len(fp_items)) + " (" + str(fp_sess) + " session, " +
                            str(fp_pers) + " persistent); 3P: " + str(len(self.third_party)) +
                            " (" + str(tp_sess) + " session, " + str(tp_pers) + " persistent)")
            ratio = len(self.third_party) / float(count)
            if len(self.third_party) == 0:
                findings.append(self.finding("First-party vs third-party split", "pass", 5, 5,
                                             "100% first-party cookies; " + split_detail))
            elif ratio <= 0.25:
                findings.append(self.finding("First-party vs third-party split", "pass", 4, 5,
                                             str(len(self.third_party)) + " third-party of " +
                                             str(count) + "; " + split_detail))
            elif ratio <= 0.5:
                findings.append(self.finding("First-party vs third-party split", "warn", 2, 5,
                                             "Third-party ratio " + format(ratio * 100, ".0f") +
                                             "%; " + split_detail,
                                             "Reduce third-party cookies or self-host tracking endpoints"))
            else:
                findings.append(self.finding("First-party vs third-party split", "fail", 0, 5,
                                             "Third-party ratio " + format(ratio * 100, ".0f") +
                                             "%; " + split_detail,
                                             "Replace third-party tags with first-party or server-side alternatives"))
        if count == 0:
            findings.append(self.finding("Session vs persistent cookies", "pass", 3, 3,
                                         "No persistent state"))
        else:
            sessions = sum(1 for c in self.cookies if c.is_session)
            ratio = sessions / float(count)
            if ratio >= 0.5:
                findings.append(self.finding("Session vs persistent cookies", "pass", 3, 3,
                                             str(sessions) + "/" + str(count) + " session cookies"))
            elif ratio >= 0.2:
                findings.append(self.finding("Session vs persistent cookies", "warn", 2, 3,
                                             str(sessions) + "/" + str(count) + " session cookies",
                                             "Prefer session cookies where long persistence is not required"))
            elif sessions > 0:
                findings.append(self.finding("Session vs persistent cookies", "warn", 1, 3,
                                             "Only " + str(sessions) + "/" + str(count) + " session cookies",
                                             "Convert short-lived state to session cookies"))
            else:
                findings.append(self.finding("Session vs persistent cookies", "fail", 0, 3,
                                             "All cookies are persistent",
                                             "Use session cookies for transient state"))
        first_party_items = [c for c in self.cookies if c not in self.third_party]
        if not first_party_items:
            findings.append(self.finding("Cookie domain scope", "pass", 2, 2,
                                         "No first-party domain scope issues"))
        else:
            broad = [c for c in first_party_items if c.domain and not self.domain_scope_ok(c.domain)]
            if not broad:
                findings.append(self.finding("Cookie domain scope", "pass", 2, 2,
                                             "Domains scoped to host or " + str(self.base)))
            elif len(broad) < len(first_party_items):
                findings.append(self.finding("Cookie domain scope", "warn", 1, 2,
                                             str(len(broad)) + " overly broad domain attribute(s)",
                                             "Restrict cookie Domain attribute to host or " + str(self.base)))
            else:
                findings.append(self.finding("Cookie domain scope", "fail", 0, 2,
                                             "All first-party cookies use broad domains",
                                             "Set host-only cookies (omit Domain) or scope to " + str(self.base)))
        return findings

    def check_security(self):
        findings = []
        header = list(self.header_cookies)
        if not self.cookies:
            for label, mx in (("Secure flag coverage", 3), ("HttpOnly flag coverage", 3),
                              ("SameSite attribute quality", 3), ("Cookie name prefixes", 2),
                              ("SameSite=None Secure enforcement", 2),
                              ("CHIPS / Partitioned cookies", 2)):
                findings.append(self.finding(label, "pass", mx, mx, "No cookies to harden"))
            return findings
        if header:
            secure_count = sum(1 for c in header if c.secure)
            ratio = secure_count / float(len(header))
            httponly_eligible = [c for c in header if not self.js_required(c)]
            if httponly_eligible:
                httponly_count = sum(1 for c in httponly_eligible if c.httponly)
                h_ratio = httponly_count / float(len(httponly_eligible))
            else:
                h_ratio = 1.0
            samesite_cookies = list(header)
        else:
            secure_count = sum(1 for c in self.script_cookies if c.secure)
            ratio = secure_count / float(len(self.script_cookies)) if self.script_cookies else 0.0
            h_ratio = 0.5
            samesite_cookies = list(self.script_cookies)
        if ratio >= 0.99:
            findings.append(self.finding("Secure flag coverage", "pass", 3, 3,
                                         "All evaluable cookies carry Secure"))
        elif ratio >= 0.7:
            findings.append(self.finding("Secure flag coverage", "warn", 2, 3,
                                         format(ratio * 100, ".0f") + "% of cookies have Secure",
                                         "Add the Secure attribute to every cookie"))
        elif ratio > 0:
            findings.append(self.finding("Secure flag coverage", "warn", 1, 3,
                                         format(ratio * 100, ".0f") + "% of cookies have Secure",
                                         "Add the Secure attribute to every cookie sent over HTTPS"))
        else:
            findings.append(self.finding("Secure flag coverage", "fail", 0, 3,
                                         "No cookies set the Secure attribute",
                                         "Set Secure on all cookies"))
        if h_ratio >= 0.99:
            findings.append(self.finding("HttpOnly flag coverage", "pass", 3, 3,
                                         "All eligible cookies are HttpOnly"))
        elif h_ratio >= 0.7:
            findings.append(self.finding("HttpOnly flag coverage", "warn", 2, 3,
                                         format(h_ratio * 100, ".0f") + "% HttpOnly coverage",
                                         "Mark authentication and session cookies HttpOnly"))
        elif h_ratio > 0:
            findings.append(self.finding("HttpOnly flag coverage", "warn", 1, 3,
                                         format(h_ratio * 100, ".0f") + "% HttpOnly coverage",
                                         "Set HttpOnly on all cookies not required by JavaScript"))
        else:
            findings.append(self.finding("HttpOnly flag coverage", "fail", 0, 3,
                                         "No HttpOnly cookies detected",
                                         "Set HttpOnly on session and authentication cookies"))
        if not samesite_cookies:
            findings.append(self.finding("SameSite attribute quality", "warn", 0, 3,
                                         "No SameSite values found",
                                         "Set SameSite=Lax or Strict on all cookies"))
        else:
            total = 0.0
            missing = 0
            for c in samesite_cookies:
                ss = (c.samesite or "").lower()
                if ss in ("strict", "lax"):
                    total += 1.0
                elif ss == "none":
                    total += 0.75 if c.secure else 0.0
                else:
                    missing += 1
            avg = total / float(len(samesite_cookies))
            if avg >= 0.99:
                findings.append(self.finding("SameSite attribute quality", "pass", 3, 3,
                                             "Strict/Lax SameSite on all cookies"))
            elif avg >= 0.6:
                findings.append(self.finding("SameSite attribute quality", "warn", 2, 3,
                                             "Average SameSite score " + format(avg * 100, ".0f") + "%",
                                             "Add SameSite=Lax to cookies missing the attribute"))
            elif avg > 0:
                findings.append(self.finding("SameSite attribute quality", "warn", 1, 3,
                                             "Average SameSite score " + format(avg * 100, ".0f") +
                                             "% (" + str(missing) + " missing)",
                                             "Set SameSite=Strict or Lax; SameSite=None requires Secure"))
            else:
                findings.append(self.finding("SameSite attribute quality", "fail", 0, 3,
                                             "SameSite missing or insecure None",
                                             "Set SameSite=Strict or Lax on all cookies"))
        prefixed = [c for c in self.cookies if c.name.startswith("__Host-") or c.name.startswith("__Secure-")]
        sensitive = [c for c in self.cookies
                     if any(t in c.name.lower() for t in SENSITIVE_TOKENS) and not c.name.startswith("__")]
        if prefixed:
            findings.append(self.finding("Cookie name prefixes", "pass", 2, 2,
                                         "Prefixes found: " + ", ".join(sorted({c.name.split("=")[0][:20] for c in prefixed})[:5])))
        elif sensitive:
            names = ", ".join(c.name for c in sensitive[:3])
            findings.append(self.finding("Cookie name prefixes", "fail", 1, 2,
                                         "Sensitive cookies without __Host-/__Secure-: " + names,
                                         "Rename sensitive cookies with the __Host- or __Secure- prefix"))
        else:
            findings.append(self.finding("Cookie name prefixes", "pass", 1, 2,
                                         "No sensitive cookies requiring a prefix"))
        none_cookies = [c for c in self.cookies if (c.samesite or "").lower() == "none"]
        if not none_cookies:
            findings.append(self.finding("SameSite=None Secure enforcement", "pass", 2, 2,
                                         "No SameSite=None cookies to enforce"))
        else:
            insecure_none = [c for c in none_cookies if not c.secure]
            if not insecure_none:
                findings.append(self.finding("SameSite=None Secure enforcement", "pass", 2, 2,
                                             str(len(none_cookies)) + " SameSite=None cookie(s), all Secure"))
            elif len(insecure_none) < len(none_cookies):
                findings.append(self.finding("SameSite=None Secure enforcement", "warn", 1, 2,
                                             str(len(insecure_none)) + " of " + str(len(none_cookies)) +
                                             " SameSite=None cookies lack Secure",
                                             "Add Secure to every SameSite=None cookie (required by browsers)"))
            else:
                findings.append(self.finding("SameSite=None Secure enforcement", "fail", 0, 2,
                                             "All SameSite=None cookies missing Secure (rejected by browsers)",
                                             "Set Secure on all SameSite=None cookies or drop SameSite=None"))
        partitioned_cookies = [c for c in self.cookies if getattr(c, "partitioned", False)]
        if partitioned_cookies:
            findings.append(self.finding("CHIPS / Partitioned cookies", "pass", 2, 2,
                                         str(len(partitioned_cookies)) + " Partitioned (CHIPS) cookie(s)"))
        elif prefixed:
            findings.append(self.finding("CHIPS / Partitioned cookies", "pass", 1, 2,
                                         "Name prefixes used (" + str(len(prefixed)) +
                                         "); no Partitioned/CHIPS attributes",
                                         "Consider Partitioned (CHIPS) for cross-site cookies"))
        else:
            findings.append(self.finding("CHIPS / Partitioned cookies", "warn", 0, 2,
                                         "No Partitioned (CHIPS) or __Host-/__Secure- usage",
                                         "Adopt CHIPS Partitioned cookies for cross-site state"))
        return findings

    def js_required(self, cookie):
        n = cookie.name.lower()
        return any(t in n for t in JS_REQUIRED_TOKENS)

    def check_privacy(self):
        findings = []
        count = len(self.cookies)
        if count == 0:
            findings.append(self.finding("Purpose classification coverage", "pass", 3, 3, "No cookies to classify"))
            findings.append(self.finding("Expiry / long-lived cookie analysis", "pass", 4, 4, "No persistent cookies"))
            findings.append(self.finding("PII detection in names/values", "pass", 4, 4, "No cookies present"))
            findings.append(self.finding("Tracking cookie detection", "pass", 2, 2, "No tracking cookies"))
            findings.append(self.finding("Long-lived cookies (>1 year)", "pass", 2, 2, "No cookies exceed one year"))
            return findings
        unknown = [c for c in self.cookies if getattr(c, "purpose", "unknown") == "unknown"]
        coverage = (count - len(unknown)) / float(count)
        if coverage >= 0.9:
            findings.append(self.finding("Purpose classification coverage", "pass", 3, 3,
                                         format(coverage * 100, ".0f") + "% of cookies classified"))
        elif coverage >= 0.6:
            findings.append(self.finding("Purpose classification coverage", "warn", 2, 3,
                                         format(coverage * 100, ".0f") + "% classified, " +
                                         str(len(unknown)) + " unknown",
                                         "Rename or document cookies with ambiguous names"))
        else:
            findings.append(self.finding("Purpose classification coverage", "fail", 0, 3,
                                         "Only " + format(coverage * 100, ".0f") + "% classified",
                                         "Use descriptive cookie names that reveal purpose"))
        persistent = [c for c in self.cookies if not c.is_session and c.days_left is not None]
        if not persistent:
            findings.append(self.finding("Expiry / long-lived cookie analysis", "pass", 4, 4,
                                         "All cookies are session-based"))
        else:
            max_days = max(c.days_left for c in persistent)
            if max_days <= 90:
                findings.append(self.finding("Expiry / long-lived cookie analysis", "pass", 4, 4,
                                             "Longest lived cookie: " + str(max_days) + " days"))
            elif max_days <= 180:
                findings.append(self.finding("Expiry / long-lived cookie analysis", "pass", 3, 4,
                                             "Longest lived cookie: " + str(max_days) + " days"))
            elif max_days <= RECOMMENDED_EXPIRY_DAYS:
                findings.append(self.finding("Expiry / long-lived cookie analysis", "warn", 2, 4,
                                             "Longest lived cookie: " + str(max_days) + " days",
                                             "Cap cookie lifetimes at 6-12 months"))
            elif max_days <= MAX_EXPIRY_DAYS:
                findings.append(self.finding("Expiry / long-lived cookie analysis", "warn", 1, 4,
                                             "Longest lived cookie: " + str(max_days) + " days (browser cap zone)",
                                             "Reduce lifetimes below " + str(RECOMMENDED_EXPIRY_DAYS) + " days"))
            else:
                findings.append(self.finding("Expiry / long-lived cookie analysis", "fail", 0, 4,
                                             "Cookie living " + str(max_days) + " days",
                                             "Do not set expiries beyond " + str(MAX_EXPIRY_DAYS) + " days"))
        pii_hits = []
        for c in self.cookies:
            for hit in detect_pii(c.name, c.value):
                pii_hits.append(c.name + " (" + hit + ")")
        if not pii_hits:
            findings.append(self.finding("PII detection in names/values", "pass", 4, 4,
                                         "No PII patterns detected"))
        elif len(pii_hits) == 1:
            findings.append(self.finding("PII detection in names/values", "warn", 2, 4,
                                         "Possible PII: " + truncate(pii_hits[0], 60),
                                         "Do not store personal data in cookies; use server-side identifiers"))
        else:
            findings.append(self.finding("PII detection in names/values", "fail", 0, 4,
                                         str(len(pii_hits)) + " possible PII cookies",
                                         "Remove personal data from cookie names and values"))
        trackers = [c.name for c in self.tracker_cookies]
        if not trackers:
            findings.append(self.finding("Tracking cookie detection", "pass", 2, 2,
                                         "No known tracking cookies"))
        elif len(trackers) <= 2:
            findings.append(self.finding("Tracking cookie detection", "warn", 1, 2,
                                         "Trackers: " + ", ".join(trackers[:5]),
                                         "Gate tracking cookies behind explicit consent"))
        else:
            findings.append(self.finding("Tracking cookie detection", "fail", 0, 2,
                                         str(len(trackers)) + " tracking cookies detected",
                                         "Consolidate trackers and load them only after consent"))
        long_live = [c for c in self.cookies
                     if not c.is_session and c.days_left is not None and c.days_left > 365]
        long_trackers = [c for c in long_live if self.is_tracker_cookie(c)]
        if not long_live:
            findings.append(self.finding("Long-lived cookies (>1 year)", "pass", 2, 2,
                                         "No cookies exceed one year"))
        elif long_trackers:
            names = ", ".join(c.name for c in long_trackers[:3])
            findings.append(self.finding("Long-lived cookies (>1 year)", "fail", 0, 2,
                                         str(len(long_trackers)) + " tracker(s) >1 year: " + names,
                                         "Cap tracking cookie lifetimes at one year or less"))
        else:
            max_days = max(c.days_left for c in long_live)
            findings.append(self.finding("Long-lived cookies (>1 year)", "warn", 1, 2,
                                         str(len(long_live)) + " cookie(s) >1 year (max " +
                                         str(max_days) + " days)",
                                         "Reduce lifetimes to 12 months or less"))
        return findings

    def check_consent(self):
        findings = []
        consent = self.consent
        lower_html = self.html.lower()
        signal_hits = []
        for probe in ("onetrust", "cookiebot", "osano", "didomi", "cookieyes", "cookie consent"):
            if probe in lower_html:
                signal_hits.append(probe)
        if consent["banner"]:
            detail = "Consent banner/notice detected"
            if signal_hits:
                detail += " (signals: " + ", ".join(signal_hits[:5]) + ")"
            findings.append(self.finding("Cookie consent banner detection", "pass", 4, 4, detail))
        else:
            findings.append(self.finding("Cookie consent banner detection", "fail", 0, 4,
                                         "No cookie consent banner found" +
                                         (" (partial signals: " + ", ".join(signal_hits[:5]) + ")"
                                          if signal_hits else ""),
                                         "Deploy a cookie consent banner before setting non-essential cookies"))
        if consent["tool"]:
            findings.append(self.finding("Consent management tool identification", "pass", 4, 4,
                                         "Tool: " + consent["tool"]))
        elif consent["banner"]:
            findings.append(self.finding("Consent management tool identification", "warn", 2, 4,
                                         "Generic/custom banner (no known CMP)",
                                         "Adopt a certified CMP for auditable consent records"))
        else:
            findings.append(self.finding("Consent management tool identification", "fail", 0, 4,
                                         "No CMP detected",
                                         "Integrate a consent management platform"))
        if not consent["nonessential"]:
            findings.append(self.finding("Consent-before-set detection", "pass", 4, 4,
                                         "Only necessary cookies set before consent"))
        elif consent["consent_cookie"] and consent["banner"]:
            findings.append(self.finding("Consent-before-set detection", "warn", 2, 4,
                                         "Non-essential cookies present with a stored consent signal",
                                         "Verify non-essential cookies are withheld until fresh consent is given"))
        else:
            detail = "Non-essential cookies present before consent"
            if consent["scripts_before_banner"]:
                detail += "; tracking scripts load before banner"
            findings.append(self.finding("Consent-before-set detection", "fail", 0, 4,
                                         detail,
                                         "Block non-essential cookies and tags until the user opts in"))
        posture = consent["posture"]
        if consent["granular"] and consent["accept_button"]:
            findings.append(self.finding("Opt-in vs opt-out mode", "pass", 3, 3,
                                         "Opt-in model with granular controls (" + posture + ")"))
        elif consent["accept_button"]:
            findings.append(self.finding("Opt-in vs opt-out mode", "warn", 2, 3,
                                         "Opt-in accept-all without granular choice (" + posture + ")",
                                         "Add granular category toggles (analytics, marketing)"))
        elif consent["opt_out"]:
            findings.append(self.finding("Opt-in vs opt-out mode", "warn", 1, 3,
                                         "Opt-out mechanism only (" + posture + ")",
                                         "Move to opt-in consent for GDPR/CCPA applicability"))
        else:
            findings.append(self.finding("Opt-in vs opt-out mode", "fail", 0, 3,
                                         "No opt-in or opt-out controls detected",
                                         "Provide clear accept/reject controls in a consent banner"))
        return findings

    def check_gdpr(self):
        findings = []
        text = self.corpus()
        if self.links["privacy"]:
            findings.append(self.finding("Privacy policy link presence", "pass", 3, 3,
                                         "Link: " + truncate(self.links["privacy"], 70)))
        else:
            findings.append(self.finding("Privacy policy link presence", "fail", 0, 3,
                                         "No privacy policy link in footer/header",
                                         "Add a clearly linked privacy policy"))
        if self.links["cookie_policy"]:
            findings.append(self.finding("Cookie policy link presence", "pass", 3, 3,
                                         "Link: " + truncate(self.links["cookie_policy"], 70)))
        else:
            findings.append(self.finding("Cookie policy link presence", "fail", 0, 3,
                                         "No cookie policy link found",
                                         "Publish and link a dedicated cookie policy"))
        processing_markers = ["legal basis", "legitimate interest", "data controller",
                              "data processor", "personal data", "processing of",
                              "purposes of the processing", "lawful basis"]
        found_markers = [m for m in processing_markers if m in text]
        if len(found_markers) >= 3:
            findings.append(self.finding("Data processing information", "pass", 2, 2,
                                         "Details found: " + ", ".join(found_markers[:3])))
        elif found_markers:
            findings.append(self.finding("Data processing information", "warn", 1, 2,
                                         "Partial disclosure: " + ", ".join(found_markers[:3]),
                                         "Document lawful basis, controller and processors in the privacy policy"))
        else:
            findings.append(self.finding("Data processing information", "fail", 0, 2,
                                         "No data processing information found",
                                         "Describe lawful basis and processing purposes in the privacy policy"))
        withdraw_markers = ["withdraw consent", "withdraw your consent", "revoke consent",
                            "change your cookie preferences", "object to processing",
                            "right to object", "change consent", "edit consent"]
        found_withdraw = [m for m in withdraw_markers if m in text]
        if self.links["cookie_settings"] or found_withdraw:
            detail = "Withdrawal path available"
            if found_withdraw:
                detail += ": " + found_withdraw[0]
            findings.append(self.finding("Right to withdraw consent", "pass", 2, 2, detail))
        else:
            findings.append(self.finding("Right to withdraw consent", "fail", 0, 2,
                                         "No withdrawal-of-consent mechanism found",
                                         "Offer a persistent link to change or withdraw cookie consent"))
        return findings

    def check_ccpa(self):
        findings = []
        text = self.corpus()
        if self.links["do_not_sell"]:
            findings.append(self.finding("Do Not Sell My Personal Information link", "pass", 2, 2,
                                         "Link: " + truncate(self.links["do_not_sell"], 70)))
        elif re.search(r"do not sell my personal information", text):
            findings.append(self.finding("Do Not Sell My Personal Information link", "pass", 2, 2,
                                         "Phrase present on page"))
        else:
            findings.append(self.finding("Do Not Sell My Personal Information link", "fail", 0, 2,
                                         "No Do Not Sell link detected",
                                         "Add a Do Not Sell or Share My Personal Information link"))
        california = "california" in text and any(t in text for t in ("resident", "consumer", "ccpa", "cpra"))
        if california:
            findings.append(self.finding("California resident rights disclosure", "pass", 2, 2,
                                         "California rights language found"))
        else:
            findings.append(self.finding("California resident rights disclosure", "fail", 0, 2,
                                         "No California resident rights language",
                                         "Disclose California consumer rights (know, delete, opt-out)"))
        opt_out = bool(self.links["do_not_sell"]) or any(
            t in text for t in ("opt out of the sale", "opt-out of the sale", "global privacy control",
                                "opt out of sharing", "do not share", "opt-out mechanism")
        ) or self.consent["opt_out"]
        if opt_out:
            findings.append(self.finding("Opt-out mechanism", "pass", 1, 1,
                                         "Sale/share opt-out mechanism available"))
        else:
            findings.append(self.finding("Opt-out mechanism", "fail", 0, 1,
                                         "No sale/share opt-out found",
                                         "Provide an opt-out for sale/share of personal information"))
        return findings

    def check_categories(self):
        findings = []
        corpus = self.corpus()
        for label, patterns, purpose in CAT_DEFS:
            of_purpose = [c for c in self.cookies if getattr(c, "purpose", "") == purpose]
            mentioned = any(p in corpus for p in patterns)
            if not of_purpose:
                findings.append(self.finding(label + " cookies", "pass", 2, 2,
                                             "None in use and category recognized" if mentioned
                                             else "No " + label.lower() + " cookies detected"))
            elif mentioned:
                findings.append(self.finding(label + " cookies", "pass", 2, 2,
                                             str(len(of_purpose)) + " cookie(s), category disclosed"))
            else:
                findings.append(self.finding(label + " cookies", "fail", 0, 2,
                                             str(len(of_purpose)) + " cookie(s) but category never disclosed",
                                             "List '" + label + "' cookies in the cookie policy and CMP"))
        return findings

    def check_thirdparty(self):
        findings = []
        count3 = len(self.third_party)
        if count3 == 0:
            findings.append(self.finding("Third-party cookie count", "pass", 5, 5,
                                         "Zero third-party cookies"))
        elif count3 <= 2:
            findings.append(self.finding("Third-party cookie count", "pass", 4, 5,
                                         str(count3) + " third-party cookie(s)"))
        elif count3 <= 5:
            findings.append(self.finding("Third-party cookie count", "warn", 2, 5,
                                         str(count3) + " third-party cookies",
                                         "Migrate third-party tags to first-party storage"))
        elif count3 <= 10:
            findings.append(self.finding("Third-party cookie count", "warn", 1, 5,
                                         str(count3) + " third-party cookies",
                                         "Reduce third-party dependencies significantly"))
        else:
            findings.append(self.finding("Third-party cookie count", "fail", 0, 5,
                                         str(count3) + " third-party cookies (heavy)",
                                         "Remove or consolidate third-party tags"))
        domains3 = sorted({(c.domain or "host-only").lstrip(".").lower() for c in self.third_party})
        if not domains3:
            findings.append(self.finding("Third-party domain analysis", "pass", 3, 3,
                                         "No third-party domains involved"))
        elif len(domains3) <= 2:
            findings.append(self.finding("Third-party domain analysis", "pass", 2, 3,
                                         "Domains: " + ", ".join(domains3[:4])))
        elif len(domains3) <= 5:
            findings.append(self.finding("Third-party domain analysis", "warn", 1, 3,
                                         str(len(domains3)) + " third-party domains: " + ", ".join(domains3[:4]),
                                         "Limit third-party domains to essential vendors"))
        else:
            findings.append(self.finding("Third-party domain analysis", "fail", 0, 3,
                                         str(len(domains3)) + " distinct third-party domains",
                                         "Cut the number of external vendors setting cookies"))
        trackers = [c.name for c in self.tracker_cookies]
        if not trackers:
            findings.append(self.finding("Cross-site tracking detection", "pass", 2, 2,
                                         "No cross-site tracking signatures"))
        elif len(trackers) <= 2:
            findings.append(self.finding("Cross-site tracking detection", "warn", 1, 2,
                                         "Light tracking: " + ", ".join(trackers[:4]),
                                         "Restrict cross-site trackers to consented visitors"))
        else:
            findings.append(self.finding("Cross-site tracking detection", "fail", 0, 2,
                                         str(len(trackers)) + " cross-site tracking cookies",
                                         "Disable advertising pixels until explicit consent"))
        return findings

    def check_policy(self):
        findings = []
        if self.links["cookie_policy"]:
            findings.append(self.finding("Cookie policy page detection", "pass", 2, 2,
                                         "Page: " + truncate(self.links["cookie_policy"], 70)))
        elif "cookie policy" in self.html.lower() or "cookies policy" in self.html.lower():
            findings.append(self.finding("Cookie policy page detection", "warn", 1, 2,
                                         "Mentioned in content but no dedicated page link",
                                         "Publish a dedicated cookie policy page"))
        else:
            findings.append(self.finding("Cookie policy page detection", "fail", 0, 2,
                                         "No cookie policy page found",
                                         "Create a cookie policy listing all cookies and purposes"))
        policy_text = (self.policy_html or self.html).lower()
        content_hits = []
        for words in (("necessary", "essential"), ("analytics", "statistic"),
                      ("advertising", "marketing"), ("functional", "preference"),
                      ("consent", "rights")):
            if any(w in policy_text for w in words):
                content_hits.append(words[0])
        if self.policy_html and len(content_hits) >= 4:
            findings.append(self.finding("Cookie policy content analysis", "pass", 2, 2,
                                         "Covers: " + ", ".join(content_hits)))
        elif len(content_hits) >= 3:
            findings.append(self.finding("Cookie policy content analysis", "warn", 1, 2,
                                         "Partial coverage: " + ", ".join(content_hits),
                                         "Describe each cookie category, purpose, duration and rights"))
        else:
            findings.append(self.finding("Cookie policy content analysis", "fail", 0, 2,
                                         "Insufficient cookie policy detail",
                                         "Document categories, purposes, durations and user rights"))
        date_pattern = (r"(last\s+(?:updated|revised|modified)\s*[:\-]?\s*"
                        r"(\d{1,2}\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{4}|"
                        r"\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4}))|"
                        r"(updated\s+on\s+[^<]{0,40}\d{4})|"
                        r"(effective\s+(?:date|as of)\s*[:\-]?\s*[^<]{0,40}\d{4})")
        match = re.search(date_pattern, policy_text)
        if match:
            snippet = re.sub(r"\s+", " ", match.group(0)).strip()
            findings.append(self.finding("Last updated date", "pass", 1, 1, "Found: " + truncate(snippet, 60)))
        else:
            findings.append(self.finding("Last updated date", "fail", 0, 1,
                                         "No last-updated date on cookie policy",
                                         "Add a visible last-updated date to the cookie policy"))
        return findings

    def check_technical(self):
        findings = []
        if not self.cookies:
            findings.append(self.finding("Cookie size analysis", "pass", 2, 2, "No cookies stored"))
            findings.append(self.finding("Cookie count optimization", "pass", 2, 2, "Zero cookie overhead"))
            findings.append(self.finding("Cookie expiration optimization", "pass", 1, 1, "No expiries to optimize"))
            return findings
        sizes = [c.size for c in self.cookies]
        total = sum(sizes)
        biggest = max(sizes)
        if biggest <= 512 and total <= IDEAL_COOKIE_BYTES:
            findings.append(self.finding("Cookie size analysis", "pass", 2, 2,
                                         "Total " + str(total) + " bytes, largest " + str(biggest) + " bytes"))
        elif total <= IDEAL_COOKIE_BYTES * 2:
            findings.append(self.finding("Cookie size analysis", "warn", 1, 2,
                                         "Total " + str(total) + " bytes, largest " + str(biggest) + " bytes",
                                         "Keep each cookie small and total request cookie payload under " +
                                         str(IDEAL_COOKIE_BYTES) + " bytes"))
        else:
            findings.append(self.finding("Cookie size analysis", "fail", 0, 2,
                                         "Cookie payload " + str(total) + " bytes exceeds practical limits",
                                         "Trim cookie values; move bulk data server-side"))
        count = len(self.cookies)
        if count <= IDEAL_COOKIE_COUNT:
            findings.append(self.finding("Cookie count optimization", "pass", 2, 2,
                                         str(count) + " cookies (<= " + str(IDEAL_COOKIE_COUNT) + ")"))
        elif count <= IDEAL_COOKIE_COUNT * 2:
            findings.append(self.finding("Cookie count optimization", "warn", 1, 2,
                                         str(count) + " cookies",
                                         "Reduce to " + str(IDEAL_COOKIE_COUNT) + " or fewer cookies"))
        else:
            findings.append(self.finding("Cookie count optimization", "fail", 0, 2,
                                         str(count) + " cookies (too many)",
                                         "Aggressively consolidate and delete unused cookies"))
        persistent = [c for c in self.cookies if not c.is_session and c.days_left is not None]
        if not persistent:
            findings.append(self.finding("Cookie expiration optimization", "pass", 1, 1,
                                         "Session-only cookies"))
        else:
            max_days = max(c.days_left for c in persistent)
            if max_days <= MAX_EXPIRY_DAYS:
                findings.append(self.finding("Cookie expiration optimization", "pass", 1, 1,
                                             "Max lifetime " + str(max_days) + " days"))
            else:
                findings.append(self.finding("Cookie expiration optimization", "fail", 0, 1,
                                             "Max lifetime " + str(max_days) + " days",
                                             "Cap cookie expiry at " + str(MAX_EXPIRY_DAYS) + " days"))
        return findings

    def run_checks(self):
        check_map = [
            ("inventory", "Cookie Inventory", 15, self.check_inventory),
            ("security", "Cookie Security", 15, self.check_security),
            ("privacy", "Cookie Privacy", 15, self.check_privacy),
            ("consent", "Consent Management", 15, self.check_consent),
            ("gdpr", "GDPR Compliance", 10, self.check_gdpr),
            ("ccpa", "CCPA Compliance", 5, self.check_ccpa),
            ("categories", "Cookie Categories", 10, self.check_categories),
            ("thirdparty", "Third-Party Cookies", 10, self.check_thirdparty),
            ("policy", "Cookie Policy", 5, self.check_policy),
            ("technical", "Technical Quality", 5, self.check_technical),
        ]
        self.results = []
        for key, title, max_points, fn in check_map:
            findings = fn()
            earned = sum(f["earned"] for f in findings)
            earned = min(earned, float(max_points))
            self.results.append({
                "key": key,
                "title": title,
                "max": max_points,
                "score": round(earned, 1),
                "findings": findings,
            })
            for f in findings:
                if f["status"] in ("warn", "fail") and f["rec"]:
                    if f["rec"] not in self.recommendations:
                        self.recommendations.append(f["rec"])
        if len(self.cookies) > IDEAL_COOKIE_COUNT:
            rec = "Reduce total cookies from " + str(len(self.cookies)) + " to " + str(IDEAL_COOKIE_COUNT) + " or fewer"
            if rec not in self.recommendations:
                self.recommendations.append(rec)

    def raw_score(self):
        return sum(r["score"] for r in self.results)

    def scale_max(self):
        total = sum(r["max"] for r in self.results)
        return total if total else 100

    def total_score(self):
        return int(round(self.raw_score() * 100.0 / self.scale_max()))

    def max_score(self):
        return 100

    def grade(self):
        return grade_for(self.total_score())

    def run(self):
        print(self.c.bold(self.c.bright_blue("[*] Analyzing: ")) + self.url)
        resp = self.fetch(self.url)
        self.response = resp
        self.final_url = resp.url
        parsed_final = urlparse(self.final_url)
        if parsed_final.hostname:
            self.page_host = parsed_final.hostname
            self.base = base_domain(self.page_host)
        self.html = resp.text or ""
        self.soup = BeautifulSoup(self.html, "html.parser")
        if resp.status_code >= 400:
            print(self.c.yellow("    [!] HTTP " + str(resp.status_code) + " returned; analyzing what was received"))
        self.collect_cookies(resp)
        self.collect_script_cookies()
        self.detect_links()
        self.detect_consent()
        self.detect_consent_tool()
        self.fetch_related()
        self.derive()
        print(self.c.bold(self.c.bright_blue("[+] ")) +
              str(len(self.cookies)) + " cookie(s) collected, " +
              str(len(self.third_party)) + " third-party, " +
              str(len(self.tracker_cookies)) + " tracker(s), CMP: " +
              (self.consent["tool"] or "none"))
        self.run_checks()

    def score_bar(self, earned, maximum, width=16):
        if maximum <= 0:
            return ""
        ratio = earned / float(maximum)
        filled = int(round(ratio * width))
        filled = max(0, min(width, filled))
        empty = width - filled
        block = "█" * filled + "░" * empty
        if ratio >= 0.8:
            return self.c.bright_green(block)
        if ratio >= 0.5:
            return self.c.bright_yellow(block)
        return self.c.bright_red(block)

    def display(self):
        c = self.c
        print()
        print(c.bold(c.bright_cyan("  COOKIE INVENTORY")))
        print(c.dim("  " + "-" * 96))
        header = "  {:<22} {:<4} {:<9} {:<4} {:<5} {:<8} {:<12} {:<8} {:>5}".format(
            "NAME", "TYPE", "LIFETIME", "SEC", "HTTP", "SAMESITE", "PURPOSE", "DAYS", "SIZE")
        print(c.bold(header))
        print(c.dim("  " + "-" * 96))
        for cookie in self.cookies:
            if cookie in self.third_party:
                ctype = "3P"
            else:
                ctype = "1P"
            lifetime = "session" if cookie.is_session else "persist"
            sec = "?" if cookie.source == "script" and not cookie.secure else ("Y" if cookie.secure else "N")
            http = "?" if cookie.source == "script" else ("Y" if cookie.httponly else "N")
            if cookie.source == "script" and not cookie.secure:
                sec = "N"
            samesite = cookie.samesite or "-"
            purpose = getattr(cookie, "purpose", "unknown")
            days = "session" if cookie.is_session else str(cookie.days_left)
            row = "  {:<22} {:<4} {:<9} {:<4} {:<5} {:<8} {:<12} {:<8} {:>5}".format(
                truncate(cookie.name, 22), ctype, lifetime, sec, http,
                truncate(samesite, 8), truncate(purpose, 12), days, cookie.size)
            if purpose == "unknown":
                painted = c.bright_yellow(row)
            elif ctype == "3P":
                painted = c.bright_red(row)
            elif purpose == "marketing":
                painted = c.bright_magenta(row)
            else:
                painted = row
            print(painted)
        print()

        print(c.bold(c.bright_cyan("  CATEGORY BREAKDOWN")))
        print(c.dim("  " + "=" * 96))
        for idx, result in enumerate(self.results, 1):
            label = "  [{:02d}] {}".format(idx, result["title"])
            pad = 52 - len(result["title"]) - 6
            if pad < 2:
                pad = 2
            line = label + " " + ("." * pad) + " " + "{:>5}/{:<3}".format(
                ("%g" % result["score"]), result["max"])
            print(c.bold(line))
            print("      " + self.score_bar(result["score"], result["max"]) + "  " +
                  c.dim("%g/%d" % (result["score"], result["max"])))
            for f in result["findings"]:
                status = c.status(f["status"])
                points = "(%g/%g)" % (f["earned"], f["max"])
                print("      " + status + " " + f["label"] + " " + c.dim(points))
                if f["detail"]:
                    print("           " + c.dim(f["detail"]))
            print()

        print(c.bold(c.bright_cyan("  PRIVACY COMPLIANCE ASSESSMENT")))
        print(c.dim("  " + "-" * 96))
        by_key = {r["key"]: r for r in self.results}

        def ratio_line(key):
            r = by_key[key]
            return r["score"], r["max"]

        gdpr_s, gdpr_m = ratio_line("gdpr")
        ccpa_s, ccpa_m = ratio_line("ccpa")
        consent_s, consent_m = ratio_line("consent")
        third_s, third_m = ratio_line("thirdparty")

        def verdict(score, maximum):
            ratio = score / float(maximum) if maximum else 0
            if ratio >= 0.8:
                return c.bright_green("strong")
            if ratio >= 0.5:
                return c.bright_yellow("moderate")
            return c.bright_red("weak")

        print("  GDPR readiness ............. " + verdict(gdpr_s, gdpr_m) +
              c.dim("  (%g/%g)" % (gdpr_s, gdpr_m)))
        print("  CCPA readiness ............. " + verdict(ccpa_s, ccpa_m) +
              c.dim("  (%g/%g)" % (ccpa_s, ccpa_m)))
        print("  Consent posture ............ " + c.bold(self.consent["posture"]))
        if self.consent["tool"]:
            print("  Consent platform ........... " + c.cyan(self.consent["tool"]))
        else:
            print("  Consent platform ........... " + c.yellow("not identified"))
        if not self.tracker_cookies:
            tracking = c.bright_green("none detected")
        elif len(self.tracker_cookies) <= 3:
            tracking = c.bright_yellow("limited (" + str(len(self.tracker_cookies)) + " trackers)")
        else:
            tracking = c.bright_red("heavy (" + str(len(self.tracker_cookies)) + " trackers)")
        print("  Tracking exposure .......... " + tracking)
        third_verdict = verdict(third_s, third_m)
        print("  Third-party risk ........... " + third_verdict + c.dim("  (%g/%g)" % (third_s, third_m)))
        purposes = {}
        for cookie in self.cookies:
            p = getattr(cookie, "purpose", "unknown")
            purposes[p] = purposes.get(p, 0) + 1
        if purposes:
            breakdown = ", ".join(k + ":" + str(v) for k, v in sorted(purposes.items()))
            print("  Purpose mix ................ " + c.dim(breakdown))
        print()

        total = self.total_score()
        maximum = self.max_score()
        grade = self.grade()
        print(c.bold(c.bright_cyan("  SCORE SUMMARY")))
        print(c.dim("  " + "-" * 96))
        score_line = "  Total Score: " + str(total) + "/" + str(maximum)
        print(score_line + "    Grade: " + c.bold(c.grade(grade)) + "  " +
              self.score_bar(total, maximum, 24))
        grade_scale = "  A+ 95-100 | A 90-94 | B 75-89 | C 60-74 | D 40-59 | F 0-39"
        print(c.dim(grade_scale))
        print()

        print(c.bold(c.bright_cyan("  RECOMMENDATIONS")))
        print(c.dim("  " + "-" * 96))
        if not self.recommendations:
            print(c.bright_green("  No critical issues found. Maintain current cookie hygiene."))
        else:
            for i, rec in enumerate(self.recommendations, 1):
                print("  " + c.bright_yellow(str(i) + ".") + " " + rec)
        print()

    def export(self, fmt):
        if fmt == "none":
            return []
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        formats = ["json", "csv", "html"] if fmt == "all" else [fmt]
        written = []
        payload = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "url": self.url,
            "final_url": self.final_url,
            "timestamp": self.started.isoformat(),
            "analyzed_at": datetime.now().isoformat(),
            "total_score": self.total_score(),
            "max_score": self.max_score(),
            "grade": self.grade(),
            "consent": self.consent,
            "links": self.links,
            "categories": self.results,
            "cookies": [c.to_dict() for c in self.cookies],
            "recommendations": self.recommendations,
        }
        if "json" in formats:
            path = os.path.join(os.getcwd(), "cookieanalyzer_report_" + stamp + ".json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, default=str)
            written.append(path)
        if "csv" in formats:
            path = os.path.join(os.getcwd(), "cookieanalyzer_report_" + stamp + ".csv")
            with open(path, "w", encoding="utf-8", newline="") as fh:
                writer = csv.writer(fh)
                writer.writerow(["section", "key", "field", "value", "detail"])
                writer.writerow(["meta", "url", "target", self.final_url, ""])
                writer.writerow(["meta", "score", "total", str(self.total_score()),
                                 str(self.max_score())])
                writer.writerow(["meta", "score_raw", "raw", "%g" % self.raw_score(),
                                 str(self.scale_max())])
                writer.writerow(["meta", "grade", "grade", self.grade(), ""])
                writer.writerow(["meta", "consent", "posture", self.consent["posture"],
                                 self.consent["tool"] or ""])
                for link_key, link_val in self.links.items():
                    writer.writerow(["link", link_key, "url", link_val or "", ""])
                for result in self.results:
                    writer.writerow(["category", result["key"], "score",
                                     "%g/%d" % (result["score"], result["max"]), result["title"]])
                    for f in result["findings"]:
                        writer.writerow(["finding", result["key"], f["status"],
                                         "%g/%g" % (f["earned"], f["max"]),
                                         f["label"] + " - " + (f["detail"] or "")])
                for cookie in self.cookies:
                    ctype = "third-party" if cookie in self.third_party else "first-party"
                    writer.writerow([
                        "cookie",
                        cookie.name,
                        getattr(cookie, "purpose", "unknown"),
                        cookie.value[:80],
                        "; ".join([
                            ctype,
                            "session" if cookie.is_session else "persistent",
                            "secure" if cookie.secure else "insecure",
                            "httponly" if cookie.httponly else "not-httponly",
                            "samesite=" + (cookie.samesite or "unset"),
                            "domain=" + (cookie.domain or "host-only"),
                            "size=" + str(cookie.size),
                        ]),
                    ])
                for i, rec in enumerate(self.recommendations, 1):
                    writer.writerow(["recommendation", str(i), "action", rec, ""])
            written.append(path)
        if "html" in formats:
            path = os.path.join(os.getcwd(), "cookieanalyzer_report_" + stamp + ".html")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.render_html(payload))
            written.append(path)
        return written

    def render_html(self, payload):
        css = """
body{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',Helvetica,Arial,sans-serif;margin:0;padding:40px 20px;line-height:1.5}
.wrap{max-width:1080px;margin:0 auto}
h1{font-size:1.6rem;margin:0 0 4px;color:#58a6ff;font-weight:600}
h2{font-size:1.1rem;margin:34px 0 12px;color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:8px}
.sub{color:#8b949e;font-size:.9rem;margin-bottom:24px}
.scorebox{background:#161b22;border:1px solid #30363d;border-left:4px solid #58a6ff;padding:18px 22px;border-radius:6px;display:flex;gap:28px;align-items:center;flex-wrap:wrap}
.big{font-size:2.6rem;font-weight:700}
.grade{font-size:1.6rem;font-weight:700;padding:4px 14px;border-radius:6px;background:#238636;color:#fff}
.grade.b{background:#1f6feb}.grade.c{background:#9e6a03}.grade.d{background:#8957e5}.grade.f{background:#da3633}
table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:6px;overflow:hidden;font-size:.88rem}
th{background:#21262d;text-align:left;padding:10px 12px;color:#79c0ff;font-weight:600}
td{padding:9px 12px;border-top:1px solid #21262d;vertical-align:top}
tr:nth-child(even) td{background:#0d1117}
.bar{background:#30363d;height:10px;border-radius:5px;overflow:hidden;min-width:120px}
.bar>i{display:block;height:100%;background:#3fb950}
.bar.mid>i{background:#d29922}.bar.low>i{background:#f85149}
.status{font-weight:700;font-size:.75rem;padding:2px 7px;border-radius:4px}
.pass{background:#238636;color:#fff}.warn{background:#9e6a03;color:#fff}.fail{background:#da3633;color:#fff}.info{background:#1f6feb;color:#fff}
ul.recs{list-style:none;padding:0}
ul.recs li{background:#161b22;border:1px solid #30363d;border-left:3px solid #d29922;margin-bottom:8px;padding:10px 14px;border-radius:4px}
.finding{margin:6px 0 6px 2px;font-size:.88rem}
.detail{color:#8b949e;margin-left:8px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.card{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:14px 16px}
.card .k{color:#8b949e;font-size:.78rem;text-transform:uppercase;letter-spacing:.04em}
.card .v{font-size:1.05rem;font-weight:600;color:#e6edf3;margin-top:4px}
a{color:#58a6ff}
footer{margin-top:40px;color:#484f58;font-size:.8rem;text-align:center}
"""
        esc = lambda s: (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))
        parts = []
        parts.append("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>")
        parts.append("<meta name='viewport' content='width=device-width,initial-scale=1'>")
        parts.append("<title>CookieAnalyzer Report</title>")
        parts.append("<style>" + css + "</style></head><body><div class='wrap'>")
        parts.append("<h1>CookieAnalyzer v" + VERSION + "</h1>")
        parts.append("<div class='sub'>Target: " + esc(payload["final_url"]) +
                     " &middot; Analyzed: " + esc(payload["analyzed_at"]) + "</div>")
        total = payload["total_score"]
        maximum = payload["max_score"]
        grade = payload["grade"]
        grade_cls = "a"
        if grade == "B":
            grade_cls = "b"
        elif grade == "C":
            grade_cls = "c"
        elif grade == "D":
            grade_cls = "d"
        elif grade == "F":
            grade_cls = "f"
        ratio = (total / float(maximum)) if maximum else 0
        bar_cls = "bar"
        if ratio < 0.6:
            bar_cls = "bar low"
        elif ratio < 0.8:
            bar_cls = "bar mid"
        parts.append("<div class='scorebox'><div class='big'>" + str(total) + "<span style='color:#8b949e;font-size:1.2rem'>/" + str(maximum) + "</span></div>")
        parts.append("<div class='grade " + grade_cls + "'>" + esc(grade) + "</div>")
        parts.append("<div style='flex:1;min-width:200px'><div class='" + bar_cls + "'><i style='width:" + format(ratio * 100, ".0f") + "%'></i></div>")
        parts.append("<div style='color:#8b949e;font-size:.8rem;margin-top:6px'>A+ 95-100 &middot; A 90-94 &middot; B 75-89 &middot; C 60-74 &middot; D 40-59 &middot; F 0-39</div></div></div>")
        consent = payload["consent"]
        parts.append("<div class='grid' style='margin-top:18px'>")
        parts.append("<div class='card'><div class='k'>Consent posture</div><div class='v'>" + esc(consent.get("posture")) + "</div></div>")
        parts.append("<div class='card'><div class='k'>Consent platform</div><div class='v'>" + esc(consent.get("tool") or "Not identified") + "</div></div>")
        parts.append("<div class='card'><div class='k'>Cookies</div><div class='v'>" + str(len(payload["cookies"])) + "</div></div>")
        parts.append("<div class='card'><div class='k'>Recommendations</div><div class='v'>" + str(len(payload["recommendations"])) + "</div></div>")
        parts.append("</div>")
        parts.append("<h2>Category Breakdown</h2><table><tr><th>Category</th><th>Score</th><th>Coverage</th><th>Status</th></tr>")
        for result in payload["categories"]:
            rr = result["score"] / float(result["max"]) if result["max"] else 0
            cls = "bar"
            label = "good"
            if rr < 0.6:
                cls = "bar low"
                label = "needs work"
            elif rr < 0.8:
                cls = "bar mid"
                label = "fair"
            parts.append("<tr><td>" + esc(result["title"]) + "</td>")
            parts.append("<td>" + "%g" % result["score"] + "/" + str(result["max"]) + "</td>")
            parts.append("<td><div class='" + cls + "'><i style='width:" + format(rr * 100, ".0f") + "%'></i></div></td>")
            parts.append("<td>" + label + "</td></tr>")
        parts.append("</table>")
        parts.append("<h2>Findings</h2>")
        for result in payload["categories"]:
            parts.append("<div style='margin-bottom:14px'><strong style='color:#79c0ff'>" +
                         esc(result["title"]) + "</strong> <span style='color:#8b949e'>(%g/%d)</span><br>" %
                         (result["score"], result["max"]))
            for f in result["findings"]:
                parts.append("<div class='finding'><span class='status " + f["status"] + "'>" +
                             f["status"].upper() + "</span> " + esc(f["label"]))
                if f["detail"]:
                    parts.append(" <span class='detail'>" + esc(f["detail"]) + "</span>")
                parts.append("</div>")
            parts.append("</div>")
        parts.append("<h2>Cookie Inventory</h2><table><tr><th>Name</th><th>Type</th><th>Purpose</th><th>Lifetime</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Domain</th><th>Size</th></tr>")
        third_keys = {(c.name, c.domain) for c in self.third_party}
        for cookie in payload["cookies"]:
            ctype = "third-party" if (cookie["name"], cookie["domain"]) in third_keys else "first-party"
            parts.append("<tr><td>" + esc(cookie["name"]) + "</td><td>" + ctype + "</td>")
            parts.append("<td>" + esc(cookie.get("purpose", "unknown")) + "</td>")
            parts.append("<td>" + esc(cookie.get("lifetime", "")) + "</td>")
            parts.append("<td>" + ("yes" if cookie["secure"] else "no") + "</td>")
            parts.append("<td>" + ("yes" if cookie["httponly"] else "no") + "</td>")
            parts.append("<td>" + esc(cookie["samesite"] or "unset") + "</td>")
            parts.append("<td>" + esc(cookie["domain"] or "host-only") + "</td>")
            parts.append("<td>" + str(cookie["size"]) + "</td></tr>")
        parts.append("</table>")
        parts.append("<h2>Privacy Compliance Assessment</h2><table><tr><th>Area</th><th>Value</th></tr>")
        by_key = {r["key"]: r for r in payload["categories"]}
        parts.append("<tr><td>GDPR readiness</td><td>%g/%g</td></tr>" % (by_key["gdpr"]["score"], by_key["gdpr"]["max"]))
        parts.append("<tr><td>CCPA readiness</td><td>%g/%g</td></tr>" % (by_key["ccpa"]["score"], by_key["ccpa"]["max"]))
        parts.append("<tr><td>Consent posture</td><td>" + esc(consent.get("posture")) + "</td></tr>")
        parts.append("<tr><td>Privacy policy</td><td>" + esc(payload["links"].get("privacy") or "not found") + "</td></tr>")
        parts.append("<tr><td>Cookie policy</td><td>" + esc(payload["links"].get("cookie_policy") or "not found") + "</td></tr>")
        parts.append("<tr><td>Do Not Sell link</td><td>" + esc(payload["links"].get("do_not_sell") or "not found") + "</td></tr>")
        parts.append("</table>")
        parts.append("<h2>Recommendations</h2>")
        if payload["recommendations"]:
            parts.append("<ul class='recs'>")
            for rec in payload["recommendations"]:
                parts.append("<li>" + esc(rec) + "</li>")
            parts.append("</ul>")
        else:
            parts.append("<p>No critical issues found. Maintain current cookie hygiene.</p>")
        parts.append("<footer>Generated by CookieAnalyzer v" + VERSION + " &middot; " +
                     esc(payload["analyzed_at"]) + "</footer>")
        parts.append("</div></body></html>")
        return "".join(parts)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cookieanalyzer",
        description="CookieAnalyzer v" + VERSION +
                    " - cookie privacy analyzer for GDPR/CCPA compliance, consent management and security",
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL to analyze")
    parser.add_argument("-t", "--timeout", type=int, default=15,
                        help="Request timeout in seconds (default: 15)")
    parser.add_argument("--export", choices=["all", "json", "csv", "html", "none"],
                        default="none", help="Export format (default: none)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    use_color = not args.no_color
    c = Colors(use_color)
    print_banner(c)
    if args.timeout <= 0:
        print(c.red("Error: timeout must be a positive integer"))
        sys.exit(2)
    analyzer = CookieAnalyzer(
        url=args.url,
        timeout=args.timeout,
        verbose=args.verbose,
        use_color=use_color,
    )
    warnings.filterwarnings("ignore")
    try:
        analyzer.run()
    except requests.exceptions.Timeout:
        print(c.bright_red("[!] Request timed out after " + str(args.timeout) +
                           "s. Increase with -t/--timeout."))
        sys.exit(1)
    except requests.exceptions.ConnectionError as exc:
        print(c.bright_red("[!] Connection failed: " + str(exc)))
        sys.exit(1)
    except requests.exceptions.RequestException as exc:
        print(c.bright_red("[!] Request failed: " + str(exc)))
        sys.exit(1)
    analyzer.display()
    if args.export != "none":
        print(c.bold(c.bright_cyan("  EXPORT")))
        print(c.dim("  " + "-" * 96))
        try:
            written = analyzer.export(args.export)
            for path in written:
                print("  " + c.bright_green("[OK]") + " " + path)
        except OSError as exc:
            print("  " + c.bright_red("[FAIL]") + " Could not write export: " + str(exc))
    finished = (datetime.now() - analyzer.started).total_seconds()
    print(c.dim("  Completed in " + format(finished, ".2f") + "s"))


if __name__ == "__main__":
    main()
