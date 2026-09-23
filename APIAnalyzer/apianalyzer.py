#!/usr/bin/env python3
import sys
import os
import argparse
import json
import csv
import base64
import time
import re
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, urlencode

def _ensure(pkg, import_name=None):
    try:
        __import__(import_name or pkg)
    except ImportError:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

_ensure("requests")
_ensure("beautifulsoup4", "bs4")

import requests
from bs4 import BeautifulSoup

VERSION = "3.0"

WEIGHTS = {
    "endpoints": 9,
    "rest": 9,
    "versioning": 8,
    "realtime": 4,
    "query": 6,
    "graphql": 5,
    "auth": 11,
    "rate_limit": 5,
    "validation": 6,
    "response": 5,
    "performance": 6,
    "reliability": 8,
    "security": 8,
    "docs": 6,
    "errors": 4,
}

PILLARS = {
    "Quality": ["endpoints", "rest", "versioning", "query", "graphql", "response", "errors"],
    "Security": ["auth", "rate_limit", "validation", "security"],
    "Performance": ["performance", "reliability", "response"],
    "Documentation": ["docs", "versioning", "endpoints"],
}

PRIORITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


class C:
    enabled = True
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    BG_BLUE = "\033[44m"
    BG_BLACK = "\033[40m"

    @classmethod
    def wrap(cls, text, *codes):
        if not cls.enabled:
            return text
        return "".join(codes) + str(text) + cls.RESET


def grade_for(score, maximum):
    if maximum <= 0:
        return "F"
    pct = (score / maximum) * 100
    if pct >= 95:
        return "A+"
    if pct >= 90:
        return "A"
    if pct >= 75:
        return "B"
    if pct >= 60:
        return "C"
    if pct >= 40:
        return "D"
    return "F"


def grade_color(g):
    if g in ("A+", "A"):
        return C.GREEN
    if g == "B":
        return C.CYAN
    if g == "C":
        return C.YELLOW
    if g == "D":
        return C.MAGENTA
    return C.RED


def pct_color(p):
    return "#3ddc97" if p >= 90 else "#4cc9f0" if p >= 75 else "#ffd166" if p >= 60 else "#f72585" if p >= 40 else "#ff4d6d"


def gauge_line(label, pct, width=28):
    pct = max(0.0, min(100.0, float(pct)))
    filled = int(round(pct / 100.0 * width))
    filled = max(0, min(width, filled))
    g = grade_for(pct, 100)
    gc = grade_color(g)
    bar = C.wrap("#" * filled, gc) + C.wrap("-" * (width - filled), C.GRAY)
    return f"  {label:<20} {bar} {pct:5.1f}%  {C.wrap(g, gc, C.BOLD)}"


def print_banner():
    banner = r"""
   ▄████████  ▄██████▄  ███    █▄     ▄████████    ▄████████
  ███    ███ ███    ███ ███    ███   ███    ███   ███    ███
  ███    █▀  ███    ███ ███    ███   ███    █▀    ███    █▀
  ███        ███    ███ ███    ███  ▄███▄▄▄      ▄███▄▄▄
▀███████████ ███    ███ ███    ███ ▀▀███▀▀▀     ▀▀███▀▀▀
        ███ ███    ███ ███    ███   ███    █▄    ███    █▄
  ▄█    ███ ███    ███ ███    ███   ███    ███   ███    ███
▄████████▀   ▀██████▀  ████████▀    ████████▀    ██████████
"""
    colors = [C.CYAN, C.GREEN, C.YELLOW, C.RED, C.MAGENTA, C.BLUE]
    lines = banner.strip("\n").split("\n")
    for i, line in enumerate(lines):
        print(C.wrap(line, colors[i % len(colors)], C.BOLD))
    sub = f"  APIAnalyzer v{VERSION}  |  REST, GraphQL & Realtime API Quality, Security, Lifecycle Analyzer"
    print(C.wrap(sub, C.WHITE, C.BOLD))
    rule = "  " + "=" * 74
    print(C.wrap(rule, C.GRAY))
    print()


class APIAnalyzer:
    COMMON_PATHS = ["/", "/api", "/api/", "/v1", "/v2", "/v3", "/graphql", "/gql", "/rest", "/api/v1", "/api/v2"]
    SWAGGER_PATHS = ["/swagger", "/swagger/", "/swagger.json", "/openapi.json", "/api-docs", "/v2/api-docs", "/v3/api-docs", "/swagger-ui.html", "/swagger/index.html", "/swagger/v1/swagger.json"]
    DOC_PATHS = ["/docs", "/docs/", "/redoc", "/redoc/", "/api-docs", "/documentation", "/api/docs"]
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "MIME sniffing protection",
        "X-Frame-Options": "Clickjacking protection",
        "Content-Security-Policy": "XSS / injection mitigation",
        "Strict-Transport-Security": "HTTPS enforcement",
        "X-XSS-Protection": "Legacy XSS filter",
        "Referrer-Policy": "Referer leakage control",
        "Permissions-Policy": "Feature policy",
    }

    def __init__(self, url, timeout=15, api_key=None, auth_type="none", verbose=False):
        self.url = url if url.startswith(("http://", "https://")) else "https://" + url
        self.parsed = urlparse(self.url)
        self.base = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.timeout = timeout
        self.api_key = api_key
        self.auth_type = auth_type
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "APIAnalyzer/3.0 (Quality, Security & Lifecycle Scanner)",
            "Accept": "application/json, */*",
        })
        if auth_type == "bearer" and api_key:
            self.session.headers["Authorization"] = f"Bearer {api_key}"
        elif auth_type == "basic" and api_key:
            self.session.headers["Authorization"] = "Basic " + base64.b64encode(api_key.encode()).decode()
        elif auth_type == "apikey" and api_key:
            self.session.headers["X-API-Key"] = api_key
            self.session.headers["api-key"] = api_key
        self.endpoints = []
        self.results = []
        self.raw = {}

    def log(self, msg):
        if self.verbose:
            print(C.wrap(f"    [.] {msg}", C.GRAY))

    def req(self, method, path, **kwargs):
        url = path if str(path).startswith("http") else urljoin(self.base + "/", str(path).lstrip("/"))
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        try:
            r = self.session.request(method, url, **kwargs)
            self.log(f"{method} {url} -> {r.status_code}")
            return r
        except requests.exceptions.Timeout:
            self.log(f"{method} {url} -> timeout")
            return None
        except requests.exceptions.SSLError:
            self.log(f"{method} {url} -> ssl error")
            return None
        except requests.exceptions.RequestException as e:
            self.log(f"{method} {url} -> {type(e).__name__}")
            return None

    def track(self, method, path, status, content_type=""):
        entry = {"method": method, "path": path, "status": status, "content_type": content_type}
        if entry not in self.endpoints:
            self.endpoints.append(entry)

    def category(self, key, name, maximum, score, findings):
        clamped = max(0, min(maximum, score))
        return {
            "key": key,
            "name": name,
            "max": maximum,
            "score": round(clamped, 1),
            "findings": findings,
            "grade": grade_for(clamped, maximum),
        }

    def check_endpoints(self):
        findings = []
        score = 0
        found_paths = []
        for p in self.COMMON_PATHS:
            r = self.req("GET", p)
            if r is not None and r.status_code < 400:
                found_paths.append(p)
                ct = r.headers.get("Content-Type", "")
                self.track("GET", p, r.status_code, ct)
                findings.append(f"Alive path: {p} ({r.status_code})")
                self.log(f"path {p} alive: {r.status_code}")
        if found_paths:
            score += 5
        swagger_found = []
        short_t = min(self.timeout, 5)
        for p in self.SWAGGER_PATHS:
            r = self.req("HEAD", p, timeout=short_t)
            if r is not None and r.status_code == 405:
                r = self.req("GET", p, timeout=short_t)
            if r is not None and r.status_code == 200:
                swagger_found.append(p)
                ct = r.headers.get("Content-Type", "")
                self.track("HEAD" if r.request.method == "HEAD" else "GET", p, r.status_code, ct)
                findings.append(f"Swagger/OpenAPI doc: {p}")
        if swagger_found:
            score += 4
        docs_found = []
        for p in self.DOC_PATHS:
            if p in swagger_found:
                continue
            r = self.req("GET", p)
            if r is not None and r.status_code == 200:
                docs_found.append(p)
                ct = r.headers.get("Content-Type", "")
                self.track("GET", p, r.status_code, ct)
                findings.append(f"Documentation: {p}")
        if docs_found:
            score += 3
        root = self.req("GET", "/")
        if root is not None:
            self.track("GET", "/", root.status_code, root.headers.get("Content-Type", ""))
            if root.status_code == 200:
                score += 1
                findings.append("Root endpoint responds")
            links = set(re.findall(r'href=["\']([^"\']+)["\']', root.text[:200000], re.I)) if root.text else set()
            apiish = [l for l in links if any(k in l.lower() for k in ("/api", "/v1", "/v2", "/graphql", "/rest"))]
            if apiish:
                score += 1
                findings.append(f"Linked API-like paths found: {len(apiish)}")
                for l in list(apiish)[:5]:
                    self.track("GET", l, "-", "text/html")
            options = self.req("OPTIONS", "/")
            if options is not None:
                allow = options.headers.get("Allow", "")
                if allow:
                    findings.append(f"Allow header at root: {allow}")
                    score += 1
        if len(self.endpoints) >= 5:
            score += 1
        findings.append(f"Total discovered endpoints: {len(self.endpoints)}")
        self.raw["endpoint_paths"] = found_paths
        self.raw["swagger_paths"] = swagger_found
        self.raw["doc_paths"] = docs_found
        return self.category("endpoints", "Endpoint Discovery", 15, score, findings)

    def check_rest(self):
        findings = []
        score = 0
        method_hits = {}
        for m in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            r = self.req(m, "/", json={})
            if r is not None:
                method_hits[m] = r.status_code
                if r.status_code not in (404, 405, 501, 502, 503):
                    self.track(m, "/", r.status_code, r.headers.get("Content-Type", ""))
                    findings.append(f"Method {m} accepted/processed at / ({r.status_code})")
        used = [m for m, s in method_hits.items() if s not in (404, 405, 501)]
        if len(used) >= 4:
            score += 4
            findings.append(f"Broad method support: {', '.join(sorted(used))}")
        elif used:
            score += 2
            findings.append(f"Limited method support: {', '.join(sorted(used))}")
        r404 = self.req("GET", "/this-path-should-not-exist-apianalyzer-404")
        status_ok = False
        if r404 is not None:
            self.track("GET", "/this-path-should-not-exist-apianalyzer-404", r404.status_code, r404.headers.get("Content-Type", ""))
            if r404.status_code == 404:
                status_ok = True
                score += 3
                findings.append("Correct 404 for unknown resource")
            else:
                findings.append(f"Unknown path returned {r404.status_code} instead of 404")
        rbad = self.req("POST", "/", data="not-json{{{", headers={"Content-Type": "application/json"})
        if rbad is not None:
            if rbad.status_code in (400, 415, 422):
                score += 2
                findings.append(f"Malformed JSON handled correctly ({rbad.status_code})")
            elif rbad.status_code == 404:
                findings.append("POST / not found; cannot evaluate 400 handling here")
            else:
                findings.append(f"Malformed JSON returned {rbad.status_code} (expected 400/415/422)")
        rmethod = self.req("OPTIONS", "/")
        allow = ""
        if rmethod is not None:
            allow = rmethod.headers.get("Allow", rmethod.headers.get("Access-Control-Allow-Methods", ""))
            if allow:
                findings.append(f"Allowed methods advertised: {allow}")
                score += 1
        roverride = self.req("GET", "/", headers={"X-HTTP-Method-Override": "DELETE"})
        if roverride is not None:
            if roverride.status_code in (400, 403, 404, 405, 422) and roverride.status_code != method_hits.get("GET", 200):
                findings.append(f"HTTP method override header produced distinct response ({roverride.status_code})")
            else:
                findings.append("X-HTTP-Method-Override present but not observably honored")
            score += 1
        rxml = self.req("GET", "/", headers={"Accept": "application/xml"})
        rjson = self.req("GET", "/", headers={"Accept": "application/json"})
        neg = False
        if rxml is not None and rjson is not None:
            cx = rxml.headers.get("Content-Type", "")
            cj = rjson.headers.get("Content-Type", "")
            if "xml" in cx and "json" in cj:
                neg = True
            if cx != cj:
                neg = True
            if neg:
                score += 2
                findings.append("Content negotiation observed via Accept header")
            else:
                findings.append("Accept header did not change content type")
        ver_hit = False
        for p in ("/v1", "/v2", "/api/v1", "/api/v2"):
            r = self.req("GET", p)
            if r is not None and r.status_code < 400:
                ver_hit = True
                findings.append(f"Versioned path active: {p}")
                self.track("GET", p, r.status_code, r.headers.get("Content-Type", ""))
                break
        if ver_hit:
            score += 3
        else:
            rhead = self.req("GET", "/", headers={"API-Version": "1"})
            if rhead is not None and rhead.headers.get("API-Version"):
                ver_hit = True
                score += 2
                findings.append("API version exposed via response header")
            if not ver_hit:
                findings.append("No API versioning detected in paths or headers")
        allowed_codes = {200, 201, 204, 400, 401, 403, 404, 500}
        seen = {e["status"] for e in self.endpoints if isinstance(e["status"], int)}
        seen &= allowed_codes
        if len(seen) >= 4:
            score += 2
            findings.append(f"Good status-code hygiene: {sorted(seen)}")
        elif seen:
            score += 1
            findings.append(f"Partial status-code usage: {sorted(seen)}")
        self.raw["method_hits"] = method_hits
        self.raw["allow_header"] = allow
        return self.category("rest", "REST API Best Practices", 15, score, findings)

    def check_versioning(self):
        findings = []
        score = 0
        versions = set()
        alive_versions = {}
        version_paths = ["/v1", "/v2", "/v3", "/api/v1", "/api/v2", "/api/v3"]
        for p in version_paths:
            r = self.req("GET", p)
            if r is not None and r.status_code < 400:
                m = re.search(r"/v(\d+)", p)
                if m:
                    versions.add(int(m.group(1)))
                alive_versions[p] = r
                self.track("GET", p, r.status_code, r.headers.get("Content-Type", ""))
                findings.append(f"Versioned path alive: {p} ({r.status_code})")
        if len(versions) >= 2:
            score += 3
            findings.append(f"Multiple API versions coexist: {sorted(versions)}")
        elif len(versions) == 1:
            score += 2
            findings.append(f"Single API version detected: {sorted(versions)}")
        else:
            findings.append("No URL-path versioning (/v1, /v2, /v3) detected")

        hdr_version = ""
        explicit_ver_headers = []
        probe = self.req("GET", "/", headers={"X-API-Version": "2", "API-Version": "2"})
        if probe is not None:
            for hk in ("API-Version", "X-API-Version"):
                hv = probe.headers.get(hk)
                if hv:
                    explicit_ver_headers.append(f"{hk}: {hv}")
            for hk, hv in probe.headers.items():
                hl = hk.lower()
                if "version" in hl and hl not in ("x-powered-by", "server"):
                    hdr_version = f"{hk}: {hv}"
                    break
        if explicit_ver_headers:
            score += 3
            hdr_version = explicit_ver_headers[0]
            findings.append(f"Explicit API version header present ({'; '.join(explicit_ver_headers)[:80]})")
        elif hdr_version:
            score += 2
            findings.append(f"Version advertised via header ({hdr_version[:80]})")
        else:
            findings.append("No header-based API version advertising observed")

        sample = []
        root = self.req("GET", "/")
        if root is not None:
            sample.append(root)
        sample.extend(alive_versions.values())
        dep_found = False
        sunset_found = ""
        for r in sample:
            dep = r.headers.get("Deprecation")
            sunset = r.headers.get("Sunset")
            warn = r.headers.get("Warning")
            if dep is not None and not dep_found:
                dep_found = True
                score += 2
                findings.append(f"Deprecation header present (RFC 8594): {dep}")
            if sunset and not sunset_found:
                sunset_found = sunset
                score += 2
                findings.append(f"Sunset header present: {sunset} - clients must migrate before this date")
            if warn and "deprecated" in str(warn).lower():
                findings.append(f"Warning header indicates deprecation: {str(warn)[:100]}")
        if not dep_found:
            findings.append("No Deprecation response header observed")
        if not sunset_found:
            findings.append("No Sunset header observed")

        breaking_hints = []
        if len(alive_versions) >= 2:
            def vnum(item):
                m = re.search(r"/v(\d+)", item[0])
                return int(m.group(1)) if m else 0
            pairs = sorted(alive_versions.items(), key=vnum)
            p_old, r_old = pairs[0]
            p_new, r_new = pairs[-1]
            ct_old = r_old.headers.get("Content-Type", "").split(";")[0].strip()
            ct_new = r_new.headers.get("Content-Type", "").split(";")[0].strip()
            if ct_old and ct_old == ct_new:
                score += 1
                findings.append("Content type consistent across versions (compatibility-friendly)")
            if "json" in ct_old and "json" in ct_new:
                try:
                    d_old = r_old.json()
                    d_new = r_new.json()
                    if isinstance(d_old, dict) and isinstance(d_new, dict):
                        removed = set(d_old) - set(d_new)
                        added = set(d_new) - set(d_old)
                        if removed:
                            hint = f"fields dropped {p_old} -> {p_new}: {sorted(removed)[:6]}"
                            breaking_hints.append(hint)
                            findings.append(f"Breaking-change hint: {hint}")
                        if added:
                            findings.append(f"Additive change {p_old} -> {p_new}: new fields {sorted(added)[:6]}")
                        if not removed and not added:
                            score += 1
                            findings.append("Top-level contract identical across versions (compatible)")
                except Exception:
                    pass
            findings.append("Compatibility analysis: multiple versions respond; keep contracts additive only")

        mig_paths = ["/changelog", "/CHANGELOG.md", "/api/changelog", "/migration", "/docs/migration", "/upgrade", "/deprecations"]
        mig_found = []
        for p in mig_paths:
            r = self.req("GET", p)
            if r is not None and r.status_code == 200 and r.text:
                mig_found.append(p)
                self.track("GET", p, r.status_code, r.headers.get("Content-Type", ""))
        if mig_found:
            score += 2
            findings.append(f"Migration/changelog resources found: {', '.join(mig_found[:4])}")
        else:
            findings.append("No changelog/migration endpoints found")
        if sunset_found:
            findings.append(f"Migration hint: schedule client upgrades before Sunset ({sunset_found})")
        elif not dep_found and versions:
            findings.append("Migration hint: publish a deprecation policy with Sunset dates for old versions")

        self.raw["api_versions"] = sorted(versions)
        self.raw["breaking_change_hints"] = breaking_hints
        self.raw["deprecation"] = {"header": dep_found, "sunset": sunset_found}
        return self.category("versioning", "Versioning & Lifecycle", 14, max(score, 0), findings)

    def check_realtime(self):
        findings = []
        score = 0
        ws_found = []
        short_t = min(self.timeout, 5)
        ws_key = base64.b64encode(os.urandom(16)).decode()
        ws_paths = ["/ws", "/websocket", "/socket.io/?EIO=4&transport=websocket", "/realtime", "/api/ws", "/live", "/notifications", "/sockjs/info"]
        for p in ws_paths:
            r = self.req(
                "GET",
                p,
                headers={
                    "Connection": "Upgrade",
                    "Upgrade": "websocket",
                    "Sec-WebSocket-Version": "13",
                    "Sec-WebSocket-Key": ws_key,
                },
                stream=True,
                timeout=short_t,
            )
            if r is None:
                continue
            status = r.status_code
            accept = r.headers.get("Sec-WebSocket-Accept", "")
            self.track("GET", p, status, r.headers.get("Content-Type", ""))
            try:
                r.close()
            except Exception:
                pass
            if status == 101 or accept:
                ws_found.append(p)
                findings.append(f"WebSocket upgrade accepted: {p} ({status})")
            elif status in (400, 426):
                findings.append(f"WebSocket handshake rejected at {p} ({status})")
        if ws_found:
            score += 3
        else:
            findings.append("No WebSocket upgrade (101) observed on common paths")

        root = self.req("GET", "/")
        blob = (root.text[:200000] if root is not None and root.text else "")
        if re.search(r"new WebSocket\b|EventSource\b|socket\.io|signalr|sockjs|text/event-stream", blob, re.I):
            score += 1
            findings.append("HTML/JS references realtime client APIs (WebSocket/EventSource/socket.io)")

        sse_paths = ["/events", "/stream", "/sse", "/api/events", "/api/stream", "/notifications/stream"]
        sse_found = []
        for p in sse_paths:
            r = self.req("GET", p, headers={"Accept": "text/event-stream"}, stream=True, timeout=short_t)
            if r is None:
                continue
            ct = r.headers.get("Content-Type", "")
            status = r.status_code
            peek = ""
            if status == 200:
                try:
                    for chunk in r.iter_content(chunk_size=64):
                        peek = (chunk or b"")[:64].decode("utf-8", "replace")
                        break
                except requests.exceptions.RequestException:
                    peek = ""
                except Exception:
                    peek = ""
            self.track("GET", p, status, ct)
            try:
                r.close()
            except Exception:
                pass
            if "text/event-stream" in ct or peek.startswith(("data:", "event:", "retry:")):
                sse_found.append(p)
                findings.append(f"Server-Sent Events endpoint: {p}")
        if sse_found:
            score += 3
        else:
            findings.append("No Server-Sent Events (text/event-stream) endpoints detected")

        if self.raw.get("graphql_endpoint"):
            score += 1
            findings.append("GraphQL endpoint present; subscriptions may provide realtime via WebSocket")

        self.raw["websocket_paths"] = ws_found
        self.raw["sse_paths"] = sse_found
        return self.category("realtime", "Realtime & Streaming", 8, max(score, 0), findings)

    def _api_base_candidates(self):
        cands = []
        for e in self.endpoints:
            ct = (e.get("content_type") or "").lower()
            if "json" in ct and isinstance(e.get("status"), int) and e["status"] < 400 and e["path"] != "/":
                cands.append(e["path"])
        for p in ("/api", "/api/", "/v1", "/v2", "/api/v1"):
            if p not in cands:
                cands.append(p)
        cands.append("/")
        seen = []
        for p in cands:
            if p not in seen:
                seen.append(p)
        return seen[:6]

    def check_query_features(self):
        findings = []
        score = 0
        base_path = "/"
        baseline = None
        for p in self._api_base_candidates():
            r = self.req("GET", p)
            if r is not None and r.status_code == 200 and "json" in r.headers.get("Content-Type", ""):
                base_path = p
                baseline = r
                break
        if baseline is None:
            findings.append("No JSON API path available to evaluate query features")
            self.raw["pagination_styles"] = []
            self.raw["filtering_supported"] = False
            self.raw["sorting_supported"] = False
            self.raw["field_selection_supported"] = False
            return self.category("query", "Pagination, Filtering & Fields", 10, 0, findings)
        b_text = baseline.text[:100000] if baseline.text else ""
        b_json = None
        try:
            b_json = baseline.json()
        except Exception:
            b_json = None

        def probe(params):
            sep = "&" if "?" in base_path else "?"
            url = base_path + sep + urlencode(params, doseq=True)
            return self.req("GET", url)

        def changed_vs_baseline(r):
            if r is None or r.status_code >= 400:
                return False, None
            t = r.text[:100000] if r.text else ""
            try:
                j = r.json()
            except Exception:
                j = None
            return t != b_text, j

        pag_found = []
        styles = {
            "offset": {"offset": 0, "limit": 2},
            "page": {"page": 1, "per_page": 2},
            "cursor": {"cursor": "apianalyzer"},
        }
        for name, params in styles.items():
            r = probe(params)
            if r is None or r.status_code >= 400:
                continue
            ch, j = changed_vs_baseline(r)
            meta_hit = False
            if isinstance(j, dict):
                keys = {k.lower() for k in j.keys()}
                markers = {"page", "total", "total_pages", "per_page", "limit", "offset", "cursor", "next", "next_cursor", "meta", "pagination"}
                if keys & markers:
                    meta_hit = True
            link = r.headers.get("Link", "")
            if link and 'rel="next"' in link:
                meta_hit = True
            if ch or meta_hit:
                pag_found.append(name)
                findings.append(f"{name.capitalize()} pagination parameters accepted ({base_path})")
        if baseline.headers.get("Link", "") and 'rel="next"' in baseline.headers.get("Link", ""):
            if "link" not in pag_found:
                pag_found.append("link")
                findings.append("RFC5988 Link header pagination present")
        pag_styles = [p for p in pag_found if p != "link"]
        score += min(3, len(pag_styles))
        if "link" in pag_found:
            score += 1
        if not pag_found:
            findings.append("No pagination parameter behavior detected on API responses")
        else:
            findings.append(f"Pagination styles detected: {sorted(set(pag_found))}")

        filt_ok = False
        for fp in ({"q": "test"}, {"search": "test"}, {"filter[status]": "active"}):
            r = probe(fp)
            ch, _j = changed_vs_baseline(r)
            if ch and r is not None and r.status_code < 400:
                filt_ok = True
                findings.append(f"Filter parameter honored: {next(iter(fp))}")
                break
        if filt_ok:
            score += 2
        else:
            findings.append("No filtering parameter response change observed")

        sort_ok = False
        for sp in ({"sort": "id"}, {"sort": "-id"}, {"order": "asc"}, {"order_by": "id"}):
            k = next(iter(sp))
            r = probe(sp)
            ch, _j = changed_vs_baseline(r)
            if ch and r is not None and r.status_code < 400:
                sort_ok = True
                findings.append(f"Sorting parameter honored: {k}={sp[k]}")
                break
        if sort_ok:
            score += 2
        else:
            findings.append("No sorting parameter response change observed")

        field_ok = False
        for fp in ({"fields": "id"}, {"_fields": "id"}, {"fields[items]": "id"}):
            fk = next(iter(fp))
            r = probe(fp)
            _ch, j = changed_vs_baseline(r)
            if r is None or r.status_code >= 400:
                continue
            if isinstance(j, dict) and isinstance(b_json, dict) and set(j.keys()) != set(b_json.keys()):
                field_ok = True
                findings.append(f"Field selection parameter appears honored: {fk}")
                break
            if isinstance(j, list) and isinstance(b_json, list) and j != b_json:
                field_ok = True
                findings.append(f"Field selection parameter appears honored: {fk}")
                break
        if self.raw.get("graphql_endpoint"):
            findings.append("GraphQL endpoint provides native field selection")
            field_ok = True
        if field_ok:
            score += 2
        else:
            findings.append("No sparse-fieldset behavior detected")

        self.raw["pagination_styles"] = sorted(set(pag_found))
        self.raw["filtering_supported"] = filt_ok
        self.raw["sorting_supported"] = sort_ok
        self.raw["field_selection_supported"] = field_ok
        return self.category("query", "Pagination, Filtering & Fields", 10, max(score, 0), findings)

    def check_graphql(self):
        findings = []
        score = 0
        gql_endpoint = None
        short_t = min(self.timeout, 5)
        for p in ("/graphql", "/gql", "/api/graphql", "/v1/graphql"):
            r = self.req("POST", p, json={"query": "{__typename}"}, timeout=short_t)
            if r is None:
                continue
            self.track("POST", p, r.status_code, r.headers.get("Content-Type", ""))
            body = ""
            try:
                body = r.text[:500]
            except Exception:
                body = ""
            ct_low = r.headers.get("Content-Type", "").lower()
            if r.status_code < 500 and (
                "application/json" in ct_low
                or "graphql" in ct_low
                or "__typename" in body
                or "data" in body
                or "graphql" in body.lower()
            ):
                if r.status_code == 200 or "errors" in body or "data" in body or "graphql" in (body + ct_low).lower():
                    gql_endpoint = p
                    findings.append(f"GraphQL endpoint detected: {p} ({r.status_code})")
                    break
        if not gql_endpoint:
            for p in ("/graphql", "/gql", "/api/graphql"):
                r = self.req("GET", p, timeout=short_t)
                if r is None:
                    continue
                ct_low = r.headers.get("Content-Type", "").lower()
                body_head = ""
                try:
                    body_head = (r.text or "")[:2000]
                except Exception:
                    body_head = ""
                if "graphql" in ct_low or "graphql" in body_head.lower() or "Must provide query" in body_head:
                    if r.status_code < 500:
                        gql_endpoint = p
                        self.track("GET", p, r.status_code, r.headers.get("Content-Type", ""))
                        findings.append(f"GraphQL signal on {p}: content-type/body indicates GraphQL ({r.status_code})")
                        break
        if not gql_endpoint:
            for e in self.endpoints:
                if "graphql" in (e.get("path") or "").lower() and isinstance(e.get("status"), int) and e["status"] < 500:
                    gql_endpoint = e["path"]
                    findings.append(f"GraphQL path discovered: {e['path']} ({e['status']})")
                    break
        if gql_endpoint:
            score += 3
            introspection = {"query": "{ __schema { queryType { name } mutationType { name } subscriptionType { name } } }"}
            ri = self.req("POST", gql_endpoint, json=introspection)
            introspection_on = False
            if ri is not None and ri.status_code == 200:
                try:
                    data = ri.json()
                    schema = data.get("data", {}).get("__schema") if isinstance(data, dict) else None
                    if schema:
                        introspection_on = True
                        q = schema.get("queryType", {}).get("name")
                        m = schema.get("mutationType", {})
                        s = schema.get("subscriptionType", {})
                        findings.append(f"Introspection enabled (query type: {q})")
                        score += 3
                        if m:
                            findings.append(f"Mutations supported (type: {m.get('name')})")
                            score += 1
                        else:
                            findings.append("No mutation type exposed")
                        if s:
                            findings.append(f"Subscriptions supported (type: {s.get('name')})")
                            score += 1
                        else:
                            findings.append("No subscription type exposed")
                except Exception:
                    pass
            if not introspection_on:
                findings.append("Introspection appears disabled or blocked")
            depth_q = '{ __type(name: "Query") { fields { type { fields { type { name } } } } } }'
            rd = self.req("POST", gql_endpoint, json={"query": depth_q})
            if rd is not None and rd.status_code == 200 and '"fields"' in rd.text:
                findings.append("Nested type traversal accepted (query depth risk)")
            bad = self.req("POST", gql_endpoint, json={"query": "{ "})
            if bad is not None and bad.status_code == 200:
                try:
                    bd = bad.json()
                    if bd.get("errors"):
                        findings.append("Malformed GraphQL query returns structured errors")
                        score += 1
                except Exception:
                    pass
            rget = self.req("GET", gql_endpoint)
            if rget is not None and rget.status_code in (400, 405):
                findings.append("GET method correctly rejected for GraphQL queries")
            elif rget is not None and rget.status_code == 200:
                findings.append("GraphQL endpoint responds to GET (batching/caching consideration)")
        else:
            findings.append("No GraphQL endpoint detected among common paths")
            findings.append("GraphQL checks skipped for this target")
            score += 1
        self.raw["graphql_endpoint"] = gql_endpoint
        return self.category("graphql", "GraphQL Analysis", 10, score, findings)

    @staticmethod
    def _jwt_exp(token):
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return None, None
            pad = "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
            return payload, payload.get("exp")
        except Exception:
            return None, None

    def check_auth(self):
        findings = []
        score = 0
        r_unauth = self.req("GET", "/")
        www = ""
        if r_unauth is not None:
            www = r_unauth.headers.get("WWW-Authenticate", "")
            if www:
                findings.append(f"WWW-Authenticate: {www[:120]}")
                score += 2
        protected_tried = False
        for p in ("/admin", "/api/admin", "/api/users", "/api/me", "/me", "/account", "/private", "/internal"):
            r = self.req("GET", p)
            if r is None:
                continue
            self.track("GET", p, r.status_code, r.headers.get("Content-Type", ""))
            if r.status_code in (401, 403):
                protected_tried = True
                findings.append(f"Protected resource enforces auth: {p} ({r.status_code})")
                score += 3
                break
        if not protected_tried:
            findings.append("No obviously protected endpoints discovered to verify auth enforcement")
        blob = ""
        for p in ("/", "/login", "/api", "/api/token", "/.well-known/openid-configuration"):
            r = self.req("GET", p)
            if r is not None and r.text:
                blob += r.text[:50000]
        if re.search(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.", blob):
            findings.append("JWT-like token observed in responses")
            score += 2
            m = re.search(r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)", blob)
            if m:
                try:
                    parts = m.group(1).split(".")
                    pad = "=" * (-len(parts[1]) % 4)
                    pl = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
                    exp = pl.get("exp")
                    if exp:
                        delta = exp - time.time()
                        mins = delta / 60
                        findings.append(f"JWT exp present; lifetime ~{mins:.0f} minutes from now")
                        if mins <= 0:
                            findings.append("JWT is expired")
                        elif mins > 60 * 24 * 365:
                            findings.append("JWT lifetime exceeds one year (consider shorter expiry)")
                            score -= 1
                        else:
                            score += 1
                    else:
                        findings.append("JWT has no exp claim")
                    if pl.get("alg") == "none":
                        findings.append("JWT alg=none is insecure")
                    elif pl.get("alg"):
                        findings.append(f"JWT algorithm: {pl.get('alg')}")
                except Exception:
                    pass
        if "oauth" in blob.lower() or "access_token" in blob or "authorization" in blob.lower():
            findings.append("OAuth 2.0 indicators present in responses/docs")
            score += 2
        rjwt = self.req("GET", "/", headers={"Authorization": "Bearer invalid.token.value"})
        if rjwt is not None and rjwt.status_code in (401, 403):
            findings.append("Invalid bearer token rejected correctly")
            score += 1
        rkey = self.req("GET", "/", headers={"X-API-Key": "invalid"})
        if rkey is not None and rkey.status_code in (401, 403):
            findings.append("Invalid API key rejected correctly")
            score += 1
        rbp = self.req("GET", "/")
        cors_headers = {k: v for k, v in (rbp.headers.items() if rbp is not None else []) if k.lower().startswith("access-control-")}
        if cors_headers:
            findings.append(f"CORS headers present: {', '.join(cors_headers.keys())}")
            origin = cors_headers.get("Access-Control-Allow-Origin", "*") or cors_headers.get("access-control-allow-origin", "*")
            if origin == "*":
                findings.append("CORS allows arbitrary origin (*)")
            elif "evil" in origin:
                findings.append("CORS reflected an untrusted origin")
            else:
                score += 1
            cred = cors_headers.get("Access-Control-Allow-Credentials", "false")
            if str(cred).lower() == "true" and origin == "*":
                findings.append("Insecure combo: Allow-Origin * with credentials")
            else:
                score += 1
        else:
            findings.append("No CORS headers observed on root response")
        pre = self.req("OPTIONS", "/", headers={"Origin": "https://example.com", "Access-Control-Request-Method": "POST"})
        if pre is not None and any(k.lower().startswith("access-control-") for k in pre.headers):
            findings.append("CORS preflight supported")
            score += 1
        if self.auth_type != "none":
            findings.append(f"Scanner authenticated with auth type: {self.auth_type}")
            score += 1
        self.raw["cors_headers"] = cors_headers
        self.raw["www_authenticate"] = www
        return self.category("auth", "Authentication & Authorization", 15, max(score, 0), findings)

    def check_rate_limit(self):
        findings = []
        score = 0
        r = self.req("GET", "/")
        if r is not None:
            rl = {k: v for k, v in r.headers.items() if "rate" in k.lower() or "ratelimit" in k.lower() or k.lower() in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "retry-after")}
            if rl:
                findings.append(f"Rate limit headers: {', '.join(f'{k}={v}' for k, v in rl.items())}")
                score += 5
            else:
                findings.append("No X-RateLimit-* headers on normal responses")
            named = []
            for hk in ("RateLimit-Limit", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "Retry-After"):
                hv = r.headers.get(hk)
                if hv is not None:
                    named.append(f"{hk}={hv}")
            if named:
                score += 2
                findings.append(f"Standard rate-limit headers present: {', '.join(named)}")
            else:
                findings.append("No RateLimit-Limit / X-RateLimit-Limit / Retry-After headers observed")
        triggered = False
        for i in range(25):
            rr = self.req("GET", "/")
            if rr is not None and rr.status_code == 429:
                triggered = True
                findings.append(f"429 Too Many Requests observed after {i + 1} rapid requests")
                ra = rr.headers.get("Retry-After", "")
                if ra:
                    findings.append(f"Retry-After: {ra}")
                    score += 2
                score += 4
                break
        if not triggered:
            findings.append("No 429 observed during 25 rapid requests (rate limiting may be absent or generous)")
        r2 = self.req("GET", "/")
        if r2 is not None:
            rl2 = {k: v for k, v in r2.headers.items() if "ratelimit" in k.lower().replace("-", "") or "rate-limit" in k.lower()}
            if rl2 and score < 8:
                score += 2
                findings.append("Rate limit configuration exposed via headers")
            ct = r2.headers.get("Content-Type", "")
            if "json" in ct and any(k.lower().startswith("x-ratelimit") for k in r2.headers):
                score += 1
        if score >= 8:
            findings.append("Rate limiting appears properly configured")
        elif score >= 4:
            findings.append("Partial rate limiting signals detected")
        else:
            findings.append("Recommendation: enforce rate limits with standard headers")
        self.raw["rate_limit_signals"] = score >= 4
        return self.category("rate_limit", "Rate Limiting", 13, max(score, 0), findings)

    def check_validation(self):
        findings = []
        score = 0
        r = self.req("POST", "/", data="<xml/>", headers={"Content-Type": "application/xml"})
        if r is not None:
            if r.status_code in (400, 415, 422):
                findings.append(f"Unsupported Content-Type rejected ({r.status_code})")
                score += 3
            elif r.status_code == 404:
                findings.append("POST / unavailable; content-type check inconclusive here")
            else:
                findings.append(f"application/xml accepted/other status: {r.status_code}")
        huge = "A" * (2 * 1024 * 1024)
        r2 = self.req("POST", "/", data=huge, headers={"Content-Type": "application/json"})
        if r2 is not None:
            if r2.status_code in (413, 400, 431):
                findings.append(f"Oversized body handled ({r2.status_code}) - request size limit present")
                score += 3
            elif r2.status_code == 404:
                findings.append("POST / unavailable; size-limit check inconclusive")
            else:
                findings.append(f"2MB body accepted with status {r2.status_code} (consider stricter limits)")
        r3 = self.req("GET", "/?id=abc'\"<script>&page=notanumber&limit=-1&offset=huge")
        if r3 is not None:
            if r3.status_code in (400, 422):
                findings.append(f"Malformed query parameters rejected ({r3.status_code})")
                score += 2
            elif r3.status_code == 200:
                try:
                    body = r3.text[:2000]
                    if "sql" in body.lower() or "syntax error" in body.lower() or "sqlite" in body.lower():
                        findings.append("Possible SQL error leakage from crafted parameters")
                    else:
                        findings.append("Query parameters accepted without explicit validation signal")
                except Exception:
                    pass
        boundary = "----apianalyzer"
        payload = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="test.php"\r\n'
            "Content-Type: application/x-php\r\n\r\n"
            "<?php echo 1; ?>\r\n"
            f"--{boundary}--\r\n"
        )
        r4 = self.req("POST", "/", data=payload.encode(), headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        if r4 is not None:
            if r4.status_code in (400, 413, 415, 422):
                findings.append(f"Malicious file upload rejected ({r4.status_code})")
                score += 2
            elif r4.status_code == 404:
                findings.append("POST / unavailable; file-upload validation inconclusive")
            else:
                findings.append(f"Multipart upload returned {r4.status_code}")
        r5 = self.req("POST", "/", data="x", headers={"Content-Type": "application/json", "Content-Length": "999999999"})
        if r5 is not None and r5.status_code in (400, 411, 413):
            findings.append("Content-Length mismatch/oversize rejected")
            score += 1
        if score == 0:
            findings.append("Recommendation: validate content types, sizes, params, and uploads server-side")
        return self.category("validation", "Input Validation", 10, max(score, 0), findings)

    def check_response(self):
        findings = []
        score = 0
        r = self.req("GET", "/")
        if r is None:
            findings.append("Root unreachable; cannot evaluate response quality")
            return self.category("response", "Response Quality", 10, 0, findings)
        ct = r.headers.get("Content-Type", "")
        if "json" in ct:
            findings.append("Root responds with JSON content type")
            score += 2
            try:
                r.json()
                findings.append("Body parses as valid JSON")
                score += 1
            except Exception:
                findings.append("Content-Type claims JSON but body failed to parse")
        elif "html" in ct:
            findings.append("Root responds with HTML (SPA or docs page)")
            soup = BeautifulSoup(r.text[:200000], "html.parser")
            title = soup.title.string.strip() if soup.title and soup.title.string else ""
            if title:
                findings.append(f"HTML title: {title}")
            score += 1
        r2 = self.req("GET", "/this-does-not-exist-xyz")
        if r2 is not None:
            ict = r2.headers.get("Content-Type", "")
            err_struct = False
            if "json" in ict:
                try:
                    ed = r2.json()
                    if isinstance(ed, dict) and any(k in ed for k in ("error", "message", "code", "status", "errors")):
                        err_struct = True
                        findings.append("Error responses use structured JSON")
                        score += 2
                except Exception:
                    pass
            if not err_struct:
                findings.append("Error response structure not clearly machine-readable")
        r3 = self.req("GET", "/?page=1&per_page=10&limit=10&offset=0&cursor=abc")
        if r3 is not None:
            pag = False
            link = r3.headers.get("Link", "")
            if link and 'rel="next"' in link:
                pag = True
                findings.append("RFC5988 Link header pagination present")
            if "json" in r3.headers.get("Content-Type", ""):
                try:
                    d = r3.json()
                    if isinstance(d, dict):
                        keys = {k.lower() for k in d.keys()}
                        markers = {"page", "total", "total_pages", "per_page", "limit", "offset", "cursor", "next", "next_cursor"}
                        hit = keys & markers
                        if hit:
                            pag = True
                            findings.append(f"Pagination fields present: {sorted(hit)}")
                        if isinstance(d.get("data"), list) and any(k in d for k in ("meta", "pagination")):
                            pag = True
                            findings.append("Paginated envelope (data + meta/pagination) detected")
                except Exception:
                    pass
            if pag:
                score += 3
            else:
                findings.append("No pagination indicators detected")
        enc = r.headers.get("Content-Encoding", "")
        r4 = self.req("GET", "/", headers={"Accept-Encoding": "gzip, deflate, br"})
        enc2 = ""
        if r4 is not None:
            enc2 = r4.headers.get("Content-Encoding", "")
            if enc2 or enc:
                findings.append(f"Response compression active: {enc2 or enc}")
                score += 2
            else:
                findings.append("No Content-Encoding compression observed")
        consistency = 0
        for e in self.endpoints:
            if isinstance(e["status"], int) and e["status"] < 400:
                if "json" in (e.get("content_type") or ""):
                    consistency += 1
        if consistency >= 2:
            findings.append(f"JSON content type consistent across {consistency} endpoints")
            score += 2
        elif consistency == 1:
            score += 1
            findings.append("JSON used on discovered successful endpoints")
        self.raw["content_encoding"] = enc2 if r4 is not None and r4.headers.get("Content-Encoding") else enc
        return self.category("response", "Response Quality", 10, max(score, 0), findings)

    def check_performance(self):
        findings = []
        score = 0
        times = []
        for _ in range(3):
            r = self.req("GET", "/")
            if r is not None:
                try:
                    times.append(r.elapsed.total_seconds())
                except Exception:
                    pass
        avg = (sum(times) / len(times)) if times else None
        if avg is not None:
            ms = avg * 1000
            findings.append(f"Average response time over 3 requests: {ms:.0f} ms")
            if avg < 0.2:
                score += 3
                findings.append("Excellent server response latency (<200 ms)")
            elif avg < 0.5:
                score += 2
                findings.append("Good server response latency (<500 ms)")
            elif avg < 1.0:
                score += 1
                findings.append("Moderate response latency (<1 s)")
            else:
                findings.append("Slow response latency (>=1 s); consider caching/CDN")
        else:
            findings.append("Could not measure response latency")
        r = self.req("GET", "/", headers={"Accept-Encoding": "gzip, deflate, br"})
        enc = r.headers.get("Content-Encoding", "") if r is not None else ""
        if enc:
            score += 2
            findings.append(f"Compression active: {enc}")
            if "br" in enc:
                findings.append("Brotli compression provides best-in-class savings")
        else:
            findings.append("No Content-Encoding compression on root response")
        if r is not None:
            cc = r.headers.get("Cache-Control", "")
            if cc:
                score += 1
                findings.append(f"Cache-Control present: {cc[:80]}")
            else:
                findings.append("No Cache-Control header on root response")
            if r.headers.get("ETag"):
                score += 1
                findings.append("ETag supplied for validators/revalidation")
            if r.headers.get("Age") or r.headers.get("Last-Modified") or r.headers.get("Date"):
                score += 1
                findings.append("Freshness/validator metadata (Age/Last-Modified/Date) present")
            try:
                ver = r.raw.version
                if ver >= 11:
                    score += 1
                    findings.append(f"Modern HTTP transport detected (HTTP/{ver // 10}.{ver % 10})")
            except Exception:
                pass
            conn = r.headers.get("Connection", "")
            if conn.lower() != "close":
                score += 1
                findings.append("Persistent connections in use (no Connection: close)")
        self.raw["avg_response_ms"] = round(avg * 1000, 1) if avg is not None else None
        return self.category("performance", "Performance Analysis", 10, max(score, 0), findings)

    def check_reliability(self):
        findings = []
        score = 0
        sample_paths = []
        for e in self.endpoints:
            if e["method"] == "GET" and isinstance(e.get("status"), int) and e["status"] < 400:
                sample_paths.append(e["path"])
        sample_paths = list(dict.fromkeys(sample_paths))[:5]
        if not sample_paths:
            sample_paths = ["/"]
        errors = 0
        tries = 0
        for p in sample_paths:
            r = self.req("GET", p)
            tries += 1
            if r is None:
                errors += 1
                continue
            if r.status_code >= 500:
                errors += 1
        err_rate = (errors / tries) if tries else 1.0
        findings.append(f"Sampled {tries} endpoints; transport/server failures: {errors} ({err_rate * 100:.0f}%)")
        if err_rate == 0:
            score += 3
            findings.append("No 5xx or transport failures during sampling")
        elif err_rate < 0.3:
            score += 1
            findings.append("Intermittent failures observed during sampling")
        else:
            findings.append("High failure rate during sampling; investigate stability")

        r1 = self.req("GET", "/")
        r2 = self.req("GET", "/")
        if r1 is not None and r2 is not None:
            if r1.status_code == r2.status_code:
                score += 2
                findings.append("Repeated requests return consistent status codes")
            else:
                findings.append(f"Inconsistent status codes on repeat: {r1.status_code} vs {r2.status_code}")
            ct1 = r1.headers.get("Content-Type", "")
            ct2 = r2.headers.get("Content-Type", "")
            if ct1 and ct1 == ct2:
                score += 1
                findings.append("Content-Type stable across repeated requests")
            if r1.headers.get("Date") and r2.headers.get("Date"):
                score += 1
                findings.append("Server Date header present (clock/infra sane)")
            try:
                if r1.raw.version >= 11:
                    score += 1
                    findings.append("HTTP/1.1+ transport (persistent, ordered responses)")
            except Exception:
                pass
            if r1.status_code == r2.status_code and (r1.text or "")[:5000] == (r2.text or "")[:5000]:
                score += 1
                findings.append("Response payloads stable across retries (idempotent reads)")

        miss = "/apianalyzer-reliability-" + str(int(time.time()))
        m1 = self.req("GET", miss)
        m2 = self.req("GET", miss)
        if m1 is not None and m2 is not None and m1.status_code == m2.status_code == 404:
            score += 1
            findings.append("Missing-resource handling stable (404 both attempts)")

        ok = sum(1 for e in self.endpoints if isinstance(e.get("status"), int) and e["status"] < 400)
        total = len(self.endpoints) or 1
        avail = ok / total
        findings.append(f"Discovered endpoint availability: {ok}/{total} ({avail * 100:.0f}%)")
        if avail >= 0.8:
            score += 1
        return self.category("reliability", "Reliability Analysis", 10, max(score, 0), findings)

    def check_security(self):
        findings = []
        score = 0
        r = self.req("GET", "/")
        if r is None:
            findings.append("Root unreachable; cannot evaluate security headers")
            return self.category("security", "Security Headers", 10, 0, findings)
        headers = {k.lower(): v for k, v in r.headers.items()}
        cors = {k: v for k, v in r.headers.items() if k.lower().startswith("access-control-")}
        if cors:
            findings.append(f"CORS headers: {', '.join(cors.keys())}")
            score += 1
        present = []
        missing = []
        for h, why in self.SECURITY_HEADERS.items():
            if h.lower() in headers:
                present.append(f"{h}={headers[h.lower()][:60]}")
                findings.append(f"OK {h} ({why})")
            else:
                missing.append(h)
                findings.append(f"Missing {h} ({why})")
        essential = ["x-content-type-options", "x-frame-options", "content-security-policy", "strict-transport-security"]
        got = sum(1 for h in essential if h in headers)
        score += got * 1.5
        if missing:
            findings.append(f"Recommendation: add {', '.join(missing[:4])}")
        if "strict-transport-security" in headers:
            hsts = headers["strict-transport-security"]
            if "max-age=" in hsts:
                try:
                    age = int(re.search(r"max-age=(\d+)", hsts).group(1))
                    if age >= 31536000:
                        score += 0.5
                        findings.append("HSTS max-age is at least one year")
                    elif age < 1000:
                        findings.append("HSTS max-age is very short")
                except Exception:
                    pass
            if "includesubdomains" not in hsts.lower():
                findings.append("HSTS missing includeSubDomains")
        if cors:
            score += 1
        self.raw["security_headers_present"] = present
        self.raw["security_headers_missing"] = missing
        return self.category("security", "Security Headers", 10, max(score, 0), findings)

    def check_docs(self):
        findings = []
        score = 0
        spec = None
        spec_path = ""
        short_t = min(self.timeout, 5)
        for p in ("/openapi.json", "/swagger.json", "/v3/api-docs", "/v2/api-docs", "/api-docs", "/swagger/v1/swagger.json"):
            r = self.req("GET", p, timeout=short_t)
            if r is not None and r.status_code == 200 and ("json" in r.headers.get("Content-Type", "") or r.text.strip().startswith("{")):
                try:
                    data = r.json()
                    if isinstance(data, dict) and ("swagger" in data or "openapi" in data or "paths" in data):
                        spec = (p, data)
                        spec_path = p
                        findings.append(f"Machine-readable spec at {p}")
                        score += 2
                        break
                except Exception:
                    pass
            elif r is not None and r.status_code in (401, 403) and not spec_path:
                findings.append(f"Spec path requires auth: {p} ({r.status_code})")
                score += 0.5
                spec_path = p
                break
        spec_blob = ""
        if spec:
            p, data = spec
            paths = data.get("paths", {})
            if paths:
                findings.append(f"Spec documents {len(paths)} paths")
                score += 1
            desc = data.get("info", {}).get("description") or data.get("info", {}).get("title") or ""
            if desc:
                findings.append("Spec includes info/description metadata")
                score += 0.5
            examples = json.dumps(data)[:200000]
            spec_blob = examples
            if '"example"' in examples or '"examples"' in examples:
                findings.append("Spec contains example values")
                score += 1
            elif re.search(r'"(requestBody|responses)"', examples):
                findings.append("Spec includes request/response sections")
                score += 0.5
            ver = data.get("openapi") or data.get("swagger") or ""
            if ver:
                findings.append(f"Spec version: {ver}")
            if '"deprecated": true' in examples or '"deprecated":true' in examples:
                findings.append("Spec marks operations as deprecated (explicit deprecation policy)")
            if re.search(r"changelog|migration|upgrade", examples, re.I):
                findings.append("Spec/docs reference migration or upgrade guidance")
        elif not spec_path:
            findings.append("No OpenAPI/Swagger specification found at common locations")
        rdocs = self.req("GET", "/docs")
        if rdocs is not None and rdocs.status_code == 200 and len(rdocs.text) > 500:
            soup = BeautifulSoup(rdocs.text[:200000], "html.parser")
            text = soup.get_text(" ", strip=True)
            if len(text) > 200:
                findings.append(f"Human docs page present (/docs, ~{len(text)} chars of text)")
                score += 1
            if "curl" in rdocs.text.lower() or "example" in rdocs.text.lower() or "GET /" in rdocs.text:
                findings.append("Docs include example requests")
                score += 0.5
        rredoc = self.req("GET", "/redoc")
        if rredoc is not None and rredoc.status_code == 200:
            findings.append("ReDoc UI available")
            score += 0.5
        rsw = self.req("GET", "/swagger-ui.html")
        if rsw is not None and rsw.status_code == 200:
            findings.append("Swagger UI available")
            score += 0.5
        if score == 0:
            findings.append("Recommendation: publish an OpenAPI spec and human-readable docs with examples")
        self.raw["openapi_spec_path"] = spec_path
        self.raw["spec_has_request_bodies"] = bool(spec_blob and "requestBody" in spec_blob)
        return self.category("docs", "Documentation Quality", 6, max(score, 0), findings)

    def check_errors(self):
        findings = []
        score = 0
        r = self.req("GET", "/apianalyzer-missing-" + str(int(time.time())))
        if r is None:
            findings.append("Endpoint unreachable; cannot evaluate error handling")
            return self.category("errors", "Error Handling", 5, 0, findings)
        text = r.text[:100000] if r.text else ""
        ct = r.headers.get("Content-Type", "")
        quality = False
        if "json" in ct:
            try:
                d = r.json()
                if isinstance(d, dict):
                    keys = set(d.keys())
                    if keys & {"error", "message", "code", "status", "errors", "detail", "title"}:
                        quality = True
                        findings.append(f"Structured error JSON keys: {sorted(keys)[:8]}")
            except Exception:
                pass
        if quality:
            score += 2
        else:
            findings.append("Error body lacks a clear structured message")
        stack_pat = [
            r"Traceback \(most recent call last\)",
            r'File ".*?", line \d+',
            r"at [a-zA-Z0-9_.]+\([a-zA-Z0-9_.]+:\d+\)",
            r"System\.[A-Za-z]+Exception",
            r"java\.lang\.",
            r"SQLSTATE\[",
            r"PDOException",
            r"Stack trace:",
            r"django\.core",
            r"werkzeug",
            r"Internal Server Error",
        ]
        leaked = [p for p in stack_pat if re.search(p, text, re.I)]
        if leaked:
            findings.append(f"Possible stack/implementation detail exposure: {leaked[:3]}")
        else:
            findings.append("No stack trace or framework fingerprint found in 404 body")
            score += 2
        r405 = self.req("DELETE", "/")
        if r405 is not None:
            if r405.status_code == 405:
                findings.append("Method not allowed handled with 405")
                score += 1
            elif r405.status_code in (400, 403, 404):
                findings.append(f"DELETE / returned {r405.status_code}")
                score += 0.5
            else:
                findings.append(f"DELETE / returned {r405.status_code}")
        r500 = self.req("POST", "/", data="{bad", headers={"Content-Type": "application/json"})
        if r500 is not None and r500.status_code >= 500:
            body = (r500.text or "")[:3000]
            if re.search(r"traceback|stack|exception", body, re.I):
                findings.append("5xx response leaks exception details")
            else:
                findings.append(f"Server error {r500.status_code} without obvious detail leak")
                score += 0.5
        msg_words = ["message", "error", "detail", "title", "code"]
        hits = [w for w in msg_words if w in text.lower()]
        if hits:
            findings.append(f"Error payload contains human-readable fields: {hits}")
            score += 0.5
        return self.category("errors", "Error Handling", 5, max(score, 0), findings)

    @staticmethod
    def _infer_type_name(v):
        if isinstance(v, bool):
            return "boolean"
        if isinstance(v, int):
            return "integer"
        if isinstance(v, float):
            return "number"
        if isinstance(v, str):
            return "string"
        if isinstance(v, list):
            return "array"
        if isinstance(v, dict):
            return "object"
        if v is None:
            return "null"
        return "unknown"

    def _infer_schema(self, v, depth=0, max_depth=3):
        if isinstance(v, dict):
            node = {"type": "object"}
            if depth < max_depth:
                node["fields"] = {
                    str(k): self._infer_schema(val, depth + 1, max_depth)
                    for k, val in list(v.items())[:25]
                }
            return node
        if isinstance(v, list):
            node = {"type": "array"}
            if v:
                node["items"] = self._infer_schema(v[0], depth + 1, max_depth)
                node["sample_size"] = len(v)
            return node
        return {"type": self._infer_type_name(v)}

    def infer_schemas(self):
        response_schemas = {}
        request_hints = {
            "accepted_content_types": ["application/json"],
            "auth_type": self.auth_type,
            "request_body_documented": bool(self.raw.get("spec_has_request_bodies")),
        }
        paths = []
        for e in self.endpoints:
            ct = (e.get("content_type") or "").lower()
            if "json" in ct and isinstance(e.get("status"), int) and e["status"] < 400 and e["method"] == "GET":
                paths.append(e["path"])
        for p in list(dict.fromkeys(paths))[:3]:
            r = self.req("GET", p)
            if r is None:
                continue
            try:
                data = r.json()
                response_schemas[p] = self._infer_schema(data)
            except Exception:
                continue
        self.raw["response_schemas"] = response_schemas
        self.raw["request_schema_hints"] = request_hints

    @staticmethod
    def _classify_finding(f):
        fl = f.lower()
        bad_kw = ("missing", "no ", "not ", "absent", "leak", "insecure", "recommend", "without", "disabled", "inconclusive", "slow", "failed", "risky", "expired")
        good_kw = ("ok ", "correct", "enforced", "present", "active", "supported", "protected", "configured", "consistent", "rejected correctly", "alive", "available", "stable", "excellent", "good ")
        if fl.startswith("ok "):
            return "ok"
        if any(w in fl for w in bad_kw):
            return "issue"
        if any(w in fl for w in good_kw):
            return "ok"
        return "neutral"

    def run(self):
        self.results = []
        checks = [
            self.check_endpoints,
            self.check_rest,
            self.check_versioning,
            self.check_realtime,
            self.check_query_features,
            self.check_graphql,
            self.check_auth,
            self.check_rate_limit,
            self.check_validation,
            self.check_response,
            self.check_performance,
            self.check_reliability,
            self.check_security,
            self.check_docs,
            self.check_errors,
        ]
        for fn in checks:
            try:
                self.results.append(fn())
            except Exception as e:
                self.results.append(self.category("error", fn.__name__, 0, 0, [f"Check failed: {type(e).__name__}: {e}"]))
        try:
            self.infer_schemas()
        except Exception:
            pass
        return self.summary()

    def _pillars(self, weighted):
        by = {i["key"]: i for i in weighted}
        pillars = {}
        for name, keys in PILLARS.items():
            ks = [k for k in keys if k in by]
            num = sum(by[k]["score"] for k in ks)
            den = sum(by[k]["max"] for k in ks)
            pctv = (num / den * 100) if den else 0
            pillars[name] = {"score": round(pctv, 1), "grade": grade_for(pctv, 100)}
        return pillars

    def _analysis_block(self, weighted):
        by = {i["key"]: i for i in weighted}

        def entry(key, extra=None):
            r = by.get(key) or {}
            d = {
                "score": r.get("score", 0),
                "max": r.get("max", 0),
                "grade": r.get("grade", "F"),
            }
            if extra:
                d.update(extra)
            return d

        return {
            "performance": entry("performance", {
                "avg_response_ms": self.raw.get("avg_response_ms"),
                "compression": self.raw.get("content_encoding") or "",
            }),
            "reliability": entry("reliability", {
                "availability_note": "see Reliability Analysis findings",
            }),
            "scalability": entry("rate_limit", {
                "pagination_styles": self.raw.get("pagination_styles", []),
                "filtering_supported": self.raw.get("filtering_supported", False),
                "sorting_supported": self.raw.get("sorting_supported", False),
                "field_selection_supported": self.raw.get("field_selection_supported", False),
            }),
            "security": entry("security", {
                "auth_grade": (by.get("auth") or {}).get("grade", "F"),
                "cors_present": bool(self.raw.get("cors_headers")),
                "headers_missing": self.raw.get("security_headers_missing", []),
            }),
            "schema": {
                "response_schema_paths": list((self.raw.get("response_schemas") or {}).keys()),
                "request_hints": self.raw.get("request_schema_hints", {}),
            },
        }

    def summary(self):
        weighted = []
        for r in self.results:
            key = r.get("key", "")
            nat = r.get("max") or 0
            weight = WEIGHTS.get(key, nat)
            item = dict(r)
            item["natural_score"] = r.get("score", 0)
            item["natural_max"] = nat
            if nat > 0 and weight > 0:
                frac = max(0.0, min(1.0, (r.get("score") or 0) / nat))
                wscore = round(frac * weight, 1)
            else:
                wscore = 0.0
            item["max"] = weight
            item["score"] = wscore
            item["grade"] = grade_for(wscore, weight) if weight > 0 else "F"
            weighted.append(item)
        raw_total = sum(i["score"] for i in weighted)
        maximum = sum(i["max"] for i in weighted)
        total = (raw_total / maximum * 100) if maximum else 0
        g = grade_for(total, 100)
        report = {
            "tool": f"APIAnalyzer v{VERSION}",
            "target": self.url,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "total_score": round(total, 1),
            "max_score": 100,
            "raw_total": round(raw_total, 1),
            "raw_max": maximum,
            "percentage": round(total, 1),
            "grade": g,
            "categories": weighted,
            "endpoints": self.endpoints,
            "pillars": self._pillars(weighted),
            "analysis": self._analysis_block(weighted),
            "schemas": self.raw.get("response_schemas", {}),
            "request_schema_hints": self.raw.get("request_schema_hints", {}),
            "api_versions": self.raw.get("api_versions", []),
            "breaking_change_hints": self.raw.get("breaking_change_hints", []),
            "recommendations": [],
        }
        report["recommendations"] = self.build_recommendations(report)
        return report

    @staticmethod
    def _prio_color(p):
        if p == "HIGH":
            return C.RED
        if p == "MEDIUM":
            return C.YELLOW
        if p == "LOW":
            return C.CYAN
        return C.GREEN

    def print_report(self, report):
        print()
        print(C.wrap("  SCAN SUMMARY", C.BOLD, C.WHITE))
        print(C.wrap("  " + "-" * 74, C.GRAY))
        target = report["target"]
        print(f"  {C.wrap('Target:', C.GRAY)}   {C.wrap(target, C.CYAN)}")
        print(f"  {C.wrap('Time:', C.GRAY)}     {C.wrap(report['scanned_at'], C.WHITE)}")
        print(f"  {C.wrap('Auth:', C.GRAY)}     {C.wrap(self.auth_type, C.WHITE)}")
        versions = report.get("api_versions") or []
        ver_txt = ", ".join(f"v{v}" for v in versions) if versions else "none detected"
        print(f"  {C.wrap('Versions:', C.GRAY)}  {C.wrap(ver_txt, C.WHITE)}")
        latency = self.raw.get("avg_response_ms")
        lat_txt = f"{latency} ms" if latency is not None else "n/a"
        print(f"  {C.wrap('Latency:', C.GRAY)}   {C.wrap(lat_txt, C.WHITE)}")
        print(f"  {C.wrap('Endpoints:', C.GRAY)} {C.wrap(str(len(self.endpoints)), C.WHITE)}")
        print()

        print(C.wrap("  QUALITY DASHBOARD", C.BOLD, C.WHITE))
        print(C.wrap("  " + "-" * 74, C.GRAY))
        print(gauge_line("Overall", report["percentage"]))
        for pname, pdata in (report.get("pillars") or {}).items():
            print(gauge_line(pname, pdata["score"]))
        ws = self.raw.get("websocket_paths") or []
        sse = self.raw.get("sse_paths") or []
        pag = self.raw.get("pagination_styles") or []
        extra = (
            f"  Realtime: WS {len(ws)} | SSE {len(sse)}   "
            f"Pagination: {', '.join(pag) if pag else 'none'}   "
            f"Compression: {self.raw.get('content_encoding') or 'none'}"
        )
        print(C.wrap(extra, C.GRAY))
        print()

        print(C.wrap("  CATEGORY BREAKDOWN", C.BOLD, C.WHITE))
        print(C.wrap("  " + "-" * 74, C.GRAY))
        header = f"  {'Category':<32}{'Score':>10}  {'Grade':<6}Bar"
        print(C.wrap(header, C.GRAY))
        for r in report["categories"]:
            g = r["grade"]
            gc = grade_color(g)
            bar_len = 24
            filled = int(round((r["score"] / r["max"]) * bar_len)) if r["max"] else 0
            filled = max(0, min(bar_len, filled))
            bar = C.wrap("#" * filled, gc) + C.wrap("-" * (bar_len - filled), C.GRAY)
            name = r["name"]
            print(f"  {name:<32}{r['score']:>5.1f}/{r['max']:<3.0f} {C.wrap(g, gc, C.BOLD):<11}{bar}")
        print(C.wrap("  " + "-" * 74, C.GRAY))
        total = report["total_score"]
        maximum = report["max_score"]
        pct = report["percentage"]
        g = report["grade"]
        gc = grade_color(g)
        score_line = f"  TOTAL: {total:.1f} / {maximum}  ({pct:.1f}%)   GRADE: {g}"
        print(C.wrap(score_line, C.BOLD, gc))
        print()

        schemas = report.get("schemas") or {}
        if schemas:
            print(C.wrap("  SCHEMA INFERENCE", C.BOLD, C.WHITE))
            print(C.wrap("  " + "-" * 74, C.GRAY))
            for pth, sch in list(schemas.items())[:3]:
                fields = sch.get("fields") or {}
                if fields:
                    parts = []
                    for fname, fsch in list(fields.items())[:8]:
                        parts.append(f"{fname}:{fsch.get('type', '?')}")
                    print(f"  {C.wrap(pth, C.CYAN)} -> {', '.join(parts)}")
                else:
                    print(f"  {C.wrap(pth, C.CYAN)} -> {sch.get('type', '?')}")
            hints = report.get("request_schema_hints") or {}
            hint_txt = f"request JSON={hints.get('accepted_content_types')} auth={hints.get('auth_type')} spec_bodies={hints.get('request_body_documented')}"
            print(C.wrap(f"  Request hints: {hint_txt}", C.GRAY))
            print()

        print(C.wrap("  API ENDPOINT INVENTORY", C.BOLD, C.WHITE))
        print(C.wrap("  " + "-" * 74, C.GRAY))
        if self.endpoints:
            print(f"  {'Method':<10}{'Status':<10}{'Path':<46}Content-Type")
            for e in self.endpoints:
                st = str(e["status"])
                sc = C.GREEN if isinstance(e["status"], int) and e["status"] < 400 else C.YELLOW if isinstance(e["status"], int) and e["status"] < 500 else C.RED
                path = e["path"][:45]
                ct = (e.get("content_type") or "")[:28]
                print(f"  {C.wrap(e['method'], C.MAGENTA, C.BOLD):<10}{C.wrap(st, sc):<10}{path:<46}{ct}")
        else:
            print(C.wrap("  No endpoints discovered.", C.YELLOW))
        print()

        print(C.wrap("  SECURITY ASSESSMENT", C.BOLD, C.WHITE))
        print(C.wrap("  " + "-" * 74, C.GRAY))
        sec = next((r for r in report["categories"] if r["key"] == "security"), None)
        auth = next((r for r in report["categories"] if r["key"] == "auth"), None)
        rl = next((r for r in report["categories"] if r["key"] == "rate_limit"), None)
        val = next((r for r in report["categories"] if r["key"] == "validation"), None)
        ok_c = warn_c = issue_c = 0
        for block in (sec, auth, rl, val):
            if not block:
                continue
            gc = grade_color(block["grade"])
            tag = f"[{block['score']}/{block['max']}] {block['grade']}"
            print(f"  {C.wrap(block['name'], C.BOLD)} {C.wrap(tag, gc)}")
            for f in block["findings"]:
                cls = self._classify_finding(f)
                if cls == "issue":
                    mark, color = "*", C.RED
                    issue_c += 1
                elif cls == "ok":
                    mark, color = "+", C.GREEN
                    ok_c += 1
                else:
                    mark, color = "-", C.GRAY
                    warn_c += 1
                print(f"    {C.wrap(mark, color)} {f}")
            print()
        print(C.wrap(f"  Summary: {ok_c} positive | {warn_c} neutral | {issue_c} issues", C.GRAY))
        missing_hdrs = self.raw.get("security_headers_missing") or []
        cors = self.raw.get("cors_headers") or {}
        origin = str(cors.get("Access-Control-Allow-Origin", cors.get("access-control-allow-origin", "")) or "none")
        print(C.wrap(f"  Headers missing: {', '.join(missing_hdrs) if missing_hdrs else 'none'}", C.GRAY))
        print(C.wrap(f"  CORS origin: {origin} | Rate signals: {'yes' if self.raw.get('rate_limit_signals') else 'no'}", C.GRAY))
        print()

        print(C.wrap("  RECOMMENDATIONS", C.BOLD, C.WHITE))
        print(C.wrap("  " + "-" * 74, C.GRAY))
        recs = report.get("recommendations") or self.build_recommendations(report)
        if recs:
            for i, rec in enumerate(recs, 1):
                prio = rec["priority"] if isinstance(rec, dict) else "INFO"
                text = rec["text"] if isinstance(rec, dict) else str(rec)
                pc = self._prio_color(prio)
                print(f"  {C.wrap(str(i) + '.', C.YELLOW, C.BOLD)} {C.wrap('[' + prio + ']', pc, C.BOLD)} {text}")
        else:
            print(C.wrap("  No major issues found. Keep up the good work.", C.GREEN))
        print()

    def build_recommendations(self, report):
        items = []
        by = {r["key"]: r for r in report["categories"]}

        def frac(key):
            r = by.get(key) or {}
            mx = r.get("max") or 0
            return (r.get("score", 0) / mx) if mx else 1.0

        def add(key, threshold, text):
            f = frac(key)
            if f < threshold:
                pr = "HIGH" if f < 0.5 else "MEDIUM" if f < 0.75 else "LOW"
                items.append({"priority": pr, "text": text, "ratio": round(f, 3)})

        add("endpoints", 0.67, "Publish discoverable API and documentation endpoints (/api, /docs, /openapi.json).")
        add("rest", 0.67, "Adopt consistent HTTP methods, status codes, versioning, and content negotiation.")
        add("versioning", 0.6, "Adopt explicit API versioning (URL or header) with Deprecation/Sunset headers and a changelog.")
        add("realtime", 0.5, "If live updates are needed, expose WebSocket or SSE endpoints with documented contracts.")
        add("query", 0.6, "Support pagination (offset/page/cursor), filtering, sorting, and sparse fieldsets on list endpoints.")
        add("graphql", 0.6, "If GraphQL is used, disable introspection in production and enforce query depth/complexity limits.")
        add("auth", 0.67, "Enforce authentication on sensitive routes; use short-lived JWTs and strict CORS.")
        cors = self.raw.get("cors_headers") or {}
        origin = str(cors.get("Access-Control-Allow-Origin", cors.get("access-control-allow-origin", "")))
        if origin == "*":
            items.append({"priority": "HIGH", "text": "Replace Access-Control-Allow-Origin: * with an explicit allowlist of trusted origins.", "ratio": 0.0})
        add("rate_limit", 0.6, "Add rate limiting with X-RateLimit-* headers and 429 + Retry-After responses.")
        add("validation", 0.6, "Validate Content-Type, payload size, parameters, and file uploads on every entry point.")
        add("response", 0.6, "Return consistent JSON, structured errors, pagination metadata, and compressed responses.")
        add("performance", 0.6, "Reduce response latency; enable compression, caching headers, and HTTP/1.1+ keep-alive.")
        add("reliability", 0.6, "Stabilize error rates: eliminate 5xx flakiness and keep repeated responses consistent.")
        add("security", 0.7, "Add missing security headers: CSP, HSTS, X-Content-Type-Options, X-Frame-Options.")
        add("docs", 0.6, "Ship an OpenAPI specification with examples and a human-readable docs portal.")
        add("errors", 0.6, "Return machine-readable error codes without stack traces or internal details.")
        hints = self.raw.get("breaking_change_hints") or []
        if hints:
            items.append({"priority": "MEDIUM", "text": f"Breaking-change risk detected ({hints[0]}); publish migration notes before rolling out.", "ratio": 0.4})
        if not items:
            items.append({"priority": "INFO", "text": "Overall quality is strong; schedule periodic re-scans after each release.", "ratio": 1.0})
        items.sort(key=lambda it: (PRIORITY_ORDER.get(it["priority"], 9), it["ratio"]))
        return items

    def export(self, fmt, report, out_dir=None):
        out_dir = out_dir or os.getcwd()
        host = (self.parsed.netloc or "target").replace(":", "_")
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(out_dir, f"apianalyzer_{host}_{stamp}")
        formats = ["json", "csv", "html"] if fmt == "all" else [fmt]
        written = []
        for f in formats:
            if f == "json":
                path = base + ".json"
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(report, fh, indent=2, default=str)
                written.append(path)
            elif f == "csv":
                path = base + ".csv"
                with open(path, "w", encoding="utf-8", newline="") as fh:
                    w = csv.writer(fh)
                    w.writerow(["section", "key", "name_or_path", "score", "max", "grade_or_status", "detail"])
                    for name, pdata in (report.get("pillars") or {}).items():
                        w.writerow(["pillar", name.lower(), name, pdata["score"], 100, pdata["grade"], ""])
                    for r in report["categories"]:
                        w.writerow(["category", r["key"], r["name"], r["score"], r["max"], r["grade"], ""])
                        for finding in r["findings"]:
                            w.writerow(["finding", r["key"], "", "", "", "", finding])
                    for e in report["endpoints"]:
                        w.writerow(["endpoint", e["method"], e["path"], "", "", e["status"], e.get("content_type", "")])
                    for rec in (report.get("recommendations") or []):
                        if isinstance(rec, dict):
                            w.writerow(["recommendation", rec.get("priority", ""), "", "", "", "", rec.get("text", "")])
                        else:
                            w.writerow(["recommendation", "", "", "", "", "", str(rec)])
                    w.writerow(["total", "", "TOTAL", report["total_score"], report["max_score"], report["grade"], report["percentage"]])
                written.append(path)
            elif f == "html":
                path = base + ".html"
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(self.render_html(report))
                written.append(path)
        return written

    def _gauge_svg(self, pct, label, color):
        pct = max(0.0, min(100.0, float(pct)))
        radius = 40
        circumference = 3.141592653589793 * radius
        dash = circumference * pct / 100.0
        label_esc = str(label).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return (
            "<div class='gauge'>"
            "<svg viewBox='0 0 100 60' width='130' height='78' role='img' aria-label='"
            + label_esc
            + " gauge'>"
            "<path d='M 10 50 A 40 40 0 0 1 90 50' fill='none' stroke='#21262d' stroke-width='10' stroke-linecap='round'/>"
            f"<path d='M 10 50 A 40 40 0 0 1 90 50' fill='none' stroke='{color}' stroke-width='10' stroke-linecap='round' stroke-dasharray='{dash:.1f} {circumference:.1f}'/>"
            f"<text x='50' y='46' text-anchor='middle' fill='{color}' font-size='16' font-weight='700'>{pct:.0f}%</text>"
            "</svg>"
            f"<div class='gauge-label'>{label_esc}</div>"
            "</div>"
        )

    def render_html(self, report):
        gc = report["grade"]

        def esc(s):
            return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))

        rows = []
        for r in report["categories"]:
            pctv = (r["score"] / r["max"] * 100) if r["max"] else 0
            color = pct_color(pctv)
            findings_html = "".join(f"<li>{esc(f)}</li>" for f in r["findings"])
            rows.append(
                f"<div class='cat'><div class='cat-head'><span class='cat-name'>{esc(r['name'])}</span>"
                f"<span class='cat-score' style='color:{color}'>{r['score']}/{r['max']} <em>{esc(r['grade'])}</em></span></div>"
                f"<div class='bar'><div class='bar-fill' style='width:{pctv:.0f}%;background:{color}'></div></div>"
                f"<ul class='findings'>{findings_html}</ul></div>"
            )
        eps = []
        for e in report["endpoints"]:
            st = str(e["status"])
            cls = "ok" if isinstance(e["status"], int) and e["status"] < 400 else "warn" if isinstance(e["status"], int) and e["status"] < 500 else "bad"
            eps.append(
                f"<tr><td class='m'>{esc(e['method'])}</td><td class='{cls}'>{esc(st)}</td>"
                f"<td>{esc(e['path'])}</td><td class='dim'>{esc(e.get('content_type') or '')}</td></tr>"
            )
        recs = report.get("recommendations") or self.build_recommendations(report)
        rec_html = ""
        for rec in recs:
            if isinstance(rec, dict):
                prio = rec.get("priority", "INFO")
                text = rec.get("text", "")
            else:
                prio = "INFO"
                text = str(rec)
            rec_html += (
                f"<li><span class='pri pri-{esc(str(prio).lower())}'>{esc(prio)}</span>{esc(text)}</li>"
            )
        total_pct = report["percentage"]
        grade_color_map = {"A+": "#3ddc97", "A": "#3ddc97", "B": "#4cc9f0", "C": "#ffd166", "D": "#f72585", "F": "#ff4d6d"}
        gcol = grade_color_map.get(gc, "#ffffff")
        overall_gauge = self._gauge_svg(report["percentage"], "Overall", pct_color(report["percentage"]))
        pillar_gauges = "".join(
            self._gauge_svg(v["score"], k, pct_color(v["score"]))
            for k, v in (report.get("pillars") or {}).items()
        )
        schemas = report.get("schemas") or {}
        if schemas:
            schema_json = esc(json.dumps(schemas, indent=2, default=str)[:6000])
            schema_html = f"<h2>Schema Inference</h2><pre class='schema'>{schema_json}</pre>"
        else:
            schema_html = ""
        analysis = report.get("analysis") or {}
        perf = analysis.get("performance") or {}
        scal = analysis.get("scalability") or {}
        lat = perf.get("avg_response_ms")
        lat_txt = f"{lat} ms" if lat is not None else "n/a"
        metrics = [
            ("Latency", lat_txt),
            ("Compression", perf.get("compression") or "none"),
            ("Versions", ", ".join(f"v{v}" for v in (report.get("api_versions") or [])) or "none"),
            ("Pagination", ", ".join(scal.get("pagination_styles") or []) or "none"),
            ("Endpoints", str(len(report["endpoints"]))),
        ]
        metrics_html = "".join(
            f"<div class='card'><div class='label'>{esc(k)}</div><div class='value' style='font-size:16px'>{esc(v)}</div></div>"
            for k, v in metrics
        )
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>APIAnalyzer Report - {esc(report['target'])}</title>
<style>
:root {{
  --bg: #0d1117; --panel: #161b22; --border: #30363d; --text: #e6edf3;
  --dim: #8b949e; --accent: #58a6ff; --green: #3ddc97;
}}
* {{ box-sizing: border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text); font-family: "Segoe UI", system-ui, sans-serif; line-height:1.5; }}
header {{ background:linear-gradient(180deg,#161b22, #0d1117); border-bottom:1px solid var(--border); padding:32px 24px; }}
.wrap {{ max-width: 980px; margin: 0 auto; }}
h1 {{ margin:0 0 6px; font-size:26px; letter-spacing:0.5px; }}
.sub {{ color:var(--dim); font-size:14px; }}
.scoreboard {{ display:flex; gap:18px; flex-wrap:wrap; margin-top:22px; }}
.card {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px 20px; min-width:140px; }}
.card .label {{ color:var(--dim); font-size:12px; text-transform:uppercase; letter-spacing:1px; }}
.card .value {{ font-size:28px; font-weight:700; margin-top:4px; }}
main {{ padding: 28px 24px 60px; }}
h2 {{ font-size:16px; text-transform:uppercase; letter-spacing:1.5px; color:var(--accent); margin:34px 0 14px; }}
.dash {{ display:flex; gap:26px; flex-wrap:wrap; align-items:flex-end; background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:18px; }}
.gauge {{ text-align:center; }}
.gauge-label {{ color:var(--dim); font-size:12px; text-transform:uppercase; letter-spacing:1px; margin-top:4px; }}
.metrics {{ display:flex; gap:14px; flex-wrap:wrap; margin-top:14px; }}
.cat {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px 18px; margin-bottom:14px; }}
.cat-head {{ display:flex; justify-content:space-between; align-items:baseline; margin-bottom:10px; }}
.cat-name {{ font-weight:600; }}
.cat-score {{ font-variant-numeric: tabular-nums; font-weight:700; }}
.cat-score em {{ font-style:normal; opacity:0.85; font-size:12px; margin-left:6px; }}
.bar {{ height:8px; background:#21262d; border-radius:6px; overflow:hidden; }}
.bar-fill {{ height:100%; border-radius:6px; }}
.findings {{ margin:12px 0 0; padding-left:18px; color:var(--dim); font-size:13.5px; }}
.findings li {{ margin:3px 0; }}
table {{ width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--border); border-radius:10px; overflow:hidden; }}
th, td {{ text-align:left; padding:9px 12px; font-size:13.5px; border-bottom:1px solid var(--border); }}
th {{ background:#21262d; color:var(--dim); font-weight:600; text-transform:uppercase; font-size:11px; letter-spacing:1px; }}
tr:last-child td {{ border-bottom:none; }}
td.m {{ color:#d2a8ff; font-weight:700; }}
td.ok {{ color:var(--green); }} td.warn {{ color:#ffd166; }} td.bad {{ color:#ff4d6d; }}
td.dim {{ color:var(--dim); }}
ol.recs {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px 16px 16px 38px; }}
ol.recs li {{ margin:7px 0; }}
.pri {{ display:inline-block; font-size:10px; font-weight:700; letter-spacing:1px; padding:2px 7px; border-radius:4px; margin-right:8px; vertical-align:1px; }}
.pri-high {{ background:#ff4d6d; color:#0d1117; }}
.pri-medium {{ background:#ffd166; color:#0d1117; }}
.pri-low {{ background:#4cc9f0; color:#0d1117; }}
.pri-info {{ background:#3ddc97; color:#0d1117; }}
pre.schema {{ background:#0d1117; border:1px solid var(--border); border-radius:10px; padding:14px; font-size:12.5px; overflow:auto; color:var(--dim); }}
footer {{ color:var(--dim); font-size:12px; text-align:center; padding:20px; border-top:1px solid var(--border); }}
@media (max-width:640px) {{ .scoreboard {{ flex-direction:column; }} .dash {{ flex-direction:column; align-items:stretch; }} }}
</style>
</head>
<body>
<header>
  <div class="wrap">
    <h1>APIAnalyzer <span style="color:var(--dim);font-weight:400">v{VERSION}</span></h1>
    <div class="sub">REST, GraphQL &amp; realtime API quality, security and lifecycle report</div>
    <div class="scoreboard">
      <div class="card"><div class="label">Target</div><div class="value" style="font-size:15px;word-break:break-all;color:var(--accent)">{esc(report['target'])}</div></div>
      <div class="card"><div class="label">Score</div><div class="value">{report['total_score']}<span style="font-size:15px;color:var(--dim)">/{report['max_score']}</span></div></div>
      <div class="card"><div class="label">Percent</div><div class="value">{report['percentage']}%</div></div>
      <div class="card"><div class="label">Grade</div><div class="value" style="color:{gcol}">{esc(gc)}</div></div>
      <div class="card"><div class="label">Scanned</div><div class="value" style="font-size:14px">{esc(report['scanned_at'])}</div></div>
    </div>
  </div>
</header>
<main>
  <div class="wrap">
    <h2>Quality Dashboard</h2>
    <div class='dash'>{overall_gauge}{pillar_gauges}</div>
    <div class='metrics scoreboard'>{metrics_html}</div>
    <h2>Category Breakdown</h2>
    {''.join(rows)}
    <h2>Endpoint Inventory</h2>
    <table>
      <thead><tr><th>Method</th><th>Status</th><th>Path</th><th>Content-Type</th></tr></thead>
      <tbody>{''.join(eps) if eps else '<tr><td colspan="4" class="dim">No endpoints discovered</td></tr>'}</tbody>
    </table>
    {schema_html}
    <h2>Recommendations</h2>
    <ol class="recs">{rec_html}</ol>
  </div>
</main>
<footer>Generated by APIAnalyzer v{VERSION} at {esc(report['scanned_at'])}</footer>
</body>
</html>
"""


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="apianalyzer",
        description=f"APIAnalyzer v{VERSION} - REST, GraphQL & realtime API quality, security and lifecycle analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python apianalyzer.py -u https://api.example.com\n  python apianalyzer.py -u https://api.example.com --export all -v\n  python apianalyzer.py -u https://api.example.com --auth-type bearer --api-key TOKEN --export json",
    )
    p.add_argument("-u", "--url", required=True, help="Target URL")
    p.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    p.add_argument("--export", choices=["all", "json", "csv", "html", "none"], default="none", help="Export format (default: none)")
    p.add_argument("--no-color", action="store_true", help="Disable colored output")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("--api-key", default=None, help="API key / token for authentication")
    p.add_argument("--auth-type", choices=["none", "bearer", "basic", "apikey"], default="none", help="Auth type (default: none)")
    p.add_argument("--output-dir", default=None, help="Directory for exported reports")
    p.add_argument("--version", action="version", version=f"APIAnalyzer {VERSION}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.no_color or not sys.stdout.isatty():
        C.enabled = False
    if args.auth_type != "none" and not args.api_key:
        print(C.wrap(f"error: --auth-type {args.auth_type} requires --api-key", C.RED, C.BOLD))
        return 2
    print_banner()
    print(C.wrap(f"  Target:    {args.url}", C.CYAN))
    print(C.wrap(f"  Timeout:   {args.timeout}s", C.GRAY))
    print(C.wrap(f"  Auth:      {args.auth_type}", C.GRAY))
    print(C.wrap(f"  Export:    {args.export}", C.GRAY))
    print(C.wrap(f"  Mode:      {'verbose' if args.verbose else 'normal'}", C.GRAY))
    print()
    analyzer = APIAnalyzer(
        url=args.url,
        timeout=args.timeout,
        api_key=args.api_key,
        auth_type=args.auth_type,
        verbose=args.verbose,
    )
    started = time.time()
    print(C.wrap("  Running checks", C.YELLOW, C.BOLD) + C.wrap(" ...", C.GRAY))
    report = analyzer.run()
    elapsed = time.time() - started
    report["elapsed_seconds"] = round(elapsed, 2)
    analyzer.print_report(report)
    if args.export != "none":
        try:
            written = analyzer.export(args.export, report, out_dir=args.output_dir)
            print(C.wrap("  EXPORTED FILES", C.BOLD, C.WHITE))
            for w in written:
                print(C.wrap(f"    + {w}", C.GREEN))
            print()
        except Exception as e:
            print(C.wrap(f"  Export failed: {type(e).__name__}: {e}", C.RED))
            return 1
    print(C.wrap(f"  Scan completed in {elapsed:.2f}s", C.GRAY))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
