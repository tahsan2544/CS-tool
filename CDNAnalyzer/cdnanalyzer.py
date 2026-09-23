#!/usr/bin/env python3
import argparse
import csv
import io
import json
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    import subprocess

    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

VERSION = "1.0"
TOTAL_POINTS = 100

CDN_SIGNATURES = {
    "cloudflare": ["cloudflare", "cf-ray", "cf-cache-status", "cf-request-id"],
    "fastly": ["fastly", "x-served-by", "x-fastly-request-id", "fastly-debug-digest"],
    "akamai": ["akamai", "x-akamai", "akamaighost", "server"][0:1] + ["x-akamai-transformed"],
    "aws cloudfront": ["cloudfront", "x-amz-cf-id", "x-amz-cf-pop"],
    "google cloud cdn": ["google frontend", "x-goog-", "gws"],
    "azure cdn / frontroute": ["microsoft azure", "x-azure-ref", "x-msedge-ref"],
    "keycdn": ["keycdn", "x-edge-location"],
    "stackpath": ["stackpath", "server: fps"],
    "bunnycdn": ["bunnycdn", "bunnycdn-edge"],
    "imperva/incapsula": ["incapsula", "x-cdn", "visid_incap"],
    "sucuri": ["sucuri", "x-sucuri"],
    "cdn77": ["cdn77", "x-cdn77"],
    "leaseweb": ["leaseweb"],
    "cacheFly": ["cachefly", "x-served-by: cachefly"],
    "cloudfront": ["x-amz-cf-pop"],
    "varnish": ["varnish", "x-varnish", "via: 1.1 varnish"],
    "nginx": ["nginx"],
    "litespeed": ["litespeed"],
    "apache": ["apache"],
    "iis": ["microsoft-iis"],
}

CDN_PROVIDER_HINTS = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-amz-cf-id": "AWS CloudFront",
    "x-amz-cf-pop": "AWS CloudFront",
    "x-fastly-request-id": "Fastly",
    "x-served-by": "Fastly/Edge",
    "x-akamai-transformed": "Akamai",
    "akamaighost": "Akamai",
    "x-goog-": "Google Cloud CDN",
    "x-azure-ref": "Azure CDN",
    "x-msedge-ref": "Azure Front Door",
    "keycdn": "KeyCDN",
    "bunnycdn": "BunnyCDN",
    "incapsula": "Imperva/Incapsula",
    "x-sucuri": "Sucuri",
    "cdn77": "CDN77",
    "x-varnish": "Varnish",
    "server: openresty": "OpenResty",
}

ORIGIN_EXPOSURE_HEADERS = [
    "x-origin",
    "x-host",
    "x-backend",
    "x-backend-server",
    "x-served-by-origin",
    "x-amz-request-id",
    "x-amz-id-2",
    "x-ahoy-origin",
    "x-real-ip",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-original-host",
    "backend",
    "x-server",
    "x-origin-server",
]


class Colors:
    def __init__(self, enabled=True):
        self.enabled = enabled

    def _c(self, code, text):
        if not self.enabled:
            return str(text)
        return f"\033[{code}m{text}\033[0m"

    def red(self, t):
        return self._c("31", t)

    def green(self, t):
        return self._c("32", t)

    def yellow(self, t):
        return self._c("33", t)

    def blue(self, t):
        return self._c("34", t)

    def magenta(self, t):
        return self._c("35", t)

    def cyan(self, t):
        return self._c("36", t)

    def white(self, t):
        return self._c("37", t)

    def bold(self, t):
        return self._c("1", t)

    def dim(self, t):
        return self._c("2", t)

    def bg_red(self, t):
        return self._c("41", t)

    def bg_green(self, t):
        return self._c("42", t)

    def bg_yellow(self, t):
        return self._c("43", t)

    def bg_blue(self, t):
        return self._c("44", t)

    def bg_magenta(self, t):
        return self._c("45", t)

    def bg_cyan(self, t):
        return self._c("46", t)


BANNER = r"""
   ____ _   _ ___ ____ _____ ____      _   _ ____
  / ___| | | |_ _/ ___|_   _|  _ \    | | | |  _ \
 | |   | |_| || | |     | | | |_) |   | | | | |_) |
 | |___|  _  || | |___  | | |  _ < _  | |_| |  _ <
  \____|_| |_|___\____| |_| |_| \_\  \___/|_| \_\
"""


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


def grade_color(grade, c):
    if grade in ("A+", "A"):
        return c.green(grade)
    if grade == "B":
        return c.cyan(grade)
    if grade == "C":
        return c.yellow(grade)
    if grade == "D":
        return c.magenta(grade)
    return c.red(grade)


def score_bar(score, max_score, width=20, c=None):
    if max_score <= 0:
        return ""
    filled = int(round((score / max_score) * width))
    filled = max(0, min(width, filled))
    empty = width - filled
    pct = int(round((score / max_score) * 100))
    if c is None:
        return "[" + "#" * filled + "-" * empty + f"] {score}/{max_score} ({pct}%)"
    if pct >= 90:
        col = c.green
    elif pct >= 70:
        col = c.cyan
    elif pct >= 50:
        col = c.yellow
    else:
        col = c.red
    return col("[" + "#" * filled + "-" * empty + f"] {score}/{max_score} ({pct}%)")


def resolve_cname(hostname):
    try:
        import subprocess

        out = subprocess.run(
            ["host", "-t", "CNAME", hostname],
            capture_output=True,
            text=True,
            timeout=8,
        )
        lines = []
        for line in out.stdout.splitlines():
            ll = line.lower()
            if "cname" in ll and "no cname" not in ll:
                parts = line.split()
                if len(parts) >= 4:
                    lines.append(parts[-1].rstrip("."))
        if lines:
            return lines
    except Exception:
        pass
    try:
        answers = socket.getaddrinfo(hostname, None)
        seen = []
        for a in answers:
            ip = a[4][0]
            if ip not in seen:
                seen.append(ip)
        return seen[:4]
    except Exception:
        return []


def fetch_cert_info(hostname, port=443, timeout=10):
    info = {
        "tls_version": None,
        "cipher": None,
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "sans": [],
        "ocsp_stapled": False,
        "chain_length": 0,
        "alpn": None,
        "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        try:
            ctx.set_alpn_protocols(["h3", "h2", "http/1.1"])
        except Exception:
            pass
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                info["tls_version"] = ssock.version()
                info["cipher"] = ssock.cipher()
                cert = ssock.getpeercert()
                info["alpn"] = ssock.selected_alpn_protocol()
                if cert:
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    info["subject"] = subject.get("commonName")
                    info["issuer"] = issuer.get("commonName")
                    info["sans"] = [v for k, v in cert.get("subjectAltName", ())][:10]
                    nb = cert.get("notBefore")
                    na = cert.get("notAfter")
                    if na:
                        try:
                            dt = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(
                                tzinfo=timezone.utc
                            )
                            info["not_after"] = dt.isoformat()
                            info["days_remaining"] = (dt - datetime.now(timezone.utc)).days
                        except Exception:
                            info["not_after"] = na
                    if nb:
                        info["not_before"] = nb
                    info["chain_length"] = 1
                try:
                    if hasattr(ssock, "shared_ciphers"):
                        info["cipher"] = ssock.cipher()
                except Exception:
                    pass
    except Exception as e:
        info["error"] = str(e)
    return info


def check_ocsp_stapling(hostname, timeout=8):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                try:
                    cert = ssock.getpeercert(binary_form=True)
                except Exception:
                    cert = None
        import subprocess

        cmd = [
            "openssl",
            "s_client",
            "-connect",
            f"{hostname}:443",
            "-servername",
            hostname,
            "-status",
            "-brief",
        ]
        out = subprocess.run(
            cmd,
            input=b"",
            capture_output=True,
            timeout=timeout,
        )
        text = (out.stdout or b"").decode("utf-8", "ignore") + (
            out.stderr or b""
        ).decode("utf-8", "ignore")
        if "OCSP response: no response sent" in text:
            return False
        if "OCSP Response Status:" in text or "successful" in text.lower() and "ocsp" in text.lower():
            return True
        if "Cert Status: good" in text:
            return True
    except Exception:
        return False
    return False


def detect_http_version(response):
    try:
        v = response.raw.version
        if v == 11:
            return "HTTP/1.1"
        if v == 10:
            return "HTTP/1.0"
        if v == 20 or v == 2:
            return "HTTP/2"
        if v == 30 or v == 3:
            return "HTTP/3"
        return f"HTTP/{v}"
    except Exception:
        return "unknown"


def detect_alpn_from_requests(response):
    try:
        raw = getattr(response.raw, "_original_response", None)
        if raw and hasattr(raw, "version"):
            pass
    except Exception:
        pass
    return None


def run_checks(url, timeout, verbose, c):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    scheme = parsed.scheme or "https"
    results = []
    details = {}

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
    }

    resp = None
    ttfb = None
    total_time = None
    err = None
    try:
        t0 = time.time()
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, stream=True)
        ttfb = time.time() - t0
        _ = resp.content
        total_time = time.time() - t0
    except Exception as e:
        err = str(e)

    if resp is None:
        for i, cat in enumerate(
            [
                "CDN Detection",
                "Cache Config",
                "Cache Status",
                "Edge Performance",
                "Compression",
                "HTTP Version",
                "SSL/TLS at Edge",
                "Origin Shield",
                "Purge & Invalidation",
                "Asset Delivery",
            ]
        ):
            results.append(
                {
                    "category": cat,
                    "score": 0,
                    "max": [20, 15, 10, 15, 10, 5, 10, 5, 5, 5][i],
                    "findings": [f"Request failed: {err}"],
                }
            )
        return results, {"error": err, "ttfb": None, "total_time": None, "headers": {}, "url": url}

    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    details["headers"] = hdrs
    details["url"] = resp.url
    details["ttfb"] = ttfb
    details["total_time"] = total_time
    details["status"] = resp.status_code
    details["http_version"] = detect_http_version(resp)

    # 1 CDN Detection max 20
    score = 0
    findings = []
    provider = None
    provider_sources = []
    hint_headers = [
        "cf-ray",
        "x-amz-cf-id",
        "x-amz-cf-pop",
        "x-fastly-request-id",
        "x-served-by",
        "x-akamai-transformed",
        "akamaighost",
        "x-goog-",
        "x-azure-ref",
        "x-msedge-ref",
        "keycdn",
        "bunnycdn",
        "x-sucuri",
        "cdn77",
        "x-varnish",
        "via",
        "x-cache",
        "server",
        "x-cdn",
        "x-edge-location",
        "x-cache-hits",
        "x-request-id",
        "cf-cache-status",
    ]
    for hk in hint_headers:
        for real_k, real_v in hdrs.items():
            if hk in real_k:
                blob = f"{real_k}: {real_v}".lower()
                for sig, name in CDN_PROVIDER_HINTS.items():
                    if sig.lower() in blob:
                        if provider is None:
                            provider = name
                            provider_sources.append(f"{real_k} -> {name}")
                        elif name not in provider:
                            provider_sources.append(f"{real_k} -> {name}")
    via = hdrs.get("via", "")
    server = hdrs.get("server", "")
    x_cache = hdrs.get("x-cache", "")
    x_served = hdrs.get("x-served-by", "")
    blob_all = json.dumps(hdrs).lower()
    if provider is None:
        for sig, name in CDN_PROVIDER_HINTS.items():
            if sig.lower() in blob_all:
                provider = name
                provider_sources.append(f"header match -> {name}")
                break
    if provider is None:
        for key, names in [
            ("cloudflare", "Cloudflare"),
            ("cloudfront", "AWS CloudFront"),
            ("fastly", "Fastly"),
            ("akamai", "Akamai"),
            ("google", "Google Cloud CDN"),
            ("varnish", "Varnish"),
            ("nginx", "NGINX"),
        ]:
            if key in blob_all:
                provider = names
                provider_sources.append(f"signature -> {names}")
                break
    if provider:
        score += 8
        findings.append(f"Provider identified: {provider} ({', '.join(provider_sources[:3])})")
    else:
        findings.append("No CDN provider signature found in headers")

    if any(k in hdrs for k in ("cf-ray", "x-amz-cf-pop", "x-fastly-request-id", "x-served-by", "x-akamai-transformed")):
        score += 4
        findings.append("Edge/POP marker header present")
    elif via or x_cache:
        score += 2
        findings.append("Via/X-Cache suggests intermediary caching layer")

    cname_targets = resolve_cname(hostname) if hostname else []
    details["cname"] = cname_targets
    cdn_cname = False
    for t in cname_targets:
        tl = t.lower()
        if any(
            x in tl
            for x in (
                "cloudflare",
                "cloudfront",
                "fastly",
                "akamai",
                "edgekey",
                "edgesuite",
                "akamaiedge",
                "edgecast",
                "keycdn",
                "bunnycdn",
                "cdn77",
                "stackpath",
                "imperva",
                "incapsula",
            )
        ):
            cdn_cname = True
            score += 4
            findings.append(f"CNAME points to CDN: {t}")
            break
    if not cdn_cname and cname_targets:
        findings.append(f"CNAME/resolution: {', '.join(cname_targets[:3])} (not recognized as CDN)")

    origin_headers = [h for h in ORIGIN_EXPOSURE_HEADERS if h in hdrs]
    details["origin_exposure"] = {h: hdrs[h] for h in origin_headers}
    if not origin_headers:
        score += 4
        findings.append("No origin exposure headers detected")
    else:
        findings.append(f"Potential origin exposure: {', '.join(origin_headers)}")

    if via:
        findings.append(f"Via: {via}")
    if server:
        findings.append(f"Server: {server}")
    score = min(score, 20)
    results.append({"category": "CDN Detection", "score": score, "max": 20, "findings": findings})
    details["provider"] = provider

    # 2 Cache Config max 15
    score = 0
    findings = []
    cc = hdrs.get("cache-control", "")
    etag = hdrs.get("etag")
    last_mod = hdrs.get("last-modified")
    vary = hdrs.get("vary")
    pragma = hdrs.get("pragma")
    expires = hdrs.get("expires")
    details["cache_control"] = cc
    if cc:
        score += 2
        findings.append(f"Cache-Control: {cc}")
        ccl = cc.lower()
        if "public" in ccl:
            score += 3
            findings.append("Marks response as public (cacheable by shared caches)")
        elif "private" in ccl:
            score += 1
            findings.append("Private cache directive - only browser cache")
        if "no-store" in ccl:
            score -= 3 if score >= 3 else 0
            findings.append("no-store present - disables caching")
        if "no-cache" in ccl:
            findings.append("no-cache present - revalidation required")
        if "max-age=" in ccl:
            score += 2
            findings.append("max-age defined")
        if "s-maxage=" in ccl:
            score += 3
            findings.append("s-maxage defined (shared/CDN cache TTL)")
        if "immutable" in ccl:
            score += 2
            findings.append("immutable directive present (edge-friendly)")
        if "must-revalidate" in ccl or "proxy-revalidate" in ccl:
            score += 1
            findings.append("Revalidation directive present")
    else:
        findings.append("No Cache-Control header")
    if etag:
        score += 2
        findings.append(f"ETag present: {etag[:40]}")
    if last_mod:
        score += 1
        findings.append(f"Last-Modified present: {last_mod}")
    if vary:
        score += 1
        findings.append(f"Vary: {vary}")
    if pragma:
        findings.append(f"Pragma: {pragma}")
    if expires:
        findings.append(f"Expires: {expires}")
        if not cc:
            score += 1
    if not etag and not last_mod and not cc:
        findings.append("No validators or cache directives found")
    score = max(0, min(score, 15))
    results.append({"category": "Cache Config", "score": score, "max": 15, "findings": findings})

    # 3 Cache Status max 10
    score = 0
    findings = []
    age = hdrs.get("age")
    cf_cache = hdrs.get("cf-cache-status")
    x_cache_status = hdrs.get("x-cache") or hdrs.get("x-cache-status")
    x_cache_hit = hdrs.get("x-cache-hits")
    cache_status = hdrs.get("cache-status")
    details["cache_status"] = {
        "age": age,
        "cf-cache-status": cf_cache,
        "x-cache": x_cache_status,
        "cache-status": cache_status,
    }
    status_blob = " ".join(
        str(x) for x in [cf_cache, x_cache_status, cache_status, x_cache_hit] if x
    ).upper()
    if "HIT" in status_blob and "MISS" not in status_blob.replace("HIT", ""):
        score += 5
        findings.append(f"Cache HIT confirmed: {status_blob.strip()}")
    elif "HIT" in status_blob:
        score += 4
        findings.append(f"Mixed cache status: {status_blob.strip()}")
    elif "MISS" in status_blob:
        score += 1
        findings.append(f"Cache MISS: {status_blob.strip()}")
    elif "EXPIRED" in status_blob:
        score += 2
        findings.append(f"Cache EXPIRED: {status_blob.strip()}")
    elif status_blob.strip():
        score += 2
        findings.append(f"Cache status header: {status_blob.strip()}")
    else:
        findings.append("No explicit cache status header")
    if age:
        try:
            age_v = int(age)
            score += 3
            findings.append(f"Age header: {age_v}s (object served from cache)")
            if age_v > 60:
                score += 1
                findings.append("Age > 60s indicates durable edge caching")
        except Exception:
            findings.append(f"Age: {age}")
    if cf_cache:
        findings.append(f"CF-Cache-Status: {cf_cache}")
    if x_cache_status:
        findings.append(f"X-Cache: {x_cache_status}")
    if cache_status:
        findings.append(f"Cache-Status: {cache_status}")
    score = max(0, min(score, 10))
    results.append({"category": "Cache Status", "score": score, "max": 10, "findings": findings})

    # 4 Edge Performance max 15
    score = 0
    findings = []
    ray_pop = hdrs.get("cf-ray")
    x_cache_loc = hdrs.get("x-cache") or ""
    x_served = hdrs.get("x-served-by") or ""
    x_amz_pop = hdrs.get("x-amz-cf-pop") or ""
    x_edge = hdrs.get("x-edge-location") or ""
    via_edge = via or ""
    pop = None
    if ray_pop and "-" in ray_pop:
        pop = ray_pop.split("-")[-1]
    elif x_amz_pop:
        pop = x_amz_pop
    elif x_edge:
        pop = x_edge
    elif x_served:
        pop = x_served.split(",")[0].strip()
    details["edge_pop"] = pop
    if ttfb is not None:
        ttfb_ms = ttfb * 1000
        details["ttfb_ms"] = round(ttfb_ms, 1)
        findings.append(f"TTFB: {ttfb_ms:.1f} ms, total: {total_time*1000:.1f} ms")
        if ttfb_ms < 100:
            score += 8
            findings.append("Excellent TTFB (<100ms) - likely served from edge")
        elif ttfb_ms < 200:
            score += 6
            findings.append("Good TTFB (<200ms)")
        elif ttfb_ms < 400:
            score += 4
            findings.append("Fair TTFB (<400ms)")
        elif ttfb_ms < 800:
            score += 2
            findings.append("Slow TTFB (<800ms) - possible origin fetch")
        else:
            score += 0
            findings.append("Very slow TTFB (>=800ms) - likely origin-bound")
    else:
        findings.append("TTFB unavailable")
    if pop:
        score += 3
        findings.append(f"Edge location/POP: {pop}")
    else:
        findings.append("No edge POP identifier found")
    regional = []
    if ray_pop:
        regional.append(f"cf-ray={ray_pop}")
    if x_amz_pop:
        regional.append(f"pop={x_amz_pop}")
    if x_served:
        regional.append(f"served-by={x_served}")
    if regional:
        score += 2
        findings.append(f"Regional markers: {'; '.join(regional)}")
    reuse = hdrs.get("connection") or ""
    keep_alive = hdrs.get("keep-alive")
    if "keep-alive" in reuse.lower() or keep_alive:
        score += 2
        findings.append(f"Connection reuse active ({reuse or 'keep-alive'}{', ' + keep_alive if keep_alive else ''})")
    elif "close" in reuse.lower():
        findings.append("Connection: close - no reuse")
    else:
        findings.append("Connection header not explicit (HTTP/2 multiplexing may apply)")
    score = max(0, min(score, 15))
    results.append({"category": "Edge Performance", "score": score, "max": 15, "findings": findings})

    # 5 Compression max 10
    score = 0
    findings = []
    ce = hdrs.get("content-encoding", "")
    accept_enc = hdrs.get("content-type", "")
    details["content_encoding"] = ce
    cel = ce.lower()
    if "br" in cel.split(",") or cel.strip() == "br":
        score += 5
        findings.append("Brotli (br) compression active - best-in-class ratio")
    elif "gzip" in cel:
        score += 3
        findings.append("gzip compression active")
    elif "deflate" in cel:
        score += 2
        findings.append("deflate compression active")
    elif "zstd" in cel:
        score += 4
        findings.append("zstd compression active")
    else:
        findings.append(f"Content-Encoding: {ce or 'none'}")
    ae = hdrs.get("vary", "")
    if "accept-encoding" in ae.lower():
        score += 2
        findings.append("Vary: Accept-Encoding - negotiated compression")
    if ce:
        score += 1
        findings.append("Compression applied to response")
    if "text/" in accept_enc or "json" in accept_enc or "javascript" in accept_enc:
        if not ce:
            findings.append("Compressible content-type served uncompressed")
        else:
            score += 2
            findings.append(f"Compressible type compressed: {accept_enc}")
    score = max(0, min(score, 10))
    results.append({"category": "Compression", "score": score, "max": 10, "findings": findings})

    # 6 HTTP Version max 5
    score = 0
    findings = []
    http_ver = details.get("http_version", "unknown")
    cert_info = fetch_cert_info(hostname, timeout=min(timeout, 10)) if hostname else {}
    alpn = cert_info.get("alpn")
    details["cert"] = cert_info
    details["alpn"] = alpn
    if alpn and alpn.lower() in ("h2", "h3", "h3-29") and http_ver == "HTTP/1.1":
        http_ver = "HTTP/2" if alpn.lower() == "h2" else "HTTP/3"
        details["http_version"] = http_ver
        findings.append(f"Negotiated protocol: {http_ver} (via ALPN: {alpn}; requests library used HTTP/1.1)")
    else:
        findings.append(f"Negotiated protocol: {http_ver}")
    if http_ver == "HTTP/3" or http_ver.startswith("HTTP/3"):
        score += 5
        findings.append("HTTP/3 (QUIC) in use - lowest latency transport")
    elif http_ver == "HTTP/2":
        score += 4
        findings.append("HTTP/2 in use - multiplexed streams")
    elif http_ver == "HTTP/1.1":
        score += 2
        findings.append("HTTP/1.1 - consider upgrading to HTTP/2 or HTTP/3")
    else:
        findings.append(f"HTTP version: {http_ver}")
    if alpn:
        findings.append(f"ALPN selected: {alpn}")
        if alpn.lower() in ("h3", "h3-29", "hq"):
            score = min(5, score + 1)
        elif alpn.lower() in ("h2", "http/1.1"):
            score = min(5, score)
    else:
        findings.append("ALPN result unavailable")
    score = max(0, min(score, 5))
    results.append({"category": "HTTP Version", "score": score, "max": 5, "findings": findings})

    # 7 SSL/TLS at Edge max 10
    score = 0
    findings = []
    if cert_info.get("error"):
        findings.append(f"TLS probe error: {cert_info['error']}")
    tls_v = cert_info.get("tls_version")
    if tls_v:
        findings.append(f"TLS version: {tls_v}")
        if tls_v == "TLSv1.3":
            score += 4
            findings.append("TLS 1.3 - modern, fastest handshake")
        elif tls_v == "TLSv1.2":
            score += 3
            findings.append("TLS 1.2 - acceptable, upgrade to 1.3 recommended")
        elif tls_v in ("TLSv1.1", "TLSv1", "SSLv3"):
            findings.append("Deprecated TLS version in use")
        else:
            score += 1
    else:
        findings.append("TLS version not determined")
    issuer = cert_info.get("issuer")
    subject = cert_info.get("subject")
    if subject:
        findings.append(f"Cert subject: {subject}")
    if issuer:
        findings.append(f"Cert issuer: {issuer}")
        score += 1
    days = cert_info.get("days_remaining")
    if days is not None:
        findings.append(f"Cert expires in {days} days ({cert_info.get('not_after')})")
        if days > 30:
            score += 1
        elif days <= 0:
            findings.append("Certificate expired or expiring immediately")
    ocsp = check_ocsp_stapling(hostname, timeout=min(timeout, 8)) if hostname else False
    details["ocsp_stapled"] = ocsp
    if ocsp:
        score += 2
        findings.append("OCSP stapling enabled - faster TLS validation")
    else:
        findings.append("OCSP stapling not detected")
    hsts = hdrs.get("strict-transport-security")
    if hsts:
        score += 2
        findings.append(f"HSTS: {hsts}")
        if "preload" in hsts.lower():
            findings.append("HSTS preload directive present")
    else:
        findings.append("HSTS header missing")
    score = max(0, min(score, 10))
    results.append({"category": "SSL/TLS at Edge", "score": score, "max": 10, "findings": findings})

    # 8 Origin Shield max 5
    score = 0
    findings = []
    origin_fetch = [
        k
        for k in hdrs
        if any(
            x in k
            for x in (
                "x-origin",
                "x-forwarded",
                "x-real-ip",
                "x-backend",
                "x-served-by-origin",
                "x-request-id",
                "x-amz-request-id",
                "true-client-ip",
                "forwarded",
            )
        )
    ]
    details["origin_headers"] = {k: hdrs[k] for k in origin_fetch}
    if origin_fetch:
        score += 2
        findings.append(f"Origin-forwarding headers present: {', '.join(origin_fetch)}")
    else:
        findings.append("No origin-forwarding headers exposed")
    if any("x-forwarded-for" in k for k in origin_fetch) or "x-forwarded-for" in hdrs:
        score += 1
        findings.append("X-Forwarded-For present (client IP propagation)")
    if any(k in hdrs for k in ("cf-ray", "x-amz-cf-pop", "x-served-by", "x-akamai-transformed")):
        score += 1
        findings.append("Edge layer absorbs traffic before origin")
    protected = any(
        k in hdrs
        for k in ("cf-ray", "x-amz-cf-pop", "x-fastly-request-id", "x-akamai-transformed", "x-served-by")
    )
    if protected:
        score += 1
        findings.append("Origin likely shielded behind CDN edge")
    else:
        findings.append("No evidence of origin shielding")
    score = max(0, min(score, 5))
    results.append({"category": "Origin Shield", "score": score, "max": 5, "findings": findings})

    # 9 Purge & Invalidation max 5
    score = 0
    findings = []
    surr_ctrl = hdrs.get("surrogate-control")
    surr_key = hdrs.get("surrogate-key")
    purge = hdrs.get("x-purge-token") or hdrs.get("purge")
    cache_tag = hdrs.get("cache-tag")
    cdn_cache = hdrs.get("cdn-cache-control")
    ecap = hdrs.get("x-cache")
    details["purge"] = {
        "surrogate-control": surr_ctrl,
        "surrogate-key": surr_key,
        "cache-tag": cache_tag,
        "cdn-cache-control": cdn_cache,
    }
    if surr_ctrl:
        score += 2
        findings.append(f"Surrogate-Control: {surr_ctrl}")
    if surr_key:
        score += 2
        findings.append(f"Surrogate-Key: {surr_key[:80]}")
    if cache_tag:
        score += 1
        findings.append(f"Cache-Tag: {cache_tag[:80]}")
    if cdn_cache:
        findings.append(f"CDN-Cache-Control: {cdn_cache}")
        score += 1
    if purge:
        findings.append("Purge token/header present")
    if not (surr_ctrl or surr_key or cache_tag or cdn_cache):
        findings.append("No purge/invalidation hints found (Surrogate-Control/Key, Cache-Tag)")
    score = max(0, min(score, 5))
    results.append({"category": "Purge & Invalidation", "score": score, "max": 5, "findings": findings})

    # 10 Asset Delivery max 5
    score = 0
    findings = []
    ctype = hdrs.get("content-type", "").lower()
    details["content_type"] = ctype
    is_asset_path = any(
        x in (parsed.path or "").lower()
        for x in (".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".webp", ".woff", ".woff2", ".ttf", ".ico", ".gif", ".avif")
    )
    is_cdn = provider is not None
    immutable = "immutable" in (cc or "").lower()
    long_ttl = False
    if "max-age=" in (cc or "").lower():
        try:
            import re as _re

            m = _re.search(r"max-age=(\d+)", cc, _re.I)
            if m and int(m.group(1)) >= 86400:
                long_ttl = True
        except Exception:
            pass
    if is_cdn:
        score += 2
        findings.append(f"Assets can be served via identified CDN: {provider}")
    if is_asset_path or any(x in ctype for x in ("image", "font", "javascript", "stylesheet", "css")):
        score += 1
        findings.append(f"Asset-type response: {ctype or 'unknown'}")
        if immutable:
            score += 1
            findings.append("immutable - ideal for fingerprinted assets")
        if long_ttl:
            score += 1
            findings.append("Long max-age (>=1 day) good for asset caching")
        if cel in ("br", "gzip", "zstd"):
            findings.append("Asset is compressed")
    else:
        findings.append(f"Content-Type: {ctype or 'unknown'} (page, not static asset)")
        if is_cdn:
            score += 1
            findings.append("CDN available for static asset offload")
        if immutable or long_ttl:
            score += 1
            findings.append("Cacheable page/delivery headers present")
    score = max(0, min(score, 5))
    results.append({"category": "Asset Delivery", "score": score, "max": 5, "findings": findings})

    return results, details


def export_json(path, payload):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)


def export_csv(path, results, summary):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["category", "score", "max", "percent", "findings"])
        for r in results:
            pct = round((r["score"] / r["max"]) * 100, 1) if r["max"] else 0
            w.writerow([r["category"], r["score"], r["max"], pct, " | ".join(r["findings"])])
        w.writerow([])
        w.writerow(["TOTAL", summary["total"], summary["max"], summary["percent"], f"Grade: {summary['grade']}"])


def export_html(path, payload, c_disabled=True):
    results = payload["results"]
    summary = payload["summary"]
    rows = ""
    for r in results:
        pct = int(round((r["score"] / r["max"]) * 100)) if r["max"] else 0
        if pct >= 90:
            col = "#22c55e"
        elif pct >= 70:
            col = "#38bdf8"
        elif pct >= 50:
            col = "#eab308"
        else:
            col = "#ef4444"
        items = "".join(f"<li>{x}</li>" for x in r["findings"])
        rows += f"""
        <tr>
          <td>{r['category']}</td>
          <td class="bar"><div class="fill" style="width:{pct}%;background:{col}"></div><span>{r['score']}/{r['max']}</span></td>
          <td style="color:{col}">{pct}%</td>
        </tr>
        <tr class="detail"><td colspan="3"><ul>{items}</ul></td></tr>"""
    grade = summary["grade"]
    gcol = "#22c55e" if grade in ("A+", "A") else "#38bdf8" if grade == "B" else "#eab308" if grade == "C" else "#ef4444"
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CDNAnalyzer Report</title>
<style>
  :root {{ --bg:#0b0f14; --panel:#121821; --text:#e6edf3; --muted:#8b98a5; --line:#1f2937; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font-family: "Segoe UI", system-ui, sans-serif; background:var(--bg); color:var(--text); }}
  header {{ padding:28px 32px; background:linear-gradient(135deg,#10161f,#162132); border-bottom:1px solid var(--line); }}
  h1 {{ margin:0; font-size:22px; letter-spacing:.5px; }}
  .meta {{ color:var(--muted); font-size:13px; margin-top:6px; }}
  .summary {{ display:flex; gap:16px; flex-wrap:wrap; padding:24px 32px; }}
  .card {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:18px 22px; min-width:160px; }}
  .card .label {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:1px; }}
  .card .value {{ font-size:28px; font-weight:700; margin-top:6px; }}
  table {{ width:calc(100% - 64px); margin:0 32px 32px; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); border-radius:10px; overflow:hidden; }}
  th, td {{ padding:12px 16px; text-align:left; font-size:14px; border-bottom:1px solid var(--line); }}
  th {{ background:#0f1520; color:var(--muted); font-weight:600; text-transform:uppercase; font-size:11px; letter-spacing:1px; }}
  tr.detail td {{ color:var(--muted); font-size:13px; background:#0e141c; }}
  tr.detail ul {{ margin:4px 0 8px 18px; padding:0; }}
  tr.detail li {{ margin:3px 0; }}
  .bar {{ position:relative; height:22px; background:#0e141c; border-radius:4px; overflow:hidden; min-width:220px; }}
  .fill {{ height:100%; }}
  .bar span {{ position:absolute; inset:0; display:flex; align-items:center; justify-content:center; font-size:12px; color:#fff; text-shadow:0 1px 2px rgba(0,0,0,.8); }}
  footer {{ padding:16px 32px; color:var(--muted); font-size:12px; border-top:1px solid var(--line); }}
</style>
</head>
<body>
<header>
  <h1>CDNAnalyzer v{VERSION} — CDN Performance Report</h1>
  <div class="meta">Target: {payload.get('url','')} &nbsp;|&nbsp; Generated: {payload.get('generated','')} &nbsp;|&nbsp; Provider: {payload.get('provider') or 'Not identified'}</div>
</header>
<div class="summary">
  <div class="card"><div class="label">Total Score</div><div class="value">{summary['total']}<span style="font-size:16px;color:var(--muted)">/{summary['max']}</span></div></div>
  <div class="card"><div class="label">Grade</div><div class="value" style="color:{gcol}">{grade}</div></div>
  <div class="card"><div class="label">TTFB</div><div class="value">{summary.get('ttfb_ms','n/a')}<span style="font-size:16px;color:var(--muted)"> ms</span></div></div>
  <div class="card"><div class="label">HTTP</div><div class="value" style="font-size:20px">{summary.get('http_version','n/a')}</div></div>
</div>
<table>
  <thead><tr><th>Category</th><th>Score</th><th>Percent</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
<footer>CDNAnalyzer v{VERSION} — static analysis report. Verify findings against your CDN dashboard before changing production cache rules.</footer>
</body>
</html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


def print_report(results, details, summary, c, verbose):
    print(c.bold(c.cyan(BANNER)))
    print(c.bold(c.white(f"  CDNAnalyzer v{VERSION}")) + c.dim("  |  CDN performance, caching & delivery analyzer"))
    print(c.dim("  " + "=" * 70))
    print()
    print(c.bold(c.yellow("  Target: ")) + c.white(str(details.get("url", ""))))
    provider = details.get("provider")
    if provider:
        print(c.bold(c.yellow("  CDN Provider: ")) + c.green(provider))
    else:
        print(c.bold(c.yellow("  CDN Provider: ")) + c.red("Not identified"))
    if details.get("edge_pop"):
        print(c.bold(c.yellow("  Edge POP: ")) + c.cyan(str(details["edge_pop"])))
    if details.get("ttfb") is not None:
        print(c.bold(c.yellow("  TTFB: ")) + c.cyan(f"{details['ttfb']*1000:.1f} ms"))
    if details.get("http_version"):
        print(c.bold(c.yellow("  HTTP Version: ")) + c.cyan(str(details["http_version"])))
    if details.get("alpn"):
        print(c.bold(c.yellow("  ALPN: ")) + c.cyan(str(details["alpn"])))
    if details.get("cname"):
        print(c.bold(c.yellow("  CNAME: ")) + c.cyan(", ".join(details["cname"][:3])))
    print()
    print(c.bold(c.yellow("  CHECKS")))
    print(c.dim("  " + "-" * 70))
    for r in results:
        bar = score_bar(r["score"], r["max"], 18, c)
        name = r["category"].ljust(24)
        print(f"  {c.bold(name)} {bar}")
        if verbose or r["score"] < r["max"]:
            for f in r["findings"]:
                if r["score"] >= r["max"] and not verbose:
                    continue
                print(c.dim(f"      - {f}"))
        if verbose:
            shown = len(r["findings"])
            if shown == 0:
                print(c.dim("      - (no findings)"))
    print(c.dim("  " + "-" * 70))
    total = summary["total"]
    grade = summary["grade"]
    pct = summary["percent"]
    print()
    print(
        "  "
        + c.bold(c.white("TOTAL: "))
        + c.bold(c.green(f"{total}/{summary['max']}"))
        + c.dim(f"  ({pct}%)")
        + "   "
        + c.bold(c.white("GRADE: "))
        + c.bg_blue(c.bold(f" {grade} "))
    )
    print()


def main():
    parser = argparse.ArgumentParser(
        prog="cdnanalyzer",
        description=f"CDNAnalyzer v{VERSION} - CDN performance, caching and delivery analyzer",
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL to analyze")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument(
        "--export",
        choices=["all", "json", "csv", "html", "none"],
        default="none",
        help="Export format (default: none)",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output (show all findings)")
    args = parser.parse_args()

    use_color = not args.no_color and sys.stdout.isatty()
    c = Colors(use_color)

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        results, details = run_checks(url, args.timeout, args.verbose, c)
    except Exception as e:
        print(c.red(f"Error during analysis: {e}"))
        sys.exit(1)

    total = sum(r["score"] for r in results)
    max_total = sum(r["max"] for r in results)
    pct = round((total / max_total) * 100, 1) if max_total else 0.0
    grade = grade_for(total)
    summary = {
        "total": total,
        "max": max_total,
        "percent": pct,
        "grade": grade,
        "ttfb_ms": details.get("ttfb_ms"),
        "http_version": details.get("http_version"),
    }

    print_report(results, details, summary, c, args.verbose)

    payload = {
        "tool": f"CDNAnalyzer v{VERSION}",
        "generated": datetime.now(timezone.utc).isoformat(),
        "url": details.get("url", url),
        "provider": details.get("provider"),
        "edge_pop": details.get("edge_pop"),
        "ttfb_ms": details.get("ttfb_ms"),
        "http_version": details.get("http_version"),
        "alpn": details.get("alpn"),
        "cname": details.get("cname"),
        "cache_control": details.get("cache_control"),
        "cache_status": details.get("cache_status"),
        "content_encoding": details.get("content_encoding"),
        "content_type": details.get("content_type"),
        "hsts": details.get("headers", {}).get("strict-transport-security"),
        "ocsp_stapled": details.get("ocsp_stapled"),
        "cert": details.get("cert"),
        "origin_exposure": details.get("origin_exposure"),
        "origin_headers": details.get("origin_headers"),
        "purge": details.get("purge"),
        "headers": details.get("headers"),
        "results": results,
        "summary": summary,
    }

    if args.export != "none":
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        written = []
        if args.export in ("all", "json"):
            p = f"cdnanalyzer_{stamp}.json"
            export_json(p, payload)
            written.append(p)
        if args.export in ("all", "csv"):
            p = f"cdnanalyzer_{stamp}.csv"
            export_csv(p, results, summary)
            written.append(p)
        if args.export in ("all", "html"):
            p = f"cdnanalyzer_{stamp}.html"
            export_html(p, payload)
            written.append(p)
        for p in written:
            print(c.green(f"  Exported: {p}"))
        print()

    if total < 60:
        print(c.yellow("  Suggestions:"))
        if not details.get("provider"):
            print(c.yellow("    - No CDN detected. Consider placing origin behind a CDN (Cloudflare, Fastly, CloudFront)."))
        cc = (details.get("cache_control") or "").lower()
        if not cc or "no-store" in cc or "no-cache" in cc:
            print(c.yellow("    - Add cacheable Cache-Control (public, s-maxage, immutable for assets)."))
        if not details.get("cache_status") or not any(details.get("cache_status", {}).values()):
            print(c.yellow("    - No cache status headers; enable edge caching and verify HIT responses."))
        if not details.get("headers", {}).get("strict-transport-security"):
            print(c.yellow("    - Enable HSTS (Strict-Transport-Security)."))
        if (details.get("ttfb") or 1) > 0.4:
            print(c.yellow("    - TTFB is high; enable edge caching / origin shield to reduce origin latency."))
        ce = (details.get("content_encoding") or "").lower()
        if not ce:
            print(c.yellow("    - Enable compression (prefer Brotli) at the edge."))
        print()

    sys.exit(0 if total >= 60 else 1)


if __name__ == "__main__":
    main()
