#!/usr/bin/env python3
"""
PerfAnalyzer v7.0 - Comprehensive Website Performance Analyzer
Advanced performance metrics, Core Web Vitals, real user simulation,
deep resource analysis, modern API detection (Speculation Rules,
View Transitions, Container Queries, CSS Nesting, WebGPU, WebTransport),
adaptive image loading, content-visibility, CSS contain, will-change,
backdrop-filter impact, scroll-driven animations, observer/RUM analytics,
bundle and tree-shaking analysis, refined Lighthouse/PSI/UX scoring,
budget compliance dashboards, and phase-based performance waterfall reporting.
"""

import sys
import os
import time
import json
import csv
import argparse
import socket
import ssl
import struct
import io
import re
import statistics
from urllib.parse import urlparse, urljoin
from collections import OrderedDict, defaultdict
from datetime import datetime

try:
    import requests
except ImportError:
    print("Installing requests...")
    os.system(f"{sys.executable} -m pip install requests -q")
    import requests

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Installing beautifulsoup4...")
    os.system(f"{sys.executable} -m pip install beautifulsoup4 -q")
    from bs4 import BeautifulSoup


class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"

    @classmethod
    def disable(cls):
        for attr in dir(cls):
            if attr.isupper() and attr != "RESET":
                setattr(cls, attr, "")


class CheckResult:
    def __init__(self, name, value, status, category, detail="", weight=1, effort=1):
        self.name = name
        self.value = value
        self.status = status
        self.category = category
        self.detail = detail
        self.weight = weight
        self.effort = effort

    def to_dict(self):
        return {
            "name": self.name,
            "value": self.value,
            "status": self.status,
            "category": self.category,
            "detail": self.detail,
            "weight": self.weight,
            "effort": self.effort,
        }


class PerfAnalyzer:
    BANNER = rf"""
{Colors.CYAN}{Colors.BOLD}
   ███████╗██████╗ ███████╗ █████╗ ████████╗██╗  ██╗███████╗██████╗
   ██╔════╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║  ██║██╔════╝██╔══██╗
   █████╗  ██████╔╝█████╗  ███████║   ██║   ███████║█████╗  ██████╔╝
   ██╔══╝  ██╔═══╝ ██╔══╝  ██╔══██║   ██║   ██╔══██║██╔══╝  ██╔══██╗
   ███████╗██║     ███████╗██║  ██║   ██║   ██║  ██║███████╗██║  ██║
   ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
{Colors.YELLOW}   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
{Colors.GREEN}   ░ Performance Analyzer v7.0 ── Simulate. Analyze. Optimize.
{Colors.CYAN}{Colors.BOLD}"""

    SCORING_WEIGHTS = {
        "vitals": 20,
        "timing": 14,
        "resources": 9,
        "caching": 6,
        "compression": 4,
        "redirects": 2,
        "protocol": 3,
        "rendering": 6,
        "images": 4,
        "mobile": 3,
        "modern": 5,
        "simulation": 4,
        "memory": 4,
        "thirdparty": 3,
        "observers": 4,
        "bundles": 5,
        "analytics": 4,
    }

    STRICT_PERFORMANCE_BUDGETS = {
        "ttfb_ms": 500,
        "lcp_ms": 2000,
        "fcp_ms": 1500,
        "si_ms": 3000,
        "tti_ms": 3500,
        "tbt_ms": 150,
        "inp_score": 200,
        "cls_score": 0.05,
        "total_page_size": 1_000_000,
        "total_resources": 35,
        "dom_parse_ms": 150,
        "js_size": 200_000,
        "css_size": 75_000,
        "img_size": 400_000,
        "font_size": 100_000,
        "render_blocking_resources": 1,
        "render_blocking_size": 80_000,
        "js_exec_time_ms": 1500,
        "third_party_domains": 5,
        "dom_elements": 1000,
        "duplicate_resources": 1,
        "long_task_count": 3,
        "main_thread_blocking_score": 6,
        "memory_estimated_kb": 12_000,
        "layout_shift_score": 0.15,
    }

    LIGHTHOUSE_WEIGHTS = {
        "fcp_ms": 10,
        "si_ms": 10,
        "lcp_ms": 25,
        "tbt_ms": 25,
        "cls_score": 10,
        "inp_score": 10,
        "tti_ms": 5,
        "ttfb_ms": 5,
    }

    RUM_PROVIDERS = {
        "New Relic": ["newrelic", "NREUM", "new-relic"],
        "Datadog RUM": ["datadoghq", "DD_RUM", "@datadog/browser"],
        "SpeedCurve": ["speedcurve"],
        "Calibre": ["calibreapp"],
        "LogRocket": ["logrocket"],
        "FullStory": ["fullstory", "fs.js"],
        "Dynatrace": ["dynatrace", "dT_"],
        "AppDynamics": ["appdynamics", "ADUM"],
        "Elastic APM": ["elasticapm", "elastic.co"],
        "Boomerang/mPulse": ["BOOMR", "boomerang.io", "mPulse"],
        "Quantum Metric": ["quantummetric"],
        "Contentsquare": ["contentsquare", "clicktale"],
        "Raygun": ["raygun"],
        "Bugsnag": ["bugsnag"],
        "Sentry Performance": ["@sentry", "Sentry.init", "browserTracing"],
        "CrUX reporting": ["chromeuxreport", "crux"],
        "mParticle": ["mparticle"],
        "Adobe Experience Cloud": ["adobedtm", "omtrdc"],
        "Matomo RUM": ["matomo", "piwik"],
        "Plausible": ["plausible.io"],
        "Fathom": ["usefathom", "fathom.cloud"],
        "Microsoft Clarity": ["clarity.ms"],
    }

    ANALYTICS_PROVIDERS = {
        "Google Analytics": ["google-analytics.com", "gtag(", "ga("],
        "Google Tag Manager": ["googletagmanager.com"],
        "Google Ads": ["googlesyndication", "googleadservices", "doubleclick"],
        "Meta Pixel": ["fbevents.js", "fbq(", "connect.facebook"],
        "Twitter/X Pixel": ["static.ads-twitter", "analytics.twitter"],
        "LinkedIn Insight": ["snap.licdn.com"],
        "TikTok Pixel": ["analytics.tiktok", "ttq("],
        "Segment": ["segment.io", "segment.com", "analytics.load"],
        "Mixpanel": ["mixpanel"],
        "Amplitude": ["amplitude.com", "amplitude"],
        "Heap": ["heapanalytics", "heap.io"],
        "Hotjar": ["hotjar.com", "hj("],
        "VWO": ["visualwebsiteoptimizer", "vwo"],
        "Optimizely": ["optimizely"],
        "Crazyegg": ["crazyegg"],
        "HubSpot": ["js.hs-scripts", "hubspot"],
        "Intercom": ["widget.intercom", "intercomcdn"],
        "Drift": ["driftt", "drift.com"],
        "Klaviyo": ["klaviyo"],
        "Mailchimp": ["list-manage", "mailchimp"],
        "Bing UET": ["bat.bing", "uetq"],
        "Plausible Analytics": ["plausible.io/js"],
        "Fathom Analytics": ["usefathom.com"],
    }

    CORE_WEB_VITALS = {
        "lcp_ms": {"good": 2500, "poor": 4000, "name": "LCP"},
        "cls_score": {"good": 0.1, "poor": 0.25, "name": "CLS"},
        "inp_score": {"good": 200, "poor": 500, "name": "INP"},
        "ttfb_ms": {"good": 800, "poor": 1800, "name": "TTFB"},
        "fcp_ms": {"good": 1800, "poor": 3000, "name": "FCP"},
        "si_ms": {"good": 3400, "poor": 5800, "name": "SI"},
        "tti_ms": {"good": 3800, "poor": 7300, "name": "TTI"},
        "tbt_ms": {"good": 200, "poor": 600, "name": "TBT"},
    }

    PERFORMANCE_BUDGETS = {
        "ttfb_ms": 800,
        "lcp_ms": 2500,
        "fcp_ms": 1800,
        "si_ms": 3400,
        "tti_ms": 3800,
        "tbt_ms": 200,
        "inp_score": 300,
        "cls_score": 0.1,
        "total_page_size": 1_600_000,
        "total_resources": 50,
        "dom_parse_ms": 200,
        "js_size": 300_000,
        "css_size": 100_000,
        "img_size": 500_000,
        "font_size": 150_000,
        "render_blocking_resources": 2,
        "render_blocking_size": 120_000,
        "js_exec_time_ms": 2000,
        "third_party_domains": 8,
        "dom_elements": 1500,
        "duplicate_resources": 2,
        "long_task_count": 5,
        "main_thread_blocking_score": 8,
        "memory_estimated_kb": 15_000,
        "layout_shift_score": 0.25,
    }

    CONNECTION_PROFILES = {
        "3g": {
            "label": "3G (Slow)",
            "latency_ms": 300,
            "download_kbps": 400,
            "upload_kbps": 400,
            "multiplier": 8.0,
            "cpu_multiplier": 2.0,
        },
        "4g": {
            "label": "4G LTE",
            "latency_ms": 70,
            "download_kbps": 12000,
            "upload_kbps": 5000,
            "multiplier": 1.5,
            "cpu_multiplier": 1.5,
        },
        "wifi": {
            "label": "WiFi",
            "latency_ms": 20,
            "download_kbps": 30000,
            "upload_kbps": 15000,
            "multiplier": 1.0,
            "cpu_multiplier": 1.0,
        },
        "fiber": {
            "label": "Fiber",
            "latency_ms": 5,
            "download_kbps": 100000,
            "upload_kbps": 100000,
            "multiplier": 0.7,
            "cpu_multiplier": 1.0,
        },
    }

    DEVICE_PROFILES = {
        "mobile": {
            "label": "Mobile (Moto G Power)",
            "cpu_multiplier": 2.5,
            "screen": "412x892",
            "dpr": 2.625,
            "ram_mb": 4000,
            "js_budget_ms": 3000,
        },
        "tablet": {
            "label": "Tablet (iPad Air)",
            "cpu_multiplier": 1.5,
            "screen": "820x1180",
            "dpr": 2,
            "ram_mb": 8000,
            "js_budget_ms": 5000,
        },
        "desktop": {
            "label": "Desktop (Intel i7)",
            "cpu_multiplier": 1.0,
            "screen": "1920x1080",
            "dpr": 1,
            "ram_mb": 16000,
            "js_budget_ms": 8000,
        },
    }

    THIRD_PARTY_CATEGORIES = {
        "googleapis.com": "Google APIs",
        "gstatic.com": "Google Static",
        "google-analytics.com": "Google Analytics",
        "googletagmanager.com": "Google Tag Manager",
        "googlesyndication.com": "Google Ads",
        "facebook.com": "Facebook",
        "fbcdn.net": "Facebook CDN",
        "twitter.com": "Twitter",
        "linkedin.com": "LinkedIn",
        "cloudflare.com": "Cloudflare",
        "jsdelivr.net": "jsDelivr CDN",
        "unpkg.com": "unpkg CDN",
        "cdnjs.cloudflare.com": "cdnjs CDN",
        "amazonaws.com": "AWS",
        "azure.com": "Azure",
        "akamaihd.net": "Akamai",
        "fastly.net": "Fastly CDN",
        "jquery.com": "jQuery",
        "bootstrapcdn.com": "Bootstrap CDN",
        "fonts.googleapis.com": "Google Fonts",
        "youtube.com": "YouTube",
        "vimeo.com": "Vimeo",
        "stripe.com": "Stripe",
        "paypal.com": "PayPal",
        "recaptcha.net": "reCAPTCHA",
        "sentry.io": "Sentry",
        "hotjar.com": "Hotjar",
        "optimizely.com": "Optimizely",
        "segment.com": "Segment",
        "mixpanel.com": "Mixpanel",
    }

    THIRD_PARTY_IMPACT = {
        "Google Analytics": {"blocking": False, "privacy": True, "weight": 2},
        "Google Tag Manager": {"blocking": True, "privacy": False, "weight": 3},
        "Google Ads": {"blocking": True, "privacy": True, "weight": 4},
        "Facebook": {"blocking": True, "privacy": True, "weight": 3},
        "Twitter": {"blocking": True, "privacy": True, "weight": 3},
        "LinkedIn": {"blocking": True, "privacy": True, "weight": 2},
        "Hotjar": {"blocking": True, "privacy": True, "weight": 3},
        "Sentry": {"blocking": False, "privacy": False, "weight": 2},
        "reCAPTCHA": {"blocking": True, "privacy": True, "weight": 4},
        "Stripe": {"blocking": True, "privacy": False, "weight": 3},
        "YouTube": {"blocking": True, "privacy": True, "weight": 4},
        "Vimeo": {"blocking": True, "privacy": True, "weight": 3},
    }

    def __init__(self, url, timeout=30, export="none", verbose=False, device="desktop", connection="wifi", strict_budget=False):
        self.url = url
        self.timeout = timeout
        self.export = export
        self.verbose = verbose
        self.device = device
        self.connection = connection
        self.strict_budget = strict_budget
        self.results = []
        self.raw_metrics = {}
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "PerfAnalyzer/7.0 (Performance Analysis Tool)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.5",
        })
        self.resource_timings = []
        self.dedup_urls = defaultdict(list)

    def add_result(self, name, value, status, category, detail="", weight=1, effort=1):
        self.results.append(CheckResult(name, value, status, category, detail, weight, effort))

    def log(self, category, icon, text):
        cat_colors = {
            "vitals": Colors.MAGENTA,
            "timing": Colors.CYAN,
            "resources": Colors.BLUE,
            "caching": Colors.YELLOW,
            "compression": Colors.GREEN,
            "redirects": Colors.RED,
            "protocol": Colors.BLUE,
            "rendering": Colors.MAGENTA,
            "images": Colors.CYAN,
            "mobile": Colors.GREEN,
            "modern": Colors.MAGENTA,
            "simulation": Colors.CYAN,
            "memory": Colors.RED,
            "thirdparty": Colors.YELLOW,
            "observers": Colors.CYAN,
            "bundles": Colors.BLUE,
            "analytics": Colors.YELLOW,
        }
        color = cat_colors.get(category, Colors.WHITE)
        print(f"  {Colors.DIM}[{color}{category.upper()}{Colors.RESET}{Colors.DIM}]{Colors.RESET} {icon} {text}")

    def status_icon(self, status):
        if status == "excellent":
            return f"{Colors.GREEN}●{Colors.RESET}"
        elif status == "good":
            return f"{Colors.GREEN}◉{Colors.RESET}"
        elif status == "needs_improvement":
            return f"{Colors.YELLOW}◉{Colors.RESET}"
        elif status == "poor":
            return f"{Colors.RED}◉{Colors.RESET}"
        return f"{Colors.DIM}○{Colors.RESET}"

    def _categorize_third_party(self, domain):
        for pattern, category in self.THIRD_PARTY_CATEGORIES.items():
            if pattern in domain:
                return category
        for known in ["cdn", "analytics", "ads", "tracking", "widget", "social", "font", "script"]:
            if known in domain:
                return known.capitalize()
        return "Other"

    def _estimate_metric(self, base_time, html_size, js_count, img_count, css_count, extra=0):
        est = base_time
        if html_size > 100000:
            est += 0.2
        if html_size > 500000:
            est += 0.5
        est += js_count * 0.1
        est += img_count * 0.05
        est += css_count * 0.08
        est += extra
        return est

    def _simulate_metric(self, base_value, conn_key=None):
        if conn_key is None:
            conn_key = self.connection
        profile = self.CONNECTION_PROFILES.get(conn_key, self.CONNECTION_PROFILES["wifi"])
        return base_value * profile["multiplier"]


    def _identify_lcp_element(self, soup):
        candidates = []
        for img in soup.find_all("img"):
            src = img.get("src", "")
            if not src:
                continue
            w = h = 0
            try:
                w = int(img.get("width", 0))
            except (ValueError, TypeError):
                pass
            try:
                h = int(img.get("height", 0))
            except (ValueError, TypeError):
                pass
            area = w * h
            candidates.append(("img", src[:80], area))
        for tag in soup.find_all(["h1", "h2", "h3"]):
            text = (tag.string or "").strip()
            if len(text) > 3:
                candidates.append(("text", text[:60], 10000))
        for div in soup.find_all("div", class_=True):
            cls = " ".join(div.get("class", []))
            if "hero" in cls.lower() or "banner" in cls.lower() or "main" in cls.lower():
                candidates.append(("div", cls[:60], 8000))
        if not candidates:
            return None, 0
        candidates.sort(key=lambda x: -x[2])
        best = candidates[0]
        return "{}: {}".format(best[0], best[1]), best[2]

    def _identify_cls_sources(self, soup, images):
        cls_sources = []
        no_dim_images = 0
        for img in images:
            if not img.get("width") and not img.get("height"):
                no_dim_images += 1
                cls_sources.append("img without dimensions: " + img.get("src", "unknown")[:60])
        iframes = soup.find_all("iframe")
        no_dim_iframes = 0
        for iframe in iframes:
            if not iframe.get("width") or not iframe.get("height"):
                no_dim_iframes += 1
                cls_sources.append("iframe without dimensions: " + iframe.get("src", "unknown")[:60])
        inline_scripts = soup.find_all("script", src=False)
        dynamic_dom = False
        for script in inline_scripts:
            text = script.string or ""
            if "createElement" in text or "appendChild" in text or "innerHTML" in text or "insertAdjacentHTML" in text:
                dynamic_dom = True
                cls_sources.append("Dynamic DOM manipulation in inline script")
                break
        if not soup.find("meta", attrs={"name": "viewport"}):
            cls_sources.append("Missing viewport meta tag")
        dynamic_fonts = False
        for style in soup.find_all("style"):
            text = style.string or ""
            if "@font-face" in text:
                dynamic_fonts = True
                cls_sources.append("Inline @font-face may cause FOIT/FOUT layout shift")
                break
        return cls_sources, no_dim_images, no_dim_iframes, dynamic_dom, dynamic_fonts

    def _identify_inp_elements(self, soup):
        inp_sources = []
        event_heavy_tags = []
        for tag in soup.find_all(True):
            handler_count = 0
            for attr in tag.attrs:
                if attr.startswith("on"):
                    handler_count += 1
            if handler_count >= 2:
                event_heavy_tags.append((tag.name, handler_count))
        event_heavy_tags.sort(key=lambda x: -x[1])
        for tag_name, count in event_heavy_tags[:5]:
            inp_sources.append("<{}> with {} event handlers".format(tag_name, count))
        form_elements = soup.find_all(["input", "textarea", "select", "button"])
        if len(form_elements) > 5:
            inp_sources.append("{} form elements (potential interaction delay)".format(len(form_elements)))
        inline_scripts = soup.find_all("script", src=False)
        heavy_inline = 0
        for script in inline_scripts:
            if len(script.string or "") > 10000:
                heavy_inline += 1
        if heavy_inline > 0:
            inp_sources.append("{} heavy inline scripts (>10KB)".format(heavy_inline))
        sync_scripts = [s for s in soup.find_all("script", src=True) if not s.get("async") and not s.get("defer")]
        if len(sync_scripts) > 2:
            inp_sources.append("{} sync scripts blocking main thread".format(len(sync_scripts)))
        return inp_sources

    def _identify_fcp_element(self, soup, html_content):
        fcp_candidates = []
        inline_styles = soup.find_all("style")
        total_inline_css = sum(len(s.string or "") for s in inline_styles)
        if total_inline_css > 500:
            fcp_candidates.append("Inline CSS ({} bytes)".format(total_inline_css))
        first_text = soup.find(["h1", "h2", "h3", "p", "span", "div"])
        if first_text and first_text.string and first_text.string.strip():
            fcp_candidates.append("First text node: <{}> \"{}\"".format(
                first_text.name, first_text.string.strip()[:40]))
        first_img = soup.find("img")
        if first_img:
            fcp_candidates.append("First image: " + first_img.get("src", "unknown")[:50])
        if not fcp_candidates and len(html_content) > 1000:
            fcp_candidates.append("Document body text content")
        return fcp_candidates
    # ─────────────────────────────────────────────
    # CHECK: Core Web Vitals (v3 - refined)
    # ─────────────────────────────────────────────
    def check_vitals(self, html_content, soup, load_time, response):
        self.log("vitals", "▸", "Estimating Core Web Vitals...")

        images = soup.find_all("img")
        scripts = soup.find_all("script", src=True)
        inline_scripts = soup.find_all("script", src=False)
        css_files = soup.find_all("link", rel="stylesheet")
        total_js = len(scripts)
        total_css = len(css_files)

        # --- LCP (refined v6: resource-loading aware) ---
        lcp_estimate = load_time
        largest_img_size = 0
        for img in images:
            src = img.get("src", "")
            w = img.get("width", "")
            h = img.get("height", "")
            if w and h:
                try:
                    size = int(w) * int(h)
                    largest_img_size = max(largest_img_size, size)
                except ValueError:
                    pass
        if largest_img_size > 1000000:
            lcp_estimate += 1.5
        elif largest_img_size > 500000:
            lcp_estimate += 0.8
        if len(html_content) > 100000:
            lcp_estimate += 0.5
        lcp_estimate += total_css * 0.15
        hero_lcp_lazy = False
        lcp_element, lcp_area = self._identify_lcp_element(soup)
        if lcp_element and lcp_element.startswith("img"):
            for img in images:
                src = img.get("src", "")
                if src and lcp_element.endswith(src[:80]) and img.get("loading") == "lazy":
                    hero_lcp_lazy = True
                    lcp_estimate += 0.4
                    break
        if hero_lcp_lazy:
            self.raw_metrics["lcp_is_lazy"] = True
        fetchpriority_hero = any(img.get("fetchpriority") == "high" for img in images)
        if fetchpriority_hero:
            lcp_estimate -= 0.2
            self.raw_metrics["lcp_fetchpriority"] = True
        preloaded_font = any(
            p.get("as") == "font" for p in soup.find_all("link", rel="preload")
        )
        if preloaded_font:
            lcp_estimate -= 0.1
        hero_text = soup.find_all(["h1", "h2"])
        for tag in hero_text:
            if tag.string and len(tag.string.strip()) > 5:
                lcp_estimate += 0.1
                break
        lcp_estimate = max(0.2, lcp_estimate)
        lcp_ms = int(lcp_estimate * 1000)
        lcp_status = "excellent" if lcp_ms < 2500 else "needs_improvement" if lcp_ms < 4000 else "poor"
        lcp_detail = "Estimated from load time ({:.2f}s), page complexity".format(load_time)
        if lcp_element:
            lcp_detail += ", likely LCP element: " + lcp_element
        if hero_lcp_lazy:
            lcp_detail += " (WARNING: LCP candidate is lazy-loaded)"
        if fetchpriority_hero:
            lcp_detail += " (fetchpriority=high on hero image)"
        self.add_result("LCP (Largest Contentful Paint)", "{}ms".format(lcp_ms), lcp_status, "vitals",
                        lcp_detail, weight=5, effort=3)
        self.raw_metrics["lcp_ms"] = lcp_ms
        self.raw_metrics["lcp_element"] = lcp_element or "unknown"

        # --- FCP (First Contentful Paint) ---
        fcp_est = load_time * 0.6
        if len(html_content) > 50000:
            fcp_est += 0.3
        sync_head_scripts = [s for s in soup.find_all("script", src=True) if not s.get("async") and not s.get("defer") and s.parent and s.parent.name == "head"]
        fcp_est += len(sync_head_scripts) * 0.2
        fcp_elements = self._identify_fcp_element(soup, html_content)
        fcp_ms = int(fcp_est * 1000)
        fcp_status = "excellent" if fcp_ms < 1800 else "needs_improvement" if fcp_ms < 3000 else "poor"
        fcp_detail = "Based on HTML size ({:,} bytes) and render-blocking resources".format(len(html_content))
        if fcp_elements:
            fcp_detail += ", likely first paint: " + fcp_elements[0]
        self.add_result("FCP (First Contentful Paint)", "{}ms".format(fcp_ms), fcp_status, "vitals",
                        fcp_detail, weight=4, effort=3)
        self.raw_metrics["fcp_ms"] = fcp_ms

        # --- CLS (Cumulative Layout Shift - v4 source identification) ---
        cls_sources, no_dim_images, no_dim_iframes, dynamic_dom, dynamic_fonts = self._identify_cls_sources(soup, images)
        cls_score = 0.0
        cls_issues = list(cls_sources)
        cls_score += no_dim_images * 0.05
        cls_score += no_dim_iframes * 0.05
        if dynamic_dom:
            cls_score += 0.15
        if dynamic_fonts:
            cls_score += 0.1
        iframes_no_srcdoc = [i for i in soup.find_all("iframe") if not i.get("srcdoc") and not i.get("width")]
        cls_score += len(iframes_no_srcdoc) * 0.02
        if cls_score <= 0.1:
            cls_status = "excellent"
        elif cls_score <= 0.25:
            cls_status = "needs_improvement"
        else:
            cls_status = "poor"
        cls_detail = "; ".join(cls_sources[:3]) if cls_sources else "No layout shift issues detected"
        self.add_result("CLS (Cumulative Layout Shift)", "{:.2f}".format(cls_score), cls_status, "vitals", cls_detail,
                        weight=5, effort=3)
        self.raw_metrics["cls_score"] = round(cls_score, 3)
        self.raw_metrics["cls_sources"] = cls_sources

        # --- INP (Interaction to Next Paint - v4 element identification) ---
        inp_sources = self._identify_inp_elements(soup)
        inp_score = 0
        inp_issues = list(inp_sources)
        inline_js_count = len(inline_scripts)
        if inline_js_count > 3:
            inp_score += 2
            inp_issues.append(f"{inline_js_count} inline scripts detected")
        sync_scripts = [s for s in scripts if not s.get("async") and not s.get("defer")]
        if len(sync_scripts) > 2:
            inp_score += 2
            inp_issues.append(f"{len(sync_scripts)} sync scripts blocking interactions")
        event_handlers = 0
        for tag in soup.find_all(True):
            for attr in tag.attrs:
                if attr.startswith("on"):
                    event_handlers += 1
        if event_handlers > 10:
            inp_score += 1
            inp_issues.append(f"{event_handlers} inline event handlers")
        total_js_size = len("".join(s.string or "" for s in inline_scripts))
        if total_js_size > 50000:
            inp_score += 1
            inp_issues.append("Heavy inline JavaScript")
        input_handlers = len(soup.find_all(["input", "textarea", "select"]))
        if input_handlers > 5:
            inp_score += 1
            inp_issues.append(f"{input_handlers} form elements without event optimization")
        inp_score_ms = inp_score * 100
        inp_status = "excellent" if inp_score_ms <= 200 else "needs_improvement" if inp_score_ms <= 500 else "poor"
        inp_detail = "; ".join(inp_issues[:3]) if inp_issues else "Minimal blocking interactions"
        self.add_result("INP (Interaction to Next Paint)", "{}ms".format(inp_score_ms), inp_status, "vitals", inp_detail,
                        weight=4, effort=3)
        self.raw_metrics["inp_score"] = inp_score_ms
        self.raw_metrics["inp_sources"] = inp_sources

        # --- TBT (Total Blocking Time) ---
        tbt_score = 0
        tbt_issues = []
        for s in scripts:
            if not s.get("async") and not s.get("defer") and s.get("src"):
                tbt_score += 200
                tbt_issues.append(f"Sync script: {s.get('src', '')[:40]}")
        for script in inline_scripts:
            text_len = len(script.string or "")
            if text_len > 1000:
                tbt_score += min(text_len // 500, 150)
                tbt_issues.append("Large inline script block")
        if tbt_score <= 200:
            tbt_status = "excellent"
        elif tbt_score <= 600:
            tbt_status = "needs_improvement"
        else:
            tbt_status = "poor"
        tbt_detail = "; ".join(tbt_issues[:3]) if tbt_issues else "No significant blocking time"
        self.add_result("TBT (Total Blocking Time)", "{}ms".format(tbt_score), tbt_status, "vitals", tbt_detail,
                        weight=5, effort=3)
        self.raw_metrics["tbt_ms"] = tbt_score

        # --- Speed Index (refined v6: multi-factor visual completion model) ---
        render_blocking_css_v6 = 0
        for link in css_files:
            media = link.get("media", "")
            if not media or media == "all":
                render_blocking_css_v6 += 1
        lazy_imgs = sum(1 for img in images if img.get("loading") == "lazy")
        lazy_ratio = (lazy_imgs / len(images)) if images else 0.0
        modern_fmt = sum(
            1 for img in images
            if (img.get("src", "").rsplit(".", 1)[-1].split("?")[0].lower()
                if "." in img.get("src", "") else "") in ("webp", "avif", "svg")
        )
        modern_ratio = (modern_fmt / len(images)) if images else 0.0
        adaptive_imgs = sum(1 for img in images if img.get("srcset"))
        picture_count = len(soup.find_all("picture"))
        adaptive_ratio = ((adaptive_imgs + picture_count) / len(images)) if images else 0.0
        has_critical_inline = any(
            (style.string or "") and len(style.string or "") > 300
            for style in soup.find_all("style")
        )
        si_payload_component = len(html_content) / 600_000
        si_js_component = total_js * 0.04
        si_blocking_component = render_blocking_css_v6 * 0.15
        si_img_component = 0.0
        if largest_img_size > 500000:
            si_img_component += 0.4
        elif largest_img_size > 200000:
            si_img_component += 0.2
        if lazy_ratio > 0.5:
            si_img_component -= 0.15
        if modern_ratio > 0.5:
            si_img_component -= 0.1
        if adaptive_ratio > 0.5:
            si_img_component -= 0.1
        si_boost_component = 0.0
        if has_critical_inline:
            si_boost_component -= 0.2
        if modern_ratio > 0.5:
            si_boost_component -= 0.1
        # v7: containment skips offscreen work; backdrop-filter adds paint cost
        all_text_v7 = self._page_text(soup, html_content)
        cv_decls = len(re.findall(r"content-visibility\s*:", all_text_v7))
        si_containment_component = 0.0
        if cv_decls > 0:
            si_containment_component -= min(0.3, 0.05 * cv_decls)
        bd_decls = len(re.findall(r"backdrop-filter\s*:", all_text_v7))
        si_paint_component = bd_decls * 0.04
        if bd_decls > 4:
            si_paint_component += 0.12
        si_est = (
            (load_time * 1.15)
            + si_payload_component
            + si_js_component
            + si_blocking_component
            + si_img_component
            + si_boost_component
            + si_containment_component
            + si_paint_component
        )
        si_est = max(0.3, si_est)
        si_ms = int(si_est * 1000)
        si_status = "excellent" if si_ms < 3400 else "needs_improvement" if si_ms < 5800 else "poor"
        si_detail = ("Visual completion model: load {:+.0f}ms, payload {:+.0f}ms, JS {:+.0f}ms, "
                     "blocking CSS {:+.0f}ms, imagery {:+.0f}ms, containment {:+.0f}ms, paint {:+.0f}ms").format(
            load_time * 1150,
            si_payload_component * 1000,
            si_js_component * 1000,
            si_blocking_component * 1000,
            (si_img_component + si_boost_component) * 1000,
            si_containment_component * 1000,
            si_paint_component * 1000,
        )
        self.add_result("Speed Index (est.)", f"{si_ms}ms", si_status, "vitals",
                        si_detail,
                        weight=3, effort=3)
        self.raw_metrics["si_ms"] = si_ms
        self.raw_metrics["si_components"] = {
            "load_time_ms": int(load_time * 1150),
            "payload_ms": int(si_payload_component * 1000),
            "js_ms": int(si_js_component * 1000),
            "blocking_css_ms": int(si_blocking_component * 1000),
            "imagery_ms": int((si_img_component + si_boost_component) * 1000),
            "containment_ms": int(si_containment_component * 1000),
            "paint_ms": int(si_paint_component * 1000),
            "payload_kb": round(len(html_content) / 1024, 1),
            "js_count": total_js,
            "render_blocking_css": render_blocking_css_v6,
            "lazy_ratio": round(lazy_ratio * 100, 1),
            "modern_format_ratio": round(modern_ratio * 100, 1),
            "adaptive_ratio": round(adaptive_ratio * 100, 1),
            "critical_inline_css": has_critical_inline,
            "content_visibility_count": cv_decls,
            "backdrop_filter_count": bd_decls,
        }

        # --- DOM Content Loaded ---
        dcl_est = load_time * 0.75 + len(html_content) / 2_000_000
        dcl_ms = int(dcl_est * 1000)
        dcl_status = "excellent" if dcl_ms < 1500 else "needs_improvement" if dcl_ms < 3000 else "poor"
        self.add_result("DOMContentLoaded (est.)", f"{dcl_ms}ms", dcl_status, "vitals",
                        "Time to parse HTML and execute deferred scripts",
                        weight=2, effort=2)
        self.raw_metrics["dcl_ms"] = dcl_ms

        # --- First Meaningful Paint ---
        fmp_est = fcp_ms + 300
        if images:
            fmp_est += 200
        fmp_ms = int(fmp_est)
        fmp_status = "excellent" if fmp_ms < 2000 else "needs_improvement" if fmp_ms < 4000 else "poor"
        self.add_result("First Meaningful Paint (est.)", f"{fmp_ms}ms", fmp_status, "vitals",
                        "Estimated based on FCP and content complexity",
                        weight=3, effort=3)
        self.raw_metrics["fmp_ms"] = fmp_ms

    # ─────────────────────────────────────────────
    # CHECK: Timing (v3 - enhanced)
    # ─────────────────────────────────────────────
    def check_timing(self, url, html_content, response, dns_time, tcp_time, ssl_time, server_time, download_time, total_time):
        self.log("timing", "▸", "Measuring time metrics...")

        ttfb = server_time
        ttfb_total_ms = int(ttfb * 1000)
        dns_ms = int(dns_time * 1000)
        tcp_ms_val = int(tcp_time * 1000)
        ssl_ms_val = int(ssl_time * 1000)
        ttfb_breakdown = "DNS: {}ms, TCP: {}ms, TLS: {}ms, Server: {}ms".format(
            dns_ms, tcp_ms_val, ssl_ms_val, ttfb_total_ms)
        ttfb_status = "excellent" if ttfb < 0.2 else "needs_improvement" if ttfb < 0.8 else "poor"
        self.add_result("TTFB (Time to First Byte)", "{}ms".format(ttfb_total_ms), ttfb_status, "timing",
                        ttfb_breakdown, weight=5, effort=4)
        self.raw_metrics["ttfb_ms"] = ttfb_total_ms
        self.raw_metrics["ttfb_dns_ms"] = dns_ms
        self.raw_metrics["ttfb_tcp_ms"] = tcp_ms_val
        self.raw_metrics["ttfb_tls_ms"] = ssl_ms_val
        self.raw_metrics["ttfb_server_ms"] = ttfb_total_ms

        srv_time = server_time
        srv_status = "excellent" if srv_time < 0.2 else "needs_improvement" if srv_time < 0.6 else "poor"
        if srv_time < 0.1:
            srv_detail = "Excellent server processing speed"
        elif srv_time < 0.3:
            srv_detail = "Good server response, minor processing overhead"
        elif srv_time < 0.6:
            srv_detail = "Server processing noticeable; consider caching or CDN"
        else:
            srv_detail = "Slow server response; investigate backend performance"
        self.add_result("Server Response Time", f"{srv_time*1000:.0f}ms", srv_status, "timing", srv_detail,
                        weight=4, effort=4)
        self.raw_metrics["server_time_ms"] = int(srv_time * 1000)

        dns_status = "excellent" if dns_time < 0.05 else "needs_improvement" if dns_time < 0.3 else "poor"
        self.add_result("DNS Resolution", f"{dns_time*1000:.0f}ms", dns_status, "timing",
                        "Time to resolve hostname via DNS",
                        weight=2, effort=3)
        self.raw_metrics["dns_ms"] = int(dns_time * 1000)

        tcp_status = "excellent" if tcp_time < 0.1 else "needs_improvement" if tcp_time < 0.3 else "poor"
        self.add_result("TCP Connection", f"{tcp_time*1000:.0f}ms", tcp_status, "timing",
                        "Time to establish TCP connection",
                        weight=2, effort=4)
        self.raw_metrics["tcp_ms"] = int(tcp_time * 1000)

        if ssl_time > 0:
            ssl_status = "excellent" if ssl_time < 0.1 else "needs_improvement" if ssl_time < 0.5 else "poor"
            self.add_result("SSL/TLS Handshake", f"{ssl_time*1000:.0f}ms", ssl_status, "timing",
                            "Time for TLS negotiation",
                            weight=2, effort=5)
            self.raw_metrics["ssl_ms"] = int(ssl_time * 1000)

        if total_time < 2:
            load_status = "excellent"
        elif total_time < 5:
            load_status = "needs_improvement"
        else:
            load_status = "poor"
        self.add_result("Total Load Time", f"{total_time*1000:.0f}ms", load_status, "timing",
                        f"Full page download: {len(html_content):,} bytes",
                        weight=3, effort=3)
        self.raw_metrics["total_load_time_ms"] = int(total_time * 1000)

        html_size = len(html_content)
        parse_time_est = html_size / 1_000_000
        if html_size > 500000:
            parse_time_est += 0.3
        if html_size > 1000000:
            parse_time_est += 0.5
        parse_ms = int(parse_time_est * 1000)
        parse_status = "excellent" if parse_ms < 50 else "needs_improvement" if parse_ms < 200 else "poor"
        self.add_result("DOM Parse Time (est.)", f"{parse_ms}ms", parse_status, "timing",
                        f"HTML size: {html_size:,} bytes",
                        weight=2, effort=2)
        self.raw_metrics["dom_parse_ms"] = parse_ms

        soup = BeautifulSoup(html_content, "html.parser")
        scripts = soup.find_all("script", src=True)
        total_js = 0
        for s in scripts:
            src = s.get("src", "")
            if src:
                if src.startswith("//"):
                    src = "https:" + src
                elif src.startswith("/"):
                    parsed = urlparse(url)
                    src = f"{parsed.scheme}://{parsed.netloc}{src}"
                try:
                    r = self.session.head(src, timeout=5)
                    cl = r.headers.get("Content-Length", "0")
                    total_js += int(cl)
                except Exception:
                    pass
        cpu_mult = self.DEVICE_PROFILES.get(self.device, {}).get("cpu_multiplier", 1.0)
        conn_mult = self.CONNECTION_PROFILES.get(self.connection, {}).get("multiplier", 1.0)
        tti_est = total_time + (total_js / 500_000) * cpu_mult
        if total_js > 500000:
            tti_est += 1.0 * cpu_mult
        tti_est *= conn_mult
        tti_ms = int(tti_est * 1000)
        tti_status = "excellent" if tti_ms < 3800 else "needs_improvement" if tti_ms < 7300 else "poor"
        self.add_result("Time to Interactive (est.)", "{}ms".format(tti_ms), tti_status, "timing",
                        "Based on JS payload: {:,} bytes, CPU: {}x, Network: {}x".format(
                            total_js, cpu_mult, conn_mult), weight=4, effort=3)
        self.raw_metrics["tti_ms"] = tti_ms
        self.raw_metrics["total_js_bytes"] = total_js

    # ─────────────────────────────────────────────
    # CHECK: Resources (v3 - enhanced)
    # ─────────────────────────────────────────────
    def check_resources(self, soup, base_url):
        self.log("resources", "▸", "Analyzing resources...")

        all_resources = []
        css_files = soup.find_all("link", rel="stylesheet")
        js_files = soup.find_all("script", src=True)
        images = soup.find_all("img")
        font_links = soup.find_all("link", rel=lambda x: x and "font" in x.lower())

        total_size = 0
        css_count = len(css_files)
        css_size = 0
        render_blocking_css = 0
        for link in css_files:
            href = link.get("href", "")
            if href:
                full_url = urljoin(base_url, href)
                try:
                    r = self.session.head(full_url, timeout=5)
                    size = int(r.headers.get("Content-Length", 0))
                    css_size += size
                    total_size += size
                    if not link.get("media"):
                        render_blocking_css += 1
                except Exception:
                    pass
        if css_count > 0:
            if render_blocking_css == 0:
                css_status = "excellent"
            elif render_blocking_css <= 2:
                css_status = "needs_improvement"
            else:
                css_status = "poor"
            self.add_result("CSS Files", f"{css_count} files ({css_size/1024:.1f}KB)", css_status, "resources",
                            f"Render-blocking: {render_blocking_css}",
                            weight=2, effort=2)
            self.raw_metrics["css_count"] = css_count
            self.raw_metrics["css_size"] = css_size
            self.raw_metrics["render_blocking_css"] = render_blocking_css

        js_count = len(js_files)
        js_size = 0
        inline_js = len(soup.find_all("script", src=False))
        async_count = 0
        defer_count = 0
        for s in js_files:
            src = s.get("src", "")
            if src:
                if s.get("async"):
                    async_count += 1
                elif s.get("defer"):
                    defer_count += 1
                full_url = urljoin(base_url, src)
                try:
                    r = self.session.head(full_url, timeout=5)
                    size = int(r.headers.get("Content-Length", 0))
                    js_size += size
                    total_size += size
                except Exception:
                    pass
        sync_js = js_count - async_count - defer_count
        if js_count > 0:
            if sync_js == 0:
                js_status = "excellent"
            elif sync_js <= 2:
                js_status = "needs_improvement"
            else:
                js_status = "poor"
            self.add_result("JavaScript Files", f"{js_count} files ({js_size/1024:.1f}KB)", js_status, "resources",
                            f"Async: {async_count}, Defer: {defer_count}, Sync: {sync_js}, Inline: {inline_js}",
                            weight=3, effort=2)
            self.raw_metrics["js_count"] = js_count
            self.raw_metrics["js_size"] = js_size

        img_count = len(images)
        img_size = 0
        formats = {}
        lazy_count = 0
        for img in images:
            src = img.get("src", "")
            if src:
                ext = src.rsplit(".", 1)[-1].split("?")[0].lower() if "." in src else "unknown"
                formats[ext] = formats.get(ext, 0) + 1
                if img.get("loading") == "lazy":
                    lazy_count += 1
                full_url = urljoin(base_url, src)
                try:
                    r = self.session.head(full_url, timeout=5)
                    size = int(r.headers.get("Content-Length", 0))
                    img_size += size
                    total_size += size
                except Exception:
                    pass
        if img_count > 0:
            fmt_str = ", ".join(f"{k}:{v}" for k, v in sorted(formats.items()))
            lazy_pct = (lazy_count / img_count * 100) if img_count else 0
            if lazy_pct > 50:
                img_status = "excellent"
            elif lazy_pct > 0:
                img_status = "needs_improvement"
            else:
                img_status = "poor"
            self.add_result("Images", f"{img_count} images ({img_size/1024:.1f}KB)", img_status, "resources",
                            f"Formats: {fmt_str}, Lazy: {lazy_count}/{img_count}",
                            weight=2, effort=2)
            self.raw_metrics["img_count"] = img_count
            self.raw_metrics["img_size"] = img_size

        html_size = len(soup.encode())
        total_size += html_size
        total_count = css_count + js_count + img_count + len(font_links)
        if total_count > 50:
            total_status = "poor"
        elif total_count > 25:
            total_status = "needs_improvement"
        else:
            total_status = "excellent"
        self.add_result("Total Resources", f"{total_count} files ({total_size/1024:.1f}KB)", total_status, "resources",
                        f"HTML: {html_size/1024:.1f}KB",
                        weight=2, effort=2)
        self.raw_metrics["total_resources"] = total_count
        self.raw_metrics["total_page_size"] = total_size

        font_count = len(font_links)
        if font_count > 0:
            font_size = 0
            for fl in font_links:
                href = fl.get("href", "")
                if href:
                    full_url = urljoin(base_url, href)
                    try:
                        r = self.session.head(full_url, timeout=5)
                        font_size += int(r.headers.get("Content-Length", 0))
                    except Exception:
                        pass
            self.add_result("Web Fonts", f"{font_count} fonts ({font_size/1024:.1f}KB)", "good", "resources",
                            weight=1, effort=1)
            self.raw_metrics["font_count"] = font_count
            self.raw_metrics["font_size"] = font_size

        external_domains = {}
        parsed_base = urlparse(base_url)
        for tag in soup.find_all(["img", "script", "link", "iframe", "source"]):
            for attr in ["src", "href", "data-src"]:
                val = tag.get(attr, "")
                if val and val.startswith("http"):
                    parsed = urlparse(val)
                    if parsed.netloc and parsed.netloc != parsed_base.netloc:
                        if parsed.netloc not in external_domains:
                            external_domains[parsed.netloc] = {"count": 0, "category": self._categorize_third_party(parsed.netloc)}
                        external_domains[parsed.netloc]["count"] += 1
        if external_domains:
            total_3p = sum(d["count"] for d in external_domains.values())
            domains_str = ", ".join(f"{d['category']} ({d['count']})" for _, d in sorted(external_domains.items(), key=lambda x: -x[1]["count"])[:6])
            third_p_status = "excellent" if len(external_domains) <= 3 else "needs_improvement" if len(external_domains) <= 8 else "poor"
            self.add_result("Third-party Resources", f"{len(external_domains)} domains ({total_3p} requests)", third_p_status, "resources",
                            f"Domains: {domains_str}",
                            weight=2, effort=2)
            self.raw_metrics["third_party_domains"] = len(external_domains)
            self.raw_metrics["third_party_requests"] = total_3p
            self.raw_metrics["third_party_details"] = {k: v for k, v in external_domains.items()}

        resource_order = []
        head_scripts = soup.find_all("script", src=True)
        for s in head_scripts:
            if not s.get("async") and not s.get("defer"):
                resource_order.append(("sync_js", s.get("src", "")[:40]))
        for s in soup.find_all("link", rel="stylesheet"):
            resource_order.append(("css", s.get("href", "")[:40]))
        for s in head_scripts:
            if s.get("defer"):
                resource_order.append(("defer_js", s.get("src", "")[:40]))
        for s in head_scripts:
            if s.get("async"):
                resource_order.append(("async_js", s.get("src", "")[:40]))
        if resource_order:
            order_detail = " -> ".join(f"[{t}]" for t, _ in resource_order[:8])
            order_status = "excellent" if len([t for t, _ in resource_order if t == "sync_js"]) == 0 else "needs_improvement"
            self.add_result("Resource Loading Order", f"{len(resource_order)} critical resources", order_status, "resources",
                            order_detail,
                            weight=1, effort=2)
        self.raw_metrics["resource_order"] = [t for t, _ in resource_order]

    # ─────────────────────────────────────────────
    # CHECK: Resource Priority Analysis (v3 NEW)
    # ─────────────────────────────────────────────
    def check_resource_priority(self, soup, base_url):
        self.log("resources", "▸", "Analyzing resource priority hints...")

        preloads = soup.find_all("link", rel="preload")
        prefetches = soup.find_all("link", rel="prefetch")
        preconnects = soup.find_all("link", rel="preconnect")
        dns_prefetches = soup.find_all("link", rel="dns-prefetch")
        modulepreloads = soup.find_all("link", rel="modulepreload")

        score = 0
        issues = []

        if preloads:
            preload_as = {}
            for p in preloads:
                as_type = p.get("as", "unknown")
                preload_as[as_type] = preload_as.get(as_type, 0) + 1
            preload_str = ", ".join(f"{k}:{v}" for k, v in preload_as.items())
            issues.append(f"{len(preloads)} preloads ({preload_str})")
            score += 2

        if preconnects:
            issues.append(f"{len(preconnects)} preconnects")
            score += 2

        if dns_prefetches:
            issues.append(f"{len(dns_prefetches)} dns-prefetches")
            score += 1

        if prefetches:
            issues.append(f"{len(prefetches)} prefetches")
            score += 1

        if modulepreloads:
            issues.append(f"{len(modulepreloads)} modulepreloads")
            score += 1

        parsed_base = urlparse(base_url)
        third_party_origins = set()
        for tag in soup.find_all(["script", "link", "iframe"]):
            for attr in ["src", "href"]:
                val = tag.get(attr, "")
                if val and val.startswith("http"):
                    parsed = urlparse(val)
                    if parsed.netloc and parsed.netloc != parsed_base.netloc:
                        third_party_origins.add(f"{parsed.scheme}://{parsed.netloc}")

        preconnect_origins = set()
        for pc in preconnects:
            href = pc.get("href", "")
            if href:
                preconnect_origins.add(href.rstrip("/"))

        missing_preconnects = []
        for origin in third_party_origins:
            if origin not in preconnect_origins:
                missing_preconnects.append(origin)

        if missing_preconnects and len(third_party_origins) > 2:
            issues.append(f"{len(missing_preconnects)} origins without preconnect")
            score -= 1

        total_hints = len(preloads) + len(prefetches) + len(dns_prefetches) + len(preconnects) + len(modulepreloads)
        if score >= 4:
            status = "excellent"
        elif score >= 2:
            status = "good"
        elif total_hints > 0:
            status = "needs_improvement"
        else:
            status = "poor"

        self.add_result("Resource Priority Hints", f"{total_hints} hints", status, "resources",
                        "; ".join(issues[:4]) if issues else "No resource hints found",
                        weight=3, effort=2)
        self.raw_metrics["resource_priority_score"] = score


    # ─────────────────────────────────────────────
    # CHECK: Resource Hints Analysis (v4 NEW)
    # ─────────────────────────────────────────────
    def check_resource_hints(self, soup, base_url, response_headers=None):
        self.log("resources", "▸", "Analyzing resource hints (v4 deep validation)...")

        preloads = soup.find_all("link", rel="preload")
        prefetches = soup.find_all("link", rel="prefetch")
        preconnects = soup.find_all("link", rel="preconnect")
        dns_prefetches = soup.find_all("link", rel="dns-prefetch")
        modulepreloads = soup.find_all("link", rel="modulepreload")
        parsed_base = urlparse(base_url)

        preload_issues = []
        preload_valid = 0
        for p in preloads:
            href = p.get("href", "")
            as_type = p.get("as", "")
            crossorigin = p.get("crossorigin")
            if not href:
                preload_issues.append("Preload without href")
                continue
            if not as_type:
                preload_issues.append("Preload without 'as' attribute: " + href[:40])
            else:
                preload_valid += 1
            if as_type == "font" and not crossorigin:
                preload_issues.append("Font preload without crossorigin: " + href[:30])
        preload_status = "excellent" if preload_valid > 0 and not preload_issues else "good" if preload_valid > 0 else "needs_improvement" if preloads else "poor"
        self.add_result("Preload Hints", "{} preloaded ({} valid)".format(len(preloads), preload_valid), preload_status, "resources",
                        "; ".join(preload_issues[:3]) if preload_issues else "Preload hints properly configured" if preloads else "No preload hints found",
                        weight=2, effort=2)
        self.raw_metrics["preload_count"] = len(preloads)

        prefetch_issues = []
        if len(prefetches) > 5:
            prefetch_issues.append("Too many prefetches may waste bandwidth")
        prefetch_status = "excellent" if 1 <= len(prefetches) <= 5 else "good" if len(prefetches) > 0 else "needs_improvement"
        self.add_result("Prefetch Hints", "{} prefetches".format(len(prefetches)), prefetch_status, "resources",
                        "; ".join(prefetch_issues[:2]) if prefetch_issues else "Prefetch hints for next-page resources" if prefetches else "No prefetch hints",
                        weight=1, effort=1)
        self.raw_metrics["prefetch_count"] = len(prefetches)

        preconnect_origins = set()
        preconnect_issues = []
        for pc in preconnects:
            href = pc.get("href", "")
            if href:
                preconnect_origins.add(href.rstrip("/"))
                crossorigin = pc.get("crossorigin")
                if not crossorigin:
                    preconnect_issues.append("Preconnect without crossorigin: " + href[:40])
        third_party_origins = set()
        for tag in soup.find_all(["script", "link", "iframe"]):
            for attr in ["src", "href"]:
                val = tag.get(attr, "")
                if val and val.startswith("http"):
                    parsed = urlparse(val)
                    if parsed.netloc and parsed.netloc != parsed_base.netloc:
                        third_party_origins.add("{}://{}".format(parsed.scheme, parsed.netloc))
        missing_preconnects = [o for o in third_party_origins if o not in preconnect_origins]
        if missing_preconnects:
            preconnect_issues.append("{} origins missing preconnect".format(len(missing_preconnects)))
        preconnect_status = "excellent" if preconnects and not missing_preconnects else "good" if preconnects else "needs_improvement" if third_party_origins else "poor"
        self.add_result("Preconnect Hints", "{} preconnects".format(len(preconnects)), preconnect_status, "resources",
                        "; ".join(preconnect_issues[:2]) if preconnect_issues else "Preconnects established for third-party origins" if preconnects else "No preconnect hints",
                        weight=2, effort=2)
        self.raw_metrics["preconnect_count"] = len(preconnects)
        self.raw_metrics["missing_preconnects"] = len(missing_preconnects)

        dns_prefetch_origins = set()
        for dp in dns_prefetches:
            href = dp.get("href", "")
            if href:
                dns_prefetch_origins.add(href.rstrip("/"))
        redundant = dns_prefetch_origins & preconnect_origins
        dns_issues = []
        if redundant:
            dns_issues.append("{} redundant (preconnect already covers)".format(len(redundant)))
        dns_status = "excellent" if dns_prefetches and not redundant else "good" if dns_prefetches else "needs_improvement"
        self.add_result("DNS-Prefetch Hints", "{} dns-prefetches".format(len(dns_prefetches)), dns_status, "resources",
                        "; ".join(dns_issues[:2]) if dns_issues else "DNS resolution ahead of time for third-party domains" if dns_prefetches else "No dns-prefetch hints",
                        weight=1, effort=1)
        self.raw_metrics["dns_prefetch_count"] = len(dns_prefetches)

        modulepreload_issues = []
        for mp in modulepreloads:
            href = mp.get("href", "")
            if href and not href.endswith(".js") and not href.endswith(".mjs"):
                modulepreload_issues.append("Non-JS modulepreload: " + href[:40])
        modulepreload_status = "excellent" if modulepreloads else "good"
        self.add_result("Modulepreload Hints", "{} modulepreloads".format(len(modulepreloads)), modulepreload_status, "resources",
                        "; ".join(modulepreload_issues[:2]) if modulepreload_issues else "Module preloading for ES modules" if modulepreloads else "No modulepreload hints (OK if not using ES modules)",
                        weight=1, effort=1)
        self.raw_metrics["modulepreload_count"] = len(modulepreloads)

        early_hints_link = ""
        if response_headers:
            early_hints_link = response_headers.get("Link", "")
        has_early_hints_preload = 'rel="preload"' in early_hints_link or "rel=preload" in early_hints_link
        early_hints_status = "excellent" if has_early_hints_preload else "needs_improvement"
        self.add_result("103 Early Hints", "Supported" if has_early_hints_preload else "Not detected", early_hints_status, "resources",
                        "Preload hints in Link header for early delivery" if has_early_hints_preload else "No 103 Early Hints preloading detected",
                        weight=2, effort=4)
        self.raw_metrics["early_hints_103"] = has_early_hints_preload

        total_hints = len(preloads) + len(prefetches) + len(dns_prefetches) + len(preconnects) + len(modulepreloads)
        hints_score = 0
        if preloads: hints_score += 2
        if preconnects: hints_score += 2
        if dns_prefetches: hints_score += 1
        if prefetches: hints_score += 1
        if modulepreloads: hints_score += 1
        if missing_preconnects: hints_score -= 1
        if redundant: hints_score -= 1
        if hints_score >= 4:
            overall_hints_status = "excellent"
        elif hints_score >= 2:
            overall_hints_status = "good"
        elif total_hints > 0:
            overall_hints_status = "needs_improvement"
        else:
            overall_hints_status = "poor"
        self.add_result("Resource Hints Overview", "{} total hints (score: {})".format(total_hints, hints_score), overall_hints_status, "resources",
                        "Preload: {}, Prefetch: {}, Preconnect: {}, DNS-Prefetch: {}, Modulepreload: {}".format(
                            len(preloads), len(prefetches), len(preconnects), len(dns_prefetches), len(modulepreloads)),
                        weight=3, effort=2)
        self.raw_metrics["resource_hints"] = total_hints
        self.raw_metrics["resource_hints_score"] = hints_score

    # ─────────────────────────────────────────────
    # CHECK: Resource Loading Optimization (v6)
    # ─────────────────────────────────────────────
    def check_resource_loading_optimization(self, soup, base_url):
        self.log("resources", "▸", "Evaluating resource loading optimization...")

        scripts = soup.find_all("script", src=True)
        css_links = soup.find_all("link", rel="stylesheet")
        images = soup.find_all("img")

        async_count = sum(1 for s in scripts if s.get("async"))
        defer_count = sum(1 for s in scripts if s.get("defer"))
        sync_count = len(scripts) - async_count - defer_count
        non_blocking_ratio = ((async_count + defer_count) / len(scripts)) if scripts else 1.0

        fetchpriority_assets = sum(
            1 for tag in soup.find_all(True) if tag.get("fetchpriority")
        )
        decoding_async = sum(1 for img in images if img.get("decoding") == "async")
        eager_above_fold = sum(
            1 for img in images
            if img.get("loading") == "eager" or img.get("fetchpriority") == "high"
        )
        lazy_count = sum(1 for img in images if img.get("loading") == "lazy")
        media_deferred_css = sum(
            1 for link in css_links if link.get("media") and link.get("media") != "all"
        )
        preloads = soup.find_all("link", rel="preload")
        preconnects = soup.find_all("link", rel="preconnect")
        modulepreloads = soup.find_all("link", rel="modulepreload")

        blocking_bytes_est = sync_count * 80_000 + max(0, len(css_links) - media_deferred_css) * 50_000

        score = 0
        details = []
        if scripts:
            if non_blocking_ratio >= 0.8:
                score += 3
                details.append("{:.0f}% scripts non-blocking".format(non_blocking_ratio * 100))
            elif non_blocking_ratio >= 0.5:
                score += 1
                details.append("{:.0f}% scripts non-blocking".format(non_blocking_ratio * 100))
            if sync_count > 0:
                score -= 1
                details.append("{} sync scripts on critical path".format(sync_count))
        else:
            score += 1

        if fetchpriority_assets:
            score += 2
            details.append("{} fetchpriority hints".format(fetchpriority_assets))
        if eager_above_fold:
            score += 1
            details.append("{} prioritized above-the-fold images".format(eager_above_fold))
        if images and lazy_count / len(images) >= 0.5:
            score += 2
            details.append("{}/{} images lazy-loaded".format(lazy_count, len(images)))
        elif images and lazy_count > 0:
            score += 1
            details.append("{}/{} images lazy-loaded".format(lazy_count, len(images)))
        if decoding_async:
            score += 1
            details.append("{} images with decoding=async".format(decoding_async))
        if media_deferred_css:
            score += 2
            details.append("{} non-blocking stylesheets via media queries".format(media_deferred_css))
        if preloads:
            score += 1
            details.append("{} preload hints active".format(len(preloads)))
        if preconnects:
            score += 1
            details.append("{} preconnects active".format(len(preconnects)))
        if modulepreloads:
            score += 1
            details.append("{} modulepreloads active".format(len(modulepreloads)))
        if blocking_bytes_est > 150_000:
            score -= 1
            details.append("~{:.0f}KB estimated render-blocking payload".format(blocking_bytes_est / 1024))
        if not details:
            details.append("No explicit resource loading optimizations detected")

        if score >= 6:
            status = "excellent"
        elif score >= 3:
            status = "good"
        elif score >= 0:
            status = "needs_improvement"
        else:
            status = "poor"

        value = "score {}/10".format(max(0, min(10, score)))
        self.add_result("Resource Loading Optimization", value, status, "resources",
                        "; ".join(details[:5]),
                        weight=3, effort=2)
        self.raw_metrics["resource_loading_score"] = score
        self.raw_metrics["non_blocking_script_ratio"] = round(non_blocking_ratio * 100, 1)
        self.raw_metrics["fetchpriority_assets"] = fetchpriority_assets
        self.raw_metrics["blocking_payload_est"] = blocking_bytes_est

    # ─────────────────────────────────────────────
    # CHECK: Layout Shift Detection (v4 NEW)
    # ─────────────────────────────────────────────
    def check_layout_shift_detection(self, soup, html_content):
        self.log("rendering", "▸", "Detecting layout shift patterns...")

        layout_shift_sources = []
        images = soup.find_all("img")
        no_dim_count = 0
        for img in images:
            if not img.get("width") and not img.get("height"):
                no_dim_count += 1
                layout_shift_sources.append("img without dimensions: " + img.get("src", "unknown")[:50])

        late_loaded_fonts = 0
        for style in soup.find_all("style"):
            if "@font-face" in (style.string or ""):
                late_loaded_fonts += 1
        if late_loaded_fonts > 0:
            layout_shift_sources.append("{} @font-face declarations (may cause FOUT)".format(late_loaded_fonts))

        dynamic_content_scripts = 0
        for script in soup.find_all("script", src=False):
            text = script.string or ""
            if "innerHTML" in text or "insertAdjacentHTML" in text or "document.write" in text:
                dynamic_content_scripts += 1
        if dynamic_content_scripts > 0:
            layout_shift_sources.append("{} scripts with dynamic content injection".format(dynamic_content_scripts))

        ad_slots = 0
        for div in soup.find_all("div", class_=True):
            cls = " ".join(div.get("class", []))
            if "ad" in cls.lower() or "banner" in cls.lower() or "sponsor" in cls.lower():
                ad_slots += 1
        if ad_slots > 0:
            layout_shift_sources.append("{} potential ad/sponsor slots".format(ad_slots))

        embeds = soup.find_all("iframe")
        no_dim_embeds = sum(1 for e in embeds if not e.get("width") or not e.get("height"))
        if no_dim_embeds > 0:
            layout_shift_sources.append("{} iframes without dimensions".format(no_dim_embeds))

        total_score = (no_dim_count * 0.05 + late_loaded_fonts * 0.1 +
                       dynamic_content_scripts * 0.15 + ad_slots * 0.08 + no_dim_embeds * 0.05)
        status = "excellent" if total_score <= 0.1 else "needs_improvement" if total_score <= 0.25 else "poor"
        self.add_result("Layout Shift Detection", "{:.2f} shift score".format(total_score), status, "rendering",
                        "; ".join(layout_shift_sources[:4]) if layout_shift_sources else "No layout shift patterns detected",
                        weight=3, effort=3)
        self.raw_metrics["layout_shift_score"] = round(total_score, 3)

    # ─────────────────────────────────────────────
    # CHECK: Long Task Detection (v4 NEW)
    # ─────────────────────────────────────────────
    def check_long_task_detection(self, soup, html_content):
        self.log("rendering", "▸", "Detecting long tasks...")

        long_tasks = []
        inline_scripts = soup.find_all("script", src=False)
        total_inline_size = 0
        for script in inline_scripts:
            text = script.string or ""
            size = len(text)
            total_inline_size += size
            if size > 50000:
                long_tasks.append("Heavy inline script ({:.1f}KB)".format(size / 1024))
            loops = len(re.findall(r'for\s*\(', text))
            if loops > 3:
                long_tasks.append("Inline script with {} loops".format(loops))
            timers = text.count("setTimeout") + text.count("setInterval")
            if timers > 2:
                long_tasks.append("Script with {} timers".format(timers))

        sync_scripts = [s for s in soup.find_all("script", src=True) if not s.get("async") and not s.get("defer")]
        if len(sync_scripts) > 3:
            long_tasks.append("{} sync scripts create sequential blocking".format(len(sync_scripts)))

        heavy_dom_scripts = 0
        for script in soup.find_all("script", src=False):
            text = script.string or ""
            dom_ops = text.count("querySelector") + text.count("getElementById") + text.count("createElement") + text.count("appendChild")
            if dom_ops > 20:
                heavy_dom_scripts += 1
                long_tasks.append("Script with {} DOM operations".format(dom_ops))

        if total_inline_size > 100000:
            long_tasks.append("Total inline JS: {:.1f}KB (heavy)".format(total_inline_size / 1024))

        if not long_tasks:
            status = "excellent"
            detail = "No long task patterns detected"
        elif len(long_tasks) <= 2:
            status = "needs_improvement"
            detail = "; ".join(long_tasks[:3])
        else:
            status = "poor"
            detail = "; ".join(long_tasks[:4])

        self.add_result("Long Task Detection", "{} potential long tasks".format(len(long_tasks)), status, "rendering",
                        detail, weight=3, effort=3)
        self.raw_metrics["long_task_count"] = len(long_tasks)

    # ─────────────────────────────────────────────
    # CHECK: Main Thread Blocking Analysis (v4 NEW)
    # ─────────────────────────────────────────────
    def check_main_thread_blocking(self, soup, html_content):
        self.log("rendering", "▸", "Analyzing main thread blocking...")

        blocking_sources = []
        blocking_score = 0

        inline_scripts = soup.find_all("script", src=False)
        for script in inline_scripts:
            text = script.string or ""
            size = len(text)
            if size > 30000:
                blocking_score += 2
                blocking_sources.append("Large inline script ({:.0f}KB)".format(size / 1024))
            if "document.write" in text:
                blocking_score += 3
                blocking_sources.append("document.write() blocks parser")
            if "alert(" in text:
                blocking_score += 2
                blocking_sources.append("alert() blocks main thread")

        sync_scripts = [s for s in soup.find_all("script", src=True) if not s.get("async") and not s.get("defer")]
        blocking_score += len(sync_scripts) * 2
        if sync_scripts:
            blocking_sources.append("{} synchronous scripts block parsing".format(len(sync_scripts)))

        blocking_css = 0
        head = soup.find("head")
        if head:
            for css in head.find_all("link", rel="stylesheet"):
                media = css.get("media", "")
                if not media or media == "all":
                    blocking_css += 1
        blocking_score += blocking_css
        if blocking_css > 0:
            blocking_sources.append("{} render-blocking CSS files".format(blocking_css))

        resize_listeners = len(re.findall(r'addEventListener\s*\(\s*["\']resize["\']', html_content))
        scroll_listeners = len(re.findall(r'addEventListener\s*\(\s*["\']scroll["\']', html_content))
        if resize_listeners + scroll_listeners > 4:
            blocking_score += 1
            blocking_sources.append("{} scroll/resize listeners without throttle".format(resize_listeners + scroll_listeners))

        if blocking_score <= 1:
            status = "excellent"
            detail = "Main thread is not significantly blocked"
        elif blocking_score <= 5:
            status = "needs_improvement"
            detail = "; ".join(blocking_sources[:3])
        else:
            status = "poor"
            detail = "; ".join(blocking_sources[:4])

        self.add_result("Main Thread Blocking", "Score: {}".format(blocking_score), status, "rendering",
                        detail, weight=3, effort=3)
        self.raw_metrics["main_thread_blocking_score"] = blocking_score

    # ─────────────────────────────────────────────
    # CHECK: Memory Usage Estimation (v7 refined)
    # ─────────────────────────────────────────────
    def check_memory_usage(self, soup, html_content):
        self.log("memory", "▸", "Estimating memory usage (v7 refined)...")

        memory_estimates = {}
        total_memory_kb = 0

        html_size_kb = len(html_content.encode("utf-8")) / 1024
        memory_estimates["html_dom"] = html_size_kb * 2
        total_memory_kb += html_size_kb * 2

        dom_elements = len(soup.find_all(True))
        dom_memory_kb = dom_elements * 0.5
        memory_estimates["dom_nodes"] = dom_memory_kb
        total_memory_kb += dom_memory_kb

        inline_scripts = soup.find_all("script", src=False)
        js_memory = sum(len(s.string or "") for s in inline_scripts) / 1024
        memory_estimates["inline_js"] = js_memory
        total_memory_kb += js_memory

        css_links = soup.find_all("link", rel="stylesheet")
        inline_css_kb = sum(len(s.string or "") for s in soup.find_all("style")) / 1024
        css_memory_kb = inline_css_kb + len(css_links) * 15
        memory_estimates["stylesheets"] = css_memory_kb
        total_memory_kb += css_memory_kb

        images = soup.find_all("img")
        image_memory_kb = 0.0
        for img in images:
            w = h = 0
            try:
                w = int(img.get("width", 0))
            except (ValueError, TypeError):
                pass
            try:
                h = int(img.get("height", 0))
            except (ValueError, TypeError):
                pass
            if w > 0 and h > 0:
                image_memory_kb += (w * h * 4) / 1024
            else:
                image_memory_kb += 200
        memory_estimates["images_decoded"] = image_memory_kb
        total_memory_kb += image_memory_kb

        event_listeners_est = 0
        for tag in soup.find_all(True):
            for attr in tag.attrs:
                if attr.startswith("on"):
                    event_listeners_est += 1
        listener_memory = event_listeners_est * 2
        memory_estimates["event_listeners"] = listener_memory
        total_memory_kb += listener_memory

        all_text = self._page_text(soup, html_content)
        will_change_layers = len(re.findall(r"will-change\s*:", all_text))
        will_change_kb = will_change_layers * 256
        memory_estimates["will_change_layers"] = will_change_kb
        total_memory_kb += will_change_kb

        backdrop_filters = len(re.findall(r"backdrop-filter\s*:", all_text))
        backdrop_kb = backdrop_filters * 512
        memory_estimates["backdrop_filter_buffers"] = backdrop_kb
        total_memory_kb += backdrop_kb

        innerhtml_sets = all_text.count(".innerHTML")
        churn_kb = min(innerhtml_sets, 40) * 5
        memory_estimates["dom_churn"] = churn_kb
        total_memory_kb += churn_kb

        content_visibility = len(re.findall(r"content-visibility\s*:", all_text))
        cv_savings_kb = content_visibility * 100
        memory_estimates["content_visibility_savings"] = -cv_savings_kb
        total_memory_kb -= cv_savings_kb
        total_memory_kb = max(total_memory_kb, 0)

        if total_memory_kb < 8000:
            status = "excellent"
            detail = "Estimated page memory: {:.0f}KB ({:.1f}MB)".format(total_memory_kb, total_memory_kb / 1024)
        elif total_memory_kb < 20000:
            status = "needs_improvement"
            detail = "Estimated page memory: {:.0f}KB ({:.1f}MB) - trim DOM/images or apply containment".format(
                total_memory_kb, total_memory_kb / 1024)
        else:
            status = "poor"
            detail = "Estimated page memory: {:.0f}KB ({:.1f}MB) - significant memory pressure".format(
                total_memory_kb, total_memory_kb / 1024)

        breakdown = "DOM: {}, Images: {:.0f}KB, CSS: {:.0f}KB, Listeners: {}, will-change: {} layers, backdrop-filter: {}".format(
            dom_elements, image_memory_kb, css_memory_kb, event_listeners_est,
            will_change_layers, backdrop_filters)
        if content_visibility:
            breakdown += ", content-visibility saves ~{:.0f}KB".format(cv_savings_kb)
        self.add_result("Memory Usage Estimation", "{:.0f}KB estimated".format(total_memory_kb), status, "memory",
                        detail + " | " + breakdown, weight=3, effort=3)
        self.raw_metrics["memory_estimated_kb"] = int(total_memory_kb)
        self.raw_metrics["dom_elements"] = dom_elements
        self.raw_metrics["memory_breakdown"] = {k: int(v) for k, v in memory_estimates.items()}
        self.raw_metrics["image_decode_kb"] = int(image_memory_kb)

    # ─────────────────────────────────────────────
    # CHECK: Render-blocking Detection (v3 NEW)
    # ─────────────────────────────────────────────
    def check_render_blocking_resources(self, soup, base_url):
        self.log("resources", "▸", "Detecting render-blocking resources...")

        render_blocking = []
        total_blocking_size = 0
        head = soup.find("head")

        if head:
            for css in head.find_all("link", rel="stylesheet"):
                href = css.get("href", "unknown")
                media = css.get("media", "")
                if not media or media == "all":
                    render_blocking.append({"type": "css", "url": href[:60], "size_estimate": 50000})
                    total_blocking_size += 50000

            for script in head.find_all("script", src=True):
                if not script.get("async") and not script.get("defer"):
                    src = script.get("src", "unknown")
                    render_blocking.append({"type": "js", "url": src[:60], "size_estimate": 80000})
                    total_blocking_size += 80000

        rb_count = len(render_blocking)
        if rb_count == 0:
            status = "excellent"
            detail = "No render-blocking resources in head"
        elif rb_count <= 2:
            status = "needs_improvement"
            detail = "; ".join(f"[{r['type']}] {r['url']}" for r in render_blocking[:3])
        else:
            status = "poor"
            detail = f"{rb_count} render-blocking resources ({total_blocking_size/1024:.0f}KB estimate)"

        self.add_result("Render-blocking Resources", f"{rb_count} found", status, "rendering",
                        detail, weight=4, effort=2)
        self.raw_metrics["render_blocking_resources"] = rb_count
        self.raw_metrics["render_blocking_size"] = total_blocking_size

    # ─────────────────────────────────────────────
    # CHECK: Critical CSS Hints (v3 NEW)
    # ─────────────────────────────────────────────
    def check_critical_css(self, soup, html_content):
        self.log("resources", "▸", "Analyzing critical CSS patterns...")

        inline_styles = soup.find_all("style")
        inline_css_size = sum(len(s.string or "") for s in inline_styles)
        has_critical_inline = False
        critical_indicators = []

        for style in inline_styles:
            text = style.string or ""
            if "font-display" in text or "@font-face" in text:
                has_critical_inline = True
                critical_indicators.append("Inline @font-face declarations")
            if "above-the-fold" in text or "critical" in text:
                has_critical_inline = True
                critical_indicators.append("Labeled critical CSS")
            if "clip-path" in text or "transform" in text or "animation" in text:
                critical_indicators.append("Inline animation/transform CSS")

        non_blocking_css = 0
        for link in soup.find_all("link", rel="stylesheet"):
            media = link.get("media", "")
            if media and media != "all":
                non_blocking_css += 1

        score = 0
        issues = []
        if inline_styles:
            issues.append(f"{len(inline_styles)} inline style blocks ({inline_css_size/1024:.1f}KB)")
            score += 1
        if has_critical_inline:
            issues.append("Critical CSS patterns detected")
            score += 1
        if non_blocking_css > 0:
            issues.append(f"{non_blocking_css} non-blocking CSS (media queries)")
            score += 2
        if critical_indicators:
            issues.extend(critical_indicators[:2])

        if score >= 3:
            status = "excellent"
        elif score >= 1:
            status = "good"
        else:
            status = "needs_improvement"

        self.add_result("Critical CSS Hints", f"{len(inline_styles)} inline, {non_blocking_css} non-blocking", status, "rendering",
                        "; ".join(issues[:3]) if issues else "No critical CSS strategy detected",
                        weight=2, effort=3)
        self.raw_metrics["inline_css_size"] = inline_css_size

    # ─────────────────────────────────────────────
    # CHECK: JS Execution Time (v3 NEW)
    # ─────────────────────────────────────────────
    def check_js_execution_time(self, soup, base_url):
        self.log("resources", "▸", "Estimating JavaScript execution time...")

        inline_scripts = soup.find_all("script", src=False)
        external_scripts = soup.find_all("script", src=True)

        total_inline_js = 0
        inline_exec_est = 0
        for script in inline_scripts:
            text = script.string or ""
            size = len(text)
            total_inline_js += size
            exec_est = size / 100_000
            if "eval(" in text or "Function(" in text:
                exec_est *= 2
            if "document.querySelector" in text or "getElementById" in text:
                exec_est += 0.05
            if "addEventListener" in text:
                exec_est += 0.02
            inline_exec_est += exec_est

        sync_external = 0
        async_external = 0
        defer_external = 0
        for s in external_scripts:
            if s.get("async"):
                async_external += 1
            elif s.get("defer"):
                defer_external += 1
            else:
                sync_external += 1

        total_exec_est = inline_exec_est + (sync_external * 0.15) + (defer_external * 0.05) + (async_external * 0.08)
        exec_ms = int(total_exec_est * 1000)

        issues = []
        if total_inline_js > 50000:
            issues.append(f"Heavy inline JS ({total_inline_js/1024:.1f}KB)")
        if sync_external > 3:
            issues.append(f"{sync_external} sync external scripts")
        if inline_exec_est > 0.5:
            issues.append(f"Inline JS exec ~{int(inline_exec_est*1000)}ms")

        if exec_ms < 500:
            status = "excellent"
        elif exec_ms < 2000:
            status = "good"
        elif exec_ms < 5000:
            status = "needs_improvement"
        else:
            status = "poor"

        self.add_result("JS Execution Time (est.)", f"{exec_ms}ms", status, "resources",
                        "; ".join(issues[:3]) if issues else f"Inline: {total_inline_js/1024:.1f}KB, External: {len(external_scripts)} scripts",
                        weight=3, effort=3)
        self.raw_metrics["js_exec_time_ms"] = exec_ms

    # ─────────────────────────────────────────────
    # CHECK: Resource Deduplication (v3 NEW)
    # ─────────────────────────────────────────────
    def check_resource_deduplication(self, soup, base_url):
        self.log("resources", "▸", "Checking for duplicate resources...")

        url_counts = defaultdict(int)

        for tag in soup.find_all(["script", "link", "img"]):
            for attr in ["src", "href"]:
                val = tag.get(attr, "")
                if val:
                    full_url = urljoin(base_url, val)
                    normalized = full_url.split("?")[0].split("#")[0]
                    url_counts[normalized] += 1

        duplicates = {url: count for url, count in url_counts.items() if count > 1}
        dup_count = len(duplicates)
        total_dup_requests = sum(count - 1 for count in duplicates.values())

        if dup_count == 0:
            status = "excellent"
            detail = "No duplicate resources detected"
        elif dup_count <= 2:
            status = "needs_improvement"
            dup_examples = list(duplicates.keys())[:3]
            detail = f"{dup_count} duplicate resources: " + ", ".join(u.split("/")[-1][:30] for u in dup_examples)
        else:
            status = "poor"
            detail = f"{dup_count} duplicate resources ({total_dup_requests} redundant requests)"

        self.add_result("Resource Deduplication", f"{dup_count} duplicates ({total_dup_requests} extra requests)", status, "resources",
                        detail, weight=2, effort=2)
        self.raw_metrics["duplicate_resources"] = dup_count
        self.raw_metrics["duplicate_requests"] = total_dup_requests

    # ─────────────────────────────────────────────
    # CHECK: Dead Code Estimation (v3 NEW)
    # ─────────────────────────────────────────────
    def check_dead_code_estimation(self, soup, html_content):
        self.log("resources", "▸", "Estimating dead code...")

        inline_scripts = soup.find_all("script", src=False)
        total_inline_bytes = 0
        potentially_dead = 0

        for script in inline_scripts:
            text = script.string or ""
            size = len(text)
            total_inline_bytes += size

            if text.strip().startswith("//") or text.strip().startswith("/*"):
                potentially_dead += size
            if "/*" in text and "*/" in text:
                comments = re.findall(r'/\*.*?\*/', text, re.DOTALL)
                potentially_dead += sum(len(c) for c in comments)
            if "console.log" in text or "console.debug" in text:
                potentially_dead += text.count("console.") * 50
            if "debugger" in text:
                potentially_dead += 100
            if "alert(" in text:
                potentially_dead += text.count("alert(") * 50

        dead_pct = (potentially_dead / total_inline_bytes * 100) if total_inline_bytes > 0 else 0

        if dead_pct < 5:
            status = "excellent"
        elif dead_pct < 15:
            status = "good"
        elif dead_pct < 30:
            status = "needs_improvement"
        else:
            status = "poor"

        detail_parts = []
        if potentially_dead > 0:
            detail_parts.append(f"~{potentially_dead/1024:.1f}KB potentially dead ({dead_pct:.0f}%)")
        detail_parts.append(f"Total inline: {total_inline_bytes/1024:.1f}KB")

        self.add_result("Dead Code Estimation", f"{dead_pct:.0f}% dead ({potentially_dead/1024:.1f}KB)", status, "resources",
                        "; ".join(detail_parts),
                        weight=1, effort=2)
        self.raw_metrics["dead_code_pct"] = round(dead_pct, 1)
        self.raw_metrics["dead_code_bytes"] = potentially_dead

    # ─────────────────────────────────────────────
    # CHECK: Font Loading Strategy (v3)
    # ─────────────────────────────────────────────
    def check_font_loading(self, soup, base_url):
        self.log("resources", "▸", "Analyzing font loading strategy...")

        font_links = soup.find_all("link", rel=lambda x: x and "font" in x.lower())
        google_fonts = [f for f in font_links if "fonts.googleapis.com" in (f.get("href") or "")]
        local_fonts = [f for f in font_links if "fonts.googleapis.com" not in (f.get("href") or "")]

        font_display_swap = False
        for tag in soup.find_all(["style", "link"]):
            text = tag.string or ""
            if "font-display" in text or "font-display: swap" in text:
                font_display_swap = True
                break

        preload_fonts = [f for f in soup.find_all("link", rel="preload") if f.get("as") == "font"]

        issues = []
        score = 0
        if google_fonts:
            issues.append(f"{len(google_fonts)} Google Font stylesheets")
            score += 1
        if local_fonts:
            issues.append(f"{len(local_fonts)} local font declarations")
            score += 2
        if font_display_swap:
            issues.append("font-display: swap detected")
            score += 1
        else:
            issues.append("No font-display strategy")
        if preload_fonts:
            issues.append(f"{len(preload_fonts)} fonts preloaded")
            score += 1

        total_font_count = len(font_links)
        if total_font_count > 5:
            issues.append(f"{total_font_count} font declarations (consider reducing)")
            score -= 1

        font_status = "excellent" if score >= 3 else "good" if score >= 2 else "needs_improvement" if score >= 1 else "poor"
        self.add_result("Font Loading Strategy", f"{total_font_count} fonts", font_status, "resources",
                        "; ".join(issues[:4]),
                        weight=1, effort=2)

    # ─────────────────────────────────────────────
    # CHECK: Third-party Script Analysis (v3 NEW)
    # ─────────────────────────────────────────────
    def check_third_party_analysis(self, soup, base_url):
        self.log("thirdparty", "▸", "Analyzing third-party script impact...")

        parsed_base = urlparse(base_url)
        third_party_scripts = []
        category_impact = defaultdict(lambda: {"count": 0, "blocking": False, "privacy": False, "weight": 0})

        for script in soup.find_all("script", src=True):
            src = script.get("src", "")
            if src and src.startswith("http"):
                parsed = urlparse(src)
                if parsed.netloc and parsed.netloc != parsed_base.netloc:
                    category = self._categorize_third_party(parsed.netloc)
                    is_async = script.get("async") is not None
                    is_defer = script.get("defer") is not None
                    blocking = not is_async and not is_defer

                    third_party_scripts.append({
                        "src": src[:60],
                        "domain": parsed.netloc,
                        "category": category,
                        "async": is_async,
                        "defer": is_defer,
                        "blocking": blocking,
                    })

                    cat_info = self.THIRD_PARTY_IMPACT.get(category, {})
                    category_impact[category]["count"] += 1
                    if blocking:
                        category_impact[category]["blocking"] = True
                    if cat_info.get("privacy"):
                        category_impact[category]["privacy"] = True
                    category_impact[category]["weight"] += cat_info.get("weight", 1)

        total_3p = len(third_party_scripts)
        blocking_3p = sum(1 for s in third_party_scripts if s["blocking"])
        privacy_categories = [cat for cat, info in category_impact.items() if info["privacy"]]

        score = 0
        issues = []
        if total_3p > 0:
            issues.append(f"{total_3p} third-party scripts total")
            score += 1
        if blocking_3p > 0:
            issues.append(f"{blocking_3p} blocking third-party scripts")
            score -= 1
        if privacy_categories:
            issues.append(f"Privacy-sensitive: {', '.join(privacy_categories[:3])}")
        if total_3p > 8:
            issues.append("High third-party count impacts performance")
            score -= 1

        cat_summary = ", ".join(f"{cat}({info['count']})" for cat, info in sorted(category_impact.items(), key=lambda x: -x[1]["weight"])[:5])
        if cat_summary:
            issues.append(f"Categories: {cat_summary}")

        if score >= 2:
            status = "excellent"
        elif score >= 0:
            status = "good"
        elif score >= -1:
            status = "needs_improvement"
        else:
            status = "poor"

        self.add_result("Third-party Script Impact", f"{total_3p} scripts ({blocking_3p} blocking)", status, "thirdparty",
                        "; ".join(issues[:4]),
                        weight=3, effort=3)
        self.raw_metrics["third_party_script_count"] = total_3p
        self.raw_metrics["third_party_blocking"] = blocking_3p

    # ─────────────────────────────────────────────
    # CHECK: Caching (v3 - deep analysis)
    # ─────────────────────────────────────────────
    def check_caching(self, headers):
        self.log("caching", "▸", "Analyzing cache headers...")

        cache_control = headers.get("Cache-Control", "")
        etag = headers.get("ETag", "")
        last_modified = headers.get("Last-Modified", "")
        expires = headers.get("Expires", "")

        score = 0
        issues = []

        if cache_control:
            cc_lower = cache_control.lower()
            if "no-store" in cc_lower:
                issues.append("Cache-Control: no-store (no caching at all)")
            elif "no-cache" in cc_lower:
                issues.append("Cache-Control: no-cache (revalidation required)")
                score += 1
            else:
                score += 2
                max_age_match = re.search(r"max-age=(\d+)", cache_control)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age >= 86400:
                        score += 2
                        issues.append(f"max-age={max_age} ({max_age // 86400}d) - strong caching")
                    elif max_age >= 3600:
                        score += 1
                        issues.append(f"max-age={max_age} ({max_age // 3600}h) - moderate caching")
                    else:
                        issues.append(f"max-age={max_age}s - short-lived cache")
                else:
                    issues.append("Cache-Control present but no max-age directive")
                if "immutable" in cc_lower:
                    score += 1
                    issues.append("immutable directive (excellent for versioned assets)")
                if "stale-while-revalidate" in cc_lower:
                    score += 1
                    issues.append("stale-while-revalidate (good for background updates)")
                if "public" in cc_lower:
                    issues.append("public cache")
                elif "private" in cc_lower:
                    issues.append("private cache (user-specific)")
                s_maxage_match = re.search(r"s-maxage=(\d+)", cache_control)
                if s_maxage_match:
                    s_maxage = int(s_maxage_match.group(1))
                    issues.append(f"s-maxage={s_maxage} (CDN-friendly)")
                    score += 1
        else:
            issues.append("No Cache-Control header")

        if etag:
            score += 1
            is_weak = etag.startswith("W/")
            if is_weak:
                issues.append("ETag present (weak)")
            else:
                issues.append("ETag present (strong)")
        else:
            issues.append("No ETag")

        if last_modified:
            score += 1
            issues.append("Last-Modified present")
        else:
            issues.append("No Last-Modified")

        if expires:
            try:
                exp_date = datetime.strptime(expires, "%a, %d %b %Y %H:%M:%S GMT")
                if exp_date > datetime.utcnow():
                    score += 1
                    issues.append("Expires: future date (good)")
                else:
                    issues.append("Expires: past date")
            except ValueError:
                issues.append("Expires: invalid format")

        if score >= 5:
            cache_status = "excellent"
        elif score >= 3:
            cache_status = "needs_improvement"
        else:
            cache_status = "poor"

        self.add_result("Cache-Control", cache_control or "Not set", cache_status, "caching",
                        "; ".join(issues[:5]),
                        weight=3, effort=2)
        self.add_result("ETag", etag or "Not set", "good" if etag else "needs_improvement", "caching",
                        "Used for conditional revalidation" if etag else "Missing - enables 304 responses",
                        weight=2, effort=1)
        self.add_result("Last-Modified", last_modified or "Not set", "good" if last_modified else "needs_improvement", "caching",
                        weight=1, effort=1)
        self.raw_metrics["cache_score"] = score

    # ─────────────────────────────────────────────
    # CHECK: Compression (v3)
    # ─────────────────────────────────────────────
    def check_compression(self, headers, html_content):
        self.log("compression", "▸", "Checking compression...")

        content_encoding = headers.get("Content-Encoding", "")
        if content_encoding:
            encodings = [e.strip().lower() for e in content_encoding.split(",")]
            if "br" in encodings:
                comp_status = "excellent"
                comp_detail = "Brotli compression (best available)"
            elif "gzip" in encodings:
                comp_status = "good"
                comp_detail = "Gzip compression"
            elif "deflate" in encodings:
                comp_status = "needs_improvement"
                comp_detail = "Deflate compression (older, less efficient)"
            else:
                comp_status = "needs_improvement"
                comp_detail = f"Unknown: {content_encoding}"
        else:
            comp_status = "poor"
            comp_detail = "No compression detected - significant opportunity"
            encodings = []

        raw_size = len(html_content.encode("utf-8"))
        transfer_encoding = headers.get("Transfer-Encoding", "")
        if "chunked" in transfer_encoding.lower():
            comp_ratio = "chunked"
        else:
            content_length = int(headers.get("Content-Length", raw_size))
            if content_length < raw_size and content_length > 0:
                ratio = (1 - content_length / raw_size) * 100
                comp_ratio = f"{ratio:.1f}% savings"
            else:
                comp_ratio = "uncompressed"

        self.add_result("Content-Encoding", content_encoding or "None", comp_status, "compression", comp_detail,
                        weight=2, effort=2)
        self.add_result("Compression Ratio", comp_ratio, comp_status, "compression",
                        f"Raw: {raw_size:,} bytes",
                        weight=1, effort=1)
        self.raw_metrics["compression"] = content_encoding or "none"

    # ─────────────────────────────────────────────
    # CHECK: Redirects (v3)
    # ─────────────────────────────────────────────
    def check_redirects(self, url):
        self.log("redirects", "▸", "Analyzing redirect chain...")

        chain = []
        current_url = url
        total_redirect_time = 0
        max_hops = 10

        for i in range(max_hops):
            try:
                start = time.time()
                resp = self.session.get(current_url, timeout=self.timeout, allow_redirects=False, stream=True)
                elapsed = time.time() - start
                status = resp.status_code
                chain.append({"url": current_url, "status": status, "time": elapsed})

                if status in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if location:
                        total_redirect_time += elapsed
                        if location.startswith("/"):
                            parsed = urlparse(current_url)
                            current_url = f"{parsed.scheme}://{parsed.netloc}{location}"
                        else:
                            current_url = location
                    else:
                        break
                else:
                    break
            except Exception as e:
                chain.append({"url": current_url, "status": "error", "time": 0, "error": str(e)})
                break

        hops = len(chain) - 1
        if hops == 0:
            redirect_status = "excellent"
        elif hops <= 2:
            redirect_status = "good"
        elif hops <= 4:
            redirect_status = "needs_improvement"
        else:
            redirect_status = "poor"

        chain_str = " -> ".join([f"[{c['status']}]" for c in chain])
        self.add_result("Redirect Chain", f"{hops} hops", redirect_status, "redirects", chain_str,
                        weight=2, effort=2)
        self.add_result("Redirect Time", f"{total_redirect_time*1000:.0f}ms",
                        "excellent" if total_redirect_time < 0.5 else "needs_improvement", "redirects",
                        weight=1, effort=1)

        parsed = urlparse(url)
        if parsed.scheme == "http":
            https_check = any(c["url"].startswith("https://") for c in chain)
            if https_check:
                self.add_result("HTTP -> HTTPS", "Yes", "excellent", "redirects", "HTTP correctly redirects to HTTPS",
                                weight=2, effort=1)
            else:
                self.add_result("HTTP -> HTTPS", "No", "poor", "redirects", "No HTTPS redirect detected",
                                weight=2, effort=1)

        www_check = any("www." in c["url"] for c in chain)
        non_www_check = any("www." not in c["url"] and c["url"].startswith("http") for c in chain)
        if www_check and non_www_check:
            self.add_result("WWW Redirect", "Canonical redirect detected", "good", "redirects")
        else:
            self.add_result("WWW Redirect", "No redirect (consistent)", "good", "redirects")

        self.raw_metrics["redirect_hops"] = hops
        self.raw_metrics["redirect_time_ms"] = int(total_redirect_time * 1000)
        self.raw_metrics["redirect_chain"] = chain

    # ─────────────────────────────────────────────
    # CHECK: Protocol & Connection (v3)
    # ─────────────────────────────────────────────
    def check_protocol(self, url, response):
        self.log("protocol", "▸", "Checking protocol and connection...")

        http_version = response.raw.version if hasattr(response.raw, "version") else 0
        version_str = {9: "HTTP/0.9", 10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2", 30: "HTTP/3"}.get(http_version, f"Unknown ({http_version})")
        if http_version >= 30:
            proto_status = "excellent"
        elif http_version >= 20:
            proto_status = "excellent"
        elif http_version == 11:
            proto_status = "needs_improvement"
        else:
            proto_status = "poor"
        self.add_result("HTTP Version", version_str, proto_status, "protocol",
                        weight=3, effort=5)
        self.raw_metrics["http_version"] = version_str

        alt_svc = response.headers.get("Alt-Svc", "")
        http3_detected = "h3" in alt_svc.lower() or "quic" in alt_svc.lower()
        if http3_detected:
            self.add_result("HTTP/3 (QUIC)", "Supported", "excellent", "protocol",
                            f"Alt-Svc: {alt_svc[:60]}",
                            weight=3, effort=5)
        else:
            self.add_result("HTTP/3 (QUIC)", "Not detected", "needs_improvement", "protocol",
                            "Alt-Svc header missing or no h3/quic advertisement",
                            weight=3, effort=5)
        self.raw_metrics["http3_support"] = http3_detected

        early_hints = response.headers.get("Link", "")
        has_early_hints = 'rel="preload"' in early_hints or "rel=preload" in early_hints
        if has_early_hints:
            self.add_result("Early Hints (103)", "Detected", "excellent", "protocol",
                            "Preload hints found in Link header",
                            weight=2, effort=4)
        else:
            self.add_result("Early Hints (103)", "Not detected", "needs_improvement", "protocol",
                            "No Early Hints (103) preloading detected",
                            weight=2, effort=4)
        self.raw_metrics["early_hints"] = has_early_hints

        client_hints = []
        ch_headers = ["Sec-CH-UA", "Sec-CH-UA-Mobile", "Sec-CH-UA-Platform",
                      "Sec-CH-Width", "Sec-CH-DPR", "Sec-CH-Viewport-Width"]
        for ch in ch_headers:
            if ch.lower().replace("-", "_") in [h.lower().replace("-", "_") for h in response.headers.keys()]:
                client_hints.append(ch)
        if client_hints:
            self.add_result("Client Hints", f"{len(client_hints)} detected", "excellent", "protocol",
                            ", ".join(client_hints[:5]),
                            weight=1, effort=3)
        else:
            self.add_result("Client Hints", "Not used", "needs_improvement", "protocol",
                            "Consider Client Hints for adaptive serving",
                            weight=1, effort=3)
        self.raw_metrics["client_hints"] = len(client_hints)

        connection = response.headers.get("Connection", "")
        keep_alive = "keep-alive" in connection.lower() or http_version >= 20
        ka_status = "excellent" if keep_alive else "needs_improvement"
        ka_detail = "Persistent connections enabled" if keep_alive else "No keep-alive; connections may be recycled"
        self.add_result("Keep-Alive", "Yes" if keep_alive else "No", ka_status, "protocol", ka_detail,
                        weight=1, effort=1)

        parsed = urlparse(url)
        if parsed.scheme == "https":
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=parsed.netloc) as s:
                    s.settimeout(5)
                    s.connect((parsed.netloc, 443))
                    cert = s.getpeercert()
                    protocol = s.version()
                    tls_status = "excellent" if "TLSv1.3" in protocol else "good" if "TLSv1.2" in protocol else "needs_improvement"
                    self.add_result("TLS Version", protocol, tls_status, "protocol",
                                    weight=2, effort=5)
                    self.raw_metrics["tls_version"] = protocol
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        try:
                            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days_left = (exp - datetime.utcnow()).days
                            cert_status = "excellent" if days_left > 90 else "needs_improvement" if days_left > 30 else "poor"
                            self.add_result("Certificate Expiry", f"{days_left} days", cert_status, "protocol",
                                            f"Expires: {not_after}",
                                            weight=1, effort=2)
                        except ValueError:
                            pass
            except Exception as e:
                self.add_result("TLS Version", "Unable to detect", "needs_improvement", "protocol", str(e))
        else:
            self.add_result("TLS Version", "N/A (HTTP)", "needs_improvement", "protocol", "Site not using HTTPS",
                            weight=2, effort=5)

    # ─────────────────────────────────────────────
    # CHECK: Service Worker Detection (v3)
    # ─────────────────────────────────────────────
    def check_service_worker(self, soup, html_content):
        self.log("protocol", "▸", "Detecting Service Worker...")

        sw_found = False
        sw_detail = []

        all_scripts = soup.find_all("script")
        for script in all_scripts:
            text = script.string or ""
            if "serviceWorker" in text or "service-worker" in text or "sw.js" in text:
                sw_found = True
                sw_detail.append("Service Worker registration found in script")
                break

        manifest_link = soup.find("link", rel="manifest")
        if manifest_link:
            href = manifest_link.get("href", "")
            if href:
                sw_found = True
                sw_detail.append(f"Web App Manifest: {href[:40]}")

        for meta in soup.find_all("meta"):
            if "service-worker" in str(meta).lower():
                sw_found = True
                sw_detail.append("Service Worker meta reference")

        if sw_found:
            self.add_result("Service Worker", "Detected", "excellent", "protocol",
                            "; ".join(sw_detail[:2]),
                            weight=1, effort=3)
        else:
            self.add_result("Service Worker", "Not detected", "needs_improvement", "protocol",
                            "No Service Worker registration detected",
                            weight=1, effort=3)
        self.raw_metrics["service_worker"] = sw_found

    # ─────────────────────────────────────────────
    # CHECK: Rendering Path (v3 - enhanced)
    # ─────────────────────────────────────────────
    def check_rendering(self, soup, html_content):
        self.log("rendering", "▸", "Analyzing critical rendering path...")

        head = soup.find("head")
        render_blocking = []
        render_blocking_count = 0
        if head:
            for css in head.find_all("link", rel="stylesheet"):
                href = css.get("href", "unknown")
                render_blocking.append(f"CSS: {href[:40]}")
                render_blocking_count += 1
            for script in head.find_all("script", src=True):
                if not script.get("async") and not script.get("defer"):
                    src = script.get("src", "unknown")
                    render_blocking.append(f"JS: {src[:40]}")
                    render_blocking_count += 1

        if render_blocking_count == 0:
            rb_status = "excellent"
        elif render_blocking_count <= 2:
            rb_status = "needs_improvement"
        else:
            rb_status = "poor"
        self.add_result("Render-blocking Resources", f"{render_blocking_count} found", rb_status, "rendering",
                        "; ".join(render_blocking[:4]) if render_blocking else "No render-blocking resources",
                        weight=3, effort=2)

        preload = soup.find_all("link", rel="preload")
        prefetch = soup.find_all("link", rel="prefetch")
        dns_prefetch = soup.find_all("link", rel="dns-prefetch")
        preconnect = soup.find_all("link", rel="preconnect")
        modulepreload = soup.find_all("link", rel="modulepreload")
        hints_count = len(preload) + len(prefetch) + len(dns_prefetch) + len(preconnect) + len(modulepreload)
        if hints_count >= 3:
            hints_status = "excellent"
        elif hints_count >= 1:
            hints_status = "good"
        else:
            hints_status = "needs_improvement"
        self.add_result("Resource Hints", f"{hints_count} found", hints_status, "rendering",
                        f"Preload: {len(preload)}, Prefetch: {len(prefetch)}, DNS-Prefetch: {len(dns_prefetch)}, Preconnect: {len(preconnect)}, Modulepreload: {len(modulepreload)}",
                        weight=2, effort=1)
        self.raw_metrics["resource_hints"] = hints_count

        crp_items = []
        if render_blocking:
            crp_items.append(("BLOCK", render_blocking_count, "Render-blocking resources"))
        crp_items.append(("INLINE", len(soup.find_all("style")), "Inline styles"))
        crp_items.append(("DEFER", len([s for s in soup.find_all("script", src=True) if s.get("defer")]), "Deferred scripts"))
        crp_items.append(("ASYNC", len([s for s in soup.find_all("script", src=True) if s.get("async")]), "Async scripts"))
        total_critical = sum(c[1] for c in crp_items)
        crp_detail = " | ".join(f"{t}:{n}" for t, n, _ in crp_items if n > 0)
        crp_status = "excellent" if total_critical <= 3 else "needs_improvement" if total_critical <= 8 else "poor"
        self.add_result("Critical Rendering Path", f"{total_critical} critical items", crp_status, "rendering",
                        crp_detail,
                        weight=2, effort=3)
        self.raw_metrics["critical_path_items"] = total_critical

    # ─────────────────────────────────────────────
    # CHECK: Rendering Performance Analysis (v6)
    # ─────────────────────────────────────────────
    def check_rendering_performance(self, soup, html_content):
        self.log("rendering", "▸", "Analyzing rendering performance...")

        all_text = self._page_text(soup, html_content)

        content_visibility = len(re.findall(r"content-visibility\s*:", all_text))
        contain_paint = len(re.findall(r"contain\s*:\s*[^;{}]*(?:paint|layout|strict|content|size|style)", all_text))
        layers = len(re.findall(r"@layer\b", all_text))
        aspect_ratio = len(re.findall(r"aspect-ratio\s*:", all_text))
        transform_opacity_anims = len(re.findall(
            r"(?:transition|animation)[^;{]*?(?:transform|opacity)\s*:", all_text
        ))
        will_change = len(re.findall(r"will-change\s*:", all_text))
        blur_filters = len(re.findall(r"(?<!-)filter\s*:\s*[^;{}]*blur", all_text))
        backdrop_filters = len(re.findall(r"backdrop-filter\s*:", all_text))
        scroll_driven_anims = len(re.findall(r"(?:animation-timeline|scroll-timeline|view-timeline)\s*:", all_text))
        layout_anim_props = len(re.findall(
            r"(?:transition|animation)[^;{]*?(?:\bwidth\b|\bheight\b|\btop\b|\bleft\b|\bmargin\b|\bpadding\b)\s*:",
            all_text,
        ))
        box_shadows = len(re.findall(r"box-shadow\s*:", all_text))
        paint_worklets = "paintWorklet" in all_text or "CSS.paintWorklet" in all_text
        houdini_props = "registerProperty" in all_text

        score = 0
        details = []
        if content_visibility:
            score += 3
            details.append("{} content-visibility usages (skip offscreen rendering)".format(content_visibility))
        if contain_paint:
            score += 2
            details.append("{} CSS containment declarations".format(contain_paint))
        if layers:
            score += 2
            details.append("@layer cascade scoping ({} layers)".format(layers))
        if aspect_ratio:
            score += 1
            details.append("{} aspect-ratio declarations (stable boxes)".format(aspect_ratio))
        if transform_opacity_anims:
            score += 1
            details.append("{} compositor-friendly transform/opacity animations".format(transform_opacity_anims))
        if paint_worklets or houdini_props:
            score += 1
            details.append("Houdini/paint worklet signals")
        if will_change > 5:
            score -= 1
            details.append("{} will-change declarations (GPU memory risk)".format(will_change))
        elif will_change > 0:
            details.append("{} will-change declarations".format(will_change))
        if scroll_driven_anims > 0:
            score += 2
            details.append("{} CSS scroll-driven animation timelines (off main thread)".format(scroll_driven_anims))
        if backdrop_filters > 4:
            score -= 2
            details.append("{} backdrop-filter declarations (full-surface repaint cost)".format(backdrop_filters))
        elif backdrop_filters > 0:
            score -= 1
            details.append("{} backdrop-filter declarations".format(backdrop_filters))
        if blur_filters > 3:
            score -= 2
            details.append("{} blur filter effects (expensive paint)".format(blur_filters))
        elif blur_filters > 0:
            score -= 1
            details.append("{} blur filter effects".format(blur_filters))
        if layout_anim_props > 2:
            score -= 2
            details.append("{} animations on layout properties (trigger reflow)".format(layout_anim_props))
        elif layout_anim_props > 0:
            score -= 1
            details.append("{} animations on layout properties".format(layout_anim_props))
        if box_shadows > 15:
            score -= 1
            details.append("{} box-shadow declarations (repaint cost)".format(box_shadows))
        if not details:
            details.append("No strong rendering optimization or anti-pattern signals")

        if score >= 5:
            status = "excellent"
        elif score >= 2:
            status = "good"
        elif score >= -1:
            status = "needs_improvement"
        else:
            status = "poor"

        value = "score {:+d}".format(score)
        self.add_result("Rendering Performance", value, status, "rendering",
                        "; ".join(details[:5]),
                        weight=3, effort=3)
        self.raw_metrics["rendering_performance_score"] = score
        self.raw_metrics["content_visibility_count"] = content_visibility
        self.raw_metrics["layout_animation_props"] = layout_anim_props
        self.raw_metrics["blur_filter_count"] = blur_filters
        self.raw_metrics["will_change_count"] = will_change
        self.raw_metrics["backdrop_filter_count"] = backdrop_filters
        self.raw_metrics["scroll_driven_count"] = scroll_driven_anims

    # ─────────────────────────────────────────────
    # CHECK: Adaptive Image Loading (v7 NEW)
    # ─────────────────────────────────────────────
    def check_adaptive_image_loading(self, soup, html_content):
        self.log("images", "▸", "Detecting adaptive image loading...")

        images = soup.find_all("img")
        sources = soup.find_all("source")
        pictures = soup.find_all("picture")
        total_imgs = len(images)

        if total_imgs == 0:
            self.add_result("Adaptive Image Loading", "No images", "good", "images",
                            "No <img> elements to evaluate",
                            weight=1, effort=1)
            self.raw_metrics["adaptive_image_score"] = 0
            self.raw_metrics["adaptive_image_coverage"] = 0.0
            return

        srcset_imgs = sum(1 for img in images if img.get("srcset"))
        sizes_imgs = sum(1 for img in images if img.get("sizes"))
        picture_imgs = sum(
            1 for pic in pictures
            for img in pic.find_all("img")
            if img.get("srcset") or pic.find("source")
        )
        type_modern_sources = sum(
            1 for s in sources
            if (s.get("type") or "") in ("image/webp", "image/avif")
        )
        fetchpriority_high = sum(1 for img in images if (img.get("fetchpriority") or "").lower() == "high")
        lazy_count = sum(1 for img in images if img.get("loading") == "lazy")
        eager_above_fold = sum(
            1 for img in images
            if img.get("loading") == "eager" or (img.get("fetchpriority") or "").lower() == "high"
        )
        decoding_async = sum(1 for img in images if img.get("decoding") == "async")
        density_hints = sum(1 for img in images if img.get("srcset") and img.get("sizes"))

        score = 0
        details = []
        if srcset_imgs:
            score += 2
            details.append("{}/{} images with srcset variants".format(srcset_imgs, total_imgs))
        if sizes_imgs:
            score += 2
            details.append("{} viewport-aware sizes attributes".format(sizes_imgs))
        if density_hints:
            score += 1
            details.append("{} images with density+viewport pairing".format(density_hints))
        if pictures:
            score += 1
            details.append("{} <picture> art-direction containers".format(len(pictures)))
        if type_modern_sources:
            score += 1
            details.append("{} typed modern <source> (webp/avif)".format(type_modern_sources))
        if fetchpriority_high:
            score += 1
            details.append("{} fetchpriority=high hero hints".format(fetchpriority_high))
        if lazy_count:
            score += 1
            details.append("{} lazy-loaded images".format(lazy_count))
        if eager_above_fold:
            score += 1
            details.append("{} prioritized above-the-fold images".format(eager_above_fold))
        if decoding_async:
            score += 1
            details.append("{} decoding=async images".format(decoding_async))
        if total_imgs >= 5 and srcset_imgs == 0 and not pictures:
            score -= 2
            details.append("No responsive variants - fixed-width downloads on mobile")
        if total_imgs >= 5 and lazy_count == 0:
            score -= 1
            details.append("No lazy loading on image-heavy page")
        if not details:
            details.append("Basic image markup without adaptive hints")

        if score >= 7:
            status = "excellent"
        elif score >= 4:
            status = "good"
        elif score >= 1:
            status = "needs_improvement"
        else:
            status = "poor"

        coverage = ((srcset_imgs + picture_imgs) / total_imgs * 100) if total_imgs else 0.0
        value = "score {:+d} ({:.0f}% adaptive)".format(score, coverage)
        self.add_result("Adaptive Image Loading", value, status, "images",
                        "; ".join(details[:5]),
                        weight=3, effort=2)
        self.raw_metrics["adaptive_image_score"] = score
        self.raw_metrics["adaptive_image_coverage"] = round(coverage, 1)
        self.raw_metrics["img_srcset_count"] = srcset_imgs
        self.raw_metrics["img_sizes_count"] = sizes_imgs
        self.raw_metrics["img_picture_count"] = len(pictures)
        self.raw_metrics["img_fetchpriority_count"] = fetchpriority_high
        self.raw_metrics["img_decoding_async_count"] = decoding_async

    # ─────────────────────────────────────────────
    # CHECK: content-visibility Usage (v7 NEW)
    # ─────────────────────────────────────────────
    def check_content_visibility(self, soup, html_content):
        self.log("rendering", "▸", "Detecting content-visibility usage...")

        all_text = self._page_text(soup, html_content)
        cv_total = len(re.findall(r"content-visibility\s*:", all_text))
        auto_count = len(re.findall(r"content-visibility\s*:\s*auto", all_text))
        hidden_count = len(re.findall(r"content-visibility\s*:\s*hidden", all_text))
        contain_intrinsic = len(re.findall(
            r"contain-intrinsic-(?:size|width|height|block-size|inline-size)\s*:", all_text
        ))
        contain_intrinsic_shorthand = len(re.findall(r"contain-intrinsic-size\s*:", all_text))
        total_intrinsic = contain_intrinsic + contain_intrinsic_shorthand

        score = 0
        details = []
        if cv_total:
            score += 3
            details.append("{} content-visibility declarations".format(cv_total))
        if auto_count:
            score += 2
            details.append("{} content-visibility:auto (skip offscreen rendering)".format(auto_count))
        if hidden_count:
            details.append("{} content-visibility:hidden (manual reveal required)".format(hidden_count))
        if total_intrinsic:
            score += 2
            details.append("{} contain-intrinsic-size hints (stable boxes, less CLS)".format(total_intrinsic))
        elif auto_count:
            score -= 1
            details.append("auto used without contain-intrinsic-size - size jump/CLS risk")
        if cv_total == 0:
            details.append("No content-visibility - long offscreen lists still fully render")

        if score >= 5:
            status = "excellent"
        elif score >= 3:
            status = "good"
        elif score >= 1:
            status = "needs_improvement"
        else:
            status = "poor" if cv_total == 0 else "needs_improvement"

        value = "{} declarations".format(cv_total) if cv_total else "Not used"
        self.add_result("Content-visibility Usage", value, status, "rendering",
                        "; ".join(details[:4]),
                        weight=3, effort=2)
        self.raw_metrics["content_visibility_count"] = cv_total
        self.raw_metrics["content_visibility_auto"] = auto_count
        self.raw_metrics["contain_intrinsic_size_count"] = total_intrinsic
        self.raw_metrics["content_visibility_score"] = score

    # ─────────────────────────────────────────────
    # CHECK: CSS contain Property Usage (v7 NEW)
    # ─────────────────────────────────────────────
    def check_css_contain_property(self, soup, html_content):
        self.log("rendering", "▸", "Detecting CSS contain property usage...")

        all_text = self._page_text(soup, html_content)
        contain_decls = re.findall(r"(?<![-\w])contain\s*:\s*([^;{}]+)", all_text)
        total_decls = len(contain_decls)

        keyword_hits = {"layout": 0, "paint": 0, "size": 0, "style": 0, "strict": 0, "content": 0, "inline-size": 0}
        for value in contain_decls:
            lowered = value.lower()
            for key in keyword_hits:
                if re.search(r"\b" + re.escape(key) + r"\b", lowered):
                    keyword_hits[key] += 1

        used_keywords = [k for k, v in keyword_hits.items() if v > 0]

        score = 0
        details = []
        if total_decls:
            score += 2
            details.append("{} contain declarations".format(total_decls))
        if keyword_hits["paint"] or keyword_hits["strict"] or keyword_hits["content"]:
            score += 2
            details.append("paint/strict containment isolates layout+paint cost")
        if keyword_hits["layout"] or keyword_hits["style"]:
            score += 1
            details.append("layout/style containment limits reflow scope")
        if keyword_hits["size"] or keyword_hits["inline-size"]:
            score += 1
            details.append("size containment enables independent sizing")
        if used_keywords:
            details.append("Keywords: " + ", ".join(used_keywords[:5]))
        else:
            details.append("No CSS contain usage - reflows/paints propagate across the tree")

        if score >= 4:
            status = "excellent"
        elif score >= 2:
            status = "good"
        elif score >= 1:
            status = "needs_improvement"
        else:
            status = "needs_improvement"

        value = "{} declarations".format(total_decls) if total_decls else "Not used"
        self.add_result("CSS contain Property", value, status, "rendering",
                        "; ".join(details[:4]),
                        weight=2, effort=2)
        self.raw_metrics["contain_property_count"] = total_decls
        self.raw_metrics["contain_property_keywords"] = used_keywords
        self.raw_metrics["contain_property_score"] = score

    # ─────────────────────────────────────────────
    # CHECK: will-change Usage (v7 NEW)
    # ─────────────────────────────────────────────
    def check_will_change_usage(self, soup, html_content):
        self.log("rendering", "▸", "Analyzing will-change usage...")

        all_text = self._page_text(soup, html_content)
        will_change_decls = re.findall(r"will-change\s*:\s*([^;{}]+)", all_text)
        count = len(will_change_decls)
        auto_count = sum(1 for v in will_change_decls if re.search(r"\bauto\b", v, re.I))
        none_count = sum(1 for v in will_change_decls if re.search(r"\bnone\b", v, re.I))
        layer_promotions = count - auto_count - none_count
        transform_opacity = sum(
            1 for v in will_change_decls
            if re.search(r"\b(?:transform|opacity)\b", v, re.I)
        )

        score = 0
        details = []
        if count == 0:
            score += 1
            details.append("No will-change - no GPU layer hoarding (good default)")
        else:
            details.append("{} will-change declarations".format(count))
            if layer_promotions > 0:
                details.append("{} active layer promotions".format(layer_promotions))
            if transform_opacity:
                score += 1
                details.append("{} targeting transform/opacity (compositor-friendly)".format(transform_opacity))
            if auto_count:
                score -= 2
                details.append("{} will-change:auto (layers kept far too long)".format(auto_count))
            if count > 6:
                score -= 2
                details.append("Overuse - each entry pins GPU memory for the session")
            elif count > 3:
                score -= 1
                details.append("Above the recommended 1-3 live entries")
            else:
                score += 1
                details.append("Sparingly used (within recommended budget)")

        if score >= 2:
            status = "excellent"
        elif score >= 1:
            status = "good"
        elif score >= 0:
            status = "needs_improvement"
        else:
            status = "poor"

        value = "{} declarations".format(count) if count else "Not used"
        self.add_result("will-change Usage", value, status, "rendering",
                        "; ".join(details[:4]),
                        weight=2, effort=2)
        self.raw_metrics["will_change_count"] = count
        self.raw_metrics["will_change_auto"] = auto_count
        self.raw_metrics["will_change_promotions"] = layer_promotions
        self.raw_metrics["will_change_score"] = score

    # ─────────────────────────────────────────────
    # CHECK: Backdrop-filter Performance Impact (v7 NEW)
    # ─────────────────────────────────────────────
    def check_backdrop_filter_impact(self, soup, html_content):
        self.log("rendering", "▸", "Measuring backdrop-filter performance impact...")

        all_text = self._page_text(soup, html_content)
        bd_decls = re.findall(r"backdrop-filter\s*:\s*([^;{}]+)", all_text)
        webkit_bd = re.findall(r"-webkit-backdrop-filter\s*:\s*([^;{}]+)", all_text)
        count = len(bd_decls) + len(webkit_bd)

        blur_amounts = []
        other_filters = 0
        for value in bd_decls + webkit_bd:
            for match in re.finditer(r"blur\(\s*([\d.]+)", value):
                blur_amounts.append(float(match.group(1)))
            if re.search(r"(?:grayscale|brightness|contrast|hue-rotate|saturate)\s*\(", value):
                other_filters += 1

        max_blur = max(blur_amounts) if blur_amounts else 0.0
        heavy_blur = sum(1 for b in blur_amounts if b > 12)
        estimated_buffers = count * 512

        score = 0
        details = []
        if count == 0:
            score += 2
            details.append("No backdrop-filter - zero backdrop snapshot/blur cost")
        else:
            details.append("{} backdrop-filter surfaces (~{}KB blur buffers est.)".format(count, estimated_buffers))
            if max_blur > 20:
                score -= 2
                details.append("max blur {:.0f}px (very expensive per frame)".format(max_blur))
            elif max_blur > 12:
                score -= 1
                details.append("max blur {:.0f}px (noticeable paint cost)".format(max_blur))
            elif max_blur > 0:
                details.append("max blur {:.0f}px (moderate)".format(max_blur))
            if count > 4:
                score -= 2
                details.append("Stacked backdrop surfaces force repeated re-blur")
            elif count > 1:
                score -= 1
                details.append("Multiple blur layers - verify they do not overlap")
            else:
                score += 1
                details.append("Single localized blur surface")
            if heavy_blur:
                details.append("{} heavy (>12px) blur filters".format(heavy_blur))
            if other_filters:
                details.append("{} additional color-adjust filters".format(other_filters))

        if score >= 2:
            status = "excellent"
        elif score >= 1:
            status = "good"
        elif score >= 0:
            status = "needs_improvement"
        else:
            status = "poor"

        value = "{} surfaces".format(count) if count else "Not used"
        self.add_result("Backdrop-filter Impact", value, status, "rendering",
                        "; ".join(details[:4]),
                        weight=2, effort=3)
        self.raw_metrics["backdrop_filter_count"] = count
        self.raw_metrics["backdrop_filter_max_blur"] = max_blur
        self.raw_metrics["backdrop_filter_heavy"] = heavy_blur
        self.raw_metrics["backdrop_filter_buffers_kb"] = estimated_buffers
        self.raw_metrics["backdrop_filter_score"] = score

    # ─────────────────────────────────────────────
    # CHECK: Scroll-driven Animations (v7 NEW)
    # ─────────────────────────────────────────────
    def check_scroll_driven_animations(self, soup, html_content):
        self.log("modern", "▸", "Detecting scroll-driven animations...")

        all_text = self._page_text(soup, html_content)
        scroll_timeline = len(re.findall(r"scroll-timeline(?:-axis|-root)?\s*:", all_text))
        view_timeline = len(re.findall(r"view-timeline(?:-axis|-name|-block|-inline)?\s*:", all_text))
        animation_timeline = len(re.findall(r"animation-timeline\s*:\s*(?:scroll|view)\s*\(", all_text))
        animation_range = len(re.findall(r"animation-range(?:-start|-end)?\s*:", all_text))
        timeline_total = scroll_timeline + view_timeline + animation_timeline
        has_reduced_motion = "prefers-reduced-motion" in all_text

        js_scroll_handlers = len(re.findall(r'addEventListener\s*\(\s*["\']scroll["\']', all_text))
        has_debounce = "debounce" in all_text.lower() or "throttle" in all_text.lower()

        score = 0
        details = []
        if animation_timeline:
            score += 3
            details.append("{} animation-timeline: scroll()/view() declarations".format(animation_timeline))
        if scroll_timeline:
            score += 2
            details.append("{} scroll-timeline declarations".format(scroll_timeline))
        if view_timeline:
            score += 2
            details.append("{} view-timeline declarations".format(view_timeline))
        if animation_range:
            score += 1
            details.append("{} animation-range bindings".format(animation_range))
        if has_reduced_motion:
            score += 1
            details.append("prefers-reduced-motion respected")
        if timeline_total == 0 and js_scroll_handlers > 0:
            score -= 1
            details.append("{} JS scroll handlers with no CSS timeline alternative".format(js_scroll_handlers))
            if not has_debounce:
                details.append("scroll handlers also lack debounce/throttle")
        if timeline_total == 0 and js_scroll_handlers == 0:
            details.append("No scroll-driven animation signals detected")
        if timeline_total > 0:
            details.append("Timelines animate off the main thread (compositor-driven)")

        if score >= 5:
            status = "excellent"
        elif score >= 3:
            status = "good"
        elif score >= 1:
            status = "needs_improvement"
        else:
            status = "needs_improvement" if timeline_total == 0 else "good"

        used = timeline_total > 0
        value = "{} timelines".format(timeline_total) if used else "Not used"
        self.add_result("Scroll-driven Animations", value, status, "modern",
                        "; ".join(details[:4]),
                        weight=2, effort=2)
        self.raw_metrics["scroll_driven_animations"] = used
        self.raw_metrics["scroll_timeline_count"] = scroll_timeline
        self.raw_metrics["view_timeline_count"] = view_timeline
        self.raw_metrics["animation_timeline_count"] = animation_timeline
        self.raw_metrics["scroll_driven_score"] = score

    # ─────────────────────────────────────────────
    # CHECK: Core Web Vitals Headroom Refinement (v7 NEW)
    # ─────────────────────────────────────────────
    def check_core_web_vitals_refinement(self):
        self.log("vitals", "▸", "Refining Core Web Vitals headroom...")

        entries = []
        worst_key = None
        worst_headroom = 0.0
        passing = ni = failing = 0

        for key, thresholds in self.CORE_WEB_VITALS.items():
            actual = self.raw_metrics.get(key)
            if actual is None:
                continue
            good = thresholds["good"]
            poor = thresholds["poor"]
            name = thresholds["name"]
            if not good:
                continue
            headroom_pct = (good - actual) / good * 100
            if actual <= good:
                passing += 1
            elif actual <= poor:
                ni += 1
            else:
                failing += 1
            entries.append((name, actual, headroom_pct))
            if worst_key is None or headroom_pct < worst_headroom:
                worst_headroom = headroom_pct
                worst_key = name

        if not entries:
            self.add_result("CWV Headroom Refinement", "No vitals", "needs_improvement", "vitals",
                            "Core Web Vitals metrics not available for headroom analysis",
                            weight=3, effort=2)
            return

        entries.sort(key=lambda x: x[2])
        summary = ", ".join("{} {:+.0f}%".format(n, h) for n, _, h in entries[:4])

        if failing >= 2:
            status = "poor"
        elif failing == 1 or ni >= 2:
            status = "needs_improvement"
        elif ni == 1:
            status = "good"
        else:
            status = "excellent"

        value = "tightest: {} {:+.0f}%".format(worst_key, worst_headroom)
        detail = "Headroom vs good thresholds (negative = over budget): " + summary
        self.add_result("CWV Headroom Refinement", value, status, "vitals", detail,
                        weight=3, effort=3)
        self.raw_metrics["cwv_headroom_pct"] = round(worst_headroom, 1)
        self.raw_metrics["cwv_headroom_worst"] = worst_key
        self.raw_metrics["cwv_pass_count"] = passing
        self.raw_metrics["cwv_ni_count"] = ni
        self.raw_metrics["cwv_fail_count"] = failing

    # ─────────────────────────────────────────────
    # CHECK: Images (v3 - enhanced)
    # ─────────────────────────────────────────────
    def check_images(self, soup, base_url):
        self.log("images", "▸", "Analyzing image optimization...")

        images = soup.find_all("img")
        total_imgs = len(images)
        if total_imgs == 0:
            self.add_result("Image Optimization", "No images found", "good", "images")
            return

        modern_formats = 0
        lazy_loaded = 0
        responsive = 0
        has_dimensions = 0
        issues = []

        for img in images:
            src = img.get("src", "")
            if src:
                ext = src.rsplit(".", 1)[-1].split("?")[0].lower() if "." in src else ""
                if ext in ("webp", "avif", "svg"):
                    modern_formats += 1
            if img.get("loading") == "lazy":
                lazy_loaded += 1
            if img.get("srcset") or img.find("source"):
                responsive += 1
            if img.get("width") and img.get("height"):
                has_dimensions += 1

        modern_pct = (modern_formats / total_imgs * 100) if total_imgs else 0
        lazy_pct = (lazy_loaded / total_imgs * 100) if total_imgs else 0
        responsive_pct = (responsive / total_imgs * 100) if total_imgs else 0
        dim_pct = (has_dimensions / total_imgs * 100) if total_imgs else 0

        if modern_pct > 50:
            fmt_status = "excellent"
        elif modern_pct > 0:
            fmt_status = "needs_improvement"
        else:
            fmt_status = "poor"
        self.add_result("Modern Formats", f"{modern_formats}/{total_imgs} ({modern_pct:.0f}%)", fmt_status, "images",
                        "WebP/AVIF usage",
                        weight=2, effort=2)

        if lazy_pct > 50:
            lazy_status = "excellent"
        elif lazy_pct > 0:
            lazy_status = "needs_improvement"
        else:
            lazy_status = "poor"
        self.add_result("Lazy Loading", f"{lazy_loaded}/{total_imgs} ({lazy_pct:.0f}%)", lazy_status, "images",
                        weight=1, effort=1)

        if responsive_pct > 50:
            resp_status = "excellent"
        elif responsive_pct > 0:
            resp_status = "needs_improvement"
        else:
            resp_status = "poor"
        self.add_result("Responsive Images", f"{responsive}/{total_imgs} ({responsive_pct:.0f}%)", resp_status, "images",
                        "srcset/picture usage",
                        weight=2, effort=2)

        if dim_pct > 80:
            dim_status = "excellent"
        elif dim_pct > 50:
            dim_status = "needs_improvement"
        else:
            dim_status = "poor"
        self.add_result("Image Dimensions", f"{has_dimensions}/{total_imgs} ({dim_pct:.0f}%)", dim_status, "images",
                        "Width/height attributes prevent layout shift",
                        weight=1, effort=1)

        self.raw_metrics["img_modern_formats"] = modern_formats
        self.raw_metrics["img_lazy_loaded"] = lazy_loaded
        self.raw_metrics["img_responsive"] = responsive

    # ─────────────────────────────────────────────
    # CHECK: Mobile (v3)
    # ─────────────────────────────────────────────
    def check_mobile(self, soup):
        self.log("mobile", "▸", "Checking mobile readiness...")

        viewport = soup.find("meta", attrs={"name": "viewport"})
        if viewport:
            content = viewport.get("content", "")
            if "width=device-width" in content:
                vp_status = "excellent"
                vp_detail = f"viewport: {content}"
            else:
                vp_status = "needs_improvement"
                vp_detail = f"viewport missing device-width: {content}"
        else:
            vp_status = "poor"
            vp_detail = "No viewport meta tag found"
        self.add_result("Viewport Meta", "Present" if viewport else "Missing", vp_status, "mobile", vp_detail,
                        weight=2, effort=1)
        self.raw_metrics["has_viewport"] = viewport is not None

        apple_touch = soup.find("link", rel="apple-touch-icon")
        self.add_result("Apple Touch Icon", "Present" if apple_touch else "Missing",
                        "good" if apple_touch else "needs_improvement", "mobile",
                        weight=1, effort=1)

        font_size_ok = True
        for tag in soup.find_all(["p", "span", "li", "td", "div"]):
            style = tag.get("style", "")
            font_match = re.search(r"font-size:\s*(\d+)px", style)
            if font_match:
                size = int(font_match.group(1))
                if size < 12:
                    font_size_ok = False
                    break
        self.add_result("Mobile Font Size", "Readable" if font_size_ok else "Too small",
                        "excellent" if font_size_ok else "poor", "mobile",
                        "Minimum 12px recommended for mobile readability",
                        weight=1, effort=2)

    # ─────────────────────────────────────────────
    # CHECK: Modern API Detection (v3 NEW)
    # ─────────────────────────────────────────────
    def check_modern_apis(self, soup, html_content):
        self.log("modern", "▸", "Detecting modern web APIs...")

        all_text = html_content
        for script in soup.find_all("script"):
            all_text += script.string or ""

        # Storage APIs
        storage_apis = []
        if "localStorage" in all_text:
            storage_apis.append("localStorage")
        if "sessionStorage" in all_text:
            storage_apis.append("sessionStorage")
        if "indexedDB" in all_text or "IndexedDB" in all_text:
            storage_apis.append("IndexedDB")

        storage_status = "excellent" if len(storage_apis) >= 2 else "good" if storage_apis else "needs_improvement"
        self.add_result("Storage APIs", ", ".join(storage_apis) if storage_apis else "None detected", storage_status, "modern",
                        f"localStorage: {'yes' if 'localStorage' in all_text else 'no'}, "
                        f"sessionStorage: {'yes' if 'sessionStorage' in all_text else 'no'}, "
                        f"IndexedDB: {'yes' if 'indexedDB' in all_text else 'no'}",
                        weight=1, effort=2)
        self.raw_metrics["storage_apis"] = storage_apis

        # Web Workers
        has_web_worker = "Worker(" in all_text or "new Worker" in all_text or "SharedWorker" in all_text
        has_service_worker = "serviceWorker" in all_text
        worker_type = "Web Worker" if has_web_worker else "Service Worker" if has_service_worker else "None"
        worker_status = "excellent" if has_web_worker else "good" if has_service_worker else "needs_improvement"
        self.add_result("Web Workers", worker_type, worker_status, "modern",
                        "Web Workers offload main thread; Service Worker enables offline/caching",
                        weight=2, effort=3)
        self.raw_metrics["web_worker"] = has_web_worker

        # WebAssembly
        has_wasm = "WebAssembly" in all_text or ".wasm" in all_text
        self.add_result("WebAssembly", "Detected" if has_wasm else "Not used",
                        "good" if has_wasm else "needs_improvement", "modern",
                        "WebAssembly enables near-native performance for compute-heavy tasks",
                        weight=1, effort=5)
        self.raw_metrics["webassembly"] = has_wasm

        # Intersection Observer
        has_io = "IntersectionObserver" in all_text
        self.add_result("Intersection Observer", "Detected" if has_io else "Not used",
                        "excellent" if has_io else "needs_improvement", "modern",
                        "IntersectionObserver enables efficient lazy loading and scroll-based actions",
                        weight=2, effort=2)
        self.raw_metrics["intersection_observer"] = has_io

        # RequestAnimationFrame
        has_raf = "requestAnimationFrame" in all_text
        self.add_result("requestAnimationFrame", "Detected" if has_raf else "Not used",
                        "excellent" if has_raf else "needs_improvement", "modern",
                        "requestAnimationFrame for smooth, jank-free animations",
                        weight=1, effort=1)
        self.raw_metrics["request_animation_frame"] = has_raf

        # Passive event listeners
        passive_pattern = re.compile(r'addEventListener\s*\(\s*["\'](?:scroll|touchstart|touchmove|wheel)["\']\s*,\s*[^,]+\s*,\s*\{[^}]*passive\s*:\s*true', re.IGNORECASE)
        has_passive = bool(passive_pattern.search(all_text))
        total_listeners = all_text.count("addEventListener")
        self.add_result("Passive Event Listeners", f"Detected ({total_listeners} listeners)" if has_passive else f"Not detected ({total_listeners} listeners)",
                        "excellent" if has_passive else "needs_improvement", "modern",
                        "Passive listeners prevent scroll jank on touch/wheel events",
                        weight=2, effort=1)
        self.raw_metrics["passive_listeners"] = has_passive

        # Debounced scroll/resize handlers
        scroll_handlers = len(re.findall(r'addEventListener\s*\(\s*["\']scroll["\']', all_text))
        resize_handlers = len(re.findall(r'addEventListener\s*\(\s*["\']resize["\']', all_text))
        has_debounce = "debounce" in all_text.lower() or "throttle" in all_text.lower()
        if (scroll_handlers > 0 or resize_handlers > 0) and has_debounce:
            debounce_status = "excellent"
            debounce_detail = f"Debounced/throttled handlers detected (scroll: {scroll_handlers}, resize: {resize_handlers})"
        elif scroll_handlers > 0 or resize_handlers > 0:
            debounce_status = "poor"
            debounce_detail = f"Scroll/resize handlers without debounce/throttle (scroll: {scroll_handlers}, resize: {resize_handlers})"
        else:
            debounce_status = "good"
            debounce_detail = "No scroll/resize handlers detected"
        self.add_result("Scroll/Resize Debouncing", debounce_detail, debounce_status, "modern",
                        debounce_detail,
                        weight=2, effort=1)
        self.raw_metrics["debounce_throttle"] = has_debounce

    def _page_text(self, soup, html_content):
        all_text = html_content
        for script in soup.find_all("script"):
            all_text += script.string or ""
        for style in soup.find_all("style"):
            all_text += style.string or ""
        return all_text

    # ─────────────────────────────────────────────
    # CHECK: Speculation Rules API (v6 NEW)
    # ─────────────────────────────────────────────
    def check_speculation_rules(self, soup, html_content, response_headers=None):
        self.log("modern", "▸", "Detecting Speculation Rules API...")

        all_text = self._page_text(soup, html_content)
        speculation_blocks = []
        for script in soup.find_all("script"):
            script_type = (script.get("type") or "").lower()
            if "speculationrules" in script_type:
                speculation_blocks.append(script.string or "")

        has_prefetch_rule = any("prefetch" in block for block in speculation_blocks)
        has_prerender_rule = any("prerender" in block for block in speculation_blocks)
        has_js_api = "speculation" in all_text.lower() and (
            "prefetch" in all_text.lower() or "prerender" in all_text.lower()
        )
        header_rules = ""
        if response_headers:
            header_rules = response_headers.get("Speculation-Rules", "")
        has_header = bool(header_rules)

        score = 0
        details = []
        if speculation_blocks:
            score += 3
            details.append("{} speculationrules script block(s)".format(len(speculation_blocks)))
            if has_prefetch_rule:
                score += 1
                details.append("prefetch rules for next navigations")
            if has_prerender_rule:
                score += 1
                details.append("prerender rules (deeper navigation warmup)")
        if has_js_api:
            score += 2
            details.append("SpeculationRules JS API usage")
        if has_header:
            score += 2
            details.append("Speculation-Rules response header present")
        if not details:
            details.append("No Speculation Rules API usage - prefetch/prerender could warm likely next pages")

        if score >= 4:
            status = "excellent"
        elif score >= 2:
            status = "good"
        elif score >= 1:
            status = "needs_improvement"
        else:
            status = "needs_improvement"

        if speculation_blocks or has_js_api or has_header:
            value = "{} rules (prefetch: {}, prerender: {})".format(
                len(speculation_blocks) + (1 if has_header else 0),
                "yes" if has_prefetch_rule else "no",
                "yes" if has_prerender_rule else "no",
            )
        else:
            value = "Not used"
        self.add_result("Speculation Rules API", value, status, "modern",
                        "; ".join(details[:4]),
                        weight=2, effort=2)
        self.raw_metrics["speculation_rules"] = bool(speculation_blocks) or has_js_api or has_header
        self.raw_metrics["speculation_prefetch"] = has_prefetch_rule
        self.raw_metrics["speculation_prerender"] = has_prerender_rule
        self.raw_metrics["speculation_score"] = score

    # ─────────────────────────────────────────────
    # CHECK: View Transitions API (v6 NEW)
    # ─────────────────────────────────────────────
    def check_view_transitions(self, soup, html_content):
        self.log("modern", "▸", "Detecting View Transitions API...")

        all_text = self._page_text(soup, html_content)
        has_start_vt = "startViewTransition" in all_text
        has_css_name = "view-transition-name" in all_text or "viewTransitionName" in all_text
        has_root_rule = "@view-transition" in all_text
        has_meta_flag = any("view-transition" in str(m).lower() for m in soup.find_all("meta"))
        has_css_group = "::view-transition" in all_text
        has_cross_doc = "view-transition" in all_text and ("history" in all_text.lower() or "navigate" in all_text.lower())

        score = 0
        details = []
        if has_start_vt:
            score += 3
            details.append("document.startViewTransition() detected")
        if has_css_name:
            score += 2
            details.append("view-transition-name CSS properties")
        if has_css_group or has_root_rule:
            score += 1
            details.append("::view-transition / @view-transition styling")
        if has_meta_flag:
            score += 1
            details.append("Meta View-Transition configuration")
        if has_cross_doc:
            score += 1
            details.append("Cross-document view transition signals")
        if not details:
            details.append("No View Transitions usage - SPA/route transitions could animate smoothly")

        if score >= 4:
            status = "excellent"
        elif score >= 2:
            status = "good"
        elif score >= 1:
            status = "needs_improvement"
        else:
            status = "needs_improvement"

        used = has_start_vt or has_css_name or has_root_rule or has_meta_flag
        value = "Detected" if used else "Not used"
        self.add_result("View Transitions API", value, status, "modern",
                        "; ".join(details[:4]),
                        weight=1, effort=2)
        self.raw_metrics["view_transitions"] = used
        self.raw_metrics["view_transitions_score"] = score

    # ─────────────────────────────────────────────
    # CHECK: Container Queries (v6 NEW)
    # ─────────────────────────────────────────────
    def check_container_queries(self, soup, html_content):
        self.log("modern", "▸", "Detecting Container Queries...")

        all_text = self._page_text(soup, html_content)
        has_at_container = len(re.findall(r"@container\b", all_text))
        has_container_type = "container-type" in all_text
        has_container_name = "container-name" in all_text
        has_cq_units = len(re.findall(r"\b\d+(?:\.\d+)?c[qwhminax]\b", all_text))
        has_inline_container = "container" in all_text and ("inline-size" in all_text or "size:" in all_text)

        score = 0
        details = []
        if has_at_container:
            score += 3
            details.append("{} @container rules".format(has_at_container))
        if has_container_type:
            score += 2
            details.append("container-type declared")
        if has_container_name:
            score += 1
            details.append("container-name declared")
        if has_cq_units:
            score += 1
            details.append("{} container query units (cqw/cqi/...)".format(has_cq_units))
        if has_inline_container:
            score += 1
            details.append("inline-size container sizing signals")
        if not details:
            details.append("No container queries - component-level responsive CSS still relies on viewport media queries")

        if score >= 4:
            status = "excellent"
        elif score >= 2:
            status = "good"
        elif score >= 1:
            status = "needs_improvement"
        else:
            status = "needs_improvement"

        used = has_at_container > 0 or has_container_type or has_cq_units > 0
        value = "{} @container rules".format(has_at_container) if used else "Not used"
        self.add_result("Container Queries", value, status, "modern",
                        "; ".join(details[:4]),
                        weight=1, effort=2)
        self.raw_metrics["container_queries"] = used
        self.raw_metrics["container_query_rules"] = has_at_container
        self.raw_metrics["container_queries_score"] = score

    # ─────────────────────────────────────────────
    # CHECK: CSS Nesting (v6 NEW)
    # ─────────────────────────────────────────────
    def check_css_nesting(self, soup, html_content):
        self.log("modern", "▸", "Detecting CSS Nesting...")

        all_text = self._page_text(soup, html_content)
        css_texts = [style.string or "" for style in soup.find_all("style")]
        css_blob = "\n".join(css_texts)

        amp_nests = len(re.findall(r"&(?!&)\s*[.:\[#a-zA-Z*]", css_blob))
        legacy_nest = len(re.findall(r"@nest\b", all_text))
        postcss_nest = ("postcss-nesting" in all_text) or ("nesting" in all_text.lower() and "css" in all_text.lower())
        nested_selectors = len(re.findall(r"\{\s*\n\s*[.#&:\[][^{}]*\{", css_blob))

        score = 0
        details = []
        if amp_nests > 0:
            score += 3
            details.append("{} '&' nesting selectors in inline CSS".format(amp_nests))
        if nested_selectors > 0:
            score += 2
            details.append("{} nested selector blocks detected".format(nested_selectors))
        if legacy_nest > 0:
            score += 1
            details.append("{} legacy @nest at-rules".format(legacy_nest))
        if postcss_nest:
            score += 1
            details.append("Nesting toolchain signal (PostCSS/processor)")
        if not details:
            details.append("No CSS nesting detected in inline styles (external CSS may still use it)")

        if score >= 4:
            status = "excellent"
        elif score >= 2:
            status = "good"
        elif score >= 1:
            status = "needs_improvement"
        else:
            status = "needs_improvement"

        used = amp_nests > 0 or nested_selectors > 0 or legacy_nest > 0
        value = "{} nested rules".format(amp_nests + nested_selectors) if used else "Not detected"
        self.add_result("CSS Nesting", value, status, "modern",
                        "; ".join(details[:4]),
                        weight=1, effort=2)
        self.raw_metrics["css_nesting"] = used
        self.raw_metrics["css_nesting_score"] = score

    # ─────────────────────────────────────────────
    # CHECK: WebGPU (v6 NEW)
    # ─────────────────────────────────────────────
    def check_webgpu(self, soup, html_content):
        self.log("modern", "▸", "Detecting WebGPU...")

        all_text = self._page_text(soup, html_content)
        has_navigator_gpu = "navigator.gpu" in all_text
        has_request_adapter = "requestAdapter" in all_text and "GPU" in all_text
        has_request_device = "requestDevice" in all_text and "GPU" in all_text
        has_wgsl = "createShaderModule" in all_text or ".wgsl" in all_text
        has_gpu_canvas = "getContext" in all_text and ("webgpu" in all_text.lower() or "gpu" in all_text)
        has_fallback = has_navigator_gpu and ("requestAdapter" in all_text) and ("catch" in all_text or "fallback" in all_text.lower())

        score = 0
        details = []
        if has_navigator_gpu:
            score += 3
            details.append("navigator.gpu detected")
        if has_request_adapter or has_request_device:
            score += 2
            details.append("GPU adapter/device acquisition")
        if has_wgsl:
            score += 1
            details.append("WGSL shader module creation")
        if has_gpu_canvas:
            score += 1
            details.append("WebGPU canvas/context usage")
        if has_fallback:
            score += 1
            details.append("Graceful fallback path present")
        if not details:
            details.append("No WebGPU usage (optional; relevant for compute/graphics-heavy apps)")

        if score >= 4:
            status = "excellent"
        elif score >= 2:
            status = "good"
        elif score >= 1:
            status = "good"
        else:
            status = "good"

        used = has_navigator_gpu or has_request_adapter or has_request_device
        value = "Detected" if used else "Not used"
        self.add_result("WebGPU", value, status, "modern",
                        "; ".join(details[:4]),
                        weight=1, effort=4)
        self.raw_metrics["webgpu"] = used
        self.raw_metrics["webgpu_score"] = score

    # ─────────────────────────────────────────────
    # CHECK: WebTransport (v6 NEW)
    # ─────────────────────────────────────────────
    def check_webtransport(self, soup, html_content):
        self.log("modern", "▸", "Detecting WebTransport...")

        all_text = self._page_text(soup, html_content)
        has_class = "WebTransport" in all_text
        has_constructor = bool(re.search(r"new\s+WebTransport\s*\(", all_text))
        has_datagrams = "datagrams" in all_text and has_class
        has_streams = ("readable" in all_text.lower() or "writable" in all_text.lower()) and has_class
        has_wt_scheme = bool(re.search(r"webtransport://|\.webtransport\b", all_text, re.IGNORECASE))
        has_quic_signal = has_class and ("quic" in all_text.lower())

        score = 0
        details = []
        if has_class:
            score += 3
            details.append("WebTransport reference detected")
        if has_constructor:
            score += 2
            details.append("new WebTransport(...) connection setup")
        if has_datagrams:
            score += 1
            details.append("Datagram channel usage")
        if has_streams:
            score += 1
            details.append("Stream channels usage")
        if has_wt_scheme or has_quic_signal:
            score += 1
            details.append("WebTransport/QUIC endpoint signals")
        if not details:
            details.append("No WebTransport usage (optional; useful for low-latency bidirectional data)")

        if score >= 4:
            status = "excellent"
        elif score >= 2:
            status = "good"
        elif score >= 1:
            status = "good"
        else:
            status = "good"

        used = has_class or has_constructor
        value = "Detected" if used else "Not used"
        self.add_result("WebTransport", value, status, "modern",
                        "; ".join(details[:4]),
                        weight=1, effort=4)
        self.raw_metrics["webtransport"] = used
        self.raw_metrics["webtransport_score"] = score

    # ─────────────────────────────────────────────
    # CHECK: Memory Leak Indicators (v3 NEW)
    # ─────────────────────────────────────────────
    def check_memory_leaks(self, soup, html_content):
        self.log("memory", "▸", "Checking for memory leak indicators...")

        all_text = html_content
        for script in soup.find_all("script"):
            all_text += script.string or ""

        issues = []
        score = 0

        # Global variable pollution
        global_assigns = re.findall(r'(?:window|globalThis)\.\w+\s*=', all_text)
        if global_assigns:
            issues.append(f"{len(global_assigns)} global variable assignments")
            score -= len(global_assigns)

        # setInterval without clearInterval
        set_intervals = all_text.count("setInterval")
        clear_intervals = all_text.count("clearInterval")
        if set_intervals > 0 and clear_intervals < set_intervals:
            issues.append(f"setInterval({set_intervals}) without matching clearInterval({clear_intervals})")
            score -= 1

        # DOM manipulation without cleanup
        append_child = all_text.count("appendChild")
        remove_child = all_text.count("removeChild")
        if append_child > 3 and remove_child == 0:
            issues.append(f"appendChild({append_child}) calls without removeChild - potential DOM leaks")
            score -= 1

        # addEventListener without removeEventListener
        add_listeners = all_text.count("addEventListener")
        remove_listeners = all_text.count("removeEventListener")
        if add_listeners > 5 and remove_listeners == 0:
            issues.append(f"addEventListener({add_listeners}) without removeEventListener - potential listener leaks")
            score -= 1

        # Closures in loops (simple heuristic)
        closure_in_loop = re.findall(r'for\s*\([^)]*\)\s*\{[^}]*function\s*\(', all_text)
        if closure_in_loop:
            issues.append(f"{len(closure_in_loop)} potential closures in loops")
            score -= 1

        # Detached DOM references
        innerhtml_sets = all_text.count(".innerHTML")
        if innerhtml_sets > 5:
            issues.append(f"innerHTML used {innerhtml_sets} times - may cause memory issues")
            score -= 1

        if score >= 0:
            status = "excellent"
            detail = "No obvious memory leak patterns detected" if not issues else "; ".join(issues[:3])
        elif score >= -2:
            status = "needs_improvement"
            detail = "; ".join(issues[:3])
        else:
            status = "poor"
            detail = "; ".join(issues[:4])

        self.add_result("Memory Leak Indicators", f"{abs(score)} potential issues", status, "memory",
                        detail,
                        weight=2, effort=3)
        self.raw_metrics["memory_leak_score"] = score

    # ─────────────────────────────────────────────
    # CHECK: Real User Metrics Simulation (v3 NEW)
    # ─────────────────────────────────────────────
    def check_real_user_simulation(self):
        self.log("simulation", "▸", f"Simulating real user experience ({self.connection} / {self.device})...")

        conn = self.CONNECTION_PROFILES.get(self.connection, self.CONNECTION_PROFILES["wifi"])
        dev = self.DEVICE_PROFILES.get(self.device, self.DEVICE_PROFILES["desktop"])

        combined_cpu = conn["cpu_multiplier"] * dev["cpu_multiplier"]

        simulated_metrics = {}
        base_metrics = {
            "ttfb_ms": self.raw_metrics.get("ttfb_ms", 500),
            "lcp_ms": self.raw_metrics.get("lcp_ms", 2500),
            "fcp_ms": self.raw_metrics.get("fcp_ms", 1800),
            "si_ms": self.raw_metrics.get("si_ms", 3400),
            "tti_ms": self.raw_metrics.get("tti_ms", 3800),
            "tbt_ms": self.raw_metrics.get("tbt_ms", 200),
        }

        for key, base_val in base_metrics.items():
            simulated = base_val * conn["multiplier"]
            if key in ("tti_ms", "tbt_ms", "lcp_ms"):
                simulated *= dev["cpu_multiplier"]
            simulated_metrics[key] = int(simulated)

        # Network throttling estimation
        total_page_size = self.raw_metrics.get("total_page_size", 0)
        if conn["download_kbps"] > 0:
            transfer_time_ms = (total_page_size * 8) / (conn["download_kbps"]) * 1000
        else:
            transfer_time_ms = 0
        network_latency = conn["latency_ms"]
        estimated_total = network_latency + transfer_time_ms
        simulated_metrics["estimated_total_ms"] = int(estimated_total)

        # CPU throttling estimation
        js_exec = self.raw_metrics.get("js_exec_time_ms", 500)
        cpu_throttled_exec = int(js_exec * combined_cpu)
        simulated_metrics["cpu_throttled_js_ms"] = cpu_throttled_exec

        # Score each simulated metric
        issues = []
        lcp_sim = simulated_metrics.get("lcp_ms", 0)
        lcp_status = "excellent" if lcp_sim < 2500 else "needs_improvement" if lcp_sim < 4000 else "poor"
        if lcp_sim > 4000:
            issues.append(f"LCP on {conn['label']}: {lcp_sim}ms (poor)")

        tti_sim = simulated_metrics.get("tti_ms", 0)
        tti_status = "excellent" if tti_sim < 3800 else "needs_improvement" if tti_sim < 7300 else "poor"
        if tti_sim > 7300:
            issues.append(f"TTI on {conn['label']}/{dev['label']}: {tti_sim}ms (poor)")

        tbt_sim = simulated_metrics.get("tbt_ms", 0)
        tbt_status = "excellent" if tbt_sim < 200 else "needs_improvement" if tbt_sim < 600 else "poor"
        if tbt_sim > 600:
            issues.append(f"TBT on {dev['label']}: {tbt_sim}ms (poor)")

        if not issues:
            overall_sim_status = "excellent"
        elif len(issues) <= 1:
            overall_sim_status = "needs_improvement"
        else:
            overall_sim_status = "poor"

        sim_detail = f"Connection: {conn['label']} ({conn['download_kbps']}kbps, {conn['latency_ms']}ms RTT), Device: {dev['label']} (CPU {combined_cpu:.1f}x)"
        if issues:
            sim_detail += " | Issues: " + "; ".join(issues[:3])

        self.add_result("Simulated LCP", f"{lcp_sim}ms ({self.connection})", lcp_status, "simulation",
                        f"Base: {base_metrics['lcp_ms']}ms * {conn['multiplier']}x connection multiplier",
                        weight=3, effort=2)
        self.add_result("Simulated TTI", f"{tti_sim}ms ({self.connection}/{self.device})", tti_status, "simulation",
                        f"Base: {base_metrics['tti_ms']}ms * {conn['multiplier']}x conn * {dev['cpu_multiplier']}x CPU",
                        weight=3, effort=2)
        self.add_result("Simulated TBT", f"{tbt_sim}ms ({self.device})", tbt_status, "simulation",
                        f"Base: {base_metrics['tbt_ms']}ms * {combined_cpu:.1f}x CPU throttle",
                        weight=2, effort=2)
        self.add_result("Network Transfer Estimate", f"{transfer_time_ms/1000:.2f}s ({conn['label']})", "good" if transfer_time_ms < 3000 else "needs_improvement", "simulation",
                        f"Page size: {total_page_size/1024:.1f}KB over {conn['download_kbps']}kbps link + {conn['latency_ms']}ms RTT",
                        weight=2, effort=2)

        self.raw_metrics["simulated_lcp"] = lcp_sim
        self.raw_metrics["simulated_tti"] = tti_sim
        self.raw_metrics["simulated_tbt"] = tbt_sim
        self.raw_metrics["simulated_total"] = estimated_total
        self.raw_metrics["cpu_throttled_js_ms"] = cpu_throttled_exec

    # ─────────────────────────────────────────────
    # CHECK: Performance Observer API (v5 NEW)
    # ─────────────────────────────────────────────
    def check_performance_observer(self, soup, html_content):
        self.log("observers", "▸", "Detecting Performance Observer API usage...")

        all_text = html_content
        for script in soup.find_all("script"):
            all_text += script.string or ""

        has_observer = "PerformanceObserver" in all_text
        observed_types = set()
        if has_observer:
            for match in re.findall(r"observe\s*\(\s*\{\s*type\s*:\s*['\"]([\w-]+)", all_text):
                observed_types.add(match)
            for match in re.findall(r"\.observe\(\s*['\"]([\w-]+)['\"]", all_text):
                observed_types.add(match)
            for known in ("largest-contentful-paint", "layout-shift", "first-input", "paint",
                          "navigation", "resource", "longtask", "long-animation-frame", "event", "element"):
                if known in all_text:
                    observed_types.add(known)

        has_buffered = has_observer and "buffered" in all_text
        has_disconnect = has_observer and "disconnect()" in all_text
        has_entrytypes = has_observer and "supportedEntryTypes" in all_text

        score = 0
        details = []
        if has_observer:
            score += 2
            details.append("PerformanceObserver detected")
            if observed_types:
                score += 1
                details.append("Observing: " + ", ".join(sorted(observed_types)[:6]))
            if has_buffered:
                score += 1
                details.append("buffered:true captures past entries")
            if has_entrytypes:
                score += 1
                details.append("supportedEntryTypes feature detection")
            if has_disconnect:
                score += 1
                details.append("Observer disconnect() cleanup present")
        else:
            details.append("PerformanceObserver not found - instrument Core Web Vitals for RUM")

        if score >= 4:
            status = "excellent"
        elif score >= 2:
            status = "good"
        else:
            status = "needs_improvement"

        if observed_types:
            value = "{} entry types".format(len(observed_types))
        elif has_observer:
            value = "Detected"
        else:
            value = "Not used"
        self.add_result("Performance Observer API", value, status, "observers",
                        "; ".join(details[:4]),
                        weight=3, effort=2)
        self.raw_metrics["performance_observer"] = has_observer
        self.raw_metrics["performance_observer_types"] = sorted(observed_types)
        self.raw_metrics["performance_observer_score"] = score

    # ─────────────────────────────────────────────
    # CHECK: Intersection Observer Lazy Loading (v5 NEW)
    # ─────────────────────────────────────────────
    def check_intersection_observer_lazy_loading(self, soup, html_content):
        self.log("observers", "▸", "Analyzing Intersection Observer lazy loading...")

        all_text = html_content
        for script in soup.find_all("script"):
            all_text += script.string or ""

        has_io = "IntersectionObserver" in all_text
        images = soup.find_all("img")
        total_imgs = len(images)
        native_lazy = sum(1 for img in images if img.get("loading") == "lazy")
        data_src = sum(1 for img in images if img.get("data-src") or img.get("data-srcset"))
        content_visibility = all_text.count("content-visibility")
        io_root_margin = has_io and "rootMargin" in all_text
        io_threshold = has_io and "threshold" in all_text

        lazy_coverage = 0.0
        if total_imgs > 0:
            lazy_coverage = ((native_lazy + data_src) / total_imgs) * 100

        score = 0
        details = []
        if has_io:
            score += 2
            details.append("IntersectionObserver used")
            if io_root_margin:
                score += 1
                details.append("rootMargin preloading configured")
            if io_threshold:
                score += 1
                details.append("threshold-based triggering")
        if native_lazy > 0:
            score += 1
            details.append("{} native loading=lazy images".format(native_lazy))
        if data_src > 0:
            score += 1
            details.append("{} data-src deferred images".format(data_src))
        if content_visibility > 0:
            score += 1
            details.append("{} content-visibility usages".format(content_visibility))
        if total_imgs > 0 and lazy_coverage >= 50:
            score += 1
            details.append("Lazy coverage {:.0f}%".format(lazy_coverage))
        if not details:
            details.append("No lazy loading strategy detected")

        if score >= 4:
            status = "excellent"
        elif score >= 2:
            status = "good"
        elif score >= 1:
            status = "needs_improvement"
        else:
            status = "poor"

        value = "IO: {}, Lazy: {:.0f}%".format("yes" if has_io else "no", lazy_coverage)
        self.add_result("Intersection Observer Lazy Load", value, status, "observers",
                        "; ".join(details[:4]),
                        weight=3, effort=2)
        self.raw_metrics["io_lazy_loading"] = has_io
        self.raw_metrics["lazy_loading_coverage"] = round(lazy_coverage, 1)
        self.raw_metrics["intersection_observer_score"] = score

    # ─────────────────────────────────────────────
    # CHECK: requestIdleCallback Usage (v5 NEW)
    # ─────────────────────────────────────────────
    def check_request_idle_callback(self, soup, html_content):
        self.log("observers", "▸", "Detecting requestIdleCallback usage...")

        all_text = html_content
        for script in soup.find_all("script"):
            all_text += script.string or ""

        ric_count = all_text.count("requestIdleCallback")
        cic_count = all_text.count("cancelIdleCallback")
        has_scheduler = "postTask" in all_text and "scheduler" in all_text.lower()
        has_messagechannel = "MessageChannel" in all_text

        score = 0
        details = []
        if ric_count > 0:
            score += 3
            details.append("requestIdleCallback x{}".format(ric_count))
            if cic_count > 0:
                score += 1
                details.append("cancelIdleCallback cleanup present")
        if has_scheduler:
            score += 2
            details.append("Scheduler.postTask detected")
        if has_messagechannel and ric_count == 0:
            score += 1
            details.append("MessageChannel used as idle fallback")
        if ric_count == 0 and not has_scheduler:
            details.append("No idle scheduling - heavy work may block input")

        if score >= 3:
            status = "excellent"
        elif score >= 1:
            status = "good"
        else:
            status = "needs_improvement"

        value = "{} calls".format(ric_count) if ric_count else "Not used"
        self.add_result("requestIdleCallback", value, status, "observers",
                        "; ".join(details[:3]),
                        weight=2, effort=1)
        self.raw_metrics["request_idle_callback_count"] = ric_count
        self.raw_metrics["request_idle_callback"] = ric_count > 0

    # ─────────────────────────────────────────────
    # CHECK: Web Vitals Library Detection (v5 NEW)
    # ─────────────────────────────────────────────
    def check_web_vitals_library(self, soup, html_content):
        self.log("observers", "▸", "Detecting Web Vitals library...")

        all_text = html_content
        for script in soup.find_all("script"):
            all_text += script.string or ""
        for script in soup.find_all("script", src=True):
            all_text += script.get("src", "")

        library_hits = []
        indicators = {
            "web-vitals package": ["from 'web-vitals'", 'from "web-vitals"', "web-vitals@"],
            "webVitals helpers": ["webVitals.get", "webVitals.on"],
            "onLCP/onCLS/onINP": ["onLCP", "onCLS", "onINP", "onFCP", "onTTFB", "onFID"],
            "getLCP/getCLS legacy": ["getLCP(", "getCLS(", "getFID(", "getFCP(", "getTTFB("],
            "reportWebVitals": ["reportWebVitals"],
            "gtag web vitals": ["web_vitals"],
        }
        for label, needles in indicators.items():
            for needle in needles:
                if needle in all_text:
                    library_hits.append(label)
                    break

        vitals_types = []
        for entry_type in ("largest-contentful-paint", "layout-shift", "first-input", "paint"):
            if entry_type in all_text:
                vitals_types.append(entry_type)

        has_custom_marks = "performance.mark" in all_text or "performance.measure" in all_text

        score = 0
        details = []
        if library_hits:
            score += 3
            details.append("Signals: " + ", ".join(sorted(set(library_hits))[:3]))
        if vitals_types:
            score += 1
            details.append("Vitals entry types referenced")
        if has_custom_marks:
            score += 1
            details.append("performance.mark/measure instrumentation")
        if not library_hits and not has_custom_marks:
            details.append("No Web Vitals library detected - consider the web-vitals package for RUM")

        if score >= 3:
            status = "excellent"
        elif score >= 1:
            status = "good"
        else:
            status = "needs_improvement"

        value = "{} signals".format(len(set(library_hits))) if library_hits else "Not detected"
        self.add_result("Web Vitals Library", value, status, "observers",
                        "; ".join(details[:3]),
                        weight=2, effort=2)
        self.raw_metrics["web_vitals_library"] = bool(library_hits)
        self.raw_metrics["web_vitals_signals"] = sorted(set(library_hits))

    # ─────────────────────────────────────────────
    # CHECK: Real User Monitoring Detection (v5 NEW)
    # ─────────────────────────────────────────────
    def check_rum_detection(self, soup, html_content):
        self.log("observers", "▸", "Scanning for Real User Monitoring (RUM)...")

        all_text = html_content
        for script in soup.find_all("script"):
            all_text += script.string or ""
        for script in soup.find_all("script", src=True):
            all_text += script.get("src", "")
        for link in soup.find_all("link"):
            all_text += link.get("href", "")
        haystack_lower = all_text.lower()

        detected = []
        for provider, needles in self.RUM_PROVIDERS.items():
            for needle in needles:
                if needle.lower() in haystack_lower:
                    detected.append(provider)
                    break

        has_perf_rum = ("getEntriesByType" in all_text and "navigation" in all_text) or "PerformanceObserver" in all_text
        mark_count = all_text.count("performance.mark") + all_text.count("performance.measure")

        score = 0
        details = []
        if detected:
            score += 3
            details.append("Providers: " + ", ".join(detected[:4]))
        if has_perf_rum:
            score += 1
            details.append("Native Performance API instrumentation")
        if mark_count > 0:
            score += 1
            details.append("{} performance.mark/measure calls".format(mark_count))
        if not detected and not has_perf_rum:
            details.append("No RUM detected - lab metrics alone miss field regressions")

        if score >= 3:
            status = "excellent"
        elif score >= 1:
            status = "good"
        else:
            status = "needs_improvement"

        value = "{} vendors".format(len(detected)) if detected else ("Custom" if has_perf_rum else "Not detected")
        self.add_result("Real User Monitoring (RUM)", value, status, "observers",
                        "; ".join(details[:4]),
                        weight=3, effort=3)
        self.raw_metrics["rum_providers"] = detected
        self.raw_metrics["rum_detected"] = bool(detected) or has_perf_rum

    # ─────────────────────────────────────────────
    # CHECK: Analytics Impact Analysis (v5 NEW)
    # ─────────────────────────────────────────────
    def check_analytics_impact(self, soup, base_url):
        self.log("analytics", "▸", "Analyzing analytics script impact...")

        parsed_base = urlparse(base_url)
        script_tags = soup.find_all("script", src=True)
        inline_text = "".join(script.string or "" for script in soup.find_all("script", src=False))
        src_text = "".join(script.get("src", "") for script in script_tags)
        haystack_lower = (src_text + inline_text).lower()

        detected = []
        for provider, needles in self.ANALYTICS_PROVIDERS.items():
            for needle in needles:
                if needle.lower() in haystack_lower:
                    detected.append(provider)
                    break

        blocking = 0
        third_party_count = 0
        for script in script_tags:
            src = script.get("src", "")
            if not src:
                continue
            full = urljoin(base_url, src)
            parsed = urlparse(full)
            is_third_party = bool(parsed.netloc) and parsed.netloc != parsed_base.netloc
            if is_third_party:
                third_party_count += 1
            matches_analytics = any(
                needle.lower() in src.lower()
                for needles in self.ANALYTICS_PROVIDERS.values()
                for needle in needles
            )
            if matches_analytics and not script.get("async") and not script.get("defer"):
                blocking += 1

        total = len(detected)
        est_overhead_ms = total * 40 + blocking * 120 + third_party_count * 25

        score = 0
        details = []
        if total > 0:
            details.append("{} analytics vendors: {}".format(total, ", ".join(detected[:4])))
            score += 1
        else:
            details.append("No analytics vendors detected")
            score += 2
        if blocking > 0:
            details.append("{} blocking analytics scripts".format(blocking))
            score -= 2
        if total > 6:
            details.append("High vendor count degrades main thread")
            score -= 1
        details.append("Est. overhead ~{}ms".format(est_overhead_ms))

        if score >= 2:
            status = "excellent"
        elif score >= 0:
            status = "good" if blocking == 0 else "needs_improvement"
        else:
            status = "poor"

        value = "{} vendors ({} blocking)".format(total, blocking)
        self.add_result("Analytics Impact", value, status, "analytics",
                        "; ".join(details[:4]),
                        weight=3, effort=3)
        self.raw_metrics["analytics_providers"] = detected
        self.raw_metrics["analytics_blocking"] = blocking
        self.raw_metrics["analytics_overhead_ms"] = est_overhead_ms

    # ─────────────────────────────────────────────
    # CHECK: Critical CSS Extraction (v5 NEW)
    # ─────────────────────────────────────────────
    def check_critical_css_extraction(self, soup, base_url):
        self.log("rendering", "▸", "Extracting critical CSS...")

        inline_blocks = [style.string or "" for style in soup.find_all("style")]
        inline_css = "\n".join(inline_blocks)
        inline_size = len(inline_css)

        external_count = 0
        non_blocking_css = 0
        external_sample = ""
        external_bytes = 0
        for link in soup.find_all("link", rel="stylesheet")[:3]:
            href = link.get("href", "")
            media = link.get("media", "")
            if media and media != "all":
                non_blocking_css += 1
            if not href:
                continue
            external_count += 1
            try:
                resp = self.session.get(urljoin(base_url, href), timeout=5)
                if resp.status_code == 200:
                    external_bytes += len(resp.content)
                    if not external_sample:
                        external_sample = resp.text[:200000]
            except Exception:
                pass

        combined = inline_css + "\n" + external_sample
        rules = re.findall(r"([^{}@]+)\{([^{}]*)\}", combined)
        critical_tokens = (
            "html", "body", ":root", "header", "nav", "h1", "h2", ".hero",
            ".container", ".header", ".banner", "main", "#root", "#app", ".navbar", ".top",
        )

        def is_critical_selector(selector):
            first = selector.split(",")[0].strip().lower()
            if not first:
                return False
            return any(token in first for token in critical_tokens)

        critical_rules = [(sel, decl) for sel, decl in rules if is_critical_selector(sel)]
        total_rules = len(rules)
        critical_bytes = sum(len(sel) + len(decl) + 2 for sel, decl in critical_rules)
        critical_pct = (critical_bytes / (critical_bytes + external_bytes + inline_size) * 100) if (critical_bytes + external_bytes + inline_size) > 0 else 0

        has_font_display = "font-display" in combined
        async_css_pattern = ('media="print" onload' in str(soup)) or ("rel='preload' as='style'" in str(soup)) or ('rel="preload" as="style"' in str(soup))

        score = 0
        details = []
        if inline_size > 0:
            score += 1
            details.append("{} inline critical bytes".format(inline_size))
        if critical_rules:
            score += 1
            details.append("{} critical rules extracted".format(len(critical_rules)))
        if non_blocking_css > 0 or async_css_pattern:
            score += 2
            details.append("Deferred non-critical stylesheets detected")
        if has_font_display:
            score += 1
            details.append("font-display strategy present")
        if total_rules == 0 and inline_size == 0 and external_count > 0:
            details.append("No inline critical CSS - extract and inline above-the-fold rules")
        if critical_pct >= 15:
            details.append("Critical CSS ~{:.0f}% of analyzed payload".format(critical_pct))

        if score >= 3:
            status = "excellent"
        elif score >= 1:
            status = "good"
        else:
            status = "needs_improvement"

        value = "{} rules / {} bytes".format(len(critical_rules), critical_bytes)
        self.add_result("Critical CSS Extraction", value, status, "rendering",
                        "; ".join(details[:4]),
                        weight=3, effort=3)
        self.raw_metrics["critical_css_bytes"] = critical_bytes
        self.raw_metrics["critical_css_rules"] = len(critical_rules)
        self.raw_metrics["critical_css_pct"] = round(critical_pct, 1)
        self.raw_metrics["inline_css_size"] = inline_size

    # ─────────────────────────────────────────────
    # CHECK: JavaScript Tree Shaking Detection (v5 NEW)
    # ─────────────────────────────────────────────
    def check_js_tree_shaking(self, soup, html_content):
        self.log("bundles", "▸", "Detecting JavaScript tree shaking signals...")

        all_text = html_content
        inline_scripts = []
        for script in soup.find_all("script", src=False):
            text = script.string or ""
            inline_scripts.append(text)
            all_text += text

        module_scripts = [s for s in soup.find_all("script") if (s.get("type") or "").lower() == "module"]
        has_import_export = False
        for text in inline_scripts:
            if re.search(r"(?:^|\n)\s*import\s+[{'\"a-zA-Z]", text) or re.search(r"(?:^|\n)\s*export\s", text):
                has_import_export = True
                break
        if not has_import_export and re.search(r"\bimport\s*\(", all_text):
            has_import_export = True

        bundler_markers = []
        for marker in ("__webpack_require__", "webpackChunk", "webpackJsonp", "__vite__", "rollup", "parcelRequire", "System.register"):
            if marker in all_text:
                bundler_markers.append(marker)

        minified_inline = 0
        uncompressed_inline = 0
        for text in inline_scripts:
            if len(text) < 500:
                continue
            newlines = text.count("\n")
            if newlines < max(3, len(text) // 2000):
                minified_inline += 1
            else:
                uncompressed_inline += 1

        script_srcs = [s.get("src", "") for s in soup.find_all("script", src=True)]
        minified_src = sum(1 for src in script_srcs if ".min.js" in src or re.search(r"\.[a-f0-9]{8,}\.js", src))

        score = 0
        details = []
        if module_scripts:
            score += 2
            details.append("{} type=module scripts (tree-shakeable)".format(len(module_scripts)))
        if has_import_export:
            score += 1
            details.append("ES module import/export syntax found")
        if not bundler_markers:
            score += 1
            details.append("No legacy bundler runtime overhead")
        else:
            details.append("Bundler markers: " + ", ".join(bundler_markers[:3]))
        if minified_src > 0:
            score += 1
            details.append("{} minified/hashed bundles".format(minified_src))
        if minified_inline > 0:
            score += 1
            details.append("{} minified inline scripts".format(minified_inline))
        if uncompressed_inline > 0:
            score -= 1
            details.append("{} unminified inline scripts".format(uncompressed_inline))

        if score >= 4:
            status = "excellent"
        elif score >= 2:
            status = "good"
        elif score >= 0:
            status = "needs_improvement"
        else:
            status = "poor"

        value = "score {}/6".format(max(score, 0))
        self.add_result("JS Tree Shaking Signals", value, status, "bundles",
                        "; ".join(details[:4]),
                        weight=3, effort=3)
        self.raw_metrics["tree_shaking_signals"] = score
        self.raw_metrics["module_script_count"] = len(module_scripts)
        self.raw_metrics["bundler_markers"] = bundler_markers

    # ─────────────────────────────────────────────
    # CHECK: Code Splitting Detection (v5 NEW)
    # ─────────────────────────────────────────────
    def check_code_splitting(self, soup, html_content):
        self.log("bundles", "▸", "Detecting code splitting...")

        all_text = html_content
        for script in soup.find_all("script"):
            all_text += script.string or ""

        script_srcs = [s.get("src", "") for s in soup.find_all("script", src=True)]
        hashed_bundles = [src for src in script_srcs if re.search(r"\.[a-f0-9]{8,}\.(?:js|mjs)", src) or re.search(r"-[a-f0-9]{8,}\.js", src, re.I)]
        chunk_named = [src for src in script_srcs if any(k in src.lower() for k in ("chunk", "vendor", "runtime", "commons", "framework", "polyfills"))]
        dynamic_imports = len(re.findall(r"\bimport\s*\(", all_text))
        lazy_patterns = sum(all_text.count(p) for p in ("React.lazy", "next/dynamic", "loadable(", "lazy(() =>"))
        route_split_hints = sum(all_text.count(p) for p in ("createBrowserRouter", "useRoutes", "VueRouter", "RouterModule"))

        total_external = len(script_srcs)
        score = 0
        details = []
        if dynamic_imports > 0:
            score += 2
            details.append("{} dynamic import() calls".format(dynamic_imports))
        if lazy_patterns > 0:
            score += 2
            details.append("{} framework lazy-loading patterns".format(lazy_patterns))
        if len(hashed_bundles) >= 2:
            score += 1
            details.append("{} content-hashed bundles".format(len(hashed_bundles)))
        if chunk_named:
            score += 1
            details.append("Chunk-style names: " + ", ".join(c.split("/")[-1][:24] for c in chunk_named[:3]))
        if route_split_hints > 0:
            score += 1
            details.append("Router-level code splitting hints")
        if total_external <= 1 and dynamic_imports == 0:
            details.append("Single monolithic bundle - no code splitting detected")

        if score >= 4:
            status = "excellent"
        elif score >= 2:
            status = "good"
        elif score >= 1:
            status = "needs_improvement"
        else:
            status = "poor" if total_external <= 1 else "needs_improvement"

        value = "{} bundles, {} dynamic imports".format(total_external, dynamic_imports)
        self.add_result("Code Splitting", value, status, "bundles",
                        "; ".join(details[:4]) if details else "No splitting signals",
                        weight=3, effort=3)
        self.raw_metrics["code_splitting_score"] = score
        self.raw_metrics["dynamic_imports"] = dynamic_imports
        self.raw_metrics["hashed_bundle_count"] = len(hashed_bundles)

    # ─────────────────────────────────────────────
    # CHECK: Bundle Size Optimization (v5 NEW)
    # ─────────────────────────────────────────────
    def check_bundle_optimization(self, soup, base_url):
        self.log("bundles", "▸", "Analyzing bundle size optimization...")

        js_files = soup.find_all("script", src=True)
        sizes = []
        total_bytes = 0
        blocking_bytes = 0
        for script in js_files:
            src = script.get("src", "")
            if not src:
                continue
            size = 0
            try:
                resp = self.session.head(urljoin(base_url, src), timeout=5)
                size = int(resp.headers.get("Content-Length", 0))
            except Exception:
                pass
            is_blocking = not script.get("async") and not script.get("defer")
            sizes.append((src[:70], size, is_blocking))
            total_bytes += size
            if is_blocking:
                blocking_bytes += size

        sizes.sort(key=lambda x: -x[1])
        largest_name, largest_size, largest_blocking = sizes[0] if sizes else ("", 0, False)
        gzip_potential = int(total_bytes * 0.7)

        score = 0
        details = []
        if total_bytes > 0:
            details.append("Total JS {:,.0f}KB".format(total_bytes / 1024))
        if largest_size > 300_000:
            details.append("Largest bundle {:.0f}KB - split or defer it".format(largest_size / 1024))
            score -= 2
        elif largest_size > 150_000:
            details.append("Largest bundle {:.0f}KB".format(largest_size / 1024))
            score -= 1
        else:
            score += 1
        if blocking_bytes > 150_000:
            details.append("{:.0f}KB render-blocking JS".format(blocking_bytes / 1024))
            score -= 2
        elif blocking_bytes == 0:
            score += 2
            details.append("No render-blocking JS")
        if len(js_files) > 10:
            details.append("{} script requests (consider merging critical path)".format(len(js_files)))
            score -= 1
        if gzip_potential > 100_000:
            details.append("Gzip/Brotli could save ~{:.0f}KB if not compressed".format(gzip_potential / 1024))

        if score >= 2:
            status = "excellent"
        elif score >= 0:
            status = "good"
        elif score >= -2:
            status = "needs_improvement"
        else:
            status = "poor"

        value = "{} bundles / {:.0f}KB".format(len(sizes), total_bytes / 1024)
        self.add_result("Bundle Size Optimization", value, status, "bundles",
                        "; ".join(details[:4]),
                        weight=4, effort=3)
        self.raw_metrics["bundle_total_bytes"] = total_bytes
        self.raw_metrics["bundle_largest_bytes"] = largest_size
        self.raw_metrics["bundle_blocking_bytes"] = blocking_bytes
        self.raw_metrics["bundle_gzip_potential"] = gzip_potential

    # ─────────────────────────────────────────────
    # CHECK: Tree Shaking Effectiveness (v5 NEW)
    # ─────────────────────────────────────────────
    def check_tree_shaking_effectiveness(self, soup, html_content):
        self.log("bundles", "▸", "Estimating tree shaking effectiveness...")

        ts_signals = self.raw_metrics.get("tree_shaking_signals", 0)
        module_count = self.raw_metrics.get("module_script_count", 0)
        code_split_score = self.raw_metrics.get("code_splitting_score", 0)
        dead_pct = self.raw_metrics.get("dead_code_pct", 0)
        largest = self.raw_metrics.get("bundle_largest_bytes", 0)
        hashed = self.raw_metrics.get("hashed_bundle_count", 0)

        base = max(0, min(100, (ts_signals / 6) * 50))
        if module_count > 0:
            base += 15
        if code_split_score >= 2:
            base += 15
        elif code_split_score >= 1:
            base += 8
        if hashed >= 2:
            base += 10
        if dead_pct > 20:
            base -= 20
        elif dead_pct > 10:
            base -= 10
        if largest > 400_000:
            base -= 15
        elif largest > 250_000:
            base -= 8

        effectiveness = max(0, min(100, int(base)))

        if effectiveness >= 70:
            status = "excellent"
        elif effectiveness >= 50:
            status = "good"
        elif effectiveness >= 30:
            status = "needs_improvement"
        else:
            status = "poor"

        details = [
            "Tree-shaking signals: {}".format(ts_signals),
            "Module scripts: {}".format(module_count),
            "Code splitting score: {}".format(code_split_score),
            "Dead code: {}%".format(dead_pct),
        ]
        self.add_result("Tree Shaking Effectiveness", "{}%".format(effectiveness), status, "bundles",
                        "; ".join(details),
                        weight=3, effort=3)
        self.raw_metrics["tree_shaking_effectiveness"] = effectiveness

    # ─────────────────────────────────────────────
    # CHECK: Mobile vs Desktop Comparison (v5 NEW)
    # ─────────────────────────────────────────────
    def check_mobile_desktop_comparison(self):
        self.log("simulation", "▸", "Comparing mobile vs desktop performance...")

        conn = self.CONNECTION_PROFILES.get(self.connection, self.CONNECTION_PROFILES["wifi"])
        base_lcp = self.raw_metrics.get("lcp_ms", 2500)
        base_tti = self.raw_metrics.get("tti_ms", 3800)
        base_tbt = self.raw_metrics.get("tbt_ms", 200)
        base_si = self.raw_metrics.get("si_ms", 3400)

        comparison = {}
        for dev_key in ("mobile", "desktop"):
            dev = self.DEVICE_PROFILES[dev_key]
            cpu = conn["cpu_multiplier"] * dev["cpu_multiplier"]
            comparison[dev_key] = {
                "lcp_ms": int(base_lcp * conn["multiplier"] * dev["cpu_multiplier"]),
                "tti_ms": int(base_tti * conn["multiplier"] * dev["cpu_multiplier"]),
                "tbt_ms": int(base_tbt * dev["cpu_multiplier"]),
                "si_ms": int(base_si * conn["multiplier"] * (0.5 + dev["cpu_multiplier"] * 0.5)),
            }

        mobile_lcp = comparison["mobile"]["lcp_ms"]
        desktop_lcp = comparison["desktop"]["lcp_ms"]
        delta = mobile_lcp - desktop_lcp

        issues = []
        if mobile_lcp > 4000:
            issues.append("Mobile LCP {}ms is poor".format(mobile_lcp))
        elif mobile_lcp > 2500:
            issues.append("Mobile LCP {}ms needs improvement".format(mobile_lcp))
        if comparison["mobile"]["tti_ms"] > 7300:
            issues.append("Mobile TTI {}ms is poor".format(comparison["mobile"]["tti_ms"]))

        if not issues and mobile_lcp <= 2500:
            status = "excellent"
        elif mobile_lcp <= 4000:
            status = "needs_improvement"
        else:
            status = "poor"

        detail = "Mobile LCP {}ms vs Desktop LCP {}ms (delta +{}ms) on {}".format(
            mobile_lcp, desktop_lcp, delta, conn["label"])
        if issues:
            detail += " | " + "; ".join(issues[:2])

        self.add_result("Mobile vs Desktop", "Mobile {}ms / Desktop {}ms".format(mobile_lcp, desktop_lcp),
                        status, "simulation", detail,
                        weight=3, effort=2)
        self.raw_metrics["mobile_desktop_comparison"] = comparison
        self.raw_metrics["mobile_desktop_delta_ms"] = delta

    # ─────────────────────────────────────────────
    # CHECK: Lighthouse Score Simulation (v5 NEW)
    # ─────────────────────────────────────────────
    def _metric_lighthouse_subscore(self, value, good, poor):
        try:
            value = float(value)
        except (TypeError, ValueError):
            return None
        if value <= 0:
            return 100
        if value <= good:
            return 100 - (value / good) * 10
        if value <= poor:
            return 90 - ((value - good) / (poor - good)) * 40
        limit = poor * 3
        if value >= limit:
            return 0
        return 50 * (1 - (value - poor) / (limit - poor))

    def check_lighthouse_simulation(self):
        self.log("simulation", "▸", "Simulating Lighthouse performance score (v7 refined)...")

        thresholds = {
            "fcp_ms": (1800, 3000),
            "si_ms": (3400, 5800),
            "lcp_ms": (2500, 4000),
            "tbt_ms": (200, 600),
            "cls_score": (0.1, 0.25),
            "inp_score": (200, 500),
            "tti_ms": (3800, 7300),
            "ttfb_ms": (800, 1800),
        }

        weighted = 0.0
        weight_sum = 0
        parts = {}
        for key, weight in self.LIGHTHOUSE_WEIGHTS.items():
            raw_value = self.raw_metrics.get(key)
            if raw_value is None:
                continue
            good, poor = thresholds[key]
            subscore = self._metric_lighthouse_subscore(raw_value, good, poor)
            if subscore is None:
                continue
            parts[key] = round(subscore, 1)
            weighted += subscore * weight
            weight_sum += weight

        base_score = weighted / weight_sum if weight_sum else 0

        # v6/v7: multiplicative efficiency factor for modern loading/rendering strategy
        efficiency = 1.0
        efficiency_notes = []
        non_blocking = self.raw_metrics.get("non_blocking_script_ratio", None)
        if non_blocking is not None and non_blocking >= 80:
            efficiency += 0.02
            efficiency_notes.append("non-blocking scripts +2%")
        rb = self.raw_metrics.get("render_blocking_resources", 0)
        if rb == 0:
            efficiency += 0.02
            efficiency_notes.append("zero render-blocking +2%")
        modern_img = self.raw_metrics.get("img_modern_formats", 0)
        img_count = self.raw_metrics.get("img_count", 0)
        if img_count > 0 and modern_img / max(img_count, 1) >= 0.5:
            efficiency += 0.02
            efficiency_notes.append("modern image formats +2%")
        if self.raw_metrics.get("compression", "none") == "br":
            efficiency += 0.01
            efficiency_notes.append("brotli +1%")
        # v7: modern rendering technique bonuses
        if self.raw_metrics.get("content_visibility_count", 0) > 0:
            efficiency += 0.015
            efficiency_notes.append("content-visibility +1.5%")
        if self.raw_metrics.get("scroll_driven_animations", False):
            efficiency += 0.015
            efficiency_notes.append("scroll-driven animations +1.5%")
        if self.raw_metrics.get("adaptive_image_coverage", 0) >= 50:
            efficiency += 0.015
            efficiency_notes.append("adaptive images +1.5%")
        if self.raw_metrics.get("contain_property_count", 0) > 0:
            efficiency += 0.01
            efficiency_notes.append("CSS contain +1%")
        efficiency = min(efficiency, 1.10)
        base_score *= efficiency

        penalty = 0
        penalty_notes = []
        if self.raw_metrics.get("third_party_blocking", 0) > 3:
            penalty += 5
            penalty_notes.append("blocking third-party (-5)")
        if self.raw_metrics.get("render_blocking_resources", 0) > 2:
            penalty += 5
            penalty_notes.append("render-blocking (-5)")
        if self.raw_metrics.get("compression", "none") == "none":
            penalty += 5
            penalty_notes.append("no compression (-5)")
        if not self.raw_metrics.get("has_viewport", True):
            penalty += 5
            penalty_notes.append("no viewport (-5)")
        if self.raw_metrics.get("redirect_hops", 0) > 2:
            penalty += 3
            penalty_notes.append("redirects (-3)")
        page_size = self.raw_metrics.get("total_page_size", 0)
        if page_size > 3_000_000:
            penalty += 4
            penalty_notes.append("page >3MB (-4)")
        elif page_size > 1_600_000:
            penalty += 2
            penalty_notes.append("page >1.6MB (-2)")
        if self.raw_metrics.get("duplicate_resources", 0) > 2:
            penalty += 2
            penalty_notes.append("duplicate resources (-2)")
        if img_count > 5 and self.raw_metrics.get("img_lazy_loaded", 0) == 0:
            penalty += 2
            penalty_notes.append("no lazy-loaded images (-2)")
        if self.raw_metrics.get("layout_animation_props", 0) > 2:
            penalty += 2
            penalty_notes.append("layout-property animations (-2)")
        if self.raw_metrics.get("lcp_is_lazy", False):
            penalty += 3
            penalty_notes.append("LCP candidate lazy-loaded (-3)")
        sim_lcp = self.raw_metrics.get("simulated_lcp", 0)
        if sim_lcp > 4000:
            penalty += 4
            penalty_notes.append("simulated mobile LCP poor (-4)")
        if self.raw_metrics.get("backdrop_filter_count", 0) > 4:
            penalty += 2
            penalty_notes.append("heavy backdrop-filter (-2)")
        if self.raw_metrics.get("will_change_count", 0) > 6:
            penalty += 2
            penalty_notes.append("will-change overuse (-2)")
        if self.raw_metrics.get("will_change_auto", 0) > 0:
            penalty += 2
            penalty_notes.append("will-change:auto (-2)")

        final_score = max(0.0, min(100.0, base_score - penalty))

        if final_score >= 90:
            status = "excellent"
        elif final_score >= 50:
            status = "good"
        elif final_score >= 25:
            status = "needs_improvement"
        else:
            status = "poor"

        detail = "Weighted metric subscores; efficiency {}x {}; penalty -{}: {}".format(
            "{:.2f}".format(efficiency),
            "(" + ", ".join(efficiency_notes) + ")" if efficiency_notes else "(neutral)",
            penalty, ", ".join(penalty_notes) if penalty_notes else "none")
        self.add_result("Lighthouse Score (simulated)", "{:.0f}/100".format(final_score), status, "simulation",
                        detail, weight=5, effort=3)
        self.raw_metrics["lighthouse_score"] = round(final_score, 1)
        self.raw_metrics["lighthouse_subscores"] = parts
        self.raw_metrics["lighthouse_penalty"] = penalty
        self.raw_metrics["lighthouse_efficiency"] = round(efficiency, 3)

    # ─────────────────────────────────────────────
    # CHECK: PageSpeed Insights Approximation (v5 NEW)
    # ─────────────────────────────────────────────
    def check_pagespeed_approximation(self):
        self.log("simulation", "▸", "Approximating PageSpeed Insights score (v7 refined)...")

        psi = float(self.raw_metrics.get("lighthouse_score", 0))
        adjustments = []

        if not self.raw_metrics.get("has_viewport", True):
            psi -= 10
            adjustments.append("no viewport: -10")
        http_version = str(self.raw_metrics.get("http_version", ""))
        if http_version.startswith("HTTP/1"):
            psi -= 3
            adjustments.append("HTTP/1.x: -3")
        page_size = self.raw_metrics.get("total_page_size", 0)
        if page_size > 3_000_000:
            psi -= 8
            adjustments.append("page >3MB: -8")
        elif page_size > 1_600_000:
            psi -= 4
            adjustments.append("page >1.6MB: -4")
        if self.raw_metrics.get("duplicate_resources", 0) > 2:
            psi -= 3
            adjustments.append("duplicate resources: -3")
        if self.raw_metrics.get("third_party_blocking", 0) > 3:
            psi -= 4
            adjustments.append("blocking third-party scripts: -4")
        if self.raw_metrics.get("redirect_hops", 0) > 2:
            psi -= 3
            adjustments.append("redirect chain: -3")
        sim_lcp = self.raw_metrics.get("simulated_lcp", 0)
        if sim_lcp > 4000:
            psi -= 6
            adjustments.append("field-like mobile LCP poor: -6")
        elif sim_lcp > 2500:
            psi -= 2
            adjustments.append("field-like mobile LCP avg: -2")
        budget_issues = self.raw_metrics.get("budget_issues", 0)
        if budget_issues == 0:
            psi += 3
            adjustments.append("all budgets met: +3")
        elif budget_issues > 4:
            psi -= 3
            adjustments.append("{} budgets over: -3".format(budget_issues))

        if self.raw_metrics.get("service_worker", False):
            psi += 2
            adjustments.append("service worker: +2")
        if self.raw_metrics.get("http3_support", False):
            psi += 2
            adjustments.append("HTTP/3: +2")
        if self.raw_metrics.get("rum_detected", False):
            psi += 2
            adjustments.append("RUM instrumentation: +2")
        if self.raw_metrics.get("web_vitals_library", False):
            psi += 1
            adjustments.append("web-vitals library: +1")
        if self.raw_metrics.get("speculation_rules", False):
            psi += 1
            adjustments.append("speculation rules: +1")
        if self.raw_metrics.get("performance_observer", False):
            psi += 1
            adjustments.append("PerformanceObserver: +1")
        # v7: modern rendering / loading signal adjustments
        if self.raw_metrics.get("content_visibility_count", 0) > 0:
            psi += 1
            adjustments.append("content-visibility: +1")
        if self.raw_metrics.get("scroll_driven_animations", False):
            psi += 1
            adjustments.append("scroll-driven animations: +1")
        if self.raw_metrics.get("adaptive_image_coverage", 0) >= 50:
            psi += 2
            adjustments.append("adaptive images: +2")
        if self.raw_metrics.get("contain_property_count", 0) > 0:
            psi += 1
            adjustments.append("CSS contain: +1")
        if self.raw_metrics.get("backdrop_filter_count", 0) > 4:
            psi -= 2
            adjustments.append("heavy backdrop-filter: -2")
        if self.raw_metrics.get("will_change_count", 0) > 6:
            psi -= 1
            adjustments.append("will-change overuse: -1")

        psi = max(0.0, min(100.0, psi))

        if psi >= 90:
            status = "excellent"
        elif psi >= 50:
            status = "good"
        elif psi >= 25:
            status = "needs_improvement"
        else:
            status = "poor"

        detail = "Lighthouse base + lab/structure/field-signal adjustments"
        if adjustments:
            detail += ": " + ", ".join(adjustments)
        self.add_result("PageSpeed Insights (approx.)", "{:.0f}/100".format(psi), status, "simulation",
                        detail, weight=4, effort=3)
        self.raw_metrics["psi_score"] = round(psi, 1)
        self.raw_metrics["psi_adjustments"] = adjustments

    # ─────────────────────────────────────────────
    # SCORING & GRADES (v7 refined)
    # ─────────────────────────────────────────────
    def calculate_score(self):
        category_scores = {}
        for category, weight in self.SCORING_WEIGHTS.items():
            cat_results = [r for r in self.results if r.category == category]
            if not cat_results:
                category_scores[category] = 50
                continue
            score_map = {"excellent": 100, "good": 84, "needs_improvement": 55, "poor": 12}
            weighted_sum = 0
            weight_total = 0
            for r in cat_results:
                w = r.weight if r.weight else 1
                weighted_sum += score_map.get(r.status, 50) * w
                weight_total += w
            cat_score = weighted_sum / weight_total if weight_total > 0 else 50
            category_scores[category] = cat_score

        base_total = sum(
            category_scores[cat] * (weight / 100)
            for cat, weight in self.SCORING_WEIGHTS.items()
        )

        # v6/v7: global refinements from budgets, compliance, vitals, and modern rendering
        adjustments = []
        total_score = base_total
        if "budget_issues" in self.raw_metrics:
            budget_issues = self.raw_metrics.get("budget_issues", 0)
            if budget_issues == 0:
                total_score += 2.0
                adjustments.append("all performance budgets met: +2.0")
            elif budget_issues > 4:
                total_score -= 3.0
                adjustments.append("{} budgets over threshold: -3.0".format(budget_issues))
        if self.strict_budget:
            violations = self.raw_metrics.get("strict_budget_violations", 0)
            if violations > 0:
                total_score -= 2.0
                adjustments.append("{} strict budget violations: -2.0".format(violations))
        cwv_failing = 0
        for key in ("lcp_ms", "fcp_ms", "cls_score", "inp_score", "ttfb_ms"):
            actual = self.raw_metrics.get(key)
            thresholds = self.CORE_WEB_VITALS.get(key)
            if actual is not None and thresholds and actual > thresholds["poor"]:
                cwv_failing += 1
        if cwv_failing >= 2:
            total_score -= 3.0
            adjustments.append("{} Core Web Vitals in poor range: -3.0".format(cwv_failing))
        elif cwv_failing == 1:
            total_score -= 1.5
            adjustments.append("1 Core Web Vital in poor range: -1.5")
        coverage = len(self.results)
        if coverage >= 55:
            total_score += 1.0
            adjustments.append("deep check coverage ({} checks): +1.0".format(coverage))
        # v7: modern rendering technique refinements
        if self.raw_metrics.get("content_visibility_count", 0) > 0:
            total_score += 1.0
            adjustments.append("content-visibility in use: +1.0")
        if self.raw_metrics.get("scroll_driven_animations", False):
            total_score += 1.0
            adjustments.append("scroll-driven animations: +1.0")
        if self.raw_metrics.get("adaptive_image_coverage", 0) >= 50:
            total_score += 1.0
            adjustments.append("adaptive image coverage >=50%: +1.0")
        if self.raw_metrics.get("contain_property_count", 0) > 0:
            total_score += 0.5
            adjustments.append("CSS contain in use: +0.5")
        if self.raw_metrics.get("backdrop_filter_count", 0) > 4:
            total_score -= 1.5
            adjustments.append("heavy backdrop-filter usage: -1.5")
        if self.raw_metrics.get("will_change_count", 0) > 6:
            total_score -= 1.0
            adjustments.append("will-change overuse: -1.0")
        if self.raw_metrics.get("will_change_auto", 0) > 0:
            total_score -= 1.0
            adjustments.append("will-change:auto detected: -1.0")

        total_score = max(0.0, min(100.0, total_score))
        self.raw_metrics["score_base"] = round(base_total, 2)
        self.raw_metrics["score_adjustments"] = adjustments
        return total_score, category_scores

    # ─────────────────────────────────────────────
    # SCORING: User Experience Score (v7 refined)
    # ─────────────────────────────────────────────
    def calculate_ux_score(self):
        score = 100.0
        deductions = []

        cls = self.raw_metrics.get("cls_score")
        if cls is not None:
            if cls > 0.25:
                score -= 30
                deductions.append("CLS {:.2f} (poor): -30".format(cls))
            elif cls > 0.1:
                score -= 15
                deductions.append("CLS {:.2f} (needs improvement): -15".format(cls))

        inp = self.raw_metrics.get("inp_score")
        if inp is not None:
            if inp > 500:
                score -= 25
                deductions.append("INP {}ms (poor): -25".format(inp))
            elif inp > 200:
                score -= 12
                deductions.append("INP {}ms (needs improvement): -12".format(inp))

        if not self.raw_metrics.get("has_viewport", True):
            score -= 15
            deductions.append("missing viewport meta: -15")

        layout_shift = self.raw_metrics.get("layout_shift_score", 0)
        if layout_shift > 0.25:
            score -= 10
            deductions.append("layout shift score {:.2f}: -10".format(layout_shift))
        elif layout_shift > 0.1:
            score -= 5
            deductions.append("layout shift score {:.2f}: -5".format(layout_shift))

        font_result = next((r for r in self.results if r.name == "Mobile Font Size"), None)
        if font_result and font_result.status == "poor":
            score -= 8
            deductions.append("mobile font size too small: -8")

        sim_lcp = self.raw_metrics.get("simulated_lcp", 0)
        if sim_lcp > 4000:
            score -= 12
            deductions.append("simulated mobile LCP poor: -12")
        elif sim_lcp > 2500:
            score -= 6
            deductions.append("simulated mobile LCP average: -6")

        if self.raw_metrics.get("img_count", 0) > 0:
            lazy_pct = self.raw_metrics.get("lazy_loading_coverage", 0)
            if lazy_pct < 30:
                score -= 5
                deductions.append("low lazy-loading coverage: -5")

        if self.raw_metrics.get("third_party_blocking", 0) > 3:
            score -= 6
            deductions.append("blocking third-party scripts: -6")

        if self.raw_metrics.get("render_blocking_resources", 0) > 2:
            score -= 6
            deductions.append("render-blocking resources: -6")

        if self.raw_metrics.get("memory_estimated_kb", 0) > 15000:
            score -= 5
            deductions.append("high estimated DOM memory: -5")

        # v7: rendering/jank refinements
        long_tasks = self.raw_metrics.get("long_task_count", 0)
        if long_tasks > 3:
            score -= 4
            deductions.append("{} potential long tasks: -4".format(long_tasks))
        backdrop_count = self.raw_metrics.get("backdrop_filter_count", 0)
        if backdrop_count > 4:
            score -= 4
            deductions.append("{} backdrop-filter surfaces (scroll jank risk): -4".format(backdrop_count))
        will_change_count = self.raw_metrics.get("will_change_count", 0)
        if will_change_count > 6:
            score -= 3
            deductions.append("{} will-change declarations (GPU pressure): -3".format(will_change_count))
        if self.raw_metrics.get("will_change_auto", 0) > 0:
            score -= 3
            deductions.append("will-change:auto keeps layers alive: -3")
        if self.raw_metrics.get("content_visibility_count", 0) > 0:
            score += 2
        if self.raw_metrics.get("scroll_driven_animations", False):
            score += 2
        if self.raw_metrics.get("adaptive_image_coverage", 0) >= 50:
            score += 2

        score = max(0.0, min(100.0, score))
        if score >= 90:
            status = "excellent"
        elif score >= 75:
            status = "good"
        elif score >= 50:
            status = "needs_improvement"
        else:
            status = "poor"

        value = "{:.0f}/100".format(score)
        detail = "; ".join(deductions[:5]) if deductions else "No UX detractors detected"
        self.add_result("User Experience Score", value, status, "vitals", detail,
                        weight=5, effort=3)
        self.raw_metrics["ux_score"] = round(score, 1)
        self.raw_metrics["ux_deductions"] = deductions
        return score, status

    def get_grade(self, score):
        if score >= 90:
            return "A+", Colors.GREEN
        elif score >= 80:
            return "A", Colors.GREEN
        elif score >= 70:
            return "B", Colors.YELLOW
        elif score >= 60:
            return "C", Colors.YELLOW
        elif score >= 50:
            return "D", Colors.RED
        else:
            return "F", Colors.RED

    def get_status_color(self, status):
        return {
            "excellent": Colors.GREEN,
            "good": Colors.GREEN,
            "needs_improvement": Colors.YELLOW,
            "poor": Colors.RED,
        }.get(status, Colors.WHITE)

    def _budget_compliance_grade(self, weighted_pct):
        if weighted_pct >= 95:
            return "A"
        elif weighted_pct >= 85:
            return "B"
        elif weighted_pct >= 70:
            return "C"
        elif weighted_pct >= 50:
            return "D"
        return "F"

    def check_performance_budgets(self):
        self.log("timing", "▸", "Checking performance budgets (v7 refined)...")
        budget_issues = []
        passes = warns = fails = evaluated = 0
        for metric, budget in self.PERFORMANCE_BUDGETS.items():
            actual = self.raw_metrics.get(metric)
            if actual is None:
                continue
            evaluated += 1
            if actual <= budget:
                passes += 1
            elif actual <= budget * 1.5:
                warns += 1
                budget_issues.append((metric, actual, budget, (actual - budget) / budget * 100))
            else:
                fails += 1
                budget_issues.append((metric, actual, budget, (actual - budget) / budget * 100))
        compliance_pct = (passes / evaluated * 100) if evaluated else 0.0
        weighted_compliance = ((passes + warns * 0.5) / evaluated * 100) if evaluated else 0.0
        self.raw_metrics["budget_compliance_pct"] = round(compliance_pct, 1)
        self.raw_metrics["budget_weighted_compliance_pct"] = round(weighted_compliance, 1)
        self.raw_metrics["budget_compliance_grade"] = self._budget_compliance_grade(weighted_compliance)
        self.raw_metrics["budget_pass"] = passes
        self.raw_metrics["budget_warn"] = warns
        self.raw_metrics["budget_fail"] = fails
        self.raw_metrics["budget_evaluated"] = evaluated
        if budget_issues:
            if fails == 0:
                budget_status = "good"
            elif fails == 1:
                budget_status = "needs_improvement"
            else:
                budget_status = "poor"
            detail_parts = ["{}: {}/{} (+{:.0f}%)".format(m, a, b, p) for m, a, b, p in budget_issues[:5]]
            detail_parts.append("compliance {:.0f}% grade {} ({} pass / {} warn / {} fail)".format(
                compliance_pct, self._budget_compliance_grade(weighted_compliance), passes, warns, fails))
            self.add_result("Performance Budget", "{}/{} over budget".format(len(budget_issues), evaluated), budget_status, "timing",
                            "; ".join(detail_parts),
                            weight=3, effort=3)
        else:
            self.add_result("Performance Budget", "All within budget", "excellent", "timing",
                            "All {} evaluated metrics within budget ({:.0f}% compliance)".format(evaluated, compliance_pct),
                            weight=3, effort=3)
        self.raw_metrics["budget_issues"] = len(budget_issues)

    # ─────────────────────────────────────────────
    # CHECK: Performance Budget Strict Mode (v5 NEW)
    # ─────────────────────────────────────────────
    def check_performance_budgets_strict(self):
        if not self.strict_budget:
            return
        self.log("timing", "▸", "Enforcing STRICT performance budgets...")
        violations = []
        for metric, budget in self.STRICT_PERFORMANCE_BUDGETS.items():
            actual = self.raw_metrics.get(metric)
            if actual is None:
                continue
            if actual > budget:
                over = actual - budget
                pct_over = (over / budget) * 100
                violations.append((metric, actual, budget, pct_over))
        if violations:
            detail_parts = ["{}: {}/{} (+{:.0f}%)".format(m, a, b, p) for m, a, b, p in violations[:5]]
            self.add_result("Strict Budget", "{} violations".format(len(violations)), "poor", "timing",
                            "; ".join(detail_parts),
                            weight=4, effort=3)
        else:
            self.add_result("Strict Budget", "All strict budgets met", "excellent", "timing",
                            "All metrics within strict performance budget thresholds",
                            weight=4, effort=3)
        self.raw_metrics["strict_budget_violations"] = len(violations)

    # ─────────────────────────────────────────────
    # OUTPUT: Performance Budget Dashboard (v7 refined + compliance grade)
    # ─────────────────────────────────────────────
    def print_budget_dashboard(self):
        print(f"\n  {Colors.BOLD}{Colors.YELLOW}PERFORMANCE BUDGET DASHBOARD{Colors.RESET}")
        print(f"  {'─'*72}")
        print(f"  {'Metric':22s} {'Actual':>12s} {'Budget':>12s} {'Status':>10s} {'Delta':>10s}")
        print(f"  {'─'*72}")

        budget_display = {
            "ttfb_ms": ("TTFB", "ms"), "lcp_ms": ("LCP", "ms"), "fcp_ms": ("FCP", "ms"),
            "si_ms": ("Speed Index", "ms"), "tti_ms": ("TTI", "ms"), "tbt_ms": ("TBT", "ms"),
            "inp_score": ("INP", "ms"),
            "cls_score": ("CLS", "score"), "total_page_size": ("Page Size", "bytes"),
            "total_resources": ("Resources", "count"), "dom_parse_ms": ("DOM Parse", "ms"),
            "js_size": ("JS Size", "bytes"), "css_size": ("CSS Size", "bytes"),
            "img_size": ("Image Size", "bytes"), "font_size": ("Font Size", "bytes"),
            "render_blocking_resources": ("Render-blocking", "count"),
            "render_blocking_size": ("Blocking Size", "bytes"),
            "js_exec_time_ms": ("JS Exec Time", "ms"),
            "third_party_domains": ("Third-party Dom.", "count"),
            "dom_elements": ("DOM Elements", "count"),
            "duplicate_resources": ("Duplicates", "count"),
            "long_task_count": ("Long Tasks", "count"),
            "main_thread_blocking_score": ("Thread Blocking", "count"),
            "memory_estimated_kb": ("Memory Est.", "kb"),
            "layout_shift_score": ("Layout Shift", "score"),
        }

        passes = warns = fails = evaluated = 0
        compliance_rows = []

        for metric, budget in self.PERFORMANCE_BUDGETS.items():
            actual = self.raw_metrics.get(metric)
            if actual is None:
                continue
            evaluated += 1
            display_name, unit = budget_display.get(metric, (metric, ""))
            if unit == "bytes":
                actual_str = "{:.1f}KB".format(actual / 1024)
                budget_str = "{:.1f}KB".format(budget / 1024)
                delta_str = "{:+.1f}KB".format((actual - budget) / 1024)
            elif unit == "kb":
                actual_str = "{:.0f}KB".format(actual)
                budget_str = "{:.0f}KB".format(budget)
                delta_str = "{:+.0f}KB".format(actual - budget)
            elif unit == "score":
                actual_str = "{:.3f}".format(actual)
                budget_str = "{:.3f}".format(budget)
                delta_str = "{:+.3f}".format(actual - budget)
            elif unit == "count":
                actual_str = "{}".format(actual)
                budget_str = "{}".format(budget)
                delta_str = "{:+d}".format(int(actual - budget))
            else:
                actual_str = "{}ms".format(actual)
                budget_str = "{}ms".format(budget)
                delta_str = "{:+.0f}ms".format(actual - budget)
            if actual <= budget:
                status_str = f"{Colors.GREEN}PASS{Colors.RESET}"
                color = Colors.GREEN
                passes += 1
                compliance_rows.append((display_name, "PASS"))
            elif actual <= budget * 1.5:
                status_str = f"{Colors.YELLOW}WARN{Colors.RESET}"
                color = Colors.YELLOW
                warns += 1
                compliance_rows.append((display_name, "WARN"))
            else:
                status_str = f"{Colors.RED}FAIL{Colors.RESET}"
                color = Colors.RED
                fails += 1
                compliance_rows.append((display_name, "FAIL"))
            print(f"  {display_name:22s} {color}{actual_str:>12s}{Colors.RESET} {budget_str:>12s} {status_str:>21s} {color}{delta_str:>10s}{Colors.RESET}")

        compliance_pct = (passes / evaluated * 100) if evaluated else 0.0
        weighted_compliance = ((passes + warns * 0.5) / evaluated * 100) if evaluated else 0.0
        self.raw_metrics["budget_compliance_pct"] = round(compliance_pct, 1)
        self.raw_metrics["budget_weighted_compliance_pct"] = round(weighted_compliance, 1)
        self.raw_metrics["budget_pass"] = passes
        self.raw_metrics["budget_warn"] = warns
        self.raw_metrics["budget_fail"] = fails
        self.raw_metrics["budget_evaluated"] = evaluated

        print(f"\n  {Colors.BOLD}BUDGET COMPLIANCE SUMMARY{Colors.RESET}")
        print(f"  {'─'*72}")
        bar_len = 40
        pass_bar_len = int((passes / evaluated * bar_len)) if evaluated else 0
        warn_bar_len = int((warns / evaluated * bar_len)) if evaluated else 0
        fail_bar_len = max(0, bar_len - pass_bar_len - warn_bar_len) if evaluated else 0
        bar = (f"{Colors.GREEN}{'█' * pass_bar_len}"
               f"{Colors.YELLOW}{'█' * warn_bar_len}"
               f"{Colors.RED}{'█' * fail_bar_len}{Colors.RESET}")
        print(f"  Compliance: {bar} {compliance_pct:.0f}% strict pass")
        print(f"  {Colors.GREEN}PASS {passes}{Colors.RESET} · {Colors.YELLOW}WARN {warns}{Colors.RESET} · {Colors.RED}FAIL {fails}{Colors.RESET} · evaluated {evaluated}/{len(self.PERFORMANCE_BUDGETS)} budgets")
        print(f"  Weighted compliance (WARN=50%): {weighted_compliance:.0f}%")
        compliance_grade = self._budget_compliance_grade(weighted_compliance)
        grade_color = Colors.GREEN if compliance_grade in ("A", "B") else Colors.YELLOW if compliance_grade in ("C", "D") else Colors.RED
        print(f"  Compliance grade: {grade_color}{Colors.BOLD}{compliance_grade}{Colors.RESET}"
              f"  {Colors.DIM}({'excellent' if compliance_grade == 'A' else 'good' if compliance_grade == 'B' else 'acceptable' if compliance_grade == 'C' else 'weak' if compliance_grade == 'D' else 'critical'}){Colors.RESET}")
        self.raw_metrics["budget_compliance_grade"] = compliance_grade
        if fails == 0 and warns == 0:
            print(f"  {Colors.GREEN}{Colors.BOLD}All evaluated budgets are met.{Colors.RESET}")
        elif fails > 0:
            failing_names = [n for n, s in compliance_rows if s == "FAIL"]
            print(f"  {Colors.RED}{Colors.BOLD}Over budget: {', '.join(failing_names[:6])}{Colors.RESET}")

    # ─────────────────────────────────────────────
    # OUTPUT: Performance Dashboard (v7 refined)
    # ─────────────────────────────────────────────
    def print_performance_dashboard(self):
        print(f"\n  {Colors.BOLD}{Colors.CYAN}PERFORMANCE DASHBOARD{Colors.RESET}")
        print(f"  {'─'*72}")

        score, _ = self.calculate_score()
        lighthouse = self.raw_metrics.get("lighthouse_score")
        psi = self.raw_metrics.get("psi_score")
        ux = self.raw_metrics.get("ux_score")
        compliance = self.raw_metrics.get("budget_compliance_pct")

        tiles = []
        tiles.append(("Score", "{:.0f}/100".format(score), score))
        if lighthouse is not None:
            tiles.append(("Lighthouse", "{:.0f}/100".format(lighthouse), lighthouse))
        if psi is not None:
            tiles.append(("PageSpeed", "{:.0f}/100".format(psi), psi))
        if ux is not None:
            tiles.append(("UX Score", "{:.0f}/100".format(ux), ux))
        if compliance is not None:
            tiles.append(("Budgets", "{:.0f}%".format(compliance), compliance))

        for label, value, numeric in tiles:
            color = Colors.GREEN if numeric >= 80 else Colors.YELLOW if numeric >= 50 else Colors.RED
            bar_len = int(numeric / 100 * 24)
            bar = "█" * bar_len + "░" * (24 - bar_len)
            print(f"  {label:12s} {color}{bar}{Colors.RESET} {color}{Colors.BOLD}{value:>10s}{Colors.RESET}")

        # v7: modern rendering signal strip
        cv_n = self.raw_metrics.get("content_visibility_count", 0)
        contain_n = self.raw_metrics.get("contain_property_count", 0)
        wc_n = self.raw_metrics.get("will_change_count", 0)
        bd_n = self.raw_metrics.get("backdrop_filter_count", 0)
        sda_flag = "yes" if self.raw_metrics.get("scroll_driven_animations") else "no"
        adapt_pct = self.raw_metrics.get("adaptive_image_coverage", 0)
        signal_parts = [
            "cv:{}".format(cv_n),
            "contain:{}".format(contain_n),
            "will-change:{}".format(wc_n),
            "backdrop:{}".format(bd_n),
            "scroll-anim:{}".format(sda_flag),
            "adaptive:{:.0f}%".format(adapt_pct),
        ]
        print(f"  {'Signals':12s} {Colors.DIM}{' '.join(signal_parts)}{Colors.RESET}")

        weighted_compliance = self.raw_metrics.get("budget_weighted_compliance_pct")
        if weighted_compliance is not None:
            budget_grade = self._budget_compliance_grade(weighted_compliance)
            bg_color = Colors.GREEN if budget_grade in ("A", "B") else Colors.YELLOW if budget_grade in ("C", "D") else Colors.RED
            print(f"  {'Budget grade':12s} {bg_color}{Colors.BOLD}{budget_grade}{Colors.RESET}"
                  f" {Colors.DIM}(weighted {weighted_compliance:.0f}%){Colors.RESET}")

        cwv_pass = cwv_avg = cwv_fail = 0
        for key in ("lcp_ms", "fcp_ms", "cls_score", "inp_score", "ttfb_ms", "si_ms", "tbt_ms"):
            actual = self.raw_metrics.get(key)
            thresholds = self.CORE_WEB_VITALS.get(key)
            if actual is None or thresholds is None:
                continue
            if actual <= thresholds["good"]:
                cwv_pass += 1
            elif actual <= thresholds["poor"]:
                cwv_avg += 1
            else:
                cwv_fail += 1
        cwv_total = cwv_pass + cwv_avg + cwv_fail
        if cwv_total:
            cwv_pct = cwv_pass / cwv_total * 100
            cwv_color = Colors.GREEN if cwv_fail == 0 else Colors.RED
            print(f"\n  {'Core Vitals':12s} {cwv_color}{cwv_pass}/{cwv_total} pass ({cwv_pct:.0f}%){Colors.RESET}"
                  f"  avg {cwv_avg} · fail {cwv_fail}")

        grade, grade_color = self.get_grade(score)
        print(f"  {'Grade':12s} {grade_color}{Colors.BOLD}{grade}{Colors.RESET}"
              f"  {Colors.DIM}checks: {len(self.results)} · device: {self.device} · connection: {self.connection}{Colors.RESET}")

    # ─────────────────────────────────────────────
    # OUTPUT: User Experience Score (v6 NEW)
    # ─────────────────────────────────────────────
    def print_user_experience_score(self):
        ux = self.raw_metrics.get("ux_score")
        if ux is None:
            return
        print(f"\n  {Colors.BOLD}{Colors.MAGENTA}USER EXPERIENCE SCORE{Colors.RESET}")
        print(f"  {'─'*72}")
        bar_len = int(ux / 100 * 30)
        bar = "█" * bar_len + "░" * (30 - bar_len)
        color = Colors.GREEN if ux >= 90 else Colors.YELLOW if ux >= 50 else Colors.RED
        print(f"  Score: {color}{bar}{Colors.RESET} {Colors.BOLD}{ux:.0f}/100{Colors.RESET}")
        if ux >= 90:
            label = "Delightful - stability and responsiveness are strong"
        elif ux >= 75:
            label = "Good - minor friction under real-world conditions"
        elif ux >= 50:
            label = "Needs improvement - noticeable UX friction"
        else:
            label = "Poor - users likely hitting jank, shifts, or slow input"
        print(f"  Zone:  {color}{label}{Colors.RESET}")

        deductions = self.raw_metrics.get("ux_deductions", [])
        if deductions:
            print(f"\n  {Colors.YELLOW}Detractors:{Colors.RESET}")
            for d in deductions[:6]:
                print(f"    {Colors.YELLOW}· {d}{Colors.RESET}")
        else:
            print(f"  {Colors.GREEN}No UX detractors detected.{Colors.RESET}")

    # ─────────────────────────────────────────────
    # OUTPUT: CWV Compliance Report (v4 NEW)
    # ─────────────────────────────────────────────
    def print_cwv_compliance_report(self):
        print(f"\n  {Colors.BOLD}{Colors.MAGENTA}CORE WEB VITALS COMPLIANCE REPORT{Colors.RESET}")
        print(f"  {'─'*66}")

        cwv_metrics = [
            ("LCP", "lcp_ms", 2500, 4000, "ms"),
            ("FCP", "fcp_ms", 1800, 3000, "ms"),
            ("CLS", "cls_score", 0.1, 0.25, ""),
            ("INP", "inp_score", 200, 500, "ms"),
            ("TBT", "tbt_ms", 200, 600, "ms"),
            ("TTFB", "ttfb_ms", 800, 1800, "ms"),
            ("SI", "si_ms", 3400, 5800, "ms"),
            ("TTI", "tti_ms", 3800, 7300, "ms"),
        ]

        passing = needs_improvement_count = failing = total = 0
        for name, key, good_th, poor_th, unit in cwv_metrics:
            actual = self.raw_metrics.get(key)
            if actual is None:
                continue
            total += 1
            if actual <= good_th:
                status = f"{Colors.GREEN}PASS{Colors.RESET}"
                passing += 1
            elif actual <= poor_th:
                status = f"{Colors.YELLOW}AVG{Colors.RESET}"
                needs_improvement_count += 1
            else:
                status = f"{Colors.RED}FAIL{Colors.RESET}"
                failing += 1
            if unit:
                val_str = "{}{}".format(actual, unit)
                good_str = "<={}{}".format(good_th, unit)
                poor_str = ">{}{}".format(poor_th, unit)
            else:
                val_str = "{:.3f}".format(actual)
                good_str = "<={:.3f}".format(good_th)
                poor_str = "> {:.3f}".format(poor_th)
            print(f"  {name:6s} {val_str:>12s}  Good: {good_str:>10s}  Poor: {poor_str:>10s}  {status}")

        print(f"\n  {Colors.BOLD}COMPLIANCE SUMMARY:{Colors.RESET}")
        if total > 0:
            pass_pct = passing / total * 100
            print(f"  {Colors.GREEN}PASS: {passing}/{total} ({pass_pct:.0f}%){Colors.RESET}")
            if needs_improvement_count:
                print(f"  {Colors.YELLOW}AVG:  {needs_improvement_count}/{total}{Colors.RESET}")
            if failing:
                print(f"  {Colors.RED}FAIL: {failing}/{total}{Colors.RESET}")
        if failing == 0 and total > 0:
            print(f"\n  {Colors.GREEN}{Colors.BOLD}All Core Web Vitals are within acceptable thresholds!{Colors.RESET}")
        elif failing > 0:
            print(f"\n  {Colors.RED}{Colors.BOLD}{failing} Core Web Vital(s) failing - requires attention{Colors.RESET}")

    # ─────────────────────────────────────────────
    # OUTPUT: Optimization Priority Matrix (v7 refined)
    # ─────────────────────────────────────────────
    def print_optimization_priority_matrix(self):
        print(f"\n  {Colors.BOLD}{Colors.YELLOW}OPTIMIZATION PRIORITY MATRIX (Impact vs Effort){Colors.RESET}")
        print(f"  {'─'*72}")

        poor_checks = [r for r in self.results if r.status in ("poor", "needs_improvement")]
        matrix = defaultdict(list)
        for r in poor_checks:
            matrix[(r.effort, r.weight)].append(r.name[:30])

        effort_labels = {1: "Trivial", 2: "Easy", 3: "Moderate", 4: "Hard", 5: "Major"}
        impact_labels = {1: "Low", 2: "Med", 3: "High", 4: "V.High", 5: "Critical"}

        print(f"  {'':12s}", end="")
        for imp in range(1, 6):
            print(f" {impact_labels[imp]:>8s}", end="")
        print(f" {'Tot':>5s}")
        print(f"  {'─'*72}")

        impact_totals = defaultdict(int)
        effort_totals = defaultdict(int)
        for eff in range(1, 6):
            print(f"  {effort_labels[eff]:12s}", end="")
            row_total = 0
            for imp in range(1, 6):
                items = matrix.get((eff, imp), [])
                row_total += len(items)
                impact_totals[imp] += len(items)
                if items:
                    cell = "[{}]".format(len(items))
                    color = Colors.GREEN if eff <= 2 and imp >= 3 else Colors.YELLOW if eff <= 3 else Colors.DIM
                    print(f" {color}{cell:>8s}{Colors.RESET}", end="")
                else:
                    print(f" {'·':>8s}", end="")
            effort_totals[eff] = row_total
            print(f" {Colors.DIM}{row_total:>5d}{Colors.RESET}")

        print(f"  {'─'*72}")
        print(f"  {Colors.DIM}{'Total':12s}", end="")
        for imp in range(1, 6):
            print(f" {impact_totals.get(imp, 0):>8d}", end="")
        print(f" {Colors.DIM}{len(poor_checks):>5d}{Colors.RESET}")

        print()
        scored = []
        for r in poor_checks:
            impact = r.weight or 1
            effort = r.effort or 1
            severity = 2.0 if r.status == "poor" else 1.0
            roi = (impact * severity) / effort
            scored.append((r, roi))
        scored.sort(key=lambda x: -x[1])

        quick_wins = [(r, roi) for r, roi in scored if (r.effort or 1) <= 2 and (r.weight or 1) >= 3]
        if quick_wins:
            print(f"  {Colors.GREEN}{Colors.BOLD}Quick Wins (High Impact, Low Effort):{Colors.RESET}")
            for r, roi in quick_wins[:5]:
                print(f"  {Colors.GREEN}  ▸ {r.name[:38]:38s} ROI {roi:.1f}{Colors.RESET}")

        big_bets = [(r, roi) for r, roi in scored if (r.effort or 1) >= 4 and (r.weight or 1) >= 4]
        if big_bets:
            print(f"  {Colors.YELLOW}{Colors.BOLD}Big Bets (High Impact, High Effort):{Colors.RESET}")
            for r, roi in big_bets[:3]:
                print(f"  {Colors.YELLOW}  ▸ {r.name[:38]:38s} ROI {roi:.1f}{Colors.RESET}")

        fill_ins = [(r, roi) for r, roi in scored if (r.effort or 1) <= 2 and (r.weight or 1) <= 2]
        if fill_ins:
            print(f"  {Colors.DIM}{Colors.BOLD}Fill-ins (Low Impact, Low Effort):{Colors.RESET}")
            for r, roi in fill_ins[:3]:
                print(f"  {Colors.DIM}  · {r.name[:38]:38s} ROI {roi:.1f}{Colors.RESET}")

        criticals = [(r, roi) for r, roi in scored if r.status == "poor" and (r.weight or 1) >= 4]
        if criticals:
            print(f"  {Colors.RED}{Colors.BOLD}Critical Fixes (poor + high impact):{Colors.RESET}")
            for r, roi in criticals[:3]:
                print(f"  {Colors.RED}  ! {r.name[:38]:38s} ROI {roi:.1f}{Colors.RESET}")

        print(f"  {Colors.DIM}ROI = (impact x severity) / effort; severity is 2.0 for poor, 1.0 for needs-improvement.{Colors.RESET}")
        print(f"  {Colors.DIM}Columns = impact (weight 1-5), rows = effort (1-5); top-left of green zone = quick wins.{Colors.RESET}")

        opportunities = []
        if not self.raw_metrics.get("content_visibility_count", 0):
            opportunities.append("Apply content-visibility:auto to long offscreen sections")
        if not self.raw_metrics.get("contain_property_count", 0):
            opportunities.append("Add contain:paint/layout on isolated widgets")
        if not self.raw_metrics.get("scroll_driven_animations", False) and self.raw_metrics.get("debounce_throttle") is not None:
            if self.raw_metrics.get("debounce_throttle") is False:
                opportunities.append("Prefer animation-timeline:scroll() over raw JS scroll handlers")
            else:
                opportunities.append("Consider animation-timeline:scroll() for scroll-linked effects")
        if self.raw_metrics.get("img_count", 0) > 0 and self.raw_metrics.get("adaptive_image_coverage", 0) < 50:
            opportunities.append("Ship srcset/sizes so mobile downloads right-sized images")
        if self.raw_metrics.get("backdrop_filter_count", 0) > 4:
            opportunities.append("Reduce stacked backdrop-filter blur surfaces")
        if self.raw_metrics.get("will_change_count", 0) > 6 or self.raw_metrics.get("will_change_auto", 0) > 0:
            opportunities.append("Trim will-change entries (1-3 live layers max)")
        if opportunities:
            print(f"\n  {Colors.CYAN}{Colors.BOLD}MODERN TECHNIQUE OPPORTUNITIES:{Colors.RESET}")
            for opp in opportunities[:6]:
                print(f"  {Colors.CYAN}  ▸ {opp}{Colors.RESET}")

    # ─────────────────────────────────────────────
    # OUTPUT: ASCII Waterfall
    # ─────────────────────────────────────────────
    def print_waterfall(self):
        print(f"\n  {Colors.BOLD}{Colors.CYAN}PERFORMANCE TIMELINE (ASCII Waterfall){Colors.RESET}")
        print(f"  {'─'*66}")

        events = []
        dns_ms = self.raw_metrics.get("dns_ms", 0)
        tcp_ms = self.raw_metrics.get("tcp_ms", 0)
        ssl_ms = self.raw_metrics.get("ssl_ms", 0)
        ttfb_ms = self.raw_metrics.get("ttfb_ms", 0)
        dom_parse = self.raw_metrics.get("dom_parse_ms", 0)
        fcp_ms = self.raw_metrics.get("fcp_ms", 0)
        lcp_ms = self.raw_metrics.get("lcp_ms", 0)
        tti_ms = self.raw_metrics.get("tti_ms", 0)
        total_ms = self.raw_metrics.get("total_load_time_ms", 0)

        if total_ms == 0:
            return

        events.append(("DNS", 0, dns_ms))
        events.append(("TCP", dns_ms, tcp_ms))
        if ssl_ms > 0:
            events.append(("SSL", dns_ms + tcp_ms, ssl_ms))
        server_offset = dns_ms + tcp_ms + ssl_ms
        events.append(("TTFB", server_offset, ttfb_ms))
        events.append(("Parse", server_offset + ttfb_ms, dom_parse))
        fcp_dur = fcp_ms - (server_offset + ttfb_ms + dom_parse) if fcp_ms > server_offset + ttfb_ms + dom_parse else dom_parse
        events.append(("FCP", server_offset + ttfb_ms + dom_parse, fcp_dur))
        events.append(("LCP", 0, lcp_ms))
        events.append(("TTI", 0, tti_ms))
        events.append(("Load", 0, total_ms))

        max_time = max(total_ms, tti_ms, lcp_ms, 1)
        bar_width = 40

        for name, offset, duration in events:
            if duration <= 0:
                continue
            start_pos = int((offset / max_time) * bar_width) if max_time > 0 else 0
            bar_len = max(1, int((duration / max_time) * bar_width))
            if start_pos + bar_len > bar_width:
                bar_len = bar_width - start_pos
            padding = " " * start_pos
            bar = "█" * bar_len
            time_label = f"{duration:.0f}ms"
            if name in ("FCP", "LCP", "TTI", "Load"):
                color = Colors.GREEN if duration < 2000 else Colors.YELLOW if duration < 4000 else Colors.RED
            else:
                color = Colors.CYAN if duration < 200 else Colors.YELLOW if duration < 500 else Colors.RED
            print(f"  {name:6s} {color}{padding}{bar}{Colors.RESET} {time_label}")

        # Simulated waterfall
        sim_lcp = self.raw_metrics.get("simulated_lcp", 0)
        sim_tti = self.raw_metrics.get("simulated_tti", 0)
        if sim_lcp > 0 or sim_tti > 0:
            print(f"\n  {Colors.BOLD}{Colors.YELLOW}SIMULATED ({self.connection}/{self.device}){Colors.RESET}")
            print(f"  {'─'*66}")
            sim_events = []
            if sim_lcp > 0:
                sim_events.append(("Sim LCP", 0, sim_lcp))
            if sim_tti > 0:
                sim_events.append(("Sim TTI", 0, sim_tti))
            sim_total = self.raw_metrics.get("simulated_total", 0)
            if sim_total > 0:
                sim_events.append(("Sim Total", 0, int(sim_total)))
            sim_max = max(sim_lcp, sim_tti, sim_total, 1)
            for name, offset, duration in sim_events:
                if duration <= 0:
                    continue
                bar_len = max(1, int((duration / sim_max) * bar_width))
                bar = "█" * bar_len
                time_label = f"{duration:.0f}ms"
                color = Colors.GREEN if duration < 2500 else Colors.YELLOW if duration < 4000 else Colors.RED
                print(f"  {name:8s} {color}{bar}{Colors.RESET} {time_label}")

    # ─────────────────────────────────────────────
    # OUTPUT: Lighthouse-like Scoring Breakdown (v3 NEW)
    # ─────────────────────────────────────────────
    def print_lighthouse_breakdown(self):
        print(f"\n  {Colors.BOLD}{Colors.CYAN}LIGHTHOUSE-LIKE SCORING{Colors.RESET}")
        print(f"  {'─'*66}")

        lighthouse_checks = {
            "Performance": ["vitals", "timing", "simulation"],
            "Best Practices": ["caching", "compression", "protocol", "memory"],
            "Resource Optimization": ["resources", "images", "thirdparty"],
            "Rendering": ["rendering", "mobile"],
        }

        for section, categories in lighthouse_checks.items():
            cat_results = [r for r in self.results if r.category in categories]
            if not cat_results:
                continue
            score_map = {"excellent": 100, "good": 80, "needs_improvement": 50, "poor": 10}
            total_weighted = sum(score_map.get(r.status, 50) * (r.weight or 1) for r in cat_results)
            total_weight = sum(r.weight or 1 for r in cat_results)
            section_score = total_weighted / total_weight if total_weight > 0 else 50

            bar_len = int(section_score / 100 * 25)
            bar = "█" * bar_len + "░" * (25 - bar_len)
            bar_color = Colors.GREEN if section_score >= 80 else Colors.YELLOW if section_score >= 50 else Colors.RED

            excellent_count = sum(1 for r in cat_results if r.status == "excellent")
            good_count = sum(1 for r in cat_results if r.status == "good")
            ni_count = sum(1 for r in cat_results if r.status == "needs_improvement")
            poor_count = sum(1 for r in cat_results if r.status == "poor")

            print(f"  {section:22s} {bar_color}{bar}{Colors.RESET} {section_score:.0f}/100  "
                  f"{Colors.GREEN}E:{excellent_count}{Colors.RESET} "
                  f"{Colors.GREEN}G:{good_count}{Colors.RESET} "
                  f"{Colors.YELLOW}NI:{ni_count}{Colors.RESET} "
                  f"{Colors.RED}P:{poor_count}{Colors.RESET}")

    # ─────────────────────────────────────────────
    # OUTPUT: Optimization Priority List
    # ─────────────────────────────────────────────
    def print_optimization_priorities(self):
        print(f"\n  {Colors.BOLD}{Colors.YELLOW}OPTIMIZATION PRIORITY LIST{Colors.RESET}")
        print(f"  {'─'*66}")
        print(f"  {'Action':40s} {'Impact':8s} {'Effort':8s} {'Priority':8s}")
        print(f"  {'─'*66}")

        poor_checks = [r for r in self.results if r.status == "poor"]
        ni_checks = [r for r in self.results if r.status == "needs_improvement"]
        actionable = poor_checks + ni_checks

        scored = []
        for r in actionable:
            impact = r.weight if r.weight else 1
            effort = r.effort if r.effort else 1
            priority_score = impact / effort
            scored.append((r, priority_score))

        scored.sort(key=lambda x: -x[1])

        impact_labels = {1: "Low", 2: "Med", 3: "High", 4: "V.High", 5: "Critical"}
        effort_labels = {1: "Trivial", 2: "Easy", 3: "Moderate", 4: "Hard", 5: "Major"}

        for r, priority in scored[:10]:
            imp = impact_labels.get(r.weight, "?")
            eff = effort_labels.get(r.effort, "?")
            p_label = f"{priority:.1f}"
            if priority >= 3.0:
                p_color = Colors.GREEN
                prefix = "▸"
            elif priority >= 1.5:
                p_color = Colors.YELLOW
                prefix = "▸"
            else:
                p_color = Colors.DIM
                prefix = "·"
            name_trunc = r.name[:38]
            print(f"  {p_color}{prefix} {name_trunc:38s} {imp:8s} {eff:8s} {p_color}{p_label:8s}{Colors.RESET}")

    # ─────────────────────────────────────────────
    # OUTPUT: Effort/Impact Matrix (v3 NEW)
    # ─────────────────────────────────────────────
    def print_effort_impact_matrix(self):
        print(f"\n  {Colors.BOLD}{Colors.MAGENTA}EFFORT / IMPACT MATRIX{Colors.RESET}")
        print(f"  {'─'*66}")

        poor_checks = [r for r in self.results if r.status in ("poor", "needs_improvement")]

        matrix = defaultdict(list)
        for r in poor_checks:
            key = (r.effort, r.weight)
            matrix[key].append(r.name[:30])

        effort_labels = {1: "Trivial", 2: "Easy", 3: "Moderate", 4: "Hard", 5: "Major"}
        impact_labels = {1: "Low", 2: "Med", 3: "High", 4: "V.High", 5: "Critical"}

        print(f"  {'':12s}", end="")
        for imp in range(1, 6):
            print(f" {impact_labels[imp]:>8s}", end="")
        print()
        print(f"  {'─'*66}")

        for eff in range(1, 6):
            print(f"  {effort_labels[eff]:12s}", end="")
            for imp in range(1, 6):
                items = matrix.get((eff, imp), [])
                if items:
                    cell = f"[{len(items)}]"
                    color = Colors.GREEN if eff <= 2 and imp >= 3 else Colors.YELLOW if eff <= 3 else Colors.DIM
                    print(f" {color}{cell:>8s}{Colors.RESET}", end="")
                else:
                    print(f" {'·':>8s}", end="")
            print()

        print()
        quick_wins = []
        for r in poor_checks:
            if r.effort <= 2 and r.weight >= 3:
                quick_wins.append(r.name[:35])
        if quick_wins:
            print(f"  {Colors.GREEN}{Colors.BOLD}Quick Wins (High Impact, Low Effort):{Colors.RESET}")
            for qw in quick_wins[:5]:
                print(f"  {Colors.GREEN}  ▸ {qw}{Colors.RESET}")

    # ─────────────────────────────────────────────
    # OUTPUT: Performance Waterfall with Phases (v5 NEW)
    # ─────────────────────────────────────────────
    def print_waterfall_phases(self):
        print(f"\n  {Colors.BOLD}{Colors.CYAN}PERFORMANCE WATERFALL BY PHASE{Colors.RESET}")
        print(f"  {'─'*66}")

        dns = self.raw_metrics.get("dns_ms", 0)
        tcp = self.raw_metrics.get("tcp_ms", 0)
        ssl = self.raw_metrics.get("ssl_ms", 0)
        ttfb = self.raw_metrics.get("ttfb_ms", 0)
        parse = self.raw_metrics.get("dom_parse_ms", 0)
        fcp = self.raw_metrics.get("fcp_ms", 0)
        lcp = self.raw_metrics.get("lcp_ms", 0)
        tti = self.raw_metrics.get("tti_ms", 0)
        load = self.raw_metrics.get("total_load_time_ms", 0)

        connect = dns + tcp + ssl
        server = ttfb
        parse_phase = parse
        fcp_wait = max(0, fcp - connect - server - parse_phase)
        lcp_fill = max(0, lcp - fcp)
        interactive = max(0, tti - lcp)
        settle = max(0, load - tti)

        phases = [
            ("Connect", connect, Colors.CYAN, "DNS/TCP/TLS"),
            ("Server", server, Colors.BLUE, "TTFB backend"),
            ("Parse", parse_phase, Colors.MAGENTA, "HTML DOM parse"),
            ("FCP wait", fcp_wait, Colors.YELLOW, "first paint build"),
            ("LCP fill", lcp_fill, Colors.YELLOW, "largest content"),
            ("Interactive", interactive, Colors.GREEN, "main thread ready"),
            ("Load", settle, Colors.DIM, "window load settle"),
        ]

        total = sum(dur for _, dur, _, _ in phases)
        if total <= 0:
            print(f"  {Colors.DIM}Insufficient timing data for phase waterfall{Colors.RESET}")
            return

        bar_width = 36
        cumulative = 0
        for name, dur, color, label in phases:
            if dur <= 0:
                continue
            start_pos = int((cumulative / total) * bar_width)
            bar_len = max(1, int((dur / total) * bar_width))
            if start_pos + bar_len > bar_width:
                bar_len = max(1, bar_width - start_pos)
            padding = " " * start_pos
            bar = "█" * bar_len
            end_ms = cumulative + dur
            print(f"  {name:11s} {color}{padding}{bar}{Colors.RESET} {dur:5d}ms  [{cumulative}–{end_ms}ms] {Colors.DIM}{label}{Colors.RESET}")
            cumulative += dur

        print(f"  {Colors.DIM}Total phase span: {total}ms | milestones: FCP {fcp}ms, LCP {lcp}ms, TTI {tti}ms, Load {load}ms{Colors.RESET}")

        sim_lcp = self.raw_metrics.get("simulated_lcp", 0)
        if sim_lcp > 0:
            ratio = sim_lcp / lcp if lcp > 0 else 1.0
            print(f"\n  {Colors.BOLD}{Colors.YELLOW}SIMULATED PHASE SCALE ({self.connection}/{self.device}){Colors.RESET}")
            print(f"  {'─'*66}")
            scaled_total = int(total * ratio)
            for name, dur, color, _ in phases:
                if dur <= 0:
                    continue
                scaled = int(dur * ratio)
                bar_len = max(1, int((scaled / max(scaled_total, 1)) * bar_width))
                bar = "█" * bar_len
                print(f"  {name:11s} {color}{bar}{Colors.RESET} {scaled:5d}ms")

    # ─────────────────────────────────────────────
    # OUTPUT: Lighthouse Simulation Report (v5 NEW)
    # ─────────────────────────────────────────────
    def print_lighthouse_simulation(self):
        score = self.raw_metrics.get("lighthouse_score")
        if score is None:
            return
        print(f"\n  {Colors.BOLD}{Colors.CYAN}LIGHTHOUSE SCORE SIMULATION{Colors.RESET}")
        print(f"  {'─'*66}")

        bar_len = int(score / 100 * 30)
        bar = "█" * bar_len + "░" * (30 - bar_len)
        color = Colors.GREEN if score >= 90 else Colors.YELLOW if score >= 50 else Colors.RED
        print(f"  Score: {color}{bar}{Colors.RESET} {Colors.BOLD}{score:.0f}/100{Colors.RESET}")
        if score >= 90:
            label = "Fast (Lighthouse green zone)"
        elif score >= 50:
            label = "Needs improvement (orange zone)"
        else:
            label = "Slow (red zone)"
        print(f"  Zone:  {color}{label}{Colors.RESET}")

        parts = self.raw_metrics.get("lighthouse_subscores", {})
        if parts:
            print(f"\n  {'Metric':16s} {'Subscore':>10s}")
            print(f"  {'─'*40}")
            display = {
                "fcp_ms": "FCP", "si_ms": "Speed Index", "lcp_ms": "LCP",
                "tbt_ms": "TBT", "cls_score": "CLS", "tti_ms": "TTI", "ttfb_ms": "TTFB",
            }
            for key, sub in parts.items():
                name = display.get(key, key)
                sub_color = Colors.GREEN if sub >= 90 else Colors.YELLOW if sub >= 50 else Colors.RED
                print(f"  {name:16s} {sub_color}{sub:>10.1f}{Colors.RESET}")

        penalty = self.raw_metrics.get("lighthouse_penalty", 0)
        if penalty:
            print(f"\n  {Colors.YELLOW}Applied penalty: -{penalty}{Colors.RESET}")

    # ─────────────────────────────────────────────
    # OUTPUT: PageSpeed Insights Report (v5 NEW)
    # ─────────────────────────────────────────────
    def print_pagespeed_report(self):
        score = self.raw_metrics.get("psi_score")
        if score is None:
            return
        print(f"\n  {Colors.BOLD}{Colors.CYAN}PAGESPEED INSIGHTS (APPROXIMATION){Colors.RESET}")
        print(f"  {'─'*66}")

        bar_len = int(score / 100 * 30)
        bar = "█" * bar_len + "░" * (30 - bar_len)
        color = Colors.GREEN if score >= 90 else Colors.YELLOW if score >= 50 else Colors.RED
        print(f"  Estimated PSI score: {color}{bar}{Colors.RESET} {Colors.BOLD}{score:.0f}/100{Colors.RESET}")

        adjustments = self.raw_metrics.get("psi_adjustments", [])
        if adjustments:
            print(f"  {Colors.DIM}Adjustments: {', '.join(adjustments)}{Colors.RESET}")
        else:
            print(f"  {Colors.DIM}No structural adjustments applied{Colors.RESET}")
        print(f"  {Colors.DIM}Note: approximation of lab+structure signals; real PSI also uses CrUX field data.{Colors.RESET}")

    # ─────────────────────────────────────────────
    # OUTPUT: Mobile vs Desktop Comparison (v5 NEW)
    # ─────────────────────────────────────────────
    def print_mobile_vs_desktop_comparison(self):
        comparison = self.raw_metrics.get("mobile_desktop_comparison")
        if not comparison:
            return
        print(f"\n  {Colors.BOLD}{Colors.YELLOW}MOBILE VS DESKTOP COMPARISON ({self.connection}){Colors.RESET}")
        print(f"  {'─'*66}")
        print(f"  {'Metric':14s} {'Mobile':>12s} {'Desktop':>12s} {'Delta':>12s}")
        print(f"  {'─'*66}")

        labels = [
            ("lcp_ms", "LCP", "ms"),
            ("tti_ms", "TTI", "ms"),
            ("tbt_ms", "TBT", "ms"),
            ("si_ms", "Speed Index", "ms"),
        ]
        for key, label, unit in labels:
            mobile = comparison.get("mobile", {}).get(key, 0)
            desktop = comparison.get("desktop", {}).get(key, 0)
            delta = mobile - desktop
            if mobile <= (2500 if key == "lcp_ms" else 100000):
                mobile_color = Colors.GREEN
            elif key == "lcp_ms" and mobile <= 4000:
                mobile_color = Colors.YELLOW
            else:
                mobile_color = Colors.RED if key == "lcp_ms" else Colors.YELLOW
            delta_color = Colors.GREEN if delta <= 0 else Colors.YELLOW if delta < 1500 else Colors.RED
            print(f"  {label:14s} {mobile_color}{mobile:>9d}{unit}{Colors.RESET} {desktop:>9d}{unit} {delta_color}{delta:>+9d}{unit}{Colors.RESET}")

        worst = self.raw_metrics.get("mobile_desktop_delta_ms", 0)
        print(f"\n  {Colors.DIM}Mobile penalty on this connection: +{worst}ms LCP vs desktop{Colors.RESET}")

    # ─────────────────────────────────────────────
    # OUTPUT: Speed Index Estimation Details (v7 refined)
    # ─────────────────────────────────────────────
    def print_speed_index_estimation(self):
        si = self.raw_metrics.get("si_ms")
        if si is None:
            return
        print(f"\n  {Colors.BOLD}{Colors.MAGENTA}SPEED INDEX ESTIMATION{Colors.RESET}")
        print(f"  {'─'*72}")

        components = self.raw_metrics.get("si_components", {})
        load_ms = self.raw_metrics.get("total_load_time_ms", 0)
        html_size = self.raw_metrics.get("total_page_size", 0)
        js_count = self.raw_metrics.get("js_count", 0)
        img_size = self.raw_metrics.get("img_size", 0)
        render_blocking = self.raw_metrics.get("render_blocking_resources", 0)

        if si <= 3400:
            status_str = f"{Colors.GREEN}GOOD (<=3400ms){Colors.RESET}"
        elif si <= 5800:
            status_str = f"{Colors.YELLOW}AVG (<=5800ms){Colors.RESET}"
        else:
            status_str = f"{Colors.RED}POOR (>5800ms){Colors.RESET}"

        print(f"  Estimated Speed Index: {Colors.BOLD}{si}ms{Colors.RESET}  {status_str}")

        if components:
            rows = [
                ("Load time component", components.get("load_time_ms", 0)),
                ("Page payload component", components.get("payload_ms", 0)),
                ("JavaScript request component", components.get("js_ms", 0)),
                ("Render-blocking CSS component", components.get("blocking_css_ms", 0)),
                ("Imagery + strategy adjust", components.get("imagery_ms", 0)),
            ]
            if "containment_ms" in components:
                rows.append(("Content-visibility containment", components.get("containment_ms", 0)))
            if "paint_ms" in components:
                rows.append(("Backdrop-filter paint cost", components.get("paint_ms", 0)))
            total_component = sum(v for _, v in rows) or 1
            print(f"\n  {'Factor':30s} {'Weight':>10s} {'Share':>8s}")
            print(f"  {'─'*52}")
            for label, value in rows:
                share = value / total_component * 100
                bar_len = max(0, min(20, int(share / 100 * 20)))
                bar = "█" * bar_len + "·" * (20 - bar_len)
                color = Colors.RED if value > 1500 else Colors.YELLOW if value > 600 else Colors.GREEN
                print(f"  {label:30s} {value:>7d}ms {color}{bar}{Colors.RESET} {share:>5.0f}%")

            print(f"\n  {'Inputs':30s} {'Value':>14s}")
            print(f"  {'─'*46}")
            print(f"  {'Page payload':30s} {components.get('payload_kb', 0):>10.1f}KB")
            print(f"  {'JavaScript requests':30s} {components.get('js_count', 0):>14d}")
            print(f"  {'Render-blocking CSS':30s} {components.get('render_blocking_css', 0):>14d}")
            print(f"  {'Lazy-loaded images':30s} {components.get('lazy_ratio', 0):>13.1f}%")
            print(f"  {'Modern image formats':30s} {components.get('modern_format_ratio', 0):>13.1f}%")
            print(f"  {'Adaptive image coverage':30s} {components.get('adaptive_ratio', 0):>13.1f}%")
            print(f"  {'Content-visibility decls':30s} {components.get('content_visibility_count', 0):>14d}")
            print(f"  {'Backdrop-filter decls':30s} {components.get('backdrop_filter_count', 0):>14d}")
            print(f"  {'Critical inline CSS':30s} {('yes' if components.get('critical_inline_css') else 'no'):>14s}")
        else:
            print(f"\n  {'Factor':26s} {'Value':>14s}")
            print(f"  {'─'*44}")
            print(f"  {'Load time component':26s} {load_ms:>10d}ms")
            print(f"  {'Page payload component':26s} {html_size/1024:>10.1f}KB")
            print(f"  {'JavaScript request count':26s} {js_count:>10d}")
            print(f"  {'Image payload component':26s} {img_size/1024:>10.1f}KB")
            print(f"  {'Render-blocking resources':26s} {render_blocking:>10d}")

        print(f"\n  {Colors.DIM}Lower SI means visual completeness arrives faster; prioritize critical{Colors.RESET}")
        print(f"  {Colors.DIM}CSS inlining, above-the-fold imagery, and deferred non-critical JS.{Colors.RESET}")
        if si > 3400:
            top_factor = "load time"
            if components:
                factor_values = [
                    ("load time", components.get("load_time_ms", 0)),
                    ("page payload", components.get("payload_ms", 0)),
                    ("JavaScript requests", components.get("js_ms", 0)),
                    ("render-blocking CSS", components.get("blocking_css_ms", 0)),
                    ("imagery", components.get("imagery_ms", 0)),
                ]
                if "containment_ms" in components:
                    factor_values.append(("content-visibility containment", components.get("containment_ms", 0)))
                if "paint_ms" in components:
                    factor_values.append(("backdrop-filter paint", components.get("paint_ms", 0)))
                top_factor = max(factor_values, key=lambda x: x[1])[0]
            print(f"  {Colors.YELLOW}Dominant factor right now: {top_factor}.{Colors.RESET}")

    # ─────────────────────────────────────────────
    # OUTPUT: Core Web Vitals Summary
    # ─────────────────────────────────────────────
    def print_cwv_summary(self):
        print(f"\n  {Colors.BOLD}{Colors.MAGENTA}CORE WEB VITALS THRESHOLDS{Colors.RESET}")
        print(f"  {'─'*66}")
        print(f"  {'Metric':12s} {'Value':12s} {'Good':10s} {'Poor':10s} {'Status':12s}")
        print(f"  {'─'*66}")

        for metric_key, thresholds in self.CORE_WEB_VITALS.items():
            actual = self.raw_metrics.get(metric_key)
            if actual is None:
                continue
            name = thresholds["name"]
            good_th = thresholds["good"]
            poor_th = thresholds["poor"]
            if actual <= good_th:
                status = f"{Colors.GREEN}PASS{Colors.RESET}"
            elif actual <= poor_th:
                status = f"{Colors.YELLOW}AVG{Colors.RESET}"
            else:
                status = f"{Colors.RED}FAIL{Colors.RESET}"
            print(f"  {name:12s} {actual:>10} {good_th:>8} {poor_th:>8} {status}")

    # ─────────────────────────────────────────────
    # OUTPUT: Main results
    # ─────────────────────────────────────────────
    def print_results(self):
        print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}  PERFORMANCE ANALYSIS RESULTS{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*70}{Colors.RESET}\n")

        current_category = None
        for result in self.results:
            if result.category != current_category:
                current_category = result.category
                cat_name = current_category.upper()
                cat_colors = {
                    "vitals": Colors.MAGENTA,
                    "timing": Colors.CYAN,
                    "resources": Colors.BLUE,
                    "caching": Colors.YELLOW,
                    "compression": Colors.GREEN,
                    "redirects": Colors.RED,
                    "protocol": Colors.BLUE,
                    "rendering": Colors.MAGENTA,
                    "images": Colors.CYAN,
                    "mobile": Colors.GREEN,
                    "modern": Colors.MAGENTA,
                    "simulation": Colors.CYAN,
                    "memory": Colors.RED,
                    "thirdparty": Colors.YELLOW,
                    "observers": Colors.CYAN,
                    "bundles": Colors.BLUE,
                    "analytics": Colors.YELLOW,
                }
                color = cat_colors.get(current_category, Colors.WHITE)
                print(f"\n  {color}{Colors.BOLD}┌─ {cat_name} {'─'*(55-len(cat_name))}┐{Colors.RESET}")

            icon = self.status_icon(result.status)
            color = self.get_status_color(result.status)
            name_len = len(result.name)
            value_len = len(result.value)
            padding = 58 - name_len - value_len
            if padding < 2:
                padding = 2
            print(f"  {icon} {result.name}{' '*padding}{color}{Colors.BOLD}{result.value}{Colors.RESET}")
            if result.detail:
                print(f"    {Colors.DIM}└─ {result.detail}{Colors.RESET}")

        print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")

        score, category_scores = self.calculate_score()
        grade, grade_color = self.get_grade(score)

        print(f"\n  {Colors.BOLD}{Colors.CYAN}PERFORMANCE SCORE{Colors.RESET}")
        print(f"  {'─'*50}")

        score_bar_len = 40
        filled = int(score / 100 * score_bar_len)
        bar = "█" * filled + "░" * (score_bar_len - filled)
        bar_color = Colors.GREEN if score >= 80 else Colors.YELLOW if score >= 50 else Colors.RED
        print(f"  Score: {bar_color}{bar}{Colors.RESET} {Colors.BOLD}{score:.0f}/100{Colors.RESET}")
        print(f"  Grade: {grade_color}{Colors.BOLD}{grade}{Colors.RESET}")

        print(f"\n  {Colors.BOLD}CATEGORY BREAKDOWN{Colors.RESET}")
        print(f"  {'─'*50}")
        for category, weight in self.SCORING_WEIGHTS.items():
            cat_score = category_scores[category]
            bar_len = int(cat_score / 100 * 25)
            bar = "█" * bar_len + "░" * (25 - bar_len)
            cat_color = Colors.GREEN if cat_score >= 80 else Colors.YELLOW if cat_score >= 50 else Colors.RED
            grade_label, _ = self.get_grade(cat_score)
            print(f"  {category.upper():12s} {cat_color}{bar}{Colors.RESET} {cat_score:.0f}/100 ({weight}%) [{grade_label}]")

        print(f"\n  {Colors.BOLD}KEY METRICS{Colors.RESET}")
        print(f"  {'─'*50}")
        metrics = [
            ("LCP", f"{self.raw_metrics.get('lcp_ms', 'N/A')}ms" if 'lcp_ms' in self.raw_metrics else "N/A"),
            ("FCP", f"{self.raw_metrics.get('fcp_ms', 'N/A')}ms" if 'fcp_ms' in self.raw_metrics else "N/A"),
            ("CLS", f"{self.raw_metrics.get('cls_score', 'N/A')}"),
            ("INP", f"{self.raw_metrics.get('inp_score', 'N/A')}ms" if 'inp_score' in self.raw_metrics else "N/A"),
            ("TBT", f"{self.raw_metrics.get('tbt_ms', 'N/A')}ms" if 'tbt_ms' in self.raw_metrics else "N/A"),
            ("TTFB", f"{self.raw_metrics.get('ttfb_ms', 'N/A')}ms" if 'ttfb_ms' in self.raw_metrics else "N/A"),
            ("Speed Index", f"{self.raw_metrics.get('si_ms', 'N/A')}ms" if 'si_ms' in self.raw_metrics else "N/A"),
            ("TTI", f"{self.raw_metrics.get('tti_ms', 'N/A')}ms" if 'tti_ms' in self.raw_metrics else "N/A"),
            ("Load Time", f"{self.raw_metrics.get('total_load_time_ms', 'N/A')}ms" if 'total_load_time_ms' in self.raw_metrics else "N/A"),
            ("Page Size", f"{self.raw_metrics.get('total_page_size', 0)/1024:.1f}KB" if 'total_page_size' in self.raw_metrics else "N/A"),
            ("Resources", f"{self.raw_metrics.get('total_resources', 'N/A')}"),
            ("HTTP Version", self.raw_metrics.get("http_version", "N/A")),
            ("Compression", self.raw_metrics.get("compression", "N/A")),
            ("UX Score", f"{self.raw_metrics.get('ux_score', 'N/A')}/100" if 'ux_score' in self.raw_metrics else "N/A"),
            ("Lighthouse (sim)", f"{self.raw_metrics.get('lighthouse_score', 'N/A')}/100" if 'lighthouse_score' in self.raw_metrics else "N/A"),
            ("PageSpeed (approx)", f"{self.raw_metrics.get('psi_score', 'N/A')}/100" if 'psi_score' in self.raw_metrics else "N/A"),
            ("Budget Compliance", f"{self.raw_metrics.get('budget_compliance_pct', 'N/A')}%" if 'budget_compliance_pct' in self.raw_metrics else "N/A"),
        ]
        for name, value in metrics:
            print(f"  {name:20s} {Colors.BOLD}{value}{Colors.RESET}")

        # Simulation summary
        if 'simulated_lcp' in self.raw_metrics:
            print(f"\n  {Colors.BOLD}SIMULATED METRICS ({self.connection}/{self.device}){Colors.RESET}")
            print(f"  {'─'*50}")
            sim_metrics = [
                ("Simulated LCP", f"{self.raw_metrics.get('simulated_lcp', 'N/A')}ms"),
                ("Simulated TTI", f"{self.raw_metrics.get('simulated_tti', 'N/A')}ms"),
                ("Simulated TBT", f"{self.raw_metrics.get('simulated_tbt', 'N/A')}ms"),
                ("CPU-throttled JS", f"{self.raw_metrics.get('cpu_throttled_js_ms', 'N/A')}ms"),
                ("Network Transfer", f"{self.raw_metrics.get('simulated_total', 'N/A')}ms"),
            ]
            for name, value in sim_metrics:
                print(f"  {name:20s} {Colors.BOLD}{value}{Colors.RESET}")

        poor_checks = [r for r in self.results if r.status == "poor"]
        needs_improvement = [r for r in self.results if r.status == "needs_improvement"]

        if poor_checks or needs_improvement:
            print(f"\n  {Colors.BOLD}{Colors.YELLOW}RECOMMENDATIONS{Colors.RESET}")
            print(f"  {'─'*50}")
            for r in poor_checks[:5]:
                print(f"  {Colors.RED}●{Colors.RESET} {r.name}: {r.detail or 'Needs attention'}")
            for r in needs_improvement[:3]:
                print(f"  {Colors.YELLOW}●{Colors.RESET} {r.name}: {r.detail or 'Could be improved'}")

        print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}\n")

        return score, grade

    # ─────────────────────────────────────────────
    # EXPORTS
    # ─────────────────────────────────────────────
    def export_json(self, score, grade):
        filename = f"perfanalyzer_{int(time.time())}.json"
        data = {
            "url": self.url,
            "timestamp": datetime.utcnow().isoformat(),
            "version": "7.0",
            "score": round(score, 1),
            "grade": grade,
            "ux_score": self.raw_metrics.get("ux_score"),
            "lighthouse_score": self.raw_metrics.get("lighthouse_score"),
            "psi_score": self.raw_metrics.get("psi_score"),
            "budget_compliance_pct": self.raw_metrics.get("budget_compliance_pct"),
            "score_adjustments": self.raw_metrics.get("score_adjustments", []),
            "device": self.device,
            "connection": self.connection,
            "strict_budget": self.strict_budget,
            "results": [r.to_dict() for r in self.results],
            "metrics": self.raw_metrics,
            "budgets": self.PERFORMANCE_BUDGETS,
            "core_web_vitals": self.CORE_WEB_VITALS,
            "connection_profiles": self.CONNECTION_PROFILES,
            "device_profiles": self.DEVICE_PROFILES,
        }
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        print(f"  {Colors.GREEN}✓{Colors.RESET} Exported to {Colors.BOLD}{filename}{Colors.RESET}")
        return filename

    def export_csv(self, score, grade):
        filename = f"perfanalyzer_{int(time.time())}.csv"
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Category", "Check", "Value", "Status", "Detail", "Weight", "Effort"])
            for r in self.results:
                writer.writerow([r.category, r.name, r.value, r.status, r.detail, r.weight, r.effort])
            writer.writerow([])
            writer.writerow(["Overall", "Score", f"{score:.0f}/100", grade, "", "", ""])
        print(f"  {Colors.GREEN}✓{Colors.RESET} Exported to {Colors.BOLD}{filename}{Colors.RESET}")
        return filename

    def export_html(self, score, grade):
        filename = f"perfanalyzer_{int(time.time())}.html"
        status_colors = {
            "excellent": "#22c55e",
            "good": "#22c55e",
            "needs_improvement": "#f59e0b",
            "poor": "#ef4444",
        }
        grade_colors = {
            "A+": "#22c55e", "A": "#22c55e", "B": "#f59e0b",
            "C": "#f59e0b", "D": "#ef4444", "F": "#ef4444",
        }
        results_html = ""
        current_cat = None
        for r in self.results:
            if r.category != current_cat:
                if current_cat is not None:
                    results_html += "</tbody></table>"
                current_cat = r.category
                results_html += '<h3 class="cat-header">' + current_cat.upper() + '</h3>'
                results_html += '<table class="results-table"><thead><tr><th>Check</th><th>Value</th><th>Status</th><th>Detail</th><th>Impact</th><th>Effort</th></tr></thead><tbody>'
            sc = status_colors.get(r.status, "#888")
            results_html += '<tr><td>' + r.name + '</td><td class="value">' + r.value + '</td><td><span class="status-badge" style="background:' + sc + '">' + r.status + '</span></td><td class="detail">' + r.detail + '</td><td>' + str(r.weight) + '/5</td><td>' + str(r.effort) + '/5</td></tr>'
        if current_cat:
            results_html += "</tbody></table>"

        gc = grade_colors.get(grade, "#888")

        cwv_html = '<table class="results-table"><thead><tr><th>Metric</th><th>Value</th><th>Good</th><th>Poor</th><th>Status</th></tr></thead><tbody>'
        for metric_key, thresholds in self.CORE_WEB_VITALS.items():
            actual = self.raw_metrics.get(metric_key)
            if actual is None:
                continue
            name = thresholds["name"]
            good_th = thresholds["good"]
            poor_th = thresholds["poor"]
            if actual <= good_th:
                s_color = "#22c55e"
                s_label = "PASS"
            elif actual <= poor_th:
                s_color = "#f59e0b"
                s_label = "AVG"
            else:
                s_color = "#ef4444"
                s_label = "FAIL"
            cwv_html += '<tr><td>' + name + '</td><td class="value">' + str(actual) + '</td><td>' + str(good_th) + '</td><td>' + str(poor_th) + '</td><td><span class="status-badge" style="background:' + s_color + '">' + s_label + '</span></td></tr>'
        cwv_html += '</tbody></table>'

        poor_checks = [r for r in self.results if r.status == "poor"]
        needs_improvement = [r for r in self.results if r.status == "needs_improvement"]
        recs_html = ""
        if poor_checks or needs_improvement:
            recs_html = '<div class="recommendations"><h2>Recommendations</h2><ul>'
            for r in poor_checks[:8]:
                recs_html += '<li style="color:#ef4444"><strong>' + r.name + '</strong>: ' + (r.detail or "Needs attention") + ' (Impact: ' + str(r.weight) + '/5, Effort: ' + str(r.effort) + '/5)</li>'
            for r in needs_improvement[:5]:
                recs_html += '<li style="color:#f59e0b"><strong>' + r.name + '</strong>: ' + (r.detail or "Could be improved") + ' (Impact: ' + str(r.weight) + '/5, Effort: ' + str(r.effort) + '/5)</li>'
            recs_html += "</ul></div>"

        html = '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        html += '<title>PerfAnalyzer v7.0 Report - ' + self.url + '</title>\n'
        html += '<style>\n'
        html += '* { margin: 0; padding: 0; box-sizing: border-box; }\n'
        html += 'body { font-family: "Segoe UI", system-ui, -apple-system, sans-serif; background: #0a0a0a; color: #e0e0e0; padding: 2rem; line-height: 1.6; }\n'
        html += '.container { max-width: 900px; margin: 0 auto; }\n'
        html += '.header { text-align: center; margin-bottom: 2rem; padding: 2rem; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border-radius: 12px; border: 1px solid #2a2a3e; }\n'
        html += '.header h1 { font-size: 1.8rem; color: #00d4ff; margin-bottom: 0.5rem; }\n'
        html += '.header .url { color: #888; font-size: 0.9rem; word-break: break-all; }\n'
        html += '.score-section { display: flex; align-items: center; justify-content: center; gap: 2rem; margin: 2rem 0; padding: 2rem; background: #111; border-radius: 12px; border: 1px solid #222; }\n'
        html += '.score-circle { width: 120px; height: 120px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 2.5rem; font-weight: bold; border: 4px solid ' + gc + '; color: ' + gc + '; }\n'
        html += '.score-details { text-align: left; }\n'
        html += '.score-details .grade { font-size: 1.5rem; font-weight: bold; color: ' + gc + '; }\n'
        html += '.score-details .label { color: #888; font-size: 0.9rem; }\n'
        html += '.section-header { color: #00d4ff; margin: 2rem 0 0.8rem; font-size: 1.1rem; letter-spacing: 0.05em; border-bottom: 1px solid #222; padding-bottom: 0.5rem; }\n'
        html += '.cat-header { color: #00d4ff; margin: 1.5rem 0 0.8rem; font-size: 1rem; letter-spacing: 0.05em; }\n'
        html += '.results-table { width: 100%; border-collapse: collapse; margin-bottom: 1rem; }\n'
        html += '.results-table th { text-align: left; padding: 0.6rem; border-bottom: 2px solid #222; color: #888; font-size: 0.8rem; text-transform: uppercase; }\n'
        html += '.results-table td { padding: 0.6rem; border-bottom: 1px solid #1a1a1a; font-size: 0.9rem; }\n'
        html += '.results-table td.value { font-weight: 600; color: #fff; white-space: nowrap; }\n'
        html += '.results-table td.detail { color: #666; font-size: 0.8rem; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }\n'
        html += '.status-badge { padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; color: #fff; font-weight: 500; text-transform: uppercase; }\n'
        html += '.recommendations { margin-top: 2rem; padding: 1.5rem; background: #1a1a0a; border-radius: 12px; border: 1px solid #333; }\n'
        html += '.recommendations h2 { color: #f59e0b; margin-bottom: 1rem; font-size: 1.1rem; }\n'
        html += '.recommendations li { margin-bottom: 0.5rem; padding-left: 0.5rem; color: #ccc; }\n'
        html += '.footer { text-align: center; margin-top: 2rem; color: #444; font-size: 0.8rem; }\n'
        html += '</style>\n</head>\n<body>\n<div class="container">\n'
        html += '<div class="header">\n<h1>PerfAnalyzer v7.0</h1>\n'
        html += '<div class="url">' + self.url + '</div>\n'
        html += '<div class="url" style="margin-top:0.3rem">Generated: ' + datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC') + '</div>\n'
        html += '<div class="url" style="margin-top:0.3rem">Device: ' + self.device + ' | Connection: ' + self.connection + '</div>\n'
        html += '</div>\n'
        html += '<div class="score-section">\n'
        html += '<div class="score-circle">' + f"{score:.0f}" + '</div>\n'
        html += '<div class="score-details">\n'
        html += '<div class="grade">Grade: ' + grade + '</div>\n'
        html += '<div class="label">Performance Score out of 100</div>\n'
        html += '<div class="label" style="margin-top:0.5rem">Total Results: ' + str(len(self.results)) + '</div>\n'
        html += '</div>\n</div>\n'
        html += '<h2 class="section-header">Core Web Vitals Thresholds</h2>\n'
        html += cwv_html + '\n'
        html += results_html + '\n'
        html += recs_html + '\n'
        html += '<div class="footer">Generated by PerfAnalyzer v7.0</div>\n'
        html += '</div>\n</body>\n</html>'
        with open(filename, "w") as f:
            f.write(html)
        print(f"  {Colors.GREEN}✓{Colors.RESET} Exported to {Colors.BOLD}{filename}{Colors.RESET}")
        return filename

    # ─────────────────────────────────────────────
    # MAIN ANALYSIS ORCHESTRATOR
    # ─────────────────────────────────────────────
    def analyze(self):
        print(self.BANNER)
        print(f"\n  {Colors.BOLD}Target:{Colors.RESET} {self.url}")
        print(f"  {Colors.BOLD}Timeout:{Colors.RESET} {self.timeout}s")
        print(f"  {Colors.BOLD}Device:{Colors.RESET} {self.DEVICE_PROFILES.get(self.device, {}).get('label', self.device)}")
        print(f"  {Colors.BOLD}Connection:{Colors.RESET} {self.CONNECTION_PROFILES.get(self.connection, {}).get('label', self.connection)}")
        print(f"  {Colors.BOLD}Strict Budget:{Colors.RESET} {'enabled' if self.strict_budget else 'disabled'}")
        print(f"  {Colors.BOLD}Started:{Colors.RESET} {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"\n{'─'*70}\n")

        print(f"  {Colors.BOLD}Starting analysis...{Colors.RESET}\n")

        dns_time = 0
        tcp_time = 0
        ssl_time = 0
        server_time = 0

        try:
            parsed = urlparse(self.url)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            print(f"  {Colors.DIM}[DNS]{Colors.RESET} Resolving {hostname}...")
            dns_start = time.time()
            try:
                socket.getaddrinfo(hostname, port)
            except socket.gaierror as e:
                print(f"  {Colors.RED}✗ DNS resolution failed: {e}{Colors.RESET}")
                return
            dns_time = time.time() - dns_start
            print(f"  {Colors.DIM}[DNS]{Colors.RESET} Resolved in {dns_time*1000:.0f}ms")

            print(f"  {Colors.DIM}[TCP]{Colors.RESET} Connecting to {hostname}:{port}...")
            tcp_start = time.time()
            sock = socket.create_connection((hostname, port), timeout=self.timeout)
            tcp_time = time.time() - tcp_start
            print(f"  {Colors.DIM}[TCP]{Colors.RESET} Connected in {tcp_time*1000:.0f}ms")

            if parsed.scheme == "https":
                print(f"  {Colors.DIM}[SSL]{Colors.RESET} Performing TLS handshake...")
                ssl_start = time.time()
                ctx = ssl.create_default_context()
                wrapped = ctx.wrap_socket(sock, server_hostname=hostname)
                ssl_time = time.time() - ssl_start
                wrapped.close()
                print(f"  {Colors.DIM}[SSL]{Colors.RESET} Handshake in {ssl_time*1000:.0f}ms")
            else:
                sock.close()

            print(f"  {Colors.DIM}[HTTP]{Colors.RESET} Fetching page...")
            fetch_start = time.time()
            response = self.session.get(self.url, timeout=self.timeout)
            server_time = time.time() - fetch_start
            html_content = response.text
            download_time = time.time() - fetch_start
            total_time = time.time() - (dns_start)
            print(f"  {Colors.DIM}[HTTP]{Colors.RESET} Fetched in {download_time*1000:.0f}ms ({len(html_content):,} bytes)")

        except requests.exceptions.Timeout:
            print(f"\n  {Colors.RED}✗ Request timed out after {self.timeout}s{Colors.RESET}")
            return
        except requests.exceptions.ConnectionError as e:
            print(f"\n  {Colors.RED}✗ Connection failed: {e}{Colors.RESET}")
            return
        except Exception as e:
            print(f"\n  {Colors.RED}✗ Error: {e}{Colors.RESET}")
            return

        soup = BeautifulSoup(html_content, "html.parser")

        print(f"\n  {Colors.BOLD}Running performance checks...{Colors.RESET}\n")

        self.check_vitals(html_content, soup, download_time, response)
        self.check_timing(self.url, html_content, response, dns_time, tcp_time, ssl_time, server_time, download_time, total_time)
        self.check_resources(soup, self.url)
        self.check_resource_priority(soup, self.url)
        self.check_resource_hints(soup, self.url, response.headers)
        self.check_resource_loading_optimization(soup, self.url)
        self.check_render_blocking_resources(soup, self.url)
        self.check_critical_css(soup, html_content)
        self.check_js_execution_time(soup, self.url)
        self.check_layout_shift_detection(soup, html_content)
        self.check_long_task_detection(soup, html_content)
        self.check_main_thread_blocking(soup, html_content)
        self.check_resource_deduplication(soup, self.url)
        self.check_dead_code_estimation(soup, html_content)
        self.check_font_loading(soup, self.url)
        self.check_third_party_analysis(soup, self.url)
        self.check_caching(response.headers)
        self.check_compression(response.headers, html_content)
        self.check_redirects(self.url)
        self.check_protocol(self.url, response)
        self.check_service_worker(soup, html_content)
        self.check_rendering(soup, html_content)
        self.check_rendering_performance(soup, html_content)
        self.check_adaptive_image_loading(soup, html_content)
        self.check_content_visibility(soup, html_content)
        self.check_css_contain_property(soup, html_content)
        self.check_will_change_usage(soup, html_content)
        self.check_backdrop_filter_impact(soup, html_content)
        self.check_scroll_driven_animations(soup, html_content)
        self.check_images(soup, self.url)
        self.check_mobile(soup)
        self.check_modern_apis(soup, html_content)
        self.check_speculation_rules(soup, html_content, response.headers)
        self.check_view_transitions(soup, html_content)
        self.check_container_queries(soup, html_content)
        self.check_css_nesting(soup, html_content)
        self.check_webgpu(soup, html_content)
        self.check_webtransport(soup, html_content)
        self.check_performance_observer(soup, html_content)
        self.check_intersection_observer_lazy_loading(soup, html_content)
        self.check_request_idle_callback(soup, html_content)
        self.check_web_vitals_library(soup, html_content)
        self.check_rum_detection(soup, html_content)
        self.check_analytics_impact(soup, self.url)
        self.check_critical_css_extraction(soup, self.url)
        self.check_js_tree_shaking(soup, html_content)
        self.check_code_splitting(soup, html_content)
        self.check_bundle_optimization(soup, self.url)
        self.check_tree_shaking_effectiveness(soup, html_content)
        self.check_memory_leaks(soup, html_content)
        self.check_memory_usage(soup, html_content)
        self.check_real_user_simulation()
        self.check_mobile_desktop_comparison()
        self.check_core_web_vitals_refinement()
        self.check_performance_budgets()
        self.check_performance_budgets_strict()
        self.check_lighthouse_simulation()
        self.check_pagespeed_approximation()
        self.calculate_ux_score()

        score, grade = self.print_results()

        self.print_cwv_compliance_report()
        self.print_budget_dashboard()
        self.print_performance_dashboard()
        self.print_user_experience_score()
        self.print_cwv_summary()
        self.print_waterfall()
        self.print_waterfall_phases()
        self.print_speed_index_estimation()
        self.print_lighthouse_simulation()
        self.print_pagespeed_report()
        self.print_mobile_vs_desktop_comparison()
        self.print_lighthouse_breakdown()
        self.print_optimization_priorities()
        self.print_optimization_priority_matrix()
        self.print_effort_impact_matrix()

        if self.export != "none":
            print(f"\n  {Colors.BOLD}Exporting results...{Colors.RESET}")
            if self.export in ("json", "all"):
                self.export_json(score, grade)
            if self.export in ("csv", "all"):
                self.export_csv(score, grade)
            if self.export in ("html", "all"):
                self.export_html(score, grade)
            print()

        return score


def main():
    parser = argparse.ArgumentParser(
        description="PerfAnalyzer v7.0 - Comprehensive Website Performance Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com
  %(prog)s -u https://example.com --export html -v
  %(prog)s -u https://example.com -t 60 --export all
  %(prog)s -u https://example.com --no-color --export json
  %(prog)s -u https://example.com --device mobile --connection 3g
  %(prog)s -u https://example.com --device tablet --connection 4g
  %(prog)s -u https://example.com --strict-budget
        """,
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL to analyze")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    parser.add_argument("--export", choices=["all", "json", "csv", "html", "none"], default="none", help="Export format (default: none)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed resource breakdown")
    parser.add_argument("--device", choices=["mobile", "tablet", "desktop"], default="desktop", help="Device profile for simulation (default: desktop)")
    parser.add_argument("--connection", choices=["3g", "4g", "wifi", "fiber"], default="wifi", help="Connection profile for simulation (default: wifi)")
    parser.add_argument("--strict-budget", action="store_true", help="Enforce strict performance budgets (exit 1 on violations)")

    args = parser.parse_args()

    if args.no_color:
        Colors.disable()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    analyzer = PerfAnalyzer(
        url,
        timeout=args.timeout,
        export=args.export,
        verbose=args.verbose,
        device=args.device,
        connection=args.connection,
        strict_budget=args.strict_budget,
    )
    analyzer.analyze()

    if args.strict_budget and analyzer.raw_metrics.get("strict_budget_violations", 0) > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
