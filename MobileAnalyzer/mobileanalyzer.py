#!/usr/bin/env python3
import sys
import os
import json
import csv
import re
import argparse
import io
from urllib.parse import urlparse, urljoin

try:
    import requests
except ImportError:
    os.system("pip install requests")
    import requests

try:
    from bs4 import BeautifulSoup
except ImportError:
    os.system("pip install beautifulsoup4")
    from bs4 import BeautifulSoup

VERSION = "7.0"

BANNER = r"""
  __  __           _ ____            _       _
  |  \/  |___ _ __(_)  _ \  __ _ ___| |_ ___| |_
  | |\/| / _ \ '__| | | | |/ _` / __| __/ __| __|
  | |  | |  __/ |  | | |_| | (_| \__ \ || (__| |_
  |_|  |_|\___|_|  |_|____/ \__,_|___/\__\___|\__|

       ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗
       ██╔══██╗╚██╗██╔╝██╔══██╗████╗  ██║╚══██╔══╝
       ██████╔╝ ╚███╔╝ ███████║██╔██╗ ██║   ██║
       ██╔═══╝  ██╔██╗ ██╔══██║██║╚██╗██║   ██║
       ██║     ██╔╝ ██╗██║  ██║██║ ╚████║   ██║
       ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝

        Mobile Analyzer v{v}
        Mobile-Friendliness & PWA Analyzer
        Progressive Enhancement · Degradation · Offline
        Low-Bandwidth · Data Saver · UX · Conversion
        Engagement · Retention · PWA · Weighted Scoring
        Touch Feedback · Haptics · Motion · Battery · Geo
""".format(v=VERSION)

COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "white": "\033[97m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}

NO_COLORS = {k: "" for k in COLORS}

PERFORMANCE_BUDGETS = {
    "3g": {
        "name": "3G",
        "max_page_size_kb": 500,
        "max_total_size_kb": 1024,
        "max_requests": 40,
        "max_image_size_kb": 200,
        "max_js_size_kb": 100,
        "max_css_size_kb": 50,
        "estimated_rtt_ms": 300,
        "bandwidth_kbps": 750,
        "load_time_ms": 8000,
    },
    "4g": {
        "name": "4G",
        "max_page_size_kb": 1500,
        "max_total_size_kb": 3072,
        "max_requests": 80,
        "max_image_size_kb": 500,
        "max_js_size_kb": 300,
        "max_css_size_kb": 100,
        "estimated_rtt_ms": 100,
        "bandwidth_kbps": 1638,
        "load_time_ms": 5000,
    },
}

CORE_WEB_VITALS_MOBILE = {
    "lcp_ms": {"good": 2500, "poor": 4000},
    "fid_ms": {"good": 100, "poor": 300},
    "cls": {"good": 0.1, "poor": 0.25},
    "inp_ms": {"good": 200, "poor": 500},
    "ttfb_ms": {"good": 800, "poor": 1800},
}

READINESS_WEIGHTS = {
    "viewport": 3.0,
    "responsive": 3.0,
    "touch": 2.5,
    "touch_gesture": 2.0,
    "touch_feedback": 1.5,
    "haptic_feedback": 1.0,
    "device_motion": 1.0,
    "battery_api": 1.0,
    "network_info": 1.5,
    "geolocation": 1.0,
    "pwa": 1.5,
    "deep_pwa": 1.5,
    "performance": 2.0,
    "perf_budget": 2.0,
    "cwv": 2.0,
    "touch_perf": 1.5,
    "content": 2.0,
    "navigation": 1.5,
    "meta": 1.0,
    "images": 1.5,
    "mobile_form": 1.5,
    "amp": 0.5,
    "device": 1.5,
    "mobile_a11y": 2.5,
    "progressive_enhancement": 2.0,
    "graceful_degradation": 2.0,
    "offline_capability": 2.5,
    "low_bandwidth": 2.0,
    "data_saver": 1.5,
    "mobile_ux": 2.0,
}

PWA_SCORE_WEIGHTS = {
    "pwa": 1.25,
    "deep_pwa": 2.0,
    "meta": 0.5,
    "offline_capability": 1.75,
    "data_saver": 0.5,
    "network_info": 0.75,
    "mobile_a11y": 0.5,
}

TOUCH_SCORE_WEIGHTS = {
    "touch": 1.0,
    "touch_gesture": 1.5,
    "touch_perf": 1.0,
    "touch_feedback": 1.25,
    "haptic_feedback": 0.75,
}

MOBILE_UX_SCORE_WEIGHTS = {
    "progressive_enhancement": 1.5,
    "graceful_degradation": 1.5,
    "navigation": 1.5,
    "touch": 1.25,
    "touch_gesture": 1.0,
    "touch_feedback": 1.5,
    "haptic_feedback": 0.75,
    "content": 1.25,
    "mobile_form": 1.25,
    "mobile_a11y": 1.75,
    "viewport": 1.0,
    "responsive": 1.25,
    "mobile_ux": 2.25,
    "mobile_conversion": 1.5,
    "geolocation": 0.5,
    "device_motion": 0.5,
}

MOBILE_PERF_SCORE_WEIGHTS = {
    "performance": 1.75,
    "perf_budget": 2.0,
    "cwv": 1.75,
    "touch_perf": 1.0,
    "low_bandwidth": 1.75,
    "data_saver": 1.25,
    "network_info": 1.25,
    "battery_api": 0.75,
    "offline_capability": 0.75,
    "images": 0.75,
}

NETWORK_ADAPT_SCORE_WEIGHTS = {
    "network_info": 2.0,
    "data_saver": 1.75,
    "low_bandwidth": 1.5,
    "perf_budget": 1.5,
    "offline_capability": 1.0,
}

ENGAGEMENT_RETENTION_WEIGHTS = {
    "mobile_engagement": 1.5,
    "mobile_retention": 1.5,
    "pwa": 1.0,
    "deep_pwa": 1.25,
    "offline_capability": 1.0,
}

CATEGORY_LABELS = {
    "viewport": "Viewport Meta",
    "responsive": "Responsive Design",
    "touch": "Touch & Tap",
    "touch_gesture": "Touch Gestures",
    "touch_feedback": "Touch Feedback",
    "haptic_feedback": "Haptic Feedback",
    "device_motion": "Device Motion API",
    "battery_api": "Battery API",
    "network_info": "Network Information API",
    "geolocation": "Geolocation API",
    "pwa": "Progressive Web App",
    "deep_pwa": "Deep PWA Analysis",
    "performance": "Mobile Performance",
    "perf_budget": "Performance Budget",
    "cwv": "Core Web Vitals",
    "touch_perf": "Touch Performance",
    "content": "Mobile Content",
    "navigation": "Mobile Navigation",
    "meta": "Mobile Meta Tags",
    "images": "Mobile Images",
    "mobile_form": "Mobile Forms",
    "amp": "AMP Detection",
    "device": "Device Features",
    "mobile_a11y": "Mobile Accessibility",
    "progressive_enhancement": "Progressive Enhancement",
    "graceful_degradation": "Graceful Degradation",
    "offline_capability": "Offline Capability",
    "low_bandwidth": "Low-Bandwidth Optimization",
    "data_saver": "Data Saver Support",
    "mobile_ux": "Mobile UX Patterns",
    "mobile_conversion": "Mobile Conversion",
    "mobile_engagement": "Mobile Engagement",
    "mobile_retention": "Mobile Retention",
}

CATEGORY_ORDER = [
    "viewport", "responsive", "touch", "touch_gesture", "touch_feedback", "haptic_feedback",
    "pwa", "deep_pwa", "offline_capability", "performance", "perf_budget",
    "low_bandwidth", "data_saver", "network_info", "battery_api", "cwv",
    "touch_perf", "content", "navigation", "meta",
    "images", "mobile_form", "device", "device_motion", "geolocation", "mobile_a11y",
    "progressive_enhancement", "graceful_degradation",
    "mobile_ux", "mobile_conversion", "mobile_engagement", "mobile_retention",
    "amp",
]

ROADMAP_PRIORITIES = {
    "viewport": 1,
    "responsive": 2,
    "touch": 3,
    "touch_gesture": 4,
    "mobile_a11y": 5,
    "navigation": 6,
    "content": 7,
    "images": 8,
    "mobile_form": 9,
    "performance": 10,
    "perf_budget": 11,
    "cwv": 12,
    "touch_perf": 13,
    "device": 14,
    "pwa": 15,
    "deep_pwa": 16,
    "meta": 17,
    "amp": 18,
    "progressive_enhancement": 19,
    "graceful_degradation": 20,
    "offline_capability": 21,
    "low_bandwidth": 22,
    "data_saver": 23,
    "mobile_ux": 24,
    "mobile_conversion": 25,
    "mobile_engagement": 26,
    "mobile_retention": 27,
    "touch_feedback": 28,
    "haptic_feedback": 29,
    "network_info": 30,
    "battery_api": 31,
    "device_motion": 32,
    "geolocation": 33,
}

ROADMAP_OWNERS = {
    "viewport": "Frontend",
    "responsive": "Frontend / Design",
    "touch": "Frontend",
    "touch_gesture": "Frontend",
    "touch_feedback": "Frontend / Design",
    "haptic_feedback": "Mobile Eng",
    "device_motion": "Mobile Eng",
    "battery_api": "Frontend / Perf",
    "network_info": "Frontend / Perf",
    "geolocation": "Product / Frontend",
    "pwa": "Frontend / Platform",
    "deep_pwa": "Frontend / Platform",
    "performance": "Perf Eng",
    "perf_budget": "Perf Eng",
    "cwv": "Perf Eng",
    "touch_perf": "Frontend / Perf",
    "content": "Content / Design",
    "navigation": "Design / Frontend",
    "meta": "SEO / Frontend",
    "images": "Design / Perf",
    "mobile_form": "Frontend / UX",
    "amp": "SEO",
    "device": "Frontend",
    "mobile_a11y": "A11y / Frontend",
    "progressive_enhancement": "Frontend",
    "graceful_degradation": "Frontend",
    "offline_capability": "Frontend / Platform",
    "low_bandwidth": "Perf Eng",
    "data_saver": "Perf Eng",
    "mobile_ux": "Design / UX",
    "mobile_conversion": "Growth / UX",
    "mobile_engagement": "Product",
    "mobile_retention": "Product",
}

SIGNAL_LABELS = {
    "viewport": "Viewport meta",
    "mobile_first": "Mobile-first CSS",
    "breakpoints": "Breakpoints",
    "safe_area": "Safe-area insets",
    "dark_mode": "Dark mode",
    "orientation": "Orientation handling",
    "touch": "Touch support",
    "hover": "Hover handling",
    "foldable": "Foldable layout",
    "haptic": "Haptic feedback",
    "ar_vr": "AR/VR support",
    "zoom": "User zoom",
    "responsive_images": "Responsive images",
    "low_bandwidth": "Low-bandwidth opts",
    "data_saver": "Data saver",
    "offline": "Offline access",
    "touch_feedback": "Touch feedback",
    "motion": "Device motion",
    "battery": "Battery awareness",
    "network_info": "Network info API",
    "geolocation": "Geolocation",
}

DEVICE_CLASSES = [
    ("Small Phone", "320-375px",
     ["viewport", "breakpoints", "touch", "zoom", "touch_feedback"],
     ["mobile_first", "dark_mode", "low_bandwidth", "haptic"]),
    ("Large Phone", "376-428px",
     ["viewport", "orientation", "dark_mode", "touch", "touch_feedback"],
     ["safe_area", "responsive_images", "data_saver", "haptic"]),
    ("Foldable Phone", "600px+ unfolded",
     ["viewport", "foldable", "safe_area", "orientation"],
     ["mobile_first", "dark_mode", "offline", "motion"]),
    ("Tablet", "600-1024px",
     ["viewport", "breakpoints", "responsive_images"],
     ["touch", "hover", "data_saver", "network_info"]),
    ("Desktop", "1024px+",
     ["viewport", "breakpoints", "hover"],
     ["dark_mode", "mobile_first", "geolocation"]),
    ("Low-Bandwidth Device", "2G/3G constrained",
     ["viewport", "touch", "low_bandwidth", "data_saver"],
     ["offline", "mobile_first", "responsive", "network_info"]),
    ("Smartwatch", "480px square",
     ["viewport", "touch", "zoom"],
     ["haptic", "dark_mode", "low_bandwidth"]),
    ("Feature Phone", "2G keypad",
     ["viewport", "content", "zoom"],
     ["low_bandwidth", "mobile_first", "data_saver"]),
    ("In-Car Display", "touch while driving",
     ["viewport", "breakpoints", "touch", "touch_feedback"],
     ["dark_mode", "orientation", "network_info"]),
]

UX_PATTERN_DEFS = {
    "hamburger_menu": ["hamburger", "menu-toggle", "nav-toggle", "burger"],
    "bottom_navigation": ["bottom-nav", "bottomnav", "tab-bar", "tabbar"],
    "sticky_header": ["sticky", "fixed-header", "navbar-fixed"],
    "swipe_carousel": ["carousel", "swiper", "swipeable"],
    "skeleton_loading": ["skeleton", "shimmer", "placeholder-loading"],
    "pull_to_refresh": ["pull-to-refresh", "pulltorefresh", "overscroll"],
    "infinite_scroll": ["infinite-scroll", "infinite_scroll", "load-more"],
    "modal_bottom_sheet": ["bottom-sheet", "bottomsheet", "modal", "dialog"],
    "stepper_wizard": ["stepper", "wizard", "step-form", "multi-step"],
    "toast_feedback": ["toast", "snackbar", "notification-bar"],
    "floating_action_button": ["fab", "floating-action", "float-btn"],
    "search_pattern": ["search-input", "search-bar", "type=\"search\"", "role=\"search\""],
}

CONVERSION_PATTERNS = {
    "sticky_cta": ["sticky-cta", "fixed-cta", "sticky-bottom", "sticky-footer"],
    "trust_signals": ["trust", "secure", "ssl", "guarantee", "money-back", "badge"],
    "social_proof": ["review", "testimonial", "rating", "star-rating", "testimonial"],
    "urgency_cues": ["limited-time", "countdown", "only-left", "hurry", "deal-ending"],
    "checkout_streamlined": ["one-page-checkout", "guest-checkout", "express-checkout", "single-page"],
    "payment_options": ["apple-pay", "google-pay", "payment-request", "stripe", "paypal"],
    "form_autofill": ["autocomplete", "autofill", "one-time-code"],
    "click_to_call": ["tel:", "call-now", "click-to-call", "phone-link"],
    "exit_intent": ["exit-intent", "mouseleave", "exitpopup", "beforeunload"],
    "personalization": ["recommend", "for-you", "recently-viewed", "continue-watching"],
}

ENGAGEMENT_PATTERNS = {
    "push_notifications": ["pushmanager", "push-subscription", "notification.permission"],
    "share_features": ["navigator.share", "share-button", "social-share"],
    "comments_discussion": ["comment-form", "disqus", "comments-section", "discussion"],
    "live_activity": ["live-stream", "realtime", "websocket", "socket.io", "sse"],
    "gamification": ["streak", "leaderboard", "badge", "points", "reward"],
    "user_generated_content": ["upload", "post-photo", "create-post", "user-content"],
    "personalized_feeds": ["feed", "for-you", "timeline", "algorithm"],
    "interactive_content": ["quiz", "poll", "interactive", "calculator", "configurator"],
    "rich_media": ["video", "lottie", "animation", "parallax"],
    "community_signals": ["forum", "community", "group", "follower"],
}

RETENTION_PATTERNS = {
    "pwa_install": ["beforeinstallprompt", "install-prompt", "appinstalled"],
    "account_system": ["login", "signup", "register", "sign-in", "my-account"],
    "offline_access": ["offline", "service-worker", "caches.open", "cache-first"],
    "email_capture": ["newsletter", "email-signup", "subscribe", "mailing-list"],
    "loyalty_program": ["loyalty", "points", "rewards", "vip", "membership"],
    "deep_linking": ["deeplink", "deep-link", "universal-link", "app-link"],
    "saved_preferences": ["localStorage", "user-preferences", "settings", "wishlist"],
    "onboarding_flow": ["onboarding", "tour", "walkthrough", "getting-started"],
    "reengagement": ["reminder", "notification", "digest", "weekly-update"],
    "content_freshness": ["latest", "recent", "new-arrivals", "updated", "blog"],
}


def get_colors(use_color):
    return COLORS if use_color else NO_COLORS


def colored(text, color, use_color=True):
    c = get_colors(use_color)
    return f"{c.get(color, '')}{text}{c['reset'] if use_color else ''}"


def parse_args():
    parser = argparse.ArgumentParser(
        description="MobileAnalyzer v7.0 - Mobile-Friendliness & PWA Analyzer",
        add_help=False,
    )
    parser.add_argument("-u", "--url", required=False, help="Target URL")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout (default: 15)")
    parser.add_argument("--export", choices=["all", "json", "csv", "html", "none"], default="none", help="Export format")
    parser.add_argument("--no-color", action="store_true", help="Disable colors")
    parser.add_argument("--network", choices=["3g", "4g"], default="4g", help="Network simulation for budget checks (default: 4g)")
    parser.add_argument("-h", "--help", action="store_true", help="Show help")
    return parser.parse_args()


def fetch_page(url, timeout):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
        }
        resp = requests.get(url, timeout=timeout, headers=headers, verify=False)
        resp.raise_for_status()
        return resp
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] Failed to fetch URL: {e}", "red"))
        sys.exit(1)


def extract_css(soup):
    css_text = ""
    for style_tag in soup.find_all("style"):
        if style_tag.string:
            css_text += style_tag.string + "\n"
    for link in soup.find_all("link", rel="stylesheet"):
        href = link.get("href")
        if href:
            try:
                if href.startswith("//"):
                    href = "https:" + href
                elif href.startswith("/"):
                    parsed = urlparse(soup.find("base").get("href", "") if soup.find("base") else "")
                    base = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else ""
                    href = base + href
                elif not href.startswith("http"):
                    parsed = urlparse(soup.find("meta", attrs={"property": "og:url"}).get("content", "") if soup.find("meta", attrs={"property": "og:url"}) else "")
                    base = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else ""
                    href = base + "/" + href
                r = requests.get(href, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
                css_text += r.text + "\n"
            except Exception:
                pass
    return css_text


def extract_js_info(soup):
    scripts = soup.find_all("script", src=True)
    inline_scripts = soup.find_all("script", src=False)
    total_size = 0
    for s in inline_scripts:
        if s.string:
            total_size += len(s.string.encode("utf-8"))
    return {
        "external_count": len(scripts),
        "inline_count": len(inline_scripts),
        "inline_size": total_size,
        "total_scripts": len(scripts) + len(inline_scripts),
    }


def extract_images(soup):
    images = soup.find_all("img")
    result = []
    for img in images:
        result.append({
            "src": img.get("src", ""),
            "width": img.get("width"),
            "height": img.get("height"),
            "srcset": img.get("srcset"),
            "loading": img.get("loading"),
            "alt": img.get("alt"),
        })
    return result


def fetch_manifest(url, soup, timeout):
    manifest_link = soup.find("link", rel="manifest")
    if not manifest_link:
        return None
    href = manifest_link.get("href")
    if not href:
        return None
    try:
        manifest_url = urljoin(url, href)
        headers = {"User-Agent": "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36"}
        resp = requests.get(manifest_url, timeout=timeout, headers=headers, verify=False)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


def fetch_service_worker(url, timeout):
    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        sw_urls = ["/sw.js", "/service-worker.js", "/service_worker.js", "/sw.min.js", "/worker.js", "/offline.js"]
        headers = {"User-Agent": "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36"}
        for sw_path in sw_urls:
            sw_url = base + sw_path
            try:
                resp = requests.get(sw_url, timeout=min(timeout, 5), headers=headers, verify=False)
                if resp.status_code == 200 and "function" in resp.text.lower():
                    return {"url": sw_url, "content": resp.text[:50000]}
            except Exception:
                continue
    except Exception:
        pass
    return None


class MobileAnalyzer:
    def __init__(self, url, timeout=15, network="4g"):
        self.url = url
        self.timeout = timeout
        self.network = network
        self.budget = PERFORMANCE_BUDGETS.get(network, PERFORMANCE_BUDGETS["4g"])
        self.resp = fetch_page(url, timeout)
        self.soup = BeautifulSoup(self.resp.text, "html.parser")
        self.css_text = extract_css(self.soup)
        self.js_info = extract_js_info(self.soup)
        self.images = extract_images(self.soup)
        self.manifest = fetch_manifest(url, self.soup, timeout)
        self.sw_data = fetch_service_worker(url, timeout)
        self.js_text_full = ""
        for s in self.soup.find_all("script"):
            if s.string:
                self.js_text_full += s.string.lower()
        self.html_text_lower = self.resp.text.lower()
        self.results = {}
        self.total_score = 0
        self.max_score = 0
        self.mobile_readiness = 0
        self.pwa_score = 0
        self.touch_score = 0
        self.perf_budget_score = 0
        self.mobile_ux_score = 0
        self.mobile_perf_score = 0
        self.roadmap = []
        self.device_matrix = []
        self.pwa_report = {}
        self.a11y_assessment = {}
        self.perf_load_estimate_ms = 0
        self.ux_patterns_analysis = {}
        self.conversion_analysis = {}
        self.engagement_analysis = {}
        self.retention_analysis = {}
        self.network_adapt_score = 0
        self.mobile_capability_score = 0

    def _add_check(self, category, check, passed, points):
        if category not in self.results:
            self.results[category] = {"category": category, "score": 0, "max": 0, "details": []}
        self.results[category]["details"].append({"check": check, "passed": passed, "points": points})
        self.results[category]["max"] += points
        self.max_score += points
        if passed:
            self.results[category]["score"] += points
            self.total_score += points

    def _check_passed(self, category, substring):
        data = self.results.get(category)
        if not data:
            return None
        needle = substring.lower()
        for d in data["details"]:
            if needle in d["check"].lower():
                return d["passed"]
        return None

    def _category_pct(self, cat):
        data = self.results.get(cat)
        if not data or data.get("max", 0) <= 0:
            return 0.0
        return round((data["score"] / data["max"]) * 100, 1)

    def _cat_ok(self, cat, threshold=0.5):
        data = self.results.get(cat)
        if not data or data.get("max", 0) <= 0:
            return False
        return (data["score"] / data["max"]) >= threshold

    def check_viewport(self):
        meta_vp = self.soup.find("meta", attrs={"name": "viewport"})
        if meta_vp:
            self._add_check("viewport", "Viewport meta tag exists", True, 3)
            content = meta_vp.get("content", "")
            if "width=device-width" in content:
                self._add_check("viewport", "width=device-width present", True, 3)
            else:
                self._add_check("viewport", "width=device-width present", False, 3)
            if "initial-scale=1" in content or "initial-scale=1.0" in content:
                self._add_check("viewport", "initial-scale=1.0 present", True, 3)
            else:
                self._add_check("viewport", "initial-scale=1.0 present", False, 3)
            if "user-scalable=no" in content or "user-scalable=0" in content:
                self._add_check("viewport", "user-scalable=no (bad for a11y)", False, 3)
            else:
                self._add_check("viewport", "user-scalable=no not used (good)", True, 3)
            if "maximum-scale=1" in content or "maximum-scale=1.0" in content:
                self._add_check("viewport", "maximum-scale=1.0 (bad for a11y)", False, 3)
            else:
                self._add_check("viewport", "maximum-scale restriction not used (good)", True, 3)
            if "viewport-fit" in content:
                self._add_check("viewport", "viewport-fit declared for notched devices", True, 2)
            else:
                self._add_check("viewport", "viewport-fit declared for notched devices", False, 2)
        else:
            self._add_check("viewport", "Viewport meta tag exists", False, 15)

    def check_responsive(self):
        media_queries = re.findall(r"@media\s*\(", self.css_text)
        if len(media_queries) > 0:
            self._add_check("responsive", f"CSS media queries found ({len(media_queries)})", True, 4)
        else:
            self._add_check("responsive", "CSS media queries found", False, 4)
        frameworks = ["bootstrap", "foundation", "tailwind", "bulma", "materialize"]
        html_lower = self.html_text_lower
        found_fw = [f for f in frameworks if f in html_lower]
        if found_fw:
            self._add_check("responsive", f"Responsive framework detected ({', '.join(found_fw)})", True, 3)
        else:
            self._add_check("responsive", "Responsive framework detected", False, 3)
        responsive_imgs = len(self.soup.find_all("picture")) + len([i for i in self.images if i.get("srcset")])
        if responsive_imgs > 0:
            self._add_check("responsive", f"Responsive images found ({responsive_imgs})", True, 4)
        else:
            self._add_check("responsive", "Responsive images found", False, 4)
        pct_widths = len(re.findall(r"width\s*:\s*\d+%", self.css_text))
        px_widths = len(re.findall(r"width\s*:\s*\d+px", self.css_text))
        if pct_widths > px_widths:
            self._add_check("responsive", "Flexible percentage-based layouts detected", True, 4)
        else:
            self._add_check("responsive", "Flexible percentage-based layouts detected", False, 4)

        min_w = len(re.findall(r"min-width\s*:", self.css_text))
        max_w = len(re.findall(r"max-width\s*:", self.css_text))
        if min_w > 0 and min_w >= max_w:
            self._add_check("responsive", f"Mobile-first CSS detected ({min_w} min-width vs {max_w} max-width queries)", True, 3)
        elif max_w > 0:
            self._add_check("responsive", f"Desktop-first CSS detected ({max_w} max-width vs {min_w} min-width queries) - prefer mobile-first", False, 3)
        else:
            self._add_check("responsive", "Mobile-first CSS detected (no min/max-width queries found)", False, 3)

        bp_values = sorted({int(v) for v in re.findall(r"(?:min|max)-width\s*:\s*(\d+)", self.css_text)})
        if len(bp_values) >= 2:
            shown = ", ".join(str(b) for b in bp_values[:8])
            more = "" if len(bp_values) <= 8 else ", +more"
            self._add_check("responsive", f"Responsive breakpoints defined ({len(bp_values)}: {shown}{more}px)", True, 3)
        elif len(bp_values) == 1:
            self._add_check("responsive", f"Only one breakpoint defined ({bp_values[0]}px) - add more device tiers", False, 3)
        else:
            self._add_check("responsive", "No width breakpoints defined in CSS", False, 3)

        if "@container" in self.css_text:
            self._add_check("responsive", "CSS container queries detected", True, 1)
        else:
            self._add_check("responsive", "CSS container queries detected", False, 1)

        modern_vu = len(re.findall(r"\b(?:dvh|svh|lvh)\b", self.css_text))
        legacy_vu = len(re.findall(r"\b(?:vh|vw)\b", self.css_text))
        if modern_vu > 0:
            self._add_check("responsive", f"Dynamic viewport units found ({modern_vu} dvh/svh/lvh)", True, 2)
        elif legacy_vu > 0:
            self._add_check("responsive", f"Only legacy vh/vw units found ({legacy_vu}) - prefer dvh/svh for mobile browser chrome", False, 2)
        else:
            self._add_check("responsive", "No viewport-relative units found for fluid layouts", False, 2)

    def check_progressive_enhancement(self):
        css = self.css_text
        js = self.js_text_full
        html = self.html_text_lower

        supports_count = len(re.findall(r"@supports\s+", css))
        if supports_count > 0:
            self._add_check("progressive_enhancement", f"CSS feature queries found (@supports x{supports_count})", True, 3)
        else:
            self._add_check("progressive_enhancement", "CSS feature queries found (@supports)", False, 3)

        semantic_tags = ["header", "nav", "main", "section", "article", "aside", "footer"]
        found_semantic = [t for t in semantic_tags if self.soup.find(t)]
        if len(found_semantic) >= 4:
            joined = ", ".join(found_semantic)
            self._add_check("progressive_enhancement", f"Semantic HTML5 elements used ({len(found_semantic)}/7: {joined})", True, 3)
        elif len(found_semantic) > 0:
            self._add_check("progressive_enhancement", f"Semantic HTML5 elements used ({len(found_semantic)}/7)", False, 3)
        else:
            self._add_check("progressive_enhancement", "Semantic HTML5 elements used (0/7)", False, 3)

        feature_detect = any(e in js for e in [
            "matchmedia", "modernizr", "featuredetect", "feature-detect",
            "'geolocation' in", '"geolocation" in', "'serviceworker' in",
            '"serviceworker" in', "in navigator", "in window", "typeof navigator",
            "cs.supports", "css.supports",
        ])
        if feature_detect:
            self._add_check("progressive_enhancement", "JavaScript feature detection found", True, 2)
        else:
            self._add_check("progressive_enhancement", "JavaScript feature detection found", False, 2)

        noscript_count = len(self.soup.find_all("noscript"))
        if noscript_count > 0:
            self._add_check("progressive_enhancement", f"<noscript> fallbacks present ({noscript_count})", True, 2)
        else:
            self._add_check("progressive_enhancement", "<noscript> fallbacks present", False, 2)

        polyfill_signals = ["polyfill", "core-js", "babel-polyfill", "picturefill", "html5shiv", "respond.js"]
        polyfill_found = [p for p in polyfill_signals if p in html or p in js]
        if polyfill_found:
            joined = ", ".join(polyfill_found[:3])
            self._add_check("progressive_enhancement", f"Polyfills detected ({joined})", True, 1)
        else:
            self._add_check("progressive_enhancement", "Polyfills detected (core-js/picturefill/html5shiv)", False, 1)

        progressive_imgs = len(self.soup.find_all("picture")) + len([i for i in self.images if i.get("srcset")])
        if progressive_imgs > 0:
            self._add_check("progressive_enhancement", f"Progressive image markup present ({progressive_imgs} picture/srcset)", True, 2)
        else:
            self._add_check("progressive_enhancement", "Progressive image markup present (picture/srcset)", False, 2)

        headings = len(self.soup.find_all(["h1", "h2", "h3"]))
        if headings >= 2:
            self._add_check("progressive_enhancement", f"Server-rendered content baseline ({headings} headings in HTML)", True, 2)
        else:
            self._add_check("progressive_enhancement", f"Server-rendered content baseline ({headings} headings in HTML)", False, 2)

        aria_roles = len([el for el in self.soup.find_all(True) if el.get("role")])
        if aria_roles > 0:
            self._add_check("progressive_enhancement", f"Explicit ARIA roles enhance semantics ({aria_roles} elements)", True, 1)
        else:
            self._add_check("progressive_enhancement", "Explicit ARIA roles enhance semantics", False, 1)

    def check_graceful_degradation(self):
        css = self.css_text
        js = self.js_text_full
        html = self.html_text_lower

        try_blocks = len(re.findall(r"\btry\s*\{", js))
        catch_blocks = len(re.findall(r"\bcatch\s*\(", js))
        if try_blocks + catch_blocks >= 2:
            self._add_check("graceful_degradation", f"Try/catch error handling found ({try_blocks + catch_blocks} blocks)", True, 3)
        elif try_blocks + catch_blocks == 1:
            self._add_check("graceful_degradation", "Try/catch error handling found (1 block)", True, 2)
        else:
            self._add_check("graceful_degradation", "Try/catch error handling found", False, 3)

        global_error = any(e in js for e in [
            "onerror", "addEventListener('error'", 'addEventListener("error"',
            "onunhandledrejection", "errorboundary", "error-boundary",
        ])
        if global_error:
            self._add_check("graceful_degradation", "Global error handler / boundary detected", True, 2)
        else:
            self._add_check("graceful_degradation", "Global error handler / boundary detected", False, 2)

        noscript_count = len(self.soup.find_all("noscript"))
        if noscript_count > 0:
            self._add_check("graceful_degradation", f"No-JS degradation path present ({noscript_count} noscript blocks)", True, 2)
        else:
            self._add_check("graceful_degradation", "No-JS degradation path present (noscript)", False, 2)

        picture_fallback = len(self.soup.find_all("picture")) > 0
        video_fallback = False
        for v in self.soup.find_all("video"):
            if v.find("source") or v.find("a") or (v.string and v.string.strip()):
                video_fallback = True
        if picture_fallback or video_fallback:
            self._add_check("graceful_degradation", "Media fallback content detected (picture/video fallback)", True, 2)
        else:
            self._add_check("graceful_degradation", "Media fallback content detected (picture/video fallback)", False, 2)

        supports_blocks = len(re.findall(r"@supports\s+", css))
        legacy_fallback = bool(re.search(r"(?:-webkit-|-moz-|-ms-)", css))
        if supports_blocks > 0 or legacy_fallback:
            vendor_text = "yes" if legacy_fallback else "no"
            self._add_check("graceful_degradation", f"CSS fallback declarations present ({supports_blocks} @supports, vendor prefixes: {vendor_text})", True, 2)
        else:
            self._add_check("graceful_degradation", "CSS fallback declarations present (@supports / vendor prefixes)", False, 2)

        aria_live = any(el.get("aria-live") for el in self.soup.find_all(True))
        if aria_live:
            self._add_check("graceful_degradation", "aria-live regions for async updates", True, 1)
        else:
            self._add_check("graceful_degradation", "aria-live regions for async updates", False, 1)

        fallback_ui = any(e in html for e in [
            "error-message", "empty-state", "no-results", "loading-fallback",
            "retry", "try-again", "offline", "something went wrong",
        ])
        if fallback_ui:
            self._add_check("graceful_degradation", "Error/empty-state UI patterns detected", True, 2)
        else:
            self._add_check("graceful_degradation", "Error/empty-state UI patterns detected", False, 2)

        polyfill = any(p in html or p in js for p in ["polyfill", "core-js", "html5shiv", "respond.js", "picturefill"])
        if polyfill:
            self._add_check("graceful_degradation", "Polyfill fallback for older browsers", True, 1)
        else:
            self._add_check("graceful_degradation", "Polyfill fallback for older browsers", False, 1)

    def check_offline_capability(self):
        js = self.js_text_full
        html = self.html_text_lower
        sw_content = self.sw_data.get("content", "") if self.sw_data else ""
        sw_lower = sw_content.lower() if sw_content else ""
        combined = js + html + sw_lower

        has_sw = bool(self.sw_data) or "serviceworker" in html
        if has_sw:
            self._add_check("offline_capability", "Service Worker available for offline caching", True, 3)
        else:
            self._add_check("offline_capability", "Service Worker available for offline caching", False, 3)

        cache_api = any(e in combined for e in [
            "caches.open", "caches.match", "cache.put", "cachestorage",
            "cache.addall", "cache.add", "caches.has",
        ])
        if cache_api:
            self._add_check("offline_capability", "Cache Storage API usage detected", True, 2)
        else:
            self._add_check("offline_capability", "Cache Storage API usage detected", False, 2)

        offline_route = any(e in combined for e in [
            "offline.html", "offline-page", "offline_route", "offline-route",
            "showoffline", "offline fallback", "serveoffline",
        ])
        if offline_route:
            self._add_check("offline_capability", "Dedicated offline fallback page/route detected", True, 2)
        else:
            self._add_check("offline_capability", "Dedicated offline fallback page/route detected", False, 2)

        online_events = (
            "navigator.online" in combined
            or bool(re.search(r"addEventListener\(\s*['\"](?:online|offline)['\"]", js))
            or "connection.change" in combined
            or "online/offline" in combined
        )
        if online_events:
            self._add_check("offline_capability", "Connectivity monitoring (navigator.onLine / online-offline events)", True, 2)
        else:
            self._add_check("offline_capability", "Connectivity monitoring (navigator.onLine / online-offline events)", False, 2)

        persistence = any(e in combined for e in ["localstorage", "sessionstorage", "indexeddb", "idb.", "idb("])
        if persistence:
            self._add_check("offline_capability", "Client-side persistence detected (localStorage/IndexedDB)", True, 2)
        else:
            self._add_check("offline_capability", "Client-side persistence detected (localStorage/IndexedDB)", False, 2)

        bg_sync = any(e in combined for e in ["backgroundsync", "background-sync", "periodicsync", "sync.register"])
        if bg_sync:
            self._add_check("offline_capability", "Background sync queues offline actions", True, 2)
        else:
            self._add_check("offline_capability", "Background sync queues offline actions", False, 2)

        precache = any(e in combined for e in ["precache", "cache.addall", "addall(", "installcache", "workbox.precache"])
        if precache:
            self._add_check("offline_capability", "Precaching of app shell assets detected", True, 2)
        else:
            self._add_check("offline_capability", "Precaching of app shell assets detected", False, 2)

        fetch_strategy = any(e in combined for e in [
            "stale-while-revalidate", "stalewhilerevalidate", "networkfirst", "network-first",
            "cachefirst", "cache-first",
        ])
        if fetch_strategy:
            self._add_check("offline_capability", "Offline-aware fetch strategy in service worker", True, 1)
        else:
            self._add_check("offline_capability", "Offline-aware fetch strategy in service worker", False, 1)

    def check_low_bandwidth(self):
        css = self.css_text
        js = self.js_text_full
        html = self.html_text_lower

        preload = len(self.soup.find_all("link", rel="preload"))
        preconnect = len(self.soup.find_all("link", rel="preconnect"))
        dns_prefetch = len(self.soup.find_all("link", rel="dns-prefetch"))
        if preload + preconnect + dns_prefetch > 0:
            self._add_check("low_bandwidth", f"Resource hints present (preload={preload}, preconnect={preconnect}, dns-prefetch={dns_prefetch})", True, 3)
        else:
            self._add_check("low_bandwidth", "Resource hints present (preload/preconnect/dns-prefetch)", False, 3)

        scripts = self.soup.find_all("script", src=True)
        async_defer = len([s for s in scripts if s.get("async") or s.get("defer") or s.get("type") == "module"])
        if not scripts or async_defer >= len(scripts) * 0.5:
            self._add_check("low_bandwidth", f"Non-blocking script loading ({async_defer}/{len(scripts)} async/defer)", True, 2)
        else:
            self._add_check("low_bandwidth", f"Non-blocking script loading ({async_defer}/{len(scripts)} async/defer)", False, 2)

        minified = sum(1 for s in scripts if ".min." in str(s.get("src") or ""))
        minified += sum(1 for l in self.soup.find_all("link", rel="stylesheet") if ".min." in str(l.get("href") or ""))
        if minified > 0:
            self._add_check("low_bandwidth", f"Minified assets detected ({minified} .min files)", True, 1)
        else:
            self._add_check("low_bandwidth", "Minified assets detected (.min.js/.min.css)", False, 1)

        headers = getattr(self.resp, "headers", {}) or {}
        encoding = str(headers.get("content-encoding", "")).lower()
        if encoding in ("gzip", "br", "zstd", "deflate"):
            self._add_check("low_bandwidth", f"Response compression active ({encoding})", True, 3)
        else:
            self._add_check("low_bandwidth", "Response compression active (gzip/br not detected)", False, 3)

        page_kb = len(self.resp.content) / 1024
        if page_kb <= self.budget["max_page_size_kb"]:
            self._add_check("low_bandwidth", f"HTML payload within low-bandwidth target ({page_kb:.0f}KB <= {self.budget['max_page_size_kb']}KB)", True, 3)
        else:
            self._add_check("low_bandwidth", f"HTML payload exceeds low-bandwidth target ({page_kb:.0f}KB > {self.budget['max_page_size_kb']}KB)", False, 3)

        inline_style_bytes = sum(len(st.string.encode("utf-8")) for st in self.soup.find_all("style") if st.string)
        if inline_style_bytes > 500:
            kb_val = inline_style_bytes / 1024
            self._add_check("low_bandwidth", f"Inlined critical CSS present ({kb_val:.1f}KB)", True, 2)
        else:
            self._add_check("low_bandwidth", "Inlined critical CSS present", False, 2)

        hosts = set()
        for tag, attr in [("script", "src"), ("link", "href"), ("img", "src")]:
            for el in self.soup.find_all(tag):
                val = str(el.get(attr) or "")
                if val.startswith("http"):
                    hosts.add(urlparse(val).netloc)
        if len(hosts) >= 2:
            self._add_check("low_bandwidth", f"Static assets served from {len(hosts)} origins (CDN sharding)", True, 1)
        else:
            self._add_check("low_bandwidth", f"Static asset origins ({len(hosts)}) - consider CDN sharding", False, 1)

        font_system = bool(re.search(r"font-family\s*:[^;]*(?:system-ui|-apple-system|Segoe UI|Roboto|sans-serif)", css))
        font_display = bool(re.search(r"font-display\s*:\s*(swap|optional|fallback)", css))
        if font_display or font_system:
            fd_text = "yes" if font_display else "no"
            sys_text = "yes" if font_system else "no"
            self._add_check("low_bandwidth", f"Font loading budget-aware (font-display: {fd_text}, system stack: {sys_text})", True, 2)
        else:
            self._add_check("low_bandwidth", "Font loading budget-aware (font-display / system stack)", False, 2)

        dynamic_import = any(e in js for e in ["import(", "react.lazy", "next/dynamic", "dynamicimport"])
        if dynamic_import:
            self._add_check("low_bandwidth", "Code splitting / dynamic import detected", True, 1)
        else:
            self._add_check("low_bandwidth", "Code splitting / dynamic import detected", False, 1)

    def check_data_saver(self):
        css = self.css_text
        js = self.js_text_full
        html = self.html_text_lower
        combined = css + js + html

        connection_api = any(e in js for e in ["navigator.connection", "effectivetype", "savadata", "save-data", "connection.savedata"])
        if connection_api:
            self._add_check("data_saver", "Network Information API (navigator.connection) probed", True, 3)
        else:
            self._add_check("data_saver", "Network Information API (navigator.connection) probed", False, 3)

        save_data_branch = "savedata" in js or "save-data" in combined or "data saver" in html or "data-saver" in html or "saveData" in combined
        if save_data_branch:
            self._add_check("data_saver", "saveData-aware code path detected", True, 3)
        else:
            self._add_check("data_saver", "saveData-aware code path detected", False, 3)

        if "prefers-reduced-data" in css:
            self._add_check("data_saver", "prefers-reduced-data media query present", True, 2)
        else:
            self._add_check("data_saver", "prefers-reduced-data media query present", False, 2)

        videos = self.soup.find_all("video")
        if not videos:
            self._add_check("data_saver", "Video payload data-saver friendly (no video elements)", True, 2)
        else:
            friendly = 0
            for v in videos:
                if (v.get("preload") in ("none", "metadata")) or v.get("poster") or not v.get("autoplay"):
                    friendly += 1
            if friendly >= len(videos) * 0.5:
                self._add_check("data_saver", f"Video elements data-saver friendly ({friendly}/{len(videos)})", True, 2)
            else:
                self._add_check("data_saver", f"Video elements not data-saver friendly ({friendly}/{len(videos)})", False, 2)

        lazy = len([i for i in self.images if i.get("loading") == "lazy"])
        if lazy > 0 or not self.images:
            self._add_check("data_saver", "Deferred image loading reduces data usage", True, 2)
        else:
            self._add_check("data_saver", "Deferred image loading reduces data usage (lazy)", False, 2)

        lqip = any(e in combined for e in ["lqip", "blur-up", "blurup", "low-quality", "placeholder-image", "tiny placeholder"])
        if lqip:
            self._add_check("data_saver", "Low-quality image placeholders (LQIP/blur-up) detected", True, 2)
        else:
            self._add_check("data_saver", "Low-quality image placeholders (LQIP/blur-up) detected", False, 2)

        srcset_count = len([i for i in self.images if i.get("srcset")])
        if srcset_count > 0:
            self._add_check("data_saver", f"srcset density selection saves bytes ({srcset_count} images)", True, 2)
        else:
            self._add_check("data_saver", "srcset density selection saves bytes", False, 2)

        lite_variant = any(e in html for e in ["lite-mode", "lite mode", "low-data", "save-data-mode", "data-saver-mode", "amphtml"])
        if lite_variant:
            self._add_check("data_saver", "Lite/low-data page variant signals", True, 1)
        else:
            self._add_check("data_saver", "Lite/low-data page variant signals", False, 1)

        content_visibility = "content-visibility" in css or "contain:" in css
        if content_visibility:
            self._add_check("data_saver", "content-visibility / CSS containment reduces rendering cost", True, 1)
        else:
            self._add_check("data_saver", "content-visibility / CSS containment reduces rendering cost", False, 1)

    def check_touch(self):
        html_text = self.html_text_lower
        js_text = self.js_text_full

        touch_events = any(e in html_text for e in ["touchstart", "touchmove", "touchend"])
        touch_in_js = any(e in js_text for e in ["touchstart", "touchmove", "touchend"])
        touch_count = html_text.count("touchstart") + html_text.count("touchmove") + html_text.count("touchend")
        touch_count += js_text.count("touchstart") + js_text.count("touchmove") + js_text.count("touchend")

        if touch_events or touch_in_js:
            self._add_check("touch", f"Touch event listeners found ({touch_count} handlers)", True, 3)
        else:
            self._add_check("touch", "Touch event listeners found", False, 3)

        touch_delay_detected = False
        click_only = not (touch_events or touch_in_js)
        has_viewport_meta = self.soup.find("meta", attrs={"name": "viewport"})
        if has_viewport_meta:
            content = has_viewport_meta.get("content", "")
            if "width=device-width" in content:
                touch_delay_detected = False
            elif click_only:
                touch_delay_detected = True
        if not touch_delay_detected:
            self._add_check("touch", "Touch delay mitigation present (viewport or touch events)", True, 2)
        else:
            self._add_check("touch", "Touch delay may occur (300ms) - no touch events or proper viewport", False, 2)

        swipe_patterns = ["swipe", "swipeleft", "swiperight", "swipedown", "swipeup", "hammertime", "hammer.js", "swipedetector", "swiper", "swipejs", "touch-swipe"]
        swipe_detected = any(e in js_text for e in swipe_patterns)
        swipe_in_css = bool(re.search(r"touch-action\s*:\s*pan-(x|y|left|right|up|down)", self.css_text))
        if swipe_detected or swipe_in_css:
            self._add_check("touch", "Swipe gesture support detected", True, 2)
        else:
            self._add_check("touch", "Swipe gesture support detected", False, 2)

        pinch_detected = any(e in js_text for e in ["pinch", "pinchtozoom", "pinch-zoom", "gesturechange", "gesturestart"])
        pinch_css = bool(re.search(r"touch-action\s*:\s*(none|pinch-zoom|manipulation)", self.css_text))
        meta_content = ""
        meta_vp = self.soup.find("meta", attrs={"name": "viewport"})
        if meta_vp:
            meta_content = meta_vp.get("content", "")
        pinch_allowed = "user-scalable=no" not in meta_content and "maximum-scale=1" not in meta_content
        if pinch_detected or pinch_css or pinch_allowed:
            self._add_check("touch", "Pinch-to-zoom support detected", True, 2)
        else:
            self._add_check("touch", "Pinch-to-zoom may be restricted", False, 2)

        long_press_detected = any(e in js_text for e in ["longpress", "long-press", "long_press", "contextmenu", "touch-hold", "touchhold"])
        if long_press_detected:
            self._add_check("touch", "Long press detection found", True, 1)
        else:
            self._add_check("touch", "Long press detection found", False, 1)

        small_targets = 0
        for el in self.soup.find_all(["button", "a", "input"]):
            style = el.get("style", "")
            w_match = re.search(r"width\s*:\s*(\d+)", style)
            h_match = re.search(r"height\s*:\s*(\d+)", style)
            if w_match and h_match:
                w, h = int(w_match.group(1)), int(h_match.group(1))
                if w < 44 or h < 44:
                    small_targets += 1
        if small_targets == 0:
            self._add_check("touch", "Touch targets >= 44x44px (or not explicitly sized)", True, 3)
        else:
            self._add_check("touch", f"Small touch targets found ({small_targets} elements < 44x44px)", False, 3)

        hover_fallback = bool(re.search(r"@media\s*\(\s*hover\s*:\s*hover\s*\)", self.css_text)) or bool(re.search(r":hover", self.css_text))
        hover_queries = re.findall(r"@media\s*\(\s*hover\s*:", self.css_text)
        if hover_fallback:
            self._add_check("touch", f"Hover state handling detected ({len(hover_queries)} hover media queries)", True, 2)
        else:
            self._add_check("touch", "Hover state handling detected", False, 2)

        meta_vp = self.soup.find("meta", attrs={"name": "viewport"})
        content = meta_vp.get("content", "") if meta_vp else ""
        if "user-scalable=no" not in content and "user-scalable=0" not in content:
            self._add_check("touch", "Viewport allows user scaling", True, 2)
        else:
            self._add_check("touch", "Viewport allows user scaling", False, 2)

    def check_touch_gestures(self):
        js_text = self.js_text_full

        pull_to_refresh = any(e in js_text for e in [
            "pull-to-refresh", "pulltorefresh", "pull_to_refresh",
            "overscroll", "touch-action: none",
            "pullrefresh", "ptr", "pull-to-reveal",
        ])
        pull_css = bool(re.search(r"overscroll-behavior\s*:\s*(contain|none)", self.css_text))
        if pull_to_refresh or pull_css:
            self._add_check("touch_gesture", "Pull-to-refresh handling detected", True, 3)
        else:
            self._add_check("touch_gesture", "Pull-to-refresh handling detected", False, 3)

        infinite_scroll = any(e in js_text for e in [
            "infinite-scroll", "infinitescroll", "infinite_scroll",
            "load-more", "loadmore", "lazy-load-more",
            "onscroll", "scrollend", "intersectionobserver",
        ])
        if infinite_scroll:
            self._add_check("touch_gesture", "Infinite scroll / load-more pattern detected", True, 2)
        else:
            self._add_check("touch_gesture", "Infinite scroll / load-more pattern detected", False, 2)

        gesture_libs = any(e in js_text for e in [
            "hammer", "zepto", "touchstone", "interact.js",
            "gesturable", "alloyfinger", "sortablejs",
            "swiped", "photoswipe",
        ])
        gesture_api = any(e in js_text for e in [
            "gesturestart", "gesturechange", "gestureend",
            "pointerdown", "pointermove", "pointerup",
            "mspointerdown", "mspointermove", "mspointerup",
        ])
        if gesture_libs or gesture_api:
            self._add_check("touch_gesture", "Advanced gesture library / Pointer Events detected", True, 2)
        else:
            self._add_check("touch_gesture", "Advanced gesture library / Pointer Events detected", False, 2)

        multi_touch = any(e in js_text for e in [
            "touches[", "event.touches", "evt.touches",
            "touchstart.length", "maxtouchpoints",
            "navigator.maxtouchpoints",
        ])
        pointer_events = any(e in js_text for e in [
            "pointerdown", "pointermove", "pointerup",
            "pointercancel", "pointerleave",
        ])
        if multi_touch or pointer_events:
            self._add_check("touch_gesture", "Multi-touch / Pointer Events support detected", True, 2)
        else:
            self._add_check("touch_gesture", "Multi-touch / Pointer Events support detected", False, 2)

        drag_drop = any(e in js_text for e in [
            "dragstart", "dragend", "dragover",
            "draggable", "dropzone", "sortable",
        ])
        if drag_drop:
            self._add_check("touch_gesture", "Drag-and-drop support detected", True, 1)
        else:
            self._add_check("touch_gesture", "Drag-and-drop support detected", False, 1)

    def check_pwa(self):
        manifest = self.manifest
        if manifest:
            self._add_check("pwa", "Web App Manifest found", True, 2)
            if manifest.get("name") or manifest.get("short_name"):
                self._add_check("pwa", f"App name configured: '{manifest.get('name') or manifest.get('short_name')}'", True, 1)
            else:
                self._add_check("pwa", "App name configured", False, 1)
            if manifest.get("start_url"):
                self._add_check("pwa", f"Start URL configured: {manifest['start_url']}", True, 1)
            else:
                self._add_check("pwa", "Start URL configured", False, 1)
            display = manifest.get("display", "")
            if display in ("standalone", "fullscreen", "minimal-ui"):
                self._add_check("pwa", f"Display mode: {display}", True, 2)
            else:
                self._add_check("pwa", f"Display mode: {display or 'not set'} (standalone/fullscreen preferred)", False, 2)
            if manifest.get("theme_color"):
                self._add_check("pwa", f"Theme color: {manifest['theme_color']}", True, 1)
            else:
                self._add_check("pwa", "Theme color configured", False, 1)
            if manifest.get("background_color"):
                self._add_check("pwa", f"Background color: {manifest['background_color']}", True, 1)
            else:
                self._add_check("pwa", "Background color configured", False, 1)
            icons = manifest.get("icons", [])
            if icons:
                sizes = [ic.get("sizes", "") for ic in icons]
                has_192 = any("192" in s for s in sizes)
                has_512 = any("512" in s for s in sizes)
                self._add_check("pwa", f"Icons configured ({len(icons)} icons, sizes: {', '.join(sizes[:5])})", True, 2)
                if has_192 and has_512:
                    self._add_check("pwa", "Has both 192x192 and 512x512 icons", True, 1)
                elif has_192 or has_512:
                    self._add_check("pwa", "Has some required icon sizes (192x192 or 512x512)", True, 1)
                else:
                    self._add_check("pwa", "Missing standard icon sizes (192x192, 512x512)", False, 1)
                purposes = [ic.get("purpose", "") for ic in icons]
                if any("maskable" in p for p in purposes):
                    self._add_check("pwa", "Maskable icon present for Android adaptive icons", True, 1)
                else:
                    self._add_check("pwa", "Maskable icon present for Android adaptive icons", False, 1)
            else:
                self._add_check("pwa", "Icons configured", False, 2)
                self._add_check("pwa", "Standard icon sizes present", False, 1)
                self._add_check("pwa", "Maskable icon present for Android adaptive icons", False, 1)
        else:
            self._add_check("pwa", "Web App Manifest found", False, 2)
            self._add_check("pwa", "App name configured", False, 1)
            self._add_check("pwa", "Start URL configured", False, 1)
            self._add_check("pwa", "Display mode configured", False, 2)
            self._add_check("pwa", "Theme color configured", False, 1)
            self._add_check("pwa", "Background color configured", False, 1)
            self._add_check("pwa", "Icons configured", False, 2)
            self._add_check("pwa", "Standard icon sizes present", False, 1)
            self._add_check("pwa", "Maskable icon present for Android adaptive icons", False, 1)

        html_text = self.html_text_lower
        sw_detected = "serviceworker" in html_text or "service-worker" in html_text or "service_worker" in html_text
        if sw_detected:
            self._add_check("pwa", "Service Worker registration detected", True, 2)
        else:
            self._add_check("pwa", "Service Worker registration detected", False, 2)

        install_detected = any(e in html_text for e in ["beforeinstallprompt", "installprompt", "install-prompt", "appinstalled", "app-installed"])
        if install_detected:
            self._add_check("pwa", "Install prompt handling detected", True, 1)
        else:
            self._add_check("pwa", "Install prompt handling detected", False, 1)

        splash_detected = any(e in html_text for e in ["splash", "splash-screen", "splashscreen", "apple-touch-startup-image"])
        if splash_detected:
            self._add_check("pwa", "Splash screen configuration detected", True, 1)
        else:
            self._add_check("pwa", "Splash screen configuration detected", False, 1)

        meta_vp = self.soup.find("meta", attrs={"name": "theme-color"})
        meta_apple = self.soup.find("meta", attrs={"name": "apple-mobile-web-app-capable"})
        meta_webapp = self.soup.find("meta", attrs={"name": "mobile-web-app-capable"})

        if meta_vp or meta_apple or meta_webapp:
            self._add_check("pwa", "PWA meta tags present", True, 1)
        else:
            self._add_check("pwa", "PWA meta tags present", False, 1)

        offline_detected = any(e in html_text for e in ["cache-first", "offline", "workbox", "caches.open", "cache.put", "cache.match"])
        if offline_detected:
            self._add_check("pwa", "Offline/caching strategy detected", True, 1)
        else:
            self._add_check("pwa", "Offline/caching strategy detected", False, 1)

        manifest_id = bool(manifest and manifest.get("id"))
        if manifest_id:
            self._add_check("pwa", "Manifest id set for stable app identity", True, 1)
        else:
            self._add_check("pwa", "Manifest id set for stable app identity", False, 1)

        manifest_description = bool(manifest and manifest.get("description"))
        if manifest_description:
            self._add_check("pwa", "Manifest description present", True, 1)
        else:
            self._add_check("pwa", "Manifest description present", False, 1)

        manifest_categories = bool(manifest and manifest.get("categories"))
        if manifest_categories:
            self._add_check("pwa", "Manifest categories declared", True, 1)
        else:
            self._add_check("pwa", "Manifest categories declared", False, 1)

        prefer_related = bool(manifest and manifest.get("prefer_related_applications") is False)
        if prefer_related:
            self._add_check("pwa", "prefer_related_applications=false keeps web install primary", True, 1)
        else:
            self._add_check("pwa", "prefer_related_applications=false keeps web install primary", False, 1)

        i18n_ready = bool(manifest and (manifest.get("lang") or manifest.get("dir")))
        if i18n_ready:
            self._add_check("pwa", "Manifest lang/dir internationalization set", True, 1)
        else:
            self._add_check("pwa", "Manifest lang/dir internationalization set", False, 1)

    def check_deep_pwa(self):
        js_text = self.js_text_full
        html_text = self.html_text_lower

        sw_content = self.sw_data.get("content", "") if self.sw_data else ""
        sw_lower = sw_content.lower() if sw_content else ""

        sw_register = any(e in js_text for e in [
            "navigator.serviceworker.register",
            "serviceworker.register",
            "sw.register",
            "service-worker.register",
        ])
        if sw_register or self.sw_data:
            self._add_check("deep_pwa", "Service Worker registration API detected", True, 3)
        else:
            self._add_check("deep_pwa", "Service Worker registration API detected", False, 3)

        sw_scope = "scope" in sw_lower or any(e in js_text for e in [
            "sw.register", "serviceworker.register",
        ])
        if sw_scope or self.sw_data:
            self._add_check("deep_pwa", "Service Worker scope/configuration detected", True, 1)
        else:
            self._add_check("deep_pwa", "Service Worker scope/configuration detected", False, 1)

        push_support = any(e in js_text for e in [
            "pushmanager", "push.manager",
            "pushsubscription", "push.subscribe",
            "notification.permission", "requestpermission",
            "pushmanager.subscribe",
        ])
        push_meta = any(e in html_text for e in [
            "push-notification", "push_api", "web-push",
        ])
        if push_support or push_meta:
            self._add_check("deep_pwa", "Push notification support detected", True, 3)
        else:
            self._add_check("deep_pwa", "Push notification support detected", False, 3)

        bg_sync = any(e in js_text for e in [
            "backgroundsync", "background-sync",
            "background_sync", "periodicsync", "periodic-sync",
            "sync.register", "syncmanager",
        ])
        if bg_sync:
            self._add_check("deep_pwa", "Background sync support detected", True, 2)
        else:
            self._add_check("deep_pwa", "Background sync support detected", False, 2)

        cache_strategies = {
            "cache-first": ["cache-first", "cachefirst"],
            "network-first": ["network-first", "networkfirst"],
            "stale-while-revalidate": ["stale-while-revalidate", "stalewhilerevalidate"],
            "network-only": ["network-only", "networkonly"],
            "cache-only": ["cache-only", "cacheonly"],
        }
        found_strategies = []
        combined_text = js_text + sw_lower
        for strategy, patterns in cache_strategies.items():
            if any(p.lower() in combined_text for p in patterns):
                found_strategies.append(strategy)
        if found_strategies:
            self._add_check("deep_pwa", f"Cache strategies detected: {', '.join(found_strategies)}", True, 2)
        else:
            self._add_check("deep_pwa", "Cache strategies detected", False, 2)

        workbox_detected = "workbox" in combined_text
        if workbox_detected:
            self._add_check("deep_pwa", "Workbox library detected", True, 1)
        else:
            self._add_check("deep_pwa", "Workbox library detected", False, 1)

        manifest_valid = False
        manifest_issues = []
        if self.manifest:
            required_fields = ["name", "short_name", "start_url", "display", "icons"]
            present = [f for f in required_fields if self.manifest.get(f)]
            missing = [f for f in required_fields if not self.manifest.get(f)]
            if len(present) >= 3:
                manifest_valid = True
            if missing:
                manifest_issues.append(f"missing: {', '.join(missing)}")
            icons = self.manifest.get("icons", [])
            if icons:
                has_maskable = any("maskable" in ic.get("purpose", "") for ic in icons)
                if not has_maskable:
                    manifest_issues.append("no maskable icon")
                sizes = [ic.get("sizes", "") for ic in icons]
                has_192 = any("192" in s for s in sizes)
                has_512 = any("512" in s for s in sizes)
                if not (has_192 and has_512):
                    manifest_issues.append("missing 192x192 or 512x512 icon")
        if manifest_valid:
            desc = "Manifest valid" if not manifest_issues else "Manifest valid (warnings: " + "; ".join(manifest_issues) + ")"
            self._add_check("deep_pwa", desc, True, 2)
        else:
            issue_text = "; ".join(manifest_issues) if manifest_issues else "incomplete or missing manifest"
            self._add_check("deep_pwa", f"Manifest validation: {issue_text}", False, 2)

        apple_touch = self.soup.find("link", rel="apple-touch-icon")
        apple_meta = self.soup.find("meta", attrs={"name": "apple-mobile-web-app-capable"})
        apple_status_bar = self.soup.find("meta", attrs={"name": "apple-mobile-web-app-status-bar-style"})
        apple_count = sum(1 for x in [apple_touch, apple_meta, apple_status_bar] if x)
        if apple_count >= 2:
            self._add_check("deep_pwa", f"iOS PWA support detected ({apple_count}/3 Apple meta tags)", True, 2)
        elif apple_count == 1:
            self._add_check("deep_pwa", f"Partial iOS PWA support ({apple_count}/3 Apple meta tags)", True, 1)
        else:
            self._add_check("deep_pwa", "iOS PWA support missing (no Apple meta tags)", False, 2)

        share_api = any(e in js_text for e in ["navigator.share", "webshare", "canshare"])
        if share_api:
            self._add_check("deep_pwa", "Web Share API integration detected", True, 1)
        else:
            self._add_check("deep_pwa", "Web Share API integration detected", False, 1)

        share_target = bool(self.manifest and self.manifest.get("share_target"))
        if share_target:
            self._add_check("deep_pwa", "Manifest share_target enables inbound sharing", True, 2)
        else:
            self._add_check("deep_pwa", "Manifest share_target enables inbound sharing", False, 2)

        file_handlers = bool(self.manifest and (self.manifest.get("file_handlers") or self.manifest.get("protocol_handlers")))
        if file_handlers:
            self._add_check("deep_pwa", "File/protocol handlers registered in manifest", True, 2)
        else:
            self._add_check("deep_pwa", "File/protocol handlers registered in manifest", False, 2)

        launch_handler = bool(self.manifest and (self.manifest.get("launch_handler") or self.manifest.get("handle_links")))
        if launch_handler:
            self._add_check("deep_pwa", "launch_handler / handle_links configured", True, 1)
        else:
            self._add_check("deep_pwa", "launch_handler / handle_links configured", False, 1)

        screenshots = bool(self.manifest and self.manifest.get("screenshots"))
        if screenshots:
            self._add_check("deep_pwa", "Store-style screenshots present in manifest", True, 1)
        else:
            self._add_check("deep_pwa", "Store-style screenshots present in manifest", False, 1)

        shortcuts = bool(self.manifest and self.manifest.get("shortcuts"))
        if shortcuts:
            self._add_check("deep_pwa", "Manifest shortcuts provide deep entry points", True, 1)
        else:
            self._add_check("deep_pwa", "Manifest shortcuts provide deep entry points", False, 1)

    def check_performance_budget(self):
        page_size = len(self.resp.content)
        page_size_kb = page_size / 1024
        budget = self.budget

        if page_size_kb < budget["max_page_size_kb"]:
            self._add_check("perf_budget", f"Page size within {budget['name']} budget ({page_size_kb:.1f}KB < {budget['max_page_size_kb']}KB)", True, 5)
        else:
            self._add_check("perf_budget", f"Page size exceeds {budget['name']} budget ({page_size_kb:.1f}KB > {budget['max_page_size_kb']}KB)", False, 5)

        total_tags = self.soup.find_all(["img", "script", "link"])
        num_requests = len(total_tags)
        if num_requests < budget["max_requests"]:
            self._add_check("perf_budget", f"Request count within {budget['name']} budget ({num_requests} < {budget['max_requests']})", True, 4)
        else:
            self._add_check("perf_budget", f"Request count exceeds {budget['name']} budget ({num_requests} > {budget['max_requests']})", False, 4)

        total_resources_kb = page_size_kb
        for link in self.soup.find_all("link", rel="stylesheet"):
            total_resources_kb += 50
        for img in self.images:
            src = img.get("src", "")
            if src.startswith("data:"):
                total_resources_kb += len(src) / 1024 / 1.37
            else:
                total_resources_kb += 100
        if total_resources_kb < budget["max_total_size_kb"]:
            self._add_check("perf_budget", f"Total resource size within {budget['name']} budget ({total_resources_kb:.0f}KB < {budget['max_total_size_kb']}KB)", True, 4)
        else:
            self._add_check("perf_budget", f"Total resource size exceeds {budget['name']} budget ({total_resources_kb:.0f}KB > {budget['max_total_size_kb']}KB)", False, 4)

        inline_js_kb = self.js_info["inline_size"] / 1024
        if inline_js_kb < budget["max_js_size_kb"]:
            self._add_check("perf_budget", f"Inline JS within {budget['name']} budget ({inline_js_kb:.1f}KB < {budget['max_js_size_kb']}KB)", True, 3)
        else:
            self._add_check("perf_budget", f"Inline JS exceeds {budget['name']} budget ({inline_js_kb:.1f}KB > {budget['max_js_size_kb']}KB)", False, 3)

        total_css_kb = len(self.css_text.encode("utf-8")) / 1024
        if total_css_kb < budget["max_css_size_kb"]:
            self._add_check("perf_budget", f"CSS size within {budget['name']} budget ({total_css_kb:.1f}KB < {budget['max_css_size_kb']}KB)", True, 3)
        else:
            self._add_check("perf_budget", f"CSS size exceeds {budget['name']} budget ({total_css_kb:.1f}KB > {budget['max_css_size_kb']}KB)", False, 3)

        est_max_img_kb = 0.0
        for img in self.images:
            src = img.get("src", "")
            if src.startswith("data:"):
                img_kb = len(src) * 0.75 / 1024
            elif img.get("srcset"):
                img_kb = 90.0
            elif any(f in src.lower() for f in [".webp", ".avif", ".jxl", ".heic", ".heif"]):
                img_kb = 60.0
            else:
                img_kb = 220.0
            if img_kb > est_max_img_kb:
                est_max_img_kb = img_kb
        if not self.images:
            self._add_check("perf_budget", f"Image size within {budget['name']} budget (no images)", True, 3)
        elif est_max_img_kb <= budget["max_image_size_kb"]:
            self._add_check("perf_budget", f"Estimated largest image within {budget['name']} budget ({est_max_img_kb:.0f}KB <= {budget['max_image_size_kb']}KB)", True, 3)
        else:
            self._add_check("perf_budget", f"Estimated largest image exceeds {budget['name']} budget ({est_max_img_kb:.0f}KB > {budget['max_image_size_kb']}KB)", False, 3)

        rtt_est = budget["estimated_rtt_ms"]
        bandwidth = budget.get("bandwidth_kbps", 1638)
        transfer_ms = int((total_resources_kb * 8 / max(bandwidth, 1)) * 1000)
        self.perf_load_estimate_ms = rtt_est + transfer_ms
        load_budget_ms = budget.get("load_time_ms", 5000)
        if self.perf_load_estimate_ms <= load_budget_ms:
            self._add_check("perf_budget", f"Estimated load time within budget ({self.perf_load_estimate_ms}ms <= {load_budget_ms}ms on {budget['name']})", True, 3)
        else:
            self._add_check("perf_budget", f"Estimated load time exceeds budget ({self.perf_load_estimate_ms}ms > {load_budget_ms}ms on {budget['name']})", False, 3)

        if rtt_est < 200:
            self._add_check("perf_budget", f"Estimated RTT: {rtt_est}ms ({budget['name']} - fast network)", True, 2)
        else:
            self._add_check("perf_budget", f"Estimated RTT: {rtt_est}ms ({budget['name']} - optimize for latency)", True, 1)

    def check_performance(self):
        page_size = len(self.resp.content)
        if page_size < 3 * 1024 * 1024:
            self._add_check("performance", f"Page size OK ({page_size / 1024:.1f}KB < 3MB)", True, 5)
        else:
            self._add_check("performance", f"Page size too large ({page_size / 1024 / 1024:.2f}MB > 3MB)", False, 5)
        all_tags = self.soup.find_all(["img", "script", "link"])
        num_requests = len(all_tags)
        if num_requests < 100:
            self._add_check("performance", f"HTTP requests reasonable ({num_requests})", True, 4)
        else:
            self._add_check("performance", f"Too many HTTP requests ({num_requests})", False, 4)
        img_count = len(self.images)
        if img_count <= 20:
            self._add_check("performance", f"Image count OK ({img_count})", True, 3)
        else:
            self._add_check("performance", f"Too many images ({img_count})", False, 3)
        total_js = self.js_info["total_scripts"]
        if total_js <= 15:
            self._add_check("performance", f"Script count OK ({total_js})", True, 3)
        else:
            self._add_check("performance", f"Too many scripts ({total_js})", False, 3)
        css_links = self.soup.find_all("link", rel="stylesheet")
        if len(css_links) <= 5:
            self._add_check("performance", f"CSS file count OK ({len(css_links)})", True, 2)
        else:
            self._add_check("performance", f"Too many CSS files ({len(css_links)})", False, 2)
        lazy_count = len([i for i in self.images if i.get("loading") == "lazy"])
        if lazy_count > 0:
            self._add_check("performance", f"Lazy loading found on {lazy_count}/{img_count} images", True, 3)
        elif img_count == 0:
            self._add_check("performance", "No images to lazy-load", True, 3)
        else:
            self._add_check("performance", "No lazy loading on images", False, 3)

        js_text = ""
        for s in self.soup.find_all("script"):
            if s.string:
                js_text += s.string
        blocking_patterns = [
            r"document\.write\s*\(",
            r"window\.onload\s*=",
            r"window\.addEventListener\s*\(\s*['\"]load['\"]",
            r"\.innerHTML\s*=",
            r"\.outerHTML\s*=",
        ]
        blocking_count = sum(len(re.findall(p, js_text)) for p in blocking_patterns)
        inline_js_size = self.js_info["inline_size"]
        if blocking_count < 3 and inline_js_size < 50000:
            self._add_check("performance", f"JS execution impact low ({blocking_count} blocking patterns, {inline_js_size / 1024:.1f}KB inline)", True, 3)
        else:
            self._add_check("performance", f"JS execution impact may be high ({blocking_count} blocking patterns, {inline_js_size / 1024:.1f}KB inline)", False, 3)

        font_links = self.soup.find_all("link", rel="preload", attrs={"as": "font"})
        font_display = re.findall(r"font-display\s*:\s*(swap|fallback|optional|block|auto)", self.css_text)
        font_preload_count = len(font_links)
        has_font_display = any(fd in ("swap", "fallback", "optional") for fd in font_display)
        if font_preload_count > 0 or has_font_display:
            self._add_check("performance", f"Font loading optimized ({font_preload_count} preloads, font-display: {font_display[0] if font_display else 'auto'})", True, 3)
        else:
            self._add_check("performance", "Font loading not optimized (no preloads or font-display)", False, 3)

        img_without_format = 0
        img_with_format = 0
        for img in self.images:
            src = img.get("src", "")
            if src.startswith("data:"):
                continue
            if any(f in src.lower() for f in [".webp", ".avif", ".jxl", ".heic", ".heif"]):
                img_with_format += 1
            else:
                img_without_format += 1
        if img_with_format > 0 or img_without_format == 0:
            self._add_check("performance", f"Image format optimization: {img_with_format} modern, {img_without_format} traditional", img_with_format > 0, 3)
        else:
            self._add_check("performance", f"No modern image formats detected ({img_without_format} images use traditional formats)", False, 3)

        total_mobile_budget = 500 * 1024
        html_size = len(self.resp.content)
        if html_size < total_mobile_budget:
            self._add_check("performance", f"Mobile resource budget OK ({html_size / 1024:.1f}KB < 500KB HTML)", True, 3)
        else:
            self._add_check("performance", f"Exceeds mobile resource budget ({html_size / 1024:.1f}KB > 500KB HTML)", False, 3)

        fetch_priority = len(re.findall(r"fetchpriority\s*=", self.resp.text, re.IGNORECASE))
        if fetch_priority > 0:
            self._add_check("performance", f"fetchpriority hints present ({fetch_priority} resources)", True, 2)
        else:
            self._add_check("performance", "fetchpriority hints present (none found)", False, 2)

        async_decoding = len([i for i in self.images if (i.get("decoding") or "").lower() in ("async", "auto")])
        if async_decoding > 0 or not self.images:
            self._add_check("performance", f"Image decoding hints present ({async_decoding} async/auto)", True, 2)
        else:
            self._add_check("performance", "Image decoding hints present (decoding=async)", False, 2)

        third_party = set()
        for tag, attr in [("script", "src"), ("link", "href"), ("img", "src")]:
            for el in self.soup.find_all(tag):
                val = str(el.get(attr) or "")
                if val.startswith("http"):
                    host = urlparse(val).netloc
                    own = urlparse(self.url).netloc
                    if host and host != own:
                        third_party.add(host)
        if len(third_party) <= 4:
            self._add_check("performance", f"Third-party script/host load controlled ({len(third_party)} external hosts)", True, 3)
        else:
            self._add_check("performance", f"High third-party host count ({len(third_party)} external hosts)", False, 3)

        variable_fonts = bool(re.search(r"font-variation-settings|@font-face[^}]*font-weight\s*:\s*\d+\s+\d+", self.css_text))
        font_preload = len(self.soup.find_all("link", rel="preload", attrs={"as": "font"}))
        if variable_fonts or font_preload > 0:
            self._add_check("performance", "Modern font delivery (variable fonts / preloaded fonts)", True, 2)
        else:
            self._add_check("performance", "Modern font delivery (variable fonts / preloaded fonts)", False, 2)

        prefetch = len(self.soup.find_all("link", rel=lambda v: v and ("prefetch" in v or "prerender" in v)))
        if prefetch > 0:
            self._add_check("performance", f"Speculative loading hints present ({prefetch} prefetch/prerender)", True, 2)
        else:
            self._add_check("performance", "Speculative loading hints present (prefetch/prerender)", False, 2)

        visibility_aware = any(e in self.js_text_full for e in [
            "visibilitychange", "pagehide", "freeze", "resume", "document.hidden",
        ])
        if visibility_aware:
            self._add_check("performance", "Page visibility lifecycle work paused offscreen", True, 2)
        else:
            self._add_check("performance", "Page visibility lifecycle work paused offscreen", False, 2)

    def check_core_web_vitals(self):
        preload_hints = len(self.soup.find_all("link", rel="preload"))
        preconnect_hints = len(self.soup.find_all("link", rel="preconnect"))

        if preload_hints > 0:
            self._add_check("cwv", f"Resource hints: {preload_hints} preload(s) found", True, 2)
        else:
            self._add_check("cwv", "Resource hints: no preload found", False, 2)

        if preconnect_hints > 0:
            self._add_check("cwv", f"Preconnect hints found ({preconnect_hints})", True, 1)
        else:
            self._add_check("cwv", "No preconnect hints found", False, 1)

        render_blocking = len(re.findall(r"rel\s*=\s*[\"']stylesheet[\"']", self.resp.text))
        script_render_blocking = len(re.findall(r"<script\s+src=[^>]+(?<!async)(?<!defer)(?<!type=[\"']module[\"'])", self.resp.text))
        total_render_blocking = render_blocking + script_render_blocking
        if total_render_blocking < 5:
            self._add_check("cwv", f"Render-blocking resources low ({total_render_blocking})", True, 3)
        else:
            self._add_check("cwv", f"Render-blocking resources high ({total_render_blocking})", False, 3)

        lcp_candidates = len(self.soup.find_all(["img", "video", "div", "section", "h1", "h2", "h3"]))
        if lcp_candidates > 0:
            self._add_check("cwv", f"LCP candidates found ({lcp_candidates} large elements)", True, 1)
        else:
            self._add_check("cwv", "No clear LCP candidates found", False, 1)

        layout_shift_risk = 0
        for img in self.images:
            if not img.get("width") and not img.get("height"):
                layout_shift_risk += 1
        for video in self.soup.find_all("video"):
            if not video.get("width") and not video.get("height"):
                layout_shift_risk += 1
        if layout_shift_risk == 0:
            self._add_check("cwv", "CLS risk low: all media has explicit dimensions", True, 3)
        else:
            self._add_check("cwv", f"CLS risk: {layout_shift_risk} media elements without dimensions", False, 3)

        if len(self.images) <= 10:
            self._add_check("cwv", "Image count favorable for mobile LCP", True, 2)
        else:
            self._add_check("cwv", f"High image count may impact mobile LCP ({len(self.images)})", False, 2)

        defer_async = len(re.findall(r"(defer|async|type=[\"']module[\"'])", self.resp.text))
        total_scripts = self.js_info["total_scripts"]
        if total_scripts == 0 or defer_async > total_scripts * 0.5:
            self._add_check("cwv", "Script loading optimized for mobile (defer/async/module)", True, 2)
        else:
            self._add_check("cwv", f"Script loading may block mobile rendering ({defer_async}/{total_scripts} deferred)", False, 2)

    def check_mobile_form(self):
        forms = self.soup.find_all("form")
        if not forms:
            self._add_check("mobile_form", "Forms present on page", False, 1)
            return
        self._add_check("mobile_form", f"Forms found ({len(forms)})", True, 1)

        inputs = self.soup.find_all("input")
        input_types = [inp.get("type", "text") for inp in inputs]
        type_counts = {}
        for t in input_types:
            type_counts[t] = type_counts.get(t, 0) + 1

        keyboard_optimized = ["email", "tel", "url", "number", "search", "date", "time"]
        optimized_count = sum(type_counts.get(t, 0) for t in keyboard_optimized)
        text_only = type_counts.get("text", 0)
        if optimized_count > 0 or text_only == 0:
            self._add_check("mobile_form", f"Mobile keyboard types optimized ({optimized_count} specialized inputs)", True, 2)
        else:
            self._add_check("mobile_form", f"No mobile keyboard optimization ({text_only} text-only inputs)", False, 2)

        autocomplete_count = len([inp for inp in inputs if inp.get("autocomplete")])
        if autocomplete_count > 0:
            self._add_check("mobile_form", f"Autocomplete attributes found ({autocomplete_count}/{len(inputs)})", True, 2)
        else:
            self._add_check("mobile_form", "No autocomplete attributes (helps mobile form filling)", False, 2)

        placeholders = len([inp for inp in inputs if inp.get("placeholder")])
        labels = len(self.soup.find_all("label"))
        aria_labels = len([inp for inp in inputs if inp.get("aria-label") or inp.get("aria-labelledby")])
        hint_count = placeholders + labels + aria_labels
        if hint_count >= len(inputs) * 0.5:
            self._add_check("mobile_form", f"Input labels/placeholders present ({hint_count} hints for {len(inputs)} inputs)", True, 2)
        else:
            self._add_check("mobile_form", f"Missing input labels/placeholders ({hint_count}/{len(inputs)})", False, 2)

        textarea_count = len(self.soup.find_all("textarea"))
        if textarea_count > 0:
            self._add_check("mobile_form", f"Textarea elements found ({textarea_count})", True, 1)
        else:
            self._add_check("mobile_form", "No textarea elements found", True, 1)

        inputmode_count = len([inp for inp in inputs if inp.get("inputmode")])
        if inputmode_count > 0:
            self._add_check("mobile_form", f"inputmode attributes found ({inputmode_count}/{len(inputs)})", True, 2)
        else:
            self._add_check("mobile_form", "No inputmode attributes (numeric/email keyboards not opted in)", False, 2)

        constraint_attrs = ["required", "pattern", "minlength", "maxlength", "min", "max", "step"]
        constraint_count = 0
        for inp in inputs:
            if any(inp.get(attr) is not None for attr in constraint_attrs):
                constraint_count += 1
        if constraint_count > 0:
            self._add_check("mobile_form", f"HTML5 constraint validation used ({constraint_count}/{len(inputs)} inputs)", True, 2)
        else:
            self._add_check("mobile_form", "No HTML5 constraint validation attributes (required/pattern/minlength)", False, 2)

        custom_validation = any(e in self.js_text_full for e in [
            "setcustomvalidity", "checkvalidity", "reportvalidity",
            "checkconstraint", "constraintvalidation", "form.checkvalidity",
        ])
        if custom_validation:
            self._add_check("mobile_form", "Custom JS validation handling detected", True, 1)
        else:
            self._add_check("mobile_form", "Custom JS validation handling detected", False, 1)

        aria_error_feedback = any(inp.get("aria-invalid") or inp.get("aria-describedby") for inp in inputs)
        error_markup = any(e in self.html_text_lower for e in ["field-error", "form-error", "error-message", "is-invalid", "input-error"])
        error_css = bool(re.search(r":invalid|\.is-invalid|\.error\s*\{", self.css_text))
        if aria_error_feedback or error_markup or error_css:
            self._add_check("mobile_form", "Inline error feedback patterns detected", True, 2)
        else:
            self._add_check("mobile_form", "Inline error feedback patterns detected", False, 2)

        otp_pattern = any(inp.get("autocomplete") == "one-time-code" for inp in inputs) or any(
            e in self.html_text_lower for e in ["otp-input", "otp-inputs", "one-time-code", "verification-code"]
        )
        if otp_pattern:
            self._add_check("mobile_form", "OTP / one-time-code input pattern detected", True, 1)
        else:
            self._add_check("mobile_form", "OTP / one-time-code input pattern detected", False, 1)

        novalidate = any(f.get("novalidate") is not None for f in forms)
        if novalidate:
            self._add_check("mobile_form", "novalidate present (custom validation UX in control)", True, 1)
        else:
            self._add_check("mobile_form", "Native browser validation retained (novalidate absent)", True, 1)

    def check_touch_performance(self):
        js_text = self.js_text_full

        fid_proxy_count = js_text.count("requestidlecallback") + js_text.count("requestanimationframe")
        if fid_proxy_count > 0:
            self._add_check("touch_perf", f"Input responsiveness helpers found ({fid_proxy_count} rAF/rIC calls)", True, 3)
        else:
            self._add_check("touch_perf", "Input responsiveness helpers found (rAF/rIC)", False, 3)

        has_passive = "passive" in js_text
        if has_passive:
            self._add_check("touch_perf", "Passive event listeners detected", True, 2)
        else:
            self._add_check("touch_perf", "Passive event listeners detected", False, 2)

        long_task_patterns = [
            r"setTimeout\s*\(\s*function\s*\(",
            r"setInterval\s*\(",
            r"while\s*\(",
            r"for\s*\([^;]+;[^;]+;[^)]*\)\s*\{",
        ]
        long_task_count = sum(len(re.findall(p, js_text)) for p in long_task_patterns)
        if long_task_count < 10:
            self._add_check("touch_perf", f"Long task indicators low ({long_task_count} potential long tasks)", True, 2)
        else:
            self._add_check("touch_perf", f"Long task indicators high ({long_task_count} potential long tasks)", False, 2)

        if self.js_info["inline_size"] < 30000:
            self._add_check("touch_perf", f"Inline JS size OK ({self.js_info['inline_size'] / 1024:.1f}KB)", True, 2)
        else:
            self._add_check("touch_perf", f"Inline JS too large ({self.js_info['inline_size'] / 1024:.1f}KB)", False, 2)

    def check_content(self):
        font_sizes = re.findall(r"font-size\s*:\s*(\d+)", self.css_text)
        small_fonts = [int(f) for f in font_sizes if int(f) < 12]
        if len(small_fonts) == 0:
            self._add_check("content", "No small font sizes (<12px)", True, 3)
        else:
            self._add_check("content", f"Small fonts found ({len(small_fonts)} declarations <12px)", False, 3)
        line_heights = re.findall(r"line-height\s*:\s*([\d.]+)", self.css_text)
        good_lh = [float(l) for l in line_heights if float(l) >= 1.5]
        if len(good_lh) > 0 or len(line_heights) == 0:
            self._add_check("content", "Adequate line-height (>=1.5) or using browser default", True, 2)
        else:
            self._add_check("content", "Line-height may be too small (<1.5)", False, 2)
        meta_vp = self.soup.find("meta", attrs={"name": "viewport"})
        content = meta_vp.get("content", "") if meta_vp else ""
        if "width=device-width" in content:
            self._add_check("content", "Content width matches viewport", True, 3)
        else:
            self._add_check("content", "Content width may not match viewport", False, 3)
        if "user-scalable=no" not in content:
            self._add_check("content", "Users can zoom to read content", True, 2)
        else:
            self._add_check("content", "Users cannot zoom to read content", False, 2)

    def check_navigation(self):
        html_text = self.html_text_lower
        hamburger_patterns = ["hamburger", "menu-toggle", "mobile-menu", "nav-toggle", "burger", "toggle-nav", "offcanvas", "sidebar"]
        found_nav = [p for p in hamburger_patterns if p in html_text]
        if found_nav:
            self._add_check("navigation", f"Hamburger/mobile menu pattern found ({', '.join(found_nav[:2])})", True, 3)
        else:
            self._add_check("navigation", "Hamburger/mobile menu pattern found", False, 3)
        mobile_nav_classes = ["mobile-nav", "mobile-menu", "nav-mobile", "m-nav", "responsive-nav", "slide-menu"]
        found_mnav = [p for p in mobile_nav_classes if p in html_text]
        if found_mnav:
            self._add_check("navigation", "Mobile navigation elements found", True, 3)
        else:
            self._add_check("navigation", "Mobile navigation elements found", False, 3)
        fixed_patterns = [r"position\s*:\s*fixed", "sticky", "navbar-fixed", "fixed-header"]
        found_fixed = [p for p in fixed_patterns if re.search(p, html_text)]
        if found_fixed:
            self._add_check("navigation", "Sticky/fixed header detected", True, 2)
        else:
            self._add_check("navigation", "Sticky/fixed header detected", False, 2)
        btt_patterns = ["back-to-top", "scroll-top", "scrolltotop", "back_to_top", "gototop"]
        found_btt = [p for p in btt_patterns if p in html_text]
        if found_btt:
            self._add_check("navigation", "Back-to-top button found", True, 2)
        else:
            self._add_check("navigation", "Back-to-top button found", False, 2)

        bottom_nav = any(e in html_text for e in [
            "bottom-nav", "bottomnav", "tab-bar", "tabbar",
            "bottom-navigation", "mobile-tab", "bottomnavbar",
        ])
        if bottom_nav:
            self._add_check("navigation", "Bottom navigation / tab bar pattern detected", True, 2)
        else:
            self._add_check("navigation", "Bottom navigation / tab bar pattern detected", False, 2)

        drawer = any(e in html_text for e in [
            "drawer", "offcanvas", "off-canvas", "nav-drawer",
            "sliding-menu", "slide-in-nav", "side-drawer",
        ])
        if drawer:
            self._add_check("navigation", "Drawer / off-canvas navigation pattern detected", True, 2)
        else:
            self._add_check("navigation", "Drawer / off-canvas navigation pattern detected", False, 2)

        swipeable_nav = any(e in html_text for e in ["swipeable", "swipeable-tabs", "swipe-nav", "carousel-nav"])
        swipeable_js = bool(re.search(r"swipe[a-z-]*\s*(tab|nav|menu)", self.js_text_full))
        if swipeable_nav or swipeable_js:
            self._add_check("navigation", "Swipeable navigation / tab pattern detected", True, 1)
        else:
            self._add_check("navigation", "Swipeable navigation / tab pattern detected", False, 1)

        fullscreen_menu = any(e in html_text for e in [
            "fullscreen-menu", "full-screen-menu", "overlay-menu",
            "menu-overlay", "fullpage-nav",
        ])
        if fullscreen_menu:
            self._add_check("navigation", "Full-screen overlay menu detected", True, 1)
        else:
            self._add_check("navigation", "Full-screen overlay menu detected", False, 1)

        safe_area_nav = "safe-area-inset-bottom" in self.css_text or "env(safe-area-inset" in self.css_text
        if safe_area_nav:
            self._add_check("navigation", "Safe-area-aware navigation (notch/home-indicator padding)", True, 2)
        else:
            self._add_check("navigation", "Safe-area-aware navigation (notch/home-indicator padding)", False, 2)

    def check_meta(self):
        meta_checks = [
            ("mobile-web-app-capable", 2),
            ("apple-mobile-web-app-capable", 2),
            ("apple-mobile-web-app-status-bar-style", 2),
            ("format-detection", 2),
            ("theme-color", 2),
        ]
        for name, pts in meta_checks:
            tag = self.soup.find("meta", attrs={"name": name})
            if tag:
                self._add_check("meta", f"{name} present", True, pts)
            else:
                self._add_check("meta", f"{name} present", False, pts)
        dark_theme_meta = self.soup.find("meta", attrs={"name": "theme-color", "media": "(prefers-color-scheme: dark)"})
        if dark_theme_meta:
            self._add_check("meta", "theme-color dark variant present", True, 1)
        else:
            self._add_check("meta", "theme-color dark variant present", False, 1)

    def check_images(self):
        total_imgs = len(self.images)
        if total_imgs == 0:
            self._add_check("images", "No images found on page", True, 2)
            self._add_check("images", "N/A - no images", True, 2)
            self._add_check("images", "N/A - no images", True, 2)
            self._add_check("images", "N/A - no images", True, 2)
            self._add_check("images", "N/A - no images", True, 2)
            return
        with_dims = len([i for i in self.images if i.get("width") and i.get("height")])
        if with_dims == total_imgs:
            self._add_check("images", f"All images have width/height ({with_dims}/{total_imgs})", True, 2)
        elif with_dims > 0:
            self._add_check("images", f"Some images have width/height ({with_dims}/{total_imgs})", True, 1)
        else:
            self._add_check("images", "No images have width/height attributes", False, 2)
        with_srcset = len([i for i in self.images if i.get("srcset")])
        if with_srcset > 0:
            self._add_check("images", f"Responsive images with srcset ({with_srcset}/{total_imgs})", True, 2)
        else:
            self._add_check("images", "No images use srcset for responsive loading", False, 2)
        with_lazy = len([i for i in self.images if i.get("loading") == "lazy"])
        if with_lazy > 0:
            self._add_check("images", f"Lazy loading found ({with_lazy}/{total_imgs})", True, 2)
        else:
            self._add_check("images", "No images use lazy loading", False, 2)
        modern_formats = 0
        for img in self.images:
            src = img.get("src", "").lower()
            if any(fmt in src for fmt in [".webp", ".avif", ".jxl", ".heic"]):
                modern_formats += 1
        if modern_formats > 0:
            self._add_check("images", f"Modern image formats used ({modern_formats})", True, 2)
        else:
            self._add_check("images", "No modern image formats (WebP, AVIF)", False, 2)
        oversized = 0
        for img in self.images:
            src = img.get("src", "")
            if src.startswith("data:"):
                if len(src) > 500 * 1024:
                    oversized += 1
        if oversized == 0:
            self._add_check("images", "No oversized inline images detected", True, 2)
        else:
            self._add_check("images", f"Oversized images found ({oversized})", False, 2)

    def check_device_features(self):
        css = self.css_text
        js = self.js_text_full
        html = self.html_text_lower
        combined = css + js + html

        fold_patterns = [
            "spanning:", "single-fold", "foldable", "folding-screen",
            "hinge", "screen-fold", "screenfold", "duo-screen",
            "surface-duo", "posture:", "fold-state", "foldstate",
            "multifold", "book-mode", "tent-mode",
        ]
        fold_found = [p for p in fold_patterns if p in combined]
        if fold_found:
            self._add_check("device", f"Foldable layout signals detected ({', '.join(fold_found[:3])})", True, 3)
        else:
            self._add_check("device", "Foldable layout signals detected (spanning/hinge media)", False, 3)

        meta_vp = self.soup.find("meta", attrs={"name": "viewport"})
        vp_content = meta_vp.get("content", "") if meta_vp else ""
        safe_area = (
            "viewport-fit=cover" in vp_content
            or "safe-area-inset" in css
            or "constant(safe-area-inset" in css
            or "title-safe-area" in css
            or "widget-safe-area" in css
        )
        if safe_area:
            self._add_check("device", "Notch/safe-area handling detected (env(safe-area-inset))", True, 3)
        else:
            self._add_check("device", "Notch/safe-area handling detected (env(safe-area-inset))", False, 3)

        dark_signals = [
            "prefers-color-scheme", "color-scheme",
            "prefers-color-scheme: dark", "data-theme",
            "dark-mode", "darkmode", "theme-toggle",
            "matchmedia('(prefers-color-scheme",
        ]
        dark_found = [p for p in dark_signals if p in combined]
        dark_meta = any(m for m in self.soup.find_all("meta", attrs={"name": "theme-color"}) if m.get("media"))
        if dark_found or dark_meta:
            self._add_check("device", "Dark mode support detected (prefers-color-scheme)", True, 3)
        else:
            self._add_check("device", "Dark mode support detected (prefers-color-scheme)", False, 3)

        orientation_css = bool(re.search(r"@media[^{]*\(\s*orientation\s*:", css))
        orientation_js = bool(re.search(r"orientationchange|screen\.orientation|prefers-color-scheme.*orientation|orientation", js))
        if orientation_css or orientation_js:
            self._add_check("device", "Device orientation handling detected", True, 2)
        else:
            self._add_check("device", "Device orientation handling detected", False, 2)

        haptic_signals = [
            "navigator.vibrate", "vibrate(", "vibration",
            "haptic", "haptics", "hapticfeedback", "haptic-feedback",
        ]
        haptic_found = [p for p in haptic_signals if p in combined]
        if haptic_found:
            self._add_check("device", f"Haptic feedback detection found ({haptic_found[0]})", True, 2)
        else:
            self._add_check("device", "Haptic feedback detection found (navigator.vibrate)", False, 2)

        arvr_signals = [
            "navigator.xr", "webxr", "requestsession", "immersive-vr",
            "immersive-ar", "local-floor", "webvr", "a-frame", "aframe",
            "model-viewer", ".usdz", ".gltf", ".glb", "ar.js",
            "quicklook", "scene-viewer", "xr-session",
        ]
        arvr_found = [p for p in arvr_signals if p in combined]
        if arvr_found:
            self._add_check("device", f"AR/VR support signals detected ({', '.join(arvr_found[:3])})", True, 3)
        else:
            self._add_check("device", "AR/VR support signals detected (WebXR/model-viewer)", False, 3)

        pointer_capability = any(e in js for e in ["maxtouchpoints", "navigator.maxtouchpoints"])
        coarse_pointer = "pointer: coarse" in css or "(pointer:coarse)" in css.replace(" ", "")
        if pointer_capability or coarse_pointer:
            self._add_check("device", "Pointer capability probing detected (maxTouchPoints/pointer:coarse)", True, 1)
        else:
            self._add_check("device", "Pointer capability probing detected (maxTouchPoints/pointer:coarse)", False, 1)

    def check_mobile_a11y(self):
        css = self.css_text
        js = self.js_text_full
        html = self.html_text_lower

        if "prefers-reduced-motion" in css or "prefers-reduced-motion" in html or "prefers-reduced-motion" in js:
            self._add_check("mobile_a11y", "prefers-reduced-motion support detected", True, 2)
        else:
            self._add_check("mobile_a11y", "prefers-reduced-motion support detected", False, 2)

        if "forced-colors" in css or "prefers-contrast" in css:
            self._add_check("mobile_a11y", "forced-colors / prefers-contrast queries found", True, 1)
        else:
            self._add_check("mobile_a11y", "forced-colors / prefers-contrast queries found", False, 1)

        meta_vp = self.soup.find("meta", attrs={"name": "viewport"})
        vp_content = meta_vp.get("content", "") if meta_vp else ""
        zoom_ok = (
            "user-scalable=no" not in vp_content
            and "user-scalable=0" not in vp_content
            and "maximum-scale=1" not in vp_content
        )
        if zoom_ok:
            self._add_check("mobile_a11y", "Viewport permits pinch-zoom for low-vision users", True, 2)
        else:
            self._add_check("mobile_a11y", "Viewport permits pinch-zoom for low-vision users", False, 2)

        fixed_fonts = len(re.findall(r"font-size\s*:\s*\d+px", css))
        relative_fonts = len(re.findall(r"font-size\s*:\s*[\d.]+(?:rem|em|vw)", css))
        if fixed_fonts == 0 and relative_fonts == 0:
            self._add_check("mobile_a11y", "No fixed px font sizes (browser defaults or relative units)", True, 2)
        elif relative_fonts >= fixed_fonts:
            self._add_check("mobile_a11y", f"Scalable typography used ({relative_fonts} rem/em vs {fixed_fonts} px)", True, 2)
        else:
            self._add_check("mobile_a11y", f"Fixed px typography dominates ({fixed_fonts} px vs {relative_fonts} rem/em)", False, 2)

        if ":focus-visible" in css:
            self._add_check("mobile_a11y", "Focus-visible styles detected", True, 2)
        elif re.search(r":focus[^{]*\{[^}]*outline\s*:\s*(?!none|0\b)", css):
            self._add_check("mobile_a11y", "Focus outline styles detected", True, 2)
        else:
            self._add_check("mobile_a11y", "Focus styles detected (:focus-visible / outline)", False, 2)

        landmarks = sum(1 for tag in ["nav", "main", "header", "footer"] if self.soup.find(tag))
        if landmarks >= 3:
            self._add_check("mobile_a11y", f"Semantic landmarks present ({landmarks}/4: nav/main/header/footer)", True, 2)
        else:
            self._add_check("mobile_a11y", f"Semantic landmarks present ({landmarks}/4: nav/main/header/footer)", False, 2)

        skip_link = any(e in html for e in ["skip-to", "skip to main", "skip-nav", "skipnav", "skip-link", "skiplink"])
        if skip_link:
            self._add_check("mobile_a11y", "Skip navigation link detected", True, 1)
        else:
            self._add_check("mobile_a11y", "Skip navigation link detected", False, 1)

        aria_els = 0
        for el in self.soup.find_all(True):
            for k in el.attrs:
                if k.startswith("aria-"):
                    aria_els += 1
                    break
        if aria_els > 0:
            self._add_check("mobile_a11y", f"ARIA attributes in use ({aria_els} elements)", True, 2)
        else:
            self._add_check("mobile_a11y", "ARIA attributes in use", False, 2)

        if self.images:
            with_alt = len([i for i in self.images if i.get("alt") is not None])
            if with_alt >= len(self.images) * 0.8:
                self._add_check("mobile_a11y", f"Image alt text coverage good ({with_alt}/{len(self.images)})", True, 2)
            else:
                self._add_check("mobile_a11y", f"Image alt text coverage low ({with_alt}/{len(self.images)})", False, 2)
        else:
            self._add_check("mobile_a11y", "Image alt text coverage (no images)", True, 2)

        html_tag = self.soup.find("html")
        if html_tag and html_tag.get("lang"):
            lang_val = html_tag.get("lang")
            self._add_check("mobile_a11y", f"Language attribute set (lang={lang_val})", True, 1)
        else:
            self._add_check("mobile_a11y", "Language attribute set on <html>", False, 1)

        big_target_css = bool(re.search(r"(?:min-)?(?:height|width|block-size|inline-size)\s*:\s*(?:44|48)px", css))
        if big_target_css:
            self._add_check("mobile_a11y", "Minimum 44/48px touch target CSS found", True, 2)
        else:
            self._add_check("mobile_a11y", "Minimum 44/48px touch target CSS found", False, 2)

        target_24 = bool(re.search(r"(?:min-)?(?:height|width|block-size|inline-size)\s*:\s*(?:24|32|44|48)px", css))
        if target_24:
            self._add_check("mobile_a11y", "WCAG 2.5.8 target size baseline (24px min) covered in CSS", True, 1)
        else:
            self._add_check("mobile_a11y", "WCAG 2.5.8 target size baseline (24px min) covered in CSS", False, 1)

        reflow_ok = bool(re.search(r"max-width\s*:\s*(?:480|600|768)\s*px|width=device-width", css + html))
        if reflow_ok or "width=device-width" in vp_content:
            self._add_check("mobile_a11y", "Reflow-friendly layout (single-column / device-width) present", True, 2)
        else:
            self._add_check("mobile_a11y", "Reflow-friendly layout (single-column / device-width) present", False, 2)

        aria_modal = any(el.get("aria-modal") or el.get("role") == "dialog" for el in self.soup.find_all(True))
        inert_attr = any(el.get("inert") is not None for el in self.soup.find_all(True))
        focus_trap = any(e in js for e in ["focus-trap", "focustrap", "trapfocus", "tabindex=\"-1\"", "inert"])
        if aria_modal or inert_attr or focus_trap:
            self._add_check("mobile_a11y", "Dialog/modal focus management signals (aria-modal/inert/trap)", True, 2)
        else:
            self._add_check("mobile_a11y", "Dialog/modal focus management signals (aria-modal/inert/trap)", False, 2)

        aria_describedby = len([el for el in self.soup.find_all(True) if el.get("aria-describedby")])
        if aria_describedby > 0:
            self._add_check("mobile_a11y", f"aria-describedby instructional wiring ({aria_describedby} elements)", True, 1)
        else:
            self._add_check("mobile_a11y", "aria-describedby instructional wiring (none found)", False, 1)

        text_zoom_ok = (
            "user-scalable=no" not in vp_content
            and "maximum-scale=1" not in vp_content
            and relative_fonts >= fixed_fonts
        )
        if text_zoom_ok:
            self._add_check("mobile_a11y", "Text zoom / resize compatibility (no scale lock, relative fonts)", True, 2)
        else:
            self._add_check("mobile_a11y", "Text zoom / resize compatibility (no scale lock, relative fonts)", False, 2)

        status_role = any(el.get("role") in ("status", "alert") for el in self.soup.find_all(True)) or "aria-live" in html
        if status_role:
            self._add_check("mobile_a11y", "Alert/status roles announce dynamic updates", True, 2)
        else:
            self._add_check("mobile_a11y", "Alert/status roles announce dynamic updates", False, 2)

    def check_mobile_ux_patterns(self):
        html = self.html_text_lower
        css = self.css_text
        js = self.js_text_full
        combined = html + css + js

        found = []
        missing = []
        for key, patterns in UX_PATTERN_DEFS.items():
            if any(p.lower() in combined for p in patterns):
                found.append(key)
            else:
                missing.append(key)
        if len(found) >= 6:
            self._add_check("mobile_ux", f"Rich mobile UX pattern coverage ({len(found)}/{len(UX_PATTERN_DEFS)} patterns)", True, 4)
        elif len(found) >= 3:
            self._add_check("mobile_ux", f"Moderate mobile UX pattern coverage ({len(found)}/{len(UX_PATTERN_DEFS)} patterns)", False, 4)
        else:
            self._add_check("mobile_ux", f"Low mobile UX pattern coverage ({len(found)}/{len(UX_PATTERN_DEFS)} patterns)", False, 4)

        for key in ["hamburger_menu", "skeleton_loading", "pull_to_refresh", "infinite_scroll", "toast_feedback", "modal_bottom_sheet"]:
            if key in found:
                pretty = key.replace("_", " ").title()
                self._add_check("mobile_ux", f"UX pattern: {pretty} present", True, 1)
            else:
                pretty = key.replace("_", " ").title()
                self._add_check("mobile_ux", f"UX pattern: {pretty} present", False, 1)

        one_hand = any(e in combined for e in ["bottom-nav", "bottomnav", "tab-bar", "fab", "floating-action", "sticky-bottom"])
        if one_hand:
            self._add_check("mobile_ux", "One-handed use patterns (bottom nav/FAB/sticky CTA)", True, 2)
        else:
            self._add_check("mobile_ux", "One-handed use patterns (bottom nav/FAB/sticky CTA)", False, 2)

        feedback = any(e in combined for e in ["toast", "snackbar", "spinner", "skeleton", "loading", "progress"])
        if feedback:
            self._add_check("mobile_ux", "Loading/feedback states visible to users", True, 2)
        else:
            self._add_check("mobile_ux", "Loading/feedback states visible to users", False, 2)

        micro_interactions = any(e in combined for e in [
            "transition", "animation", "keyframes", "transform", "ripple",
            ":active", "hover-scale", "micro-interaction",
        ])
        if micro_interactions:
            self._add_check("mobile_ux", "Micro-interaction polish (transitions/transforms/animations)", True, 2)
        else:
            self._add_check("mobile_ux", "Micro-interaction polish (transitions/transforms/animations)", False, 2)

        empty_states = any(e in combined for e in [
            "empty-state", "no-results", "no-data", "nothing-here", "placeholder",
            "start-here", "first-use",
        ])
        if empty_states:
            self._add_check("mobile_ux", "Designed empty/first-use states present", True, 2)
        else:
            self._add_check("mobile_ux", "Designed empty/first-use states present", False, 2)

        motion_friendly = "prefers-reduced-motion" in combined
        if motion_friendly:
            self._add_check("mobile_ux", "Animations respect prefers-reduced-motion", True, 2)
        else:
            self._add_check("mobile_ux", "Animations respect prefers-reduced-motion", False, 2)

        thumb_zone = any(e in combined for e in [
            "bottom-nav", "bottomnav", "fab", "floating-action", "sticky-bottom",
            "safe-area-inset-bottom", "env(safe-area-inset-bottom",
        ])
        if thumb_zone:
            self._add_check("mobile_ux", "Thumb-zone optimized controls (bottom-anchored / safe-area aware)", True, 2)
        else:
            self._add_check("mobile_ux", "Thumb-zone optimized controls (bottom-anchored / safe-area aware)", False, 2)

        self.ux_patterns_analysis = {
            "found": found,
            "missing": missing,
            "coverage": f"{len(found)}/{len(UX_PATTERN_DEFS)}",
        }

    def check_mobile_conversion(self):
        html = self.html_text_lower
        js = self.js_text_full
        combined = html + js

        found = []
        missing = []
        for key, patterns in CONVERSION_PATTERNS.items():
            if any(p.lower() in combined for p in patterns):
                found.append(key)
            else:
                missing.append(key)

        cta_elements = len(self.soup.find_all(["button", "a"])) 
        primary_ctas = 0
        for el in self.soup.find_all(["button", "a", "input"]):
            text = (el.get_text() or "").lower()
            classes = " ".join(el.get("class", [])).lower()
            if any(k in text or k in classes for k in ["buy", "checkout", "sign up", "get started", "subscribe", "download", "cta", "primary"]):
                primary_ctas += 1
        if primary_ctas > 0:
            self._add_check("mobile_conversion", f"Primary CTAs detected ({primary_ctas} conversion actions)", True, 3)
        else:
            self._add_check("mobile_conversion", "Primary CTAs detected (buy/signup/get started)", False, 3)

        forms = self.soup.find_all("form")
        if forms:
            inputs = self.soup.find_all("input")
            text_only = len([i for i in inputs if (i.get("type") or "text") == "text"])
            if text_only <= len(inputs) * 0.4:
                self._add_check("mobile_conversion", f"Low-friction forms ({text_only}/{len(inputs)} generic text inputs)", True, 2)
            else:
                self._add_check("mobile_conversion", f"High-friction forms ({text_only}/{len(inputs)} generic text inputs)", False, 2)
        else:
            self._add_check("mobile_conversion", "Conversion forms present", False, 2)

        for key in ["sticky_cta", "trust_signals", "social_proof", "payment_options", "click_to_call"]:
            if key in found:
                pretty = key.replace("_", " ").title()
                self._add_check("mobile_conversion", f"Conversion lever: {pretty} present", True, 2)
            else:
                pretty = key.replace("_", " ").title()
                self._add_check("mobile_conversion", f"Conversion lever: {pretty} present", False, 2)

        if len(found) >= 5:
            self._add_check("mobile_conversion", f"Strong conversion optimization signals ({len(found)}/{len(CONVERSION_PATTERNS)})", True, 3)
        elif len(found) >= 2:
            self._add_check("mobile_conversion", f"Partial conversion optimization signals ({len(found)}/{len(CONVERSION_PATTERNS)})", False, 3)
        else:
            self._add_check("mobile_conversion", f"Weak conversion optimization signals ({len(found)}/{len(CONVERSION_PATTERNS)})", False, 3)

        self.conversion_analysis = {
            "found": found,
            "missing": missing,
            "coverage": f"{len(found)}/{len(CONVERSION_PATTERNS)}",
        }

    def check_mobile_engagement(self):
        html = self.html_text_lower
        js = self.js_text_full
        combined = html + js

        found = []
        missing = []
        for key, patterns in ENGAGEMENT_PATTERNS.items():
            if any(p.lower() in combined for p in patterns):
                found.append(key)
            else:
                missing.append(key)

        for key in ["push_notifications", "share_features", "comments_discussion", "gamification", "personalized_feeds"]:
            if key in found:
                pretty = key.replace("_", " ").title()
                self._add_check("mobile_engagement", f"Engagement signal: {pretty} present", True, 2)
            else:
                pretty = key.replace("_", " ").title()
                self._add_check("mobile_engagement", f"Engagement signal: {pretty} present", False, 2)

        media_count = len(self.soup.find_all(["video", "img"])) + len(self.soup.find_all(attrs={"data-lottie": True}))
        if media_count > 5:
            self._add_check("mobile_engagement", f"Rich media content available ({media_count} media elements)", True, 2)
        elif media_count > 0:
            self._add_check("mobile_engagement", f"Some media content present ({media_count} media elements)", True, 1)
        else:
            self._add_check("mobile_engagement", "Rich media content available", False, 2)

        if len(found) >= 5:
            self._add_check("mobile_engagement", f"Strong engagement signals ({len(found)}/{len(ENGAGEMENT_PATTERNS)})", True, 4)
        elif len(found) >= 2:
            self._add_check("mobile_engagement", f"Partial engagement signals ({len(found)}/{len(ENGAGEMENT_PATTERNS)})", False, 4)
        else:
            self._add_check("mobile_engagement", f"Weak engagement signals ({len(found)}/{len(ENGAGEMENT_PATTERNS)})", False, 4)

        self.engagement_analysis = {
            "found": found,
            "missing": missing,
            "coverage": f"{len(found)}/{len(ENGAGEMENT_PATTERNS)}",
        }

    def check_mobile_retention(self):
        html = self.html_text_lower
        js = self.js_text_full
        combined = html + js

        found = []
        missing = []
        for key, patterns in RETENTION_PATTERNS.items():
            if any(p.lower() in combined for p in patterns):
                found.append(key)
            else:
                missing.append(key)

        for key in ["pwa_install", "account_system", "offline_access", "email_capture", "loyalty_program"]:
            if key in found:
                pretty = key.replace("_", " ").title()
                self._add_check("mobile_retention", f"Retention signal: {pretty} present", True, 2)
            else:
                pretty = key.replace("_", " ").title()
                self._add_check("mobile_retention", f"Retention signal: {pretty} present", False, 2)

        if self.manifest and (self.manifest.get("shortcuts") or self.manifest.get("share_target")):
            self._add_check("mobile_retention", "Manifest shortcuts / share_target aid retention", True, 2)
        else:
            self._add_check("mobile_retention", "Manifest shortcuts / share_target aid retention", False, 2)

        if len(found) >= 5:
            self._add_check("mobile_retention", f"Strong retention signals ({len(found)}/{len(RETENTION_PATTERNS)})", True, 4)
        elif len(found) >= 2:
            self._add_check("mobile_retention", f"Partial retention signals ({len(found)}/{len(RETENTION_PATTERNS)})", False, 4)
        else:
            self._add_check("mobile_retention", f"Weak retention signals ({len(found)}/{len(RETENTION_PATTERNS)})", False, 4)

        self.retention_analysis = {
            "found": found,
            "missing": missing,
            "coverage": f"{len(found)}/{len(RETENTION_PATTERNS)}",
        }

    def check_touch_feedback(self):
        css = self.css_text
        js = self.js_text_full
        html = self.html_text_lower
        combined = css + js + html

        active_selectors = len(re.findall(r":active\b", css))
        if active_selectors > 0:
            self._add_check("touch_feedback", f"CSS :active touch feedback found ({active_selectors} selectors)", True, 3)
        else:
            self._add_check("touch_feedback", "CSS :active touch feedback found (no :active states)", False, 3)

        ripple = any(e in combined for e in [
            "ripple", "mdc-ripple", "touch-ripple", "material-ripple",
            "water-ripple", "ripple-effect", "ink-splash",
        ])
        if ripple:
            self._add_check("touch_feedback", "Ripple / press animation effect detected", True, 2)
        else:
            self._add_check("touch_feedback", "Ripple / press animation effect detected", False, 2)

        tap_highlight = "-webkit-tap-highlight-color" in css
        if tap_highlight:
            self._add_check("touch_feedback", "Tap highlight color customized (-webkit-tap-highlight-color)", True, 2)
        else:
            self._add_check("touch_feedback", "Tap highlight color customized (-webkit-tap-highlight-color)", False, 2)

        pressed_state = any(e in combined for e in [
            "is-pressed", "btn-pressed", "button-active", "active-state",
            "touch-active", "tap-highlight", "pressed", "aria-pressed",
        ])
        if pressed_state:
            self._add_check("touch_feedback", "Pressed / active state styling detected", True, 2)
        else:
            self._add_check("touch_feedback", "Pressed / active state styling detected", False, 2)

        scale_on_active = bool(re.search(r":active[^{]*\{[^}]*transform\s*:", css)) or bool(
            re.search(r":active[^{]*\{[^}]*scale", css)
        )
        if scale_on_active:
            self._add_check("touch_feedback", "Transform feedback on :active (scale/press micro-interaction)", True, 2)
        else:
            self._add_check("touch_feedback", "Transform feedback on :active (scale/press micro-interaction)", False, 2)

        transition_feedback = bool(re.search(r"(?:button|\.btn|:active)[^{]*\{[^}]*transition\s*:", css)) or bool(
            re.search(r"transition[^{]*transform", css)
        )
        if transition_feedback:
            self._add_check("touch_feedback", "Transition feedback on interactive elements", True, 1)
        else:
            self._add_check("touch_feedback", "Transition feedback on interactive elements", False, 1)

        visual_response = any(e in combined for e in [
            "focus-visible", "focus-within", "spinner", "loading", "progress",
            "toast", "snackbar", "aria-busy",
        ])
        if visual_response:
            self._add_check("touch_feedback", "Visual response states (focus/loading/toast) present", True, 2)
        else:
            self._add_check("touch_feedback", "Visual response states (focus/loading/toast) present", False, 2)

    def check_haptic_feedback(self):
        css = self.css_text
        js = self.js_text_full
        html = self.html_text_lower
        combined = css + js + html

        vibrate_api = any(e in combined for e in [
            "navigator.vibrate", "vibrate(", "vibrate([", "vibration api",
        ])
        if vibrate_api:
            self._add_check("haptic_feedback", "navigator.vibrate() haptic API usage detected", True, 3)
        else:
            self._add_check("haptic_feedback", "navigator.vibrate() haptic API usage detected", False, 3)

        vibrate_pattern = bool(re.search(r"vibrate\s*\(\s*\[", js)) or "vibrationpattern" in combined
        if vibrate_pattern:
            self._add_check("haptic_feedback", "Structured vibration patterns (arrays) detected", True, 2)
        else:
            self._add_check("haptic_feedback", "Structured vibration patterns (arrays) detected", False, 2)

        feature_detect = any(e in js for e in [
            "'vibrate' in navigator", '"vibrate" in navigator',
            "typeof navigator.vibrate", "navigator.vibrate &&",
            "if (navigator.vibrate", "if(navigator.vibrate",
        ]) or "vibrate" in js
        if feature_detect:
            self._add_check("haptic_feedback", "Haptic capability feature detection present", True, 2)
        else:
            self._add_check("haptic_feedback", "Haptic capability feature detection present", False, 2)

        haptic_keywords = [p for p in [
            "haptic", "haptics", "hapticfeedback", "haptic-feedback",
            "taptic", "impactfeedback", "selectionfeedback", "notificationfeedback",
        ] if p in combined]
        if haptic_keywords:
            self._add_check("haptic_feedback", f"Platform haptic keywords found ({haptic_keywords[0]})", True, 2)
        else:
            self._add_check("haptic_feedback", "Platform haptic keywords found (haptic/taptic)", False, 2)

        manifest_vibration = bool(self.manifest and self.manifest.get("vibrate"))
        if manifest_vibration:
            self._add_check("haptic_feedback", "Manifest vibrate permission / pattern declared", True, 1)
        else:
            self._add_check("haptic_feedback", "Manifest vibrate permission / pattern declared", False, 1)

        dual_feedback = vibrate_api and any(e in combined for e in [
            "toast", "snackbar", "ripple", ":active", "spinner", "progress", "aria-live",
        ])
        if dual_feedback:
            self._add_check("haptic_feedback", "Haptics paired with visual/aural feedback (not sole channel)", True, 2)
        else:
            self._add_check("haptic_feedback", "Haptics paired with visual/aural feedback (not sole channel)", False, 2)

        reduced_motion_ok = "prefers-reduced-motion" not in combined or any(
            e in combined for e in ["reduced-motion", "nomotion", "disablevibration", "hapticsoff"]
        )
        if reduced_motion_ok:
            self._add_check("haptic_feedback", "Motion-preference aware vibration handling", True, 1)
        else:
            self._add_check("haptic_feedback", "Motion-preference aware vibration handling", False, 1)

    def check_device_motion(self):
        css = self.css_text
        js = self.js_text_full
        html = self.html_text_lower
        combined = css + js + html

        motion_event = "devicemotion" in combined
        if motion_event:
            self._add_check("device_motion", "devicemotion event listener detected", True, 3)
        else:
            self._add_check("device_motion", "devicemotion event listener detected", False, 3)

        orientation_event = any(e in combined for e in [
            "deviceorientation", "deviceorientationabsolute", "deviceorientationabsolute",
        ])
        if orientation_event:
            self._add_check("device_motion", "deviceorientation event listener detected", True, 3)
        else:
            self._add_check("device_motion", "deviceorientation event listener detected", False, 3)

        permission_request = any(e in js for e in [
            "requestpermission", "devicemotionevent.requestpermission",
            "deviceorientationevent.requestpermission",
        ])
        if permission_request:
            self._add_check("device_motion", "iOS motion permission request (DeviceMotionEvent.requestPermission) handled", True, 2)
        else:
            self._add_check("device_motion", "iOS motion permission request (DeviceMotionEvent.requestPermission) handled", False, 2)

        sensor_api = any(e in combined for e in [
            "accelerometer", "gyroscope", "magnetometer",
            "linearacceleration", "absoluteorientation", "relativemotion",
            "sensor.", "newsensor",
        ])
        if sensor_api:
            self._add_check("device_motion", "Generic Sensor API (accelerometer/gyroscope) detected", True, 2)
        else:
            self._add_check("device_motion", "Generic Sensor API (accelerometer/gyroscope) detected", False, 2)

        motion_usage = any(e in combined for e in [
            "parallax", "tilt", "tilt-effect", "acceleration.x", "acceleration.y",
            "rotationrate", "accelerationincludinggravity", "shake", "shakedetect",
            "compass", "tilt-shift",
        ])
        if motion_usage:
            self._add_check("device_motion", "Motion data used for UX (parallax/tilt/shake)", True, 2)
        else:
            self._add_check("device_motion", "Motion data used for UX (parallax/tilt/shake)", False, 2)

        motion_fallback = any(e in combined for e in [
            "window.devicemotion", "if (devicemotion", "devicemotion &&",
            "typeof devicemotion", "'devicemotion' in", "desktop", "mouse parallax",
        ]) or "prefers-reduced-motion" in combined
        if motion_fallback:
            self._add_check("device_motion", "Motion fallback / reduced-motion guard present", True, 2)
        else:
            self._add_check("device_motion", "Motion fallback / reduced-motion guard present", False, 2)

        screen_orientation_lock = any(e in js for e in [
            "screen.orientation.lock", "orientation.lock", "orientationchange",
        ])
        if screen_orientation_lock:
            self._add_check("device_motion", "Screen orientation lock/change handling detected", True, 1)
        else:
            self._add_check("device_motion", "Screen orientation lock/change handling detected", False, 1)

    def check_battery_api(self):
        js = self.js_text_full
        html = self.html_text_lower
        css = self.css_text
        combined = js + html + css

        battery_api = any(e in combined for e in [
            "getbattery", "batterymanager", "navigator.battery",
            "chargingchange", "levelchange", "chargingtime", "dischargingtime",
        ])
        if battery_api:
            self._add_check("battery_api", "Battery Status API (navigator.getBattery) detected", True, 3)
        else:
            self._add_check("battery_api", "Battery Status API (navigator.getBattery) detected", False, 3)

        battery_events = any(e in js for e in [
            "chargingchange", "chargingtimechange", "dischargingtimechange", "levelchange",
        ])
        if battery_events:
            self._add_check("battery_api", "Battery level/charging event listeners present", True, 2)
        else:
            self._add_check("battery_api", "Battery level/charging event listeners present", False, 2)

        low_battery_branch = any(e in combined for e in [
            "lowbattery", "low-battery", "batterysaver", "battery-saver",
            "level < 0.2", "level<0.2", "level <= 0.15", "battery.low",
            "power.save", "savepower",
        ])
        if low_battery_branch:
            self._add_check("battery_api", "Low-battery adaptive behavior detected", True, 3)
        else:
            self._add_check("battery_api", "Low-battery adaptive behavior detected", False, 3)

        charging_state = any(e in combined for e in ["charging", "ischarging", "oncharger", " plugged"])
        if charging_state:
            self._add_check("battery_api", "Charging-state awareness detected", True, 1)
        else:
            self._add_check("battery_api", "Charging-state awareness detected", False, 1)

        battery_feature_detect = any(e in js for e in [
            "'getbattery' in navigator", '"getbattery" in navigator',
            "navigator.getbattery", "typeof navigator.getbattery",
        ])
        if battery_feature_detect:
            self._add_check("battery_api", "Battery API feature detection present", True, 2)
        else:
            self._add_check("battery_api", "Battery API feature detection present", False, 2)

        power_optimized = any(e in combined for e in [
            "requestidlecallback", "visibilitychange", "pagehide", "freeze",
            "content-visibility", "suspendanimation", "stopanimation",
        ])
        if power_optimized:
            self._add_check("battery_api", "Power-friendly lifecycle handling (idle/visibility/pagehide)", True, 2)
        else:
            self._add_check("battery_api", "Power-friendly lifecycle handling (idle/visibility/pagehide)", False, 2)

    def check_network_information(self):
        js = self.js_text_full
        html = self.html_text_lower
        css = self.css_text
        combined = js + html + css

        connection_api = any(e in combined for e in [
            "navigator.connection", "navigator.mozconnection",
            "navigator.webkitconnection", "connection.effectivetype",
            "connection.downlink", "connection.rtt",
        ])
        if connection_api:
            self._add_check("network_info", "Network Information API (navigator.connection) detected", True, 3)
        else:
            self._add_check("network_info", "Network Information API (navigator.connection) detected", False, 3)

        effective_type_branch = any(e in combined for e in [
            "effectivetype", "effective-type", "'2g'", '"2g"', "'slow-2g'",
            "'3g'", '"3g"', "'4g'", "save-data",
        ]) and "connection" in combined
        if effective_type_branch:
            self._add_check("network_info", "effectiveType-driven content adaptation detected", True, 3)
        else:
            self._add_check("network_info", "effectiveType-driven content adaptation detected", False, 3)

        save_data_probe = any(e in combined for e in ["savedata", "save-data", "data saver", "data-saver"])
        if save_data_probe:
            self._add_check("network_info", "saveData preference probed and acted upon", True, 2)
        else:
            self._add_check("network_info", "saveData preference probed and acted upon", False, 2)

        downlink_rtt = any(e in js for e in [
            "connection.downlink", "connection.rtt", ".downlinkmax", "rtt",
        ])
        if downlink_rtt:
            self._add_check("network_info", "downlink / RTT metrics consulted", True, 2)
        else:
            self._add_check("network_info", "downlink / RTT metrics consulted", False, 2)

        online_offline = (
            "navigator.online" in combined
            or bool(re.search(r"addEventListener\(\s*['\"](?:online|offline)['\"]", js))
            or "connection.change" in combined
        )
        if online_offline:
            self._add_check("network_info", "online/offline connectivity transitions handled", True, 2)
        else:
            self._add_check("network_info", "online/offline connectivity transitions handled", False, 2)

        change_listener = any(e in js for e in [
            "connection.addEventListener", "connection.onchange",
            "'change'.connection", "connection, ", "ontypechange",
        ])
        if change_listener:
            self._add_check("network_info", "Connection change listener re-adapts on network switch", True, 2)
        else:
            self._add_check("network_info", "Connection change listener re-adapts on network switch", False, 2)

        reduced_data_media = "prefers-reduced-data" in css
        if reduced_data_media:
            self._add_check("network_info", "@media (prefers-reduced-data) respected in CSS", True, 2)
        else:
            self._add_check("network_info", "@media (prefers-reduced-data) respected in CSS", False, 2)

        tiered_loading = any(e in combined for e in [
            "lazy", "loading=\"lazy\"", "fetchpriority", "priority: low",
            "preload", "debounce", "throttle", "batch", "chunk",
        ])
        if tiered_loading:
            self._add_check("network_info", "Tiered/lazy loading reduces cost on slow networks", True, 2)
        else:
            self._add_check("network_info", "Tiered/lazy loading reduces cost on slow networks", False, 2)

    def check_geolocation(self):
        js = self.js_text_full
        html = self.html_text_lower
        combined = js + html

        geo_api = any(e in combined for e in [
            "navigator.geolocation", "geolocation.getcurrentposition",
            "geolocation.watchposition", "geolocation.clearwatch",
        ])
        if geo_api:
            self._add_check("geolocation", "Geolocation API usage detected", True, 3)
        else:
            self._add_check("geolocation", "Geolocation API usage detected", False, 3)

        permission_flow = any(e in combined for e in [
            "permission", "permission denied", "permissiondenied",
            "geolocation.requestpermission", "querypermission",
            "navigator.permissions",
        ])
        if permission_flow:
            self._add_check("geolocation", "Location permission request / denial handling", True, 3)
        else:
            self._add_check("geolocation", "Location permission request / denial handling", False, 3)

        error_handling = any(e in js for e in [
            "code === 1", "code===1", "code == 1", "position_error",
            "onerror", "error.code", "geoerror", "err.code",
        ])
        if error_handling:
            self._add_check("geolocation", "Geolocation error callback / fallback handling", True, 2)
        else:
            self._add_check("geolocation", "Geolocation error callback / fallback handling", False, 2)

        manual_fallback = any(e in combined for e in [
            "enter location", "manual location", "zip code", "postcode",
            "city search", "address input", "location input", "use current location",
        ])
        if manual_fallback:
            self._add_check("geolocation", "Manual location fallback for denied/blocked GPS", True, 2)
        else:
            self._add_check("geolocation", "Manual location fallback for denied/blocked GPS", False, 2)

        map_integration = any(e in combined for e in [
            "google.maps", "leaflet", "mapbox", "openstreetmap", "maplibre",
            "showmap", "map-container", "ymaps",
        ])
        if map_integration:
            self._add_check("geolocation", "Map integration consumes location data", True, 2)
        else:
            self._add_check("geolocation", "Map integration consumes location data", False, 2)

        https_ok = str(self.url).startswith("https://")
        if geo_api and https_ok:
            self._add_check("geolocation", "Geolocation served over HTTPS (secure context required)", True, 2)
        elif geo_api and not https_ok:
            self._add_check("geolocation", "Geolocation served over HTTPS (secure context required)", False, 2)
        else:
            self._add_check("geolocation", "Geolocation served over HTTPS (secure context required)", True, 1)

        precise_location = any(e in combined for e in [
            "enablehighaccuracy", "enableHighAccuracy", "timeout:", "maximumage",
        ])
        if precise_location:
            self._add_check("geolocation", "Geolocation options (high accuracy/timeout) configured", True, 1)
        else:
            self._add_check("geolocation", "Geolocation options (high accuracy/timeout) configured", False, 1)

        geo_pwa = bool(self.manifest and any(
            k in self.manifest for k in ("geolocation", "handlers", "protocol_handlers")
        )) or "geolocation" in combined
        if geo_pwa:
            self._add_check("geolocation", "Location features align with PWA capabilities", True, 2)
        else:
            self._add_check("geolocation", "Location features align with PWA capabilities", False, 2)

    def check_amp(self):
        amp_link = self.soup.find("link", rel="amphtml")
        if amp_link:
            self._add_check("amp", "AMP version available", True, 3)
        else:
            self._add_check("amp", "AMP version available", False, 3)
        html_text = self.html_text_lower
        if "amp-boilerplate" in html_text or "<html amp" in html_text or "<html \u26a1" in html_text:
            self._add_check("amp", "AMP boilerplate detected", True, 2)
        else:
            self._add_check("amp", "AMP boilerplate detected", False, 2)

    def run_all_checks(self):
        self.check_viewport()
        self.check_responsive()
        self.check_progressive_enhancement()
        self.check_graceful_degradation()
        self.check_offline_capability()
        self.check_low_bandwidth()
        self.check_data_saver()
        self.check_network_information()
        self.check_touch()
        self.check_touch_gestures()
        self.check_touch_feedback()
        self.check_haptic_feedback()
        self.check_pwa()
        self.check_deep_pwa()
        self.check_performance()
        self.check_performance_budget()
        self.check_core_web_vitals()
        self.check_touch_performance()
        self.check_content()
        self.check_navigation()
        self.check_meta()
        self.check_images()
        self.check_mobile_form()
        self.check_device_features()
        self.check_device_motion()
        self.check_battery_api()
        self.check_geolocation()
        self.check_mobile_a11y()
        self.check_mobile_ux_patterns()
        self.check_mobile_conversion()
        self.check_mobile_engagement()
        self.check_mobile_retention()
        self.check_amp()
        self._compute_scores()
        self._build_roadmap()
        self._build_device_matrix()
        self._build_pwa_capability_report()
        self._build_a11y_assessment()
        self._build_analysis_reports()

    def _weighted_category_score(self, weights):
        w_score = 0.0
        w_max = 0.0
        for cat, data in self.results.items():
            w = weights.get(cat, 1.0)
            w_score += data["score"] * w
            w_max += data["max"] * w
        if w_max <= 0:
            return 0.0
        return round((w_score / w_max) * 100, 1)

    def _compute_scores(self):
        if self.max_score > 0:
            base_readiness = (self.total_score / self.max_score) * 100
        else:
            base_readiness = 0.0
        weighted_readiness = self._weighted_category_score(READINESS_WEIGHTS)

        ux_component = self._weighted_category_score(MOBILE_UX_SCORE_WEIGHTS)
        ux_pattern_bonus = 0.0
        ux_data = self.results.get("mobile_ux", {"score": 0, "max": 1})
        ux_pct = (ux_data["score"] / max(ux_data["max"], 1)) * 100
        if ux_pct >= 80:
            ux_pattern_bonus = 4.0
        elif ux_pct >= 60:
            ux_pattern_bonus = 2.0
        self.mobile_ux_score = round(min(100.0, ux_component + ux_pattern_bonus), 1)

        perf_weighted = self._weighted_category_score(MOBILE_PERF_SCORE_WEIGHTS)
        budget_data = self.results.get("perf_budget", {"score": 0, "max": 1})
        base_budget = (budget_data["score"] / max(budget_data["max"], 1)) * 100
        page_kb = len(self.resp.content) / 1024
        ratio = page_kb / max(self.budget["max_page_size_kb"], 1)
        if ratio > 1.5:
            penalty = 0.85
        elif ratio > 1.0:
            penalty = 0.95
        else:
            penalty = 1.0
        est_penalty = 1.0
        load_budget = self.budget.get("load_time_ms", 5000)
        if self.perf_load_estimate_ms > load_budget * 1.5:
            est_penalty = 0.9
        elif self.perf_load_estimate_ms <= load_budget * 0.6:
            est_penalty = 1.03
        self.perf_budget_score = round(base_budget * penalty * est_penalty, 1)
        if self.perf_budget_score > 100:
            self.perf_budget_score = 100.0

        self.network_adapt_score = self._weighted_category_score(NETWORK_ADAPT_SCORE_WEIGHTS)
        self.mobile_perf_score = round(
            min(
                100.0,
                (perf_weighted * 0.62)
                + (self.perf_budget_score * 0.25)
                + (self.network_adapt_score * 0.13),
            ),
            1,
        )

        analysis_avg = (
            self._category_pct("mobile_ux")
            + self._category_pct("mobile_conversion")
            + self._category_pct("mobile_engagement")
            + self._category_pct("mobile_retention")
        ) / 4.0
        a11y_pct = self._category_pct("mobile_a11y")
        capability_component = (
            self._category_pct("touch_feedback")
            + self._category_pct("haptic_feedback")
            + self._category_pct("network_info")
            + self._category_pct("battery_api")
            + self._category_pct("device_motion")
            + self._category_pct("geolocation")
        ) / 6.0
        self.mobile_capability_score = round(capability_component, 1)
        readiness_blend = (
            base_readiness * 0.25
            + weighted_readiness * 0.42
            + self.mobile_ux_score * 0.10
            + self.mobile_perf_score * 0.11
            + analysis_avg * 0.05
            + a11y_pct * 0.04
            + capability_component * 0.03
        )
        self.mobile_readiness = round(min(100.0, readiness_blend), 1)

        pwa_base = self._weighted_category_score(PWA_SCORE_WEIGHTS)
        offline_pct = self._category_pct("offline_capability")
        pwa_cat_pct = self._category_pct("pwa")
        deep_pwa_pct = self._category_pct("deep_pwa")
        installability_boost = 0.0
        manifest_ok = bool(self._check_passed("pwa", "Web App Manifest"))
        sw_ok = bool(self._check_passed("pwa", "Service Worker registration"))
        if manifest_ok and sw_ok:
            installability_boost = 4.0
        elif manifest_ok or sw_ok:
            installability_boost = 1.5
        self.pwa_score = round(
            min(
                100.0,
                (pwa_base * 0.66)
                + (offline_pct * 0.16)
                + (pwa_cat_pct * 0.08)
                + (deep_pwa_pct * 0.10)
                + installability_boost,
            ),
            1,
        )
        self.touch_score = self._weighted_category_score(TOUCH_SCORE_WEIGHTS)

    def _build_roadmap(self):
        failed_items = []
        for cat, data in self.results.items():
            for detail in data["details"]:
                if not detail["passed"]:
                    priority = ROADMAP_PRIORITIES.get(cat, 99)
                    failed_items.append((priority, cat, detail["check"], detail["points"]))
        failed_items.sort(key=lambda x: (-x[3], x[0]))
        self.roadmap = []
        seen = set()
        quick_win_count = 0
        phase_counts = {"p1": 0, "p2": 0, "p3": 0}
        for priority, cat, check, points in failed_items:
            key = f"{cat}:{check}"
            if key in seen:
                continue
            seen.add(key)
            label = CATEGORY_LABELS.get(cat, cat)
            urgency = "CRITICAL" if points >= 3 else "HIGH" if points >= 2 else "MEDIUM"
            if urgency == "CRITICAL":
                phase = "Phase 1 - Quick Wins (this week)"
                quick_win_count += 1
                phase_counts["p1"] += 1
                roi = "High ROI - low effort, high score impact"
            elif urgency == "HIGH":
                phase = "Phase 2 - Near Term (this sprint)"
                phase_counts["p2"] += 1
                roi = "Medium ROI - meaningful score lift"
            else:
                phase = "Phase 3 - Long Term (backlog)"
                phase_counts["p3"] += 1
                roi = "Long-tail polish - incremental gain"
            effort = "Low" if points <= 2 else "Medium" if points == 3 else "High"
            owner = ROADMAP_OWNERS.get(cat, "Engineering")
            if cat in ("mobile_a11y", "viewport"):
                depends = "None - independent fix"
            elif cat in ("deep_pwa", "offline_capability"):
                depends = "Requires Service Worker + Manifest"
            elif cat in ("network_info", "data_saver", "low_bandwidth", "perf_budget"):
                depends = "Coordinate with perf budget changes"
            elif cat in ("touch_feedback", "haptic_feedback", "device_motion"):
                depends = "Requires touch-capable test device"
            else:
                depends = "None - independent fix"
            est_gain = round((points / max(self.max_score, 1)) * 100, 2)
            self.roadmap.append({
                "priority": urgency,
                "phase": phase,
                "category": label,
                "issue": check,
                "impact": f"{points} points",
                "effort": effort,
                "category_key": cat,
                "owner": owner,
                "roi": roi,
                "depends_on": depends,
                "est_score_gain_pct": est_gain,
            })
        total_items = len(self.roadmap)
        self.roadmap_summary = {
            "total_items": total_items,
            "critical": sum(1 for i in self.roadmap if i["priority"] == "CRITICAL"),
            "high": sum(1 for i in self.roadmap if i["priority"] == "HIGH"),
            "medium": sum(1 for i in self.roadmap if i["priority"] == "MEDIUM"),
            "quick_wins": quick_win_count,
            "phase_1_count": phase_counts["p1"],
            "phase_2_count": phase_counts["p2"],
            "phase_3_count": phase_counts["p3"],
            "owners": sorted({i["owner"] for i in self.roadmap}),
            "phases": [
                "Phase 1 - Quick Wins (this week)",
                "Phase 2 - Near Term (this sprint)",
                "Phase 3 - Long Term (backlog)",
            ],
            "headline": (
                f"{phase_counts['p1']} quick wins, {phase_counts['p2']} near-term, "
                f"{phase_counts['p3']} backlog items"
            ),
        }

    def _build_device_matrix(self):
        touch_data = self.results.get("touch", {"score": 0, "max": 1})
        touch_ok = (touch_data["score"] / max(touch_data["max"], 1)) >= 0.5

        def signal(key):
            if key == "touch":
                return touch_ok
            if key == "viewport":
                v = self._check_passed("viewport", "Viewport meta tag exists")
                if v is None:
                    v = self._check_passed("viewport", "width=device-width")
                return bool(v)
            if key == "mobile_first":
                return bool(self._check_passed("responsive", "Mobile-first CSS"))
            if key == "breakpoints":
                return bool(self._check_passed("responsive", "breakpoints defined")) or bool(self._check_passed("responsive", "breakpoint"))
            if key == "safe_area":
                return bool(self._check_passed("device", "Notch/safe-area"))
            if key == "dark_mode":
                return bool(self._check_passed("device", "Dark mode"))
            if key == "orientation":
                return bool(self._check_passed("device", "orientation"))
            if key == "hover":
                return bool(self._check_passed("touch", "Hover state"))
            if key == "foldable":
                return bool(self._check_passed("device", "Foldable"))
            if key == "haptic":
                return bool(self._check_passed("device", "Haptic"))
            if key == "ar_vr":
                return bool(self._check_passed("device", "AR/VR"))
            if key == "zoom":
                z = self._check_passed("touch", "Viewport allows user scaling")
                if z is None:
                    z = self._check_passed("viewport", "user-scalable=no not used")
                return bool(z)
            if key == "responsive_images":
                return bool(self._check_passed("responsive", "Responsive images"))
            if key == "low_bandwidth":
                return self._cat_ok("low_bandwidth", 0.5)
            if key == "data_saver":
                return self._cat_ok("data_saver", 0.4)
            if key == "offline":
                return self._cat_ok("offline_capability", 0.4)
            if key == "responsive":
                return self._cat_ok("responsive", 0.5)
            if key == "touch_feedback":
                return self._cat_ok("touch_feedback", 0.45)
            if key == "content":
                return self._cat_ok("content", 0.5)
            if key == "motion":
                return self._cat_ok("device_motion", 0.4)
            if key == "battery":
                return self._cat_ok("battery_api", 0.35)
            if key == "network_info":
                return self._cat_ok("network_info", 0.4)
            if key == "geolocation":
                return self._cat_ok("geolocation", 0.4)
            return False

        self.device_matrix = []
        supported_count = 0
        partial_count = 0
        unsupported_count = 0
        for name, range_str, requires, optional in DEVICE_CLASSES:
            required_pass = sum(1 for k in requires if signal(k))
            optional_pass = sum(1 for k in optional if signal(k))
            missing = [SIGNAL_LABELS.get(k, k) for k in requires if not signal(k)]
            optional_missing = [SIGNAL_LABELS.get(k, k) for k in optional if not signal(k)]
            if required_pass == len(requires):
                status = "supported"
                supported_count += 1
            elif required_pass * 2 >= len(requires):
                status = "partial"
                partial_count += 1
            else:
                status = "unsupported"
                unsupported_count += 1
            coverage_pct = round((required_pass / max(len(requires), 1)) * 100, 1)
            if status == "supported":
                note = "Fully ready for this device class"
            elif status == "partial":
                note = f"Works with gaps: {', '.join(missing[:3])}" if missing else "Minor optional gaps"
            else:
                note = f"Key gaps: {', '.join(missing[:3])}" if missing else "Needs work"
            self.device_matrix.append({
                "device": name,
                "range": range_str,
                "status": status,
                "required_coverage": f"{required_pass}/{len(requires)}",
                "optional_coverage": f"{optional_pass}/{len(optional)}",
                "missing_required": missing,
                "missing_optional": optional_missing,
                "coverage_pct": coverage_pct,
                "note": note,
            })
        total_devices = len(self.device_matrix)
        overall_pct = 0.0
        if total_devices > 0:
            overall_pct = round(
                (supported_count + 0.5 * partial_count) / total_devices * 100, 1
            )
        if overall_pct >= 85:
            readiness_label = "Excellent cross-device readiness"
        elif overall_pct >= 65:
            readiness_label = "Good - a few device classes need work"
        elif overall_pct >= 40:
            readiness_label = "Fair - significant device gaps remain"
        else:
            readiness_label = "Poor - prioritize core mobile device support"
        weak_devices = [
            row["device"] for row in self.device_matrix
            if row["status"] != "supported"
        ]
        self.device_matrix_summary = {
            "supported": supported_count,
            "partial": partial_count,
            "unsupported": unsupported_count,
            "total": total_devices,
            "overall_pct": overall_pct,
            "readiness_label": readiness_label,
            "weak_devices": weak_devices,
            "signal_coverage": round(
                sum(row.get("coverage_pct", 0) for row in self.device_matrix) / max(total_devices, 1), 1
            ),
        }

    def _build_pwa_capability_report(self):
        features = [
            ("Web App Manifest", self._check_passed("pwa", "Web App Manifest")),
            ("Service Worker", self._check_passed("pwa", "Service Worker registration")),
            ("Install Prompt Handling", self._check_passed("pwa", "Install prompt")),
            ("Offline / Caching", self._check_passed("pwa", "Offline/caching")),
            ("App Icons", self._check_passed("pwa", "Icons configured")),
            ("Maskable Icon", self._check_passed("pwa", "Maskable icon")),
            ("Standalone Display", self._check_passed("pwa", "Display mode")),
            ("Theme Colors", self._check_passed("pwa", "Theme color")),
            ("Splash Screen", self._check_passed("pwa", "Splash screen")),
            ("Push Notifications", self._check_passed("deep_pwa", "Push notification")),
            ("Background Sync", self._check_passed("deep_pwa", "Background sync")),
            ("Cache Strategies", self._check_passed("deep_pwa", "Cache strategies")),
            ("iOS PWA Support", self._check_passed("deep_pwa", "iOS PWA")),
            ("Web Share API", self._check_passed("deep_pwa", "Web Share")),
            ("Workbox Integration", self._check_passed("deep_pwa", "Workbox")),
            ("Offline Fallback Route", self._check_passed("offline_capability", "Offline fallback")),
            ("Connectivity Monitoring", self._check_passed("offline_capability", "Connectivity monitoring")),
            ("Data Saver Awareness", self._check_passed("data_saver", "saveData-aware")),
            ("Network Information API", self._check_passed("data_saver", "Network Information API")),
            ("Low-Bandwidth Hints", self._check_passed("low_bandwidth", "Resource hints")),
            ("Touch Feedback States", self._check_passed("touch_feedback", ":active")),
            ("Haptic Feedback", self._check_passed("haptic_feedback", "navigator.vibrate")),
            ("Network Info Adaptation", self._check_passed("network_info", "Network Information API")),
            ("Battery Awareness", self._check_passed("battery_api", "Battery Status API")),
            ("Device Motion Support", self._check_passed("device_motion", "devicemotion")),
            ("Geolocation Integration", self._check_passed("geolocation", "Geolocation API")),
            ("Manifest Identity (id)", self._check_passed("pwa", "Manifest id")),
            ("Share Target", self._check_passed("deep_pwa", "share_target")),
            ("App Shortcuts", self._check_passed("deep_pwa", "shortcuts")),
        ]
        feature_list = []
        supported = 0
        for label, value in features:
            ok = bool(value)
            if ok:
                supported += 1
            feature_list.append({
                "feature": label,
                "supported": ok,
                "status": "yes" if ok else "no",
            })
        manifest_ok = bool(self._check_passed("pwa", "Web App Manifest"))
        sw_ok = bool(self._check_passed("pwa", "Service Worker registration"))
        icons_ok = bool(self._check_passed("pwa", "Icons configured")) or bool(self._check_passed("pwa", "Standard icon sizes"))
        entry_ok = bool(self._check_passed("pwa", "Start URL")) or bool(self._check_passed("pwa", "Display mode"))
        installable = manifest_ok and sw_ok and icons_ok and entry_ok
        offline_ok = self._cat_ok("offline_capability", 0.5)
        total = len(feature_list)
        capability_pct = round((supported / max(total, 1)) * 100, 1)
        if capability_pct >= 80 and offline_ok:
            tier = "Full-featured PWA"
        elif capability_pct >= 80:
            tier = "Install-ready"
        elif capability_pct >= 50:
            tier = "Partial PWA"
        else:
            tier = "Basic web app"
        installability_criteria = [
            {"criterion": "Web app manifest linked", "met": bool(self._check_passed("pwa", "Web App Manifest"))},
            {"criterion": "Service worker registered", "met": bool(self._check_passed("pwa", "Service Worker registration"))},
            {"criterion": "Icons (192 + 512)", "met": bool(self._check_passed("pwa", "Standard icon sizes")) or bool(self._check_passed("pwa", "Icons configured"))},
            {"criterion": "Start URL configured", "met": bool(self._check_passed("pwa", "Start URL"))},
            {"criterion": "Standalone display mode", "met": bool(self._check_passed("pwa", "Display mode"))},
            {"criterion": "Name / short_name set", "met": bool(self._check_passed("pwa", "App name"))},
        ]
        criteria_met = sum(1 for c in installability_criteria if c["met"])
        score_opportunities = []
        missing_for_score = [f["feature"] for f in feature_list if not f["supported"]]
        opp_map = {
            "Web App Manifest": ("Add manifest with name, icons, start_url, display", 8.0),
            "Service Worker": ("Register SW to unlock offline + installability", 10.0),
            "App Icons": ("Ship 192x192 and 512x512 icons", 5.0),
            "Maskable Icon": ("Add maskable icon for Android adaptive", 2.0),
            "Standalone Display": ("Set display: standalone", 3.0),
            "Install Prompt Handling": ("Handle beforeinstallprompt", 3.0),
            "Offline / Caching": ("Cache core assets for offline use", 6.0),
            "Offline Fallback Route": ("Serve offline.html on failed navigation", 3.0),
            "Push Notifications": ("Wire PushManager for re-engagement", 4.0),
            "Background Sync": ("Queue offline actions with Background Sync", 3.0),
            "iOS PWA Support": ("Add apple-touch-icon + apple meta tags", 3.0),
            "Web Share API": ("Integrate navigator.share()", 2.0),
            "Share Target": ("Add manifest share_target for inbound shares", 2.0),
            "App Shortcuts": ("Add manifest shortcuts for launch actions", 2.0),
            "Manifest Identity (id)": ("Set manifest id for stable identity", 1.0),
        }
        for feat in missing_for_score:
            advice, gain = opp_map.get(feat, (f"Add {feat} support", 1.5))
            score_opportunities.append({"opportunity": advice, "est_gain": gain})
        score_opportunities.sort(key=lambda x: -x["est_gain"])
        missing = [f["feature"] for f in feature_list if not f["supported"]]
        gaps = []
        for feat in missing:
            gaps.append({
                "gap": feat,
                "priority": "HIGH" if feat in (
                    "Web App Manifest", "Service Worker", "App Icons",
                    "Offline / Caching", "Offline Fallback Route",
                ) else "MEDIUM",
            })
        if not offline_ok:
            gaps.append({
                "gap": "Offline experience incomplete",
                "priority": "HIGH",
            })
        next_steps = []
        step_map = {
            "Web App Manifest": "Create and link a web app manifest with name, icons, start_url",
            "Service Worker": "Register a service worker for caching and offline support",
            "Install Prompt Handling": "Handle beforeinstallprompt to offer installation",
            "Offline / Caching": "Implement a caching strategy for core assets",
            "App Icons": "Add 192x192 and 512x512 icons to the manifest",
            "Maskable Icon": "Add a maskable icon for Android adaptive icons",
            "Standalone Display": "Set display: standalone in the manifest",
            "Theme Colors": "Add theme_color to manifest and meta theme-color",
            "Splash Screen": "Configure splash screens for app launch",
            "Push Notifications": "Implement Web Push with PushManager subscription",
            "Background Sync": "Add Background Sync API for offline action queueing",
            "Cache Strategies": "Define cache-first / network-first routes",
            "iOS PWA Support": "Add apple-touch-icon and apple-mobile-web-app meta tags",
            "Web Share API": "Integrate navigator.share() for native share sheets",
            "Workbox Integration": "Use Workbox to simplify service worker caching",
            "Offline Fallback Route": "Serve an offline.html fallback for failed navigations",
            "Connectivity Monitoring": "Listen for online/offline events to adapt UX",
            "Data Saver Awareness": "Check navigator.connection.saveData and reduce payloads",
            "Network Information API": "Probe effectiveType to adapt content quality",
            "Low-Bandwidth Hints": "Add preload/preconnect hints for critical resources",
            "Touch Feedback States": "Add :active states and tap-highlight styling for touch affordance",
            "Haptic Feedback": "Use navigator.vibrate() for subtle haptic confirmation on key actions",
            "Network Info Adaptation": "Branch content quality on navigator.connection.effectiveType",
            "Battery Awareness": "Check navigator.getBattery() and reduce work at low battery",
            "Device Motion Support": "Listen to devicemotion/deviceorientation with a reduced-motion guard",
            "Geolocation Integration": "Integrate navigator.geolocation with permission and error fallbacks",
            "Manifest Identity (id)": "Set an id in the manifest so installed app identity is stable",
            "Share Target": "Add share_target to the manifest to receive shared content",
            "App Shortcuts": "Define manifest shortcuts for quick re-entry actions",
            "Offline experience incomplete": "Add a service worker with an offline fallback page",
        }
        for feat in missing[:5]:
            next_steps.append(step_map.get(feat, f"Add {feat} support"))
        if not next_steps:
            next_steps.append("Maintain PWA features and monitor Lighthouse PWA score")
        next_steps.extend(
            s["opportunity"] for s in score_opportunities[:3]
            if s["opportunity"] not in next_steps
        )
        self.pwa_report = {
            "features": feature_list,
            "supported": supported,
            "total": total,
            "capability_pct": capability_pct,
            "tier": tier,
            "installable": installable,
            "offline_ready": offline_ok,
            "missing": missing,
            "gaps": gaps,
            "next_steps": next_steps,
            "installability_criteria": installability_criteria,
            "criteria_met": criteria_met,
            "criteria_total": len(installability_criteria),
            "score_opportunities": score_opportunities[:5],
            "pwa_score": self.pwa_score,
            "badges": self._pwa_badges(capability_pct, installable, offline_ok),
        }

    def _pwa_badges(self, capability_pct, installable, offline_ok):
        badges = []
        if installable:
            badges.append("Installable")
        if offline_ok:
            badges.append("Offline Ready")
        if capability_pct >= 90:
            badges.append("Best-in-class PWA")
        elif capability_pct >= 75:
            badges.append("Strong PWA")
        if bool(self._check_passed("deep_pwa", "Push notification")):
            badges.append("Push Enabled")
        if bool(self._check_passed("deep_pwa", "iOS PWA")):
            badges.append("iOS Ready")
        if bool(self._check_passed("offline_capability", "Background sync")):
            badges.append("Background Sync")
        if not badges:
            badges.append("Foundations Needed")
        return badges

    def _build_a11y_assessment(self):
        data = self.results.get("mobile_a11y", {"score": 0, "max": 1, "details": []})
        pct = round((data["score"] / max(data["max"], 1)) * 100, 1)
        if pct >= 80:
            level = "Strong"
            wcag = "Likely WCAG 2.2 AA aligned for mobile"
        elif pct >= 50:
            level = "Needs Improvement"
            wcag = "Partial WCAG 2.2 AA coverage - remediate failed checks"
        else:
            level = "Poor"
            wcag = "Below WCAG 2.2 AA - prioritize mobile accessibility fixes"
        issues = [d["check"] for d in data["details"] if not d["passed"]]
        strengths = [d["check"] for d in data["details"] if d["passed"]]
        priority_fixes = []
        fix_map = {
            "pinch-zoom": "Allow pinch-zoom in viewport meta (remove user-scalable=no)",
            "Focus": "Add :focus-visible styles for keyboard/switch navigation",
            "landmarks": "Add semantic landmarks: header, nav, main, footer",
            "alt text": "Add descriptive alt attributes to meaningful images",
            "Language attribute": "Set lang attribute on the <html> element",
            "touch target": "Enforce min 44x48px touch targets in CSS",
            "typography": "Use rem/em font sizes for scalable text",
            "reduced-motion": "Respect prefers-reduced-motion",
            "Skip navigation": "Add a skip-to-content link",
            "ARIA": "Add ARIA roles/labels where native semantics are missing",
            "forced-colors": "Support forced-colors and prefers-contrast",
            "target size": "Meet WCAG 2.5.8: at least 24x24px target spacing/size",
            "Reflow": "Support single-column reflow at 320px CSS width (WCAG 1.4.10)",
            "Text zoom": "Do not lock viewport scale; use relative font sizes for text resize",
            "Dialog/modal": "Trap focus in dialogs with aria-modal/inert and restore on close",
            "aria-describedby": "Wire aria-describedby from inputs to their help/error text",
            "Alert/status": "Use role=alert / aria-live for async status and errors",
        }
        for issue in issues:
            for needle, fix in fix_map.items():
                if needle.lower() in issue.lower():
                    priority_fixes.append(fix)
                    break
            if len(priority_fixes) >= 5:
                break
        zoom_ok = bool(self._check_passed("mobile_a11y", "pinch-zoom"))
        focus_ok = bool(self._check_passed("mobile_a11y", "Focus"))
        target_ok = bool(self._check_passed("mobile_a11y", "touch target"))
        critical_failures = []
        if not zoom_ok:
            critical_failures.append("Pinch-zoom blocked for low-vision users")
        if not focus_ok:
            critical_failures.append("Missing visible focus styles")
        if not target_ok:
            critical_failures.append("Touch targets below 44/48px minimum")
        wcag_criteria = [
            {"criterion": "1.4.4 Resize Text", "met": bool(self._check_passed("mobile_a11y", "Text zoom"))},
            {"criterion": "1.4.10 Reflow", "met": bool(self._check_passed("mobile_a11y", "Reflow"))},
            {"criterion": "1.4.13 Content on Hover", "met": bool(self._check_passed("mobile_a11y", "Focus"))},
            {"criterion": "2.1.1 Keyboard", "met": bool(self._check_passed("mobile_a11y", "Focus"))},
            {"criterion": "2.4.1 Bypass Blocks", "met": bool(self._check_passed("mobile_a11y", "Skip navigation"))},
            {"criterion": "2.4.7 Focus Visible", "met": focus_ok},
            {"criterion": "2.5.8 Target Size (Minimum)", "met": bool(self._check_passed("mobile_a11y", "target size")) or target_ok},
            {"criterion": "3.3.2 Labels or Instructions", "met": bool(self._check_passed("mobile_form", "labels")) or bool(self._check_passed("mobile_a11y", "aria-describedby"))},
            {"criterion": "4.1.2 Name, Role, Value", "met": bool(self._check_passed("mobile_a11y", "ARIA"))},
            {"criterion": "4.1.3 Status Messages", "met": bool(self._check_passed("mobile_a11y", "Alert/status"))},
            {"criterion": "1.4.3 Contrast (proxy: forced-colors)", "met": bool(self._check_passed("mobile_a11y", "forced-colors"))},
            {"criterion": "2.3.3 Animation from Interactions", "met": bool(self._check_passed("mobile_a11y", "reduced-motion"))},
        ]
        criteria_met = sum(1 for c in wcag_criteria if c["met"])
        self.a11y_assessment = {
            "score": pct,
            "level": level,
            "wcag_note": wcag,
            "issues": issues,
            "strengths": strengths,
            "priority_fixes": priority_fixes,
            "critical_failures": critical_failures,
            "passed_count": len(strengths),
            "total_checks": len(strengths) + len(issues),
            "wcag_criteria": wcag_criteria,
            "criteria_met": criteria_met,
            "criteria_total": len(wcag_criteria),
            "criteria_pct": round((criteria_met / max(len(wcag_criteria), 1)) * 100, 1),
            "headroom_to_strong": round(max(0.0, 80 - pct), 1),
        }

    def _build_analysis_reports(self):
        def pct_of(key_data, total):
            if total <= 0:
                return 0.0
            return round((key_data / total) * 100, 1)

        ux = self.ux_patterns_analysis or {"found": [], "missing": [], "coverage": "0/0"}
        conv = self.conversion_analysis or {"found": [], "missing": [], "coverage": "0/0"}
        eng = self.engagement_analysis or {"found": [], "missing": [], "coverage": "0/0"}
        ret = self.retention_analysis or {"found": [], "missing": [], "coverage": "0/0"}

        ux_score = self._category_pct("mobile_ux")
        conv_score = self._category_pct("mobile_conversion")
        eng_score = self._category_pct("mobile_engagement")
        ret_score = self._category_pct("mobile_retention")

        self.ux_patterns_analysis = dict(ux)
        self.ux_patterns_analysis["score"] = ux_score
        self.conversion_analysis = dict(conv)
        self.conversion_analysis["score"] = conv_score
        self.engagement_analysis = dict(eng)
        self.engagement_analysis["score"] = eng_score
        self.retention_analysis = dict(ret)
        self.retention_analysis["score"] = ret_score

        def grade_from(p):
            if p >= 80:
                return "Excellent"
            if p >= 60:
                return "Good"
            if p >= 40:
                return "Needs Work"
            return "Poor"

        self.ux_patterns_analysis["grade"] = grade_from(ux_score)
        self.conversion_analysis["grade"] = grade_from(conv_score)
        self.engagement_analysis["grade"] = grade_from(eng_score)
        self.retention_analysis["grade"] = grade_from(ret_score)

    def get_grade(self):
        pct = self.mobile_readiness
        if pct >= 90:
            return "A", "Excellent", "green"
        elif pct >= 70:
            return "B", "Good", "cyan"
        elif pct >= 50:
            return "C", "Needs Improvement", "yellow"
        elif pct >= 30:
            return "D", "Poor", "red"
        else:
            return "F", "Very Poor", "red"

    def get_recommendations(self):
        recs = []
        for cat, data in self.results.items():
            for detail in data["details"]:
                if not detail["passed"]:
                    if cat == "viewport":
                        if "Viewport meta" in detail["check"]:
                            recs.append("Add a viewport meta tag: <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">")
                        elif "user-scalable" in detail["check"]:
                            recs.append("Remove user-scalable=no to allow zooming for accessibility")
                        elif "maximum-scale" in detail["check"]:
                            recs.append("Remove maximum-scale restriction to allow zooming")
                        elif "viewport-fit" in detail["check"]:
                            recs.append("Add viewport-fit=cover to the viewport meta for notched devices")
                    elif cat == "responsive":
                        if "media queries" in detail["check"]:
                            recs.append("Add CSS media queries for responsive breakpoints")
                        elif "framework" in detail["check"]:
                            recs.append("Consider using a responsive CSS framework (Bootstrap, Tailwind, etc.)")
                        elif "Responsive images" in detail["check"]:
                            recs.append("Use srcset attribute or <picture> element for responsive images")
                        elif "Flexible" in detail["check"]:
                            recs.append("Use percentage-based widths instead of fixed pixel widths")
                        elif "Mobile-first" in detail["check"] or "Desktop-first" in detail["check"]:
                            recs.append("Write mobile-first CSS using min-width media queries instead of max-width")
                        elif "breakpoint" in detail["check"]:
                            recs.append("Define at least 2-3 width breakpoints covering common device widths (375, 768, 1024, 1280)")
                        elif "container queries" in detail["check"]:
                            recs.append("Adopt CSS container queries (@container) for component-level responsiveness")
                        elif "viewport units" in detail["check"] or "vh/vw" in detail["check"] or "viewport-relative" in detail["check"]:
                            recs.append("Use dynamic viewport units (dvh/svh/lvh) so layouts adapt to mobile browser chrome")
                    elif cat == "touch":
                        if "Touch event" in detail["check"]:
                            recs.append("Add touch event listeners for better mobile interaction")
                        elif "Touch delay" in detail["check"]:
                            recs.append("Add touchstart/touchend handlers or set viewport width=device-width to avoid 300ms delay")
                        elif "Swipe" in detail["check"]:
                            recs.append("Implement swipe gesture detection for mobile navigation")
                        elif "Pinch-to-zoom" in detail["check"]:
                            recs.append("Allow pinch-to-zoom by not restricting user-scalable and maximum-scale")
                        elif "Long press" in detail["check"]:
                            recs.append("Consider adding long-press detection for contextual mobile actions")
                        elif "touch targets" in detail["check"]:
                            recs.append("Ensure all interactive elements are at least 44x44px")
                        elif "Hover" in detail["check"]:
                            recs.append("Add @media (hover: hover) and @media (hover: none) queries for touch devices")
                    elif cat == "touch_gesture":
                        if "Pull-to-refresh" in detail["check"]:
                            recs.append("Add overscroll-behavior: contain/none to prevent unwanted pull-to-refresh")
                        elif "Infinite scroll" in detail["check"]:
                            recs.append("Implement infinite scroll with IntersectionObserver for mobile content loading")
                        elif "Advanced gesture" in detail["check"]:
                            recs.append("Consider using Hammer.js or Pointer Events for advanced touch gestures")
                        elif "Multi-touch" in detail["check"]:
                            recs.append("Add multi-touch support using Pointer Events API for better cross-device compatibility")
                        elif "Drag-and-drop" in detail["check"]:
                            recs.append("Implement touch-friendly drag-and-drop with visual feedback for mobile")
                    elif cat == "pwa":
                        if "Web App Manifest" in detail["check"]:
                            recs.append("Create a web app manifest (manifest.json) and link it with <link rel=\"manifest\">")
                        elif "Service Worker" in detail["check"]:
                            recs.append("Register a service worker for offline support and caching")
                        elif "Install prompt" in detail["check"]:
                            recs.append("Implement beforeinstallprompt event handler for install prompts")
                        elif "Display mode" in detail["check"]:
                            recs.append("Set display to 'standalone' or 'fullscreen' in the web app manifest")
                        elif "Theme color" in detail["check"]:
                            recs.append("Add theme_color to manifest.json and <meta name=\"theme-color\">")
                        elif "Background color" in detail["check"]:
                            recs.append("Add background_color to manifest.json")
                        elif "Icons" in detail["check"] or "icon sizes" in detail["check"]:
                            recs.append("Add icons to manifest.json with 192x192 and 512x512 sizes")
                        elif "Maskable" in detail["check"]:
                            recs.append("Add a maskable purpose icon for Android adaptive icons")
                        elif "Splash" in detail["check"]:
                            recs.append("Configure splash screens for iOS with apple-touch-startup-image")
                        elif "Start URL" in detail["check"]:
                            recs.append("Set start_url in the web app manifest")
                        elif "App name" in detail["check"]:
                            recs.append("Set name/short_name in the web app manifest")
                        elif "Manifest id" in detail["check"]:
                            recs.append("Set an id in the manifest so the installed app identity stays stable")
                        elif "description" in detail["check"]:
                            recs.append("Add a description to the manifest for store-like listings")
                        elif "categories" in detail["check"]:
                            recs.append("Declare manifest categories (e.g. shopping, news, lifestyle)")
                        elif "prefer_related_applications" in detail["check"]:
                            recs.append("Set prefer_related_applications: false so the web install stays primary")
                        elif "lang/dir" in detail["check"]:
                            recs.append("Set lang and dir in the manifest for localized installs")
                    elif cat == "deep_pwa":
                        if "Service Worker registration API" in detail["check"]:
                            recs.append("Register service worker with navigator.serviceWorker.register() in your main script")
                        elif "Service Worker scope" in detail["check"]:
                            recs.append("Configure service worker scope for proper control over your app")
                        elif "Push notification" in detail["check"]:
                            recs.append("Implement Push API: request notification permission and subscribe via PushManager")
                        elif "Background sync" in detail["check"]:
                            recs.append("Add background sync with SyncManager.register() for offline data persistence")
                        elif "Cache strategies" in detail["check"]:
                            recs.append("Implement cache strategies (cache-first, network-first, stale-while-revalidate) via Workbox")
                        elif "Workbox" in detail["check"]:
                            recs.append("Integrate Workbox for simplified service worker caching and routing")
                        elif "Manifest valid" in detail["check"]:
                            recs.append("Fix manifest issues: add missing required fields and maskable icons")
                        elif "iOS PWA" in detail["check"]:
                            recs.append("Add apple-mobile-web-app-capable, apple-mobile-web-app-status-bar-style, and apple-touch-icon")
                        elif "Web Share" in detail["check"]:
                            recs.append("Integrate navigator.share() for native share sheets on mobile")
                        elif "share_target" in detail["check"]:
                            recs.append("Add share_target to the manifest so the installed app can receive shares")
                        elif "File/protocol" in detail["check"]:
                            recs.append("Register file_handlers/protocol_handlers so the PWA opens related content")
                        elif "launch_handler" in detail["check"]:
                            recs.append("Configure launch_handler/handle_links for predictable app opening")
                        elif "screenshots" in detail["check"]:
                            recs.append("Add screenshots to the manifest for richer install UI")
                        elif "shortcuts" in detail["check"]:
                            recs.append("Add manifest shortcuts for one-tap access to key actions")
                    elif cat == "performance":
                        if "Page size" in detail["check"]:
                            recs.append("Reduce page size below 3MB for mobile users")
                        elif "HTTP requests" in detail["check"]:
                            recs.append("Reduce HTTP requests by combining files and using sprites")
                        elif "Image count" in detail["check"]:
                            recs.append("Reduce number of images or use lazy loading")
                        elif "Script count" in detail["check"]:
                            recs.append("Reduce JavaScript files - combine and minify scripts")
                        elif "CSS file" in detail["check"]:
                            recs.append("Combine CSS files to reduce HTTP requests")
                        elif "Lazy loading" in detail["check"]:
                            recs.append("Add loading=\"lazy\" attribute to images below the fold")
                        elif "JS execution" in detail["check"]:
                            recs.append("Reduce blocking JavaScript - use defer/async and minimize inline JS")
                        elif "Font loading" in detail["check"]:
                            recs.append("Add font-display: swap and preload critical fonts")
                        elif "image format" in detail["check"]:
                            recs.append("Convert images to WebP or AVIF format for better compression")
                        elif "resource budget" in detail["check"]:
                            recs.append("Reduce HTML payload below 500KB for fast mobile loading")
                        elif "fetchpriority" in detail["check"]:
                            recs.append("Add fetchpriority=high to the LCP hero image / critical CSS")
                        elif "decoding hints" in detail["check"]:
                            recs.append("Add decoding=async to images to avoid main-thread decode jank")
                        elif "third-party" in detail["check"] or "external hosts" in detail["check"]:
                            recs.append("Reduce third-party hosts - self-host or defer non-critical scripts")
                        elif "font delivery" in detail["check"]:
                            recs.append("Adopt variable fonts and preload the primary font file")
                        elif "Speculative loading" in detail["check"]:
                            recs.append("Add <link rel=prefetch> for likely next navigations")
                        elif "visibility lifecycle" in detail["check"]:
                            recs.append("Pause timers/workers on visibilitychange and pagehide")
                    elif cat == "perf_budget":
                        if "Page size" in detail["check"]:
                            recs.append(f"Reduce total page size below {self.budget['max_page_size_kb']}KB for {self.budget['name']} networks")
                        elif "Request count" in detail["check"]:
                            recs.append(f"Reduce HTTP requests below {self.budget['max_requests']} for {self.budget['name']} networks")
                        elif "Total resource size" in detail["check"]:
                            recs.append(f"Reduce total resource size below {self.budget['max_total_size_kb']}KB for {self.budget['name']}")
                        elif "Inline JS" in detail["check"]:
                            recs.append(f"Reduce inline JS below {self.budget['max_js_size_kb']}KB for {self.budget['name']} networks")
                        elif "CSS size" in detail["check"]:
                            recs.append(f"Reduce CSS size below {self.budget['max_css_size_kb']}KB for {self.budget['name']} networks")
                        elif "Image size" in detail["check"] or "largest image" in detail["check"]:
                            recs.append("Compress images and use srcset/modern formats to stay within the per-image budget")
                        elif "load time" in detail["check"]:
                            recs.append("Reduce total transferred bytes to bring estimated load time within the mobile budget")
                    elif cat == "cwv":
                        if "Resource hints" in detail["check"]:
                            recs.append("Add <link rel=\"preload\"> for critical resources (fonts, hero images, key CSS/JS)")
                        elif "Preconnect" in detail["check"]:
                            recs.append("Add <link rel=\"preconnect\"> to third-party origins for faster connections")
                        elif "Render-blocking" in detail["check"]:
                            recs.append("Reduce render-blocking resources: use defer/async for scripts, critical CSS inlining")
                        elif "LCP candidates" in detail["check"]:
                            recs.append("Optimize largest contentful paint: preload hero images, reduce server response time")
                        elif "CLS risk" in detail["check"]:
                            recs.append("Add explicit width/height attributes to images and videos to prevent layout shift")
                        elif "Image count" in detail["check"]:
                            recs.append("Reduce image count or lazy-load non-critical images for faster LCP")
                        elif "Script loading" in detail["check"]:
                            recs.append("Add defer/async attributes to non-critical scripts for better mobile rendering")
                    elif cat == "touch_perf":
                        if "Input responsiveness" in detail["check"]:
                            recs.append("Use requestAnimationFrame and requestIdleCallback for responsive input handling")
                        elif "Passive event" in detail["check"]:
                            recs.append("Use passive: true on touch event listeners to improve scroll performance")
                        elif "Long task" in detail["check"]:
                            recs.append("Break up long tasks with setTimeout or requestIdleCallback")
                        elif "Inline JS" in detail["check"]:
                            recs.append("Move inline JavaScript to external files or reduce inline script size")
                    elif cat == "content":
                        if "font sizes" in detail["check"]:
                            recs.append("Ensure all font sizes are at least 12px for mobile readability")
                        elif "line-height" in detail["check"]:
                            recs.append("Set line-height to at least 1.5 for better readability")
                        elif "Content width" in detail["check"]:
                            recs.append("Add viewport meta tag with width=device-width")
                        elif "zoom" in detail["check"]:
                            recs.append("Allow user zooming for better accessibility")
                    elif cat == "navigation":
                        if "Hamburger" in detail["check"]:
                            recs.append("Add a hamburger/mobile menu toggle for smaller screens")
                        elif "Mobile navigation" in detail["check"]:
                            recs.append("Implement mobile-specific navigation patterns")
                        elif "Sticky" in detail["check"]:
                            recs.append("Consider adding a sticky header for easy navigation")
                        elif "Back-to-top" in detail["check"]:
                            recs.append("Add a back-to-top button for long pages")
                        elif "Bottom navigation" in detail["check"]:
                            recs.append("Add a bottom tab bar for thumb-reachable primary navigation on phones")
                        elif "Drawer" in detail["check"]:
                            recs.append("Implement a drawer/off-canvas navigation pattern for small screens")
                        elif "Swipeable" in detail["check"]:
                            recs.append("Support swipeable tabs/carousels for mobile navigation flows")
                        elif "Full-screen overlay" in detail["check"]:
                            recs.append("Use a full-screen overlay menu for compact mobile navigation")
                        elif "Safe-area-aware" in detail["check"]:
                            recs.append("Pad fixed navigation with env(safe-area-inset-bottom) for notched devices")
                    elif cat == "meta":
                        if "mobile-web-app-capable" in detail["check"]:
                            recs.append("Add <meta name=\"mobile-web-app-capable\" content=\"yes\">")
                        elif "apple-mobile-web-app" in detail["check"]:
                            recs.append("Add Apple mobile web app meta tags for iOS")
                        elif "format-detection" in detail["check"]:
                            recs.append("Add <meta name=\"format-detection\" content=\"telephone=no\">")
                        elif "theme-color" in detail["check"]:
                            recs.append("Add <meta name=\"theme-color\" content=\"#your-color\">")
                    elif cat == "images":
                        if "width/height" in detail["check"]:
                            recs.append("Add width and height attributes to images to prevent layout shift")
                        elif "srcset" in detail["check"]:
                            recs.append("Use srcset attribute to serve responsive image sizes")
                        elif "Lazy loading" in detail["check"]:
                            recs.append("Add loading=\"lazy\" to images below the fold")
                        elif "Modern image" in detail["check"]:
                            recs.append("Convert images to WebP or AVIF format for better compression")
                        elif "Oversized" in detail["check"]:
                            recs.append("Compress and optimize oversized images")
                    elif cat == "mobile_form":
                        if "keyboard types" in detail["check"]:
                            recs.append("Use type=\"email\", type=\"tel\", type=\"url\", type=\"number\" for proper mobile keyboards")
                        elif "Autocomplete" in detail["check"]:
                            recs.append("Add autocomplete attributes to form inputs for faster mobile form filling")
                        elif "labels" in detail["check"]:
                            recs.append("Add labels or placeholders to all form inputs for mobile usability")
                        elif "Forms found" in detail["check"]:
                            recs.append("Add form elements to your page with proper mobile input types")
                        elif "inputmode" in detail["check"]:
                            recs.append("Add inputmode=\"numeric\"/\"email\"/\"decimal\" so mobile keyboards match the data")
                        elif "constraint validation" in detail["check"]:
                            recs.append("Use HTML5 constraint attributes (required, pattern, minlength) for client-side validation")
                        elif "Custom JS validation" in detail["check"]:
                            recs.append("Handle setCustomValidity/reportValidity for mobile-friendly validation messages")
                        elif "error feedback" in detail["check"]:
                            recs.append("Show inline error feedback with aria-invalid and aria-describedby near the field")
                        elif "OTP" in detail["check"]:
                            recs.append("Support autocomplete=\"one-time-code\" for SMS/email verification inputs")
                    elif cat == "device":
                        if "Foldable" in detail["check"]:
                            recs.append("Add foldable support: use @media (spanning: coalesce) and hinge-aware layouts")
                        elif "Notch/safe-area" in detail["check"]:
                            recs.append("Add viewport-fit=cover and env(safe-area-inset-*) padding for notched devices")
                        elif "Dark mode" in detail["check"]:
                            recs.append("Support prefers-color-scheme with a dark palette and dark theme-color meta")
                        elif "orientation" in detail["check"]:
                            recs.append("Handle orientation changes via orientationchange events and (orientation: portrait/landscape) media queries")
                        elif "Haptic" in detail["check"]:
                            recs.append("Use navigator.vibrate() for subtle haptic feedback on key interactions")
                        elif "AR/VR" in detail["check"]:
                            recs.append("Consider WebXR or <model-viewer> for immersive AR/VR product experiences")
                        elif "Pointer capability" in detail["check"]:
                            recs.append("Probe navigator.maxTouchPoints / (pointer: coarse) to adapt UI to touch devices")
                    elif cat == "mobile_a11y":
                        if "reduced-motion" in detail["check"]:
                            recs.append("Respect prefers-reduced-motion and disable non-essential animations")
                        elif "forced-colors" in detail["check"]:
                            recs.append("Add forced-colors and prefers-contrast media queries for high-contrast modes")
                        elif "pinch-zoom" in detail["check"]:
                            recs.append("Allow pinch-zoom in the viewport meta for low-vision users")
                        elif "typography" in detail["check"] or "Fixed px typography" in detail["check"] or "font sizes" in detail["check"]:
                            recs.append("Use rem/em font sizes so users can scale text with system settings")
                        elif "Focus" in detail["check"]:
                            recs.append("Add visible :focus-visible styles for keyboard and switch-device users")
                        elif "landmarks" in detail["check"]:
                            recs.append("Use semantic landmarks: <header>, <nav>, <main>, <footer>")
                        elif "Skip navigation" in detail["check"]:
                            recs.append("Add a skip-to-content link as the first focusable element")
                        elif "ARIA" in detail["check"]:
                            recs.append("Add ARIA attributes (aria-label, aria-describedby) where native semantics are missing")
                        elif "alt text" in detail["check"]:
                            recs.append("Add descriptive alt attributes to all meaningful images")
                        elif "Language attribute" in detail["check"]:
                            recs.append("Set lang attribute on the <html> element")
                        elif "touch target" in detail["check"] or "target size" in detail["check"]:
                            recs.append("Enforce minimum 44x48px touch targets in CSS (min-height/min-width)")
                        elif "Reflow" in detail["check"]:
                            recs.append("Ensure the layout reflows to a single column at 320px CSS width (WCAG 1.4.10)")
                        elif "Dialog/modal" in detail["check"]:
                            recs.append("Trap focus in dialogs with aria-modal='true' and inert background content")
                        elif "aria-describedby" in detail["check"]:
                            recs.append("Link inputs to help/error text via aria-describedby")
                        elif "Text zoom" in detail["check"]:
                            recs.append("Avoid viewport scale locks and use rem/em so text can be resized")
                        elif "Alert/status" in detail["check"]:
                            recs.append("Announce async results with role=alert or aria-live regions")
                    elif cat == "amp":
                        if "AMP version" in detail["check"]:
                            recs.append("Consider creating an AMP version for faster mobile loading")
                    elif cat == "progressive_enhancement":
                        if "Semantic HTML" in detail["check"]:
                            recs.append("Use semantic HTML5 elements (header/nav/main/section/article/aside/footer)")
                        elif "feature queries" in detail["check"] or "@supports" in detail["check"]:
                            recs.append("Layer enhanced CSS behind @supports feature queries")
                        elif "feature detection" in detail["check"]:
                            recs.append("Detect capabilities with matchMedia / CSS.supports / 'x' in navigator before enhancing")
                        elif "noscript" in detail["check"]:
                            recs.append("Add <noscript> fallbacks so core content works without JavaScript")
                        elif "Polyfills" in detail["check"]:
                            recs.append("Include targeted polyfills (core-js, picturefill) for older mobile browsers")
                        elif "Progressive image" in detail["check"] or "picture/srcset" in detail["check"]:
                            recs.append("Use <picture> and srcset so browsers pick the best image they support")
                        elif "Server-rendered" in detail["check"] or "headings" in detail["check"]:
                            recs.append("Render core headings/content on the server so the page works before JS runs")
                        elif "ARIA roles" in detail["check"]:
                            recs.append("Add explicit ARIA roles where native HTML semantics are missing")
                        elif "fallback strategy" in detail["check"] or "CSS fallback" in detail["check"]:
                            recs.append("Add vendor-prefixed fallbacks before unprefixed CSS properties")
                        elif "Progressive form" in detail["check"]:
                            recs.append("Use native input types plus progressive JS validation on forms")
                    elif cat == "graceful_degradation":
                        if "Try/catch" in detail["check"]:
                            recs.append("Wrap risky operations in try/catch so failures do not break the page")
                        elif "Global error handler" in detail["check"]:
                            recs.append("Add window.onerror / error boundary to catch uncaught errors")
                        elif "No-JS degradation" in detail["check"]:
                            recs.append("Add <noscript> blocks so the page remains usable without JS")
                        elif "Media fallback" in detail["check"]:
                            recs.append("Provide fallback content inside <picture>/<video> for unsupported formats")
                        elif "CSS fallback" in detail["check"]:
                            recs.append("Declare CSS fallbacks (vendor prefixes or earlier values) before modern rules")
                        elif "aria-live" in detail["check"]:
                            recs.append("Use aria-live regions so async failures are announced to screen readers")
                        elif "Error/empty-state" in detail["check"]:
                            recs.append("Show clear error/empty-state/retry UI when data or features fail to load")
                        elif "Polyfills keep" in detail["check"]:
                            recs.append("Load polyfills so older browsers get core functionality")
                        elif "Safe navigation" in detail["check"] or "javascript:" in detail["check"]:
                            recs.append("Use real href attributes instead of javascript: links so navigation survives JS failure")
                        elif "Feature guards" in detail["check"]:
                            recs.append("Guard API calls with typeof / 'in' checks before using modern APIs")
                    elif cat == "offline_capability":
                        if "Service Worker available" in detail["check"]:
                            recs.append("Register a service worker to enable offline caching")
                        elif "Cache Storage" in detail["check"]:
                            recs.append("Use Cache Storage (caches.open/put/match) to store core assets")
                        elif "offline fallback" in detail["check"]:
                            recs.append("Serve a dedicated offline.html fallback for failed navigations")
                        elif "Connectivity monitoring" in detail["check"]:
                            recs.append("Listen for navigator.onLine and online/offline events to adapt UX")
                        elif "Client-side persistence" in detail["check"]:
                            recs.append("Persist critical data in localStorage/IndexedDB so it survives offline")
                        elif "Background sync" in detail["check"]:
                            recs.append("Queue offline actions with the Background Sync API")
                        elif "Precaching" in detail["check"]:
                            recs.append("Precache the app shell (cache.addAll) during the service worker install event")
                        elif "Manifest navigation scope" in detail["check"]:
                            recs.append("Set start_url and scope in the manifest for offline navigation")
                        elif "fetch strategy" in detail["check"]:
                            recs.append("Implement cache-first or stale-while-revalidate fetch strategies in the SW")
                    elif cat == "low_bandwidth":
                        if "Resource hints" in detail["check"]:
                            recs.append("Add preload/preconnect/dns-prefetch hints for critical resources")
                        elif "Non-blocking script" in detail["check"]:
                            recs.append("Load non-critical scripts with async/defer/type=module")
                        elif "Minified assets" in detail["check"]:
                            recs.append("Serve .min.js/.min.css builds to reduce transfer size")
                        elif "compression" in detail["check"]:
                            recs.append("Enable gzip or Brotli compression on the server/CDN")
                        elif "HTML payload" in detail["check"] or "low-bandwidth target" in detail["check"]:
                            recs.append("Reduce HTML payload to stay within the low-bandwidth size target")
                        elif "critical CSS" in detail["check"]:
                            recs.append("Inline critical CSS in <head> and defer the rest")
                        elif "CDN" in detail["check"] or "origins" in detail["check"]:
                            recs.append("Serve static assets from a CDN / sharded origins")
                        elif "Font loading" in detail["check"]:
                            recs.append("Use font-display: swap and system font stacks to avoid font blocking")
                        elif "Code splitting" in detail["check"]:
                            recs.append("Split bundles with dynamic import() so mobile downloads less JS")
                    elif cat == "data_saver":
                        if "Network Information API" in detail["check"]:
                            recs.append("Probe navigator.connection (effectiveType/saveData) to adapt content quality")
                        elif "saveData-aware" in detail["check"]:
                            recs.append("Detect navigator.connection.saveData and serve lighter assets when true")
                        elif "prefers-reduced-data" in detail["check"]:
                            recs.append("Add @media (prefers-reduced-data: reduce) to drop non-essential media")
                        elif "Video elements" in detail["check"] or "Video payload" in detail["check"] or "Poster" in detail["check"]:
                            recs.append("Set video preload=\"none\"/\"metadata\" and use posters to avoid auto-downloads")
                        elif "Deferred image" in detail["check"]:
                            recs.append("Add loading=\"lazy\" to below-the-fold images")
                        elif "placeholders" in detail["check"] or "LQIP" in detail["check"]:
                            recs.append("Use low-quality image placeholders (LQIP/blur-up) for perceived speed")
                        elif "srcset density" in detail["check"]:
                            recs.append("Provide srcset/sizes so devices download only the resolution they need")
                        elif "Lite/low-data" in detail["check"]:
                            recs.append("Offer a lite/low-data mode for data-constrained users")
                        elif "content-visibility" in detail["check"]:
                            recs.append("Apply content-visibility: auto to offscreen sections")
                    elif cat == "mobile_ux":
                        if "pattern coverage" in detail["check"] or "UX pattern" in detail["check"]:
                            recs.append("Adopt standard mobile UX patterns: skeleton loaders, toasts, bottom sheets, pull-to-refresh")
                        elif "One-handed" in detail["check"]:
                            recs.append("Add bottom navigation, FABs, or sticky CTAs within thumb reach")
                        elif "Loading/feedback" in detail["check"]:
                            recs.append("Show visible loading/feedback states (spinners, skeletons) during async work")
                        elif "Micro-interaction" in detail["check"]:
                            recs.append("Add micro-interactions (transitions, transforms) to make taps feel responsive")
                        elif "empty/first-use" in detail["check"]:
                            recs.append("Design empty and first-use states that guide the user to act")
                        elif "prefers-reduced-motion" in detail["check"]:
                            recs.append("Gate non-essential animations behind prefers-reduced-motion")
                        elif "Thumb-zone" in detail["check"]:
                            recs.append("Place primary controls in the thumb zone (bottom, safe-area padded)")
                    elif cat == "mobile_conversion":
                        if "Primary CTAs" in detail["check"]:
                            recs.append("Add clear primary CTAs (Buy, Sign up, Get started) sized for touch")
                        elif "friction" in detail["check"]:
                            recs.append("Reduce form friction: specialized input types, autocomplete, fewer fields")
                        elif "Conversion lever" in detail["check"] or "conversion optimization" in detail["check"]:
                            recs.append("Add conversion levers: sticky CTA, trust badges, reviews, mobile payments, click-to-call")
                    elif cat == "mobile_engagement":
                        if "Engagement signal" in detail["check"] or "engagement signals" in detail["check"]:
                            recs.append("Add engagement signals: push, share, comments, gamification, personalized feeds")
                        elif "Rich media" in detail["check"] or "media content" in detail["check"]:
                            recs.append("Add rich media (video, animation) with mobile-friendly lazy loading")
                    elif cat == "mobile_retention":
                        if "Retention signal" in detail["check"] or "retention signals" in detail["check"]:
                            recs.append("Add retention signals: PWA install, accounts, offline access, email capture, loyalty")
                        elif "shortcuts" in detail["check"]:
                            recs.append("Define manifest shortcuts and share_target for faster return paths")
                    elif cat == "touch_feedback":
                        if ":active" in detail["check"]:
                            recs.append("Add :active styles so buttons/links respond immediately to touch")
                        elif "Ripple" in detail["check"]:
                            recs.append("Add a ripple or press animation to convey tap acknowledgment")
                        elif "Tap highlight" in detail["check"]:
                            recs.append("Customize -webkit-tap-highlight-color to match your brand feedback")
                        elif "Pressed" in detail["check"]:
                            recs.append("Style pressed/active states (is-pressed, aria-pressed) on controls")
                        elif "Transform feedback" in detail["check"]:
                            recs.append("Add a subtle :active transform (scale 0.98) for tactile-looking feedback")
                        elif "Transition feedback" in detail["check"]:
                            recs.append("Add short transitions on interactive elements for smoother feedback")
                        elif "Visual response" in detail["check"]:
                            recs.append("Show focus/loading/toast states so every tap gets a visible response")
                    elif cat == "haptic_feedback":
                        if "navigator.vibrate" in detail["check"]:
                            recs.append("Call navigator.vibrate() on key confirmations (feature-detected)")
                        elif "vibration patterns" in detail["check"] or "Structured vibration" in detail["check"]:
                            recs.append("Use vibration pattern arrays [ms] for distinct success/error feedback")
                        elif "feature detection" in detail["check"]:
                            recs.append("Feature-detect navigator.vibrate before calling it")
                        elif "haptic keywords" in detail["check"]:
                            recs.append("Adopt platform haptic naming (haptic/taptic) in your feedback layer")
                        elif "Manifest vibrate" in detail["check"]:
                            recs.append("Declare a vibrate permission/pattern in the web app manifest")
                        elif "visual/aural" in detail["check"]:
                            recs.append("Never rely on haptics alone - pair with visual feedback")
                        elif "Motion-preference" in detail["check"]:
                            recs.append("Gate vibration behind prefers-reduced-motion / user settings")
                    elif cat == "device_motion":
                        if "devicemotion" in detail["check"]:
                            recs.append("Listen for devicemotion events to enable tilt/shake interactions")
                        elif "deviceorientation" in detail["check"]:
                            recs.append("Listen for deviceorientation events for compass/tilt features")
                        elif "iOS motion permission" in detail["check"]:
                            recs.append("Handle DeviceMotionEvent.requestPermission() for iOS 13+ motion access")
                        elif "Generic Sensor" in detail["check"]:
                            recs.append("Consider Generic Sensor API (Accelerometer/Gyroscope) with fallbacks")
                        elif "Motion data used" in detail["check"]:
                            recs.append("Use motion data for parallax/tilt UX (with graceful fallback)")
                        elif "Motion fallback" in detail["check"]:
                            recs.append("Guard motion effects behind feature detection and prefers-reduced-motion")
                        elif "orientation lock" in detail["check"]:
                            recs.append("Handle screen orientation changes and lock orientation where needed")
                    elif cat == "battery_api":
                        if "Battery Status API" in detail["check"]:
                            recs.append("Probe navigator.getBattery() to adapt behavior at low battery")
                        elif "Battery level" in detail["check"]:
                            recs.append("Subscribe to levelchange/chargingchange to react to battery state")
                        elif "Low-battery" in detail["check"]:
                            recs.append("Add a low-battery mode that reduces animation and background work")
                        elif "Charging-state" in detail["check"]:
                            recs.append("Allow heavier work (sync, prefetch) while charging")
                        elif "feature detection" in detail["check"]:
                            recs.append("Feature-detect navigator.getBattery before using it")
                        elif "Power-friendly" in detail["check"]:
                            recs.append("Pause work on visibilitychange/pagehide to save battery")
                    elif cat == "network_info":
                        if "Network Information API" in detail["check"]:
                            recs.append("Read navigator.connection.effectiveType to tailor content quality")
                        elif "effectiveType" in detail["check"]:
                            recs.append("Serve lighter variants on 2g/3g effectiveType connections")
                        elif "saveData" in detail["check"]:
                            recs.append("Honor navigator.connection.saveData by skipping heavy media")
                        elif "downlink" in detail["check"]:
                            recs.append("Use connection.downlink/rtt to decide prefetch depth")
                        elif "connectivity transitions" in detail["check"]:
                            recs.append("React to online/offline transitions with clear UX messaging")
                        elif "change listener" in detail["check"]:
                            recs.append("Listen for connection change events and re-adapt dynamically")
                        elif "prefers-reduced-data" in detail["check"]:
                            recs.append("Add @media (prefers-reduced-data: reduce) styles")
                        elif "Tiered/lazy" in detail["check"]:
                            recs.append("Load content in tiers (lazy/chunked) so slow networks stay responsive")
                    elif cat == "geolocation":
                        if "Geolocation API usage" in detail["check"]:
                            recs.append("Integrate navigator.geolocation where location adds real value")
                        elif "permission request" in detail["check"]:
                            recs.append("Explain why you need location before calling getCurrentPosition")
                        elif "error callback" in detail["check"]:
                            recs.append("Handle geolocation error codes with a friendly fallback")
                        elif "Manual location" in detail["check"]:
                            recs.append("Offer manual city/ZIP entry when GPS is denied")
                        elif "Map integration" in detail["check"]:
                            recs.append("Wire location into a map (Leaflet/Google Maps) for context")
                        elif "HTTPS" in detail["check"]:
                            recs.append("Serve over HTTPS - geolocation requires a secure context")
                        elif "Geolocation options" in detail["check"]:
                            recs.append("Set enableHighAccuracy/timeout/maximumAge options on position requests")
                        elif "PWA capabilities" in detail["check"]:
                            recs.append("Connect location features with manifest handlers for PWA depth")
        return recs

    def print_results(self, use_color=True):
        c = get_colors(use_color)
        print()
        print(colored("=" * 70, "cyan", use_color))
        print(colored(" MOBILE-FRIENDLINESS & PWA ANALYSIS RESULTS", "bold", use_color))
        print(colored(f" URL: {self.url}", "white", use_color))
        print(colored(f" Network Budget: {self.budget['name']}", "white", use_color))
        print(colored("=" * 70, "cyan", use_color))
        print()
        category_labels = CATEGORY_LABELS
        cat_order = CATEGORY_ORDER
        for cat_key in cat_order:
            if cat_key not in self.results:
                continue
            data = self.results[cat_key]
            label = category_labels.get(cat_key, cat_key)
            pct = (data["score"] / data["max"]) * 100 if data["max"] > 0 else 0
            if pct >= 80:
                bar_color = "green"
            elif pct >= 50:
                bar_color = "yellow"
            else:
                bar_color = "red"
            filled = int(pct / 5)
            bar = "\u2588" * filled + "\u2591" * (20 - filled)
            print(colored(f"  [{label}]", "bold", use_color))
            score_str = f"{data['score']}/{data['max']}"
            print(f"    Score: {colored(score_str, bar_color, use_color)}  [{colored(bar, bar_color, use_color)}] {pct:.0f}%")
            for detail in data["details"]:
                icon = colored("[+]", "green", use_color) if detail["passed"] else colored("[-]", "red", use_color)
                print(f"      {icon} {detail['check']}")
            print()
        grade, verdict, grade_color = self.get_grade()
        print(colored("-" * 70, "cyan", use_color))
        print(colored("  SCORES SUMMARY", "bold", use_color))
        readiness_str = f"{self.mobile_readiness}%"
        grade_str = f"Grade: {grade} - {verdict}"
        print(f"  Mobile Readiness Score: {colored(readiness_str, grade_color, use_color)}  {colored(grade_str, grade_color, use_color)}")
        pwa_color = "green" if self.pwa_score >= 70 else "yellow" if self.pwa_score >= 40 else "red"
        touch_color = "green" if self.touch_score >= 70 else "yellow" if self.touch_score >= 40 else "red"
        budget_color = "green" if self.perf_budget_score >= 70 else "yellow" if self.perf_budget_score >= 40 else "red"
        ux_color = "green" if self.mobile_ux_score >= 70 else "yellow" if self.mobile_ux_score >= 40 else "red"
        perf_color = "green" if self.mobile_perf_score >= 70 else "yellow" if self.mobile_perf_score >= 40 else "red"
        pwa_str = f"{self.pwa_score}%"
        touch_str = f"{self.touch_score}%"
        budget_str = f"{self.perf_budget_score}% ({self.budget['name']})"
        ux_str = f"{self.mobile_ux_score}%"
        perf_str = f"{self.mobile_perf_score}%"
        net_str = f"{self.network_adapt_score}%"
        cap_str = f"{self.mobile_capability_score}%"
        points_str = f"{self.total_score}/{self.max_score}"
        print(f"  PWA Capability Score:    {colored(pwa_str, pwa_color, use_color)}")
        print(f"  Touch Readiness Score:   {colored(touch_str, touch_color, use_color)}")
        print(f"  Mobile UX Score:         {colored(ux_str, ux_color, use_color)}")
        print(f"  Mobile Performance Score: {colored(perf_str, perf_color, use_color)}")
        print(f"  Perf Budget Score:       {colored(budget_str, budget_color, use_color)}")
        net_color = "green" if self.network_adapt_score >= 70 else "yellow" if self.network_adapt_score >= 40 else "red"
        cap_color = "green" if self.mobile_capability_score >= 70 else "yellow" if self.mobile_capability_score >= 40 else "red"
        print(f"  Network Adapt Score:     {colored(net_str, net_color, use_color)}")
        print(f"  Device Capability Score: {colored(cap_str, cap_color, use_color)}")
        print(f"  Points: {colored(points_str, grade_color, use_color)}")
        print(colored("-" * 70, "cyan", use_color))
        recs = self.get_recommendations()
        if recs:
            print()
            print(colored("  RECOMMENDATIONS:", "yellow", use_color))
            for i, rec in enumerate(recs, 1):
                print(f"  {colored(str(i) + '.', 'yellow', use_color)} {rec}")
        if self.roadmap:
            print()
            print(colored("  MOBILE OPTIMIZATION ROADMAP:", "magenta", use_color))
            print(colored("  " + "-" * 66, "magenta", use_color))
            summary = getattr(self, "roadmap_summary", None)
            if summary:
                sum_line = f"  {summary['total_items']} items | {summary['critical']} critical | {summary['high']} high | {summary['medium']} medium | {summary['quick_wins']} quick wins"
                print(colored(sum_line, "white", use_color))
                headline = summary.get("headline", "")
                if headline:
                    print(colored(f"  Plan: {headline}", "white", use_color))
                owners = summary.get("owners", [])
                if owners:
                    print(colored(f"  Teams involved: {', '.join(owners)}", "white", use_color))
                print()
            for i, item in enumerate(self.roadmap, 1):
                priority_color = "red" if item["priority"] == "CRITICAL" else "yellow" if item["priority"] == "HIGH" else "cyan"
                priority_label = item["priority"]
                effort = item.get("effort", "Medium")
                print(f"  {colored(str(i) + '. [' + priority_label + ']', priority_color, use_color)} {item['category']}: {item['issue']}")
                phase_impact = f"{item['phase']} | Impact: {item['impact']} | Effort: {effort}"
                print(f"     {colored(phase_impact, 'white', use_color)}")
                owner = item.get("owner", "")
                roi = item.get("roi", "")
                gain = item.get("est_score_gain_pct", 0)
                meta_line = f"Owner: {owner} | {roi} | Est. score gain: +{gain}%"
                print(f"     {colored(meta_line, 'white', use_color)}")
            print()
        if self.device_matrix:
            print()
            print(colored("  DEVICE COMPATIBILITY MATRIX:", "blue", use_color))
            print(colored("  " + "-" * 66, "blue", use_color))
            matrix_summary = getattr(self, "device_matrix_summary", None)
            if matrix_summary:
                ms_line = f"  Overall: {matrix_summary['overall_pct']}% | {matrix_summary['supported']} supported, {matrix_summary['partial']} partial, {matrix_summary['unsupported']} unsupported"
                print(colored(ms_line, "white", use_color))
                readiness_label = matrix_summary.get("readiness_label", "")
                if readiness_label:
                    print(colored(f"  {readiness_label}", "white", use_color))
                weak = matrix_summary.get("weak_devices", [])
                if weak:
                    print(colored(f"  Needs attention: {', '.join(weak)}", "yellow", use_color))
                print()
            header = f"  {'Device':<20}{'Range':<20}{'Status':<12}{'Cover':<8}"
            print(colored(header, "bold", use_color))
            for row in self.device_matrix:
                if row["status"] == "supported":
                    status_color = "green"
                    status_text = "SUPPORTED"
                elif row["status"] == "partial":
                    status_color = "yellow"
                    status_text = "PARTIAL"
                else:
                    status_color = "red"
                    status_text = "UNSUPPORTED"
                cover = f"{row.get('coverage_pct', 0)}%"
                line = f"  {row['device']:<20}{row['range']:<20}"
                pad = " " * max(12 - len(status_text), 1)
                print(f"{line}{colored(status_text, status_color, use_color)}{pad}{cover}")
                note = row.get("note", "")
                if note:
                    print(f"     {colored(note, 'white', use_color)}")
                if row["missing_required"]:
                    missing_text = "missing: " + ", ".join(row["missing_required"])
                    print(f"     {colored(missing_text, 'white', use_color)}")
            print()
        if self.a11y_assessment:
            print()
            print(colored("  MOBILE ACCESSIBILITY ASSESSMENT:", "cyan", use_color))
            print(colored("  " + "-" * 66, "cyan", use_color))
            level = self.a11y_assessment.get("level", "Unknown")
            level_color = "green" if level == "Strong" else "yellow" if level == "Needs Improvement" else "red"
            a11y_score = self.a11y_assessment.get("score", 0)
            score_line = f"  Score: {a11y_score}% - Level: {level}"
            print(colored(score_line, level_color, use_color))
            wcag_note = self.a11y_assessment.get("wcag_note", "")
            if wcag_note:
                print(f"  {colored(wcag_note, 'white', use_color)}")
            critical = self.a11y_assessment.get("critical_failures", [])
            if critical:
                print(colored("  Critical failures:", "red", use_color))
                for crit in critical:
                    print(f"    [!] {crit}")
            issues = self.a11y_assessment.get("issues", [])
            if issues:
                print(colored("  Issues:", "yellow", use_color))
                for issue in issues:
                    print(f"    [-] {issue}")
            else:
                print(colored("  No mobile accessibility issues detected.", "green", use_color))
            fixes = self.a11y_assessment.get("priority_fixes", [])
            if fixes:
                print(colored("  Priority fixes:", "magenta", use_color))
                for fix in fixes:
                    print(f"    [>] {fix}")
            wcag_criteria = self.a11y_assessment.get("wcag_criteria", [])
            if wcag_criteria:
                met = self.a11y_assessment.get("criteria_met", 0)
                total_c = self.a11y_assessment.get("criteria_total", len(wcag_criteria))
                pct_c = self.a11y_assessment.get("criteria_pct", 0)
                print(colored(f"  WCAG 2.2 mapping: {met}/{total_c} criteria met ({pct_c}%)", "cyan", use_color))
                for crit in wcag_criteria:
                    icon = colored("[+]", "green", use_color) if crit["met"] else colored("[-]", "red", use_color)
                    print(f"    {icon} {crit['criterion']}")
            headroom = self.a11y_assessment.get("headroom_to_strong", 0)
            if headroom > 0:
                print(colored(f"  Points needed to reach Strong level: {headroom}", "yellow", use_color))
        if self.pwa_report:
            print()
            print(colored("  PWA CAPABILITY REPORT:", "magenta", use_color))
            print(colored("  " + "-" * 66, "magenta", use_color))
            tier = self.pwa_report.get("tier", "Unknown")
            cap_pct = self.pwa_report.get("capability_pct", 0)
            supported_n = self.pwa_report.get("supported", 0)
            total_n = self.pwa_report.get("total", 0)
            installable = self.pwa_report.get("installable", False)
            offline_ready = self.pwa_report.get("offline_ready", False)
            summary = f"  Tier: {tier} ({cap_pct}% - {supported_n}/{total_n} features)"
            print(colored(summary, "bold", use_color))
            badges = self.pwa_report.get("badges", [])
            if badges:
                print(f"  Badges: {colored(', '.join(badges), 'cyan', use_color)}")
            criteria = self.pwa_report.get("installability_criteria", [])
            if criteria:
                cm = self.pwa_report.get("criteria_met", 0)
                ct = self.pwa_report.get("criteria_total", len(criteria))
                print(colored(f"  Installability criteria: {cm}/{ct}", "white", use_color))
                for crit in criteria:
                    icon = colored("[+]", "green", use_color) if crit["met"] else colored("[-]", "red", use_color)
                    print(f"    {icon} {crit['criterion']}")
            install_text = "READY" if installable else "NOT READY"
            install_color = "green" if installable else "red"
            print(f"  Installability: {colored(install_text, install_color, use_color)}")
            offline_text = "READY" if offline_ready else "NOT READY"
            offline_color = "green" if offline_ready else "red"
            print(f"  Offline Readiness: {colored(offline_text, offline_color, use_color)}")
            for feat in self.pwa_report.get("features", []):
                if feat["supported"]:
                    icon = colored("[+]", "green", use_color)
                    status_word = "yes"
                else:
                    icon = colored("[-]", "red", use_color)
                    status_word = "no"
                print(f"    {icon} {feat['feature']}: {status_word}")
            opportunities = self.pwa_report.get("score_opportunities", [])
            if opportunities:
                print(colored("  Score opportunities:", "yellow", use_color))
                for opp in opportunities:
                    gain = opp.get("est_gain", 0)
                    print(f"    [~] {opp['opportunity']} (~+{gain} pts)")
            next_steps = self.pwa_report.get("next_steps", [])
            if next_steps:
                print(colored("  Next steps:", "yellow", use_color))
                for step in next_steps:
                    print(f"    [>] {step}")
        analysis_sections = [
            ("MOBILE UX PATTERNS ANALYSIS", self.ux_patterns_analysis, "cyan"),
            ("MOBILE CONVERSION OPTIMIZATION", self.conversion_analysis, "green"),
            ("MOBILE ENGAGEMENT SIGNALS", self.engagement_analysis, "yellow"),
            ("MOBILE RETENTION SIGNALS", self.retention_analysis, "magenta"),
        ]
        for title, data, color_key in analysis_sections:
            if not data:
                continue
            print()
            print(colored(f"  {title}:", color_key, use_color))
            print(colored("  " + "-" * 66, color_key, use_color))
            score_val = data.get("score", 0)
            grade_val = data.get("grade", "N/A")
            coverage_val = data.get("coverage", "0/0")
            line = f"  Score: {score_val}% - Grade: {grade_val} - Coverage: {coverage_val}"
            print(colored(line, "white", use_color))
            found = data.get("found", [])
            missing = data.get("missing", [])
            if found:
                print(colored("  Detected:", "green", use_color))
                for item in found:
                    pretty = item.replace("_", " ").title()
                    print(f"    [+] {pretty}")
            if missing:
                print(colored("  Missing:", "yellow", use_color))
                for item in missing[:8]:
                    pretty = item.replace("_", " ").title()
                    print(f"    [-] {pretty}")
                if len(missing) > 8:
                    print(f"    ... and {len(missing) - 8} more")
        print()
        print()

    def export_json(self, filepath):
        data = {
            "url": self.url,
            "version": VERSION,
            "network_budget": self.budget["name"],
            "total_score": self.total_score,
            "max_score": self.max_score,
            "mobile_readiness": self.mobile_readiness,
            "pwa_score": self.pwa_score,
            "touch_score": self.touch_score,
            "mobile_ux_score": self.mobile_ux_score,
            "mobile_perf_score": self.mobile_perf_score,
            "perf_budget_score": self.perf_budget_score,
            "network_adapt_score": self.network_adapt_score,
            "mobile_capability_score": self.mobile_capability_score,
            "perf_load_estimate_ms": self.perf_load_estimate_ms,
            "grade": self.get_grade()[0],
            "verdict": self.get_grade()[1],
            "categories": self.results,
            "recommendations": self.get_recommendations(),
            "optimization_roadmap": self.roadmap,
            "roadmap_summary": getattr(self, "roadmap_summary", {}),
            "device_compatibility_matrix": self.device_matrix,
            "device_matrix_summary": getattr(self, "device_matrix_summary", {}),
            "mobile_accessibility_assessment": self.a11y_assessment,
            "pwa_capability_report": self.pwa_report,
            "mobile_ux_patterns_analysis": self.ux_patterns_analysis,
            "mobile_conversion_optimization": self.conversion_analysis,
            "mobile_engagement_signals": self.engagement_analysis,
            "mobile_retention_signals": self.retention_analysis,
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(colored(f"[+] Results exported to {filepath}", "green"))

    def export_csv(self, filepath):
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Category", "Check", "Passed", "Points"])
            for cat, data in self.results.items():
                for detail in data["details"]:
                    writer.writerow([cat, detail["check"], detail["passed"], detail["points"]])
            writer.writerow([])
            writer.writerow(["Total Score", f"{self.total_score}/{self.max_score}"])
            writer.writerow(["Mobile Readiness", f"{self.mobile_readiness}%"])
            writer.writerow(["PWA Score", f"{self.pwa_score}%"])
            writer.writerow(["Touch Score", f"{self.touch_score}%"])
            writer.writerow(["Mobile UX Score", f"{self.mobile_ux_score}%"])
            writer.writerow(["Mobile Performance Score", f"{self.mobile_perf_score}%"])
            writer.writerow(["Perf Budget Score", f"{self.perf_budget_score}% ({self.budget['name']})"])
            writer.writerow(["Network Adapt Score", f"{self.network_adapt_score}%"])
            writer.writerow(["Device Capability Score", f"{self.mobile_capability_score}%"])
            writer.writerow(["Est Load Time", f"{self.perf_load_estimate_ms}ms"])
            writer.writerow(["Grade", self.get_grade()[0]])
            writer.writerow([])
            writer.writerow(["ROADMAP Priority", "Phase", "Category", "Issue", "Impact", "Effort", "Owner", "ROI", "Est Gain %"])
            for item in self.roadmap:
                writer.writerow([
                    item["priority"], item.get("phase", ""), item["category"], item["issue"],
                    item["impact"], item.get("effort", ""), item.get("owner", ""),
                    item.get("roi", ""), item.get("est_score_gain_pct", ""),
                ])
            writer.writerow([])
            writer.writerow(["DEVICE MATRIX Device", "Range", "Status", "Required Coverage", "Coverage %", "Missing Required", "Note"])
            for row in self.device_matrix:
                missing = "; ".join(row.get("missing_required", []))
                writer.writerow([row["device"], row["range"], row["status"], row["required_coverage"], row.get("coverage_pct", ""), missing, row.get("note", "")])
            writer.writerow([])
            writer.writerow(["A11Y Score", f"{self.a11y_assessment.get('score', 0)}%"])
            writer.writerow(["A11Y Level", self.a11y_assessment.get("level", "")])
            writer.writerow(["A11Y WCAG Note", self.a11y_assessment.get("wcag_note", "")])
            writer.writerow([
                "A11Y WCAG Criteria",
                f"{self.a11y_assessment.get('criteria_met', 0)}/{self.a11y_assessment.get('criteria_total', 0)}",
            ])
            for crit in self.a11y_assessment.get("wcag_criteria", []):
                writer.writerow(["A11Y WCAG Criterion", crit["criterion"], "yes" if crit["met"] else "no"])
            for issue in self.a11y_assessment.get("issues", []):
                writer.writerow(["A11Y Issue", issue])
            for fix in self.a11y_assessment.get("priority_fixes", []):
                writer.writerow(["A11Y Priority Fix", fix])
            writer.writerow([])
            writer.writerow(["PWA Feature", "Supported"])
            for feat in self.pwa_report.get("features", []):
                writer.writerow([feat["feature"], "yes" if feat["supported"] else "no"])
            writer.writerow(["PWA Tier", self.pwa_report.get("tier", "")])
            writer.writerow(["PWA Score", f"{self.pwa_report.get('pwa_score', self.pwa_score)}%"])
            writer.writerow(["PWA Installable", "yes" if self.pwa_report.get("installable") else "no"])
            writer.writerow(["PWA Offline Ready", "yes" if self.pwa_report.get("offline_ready") else "no"])
            writer.writerow(["PWA Badges", ", ".join(self.pwa_report.get("badges", []))])
            writer.writerow([
                "PWA Installability Criteria",
                f"{self.pwa_report.get('criteria_met', 0)}/{self.pwa_report.get('criteria_total', 0)}",
            ])
            for crit in self.pwa_report.get("installability_criteria", []):
                writer.writerow(["PWA Criterion", crit["criterion"], "yes" if crit["met"] else "no"])
            for opp in self.pwa_report.get("score_opportunities", []):
                writer.writerow(["PWA Opportunity", opp["opportunity"], f"+{opp.get('est_gain', 0)}"])
            for step in self.pwa_report.get("next_steps", []):
                writer.writerow(["PWA Next Step", step])
            writer.writerow([])
            analysis_blocks = [
                ("UX Pattern", self.ux_patterns_analysis),
                ("Conversion", self.conversion_analysis),
                ("Engagement", self.engagement_analysis),
                ("Retention", self.retention_analysis),
            ]
            for prefix, block in analysis_blocks:
                if not block:
                    continue
                writer.writerow([f"{prefix} Score", f"{block.get('score', 0)}%"])
                writer.writerow([f"{prefix} Grade", block.get("grade", "")])
                for item in block.get("found", []):
                    writer.writerow([f"{prefix} Detected", item])
                for item in block.get("missing", []):
                    writer.writerow([f"{prefix} Missing", item])
                writer.writerow([])
        print(colored(f"[+] Results exported to {filepath}", "green"))

    def export_html(self, filepath):
        recs = self.get_recommendations()
        recs_html = "".join(f"<li>{r}</li>" for r in recs) if recs else "<li>No recommendations - looking good!</li>"
        roadmap_html = ""
        for i, item in enumerate(self.roadmap, 1):
            priority_bg = "#dc2626" if item["priority"] == "CRITICAL" else "#d97706" if item["priority"] == "HIGH" else "#0891b2"
            phase_label = item.get("phase", "")
            effort_label = item.get("effort", "Medium")
            roadmap_html += f'<div style="padding:8px 12px;margin-bottom:6px;background:#1e293b;border-radius:6px;border-left:3px solid {priority_bg}"><span style="color:{priority_bg};font-weight:bold;margin-right:8px">[{item["priority"]}]</span><span style="color:#e2e8f0">{item["category"]}: {item["issue"]}</span><span style="color:#64748b;margin-left:8px">({item["impact"]}, effort: {effort_label})</span><div style="color:#475569;font-size:12px;margin-top:4px">{phase_label} | Owner: {item.get("owner", "Engineering")} | {item.get("roi", "")} | Est. +{item.get("est_score_gain_pct", 0)}%</div></div>'
        if not roadmap_html:
            roadmap_html = '<div style="color:#22c55e;padding:12px">No critical issues - your site is well optimized!</div>'

        matrix_rows_html = ""
        for row in self.device_matrix:
            if row["status"] == "supported":
                status_bg = "#16a34a"
                status_text = "SUPPORTED"
            elif row["status"] == "partial":
                status_bg = "#ca8a04"
                status_text = "PARTIAL"
            else:
                status_bg = "#dc2626"
                status_text = "UNSUPPORTED"
            missing_text = ", ".join(row.get("missing_required", [])) or "-"
            cover_pct = row.get("coverage_pct", 0)
            note_text = row.get("note", "")
            matrix_rows_html += f'<tr><td style="padding:8px;border-bottom:1px solid #1e293b">{row["device"]}</td><td style="padding:8px;border-bottom:1px solid #1e293b">{row["range"]}</td><td style="padding:8px;border-bottom:1px solid #1e293b"><span style="background:{status_bg};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{status_text}</span></td><td style="padding:8px;border-bottom:1px solid #1e293b">{row["required_coverage"]} ({cover_pct}%)</td><td style="padding:8px;border-bottom:1px solid #1e293b;color:#94a3b8">{missing_text}</td><td style="padding:8px;border-bottom:1px solid #1e293b;color:#64748b">{note_text}</td></tr>'
        if not matrix_rows_html:
            matrix_rows_html = '<tr><td colspan="6" style="padding:8px;color:#64748b">No matrix data</td></tr>'

        a11y_issues_html = ""
        for crit in self.a11y_assessment.get("critical_failures", []):
            a11y_issues_html += f'<div style="padding:4px 0;color:#f87171">[!] {crit}</div>'
        for issue in self.a11y_assessment.get("issues", []):
            a11y_issues_html += f'<div style="padding:4px 0;color:#f87171">&#10007; {issue}</div>'
        if not a11y_issues_html:
            a11y_issues_html = '<div style="color:#22c55e;padding:4px 0">No mobile accessibility issues detected</div>'
        a11y_fixes_html = ""
        for fix in self.a11y_assessment.get("priority_fixes", []):
            a11y_fixes_html += f'<div style="padding:4px 0;color:#a78bfa">[>] {fix}</div>'
        a11y_criteria_html = ""
        for crit in self.a11y_assessment.get("wcag_criteria", []):
            c_icon = "&#10003;" if crit["met"] else "&#10007;"
            c_color = "#22c55e" if crit["met"] else "#ef4444"
            a11y_criteria_html += f'<div style="padding:3px 0;color:{c_color}">{c_icon} {crit["criterion"]}</div>'

        pwa_features_html = ""
        for feat in self.pwa_report.get("features", []):
            if feat["supported"]:
                icon = "&#10003;"
                ic = "#22c55e"
            else:
                icon = "&#10007;"
                ic = "#ef4444"
            pwa_features_html += f'<div style="padding:4px 0;border-bottom:1px solid #1e293b"><span style="color:{ic};margin-right:8px">{icon}</span>{feat["feature"]}</div>'
        pwa_badges = self.pwa_report.get("badges", [])
        pwa_badges_html = "".join(
            f'<span style="background:#1e293b;color:#67e8f9;padding:3px 10px;border-radius:12px;font-size:12px;margin-right:6px">{b}</span>'
            for b in pwa_badges
        )
        pwa_criteria_html = ""
        for crit in self.pwa_report.get("installability_criteria", []):
            c_icon = "&#10003;" if crit["met"] else "&#10007;"
            c_color = "#22c55e" if crit["met"] else "#ef4444"
            pwa_criteria_html += f'<div style="padding:3px 0;color:{c_color}">{c_icon} {crit["criterion"]}</div>'
        pwa_opps_html = ""
        for opp in self.pwa_report.get("score_opportunities", []):
            pwa_opps_html += f'<div style="padding:3px 0;color:#fbbf24">[~] {opp["opportunity"]} (~+{opp.get("est_gain", 0)} pts)</div>'
        pwa_steps_html = ""
        for step in self.pwa_report.get("next_steps", []):
            pwa_steps_html += f'<div style="padding:4px 0;color:#fbbf24">[>] {step}</div>'

        analysis_html = ""
        analysis_defs = [
            ("Mobile UX Patterns Analysis", self.ux_patterns_analysis),
            ("Mobile Conversion Optimization", self.conversion_analysis),
            ("Mobile Engagement Signals", self.engagement_analysis),
            ("Mobile Retention Signals", self.retention_analysis),
        ]
        for section_title, block in analysis_defs:
            if not block:
                continue
            score_val = block.get("score", 0)
            grade_val = block.get("grade", "N/A")
            coverage_val = block.get("coverage", "0/0")
            color = "#22c55e" if score_val >= 80 else "#eab308" if score_val >= 50 else "#ef4444"
            items_html = ""
            for item in block.get("found", []):
                pretty = item.replace("_", " ").title()
                items_html += f'<div style="padding:3px 0;color:#22c55e">[+] {pretty}</div>'
            for item in block.get("missing", [])[:8]:
                pretty = item.replace("_", " ").title()
                items_html += f'<div style="padding:3px 0;color:#f87171">[-] {pretty}</div>'
            analysis_html += f'''
            <div style="background:#0f172a;border-radius:8px;padding:16px;margin-bottom:12px">
                <h3 style="margin:0 0 8px;color:#e2e8f0">{section_title}</h3>
                <div style="color:#94a3b8;font-size:14px;margin-bottom:8px">Score: <span style="color:{color};font-weight:bold">{score_val}%</span> - Grade: {grade_val} - Coverage: {coverage_val}</div>
                {items_html}
            </div>'''

        cats_html = ""
        cat_order = CATEGORY_ORDER
        for cat_key in cat_order:
            if cat_key not in self.results:
                continue
            data = self.results[cat_key]
            pct = round((data["score"] / data["max"]) * 100, 1) if data["max"] > 0 else 0
            color = "#22c55e" if pct >= 80 else "#eab308" if pct >= 50 else "#ef4444"
            details_html = ""
            for d in data["details"]:
                icon = "&#10003;" if d["passed"] else "&#10007;"
                ic = "#22c55e" if d["passed"] else "#ef4444"
                details_html += f'<div style="padding:4px 0;border-bottom:1px solid #1e293b"><span style="color:{ic};margin-right:8px">{icon}</span>{d["check"]}</div>'
            label = CATEGORY_LABELS.get(cat_key, cat_key)
            cats_html += f"""
            <div style="background:#0f172a;border-radius:8px;padding:16px;margin-bottom:12px">
                <h3 style="margin:0 0 8px;color:#e2e8f0">{label}</h3>
                <div style="background:#1e293b;border-radius:4px;height:20px;overflow:hidden;margin-bottom:8px">
                    <div style="background:{color};height:100%;width:{pct}%;border-radius:4px"></div>
                </div>
                <div style="color:#94a3b8;font-size:14px">{data['score']}/{data['max']} ({pct}%)</div>
                {details_html}
            </div>"""
        grade, verdict, _ = self.get_grade()
        grade_colors = {"A": "#22c55e", "B": "#06b6d4", "C": "#eab308", "D": "#f97316", "F": "#ef4444"}
        gc = grade_colors.get(grade, "#94a3b8")
        pwa_color = "#22c55e" if self.pwa_score >= 70 else "#eab308" if self.pwa_score >= 40 else "#ef4444"
        touch_color = "#22c55e" if self.touch_score >= 70 else "#eab308" if self.touch_score >= 40 else "#ef4444"
        budget_color = "#22c55e" if self.perf_budget_score >= 70 else "#eab308" if self.perf_budget_score >= 40 else "#ef4444"
        net_color = "#22c55e" if self.network_adapt_score >= 70 else "#eab308" if self.network_adapt_score >= 40 else "#ef4444"
        cap_color = "#22c55e" if self.mobile_capability_score >= 70 else "#eab308" if self.mobile_capability_score >= 40 else "#ef4444"
        ux_score_color = "#22c55e" if self.mobile_ux_score >= 70 else "#eab308" if self.mobile_ux_score >= 40 else "#ef4444"
        perf_score_color = "#22c55e" if self.mobile_perf_score >= 70 else "#eab308" if self.mobile_perf_score >= 40 else "#ef4444"
        a11y_level = self.a11y_assessment.get("level", "N/A")
        a11y_score = self.a11y_assessment.get("score", 0)
        a11y_criteria_line = (
            f"{self.a11y_assessment.get('criteria_met', 0)}/"
            f"{self.a11y_assessment.get('criteria_total', 0)} WCAG criteria"
        )
        pwa_tier = self.pwa_report.get("tier", "N/A")
        pwa_cap = self.pwa_report.get("capability_pct", 0)
        pwa_installable = "READY" if self.pwa_report.get("installable") else "NOT READY"
        matrix_label = getattr(self, "device_matrix_summary", {}).get("readiness_label", "")
        matrix_pct = getattr(self, "device_matrix_summary", {}).get("overall_pct", 0)
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MobileAnalyzer v{VERSION} Report - {self.url}</title>
</head>
<body style="margin:0;padding:24px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#020617;color:#e2e8f0">
<div style="max-width:700px;margin:0 auto">
<h1 style="color:#f1f5f9;border-bottom:2px solid #334155;padding-bottom:12px">MobileAnalyzer v{VERSION} Report</h1>
<p style="color:#94a3b8">URL: {self.url}</p>
<p style="color:#94a3b8">Network Budget: {self.budget['name']}</p>
<div style="text-align:center;padding:24px;background:#0f172a;border-radius:12px;margin:16px 0">
<div style="font-size:48px;font-weight:bold;color:{gc}">{grade}</div>
<div style="font-size:24px;color:#94a3b8">{verdict}</div>
<div style="font-size:18px;color:#64748b">{self.total_score}/{self.max_score} ({self.mobile_readiness}%)</div>
</div>
<div style="display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap">
<div style="flex:1;min-width:140px;background:#0f172a;border-radius:8px;padding:16px;text-align:center">
<div style="font-size:14px;color:#94a3b8;margin-bottom:4px">PWA Score</div>
<div style="font-size:24px;font-weight:bold;color:{pwa_color}">{self.pwa_score}%</div>
</div>
<div style="flex:1;min-width:140px;background:#0f172a;border-radius:8px;padding:16px;text-align:center">
<div style="font-size:14px;color:#94a3b8;margin-bottom:4px">Touch Score</div>
<div style="font-size:24px;font-weight:bold;color:{touch_color}">{self.touch_score}%</div>
</div>
<div style="flex:1;min-width:140px;background:#0f172a;border-radius:8px;padding:16px;text-align:center">
<div style="font-size:14px;color:#94a3b8;margin-bottom:4px">Perf Budget</div>
<div style="font-size:24px;font-weight:bold;color:{budget_color}">{self.perf_budget_score}%</div>
</div>
<div style="flex:1;min-width:140px;background:#0f172a;border-radius:8px;padding:16px;text-align:center">
<div style="font-size:14px;color:#94a3b8;margin-bottom:4px">Mobile UX</div>
<div style="font-size:24px;font-weight:bold;color:{ux_score_color}">{self.mobile_ux_score}%</div>
</div>
<div style="flex:1;min-width:140px;background:#0f172a;border-radius:8px;padding:16px;text-align:center">
<div style="font-size:14px;color:#94a3b8;margin-bottom:4px">Mobile Perf</div>
<div style="font-size:24px;font-weight:bold;color:{perf_score_color}">{self.mobile_perf_score}%</div>
</div>
<div style="flex:1;min-width:140px;background:#0f172a;border-radius:8px;padding:16px;text-align:center">
<div style="font-size:14px;color:#94a3b8;margin-bottom:4px">Network Adapt</div>
<div style="font-size:24px;font-weight:bold;color:{net_color}">{self.network_adapt_score}%</div>
</div>
<div style="flex:1;min-width:140px;background:#0f172a;border-radius:8px;padding:16px;text-align:center">
<div style="font-size:14px;color:#94a3b8;margin-bottom:4px">Capabilities</div>
<div style="font-size:24px;font-weight:bold;color:{cap_color}">{self.mobile_capability_score}%</div>
</div>
</div>
<h2 style="color:#f1f5f9">Category Breakdown</h2>
{cats_html}
<h2 style="color:#f1f5f9">Device Compatibility Matrix</h2>
<div style="background:#0f172a;border-radius:8px;padding:12px 16px;margin-bottom:8px;color:#94a3b8">Overall: {matrix_pct}% - {matrix_label}</div>
<table style="width:100%;border-collapse:collapse;background:#0f172a;border-radius:8px;overflow:hidden">
<thead><tr style="background:#1e293b;color:#94a3b8;text-align:left">
<th style="padding:8px">Device</th><th style="padding:8px">Range</th><th style="padding:8px">Status</th><th style="padding:8px">Required</th><th style="padding:8px">Missing</th>
</tr></thead>
<tbody>
{matrix_rows_html}
</tbody>
</table>
<h2 style="color:#f1f5f9">Mobile Accessibility Assessment</h2>
<div style="background:#0f172a;border-radius:8px;padding:16px">
<div style="font-size:18px;color:#e2e8f0;margin-bottom:8px">Score: {a11y_score}% - Level: {a11y_level} ({a11y_criteria_line})</div>
{a11y_issues_html}
{a11y_criteria_html}
{a11y_fixes_html}
</div>
<h2 style="color:#f1f5f9">PWA Capability Report</h2>
<div style="background:#0f172a;border-radius:8px;padding:16px">
<div style="font-size:18px;color:#e2e8f0;margin-bottom:4px">Tier: {pwa_tier} ({pwa_cap}%)</div>
<div style="font-size:14px;color:#94a3b8;margin-bottom:8px">Installability: {pwa_installable}</div>
<div style="margin-bottom:12px">{pwa_badges_html}</div>
<div style="margin-bottom:8px;color:#94a3b8;font-size:13px">Installability criteria</div>
{pwa_criteria_html}
{pwa_features_html}
<div style="margin-top:12px;color:#94a3b8;font-size:13px">Score opportunities</div>
{pwa_opps_html}
<div style="margin-top:12px;color:#94a3b8;font-size:13px">Next steps</div>
{pwa_steps_html}
</div>
<h2 style="color:#f1f5f9">Optimization Roadmap</h2>
<div style="background:#0f172a;border-radius:8px;padding:16px">
{roadmap_html}
</div>
<h2 style="color:#f1f5f9">Recommendations</h2>
<div style="background:#0f172a;border-radius:8px;padding:16px">
<ol style="margin:0;padding-left:20px">{recs_html}</ol>
</div>
<p style="color:#475569;text-align:center;margin-top:24px">Generated by MobileAnalyzer v{VERSION}</p>
</div>
</body>
</html>"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        print(colored(f"[+] Results exported to {filepath}", "green"))


def main():
    args = parse_args()
    if args.help:
        print(BANNER)
        print("Usage: mobileanalyzer.py -u <URL> [-t TIMEOUT] [--network 3g|4g] [--export FORMAT] [--no-color]")
        print()
        print("Options:")
        print("  -u, --url       Target URL (required)")
        print("  -t, --timeout   Request timeout in seconds (default: 15)")
        print("  --network       Network budget: 3g or 4g (default: 4g)")
        print("  --export        Export format: all/json/csv/html/none (default: none)")
        print("  --no-color      Disable colored output")
        print("  -h, --help      Show this help message")
        print()
        print("v7.0 highlights:")
        print("  - Touch feedback, haptic feedback, device motion, battery, network info, geolocation checks")
        print("  - Refined mobile UX / performance / accessibility / PWA analysis")
        print("  - Weighted readiness, PWA, UX, performance + network-adapt scoring")
        print("  - Owner/ROI roadmap, 9-class device matrix, WCAG criteria map, PWA opportunities")
        print("  - Foldable, notch/safe-area, dark mode, orientation, haptic, AR/VR checks")
        print("  - Mobile-first CSS and breakpoint analysis")
        sys.exit(0)
    if not args.url:
        print(colored("[!] Missing required argument: -u/--url", "red"))
        sys.exit(2)
    use_color = not args.no_color
    print(BANNER)
    print(colored(f"[*] Analyzing: {args.url}", "cyan", use_color))
    print(colored(f"[*] Timeout: {args.timeout}s", "cyan", use_color))
    print(colored(f"[*] Network Budget: {args.network.upper()}", "cyan", use_color))
    print()
    analyzer = MobileAnalyzer(args.url, args.timeout, args.network)
    analyzer.run_all_checks()
    analyzer.print_results(use_color)
    if args.export in ("json", "all"):
        analyzer.export_json("mobile_report.json")
    if args.export in ("csv", "all"):
        analyzer.export_csv("mobile_report.csv")
    if args.export in ("html", "all"):
        analyzer.export_html("mobile_report.html")


if __name__ == "__main__":
    main()
