#!/usr/bin/env python3

import sys
import os
import re
import csv
import json
import time
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse, urljoin, urlunparse, unquote

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

VERSION = "2.0"
USER_AGENT = "SitemapAnalyzer/2.0"
SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"
MAX_CHILD_SITEMAPS = 5
ROBOTS_DIRECTIVES = {
    "user-agent", "allow", "disallow", "crawl-delay", "sitemap", "host",
    "request-rate", "visit-time", "clean-param",
}
VALID_CHANGEFREQ = {"always", "hourly", "daily", "weekly", "monthly", "yearly", "never"}

FONT = {
    "S": ["  ____  ", " / ___| ", "| |     ", "| |___  ", " \\____| "],
    "I": [" _ ", "| |", "| |", "| |", "|_|"],
    "T": [" _____ ", "|_   _|", "  | |  ", "  | |  ", "  |_|  "],
    "E": [" _____ ", "| ____|", "|  _|  ", "| |___ ", "|_____|"],
    "M": [" __  __ ", "|  \\/  |", "| |\\/| |", "| |  | |", "|_|  |_|"],
    "A": ["    _   ", "   / \\  ", "  / _ \\ ", " / ___ \\", "/_/   \\_\\"],
    "P": [" ____  ", "|  _ \\ ", "| |_) |", "|  __/ ", "|_|    "],
    "N": [" _   _ ", "| \\ | |", "|  \\| |", "| |\\  |", "|_| \\_|"],
    "L": [" _     ", "| |    ", "| |    ", "| |___ ", "|_____|"],
    "Y": ["__   __", "\\ \\ / /", " \\ V / ", "  | |  ", "  |_|  "],
    "Z": [" _____ ", "|___  |", "   / / ", "  / /  ", " /_/___|"],
    "R": [" ____  ", "|  _ \\ ", "| |_) |", "|  _ < ", "|_| \\_\\"],
    " ": ["   ", "   ", "   ", "   ", "   "],
}

C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[94m"
C_MAGENTA = "\033[95m"
C_CYAN = "\033[96m"
C_WHITE = "\033[97m"
C_GRAY = "\033[90m"
LINE_COLORS = [C_CYAN, C_GREEN, C_YELLOW, C_MAGENTA, C_BLUE]

COLORS_ENABLED = True


def paint(text, color):
    if not COLORS_ENABLED:
        return text
    return f"{color}{text}{C_RESET}"


def disable_colors():
    global COLORS_ENABLED
    COLORS_ENABLED = False


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


def grade_color(grade):
    if grade in ("A+", "A"):
        return C_GREEN
    if grade == "B":
        return C_CYAN
    if grade == "C":
        return C_YELLOW
    if grade == "D":
        return C_MAGENTA
    return C_RED


def status_color(status):
    return {"pass": C_GREEN, "warn": C_YELLOW, "fail": C_RED}.get(status, C_WHITE)


def status_label(status):
    return {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}.get(status, status.upper())


def local_tag(tag):
    if not isinstance(tag, str):
        return ""
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def build_word(word):
    rows = []
    for row in range(5):
        parts = []
        for ch in word.upper():
            glyph = FONT.get(ch, FONT[" "])
            parts.append(glyph[row])
        rows.append("  ".join(parts).rstrip())
    return rows


def print_banner():
    line1 = build_word("SITEMAP")
    line2 = build_word("ANALYZER")
    if COLORS_ENABLED:
        for i, row in enumerate(line1):
            print(paint(row, LINE_COLORS[i % len(LINE_COLORS)]))
        for i, row in enumerate(line2):
            print(paint(row, LINE_COLORS[(i + 2) % len(LINE_COLORS)]))
    else:
        for row in line1 + line2:
            print(row)
    print(paint("  +============================================================+", C_CYAN))
    print(paint("  |  ", C_CYAN) + paint(f"SITEMAP & CRAWLABILITY ANALYZER  v{VERSION}".ljust(56), C_WHITE) + paint("|", C_CYAN))
    print(paint("  |  ", C_CYAN) + paint("Sitemaps | Robots.txt | Crawlability | Indexability".ljust(56), C_YELLOW) + paint("|", C_CYAN))
    print(paint("  +============================================================+", C_CYAN))
    print()


class CategoryResult:
    def __init__(self, key, title, max_points):
        self.key = key
        self.title = title
        self.max_points = float(max_points)
        self.checks = []

    def add(self, name, status, detail=""):
        if status not in ("pass", "warn", "fail"):
            status = "fail"
        self.checks.append({
            "check": name,
            "status": status,
            "detail": str(detail),
            "points": 0.0,
            "max": 0.0,
        })
        return self

    def finalize(self):
        if not self.checks:
            return self
        share = self.max_points / len(self.checks)
        factor = {"pass": 1.0, "warn": 0.5, "fail": 0.0}
        for item in self.checks:
            item["max"] = round(share, 2)
            item["points"] = round(share * factor[item["status"]], 2)
        return self

    @property
    def score(self):
        if not self.checks:
            return 0.0
        share = self.max_points / len(self.checks)
        factor = {"pass": 1.0, "warn": 0.5, "fail": 0.0}
        raw = sum(share * factor[i["status"]] for i in self.checks)
        return round(min(raw, self.max_points), 2)

    @property
    def pct(self):
        if self.max_points <= 0:
            return 0.0
        return round(self.score / self.max_points * 100, 1)

    def to_dict(self):
        return {
            "key": self.key,
            "title": self.title,
            "score": self.score,
            "max": self.max_points,
            "pct": self.pct,
            "checks": self.checks,
        }


class SitemapAnalyzer:
    def __init__(self, url, timeout=15, verbose=False):
        self.url = self.normalize_url(url)
        self.timeout = timeout
        self.verbose = verbose
        parsed = urlparse(self.url)
        self.scheme = parsed.scheme or "https"
        self.netloc = parsed.netloc
        self.root = f"{self.scheme}://{self.netloc}"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xml;q=0.9,*/*;q=0.8",
        })
        self.robots_url = urljoin(self.root + "/", "robots.txt")
        self.robots_text = None
        self.robots_status = None
        self.robots_rules = []
        self.robots_sitemaps = []
        self.sitemap_url = None
        self.sitemap_status = None
        self.sitemap_bytes = 0
        self.sitemap_root = None
        self.sitemap_is_index = False
        self.sitemap_entries = []
        self.child_sitemap_urls = []
        self.child_sitemap_count = 0
        self.sitemap_has_news = False
        self.sitemap_image_tags = 0
        self.sitemap_video_tags = 0
        self.sitemap_hreflang_count = 0
        self.page_resp = None
        self.soup = None
        self.page_html = ""
        self.started_at = None
        self.elapsed = 0.0
        self.results = []
        self.total_score = 0.0
        self.grade = "F"
        self.meta_robots = ""
        self.x_robots = ""
        self.canonical = ""
        self.internal_links = []
        self.external_links = 0

    def normalize_url(self, url):
        url = url.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
            url = "https://" + url
        return url

    def log(self, message):
        if self.verbose:
            print(paint(f"    [debug] {message}", C_GRAY))

    def fetch(self, url, stream=False):
        self.log(f"GET {url}")
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True, stream=stream)
            self.log(f"  -> {resp.status_code} ({len(resp.content)} bytes, {resp.url})")
            return resp
        except requests.RequestException as exc:
            self.log(f"  -> error: {exc}")
            return None

    def parse_robots(self, text):
        rules = []
        sitemaps = []
        current_agents = []
        bad_lines = []
        known_count = 0
        for idx, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                bad_lines.append(f"line {idx}: missing ':'")
                continue
            name, value = line.split(":", 1)
            name = name.strip().lower()
            value = value.strip()
            if not name:
                bad_lines.append(f"line {idx}: empty directive")
                continue
            if name not in ROBOTS_DIRECTIVES:
                bad_lines.append(f"line {idx}: unknown directive '{name}'")
            else:
                known_count += 1
            if name == "user-agent":
                current_agents = [value] if value else []
                rules.append({"type": "user-agent", "value": value, "agents": list(current_agents)})
            elif name == "sitemap":
                sitemaps.append(value)
            elif name in ("allow", "disallow"):
                rules.append({"type": name, "value": value, "agents": list(current_agents)})
            else:
                rules.append({"type": name, "value": value, "agents": list(current_agents)})
        return rules, sitemaps, bad_lines, known_count

    def fetch_robots(self):
        resp = self.fetch(self.robots_url)
        if resp is None:
            self.robots_status = None
            return
        self.robots_status = resp.status_code
        if resp.status_code == 200:
            try:
                self.robots_text = resp.content.decode("utf-8", errors="replace")
            except Exception:
                self.robots_text = resp.text
            self.robots_rules, self.robots_sitemaps, self._robots_bad, self._robots_known = self.parse_robots(self.robots_text)
        else:
            self._robots_bad = []
            self._robots_known = 0

    def robots_get(self, rule_type):
        return [r for r in self.robots_rules if r["type"] == rule_type]

    def fetch_sitemap(self):
        candidates = list(self.robots_sitemaps)
        for path in ("/sitemap.xml", "/sitemap_index.xml", "/sitemapindex.xml"):
            candidate = urljoin(self.root + "/", path.lstrip("/"))
            if candidate not in candidates:
                candidates.append(candidate)
        for candidate in candidates:
            resp = self.fetch(candidate)
            if resp is None or resp.status_code != 200:
                continue
            content_type = (resp.headers.get("Content-Type") or "").lower()
            if "html" in content_type and b"<urlset" not in resp.content and b"<sitemapindex" not in resp.content:
                continue
            try:
                root = ET.fromstring(resp.content)
            except ET.ParseError:
                self.log(f"sitemap parse failed: {candidate}")
                continue
            self.sitemap_url = candidate
            self.sitemap_status = resp.status_code
            self.sitemap_bytes = len(resp.content)
            self.sitemap_root = root
            root_tag = local_tag(root.tag).lower()
            self.sitemap_is_index = root_tag == "sitemapindex"
            if self.sitemap_is_index:
                self.collect_child_sitemaps(root)
            else:
                self.sitemap_entries = self.extract_entries(root, kind="url")
            self.collect_sitemap_extras(root)
            return
        self.log("no parseable sitemap found")

    def collect_sitemap_extras(self, root):
        for el in root.iter():
            tag = el.tag if isinstance(el.tag, str) else ""
            lowered = tag.lower()
            local = local_tag(tag).lower()
            if "news" in lowered:
                self.sitemap_has_news = True
            if local == "image" or "sitemap-image" in lowered or "image:loc" in lowered:
                self.sitemap_image_tags += 1
            if local == "video" or "sitemap-video" in lowered or "video:loc" in lowered:
                self.sitemap_video_tags += 1
            if local == "link" and el.get("hreflang"):
                self.sitemap_hreflang_count += 1
        if not self.sitemap_has_news:
            for el in root.iter():
                for value in el.attrib.values():
                    if isinstance(value, str) and "news" in value.lower():
                        self.sitemap_has_news = True
                        break
                if self.sitemap_has_news:
                    break
        self.log(f"extras: news={self.sitemap_has_news} image={self.sitemap_image_tags} video={self.sitemap_video_tags} hreflang={self.sitemap_hreflang_count}")

    def collect_child_sitemaps(self, root):
        locations = []
        for el in root.iter():
            if local_tag(el.tag).lower() == "loc" and el.text:
                loc = el.text.strip()
                if loc:
                    locations.append(loc)
        self.child_sitemap_urls = locations
        self.child_sitemap_count = len(locations)
        for child_url in locations[:MAX_CHILD_SITEMAPS]:
            resp = self.fetch(child_url)
            if resp is None or resp.status_code != 200:
                continue
            try:
                child_root = ET.fromstring(resp.content)
            except ET.ParseError:
                continue
            self.sitemap_bytes += len(resp.content)
            self.sitemap_entries.extend(self.extract_entries(child_root, kind="url"))

    def extract_entries(self, root, kind="url"):
        entries = []
        wanted = "sitemap" if kind == "sitemap" else "url"
        for el in root.iter():
            if local_tag(el.tag).lower() != wanted:
                continue
            entry = {"loc": "", "lastmod": "", "changefreq": "", "priority": "", "child": kind}
            for child in el:
                tag = local_tag(child.tag).lower()
                text = (child.text or "").strip()
                if tag in entry:
                    entry[tag] = text
            if entry["loc"]:
                entries.append(entry)
        return entries

    def fetch_page(self):
        self.page_resp = self.fetch(self.url)
        if self.page_resp is None:
            return
        content_type = (self.page_resp.headers.get("Content-Type") or "").lower()
        if "html" in content_type or not content_type:
            self.page_html = self.page_resp.text or ""
            self.soup = BeautifulSoup(self.page_html, "html.parser")
        if self.soup:
            self.collect_page_signals()

    def collect_page_signals(self):
        meta = self.soup.find("meta", attrs={"name": re.compile(r"^(robots|googlebot)$", re.I)})
        self.meta_robots = ""
        for tag in self.soup.find_all("meta"):
            name = (tag.get("name") or "").lower()
            if name in ("robots", "googlebot"):
                self.meta_robots = f"{self.meta_robots} {tag.get('content') or ''}".strip()
        if meta and not self.meta_robots:
            self.meta_robots = meta.get("content") or ""
        self.x_robots = ""
        if self.page_resp is not None:
            self.x_robots = self.page_resp.headers.get("X-Robots-Tag") or ""
        canonical_tag = self.soup.find("link", rel=lambda v: v and "canonical" in ([v] if isinstance(v, str) else v))
        self.canonical = ""
        if canonical_tag and canonical_tag.get("href"):
            self.canonical = urljoin(self.url, canonical_tag.get("href").strip())
        self.internal_links = []
        self.external_links = 0
        for a in self.soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            absolute = urljoin(self.url, href)
            parsed = urlparse(absolute)
            if parsed.scheme not in ("http", "https"):
                continue
            if parsed.netloc == self.netloc:
                self.internal_links.append(absolute)
            else:
                self.external_links += 1

    def page_ok(self):
        if self.page_resp is None:
            return False
        return 200 <= self.page_resp.status_code < 300

    def check_robots(self):
        cat = CategoryResult("robots", "robots.txt Analysis", 20)
        exists = self.robots_status == 200 and self.robots_text is not None
        cat.add("robots.txt existence", "pass" if exists else "fail",
                f"HTTP {self.robots_status} at {self.robots_url}" if self.robots_status is not None else "Request failed")
        if not exists:
            cat.add("robots.txt syntax validation", "fail", "File missing, cannot validate syntax")
            cat.add("User-agent directives", "fail", "No user-agent directives found")
            cat.add("Disallow rules analysis", "fail", "No disallow rules to analyze")
            cat.add("Allow rules analysis", "fail", "No allow rules to analyze")
            cat.add("Crawl-delay directive", "fail", "Crawl-delay not present")
            cat.add("Sitemap directive in robots.txt", "fail", "No Sitemap directive found")
            cat.add("Host directive", "fail", "Host directive not present")
            return cat.finalize()
        bad = getattr(self, "_robots_bad", [])
        known = getattr(self, "_robots_known", 0)
        if not bad and known > 0:
            cat.add("robots.txt syntax validation", "pass", f"{known} valid directives, 0 syntax issues")
        elif bad:
            sample = "; ".join(bad[:3])
            cat.add("robots.txt syntax validation", "warn" if len(bad) <= 3 else "fail", f"{len(bad)} issue(s): {sample}")
        else:
            cat.add("robots.txt syntax validation", "fail", "No valid directives parsed")
        agents = self.robots_get("user-agent")
        if agents:
            names = ", ".join(a["value"] for a in agents if a["value"]) or "(empty)"
            cat.add("User-agent directives", "pass", f"{len(agents)} user-agent block(s): {names[:80]}")
        else:
            cat.add("User-agent directives", "fail", "No User-agent lines found")
        disallows = self.robots_get("disallow")
        star_block = False
        for rule in agents:
            if rule["value"] == "*":
                star_block = True
        full_block = any(d["value"] == "/" and star_block for d in disallows)
        if full_block:
            cat.add("Disallow rules analysis", "warn", f"{len(disallows)} disallow rule(s); global 'Disallow: /' present")
        elif disallows:
            cat.add("Disallow rules analysis", "pass", f"{len(disallows)} disallow rule(s) found")
        else:
            cat.add("Disallow rules analysis", "pass", "No disallow rules (crawl fully open)")
        allows = self.robots_get("allow")
        if allows:
            cat.add("Allow rules analysis", "pass", f"{len(allows)} allow rule(s) found")
        elif disallows:
            cat.add("Allow rules analysis", "warn", "Disallow rules present but no Allow overrides")
        else:
            cat.add("Allow rules analysis", "pass", "No allow rules needed")
        delays = self.robots_get("crawl-delay")
        if delays:
            cat.add("Crawl-delay directive", "pass", f"Crawl-delay: {delays[0]['value']}")
        else:
            cat.add("Crawl-delay directive", "warn", "Crawl-delay not specified")
        sitemap_dirs = [r for r in self.robots_rules if r["type"] == "sitemap"]
        if sitemap_dirs:
            cat.add("Sitemap directive in robots.txt", "pass", f"{len(sitemap_dirs)} sitemap directive(s): {sitemap_dirs[0]['value'][:80]}")
        else:
            cat.add("Sitemap directive in robots.txt", "fail", "No Sitemap directive in robots.txt")
        hosts = self.robots_get("host")
        if hosts:
            cat.add("Host directive", "pass", f"Host: {hosts[0]['value']}")
        else:
            cat.add("Host directive", "warn", "Host directive not present")
        return cat.finalize()

    def check_sitemap_detection(self):
        cat = CategoryResult("sitemap", "Sitemap Detection", 15)
        found = self.sitemap_url is not None
        direct = self.sitemap_url and self.sitemap_url.rstrip("/").endswith("sitemap.xml")
        if found and (direct or self.robots_sitemaps):
            cat.add("sitemap.xml detection", "pass", f"Sitemap discovered: {self.sitemap_url}")
        elif found:
            cat.add("sitemap.xml detection", "warn", f"Alternate sitemap path used: {self.sitemap_url}")
        else:
            cat.add("sitemap.xml detection", "fail", "No sitemap.xml found at standard locations")
        if self.sitemap_is_index:
            cat.add("Sitemap index detection", "pass", f"Sitemap index detected with {self.child_sitemap_count} child sitemap(s)")
        elif found:
            cat.add("Sitemap index detection", "warn", "Plain urlset sitemap found, no sitemap index")
        else:
            cat.add("Sitemap index detection", "fail", "No sitemap index detected")
        multi = len(self.robots_sitemaps) + (1 if found else 0)
        if self.sitemap_is_index and self.child_sitemap_count >= 1:
            multi = max(multi, self.child_sitemap_count)
        if multi >= 2:
            cat.add("Multiple sitemaps", "pass", f"{multi} sitemap resources referenced")
        elif multi == 1:
            cat.add("Multiple sitemaps", "warn", "Single sitemap resource found")
        else:
            cat.add("Multiple sitemaps", "fail", "No sitemaps found")
        if self.robots_sitemaps:
            cat.add("Sitemap in robots.txt", "pass", f"{len(self.robots_sitemaps)} Sitemap directive(s) in robots.txt")
        else:
            cat.add("Sitemap in robots.txt", "fail", "robots.txt does not reference a sitemap")
        if not found:
            cat.add("Sitemap size analysis", "fail", "No sitemap available to measure")
        else:
            size = self.sitemap_bytes
            kb = size / 1024.0
            if size == 0:
                cat.add("Sitemap size analysis", "fail", "Empty sitemap payload")
            elif size > 50 * 1024 * 1024:
                cat.add("Sitemap size analysis", "fail", f"{kb:.1f} KB exceeds 50MB uncompressed limit")
            elif size > 10 * 1024 * 1024:
                cat.add("Sitemap size analysis", "warn", f"{kb:.1f} KB is large; consider splitting")
            else:
                cat.add("Sitemap size analysis", "pass", f"{kb:.1f} KB within limits")
        return cat.finalize()

    def check_sitemap_content(self):
        cat = CategoryResult("content", "Sitemap Content", 15)
        entries = self.sitemap_entries
        if not entries:
            cat.add("URL count analysis", "fail", "No URLs parsed from sitemap")
            cat.add("Lastmod dates", "fail", "No lastmod data available")
            cat.add("Changefreq values", "fail", "No changefreq data available")
            cat.add("Priority values", "fail", "No priority data available")
            cat.add("URL structure analysis", "fail", "No URLs available for structure analysis")
            cat.add("Lastmod freshness (90 days)", "fail", "No lastmod data available")
            cat.add("Image/video tags in sitemap", "fail", "No sitemap URLs to inspect")
            cat.add("hreflang alternates in sitemap", "fail", "No sitemap URLs to inspect")
            return cat.finalize()
        count = len(entries)
        if count >= 10:
            cat.add("URL count analysis", "pass", f"{count} URLs listed")
        elif count >= 1:
            cat.add("URL count analysis", "warn", f"Only {count} URL(s) listed")
        else:
            cat.add("URL count analysis", "fail", "Zero URLs listed")
        lastmods = [e for e in entries if e.get("lastmod")]
        lm_pct = len(lastmods) / count * 100 if count else 0
        if lm_pct >= 50:
            cat.add("Lastmod dates", "pass", f"{len(lastmods)}/{count} URLs have lastmod ({lm_pct:.0f}%)")
        elif lastmods:
            cat.add("Lastmod dates", "warn", f"Only {len(lastmods)}/{count} URLs have lastmod ({lm_pct:.0f}%)")
        else:
            cat.add("Lastmod dates", "fail", "No lastmod values present")
        changefreqs = [e for e in entries if e.get("changefreq")]
        invalid_cf = [e["changefreq"] for e in changefreqs if e["changefreq"].lower() not in VALID_CHANGEFREQ]
        cf_pct = len(changefreqs) / count * 100 if count else 0
        if changefreqs and not invalid_cf and cf_pct >= 50:
            cat.add("Changefreq values", "pass", f"{len(changefreqs)}/{count} URLs have valid changefreq")
        elif changefreqs:
            detail = f"{len(changefreqs)}/{count} present"
            if invalid_cf:
                detail += f", {len(invalid_cf)} invalid value(s): {invalid_cf[0]}"
            cat.add("Changefreq values", "warn", detail)
        else:
            cat.add("Changefreq values", "fail", "No changefreq values present")
        priorities = []
        invalid_pr = 0
        for entry in entries:
            raw = entry.get("priority") or ""
            if not raw:
                continue
            priorities.append(raw)
            try:
                value = float(raw)
                if value < 0.0 or value > 1.0:
                    invalid_pr += 1
            except ValueError:
                invalid_pr += 1
        pr_pct = len(priorities) / count * 100 if count else 0
        if priorities and invalid_pr == 0 and pr_pct >= 50:
            cat.add("Priority values", "pass", f"{len(priorities)}/{count} URLs have valid priority")
        elif priorities:
            cat.add("Priority values", "warn", f"{len(priorities)}/{count} present, {invalid_pr} invalid")
        else:
            cat.add("Priority values", "fail", "No priority values present")
        absolute = 0
        https = 0
        malformed = 0
        for entry in entries:
            loc = entry.get("loc") or ""
            parsed = urlparse(loc)
            if parsed.scheme in ("http", "https") and parsed.netloc:
                absolute += 1
                if parsed.scheme == "https":
                    https += 1
            else:
                malformed += 1
        if malformed == 0 and https == absolute and absolute > 0:
            cat.add("URL structure analysis", "pass", f"All {absolute} URLs absolute HTTPS")
        elif malformed == 0 and absolute > 0:
            cat.add("URL structure analysis", "warn", f"{absolute} absolute URLs, {https} on HTTPS")
        elif absolute > 0:
            cat.add("URL structure analysis", "warn", f"{absolute} valid absolute, {malformed} malformed")
        else:
            cat.add("URL structure analysis", "fail", "No well-formed absolute URLs in sitemap")
        fresh = 0
        parseable = 0
        cutoff = time.time() - 90 * 86400
        for entry in lastmods:
            raw = (entry.get("lastmod") or "").strip()
            try:
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                if dt.tzinfo is not None:
                    ts = dt.timestamp()
                else:
                    ts = (dt - datetime(1970, 1, 1)).total_seconds()
                parseable += 1
                if ts >= cutoff:
                    fresh += 1
            except (ValueError, TypeError):
                continue
        if parseable:
            fresh_pct = fresh / parseable * 100
            if fresh_pct >= 50:
                cat.add("Lastmod freshness (90 days)", "pass",
                        f"{fresh}/{parseable} lastmod values within last 90 days ({fresh_pct:.0f}%)")
            elif fresh > 0:
                cat.add("Lastmod freshness (90 days)", "warn",
                        f"only {fresh}/{parseable} lastmod values within last 90 days ({fresh_pct:.0f}%)")
            else:
                cat.add("Lastmod freshness (90 days)", "fail",
                        f"0/{parseable} lastmod values within last 90 days")
        else:
            cat.add("Lastmod freshness (90 days)", "fail", "No parseable lastmod dates to check")
        if self.sitemap_image_tags or self.sitemap_video_tags:
            media = []
            if self.sitemap_image_tags:
                media.append(f"{self.sitemap_image_tags} image tag(s)")
            if self.sitemap_video_tags:
                media.append(f"{self.sitemap_video_tags} video tag(s)")
            cat.add("Image/video tags in sitemap", "pass", ", ".join(media))
        elif entries:
            cat.add("Image/video tags in sitemap", "warn", "No image:/video: extension tags found")
        else:
            cat.add("Image/video tags in sitemap", "fail", "No sitemap URLs to inspect")
        if self.sitemap_hreflang_count:
            cat.add("hreflang alternates in sitemap", "pass",
                    f"{self.sitemap_hreflang_count} xhtml:link hreflang alternate(s)")
        elif entries:
            cat.add("hreflang alternates in sitemap", "warn", "No hreflang alternates declared in sitemap")
        else:
            cat.add("hreflang alternates in sitemap", "fail", "No sitemap URLs to inspect")
        return cat.finalize()

    def check_sitemap_validity(self):
        cat = CategoryResult("validity", "Sitemap Validity", 10)
        if self.sitemap_root is None:
            cat.add("XML validity", "fail", "No sitemap XML document retrieved")
            cat.add("Schema validation (sitemaps.org)", "fail", "No document to validate against sitemaps.org schema")
            cat.add("News sitemap namespace", "fail", "No sitemap document to inspect for news namespace")
            cat.add("URL encoding", "fail", "No sitemap URLs available")
            cat.add("Duplicate URL detection", "fail", "No sitemap URLs available")
            return cat.finalize()
        try:
            ET.fromstring(ET.tostring(self.sitemap_root))
            xml_ok = True
            xml_detail = "Document parses as well-formed XML"
        except ET.ParseError as exc:
            xml_ok = False
            xml_detail = f"XML parse error: {exc}"
        cat.add("XML validity", "pass" if xml_ok else "fail", xml_detail)
        root_tag = local_tag(self.sitemap_root.tag).lower()
        has_ns = SITEMAP_NS in (self.sitemap_root.tag if isinstance(self.sitemap_root.tag, str) else "")
        if root_tag in ("urlset", "sitemapindex") and has_ns:
            cat.add("Schema validation (sitemaps.org)", "pass", f"Root <{root_tag}> with sitemaps.org 0.9 namespace")
        elif root_tag in ("urlset", "sitemapindex"):
            cat.add("Schema validation (sitemaps.org)", "warn", f"Root <{root_tag}> missing sitemaps.org namespace")
        else:
            cat.add("Schema validation (sitemaps.org)", "fail", f"Unexpected root element <{root_tag or 'unknown'}>")
        if self.sitemap_has_news:
            cat.add("News sitemap namespace", "pass", "news: namespace detected in sitemap")
        elif root_tag in ("urlset", "sitemapindex"):
            cat.add("News sitemap namespace", "warn", "No news: namespace found (optional Google News sitemap)")
        else:
            cat.add("News sitemap namespace", "fail", "No sitemap document to inspect for news namespace")
        locs = [e.get("loc") or "" for e in self.sitemap_entries]
        if self.sitemap_is_index:
            locs = locs + list(self.child_sitemap_urls)
        bad_encoding = []
        for loc in locs:
            if " " in loc or re.search(r"[^\x21-\x7e]", loc):
                bad_encoding.append(loc)
            elif re.search(r"%[0-9A-Fa-f]{2}", loc):
                continue
        if not locs:
            cat.add("URL encoding", "fail", "No loc values to check")
        elif not bad_encoding:
            cat.add("URL encoding", "pass", f"All {len(locs)} loc values cleanly encoded")
        elif len(bad_encoding) <= max(1, len(locs) // 10):
            cat.add("URL encoding", "warn", f"{len(bad_encoding)} loc value(s) contain spaces/non-ASCII")
        else:
            cat.add("URL encoding", "fail", f"{len(bad_encoding)}/{len(locs)} loc values have encoding issues")
        seen = {}
        duplicates = 0
        for loc in locs:
            key = loc.rstrip("/")
            if key in seen:
                duplicates += 1
            seen[key] = True
        if not locs:
            cat.add("Duplicate URL detection", "fail", "No URLs to check for duplicates")
        elif duplicates == 0:
            cat.add("Duplicate URL detection", "pass", f"No duplicate URLs among {len(locs)} entries")
        else:
            cat.add("Duplicate URL detection", "fail", f"{duplicates} duplicate URL(s) detected")
        return cat.finalize()

    def meta_allows_index(self):
        content = (self.meta_robots or "").lower()
        if "noindex" in content:
            return False
        return True

    def x_robots_allows_index(self):
        content = (self.x_robots or "").lower()
        if "noindex" in content:
            return False
        return True

    def check_crawlability(self):
        cat = CategoryResult("crawl", "Crawlability", 10)
        if not self.page_ok():
            reason = "Target page could not be fetched"
            if self.page_resp is not None:
                reason = f"HTTP {self.page_resp.status_code} on target page"
            cat.add("Meta robots directives", "fail", reason)
            cat.add("X-Robots-Tag header", "fail", reason)
            cat.add("Canonical URL analysis", "fail", reason)
            cat.add("Pagination handling", "fail", reason)
            return cat.finalize()
        content = (self.meta_robots or "").lower()
        if not content:
            cat.add("Meta robots directives", "pass", "No meta robots tag; default index,follow applies")
        elif "noindex" in content:
            cat.add("Meta robots directives", "fail", f"Meta robots blocks indexing: {self.meta_robots}")
        elif "nofollow" in content:
            cat.add("Meta robots directives", "warn", f"Meta robots includes nofollow: {self.meta_robots}")
        else:
            cat.add("Meta robots directives", "pass", f"Meta robots permissive: {self.meta_robots}")
        x_content = (self.x_robots or "").lower()
        if not x_content:
            cat.add("X-Robots-Tag header", "pass", "No X-Robots-Tag header (nothing restricted)")
        elif "noindex" in x_content:
            cat.add("X-Robots-Tag header", "fail", f"X-Robots-Tag blocks indexing: {self.x_robots}")
        else:
            cat.add("X-Robots-Tag header", "pass", f"X-Robots-Tag present: {self.x_robots}")
        if self.canonical:
            target = self.normalize_for_compare(self.canonical)
            current = self.normalize_for_compare(self.url)
            if target == current:
                cat.add("Canonical URL analysis", "pass", f"Self-referencing canonical: {self.canonical}")
            elif urlparse(self.canonical).netloc == self.netloc:
                cat.add("Canonical URL analysis", "warn", f"Canonical points elsewhere on domain: {self.canonical}")
            else:
                cat.add("Canonical URL analysis", "fail", f"Cross-domain canonical: {self.canonical}")
        else:
            cat.add("Canonical URL analysis", "warn", "No canonical link element declared")
        pagin_signals = self.pagination_signals()
        rel_next = self.find_rel_links("next")
        rel_prev = self.find_rel_links("prev")
        if pagin_signals:
            if rel_next or rel_prev:
                cat.add("Pagination handling", "pass", f"Crawlable pagination with rel next/prev ({len(rel_next)} next, {len(rel_prev)} prev)")
            else:
                cat.add("Pagination handling", "warn", "Pagination signals present without rel next/prev")
        else:
            cat.add("Pagination handling", "pass", "No pagination on this page; nothing to hinder crawling")
        return cat.finalize()

    def normalize_for_compare(self, url):
        parsed = urlparse(url)
        path = parsed.path or "/"
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        query = parsed.query
        cleaned = []
        for pair in query.split("&"):
            if not pair:
                continue
            key = pair.split("=", 1)[0].lower()
            if key.startswith("utm_") or key in ("gclid", "fbclid", "ref"):
                continue
            cleaned.append(pair)
        query = "&".join(cleaned)
        return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", query, ""))

    def find_rel_links(self, rel_name):
        if not self.soup:
            return []
        found = []
        for tag in self.soup.find_all("link"):
            rels = tag.get("rel") or []
            if isinstance(rels, str):
                rels = [rels]
            if any(str(r).lower() == rel_name for r in rels):
                found.append(tag)
        return found

    def pagination_signals(self):
        signals = 0
        if re.search(r"[?&]page=\d+|/page/\d+", self.url, re.I):
            signals += 1
        if self.page_html and re.search(r"[?&]page=\d+|/page/\d+", self.page_html, re.I):
            signals += 1
        if self.soup:
            pagers = self.soup.select(".pagination, ul.pagination, nav.pagination, .page-numbers, .pager, ul.pages")
            if pagers:
                signals += 1
            for tag in self.soup.find_all(attrs={"aria-label": True}):
                if "pagination" in str(tag.get("aria-label", "")).lower():
                    signals += 1
                    break
            rel_next = self.find_rel_links("next")
            rel_prev = self.find_rel_links("prev")
            if rel_next or rel_prev:
                signals += 1
        return signals

    def check_indexability(self):
        cat = CategoryResult("index", "Indexability", 10)
        if not self.page_ok():
            reason = "Target page unavailable for indexability checks"
            if self.page_resp is not None:
                reason = f"HTTP {self.page_resp.status_code}; page not indexable"
            cat.add("Page indexability", "fail", reason)
            cat.add("Noindex detection", "fail", reason)
            cat.add("Canonical consistency", "fail", reason)
            cat.add("Duplicate content hints", "fail", reason)
            return cat.finalize()
        indexable = self.meta_allows_index() and self.x_robots_allows_index()
        cat.add("Page indexability", "pass" if indexable else "fail",
                "Page is indexable (200, no noindex signals)" if indexable else "Page blocked from index by robots signals")
        noindex = (not self.meta_allows_index()) or (not self.x_robots_allows_index())
        if noindex:
            source = []
            if not self.meta_allows_index():
                source.append("meta robots")
            if not self.x_robots_allows_index():
                source.append("X-Robots-Tag")
            cat.add("Noindex detection", "fail", f"noindex detected via {', '.join(source)}")
        else:
            cat.add("Noindex detection", "pass", "No noindex directives found")
        if self.canonical:
            same = self.normalize_for_compare(self.canonical) == self.normalize_for_compare(self.url)
            same_domain = urlparse(self.canonical).netloc == self.netloc
            if same:
                cat.add("Canonical consistency", "pass", "Canonical is consistent with the requested URL")
            elif same_domain:
                cat.add("Canonical consistency", "warn", f"Canonical mismatch on same domain: {self.canonical}")
            else:
                cat.add("Canonical consistency", "fail", f"Canonical consolidated to another host: {self.canonical}")
        else:
            cat.add("Canonical consistency", "warn", "No canonical declared; duplication risk if URL variants exist")
        text = ""
        if self.soup:
            text = self.soup.get_text(" ", strip=True)
        words = len(text.split()) if text else 0
        title = ""
        if self.soup and self.soup.title and self.soup.title.string:
            title = self.soup.title.string.strip()
        if words >= 200 and title:
            cat.add("Duplicate content hints", "pass", f"~{words} words with a title; low duplication risk")
        elif words >= 80:
            cat.add("Duplicate content hints", "warn", f"~{words} words; moderate thin-content/duplication risk")
        else:
            cat.add("Duplicate content hints", "fail", f"~{words} words; strong thin-content/duplicate hint")
        return cat.finalize()

    def check_internal_links(self):
        cat = CategoryResult("links", "Internal Linking", 10)
        if not self.page_ok() or self.soup is None:
            reason = "Target page unavailable for link analysis"
            cat.add("Internal link count", "fail", reason)
            cat.add("Orphan page detection hints", "fail", reason)
            cat.add("Link depth analysis", "fail", reason)
            cat.add("Navigation structure", "fail", reason)
            return cat.finalize()
        count = len(self.internal_links)
        unique = len(set(self.normalize_for_compare(u) for u in self.internal_links))
        if count >= 15:
            cat.add("Internal link count", "pass", f"{count} internal links ({unique} unique)")
        elif count >= 5:
            cat.add("Internal link count", "warn", f"Only {count} internal links ({unique} unique)")
        else:
            cat.add("Internal link count", "fail", f"Only {count} internal links ({unique} unique)")
        nav_present = self.has_navigation()
        in_sitemap = False
        if self.sitemap_entries:
            current = self.normalize_for_compare(self.url)
            in_sitemap = any(self.normalize_for_compare(e.get("loc") or "") == current for e in self.sitemap_entries)
        if count == 0:
            cat.add("Orphan page detection hints", "fail", "Zero internal links on page; orphan risk is high")
        elif nav_present and (in_sitemap or not self.sitemap_entries):
            cat.add("Orphan page detection hints", "pass", "Navigation present; page reachable via site chrome")
        elif nav_present:
            cat.add("Orphan page detection hints", "pass", "Navigation links present on the page")
        else:
            cat.add("Orphan page detection hints", "warn", "No nav/footer links detected; possible orphan signals")
        depth = len([p for p in urlparse(self.url).path.split("/") if p]) + 1
        breadcrumbs = self.soup.select("[aria-label*='breadcrumb' i], nav.breadcrumb, .breadcrumb, ol.breadcrumb")
        if depth <= 3:
            cat.add("Link depth analysis", "pass", f"URL depth {depth} (<=3 hops from root)" + (f"; breadcrumb trail found" if breadcrumbs else ""))
        elif depth <= 5:
            cat.add("Link depth analysis", "warn", f"URL depth {depth}; moderately deep")
        else:
            cat.add("Link depth analysis", "fail", f"URL depth {depth}; deeper than 5 hops")
        if nav_present:
            cat.add("Navigation structure", "pass", "Header/footer navigation structure detected")
        else:
            cat.add("Navigation structure", "warn", "No clear navigation landmarks found")
        return cat.finalize()

    def has_navigation(self):
        if not self.soup:
            return False
        if self.soup.find("nav"):
            return True
        if self.soup.find("header") and self.soup.header.find("a", href=True):
            return True
        if self.soup.select("ul.nav, #nav, #navigation, .navbar, .menu, .main-menu, .site-navigation"):
            return True
        return False

    def check_url_structure(self):
        cat = CategoryResult("url", "URL Structure", 5)
        parsed = urlparse(self.url)
        length = len(self.url)
        if length <= 100:
            cat.add("URL length analysis", "pass", f"URL length {length} chars (<=100)")
        elif length <= 200:
            cat.add("URL length analysis", "warn", f"URL length {length} chars (101-200)")
        else:
            cat.add("URL length analysis", "fail", f"URL length {length} chars (>200)")
        params = [p for p in parsed.query.split("&") if p]
        path_segs = [s for s in parsed.path.split("/") if s]
        if len(params) == 0:
            cat.add("URL structure (folders vs parameters)", "pass", f"Clean path with {len(path_segs)} folder segment(s), no query parameters")
        elif len(params) <= 2:
            cat.add("URL structure (folders vs parameters)", "warn", f"{len(params)} query parameter(s) with {len(path_segs)} folder segment(s)")
        else:
            cat.add("URL structure (folders vs parameters)", "fail", f"{len(params)} query parameters; overly complex URL")
        if parsed.scheme == "https":
            cat.add("HTTPS usage", "pass", "URL served over HTTPS scheme")
        else:
            cat.add("HTTPS usage", "fail", "URL not using HTTPS")
        slash_issues = 0
        if self.internal_links:
            current_path = parsed.path
            if current_path and not current_path.endswith("/"):
                alt = current_path + "/"
            elif current_path != "/":
                alt = current_path.rstrip("/")
            else:
                alt = None
            if alt:
                for link in set(self.internal_links):
                    lp = urlparse(link).path
                    if lp == alt:
                        slash_issues += 1
        if slash_issues:
            cat.add("Trailing slash consistency", "warn", f"Found {slash_issues} internal link(s) differing only by trailing slash")
        else:
            cat.add("Trailing slash consistency", "pass", "No trailing-slash conflicts detected among internal links")
        return cat.finalize()

    def infinite_scroll_signals(self):
        if not self.page_html:
            return []
        patterns = [
            (r"IntersectionObserver", "IntersectionObserver usage"),
            (r"window\.addEventListener\(\s*['\"]scroll", "scroll event listener"),
            (r"onscroll\s*=", "inline onscroll handler"),
            (r"load[- ]?more", "load-more control"),
            (r"infinite[-_ ]?scroll", "infinite-scroll library/markup"),
            (r"ajax\.scroll|endless", "endless scroll helper"),
        ]
        hits = []
        for pattern, label in patterns:
            if re.search(pattern, self.page_html, re.I):
                hits.append(label)
        return hits

    def check_pagination(self):
        cat = CategoryResult("pagination", "Pagination", 5)
        if not self.page_ok() or self.soup is None:
            reason = "Target page unavailable for pagination checks"
            cat.add('rel="next"/"prev" detection', "fail", reason)
            cat.add("Pagination patterns", "fail", reason)
            cat.add("Infinite scroll detection", "fail", reason)
            return cat.finalize()
        rel_next = self.find_rel_links("next")
        rel_prev = self.find_rel_links("prev")
        pagin = self.pagination_signals()
        if rel_next and rel_prev:
            cat.add('rel="next"/"prev" detection', "pass", "Both rel=next and rel=prev present")
        elif rel_next or rel_prev:
            cat.add('rel="next"/"prev" detection', "warn", "Partial rel next/prev annotations found")
        elif pagin:
            cat.add('rel="next"/"prev" detection', "warn", "Pagination present without rel next/prev links")
        else:
            cat.add('rel="next"/"prev" detection', "pass", "No pagination; rel next/prev not required")
        if pagin:
            param_page = bool(re.search(r"[?&]page=\d+|/page/\d+", self.url, re.I) or (self.page_html and re.search(r"[?&]page=\d+|/page/\d+", self.page_html, re.I)))
            pager_ui = bool(self.soup.select(".pagination, ul.pagination, nav.pagination, .page-numbers, .pager"))
            if pager_ui and not param_page:
                cat.add("Pagination patterns", "pass", "Structured pagination controls detected")
            elif pager_ui:
                cat.add("Pagination patterns", "pass", "Pagination UI with parameterized page URLs")
            elif param_page:
                cat.add("Pagination patterns", "warn", "Parameterized pagination without clear pager markup")
            else:
                cat.add("Pagination patterns", "warn", "Ambiguous pagination signals detected")
        else:
            cat.add("Pagination patterns", "pass", "Single-page content; no pagination pattern needed")
        infinite = self.infinite_scroll_signals()
        if infinite:
            if pagin and (rel_next or rel_prev):
                cat.add("Infinite scroll detection", "warn", f"Infinite-scroll hints with crawlable pagination: {', '.join(infinite[:3])}")
            elif pagin:
                cat.add("Infinite scroll detection", "warn", f"Infinite-scroll hints alongside weak pagination: {', '.join(infinite[:3])}")
            else:
                cat.add("Infinite scroll detection", "fail", f"Infinite scroll without crawlable pagination: {', '.join(infinite[:3])}")
        else:
            cat.add("Infinite scroll detection", "pass", "No infinite-scroll patterns detected")
        return cat.finalize()

    def hreflang_links(self):
        if not self.soup:
            return []
        found = []
        for tag in self.soup.find_all("link"):
            rels = tag.get("rel") or []
            if isinstance(rels, str):
                rels = [rels]
            if any(str(r).lower() == "alternate" for r in rels) and tag.get("hreflang"):
                found.append(tag)
        return found

    def check_international(self):
        cat = CategoryResult("intl", "International", 5)
        if not self.page_ok() or self.soup is None:
            reason = "Target page unavailable for international checks"
            cat.add("hreflang annotations", "fail", reason)
            cat.add("Language alternates", "fail", reason)
            cat.add("Regional targeting", "fail", reason)
            return cat.finalize()
        tags = self.hreflang_links()
        if tags:
            langs = [str(t.get("hreflang")) for t in tags]
            cat.add("hreflang annotations", "pass", f"{len(tags)} hreflang alternate(s): {', '.join(langs[:8])}")
        else:
            cat.add("hreflang annotations", "warn", "No hreflang alternate annotations found")
        html_tag = self.soup.find("html")
        lang_attr = ""
        if html_tag and html_tag.get("lang"):
            lang_attr = str(html_tag.get("lang")).strip()
        if lang_attr and tags:
            cat.add("Language alternates", "pass", f"html lang='{lang_attr}' with {len(tags)} language alternate(s)")
        elif lang_attr:
            cat.add("Language alternates", "warn", f"html lang='{lang_attr}' but no alternate link annotations")
        elif tags:
            cat.add("Language alternates", "warn", f"{len(tags)} alternate link(s) but missing html lang attribute")
        else:
            cat.add("Language alternates", "fail", "No html lang attribute and no language alternates")
        langs = [str(t.get("hreflang", "")).lower() for t in tags]
        has_x_default = any(l == "x-default" for l in langs)
        has_regional = any("-" in l and l != "x-default" for l in langs)
        if has_x_default and has_regional:
            cat.add("Regional targeting", "pass", "x-default plus region-specific hreflang targets present")
        elif has_x_default:
            cat.add("Regional targeting", "warn", "x-default present without region-specific variants")
        elif has_regional:
            cat.add("Regional targeting", "warn", "Region-specific hreflang present without x-default")
        elif tags:
            cat.add("Regional targeting", "warn", "hreflang entries lack regional targeting variants")
        else:
            cat.add("Regional targeting", "warn", "No regional hreflang targeting detected")
        return cat.finalize()

    def run(self):
        self.started_at = datetime.now()
        start = time.time()
        print_banner()
        print(paint("  [*] Target:", C_CYAN), paint(self.url, C_WHITE))
        print(paint("  [*] Started:", C_CYAN), paint(self.started_at.strftime("%Y-%m-%d %H:%M:%S"), C_WHITE))
        print()
        print(paint("  [1/4] Fetching robots.txt...", C_YELLOW))
        self.fetch_robots()
        print(paint("  [2/4] Detecting and parsing sitemaps...", C_YELLOW))
        self.fetch_sitemap()
        print(paint("  [3/4] Fetching target page...", C_YELLOW))
        self.fetch_page()
        print(paint("  [4/4] Running 10 analysis categories...", C_YELLOW))
        print()
        self.results = [
            self.check_robots(),
            self.check_sitemap_detection(),
            self.check_sitemap_content(),
            self.check_sitemap_validity(),
            self.check_crawlability(),
            self.check_indexability(),
            self.check_internal_links(),
            self.check_url_structure(),
            self.check_pagination(),
            self.check_international(),
        ]
        self.total_score = round(sum(c.score for c in self.results), 1)
        self.grade = grade_for(self.total_score)
        self.elapsed = round(time.time() - start, 2)
        return self

    def category(self, key):
        for cat in self.results:
            if cat.key == key:
                return cat
        return None

    def target_info(self):
        status = "unreachable"
        title = ""
        server = ""
        final_url = self.url
        load_time = self.elapsed
        if self.page_resp is not None:
            status = str(self.page_resp.status_code)
            final_url = str(self.page_resp.url)
            server = str(self.page_resp.headers.get("Server") or "n/a")
        if self.soup and self.soup.title and self.soup.title.string:
            title = self.soup.title.string.strip()
        return {
            "status": status,
            "title": title,
            "server": server,
            "final_url": final_url,
            "load_time": load_time,
        }

    def print_breakdown(self):
        print(paint("  +--------------------------------------------------------------+", C_CYAN))
        print(paint("  |  ", C_CYAN) + paint("CATEGORY BREAKDOWN".ljust(58), C_WHITE) + paint("|", C_CYAN))
        print(paint("  +--------------------------------------------------------------+", C_CYAN))
        for cat in self.results:
            gcolor = C_GREEN if cat.pct >= 75 else C_YELLOW if cat.pct >= 50 else C_RED
            bar = self.make_bar(cat.pct, 14, gcolor)
            score_txt = f"{cat.score:g}/{cat.max_points:g}"
            pct_txt = f"{cat.pct:.0f}%"
            print(
                f"    {paint(cat.title, C_WHITE):<45.45s} {score_txt:>9}  {bar}  {paint(pct_txt, gcolor):<14.14s}"
            )
        gcolor = grade_color(self.grade)
        print(paint("  +--------------------------------------------------------------+", C_CYAN))
        total_txt = f"{self.total_score:g}/100"
        print(
            f"    {paint('TOTAL', C_BOLD):<45.45s} {paint(total_txt, gcolor):>9}  "
            f"{self.make_bar(self.total_score, 14, gcolor)}  {paint('Grade: ' + self.grade, gcolor + C_BOLD)}"
        )
        print(paint("  +--------------------------------------------------------------+", C_CYAN))
        print()

    def make_bar(self, pct, width, color):
        filled = int(round(pct / 100 * width))
        filled = max(0, min(width, filled))
        bar = "#" * filled + "-" * (width - filled)
        return paint(f"[{bar}]", color)

    def print_checks(self, keys, title, header_color=C_CYAN):
        print(paint(f"  +--------------------------------------------------------------+", header_color))
        print(paint("  |  ", header_color) + paint(title.ljust(58), C_WHITE) + paint("|", header_color))
        print(paint("  +--------------------------------------------------------------+", header_color))
        for key in keys:
            cat = self.category(key)
            if not cat:
                continue
            print(paint(f"    [{cat.title}]", C_BOLD) + paint(f"  {cat.score:g}/{cat.max_points:g}", C_GRAY))
            for item in cat.checks:
                sc = status_color(item["status"])
                label = paint(status_label(item["status"]), sc)
                points = f"({item['points']:g}/{item['max']:g})"
                detail = item["detail"]
                if not self.verbose and len(detail) > 72:
                    detail = detail[:69] + "..."
                print(f"      {label}  {item['check']:<40.40s} {paint(points, C_GRAY):<14.14s} {paint(detail, C_GRAY)}")
            print()

    def print_crawlability_report(self):
        info = self.target_info()
        print(paint("  +--------------------------------------------------------------+", C_BLUE))
        print(paint("  |  ", C_BLUE) + paint("CRAWLABILITY REPORT".ljust(58), C_WHITE) + paint("|", C_BLUE))
        print(paint("  +--------------------------------------------------------------+", C_BLUE))
        print(f"    {'HTTP Status:':<22} {info['status']}")
        print(f"    {'Final URL:':<22} {info['final_url']}")
        print(f"    {'Meta Robots:':<22} {self.meta_robots or 'none (index,follow default)'}")
        print(f"    {'X-Robots-Tag:':<22} {self.x_robots or 'none'}")
        print(f"    {'Canonical:':<22} {self.canonical or 'none'}")
        robots_ok = self.meta_allows_index() and self.x_robots_allows_index() and self.page_ok()
        verdict = paint("CRAWLABLE", C_GREEN) if robots_ok else paint("RESTRICTED / NOT CRAWLABLE", C_RED)
        print(f"    {'Crawl Verdict:':<22} {verdict}")
        print()
        self.print_checks(["crawl"], "CRAWLABILITY CHECK DETAILS", C_BLUE)

    def print_sitemap_analysis(self):
        print(paint("  +--------------------------------------------------------------+", C_GREEN))
        print(paint("  |  ", C_GREEN) + paint("SITEMAP ANALYSIS".ljust(58), C_WHITE) + paint("|", C_GREEN))
        print(paint("  +--------------------------------------------------------------+", C_GREEN))
        print(f"    {'robots.txt:':<22} {self.robots_url} (HTTP {self.robots_status})")
        print(f"    {'Sitemap URL:':<22} {self.sitemap_url or 'not found'}")
        kind = "sitemap index" if self.sitemap_is_index else ("urlset" if self.sitemap_root is not None else "n/a")
        print(f"    {'Sitemap Type:':<22} {kind}")
        print(f"    {'Sitemap Size:':<22} {self.sitemap_bytes / 1024.0:.1f} KB" if self.sitemap_bytes else f"    {'Sitemap Size:':<22} n/a")
        print(f"    {'Child Sitemaps:':<22} {self.child_sitemap_count}")
        print(f"    {'URL Entries:':<22} {len(self.sitemap_entries)}")
        print(f"    {'Sitemaps in robots:':<22} {len(self.robots_sitemaps)}")
        print()
        self.print_checks(["sitemap", "content", "validity"], "SITEMAP CHECK DETAILS", C_GREEN)

    def print_indexability_assessment(self):
        info = self.target_info()
        indexable = self.page_ok() and self.meta_allows_index() and self.x_robots_allows_index()
        print(paint("  +--------------------------------------------------------------+", C_MAGENTA))
        print(paint("  |  ", C_MAGENTA) + paint("INDEXABILITY ASSESSMENT".ljust(58), C_WHITE) + paint("|", C_MAGENTA))
        print(paint("  +--------------------------------------------------------------+", C_MAGENTA))
        print(f"    {'Page Title:':<22} {(info['title'] or 'n/a')[:70]}")
        print(f"    {'Status Code:':<22} {info['status']}")
        print(f"    {'Noindex:':<22} {'yes' if not (self.meta_allows_index() and self.x_robots_allows_index()) else 'no'}")
        print(f"    {'Canonical Set:':<22} {'yes' if self.canonical else 'no'}")
        verdict = paint("INDEXABLE", C_GREEN) if indexable else paint("NOT INDEXABLE", C_RED)
        print(f"    {'Index Verdict:':<22} {verdict}")
        print()
        self.print_checks(["index"], "INDEXABILITY CHECK DETAILS", C_MAGENTA)

    def print_summary(self):
        gcolor = grade_color(self.grade)
        print(paint("  +==============================================================+", gcolor))
        total_txt = f"{self.total_score:g} / 100"
        grade_line = f"SCORE: {total_txt}    GRADE: {self.grade}"
        print(paint("  |  ", gcolor) + paint(grade_line.center(58), gcolor + C_BOLD) + paint("|", gcolor))
        passed = sum(1 for c in self.results for i in c.checks if i["status"] == "pass")
        warned = sum(1 for c in self.results for i in c.checks if i["status"] == "warn")
        failed = sum(1 for c in self.results for i in c.checks if i["status"] == "fail")
        stats = f"PASS {passed}   WARN {warned}   FAIL {failed}   TIME {self.elapsed}s"
        print(paint("  |  ", gcolor) + paint(stats.center(58), C_WHITE) + paint("|", gcolor))
        print(paint("  +==============================================================+", gcolor))
        print()
        print(paint(f"  Grades: ", C_GRAY) + paint("A+ 95-100  A 90-94  B 75-89  C 60-74  D 40-59  F 0-39", C_GRAY))
        print()

    def display(self):
        self.print_breakdown()
        self.print_crawlability_report()
        self.print_sitemap_analysis()
        self.print_indexability_assessment()
        self.print_checks(["links", "url", "pagination", "intl"], "STRUCTURE & DISCOVERY DETAILS", C_YELLOW)
        self.print_summary()

    def to_payload(self):
        info = self.target_info()
        return {
            "tool": "SitemapAnalyzer",
            "version": VERSION,
            "url": self.url,
            "analyzed_at": self.started_at.strftime("%Y-%m-%d %H:%M:%S") if self.started_at else "",
            "elapsed_seconds": self.elapsed,
            "score": self.total_score,
            "max_score": 100,
            "grade": self.grade,
            "target": info,
            "robots": {
                "url": self.robots_url,
                "status": self.robots_status,
                "sitemaps": self.robots_sitemaps,
                "rule_count": len(self.robots_rules),
            },
            "sitemap": {
                "url": self.sitemap_url,
                "status": self.sitemap_status,
                "is_index": self.sitemap_is_index,
                "bytes": self.sitemap_bytes,
                "child_count": self.child_sitemap_count,
                "children": self.child_sitemap_urls,
                "entry_count": len(self.sitemap_entries),
                "entries": self.sitemap_entries[:500],
                "has_news_namespace": self.sitemap_has_news,
                "image_tag_count": self.sitemap_image_tags,
                "video_tag_count": self.sitemap_video_tags,
                "hreflang_count": self.sitemap_hreflang_count,
            },
            "page": {
                "meta_robots": self.meta_robots,
                "x_robots_tag": self.x_robots,
                "canonical": self.canonical,
                "internal_link_count": len(self.internal_links),
                "external_link_count": self.external_links,
            },
            "categories": [c.to_dict() for c in self.results],
        }

    def export_json(self, path):
        payload = self.to_payload()
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        print(f"    {paint('[+] JSON report saved:', C_GREEN)} {path}")

    def export_csv(self, path):
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["Category", "CategoryKey", "Check", "Status", "Points", "MaxPoints", "Detail"])
            for cat in self.results:
                for item in cat.checks:
                    writer.writerow([cat.title, cat.key, item["check"], item["status"], item["points"], item["max"], item["detail"]])
            writer.writerow([])
            for cat in self.results:
                writer.writerow([cat.title, cat.key, "CATEGORY TOTAL", "", cat.score, cat.max_points, f"{cat.pct}%"])
            writer.writerow(["TOTAL", "", "FINAL SCORE", self.grade, self.total_score, 100, self.grade])
        print(f"    {paint('[+] CSV report saved:', C_GREEN)} {path}")

    def export_html(self, path):
        payload = self.to_payload()
        info = payload["target"]
        pct = payload["score"]
        grade = payload["grade"]
        ring_color = "#3fb950" if pct >= 75 else "#d29922" if pct >= 50 else "#f85149"
        categories_html = ""
        for cat in payload["categories"]:
            cat_pct = cat["pct"]
            cat_color = "#3fb950" if cat_pct >= 75 else "#d29922" if cat_pct >= 50 else "#f85149"
            rows = ""
            for item in cat["checks"]:
                color = "#3fb950" if item["status"] == "pass" else "#d29922" if item["status"] == "warn" else "#f85149"
                label = item["status"].upper()
                detail = item["detail"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                name = item["check"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                rows += f'<tr><td style="color:{color};font-weight:700">{label}</td><td>{name}</td><td>{item["points"]}/{item["max"]}</td><td>{detail}</td></tr>\n'
            categories_html += f'''<details style="margin:10px 0" open>
<summary style="cursor:pointer;padding:12px 16px;background:#161b22;border:1px solid #30363d;border-radius:6px;font-size:1.02em">
<span style="color:{cat_color};font-weight:700">{cat["title"]}</span>
<span style="float:right;color:#8b949e">{cat["score"]}/{cat["max"]} ({cat_pct:.0f}%)</span>
</summary>
<div style="padding:0 16px 16px;background:#0d1117;border:1px solid #30363d;border-top:0;border-radius:0 0 6px 6px">
<table style="width:100%;border-collapse:collapse;margin-top:8px">
<tr style="border-bottom:1px solid #30363d"><th style="color:#8b949e;text-align:left;padding:6px 8px">Status</th><th style="color:#8b949e;text-align:left;padding:6px 8px">Check</th><th style="color:#8b949e;text-align:left;padding:6px 8px">Score</th><th style="color:#8b949e;text-align:left;padding:6px 8px">Detail</th></tr>
{rows}</table>
<div style="margin-top:10px;background:#21262d;border-radius:4px;height:10px"><div style="width:{cat_pct:.0f}%;background:{cat_color};height:10px;border-radius:4px"></div></div>
</div>
</details>\n'''
        robots = payload["robots"]
        sitemap = payload["sitemap"]
        page = payload["page"]
        robots_rows = "".join(
            f"<tr><td>{s}</td></tr>" for s in robots.get("sitemaps", [])
        ) or '<tr><td style="color:#8b949e">None</td></tr>'
        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SitemapAnalyzer Report - {payload["url"]}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 30px; line-height: 1.5; }}
h1 {{ color: #3fb950; border-bottom: 2px solid #30363d; padding-bottom: 10px; font-size: 1.5em; }}
h2 {{ color: #58a6ff; font-size: 1.15em; margin: 0 0 10px; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin: 15px 0; }}
.stat {{ display: inline-block; text-align: center; padding: 12px 20px; margin: 4px; background: #0d1117; border-radius: 6px; border: 1px solid #30363d; min-width: 90px; }}
.stat .val {{ font-size: 1.8em; font-weight: 700; color: #58a6ff; }}
.stat .lbl {{ font-size: 0.82em; color: #8b949e; margin-top: 2px; }}
.score-ring {{ width: 130px; height: 130px; border-radius: 50%; border: 8px solid {ring_color}; display: flex; align-items: center; justify-content: center; font-size: 2.2em; font-weight: 700; margin: 0 auto 12px; color: {ring_color}; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 7px 10px; text-align: left; border-bottom: 1px solid #30363d; font-size: 0.92em; }}
th {{ color: #8b949e; font-weight: 600; }}
.mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.88em; color: #8b949e; word-break: break-all; }}
</style></head><body>
<h1>SitemapAnalyzer Report v{VERSION}</h1>
<div class="card">
<h2>Score Overview</h2>
<div style="text-align:center">
<div class="score-ring">{pct:.0f}%</div>
<p style="font-size:1.1em;font-weight:600">{payload["score"]}/100 points | Grade: {grade}</p>
<p class="mono">{payload["url"]}</p>
</div>
<div style="text-align:center;margin-top:12px">
<div class="stat"><div class="val">{info["status"]}</div><div class="lbl">HTTP</div></div>
<div class="stat"><div class="val">{sitemap["entry_count"]}</div><div class="lbl">Sitemap URLs</div></div>
<div class="stat"><div class="val">{page["internal_link_count"]}</div><div class="lbl">Internal Links</div></div>
<div class="stat"><div class="val">{payload["elapsed_seconds"]}s</div><div class="lbl">Duration</div></div>
</div>
</div>
<div class="card">
<h2>Target Information</h2>
<table>
<tr><th>URL</th><td class="mono">{payload["url"]}</td></tr>
<tr><th>Title</th><td>{info["title"] or "n/a"}</td></tr>
<tr><th>Status</th><td>{info["status"]}</td></tr>
<tr><th>Server</th><td>{info["server"] or "n/a"}</td></tr>
<tr><th>Meta Robots</th><td>{page["meta_robots"] or "none"}</td></tr>
<tr><th>X-Robots-Tag</th><td>{page["x_robots_tag"] or "none"}</td></tr>
<tr><th>Canonical</th><td class="mono">{page["canonical"] or "none"}</td></tr>
</table>
</div>
<div class="card">
<h2>robots.txt &amp; Sitemap</h2>
<table>
<tr><th>robots.txt</th><td class="mono">{robots["url"]} (HTTP {robots["status"]})</td></tr>
<tr><th>Sitemap URL</th><td class="mono">{sitemap["url"] or "not found"}</td></tr>
<tr><th>Type</th><td>{"sitemap index" if sitemap["is_index"] else "urlset" if sitemap["url"] else "n/a"}</td></tr>
<tr><th>Size</th><td>{sitemap["bytes"] / 1024.0:.1f} KB</td></tr>
<tr><th>Child Sitemaps</th><td>{sitemap["child_count"]}</td></tr>
<tr><th>URL Entries</th><td>{sitemap["entry_count"]}</td></tr>
</table>
<table style="margin-top:12px"><tr><th>Sitemaps referenced in robots.txt</th></tr>{robots_rows}</table>
</div>
<div class="card">
<h2>Category Breakdown</h2>
{categories_html}
</div>
<p style="color:#8b949e;text-align:center;font-size:0.85em">Generated by SitemapAnalyzer v{VERSION} | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
</body></html>"""
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"    {paint('[+] HTML report saved:', C_GREEN)} {path}")


def main():
    parser = argparse.ArgumentParser(
        prog="sitemapanalyzer",
        description=f"SitemapAnalyzer v{VERSION} - Sitemap and Crawlability Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python sitemapanalyzer.py -u https://example.com
  python sitemapanalyzer.py -u example.com -t 30 -v
  python sitemapanalyzer.py -u https://example.com --export all
  python sitemapanalyzer.py -u https://example.com --export json --no-color
""",
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout (default: 15)")
    parser.add_argument("--export", default="none", choices=["all", "json", "csv", "html", "none"],
                        help="Export format: all/json/csv/html/none (default: none)")
    parser.add_argument("--no-color", action="store_true", help="Disable colors")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        disable_colors()

    analyzer = SitemapAnalyzer(args.url, timeout=args.timeout, verbose=args.verbose)
    analyzer.run()
    analyzer.display()

    if args.export != "none":
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        print(paint("  [*] Exporting reports...", C_CYAN))
        if args.export in ("all", "json"):
            analyzer.export_json(f"sitemap_report_{ts}.json")
        if args.export in ("all", "csv"):
            analyzer.export_csv(f"sitemap_report_{ts}.csv")
        if args.export in ("all", "html"):
            analyzer.export_html(f"sitemap_report_{ts}.html")
        print()


if __name__ == "__main__":
    main()
