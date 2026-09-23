#!/usr/bin/env python3
import sys
import os
import re
import json
import csv
import io
import argparse
import colorsys
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin
from collections import OrderedDict

def _install(pkg, import_name=None):
    import subprocess
    import_name = import_name or pkg
    try:
        __import__(import_name)
        return True
    except ImportError:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
            __import__(import_name)
            return True
        except Exception:
            return False

_have_requests = _install("requests")
_have_bs4 = _install("beautifulsoup4", "bs4")

if _have_requests:
    import requests

if _have_bs4:
    from bs4 import BeautifulSoup, Comment
else:
    BeautifulSoup = None

USE_COLOR = True

class C:
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
    BRIGHT_RED = "\033[91;1m"
    BRIGHT_GREEN = "\033[92;1m"
    BRIGHT_YELLOW = "\033[93;1m"
    BRIGHT_BLUE = "\033[94;1m"
    BRIGHT_MAGENTA = "\033[95;1m"
    BRIGHT_CYAN = "\033[96;1m"
    BG_DARK = "\033[48;5;234m"
    UNDERLINE = "\033[4m"

def paint(text, *codes):
    if not USE_COLOR:
        return text
    return "".join(codes) + text + C.RESET

def gradient_text(text, start_hue=0.0, sat=0.85, val=1.0):
    if not USE_COLOR:
        return text
    out = []
    n = max(len(text) - 1, 1)
    for i, ch in enumerate(text):
        hue = (start_hue + (i / n) * 0.7) % 1.0
        r, g, b = colorsys.hsv_to_rgb(hue, sat, val)
        out.append(f"\033[38;2;{int(r*255)};{int(g*255)};{int(b*255)}m{ch}")
    return "".join(out) + C.RESET

BANNER_LINES = [
    " _   _ _   _ ____   _____                             _    _             ",
    "| | | | \\ | |  _ \\ / ____|                           | |  | |            ",
    "| |_| |  \\| | | | | (___  _   _ _ __ ___  _ __   ___ | |__| |_   _ _ __  ",
    "|  _  | |\\  | | | |\\___ \\| | | | '__/ _ \\| '_ \\ / _ \\|  __  | | | | '__| ",
    "| |_| | |\\  | |_| |____) | |_| | | | (_) | | | | (_) | |  | | |_| | |    ",
    "|\\___/|_| \\_|____/|_____/ \\__,_|_|  \\___/|_| |_|\\___/|_|  |_|\\__,_|_|    ",
    "                                                                         ",
]

CATEGORY_META = OrderedDict([
    ("structure", {"label": "DOCTYPE & Document Structure", "max": 15}),
    ("elements", {"label": "Element Validation", "max": 15}),
    ("attributes", {"label": "Attribute Validation", "max": 15}),
    ("semantic", {"label": "Semantic HTML", "max": 10}),
    ("a11y_markup", {"label": "Accessibility Markup", "max": 10}),
    ("seo_markup", {"label": "SEO Markup", "max": 10}),
    ("security_markup", {"label": "Security Markup", "max": 5}),
    ("encoding", {"label": "Encoding & Character Set", "max": 5}),
    ("links", {"label": "Links & References", "max": 10}),
    ("perf_markup", {"label": "Performance Markup", "max": 5}),
])

TOTAL_MAX = sum(v["max"] for v in CATEGORY_META.values())

VOID_ELEMENTS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
}

DEPRECATED_ELEMENTS = {
    "font", "center", "marquee", "blink", "big", "strike", "tt", "acronym",
    "applet", "basefont", "bgsound", "dir", "frame", "frameset", "noframes",
    "isindex", "listing", "menuitem", "multicol", "nextid", "nobr", "spacer",
    "shadow", "keygen",
}

DEPRECATED_ATTRS = {
    "align", "bgcolor", "background", "border", "color", "face",
    "valign", "hspace", "vspace", "clear", "language",
    "scrollamount", "scrolldelay", "truespeed", "span", "summary",
    "frameborder", "cellpadding", "cellspacing", "rules", "longdesc",
    "lowsrc", "archive", "codebase", "codetype", "declare", "prompt",
    "datasrc", "datafld", "dataformatas", "umbf", "logging", "char",
    "charoff", "axis", "nohref",
}

BOOLEAN_ATTRS = {
    "allowfullscreen", "async", "autofocus", "autoplay", "checked", "controls",
    "default", "defer", "disabled", "formnovalidate", "hidden", "inert",
    "ismap", "itemscope", "loop", "multiple", "muted", "nomodule", "novalidate",
    "open", "playsinline", "readonly", "required", "reversed", "selected",
}

ARIA_ATTR_RE = re.compile(r"^aria-[a-z][a-z0-9-]*$")
ARIA_ROLES = {
    "alert", "alertdialog", "application", "article", "banner", "button",
    "cell", "checkbox", "columnheader", "combobox", "complementary",
    "contentinfo", "definition", "dialog", "directory", "document", "feed",
    "figure", "form", "grid", "gridcell", "group", "heading", "img",
    "link", "list", "listbox", "listitem", "log", "main", "marquee", "math",
    "menu", "menubar", "menuitem", "menuitemcheckbox", "menuitemradio",
    "navigation", "none", "note", "option", "presentation", "progressbar",
    "radio", "radiogroup", "region", "row", "rowgroup", "rowheader",
    "scrollbar", "search", "searchbox", "separator", "slider", "spinbutton",
    "status", "switch", "tab", "table", "tablist", "tabpanel", "term",
    "textbox", "timer", "toolbar", "tooltip", "tree", "treegrid", "treeitem",
}

SEMANTIC_ELEMENTS = {
    "header", "nav", "main", "article", "section", "footer", "aside",
    "figure", "figcaption", "details", "summary", "mark", "time", "data",
    "address", "blockquote", "cite", "q", "abbr", "dfn", "kbd", "samp",
    "var", "progress", "meter", "template", "picture", "video", "audio",
}

LANDMARK_ROLES = {"banner", "navigation", "main", "complementary", "contentinfo", "search", "form", "region"}

OG_PREFIX = "og:"
DATA_DATA_URI = re.compile(r"^data:", re.I)
MAX_ENTITY_SAMPLE = 50000


class StructureParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.has_doctype = False
        self.doctype_text = None
        self.html_attrs = {}
        self.in_head = False
        self.in_body = False
        self.has_head = False
        self.has_body = False
        self.charset_meta = None
        self.viewport_meta = None
        self.title_text = None
        self.in_title = False
        self.meta_tags = []
        self.tags_seen = []
        self.first_non_comment = None

    def handle_decl(self, decl):
        self.has_doctype = True
        self.doctype_text = decl

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if self.first_non_comment is None:
            self.first_non_comment = tag
        if tag == "html" and not self.html_attrs:
            self.html_attrs = d
        elif tag == "head":
            self.has_head = True
            self.in_head = True
        elif tag == "body":
            self.has_body = True
            self.in_body = True
        elif tag == "meta":
            self.meta_tags.append(d)
            cs = d.get("charset")
            if cs:
                self.charset_meta = cs
            if d.get("http-equiv", "").lower() == "content-type":
                content = d.get("content", "")
                m = re.search(r"charset=([\w-]+)", content, re.I)
                if m:
                    self.charset_meta = m.group(1)
            if d.get("name", "").lower() == "viewport":
                self.viewport_meta = d.get("content", "")
        elif tag == "title":
            self.in_title = True
            self.title_text = ""
        self.tags_seen.append(tag)

    def handle_endtag(self, tag):
        if tag == "head":
            self.in_head = False
        elif tag == "body":
            self.in_body = False
        elif tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_text = (self.title_text or "") + data


class NestingParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.unclosed = []
        self.misnested = []
        self.duplicate_ids = []
        self._id_counts = {}
        self.deprecated = []
        self.empty_ok = set(VOID_ELEMENTS)
        self.seen_tags = []
        self.order_violations = []

    def handle_starttag(self, tag, attrs):
        self.seen_tags.append(tag)
        attr_dict = dict(attrs)
        if "id" in attr_dict and attr_dict["id"]:
            self._id_counts[attr_dict["id"]] = self._id_counts.get(attr_dict["id"], 0) + 1
        if tag in DEPRECATED_ELEMENTS:
            self.deprecated.append(tag)
        if tag == "html":
            if self.stack:
                self.order_violations.append("html element not at document root")
        if tag == "head" and "body" in self.stack:
            self.order_violations.append("head appears after body")
        if tag in VOID_ELEMENTS:
            return
        self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.seen_tags.append(tag)
        attr_dict = dict(attrs)
        if "id" in attr_dict and attr_dict["id"]:
            self._id_counts[attr_dict["id"]] = self._id_counts.get(attr_dict["id"], 0) + 1
        if tag in DEPRECATED_ELEMENTS:
            self.deprecated.append(tag)

    def handle_endtag(self, tag):
        if tag in VOID_ELEMENTS:
            return
        if not self.stack:
            self.unclosed.append(f"stray closing </{tag}>")
            return
        if tag in self.stack:
            while self.stack:
                top = self.stack.pop()
                if top == tag:
                    break
                if top not in VOID_ELEMENTS:
                    self.unclosed.append(f"<{top}> not closed before </{tag}>")
                    self.misnested.append(f"</{tag}> closes over <{top}>")
        else:
            self.unclosed.append(f"stray closing </{tag}>")

    def close(self):
        super().close()
        for t in self.stack:
            if t not in VOID_ELEMENTS:
                self.unclosed.append(f"<{t}> never closed")
        for k, v in self._id_counts.items():
            if v > 1:
                self.duplicate_ids.append(k)


class LinkCollector(HTMLParser):
    def __init__(self, base_url):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links = []
        self.assets = []
        self.base_href = None
        self.fragments = []
        self.protocol_relative = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "base" and d.get("href"):
            self.base_href = d["href"]
        if tag == "a" and d.get("href"):
            href = d["href"].strip()
            self.links.append(href)
            if href.startswith("//"):
                self.protocol_relative.append(href)
            if href.startswith("#"):
                self.fragments.append(href[1:])
            else:
                parsed = urlparse(href)
                if parsed.fragment:
                    self.fragments.append(parsed.fragment)
        if tag in ("link",) and d.get("href"):
            self.assets.append(d["href"])
        if tag in ("script", "img", "iframe", "source", "video", "audio"):
            for k in ("src", "data-src", "poster"):
                if d.get(k):
                    self.assets.append(d[k])
            if tag == "img" and d.get("srcset"):
                for part in d["srcset"].split(","):
                    u = part.strip().split(" ")[0]
                    if u:
                        self.assets.append(u)


class EncodingAnalyzer:
    def __init__(self, raw, soup, meta_charset):
        self.raw = raw or b""
        self.soup = soup
        self.meta_charset = meta_charset

    def detect_bom(self):
        raw = self.raw
        if raw.startswith(b"\xef\xbb\xbf"):
            return "UTF-8"
        if raw.startswith(b"\xff\xfe\x00\x00"):
            return "UTF-32 LE"
        if raw.startswith(b"\x00\x00\xfe\xff"):
            return "UTF-32 BE"
        if raw.startswith(b"\xff\xfe"):
            return "UTF-16 LE"
        if raw.startswith(b"\xfe\xff"):
            return "UTF-16 BE"
        return None

    def non_ascii_ratio(self):
        if not self.raw:
            return 0.0
        sample = self.raw[:MAX_ENTITY_SAMPLE]
        try:
            sample.decode("ascii")
            return 0.0
        except UnicodeDecodeError:
            pass
        non = sum(1 for b in sample if b > 127)
        return non / max(len(sample), 1)

    def count_entities(self):
        text = None
        if self.soup and self.soup.body:
            text = self.soup.body.get_text()
        elif self.soup:
            text = str(self.soup)
        if not text:
            return 0, 0
        named = len(re.findall(r"&(?:[a-zA-Z][a-zA-Z0-9]{1,31});", text))
        numeric = len(re.findall(r"&#(?:x[0-9a-fA-F]+|[0-9]+);", text))
        return named, numeric


class HTMLValidator:
    def __init__(self, url, timeout=15, verbose=False):
        self.url = url
        self.timeout = timeout
        self.verbose = verbose
        self.raw_html = ""
        self.raw_bytes = b""
        self.soup = None
        self.final_url = url
        self.http_status = None
        self.headers = {}
        self.scores = OrderedDict((k, 0) for k in CATEGORY_META)
        self.errors = []
        self.warnings = []
        self.recommendations = []
        self.details = OrderedDict((k, []) for k in CATEGORY_META)
        self.fetched_ok = False
        self.link_results = {}
        self.meta_charset = None

    def log(self, msg):
        if self.verbose:
            print(paint(f"    [debug] {msg}", C.DIM))

    def add_error(self, category, message):
        self.errors.append({"category": category, "message": message})

    def add_warning(self, category, message):
        self.warnings.append({"category": category, "message": message})

    def add_rec(self, category, message):
        self.recommendations.append({"category": category, "message": message})

    def note(self, category, message):
        self.details[category].append(message)

    def fetch(self):
        self.log(f"Fetching {self.url}")
        if not _have_requests:
            self.add_error("structure", "requests library unavailable; cannot fetch URL")
            return False
        headers = {
            "User-Agent": "HTMLValidator/1.0 (+https://localhost/htmlvalidator)",
            "Accept": "text/html,application/xhtml+xml",
        }
        try:
            resp = requests.get(self.url, timeout=self.timeout, headers=headers, allow_redirects=True)
        except requests.exceptions.Timeout:
            self.add_error("structure", f"Request timed out after {self.timeout}s")
            return False
        except requests.exceptions.SSLError:
            self.add_error("structure", "SSL certificate verification failed")
            return False
        except requests.exceptions.ConnectionError as e:
            self.add_error("structure", f"Connection error: {e.__class__.__name__}")
            return False
        except Exception as e:
            self.add_error("structure", f"Request failed: {e}")
            return False
        self.http_status = resp.status_code
        self.headers = dict(resp.headers)
        self.final_url = str(resp.url)
        self.raw_bytes = resp.content or b""
        try:
            self.raw_html = resp.text
        except Exception:
            self.raw_html = self.raw_bytes.decode("utf-8", errors="replace")
        if resp.status_code >= 400:
            self.add_error("structure", f"HTTP status {resp.status_code}")
            return False
        ct = resp.headers.get("Content-Type", "")
        if ct and "html" not in ct.lower() and "xml" not in ct.lower() and ct.strip():
            self.add_warning("structure", f"Content-Type is '{ct}', expected HTML")
        self.fetched_ok = True
        self.log(f"Fetched {len(self.raw_bytes)} bytes, status {resp.status_code}")
        return True

    def parse(self):
        if not self.raw_html:
            return
        if BeautifulSoup is None:
            self.add_error("elements", "beautifulsoup4 unavailable; cannot parse HTML")
            return
        try:
            self.soup = BeautifulSoup(self.raw_html, "html.parser")
        except Exception as e:
            self.add_error("elements", f"HTML parse failed: {e}")

    def run_all(self):
        if not self.fetch():
            for k in self.scores:
                self.scores[k] = 0
            return
        self.parse()
        self.check_structure()
        self.check_elements()
        self.check_attributes()
        self.check_semantic()
        self.check_a11y_markup()
        self.check_seo_markup()
        self.check_security_markup()
        self.check_encoding()
        self.check_links()
        self.check_perf_markup()

    def set_score(self, category, value):
        cap = CATEGORY_META[category]["max"]
        self.scores[category] = max(0, min(cap, int(round(value))))

    def check_structure(self):
        cat = "structure"
        maxp = CATEGORY_META[cat]["max"]
        score = 0.0
        parser = StructureParser()
        try:
            parser.feed(self.raw_html)
            parser.close()
        except Exception as e:
            self.add_warning(cat, f"Structure parser error: {e}")
        if parser.has_doctype:
            score += 3
            self.note(cat, "DOCTYPE declared")
            dt = (parser.doctype_text or "").strip()
            dt_norm = re.sub(r"^doctype\s+", "", dt, flags=re.I).strip()
            if dt_norm.lower() == "html":
                score += 2
                self.note(cat, "HTML5 doctype <!DOCTYPE html> correct")
            else:
                self.add_warning(cat, f"Non-HTML5 doctype: DOCTYPE {dt[:60]}")
                self.add_rec(cat, "Use <!DOCTYPE html> for HTML5 documents")
        else:
            self.add_error(cat, "Missing DOCTYPE declaration")
            self.add_rec(cat, "Add <!DOCTYPE html> as the first line of the document")
        html_seen = "html" in parser.tags_seen
        if html_seen:
            if "lang" in parser.html_attrs and str(parser.html_attrs.get("lang") or "").strip():
                score += 2
                self.note(cat, f"html lang attribute: {parser.html_attrs['lang']}")
            else:
                self.add_error(cat, "html element missing lang attribute")
                self.add_rec(cat, 'Add lang="en" (or appropriate language) to <html>')
        else:
            self.add_error(cat, "No <html> element found")
        if parser.has_head:
            score += 1
        else:
            self.add_error(cat, "Missing <head> element")
        if parser.has_body:
            score += 1
        else:
            self.add_error(cat, "Missing <body> element")
        if parser.charset_meta:
            score += 2
            self.note(cat, f"Charset declared: {parser.charset_meta}")
            self.meta_charset = parser.charset_meta
        else:
            self.add_error(cat, "Missing charset meta tag")
            self.add_rec(cat, 'Add <meta charset="utf-8"> inside <head>')
        if parser.viewport_meta:
            score += 2
            self.note(cat, "Viewport meta present")
        else:
            self.add_warning(cat, "Missing viewport meta tag")
            self.add_rec(cat, 'Add <meta name="viewport" content="width=device-width, initial-scale=1">')
        title = (parser.title_text or "").strip()
        if title:
            score += 2
            self.note(cat, f"Title present ({len(title)} chars)")
            if len(title) > 70:
                self.add_warning(cat, f"Title is {len(title)} characters (recommended <= 60-70)")
        else:
            self.add_error(cat, "Missing or empty <title> element")
            self.add_rec(cat, "Add a descriptive <title> in <head>")
        if self.soup:
            metas = self.soup.find_all("meta")
            if not metas:
                self.add_warning(cat, "No meta tags found")
        self.set_score(cat, score * (maxp / 15.0))

    def check_elements(self):
        cat = "elements"
        maxp = CATEGORY_META[cat]["max"]
        score = 15.0
        p = NestingParser()
        try:
            p.feed(self.raw_html)
            p.close()
        except Exception as e:
            self.add_warning(cat, f"Element parser error: {e}")
        if p.unclosed:
            dedup = list(dict.fromkeys(p.unclosed))
            for u in dedup[:10]:
                self.add_error(cat, u)
            if len(dedup) > 10:
                self.add_warning(cat, f"...and {len(dedup)-10} more unclosed/stray tag issues")
            score -= min(5, len(dedup) * 1.5)
            self.add_rec(cat, "Close all elements in the correct order; prefer self-closing syntax only for void elements")
        else:
            self.note(cat, "All elements properly closed")
        if p.misnested:
            dedup = list(dict.fromkeys(p.misnested))
            for m in dedup[:8]:
                self.add_error(cat, f"Improper nesting: {m}")
            score -= min(4, len(dedup) * 1.2)
            self.add_rec(cat, "Fix improperly nested tags (e.g. <b><i></b></i> must be <b><i></i></b>)")
        else:
            self.note(cat, "No improper nesting detected")
        if p.duplicate_ids:
            for d in p.duplicate_ids[:8]:
                self.add_error(cat, f"Duplicate id: '{d}'")
            score -= min(3, len(p.duplicate_ids) * 1.0)
            self.add_rec(cat, "Make every id unique in the document")
        else:
            self.note(cat, "No duplicate IDs")
        if p.deprecated:
            uniq = sorted(set(p.deprecated))
            for d in uniq[:8]:
                self.add_warning(cat, f"Deprecated element: <{d}>")
            score -= min(3, len(uniq) * 0.75)
            self.add_rec(cat, "Replace deprecated elements with CSS-styled semantic equivalents")
        else:
            self.note(cat, "No deprecated elements found")
        if self.soup:
            empties = []
            for tag in VOID_ELEMENTS:
                for el in self.soup.find_all(tag):
                    if el.contents and any(
                        not isinstance(c, Comment) and str(c).strip()
                        for c in el.contents
                    ):
                        empties.append(tag)
            if empties:
                for e in sorted(set(empties))[:6]:
                    self.add_warning(cat, f"Void element <{e}> contains content")
                score -= min(2, len(set(empties)) * 0.5)
            else:
                self.note(cat, "Void/empty elements correct")
        if p.order_violations:
            for v in p.order_violations[:5]:
                self.add_warning(cat, f"Document order: {v}")
            score -= min(1, len(p.order_violations) * 0.5)
        if self.soup and self.soup.html is None:
            self.add_error(cat, "Missing <html> root element")
            score -= 3
        self.set_score(cat, score * (maxp / 15.0))

    def check_attributes(self):
        cat = "attributes"
        maxp = CATEGORY_META[cat]["max"]
        score = 15.0
        if not self.soup:
            self.set_score(cat, 0)
            return
        required_issues = []
        missing_alt = 0
        for img in self.soup.find_all("img"):
            if not img.has_attr("alt"):
                missing_alt += 1
                required_issues.append("img missing alt attribute")
        empty_alt = sum(1 for img in self.soup.find_all("img") if img.has_attr("alt") and not (img.get("alt") or "").strip())
        for a in self.soup.find_all("a"):
            if not a.has_attr("href"):
                required_issues.append("a missing href attribute")
        for inp in self.soup.find_all(["input", "select", "textarea"]):
            t = (inp.get("type") or "text").lower()
            if t in ("hidden",):
                continue
            if not inp.has_attr("name"):
                required_issues.append(f"{inp.name} missing name attribute")
        for link in self.soup.find_all("link"):
            rel = " ".join(link.get("rel") or []).lower()
            if "stylesheet" in rel and not link.get("href"):
                required_issues.append("link stylesheet missing href")
        if required_issues:
            uniq = list(dict.fromkeys(required_issues))
            for r in uniq[:10]:
                self.add_error(cat, r)
            score -= min(5, len(uniq) * 1.0)
            self.add_rec(cat, "Provide required attributes (alt on img, href on a, name on form controls)")
        else:
            self.note(cat, "Required attributes present")
        if empty_alt and empty_alt < sum(1 for _ in self.soup.find_all("img")):
            self.note(cat, f"{empty_alt} decorative image(s) use empty alt")
        dep_found = []
        for tag in self.soup.find_all(True):
            for attr in tag.attrs:
                al = attr.lower()
                if tag.name == "meta" and al in ("name", "charset", "content", "http-equiv", "property"):
                    continue
                if tag.name == "a" and al == "name":
                    continue
                if tag.name == "img" and al in ("width", "height"):
                    continue
                if al in DEPRECATED_ATTRS:
                    dep_found.append(f"{tag.name}[{al}]")
        if dep_found:
            uniq = sorted(set(dep_found))
            for d in uniq[:10]:
                self.add_warning(cat, f"Deprecated attribute: {d}")
            score -= min(4, len(uniq) * 0.5)
            self.add_rec(cat, "Replace presentational attributes with CSS")
        else:
            self.note(cat, "No deprecated attributes found")
        bool_issues = []
        for tag in self.soup.find_all(True):
            for attr, val in tag.attrs.items():
                al = attr.lower()
                if al in BOOLEAN_ATTRS:
                    if val is None:
                        continue
                    sval = str(val).strip().lower()
                    if sval not in ("", al, "true"):
                        bool_issues.append(f"{tag.name}[{al}]='{val}'")
                elif al in ("disabled", "checked", "selected", "readonly", "required", "multiple", "hidden", "autofocus", "autoplay", "controls", "loop", "muted", "defer", "async", "open", "reversed", "novalidate", "autofocus", "ismap", "defer"):
                    if val is not None and str(val).strip().lower() not in ("", al, "true"):
                        bool_issues.append(f"{tag.name}[{al}]='{val}'")
        if bool_issues:
            uniq = sorted(set(bool_issues))
            for b in uniq[:8]:
                self.add_warning(cat, f"Boolean attribute has value: {b}")
            score -= min(2, len(uniq) * 0.4)
            self.add_rec(cat, 'Use bare boolean attributes (e.g. "checked", not "checked=checked")')
        else:
            self.note(cat, "Boolean attributes correct")
        data_issues = []
        for tag in self.soup.find_all(True):
            for attr in tag.attrs:
                if attr.startswith("data-"):
                    if not re.match(r"^data-[a-z]+([a-z0-9-]*[a-z0-9])?$", attr):
                        data_issues.append(f"{tag.name}[{attr}]")
                    elif re.search(r"[A-Z]", attr):
                        data_issues.append(f"{tag.name}[{attr}] uppercase in data-*")
        if data_issues:
            for d in sorted(set(data_issues))[:8]:
                self.add_warning(cat, f"Custom data attribute issue: {d}")
            score -= min(2, len(set(data_issues)) * 0.5)
            self.add_rec(cat, 'Use lowercase data-* attribute names with hyphens (data-user-id)')
        else:
            self.note(cat, "data-* attributes valid")
        aria_issues = []
        aria_count = 0
        for tag in self.soup.find_all(True):
            for attr in tag.attrs:
                if attr.startswith("aria-"):
                    aria_count += 1
                    if not ARIA_ATTR_RE.match(attr):
                        aria_issues.append(f"{tag.name}[{attr}] invalid ARIA attribute name")
                    else:
                        if attr == "aria-labelledby" or attr == "aria-describedby" or attr == "aria-controls" or attr == "aria-owns" or attr == "aria-activedescendant":
                            val = str(tag.get(attr) or "").strip()
                            if val:
                                for ref in val.split():
                                    if not self.soup.find(id=ref) and not self.soup.find(attrs={"id": ref}):
                                        aria_issues.append(f"{tag.name}[{attr}] references missing id '{ref}'")
                        if attr == "aria-hidden":
                            if str(tag.get(attr)).lower() not in ("true", "false"):
                                aria_issues.append(f"{tag.name}[aria-hidden] must be true/false")
                        if attr == "aria-expanded" or attr == "aria-checked" or attr == "aria-selected" or attr == "aria-disabled" or attr == "aria-required" or attr == "aria-modal" or attr == "aria-invalid":
                            if str(tag.get(attr)).lower() not in ("true", "false", "mixed", "undefined"):
                                aria_issues.append(f"{tag.name}[{attr}] invalid value '{tag.get(attr)}'")
                        if attr == "aria-label" and not str(tag.get(attr) or "").strip():
                            aria_issues.append(f"{tag.name}[aria-label] is empty")
                if attr == "role":
                    role = str(tag.get("role") or "").strip().lower()
                    if role and role not in ARIA_ROLES:
                        aria_issues.append(f"{tag.name}[role='{role}'] unknown role")
        if aria_issues:
            for a in sorted(set(aria_issues))[:10]:
                self.add_warning(cat, f"ARIA issue: {a}")
            score -= min(3, len(set(aria_issues)) * 0.6)
            self.add_rec(cat, "Validate ARIA attribute names, values, and id references")
        else:
            if aria_count:
                self.note(cat, f"ARIA attributes valid ({aria_count} found)")
            else:
                self.note(cat, "No ARIA attributes present (checked)")
        self.set_score(cat, score * (maxp / 15.0))

    def check_semantic(self):
        cat = "semantic"
        maxp = CATEGORY_META[cat]["max"]
        score = 10.0
        if not self.soup:
            self.set_score(cat, 0)
            return
        present = []
        missing = []
        core = ["header", "nav", "main", "article", "section", "footer"]
        for el in core:
            if self.soup.find(el):
                present.append(el)
            else:
                missing.append(el)
        extra = ["aside", "figure", "figcaption", "details", "summary"]
        extra_present = [e for e in extra if self.soup.find(e)]
        score = 4.0 * (len(present) / len(core)) + 1.5 * (len(extra_present) / len(extra))
        self.note(cat, f"Semantic elements found: {', '.join(present + extra_present) if present or extra_present else 'none'}")
        if missing:
            self.add_warning(cat, f"Missing semantic elements: {', '.join(missing)}")
            self.add_rec(cat, "Use semantic containers like <main>, <nav>, <header>, <footer> instead of generic divs")
        if self.soup.find_all("div") and not present:
            self.add_warning(cat, "Layout uses only div elements; no semantic landmarks")
        headings = []
        for h in range(1, 7):
            for el in self.soup.find_all(f"h{h}"):
                headings.append(h)
        if not headings:
            self.add_error(cat, "No headings found")
            score -= 2
            self.add_rec(cat, "Add a heading structure starting with <h1>")
        else:
            h1s = self.soup.find_all("h1")
            if len(h1s) == 0:
                self.add_error(cat, "No <h1> heading")
                score -= 1.5
            elif len(h1s) > 1:
                self.add_warning(cat, f"Multiple <h1> headings ({len(h1s)})")
                score -= 1.0
                self.add_rec(cat, "Use a single <h1> for the page's primary topic")
            else:
                score += 0.5
                self.note(cat, "Single h1 present")
            skipped = []
            prev = 0
            for h in headings:
                if prev and h > prev + 1:
                    skipped.append(f"h{prev}->h{h}")
                prev = h
            if skipped:
                uniq = sorted(set(skipped))
                self.add_warning(cat, f"Heading level skipped: {', '.join(uniq[:5])}")
                score -= min(1.5, len(uniq) * 0.5)
                self.add_rec(cat, "Do not skip heading levels (h2 should follow h1, etc.)")
            else:
                score += 0.5
                self.note(cat, "Heading hierarchy consistent")
        landmarks = set()
        for el in self.soup.find_all(True):
            role = str(el.get("role") or "").lower()
            if role in LANDMARK_ROLES:
                landmarks.add(role)
            if el.name in ("nav", "main", "header", "footer", "aside"):
                landmarks.add(el.name if el.name != "header" else "banner" if self.soup.find_all("header") and el.name == "header" and el.find_parent("article") is None and el.find_parent("section") is None else el.name)
            if el.name == "section" and el.get("aria-label"):
                landmarks.add("region")
        if len(landmarks) >= 3:
            score += 2
            self.note(cat, f"Landmark regions: {', '.join(sorted(landmarks))}")
        elif landmarks:
            score += 1
            self.note(cat, f"Limited landmarks: {', '.join(sorted(landmarks))}")
            self.add_warning(cat, "Few landmark regions detected")
        else:
            self.add_warning(cat, "No landmark regions detected")
            self.add_rec(cat, "Add landmark elements (header, nav, main, footer) or roles")
        divs = len(self.soup.find_all("div"))
        if divs > 30 and len(present) < 3:
            self.add_warning(cat, f"Heavy div usage ({divs} divs) with few semantic elements")
            score -= 1
        self.set_score(cat, score * (maxp / 10.0))

    def check_a11y_markup(self):
        cat = "a11y_markup"
        maxp = CATEGORY_META[cat]["max"]
        score = 10.0
        if not self.soup:
            self.set_score(cat, 0)
            return
        imgs = self.soup.find_all("img")
        if imgs:
            no_alt = [i for i in imgs if not i.has_attr("alt")]
            empty_alt = [i for i in imgs if i.has_attr("alt") and not (i.get("alt") or "").strip()]
            if no_alt:
                self.add_error(cat, f"{len(no_alt)} image(s) missing alt attribute")
                score -= min(3, len(no_alt) * 0.8)
                self.add_rec(cat, "Add descriptive alt text to informative images; alt=\"\" for decorative")
            elif empty_alt and len(empty_alt) == len(imgs):
                self.add_warning(cat, "All images have empty alt text")
                score -= 1
                self.add_rec(cat, "Ensure informative images have descriptive alt text")
            else:
                score += 1.5
                self.note(cat, f"Images have alt text ({len(imgs)} images)")
            bad_len = [i for i in imgs if i.get("alt") and len(str(i.get("alt"))) > 150]
            if bad_len:
                self.add_warning(cat, f"{len(bad_len)} image alt text longer than 150 chars")
                score -= 0.5
        else:
            self.note(cat, "No images present")
            score += 0.5
        form_controls = self.soup.find_all(["input", "select", "textarea"])
        form_controls = [c for c in form_controls if (c.get("type") or "text").lower() not in ("hidden", "submit", "button", "reset", "image")]
        if form_controls:
            unlabeled = 0
            for c in form_controls:
                cid = c.get("id")
                labeled = False
                if cid and self.soup.find("label", attrs={"for": cid}):
                    labeled = True
                if c.find_parent("label") is not None:
                    labeled = True
                if c.get("aria-label") or c.get("aria-labelledby") or c.get("title"):
                    labeled = True
                if not labeled:
                    unlabeled += 1
            if unlabeled:
                self.add_error(cat, f"{unlabeled} form control(s) without a label")
                score -= min(3, unlabeled * 0.8)
                self.add_rec(cat, "Associate <label for> with every form control, or use aria-label")
            else:
                score += 1.5
                self.note(cat, f"All {len(form_controls)} form controls labeled")
        else:
            self.note(cat, "No form controls present")
            score += 0.5
        role_count = sum(1 for t in self.soup.find_all(True) if t.get("role"))
        aria_count = sum(1 for t in self.soup.find_all(True) for a in t.attrs if a.startswith("aria-"))
        if role_count or aria_count:
            score += 1.5
            self.note(cat, f"ARIA usage: {role_count} roles, {aria_count} aria-* attributes")
        else:
            self.add_warning(cat, "No ARIA roles or aria-* attributes found")
            score -= 0.5
            self.add_rec(cat, "Add ARIA roles where native semantics are insufficient")
        skip = False
        for a in self.soup.find_all("a", href=True):
            href = str(a.get("href") or "")
            if href.startswith("#") and href[1:]:
                fid = href[1:]
                target = self.soup.find(id=fid)
                if target:
                    txt = a.get_text(strip=True).lower()
                    if any(k in txt for k in ("skip", "main content", "content", "jump")) or fid.lower() in ("main", "content", "maincontent", "skip"):
                        skip = True
        if skip:
            score += 2
            self.note(cat, "Skip navigation link present")
        else:
            self.add_warning(cat, "No skip navigation link detected")
            score -= 1
            self.add_rec(cat, 'Add a skip link like <a href="#main">Skip to main content</a> as the first focusable element')
        focus_css = False
        for st in self.soup.find_all("style"):
            if st.string and ":focus" in (st.string or ""):
                focus_css = True
                break
        inline_focus = False
        if not focus_css:
            for tag in self.soup.find_all(attrs={"style": True}):
                if ":focus" in (tag.get("style") or ""):
                    inline_focus = True
                    break
        if focus_css or inline_focus:
            score += 1.5
            self.note(cat, "Focus styles declared in page CSS")
        else:
            self.add_warning(cat, "No :focus styles found in inline stylesheets")
            score -= 0.5
            self.add_rec(cat, "Define visible :focus indicators so keyboard users can track position")
        lang_ok = bool((self.soup.html and self.soup.html.get("lang")))
        if not lang_ok:
            score -= 1
        self.set_score(cat, score * (maxp / 10.0))

    def check_seo_markup(self):
        cat = "seo_markup"
        maxp = CATEGORY_META[cat]["max"]
        score = 10.0
        if not self.soup:
            self.set_score(cat, 0)
            return
        desc = self.soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
        if desc and (desc.get("content") or "").strip():
            d = desc.get("content").strip()
            score += 3
            self.note(cat, f"Meta description present ({len(d)} chars)")
            if len(d) < 50:
                self.add_warning(cat, f"Meta description short ({len(d)} chars, recommended 50-160)")
                score -= 0.5
            elif len(d) > 160:
                self.add_warning(cat, f"Meta description long ({len(d)} chars, recommended <= 160)")
                score -= 0.5
        else:
            self.add_error(cat, "Missing meta description")
            self.add_rec(cat, 'Add <meta name="description" content="..."> with a 50-160 char summary')
            score = max(score - 3, 0)
        og = {}
        for m in self.soup.find_all("meta"):
            p = (m.get("property") or m.get("name") or "").lower()
            if p.startswith(OG_PREFIX):
                og[p] = m.get("content") or ""
        og_keys = set(og)
        required_og = {"og:title", "og:description", "og:image", "og:url", "og:type"}
        have = required_og & og_keys
        if have:
            score += 3 * (len(have) / len(required_og))
            self.note(cat, f"Open Graph tags: {', '.join(sorted(have))}")
            missing_og = required_og - og_keys
            if missing_og:
                self.add_warning(cat, f"Missing Open Graph tags: {', '.join(sorted(missing_og))}")
                self.add_rec(cat, "Add complete og:* tags for rich social sharing previews")
        else:
            self.add_warning(cat, "No Open Graph (og:*) tags found")
            self.add_rec(cat, "Add og:title, og:description, og:image, og:url, og:type")
        tw = self.soup.find("meta", attrs={"name": re.compile(r"^twitter:card$", re.I)})
        if tw:
            score += 0.5
        canon = self.soup.find("link", rel=lambda v: v and "canonical" in (v if isinstance(v, list) else [v]))
        if canon and canon.get("href"):
            score += 2
            self.note(cat, f"Canonical URL: {canon.get('href')}")
        else:
            self.add_warning(cat, "No canonical link element")
            self.add_rec(cat, 'Add <link rel="canonical" href="..."> to prevent duplicate content issues')
        ld = self.soup.find_all("script", type=lambda v: v and "ld+json" in v)
        micro = self.soup.find_all(attrs={"itemtype": True})
        rdfa = self.soup.find_all(attrs={"typeof": True})
        if ld or micro or rdfa:
            score += 2
            kinds = []
            if ld:
                kinds.append(f"JSON-LD ({len(ld)})")
            if micro:
                kinds.append(f"Microdata ({len(micro)})")
            if rdfa:
                kinds.append(f"RDFa ({len(rdfa)})")
            self.note(cat, f"Structured data: {', '.join(kinds)}")
            for script in ld:
                raw = script.string or script.get_text() or ""
                try:
                    json.loads(raw)
                    self.note(cat, "JSON-LD block parses as valid JSON")
                except Exception:
                    self.add_warning(cat, "JSON-LD block contains invalid JSON")
                    score -= 0.5
        else:
            self.add_warning(cat, "No structured data found")
            self.add_rec(cat, "Add JSON-LD structured data (schema.org) for rich results")
        robots = self.soup.find("meta", attrs={"name": re.compile(r"^robots$", re.I)})
        if robots:
            score += 0.5
            self.note(cat, f"Robots meta: {robots.get('content')}")
        self.set_score(cat, score * (maxp / 10.0))

    def check_security_markup(self):
        cat = "security_markup"
        maxp = CATEGORY_META[cat]["max"]
        score = 5.0
        if not self.soup:
            self.set_score(cat, 0)
            return
        csp = None
        for m in self.soup.find_all("meta"):
            if (m.get("http-equiv") or "").lower() == "content-security-policy":
                csp = m.get("content") or ""
        if csp:
            score += 2
            self.note(cat, "Meta CSP declared")
            if "unsafe-inline" in csp:
                self.add_warning(cat, "CSP allows 'unsafe-inline'")
                score -= 0.5
            if "unsafe-eval" in csp:
                self.add_warning(cat, "CSP allows 'unsafe-eval'")
                score -= 0.5
            if not any(d in csp for d in ("default-src", "script-src", "object-src")):
                self.add_warning(cat, "CSP lacks default-src/script-src directives")
        else:
            self.add_warning(cat, "No Content-Security-Policy meta tag")
            self.add_rec(cat, "Declare a Content-Security-Policy (header preferred, meta fallback)")
            score -= 1.5
        rp = None
        for m in self.soup.find_all("meta"):
            if (m.get("http-equiv") or "").lower() == "referrer":
                rp = m.get("content") or ""
        if rp:
            score += 1.5
            self.note(cat, f"Referrer policy meta: {rp}")
            if rp.lower() in ("unsafe-url",):
                self.add_warning(cat, "Referrer-Policy is 'unsafe-url'")
                score -= 0.5
        else:
            self.add_warning(cat, "No referrer policy meta tag")
            self.add_rec(cat, 'Add <meta name="referrer" content="strict-origin-when-cross-origin">')
            score -= 1
        xua = None
        for m in self.soup.find_all("meta"):
            if (m.get("http-equiv") or "").lower() == "x-ua-compatible":
                xua = m.get("content") or ""
        if xua:
            score += 1
            self.note(cat, f"X-UA-Compatible: {xua}")
        else:
            self.add_warning(cat, "No X-UA-Compatible meta tag")
            score -= 0.5
            self.add_rec(cat, 'Add <meta http-equiv="X-UA-Compatible" content="IE=edge">')
        insecure = 0
        for tag in self.soup.find_all(["script", "img", "iframe", "link", "source"]):
            u = tag.get("src") or tag.get("href") or ""
            if str(u).startswith("http://"):
                insecure += 1
        if insecure:
            self.add_error(cat, f"{insecure} resource(s) loaded over insecure HTTP")
            score -= 1
            self.add_rec(cat, "Serve all assets over HTTPS")
        else:
            score += 0.5
            self.note(cat, "No insecure http:// subresources detected")
        doc_writes = 0
        for sc in self.soup.find_all("script"):
            if not sc.get("src") and re.search(r"document\.write\s*\(", sc.string or ""):
                doc_writes += 1
        if doc_writes:
            self.add_warning(cat, f"{doc_writes} inline script(s) use document.write")
            score -= min(0.5, doc_writes * 0.2)
        for m in self.soup.find_all("meta"):
            if (m.get("http-equiv") or "").lower() == "set-cookie":
                self.add_warning(cat, "Meta Set-Cookie is insecure and ignored by browsers")
                score -= 0.3
        self.set_score(cat, score * (maxp / 5.0))

    def check_encoding(self):
        cat = "encoding"
        maxp = CATEGORY_META[cat]["max"]
        score = 5.0
        analyzer = EncodingAnalyzer(self.raw_bytes, self.soup, self.meta_charset)
        bom = analyzer.detect_bom()
        if self.meta_charset:
            score += 2
            self.note(cat, f"Charset declaration: {self.meta_charset}")
        else:
            self.add_error(cat, "No character encoding declaration in document")
            self.add_rec(cat, 'Add <meta charset="utf-8"> within the first 1024 bytes of <head>')
            score -= 1.5
        is_utf8 = False
        if self.meta_charset and self.meta_charset.lower().replace("-", "") in ("utf8",):
            is_utf8 = True
        if is_utf8:
            score += 2
            self.note(cat, "UTF-8 encoding in use")
        elif self.meta_charset:
            self.add_warning(cat, f"Encoding '{self.meta_charset}' detected; UTF-8 recommended")
            self.add_rec(cat, 'Migrate document encoding to UTF-8 (<meta charset="utf-8">)')
            score -= 1
        else:
            score -= 0.5
        if bom:
            self.note(cat, f"Byte order mark: {bom}")
            if bom.startswith("UTF-16") or bom.startswith("UTF-32"):
                self.add_warning(cat, f"{bom} BOM with HTML5 markup is unusual; UTF-8 preferred")
                score -= 0.5
        named, numeric = analyzer.count_entities()
        if named or numeric:
            score += 1
            self.note(cat, f"Character entities: {named} named, {numeric} numeric")
        else:
            self.note(cat, "No named/numeric character entities in body text")
        ratio = analyzer.non_ascii_ratio()
        if ratio > 0:
            self.note(cat, f"Non-ASCII byte ratio in sample: {ratio:.2%}")
            if not is_utf8 and self.meta_charset:
                self.add_warning(cat, "Non-ASCII content present; verify declared encoding matches bytes")
                score -= 0.5
        try:
            if self.raw_bytes:
                enc = (self.meta_charset or "utf-8")
                self.raw_bytes.decode(enc, errors="strict")
                score += 0.5
                self.note(cat, f"Raw bytes decode cleanly as {enc}")
        except (UnicodeDecodeError, LookupError):
            self.add_warning(cat, f"Raw bytes do not decode cleanly as {self.meta_charset or 'utf-8'}")
            score -= 0.5
        self.set_score(cat, score * (maxp / 5.0))

    def check_links(self):
        cat = "links"
        maxp = CATEGORY_META[cat]["max"]
        score = 10.0
        if not self.soup:
            self.set_score(cat, 0)
            return
        collector = LinkCollector(self.final_url)
        try:
            collector.feed(self.raw_html)
        except Exception as e:
            self.add_warning(cat, f"Link parser error: {e}")
        base = collector.base_href or self.final_url
        all_ids = set()
        for el in self.soup.find_all(id=True):
            all_ids.add(str(el.get("id")))
        name_anchors = set()
        for el in self.soup.find_all(attrs={"name": True}):
            name_anchors.add(str(el.get("name")))
        frag_bad = []
        for frag in collector.fragments:
            if frag and frag not in all_ids and frag not in name_anchors:
                frag_bad.append(frag)
        if frag_bad:
            uniq = sorted(set(frag_bad))
            for f in uniq[:8]:
                self.add_warning(cat, f"Broken fragment link: #{f}")
            score -= min(3, len(uniq) * 0.75)
            self.add_rec(cat, "Ensure every #fragment target exists as an id or a[name]")
        else:
            if collector.fragments:
                score += 1
                self.note(cat, f"All {len(collector.fragments)} same-page fragments resolve")
            else:
                self.note(cat, "No same-page fragment links")
        if collector.protocol_relative:
            for pr in sorted(set(collector.protocol_relative))[:5]:
                self.add_warning(cat, f"Protocol-relative URL: {pr}")
            score -= min(1.5, len(set(collector.protocol_relative)) * 0.5)
            self.add_rec(cat, "Prefer absolute https:// URLs over protocol-relative // URLs")
        else:
            score += 0.5
            self.note(cat, "No protocol-relative URLs")
        internal = []
        external = []
        scheme_bad = []
        parsed_base = urlparse(base)
        for href in collector.links:
            if href.startswith(("mailto:", "tel:", "javascript:", "data:")):
                continue
            if href.startswith("http://") or href.startswith("https://"):
                if urlparse(href).netloc == parsed_base.netloc:
                    internal.append(href)
                else:
                    external.append(href)
            elif href.startswith("//"):
                scheme_bad.append(href)
            elif href.startswith("/"):
                internal.append(urljoin(base, href))
            elif href.startswith("#"):
                continue
            else:
                internal.append(urljoin(base, href))
        self.log(f"Links: {len(internal)} internal, {len(external)} external")
        broken_internal = []
        checked_internal = 0
        if _have_requests:
            for u in list(dict.fromkeys(internal))[:12]:
                try:
                    r = requests.head(u, timeout=min(self.timeout, 8), allow_redirects=True, headers={"User-Agent": "HTMLValidator/1.0"})
                    if r.status_code == 405:
                        r = requests.get(u, timeout=min(self.timeout, 8), allow_redirects=True, headers={"User-Agent": "HTMLValidator/1.0"}, stream=True)
                        r.close()
                    checked_internal += 1
                    if r.status_code >= 400:
                        broken_internal.append((u, r.status_code))
                except Exception:
                    checked_internal += 1
        if broken_internal:
            for u, code in broken_internal[:8]:
                self.add_error(cat, f"Broken internal link ({code}): {u[:120]}")
            score -= min(4, len(broken_internal) * 1.0)
            self.add_rec(cat, "Fix or remove links returning 4xx/5xx status codes")
        else:
            if checked_internal:
                score += 1.5
                self.note(cat, f"{checked_internal} internal link(s) checked, none broken")
            elif internal:
                self.note(cat, f"{len(internal)} internal link(s) present (not checked)")
        checked_ext = 0
        broken_ext = []
        if _have_requests and external:
            for u in list(dict.fromkeys(external))[:6]:
                try:
                    r = requests.head(u, timeout=min(self.timeout, 8), allow_redirects=True, headers={"User-Agent": "HTMLValidator/1.0"})
                    if r.status_code == 405:
                        r = requests.get(u, timeout=min(self.timeout, 8), allow_redirects=True, headers={"User-Agent": "HTMLValidator/1.0"}, stream=True)
                        r.close()
                    checked_ext += 1
                    if r.status_code >= 400:
                        broken_ext.append((u, r.status_code))
                except Exception:
                    checked_ext += 1
            if broken_ext:
                for u, code in broken_ext[:6]:
                    self.add_warning(cat, f"External link issue ({code}): {u[:120]}")
                score -= min(2, len(broken_ext) * 0.5)
                self.add_rec(cat, "Review external links that fail to respond")
            elif checked_ext:
                score += 1
                self.note(cat, f"{checked_ext} external link(s) sampled, none broken")
        elif external:
            self.note(cat, f"{len(external)} external link(s) present (sampled)")
        no_text = 0
        for a in self.soup.find_all("a", href=True):
            if not a.get_text(strip=True) and not a.get("aria-label") and not a.get("title") and not a.find("img", alt=True):
                no_text += 1
        if no_text:
            self.add_warning(cat, f"{no_text} link(s) without accessible text")
            score -= min(1.5, no_text * 0.5)
            self.add_rec(cat, "Give links visible text or aria-label")
        else:
            score += 0.5
        target_blank = 0
        unsafe_blank = 0
        for a in self.soup.find_all("a", href=True):
            if "_blank" in (a.get("target") or ""):
                target_blank += 1
                rel = " ".join(a.get("rel") or []).lower()
                if "noopener" not in rel and "noreferrer" not in rel:
                    unsafe_blank += 1
        if unsafe_blank:
            self.add_warning(cat, f"{unsafe_blank} link(s) open in new tab without rel=noopener")
            score -= min(1.5, unsafe_blank * 0.5)
            self.add_rec(cat, 'Add rel="noopener noreferrer" to links with target="_blank"')
        elif target_blank:
            score += 0.5
            self.note(cat, "target=_blank links use rel=noopener")
        if not collector.links:
            self.add_warning(cat, "No hyperlinks found on page")
            score -= 1
        self.link_results = {
            "internal_total": len(internal),
            "external_total": len(external),
            "internal_checked": checked_internal,
            "external_checked": checked_ext,
            "internal_broken": [{"url": u, "status": c} for u, c in broken_internal],
            "external_broken": [{"url": u, "status": c} for u, c in broken_ext],
            "fragment_issues": sorted(set(frag_bad)),
            "protocol_relative": sorted(set(collector.protocol_relative)),
        }
        self.set_score(cat, score * (maxp / 10.0))

    def check_perf_markup(self):
        cat = "perf_markup"
        maxp = CATEGORY_META[cat]["max"]
        score = 5.0
        if not self.soup:
            self.set_score(cat, 0)
            return
        hints = {"preload": 0, "prefetch": 0, "preconnect": 0, "dns-prefetch": 0, "modulepreload": 0}
        for lk in self.soup.find_all("link"):
            rels = [r.lower() for r in (lk.get("rel") or [])] if isinstance(lk.get("rel"), list) else [str(lk.get("rel") or "").lower()]
            for r in rels:
                if r in hints:
                    hints[r] += 1
        hint_total = sum(hints.values())
        if hint_total:
            score += 1.5
            found = [f"{k}:{v}" for k, v in hints.items() if v]
            self.note(cat, f"Resource hints: {', '.join(found)}")
        else:
            self.add_warning(cat, "No resource hints (preload/prefetch/preconnect) found")
            score -= 0.5
            self.add_rec(cat, "Use <link rel=\"preconnect\"> for critical origins and preload for key assets")
        scripts = self.soup.find_all("script", src=True)
        if scripts:
            async_c = sum(1 for s in scripts if s.has_attr("async"))
            defer_c = sum(1 for s in scripts if s.has_attr("defer"))
            blocking = [s for s in scripts if not s.has_attr("async") and not s.has_attr("defer") and (s.get("type") or "").lower() != "module"]
            if blocking:
                self.add_warning(cat, f"{len(blocking)} render-blocking script(s) without async/defer")
                score -= min(2, len(blocking) * 0.5)
                self.add_rec(cat, 'Add async or defer to <script src> tags (or use type="module")')
            else:
                score += 1.5
                self.note(cat, f"Scripts non-blocking ({async_c} async, {defer_c} defer of {len(scripts)})")
        else:
            self.note(cat, "No external scripts")
            score += 0.5
        imgs = self.soup.find_all("img", src=True)
        if imgs:
            lazy = [i for i in imgs if str(i.get("loading", "")).lower() == "lazy"]
            ratio = len(lazy) / len(imgs)
            if lazy:
                score += 1.5 * min(ratio * 2, 1.0)
                self.note(cat, f"Lazy loading on {len(lazy)}/{len(imgs)} images")
                if ratio < 0.5 and len(imgs) > 5:
                    self.add_warning(cat, f"Only {len(lazy)} of {len(imgs)} images use loading=\"lazy\"")
                    self.add_rec(cat, 'Add loading="lazy" to below-the-fold images (not to the LCP image)')
            else:
                if len(imgs) > 3:
                    self.add_warning(cat, "No images use loading=\"lazy\"")
                    score -= 1
                    self.add_rec(cat, 'Add loading="lazy" to offscreen images')
                else:
                    score += 0.5
                    self.note(cat, "Few images; lazy loading optional")
        else:
            self.note(cat, "No images with src")
            score += 0.5
        css_links = [l for l in self.soup.find_all("link", rel=lambda v: v and "stylesheet" in (v if isinstance(v, list) else str(v).split()))]
        if css_links:
            media = sum(1 for l in css_links if l.get("media") and l.get("media") != "all")
            if media:
                score += 0.5
                self.note(cat, f"{media} stylesheet(s) scoped by media attribute")
        async_imgs = sum(1 for i in self.soup.find_all("img") if i.get("decoding") == "async")
        if async_imgs:
            score += 0.25
            self.note(cat, f"{async_imgs} image(s) use decoding=async")
        noscript = self.soup.find_all("noscript")
        if noscript:
            score += 0.25
            self.note(cat, "noscript fallbacks present")
        self.set_score(cat, score * (maxp / 5.0))

    @property
    def total_score(self):
        return sum(self.scores.values())

    @property
    def grade(self):
        s = self.total_score
        if s >= 95:
            return "A+"
        if s >= 90:
            return "A"
        if s >= 75:
            return "B"
        if s >= 60:
            return "C"
        if s >= 40:
            return "D"
        return "F"

    def grade_color(self, grade):
        return {
            "A+": C.BRIGHT_GREEN, "A": C.GREEN, "B": C.BRIGHT_CYAN,
            "C": C.BRIGHT_YELLOW, "D": C.YELLOW, "F": C.RED,
        }.get(grade, C.WHITE)

    def bar(self, value, maximum, width=24):
        if maximum <= 0:
            return ""
        filled = int(round((value / maximum) * width))
        filled = max(0, min(width, filled))
        empty = width - filled
        if value / maximum >= 0.9:
            color = C.GREEN
        elif value / maximum >= 0.75:
            color = C.CYAN
        elif value / maximum >= 0.6:
            color = C.YELLOW
        else:
            color = C.RED
        return paint("█" * filled, color) + paint("░" * empty, C.DIM)

    def build_report(self):
        report = {
            "tool": "HTMLValidator",
            "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target_url": self.url,
            "final_url": self.final_url,
            "http_status": self.http_status,
            "total_score": self.total_score,
            "max_score": TOTAL_MAX,
            "grade": self.grade,
            "categories": [],
            "errors": self.errors,
            "warnings": self.warnings,
            "recommendations": self.recommendations,
            "link_results": self.link_results,
        }
        for key, meta in CATEGORY_META.items():
            report["categories"].append({
                "id": key,
                "label": meta["label"],
                "score": self.scores[key],
                "max": meta["max"],
                "details": self.details[key],
            })
        return report

    def print_report(self):
        width = 78
        print()
        print(paint("=" * width, C.BRIGHT_BLUE))
        print(paint(" HTMLValidator v1.0 — Validation Report".center(width), C.BOLD, C.WHITE))
        print(paint("=" * width, C.BRIGHT_BLUE))
        print()
        print(f"  {paint('Target:', C.DIM)} {self.final_url}")
        print(f"  {paint('HTTP Status:', C.DIM)} {self.http_status}")
        print(f"  {paint('Fetched:', C.DIM)} {len(self.raw_bytes)} bytes")
        print(f"  {paint('Timestamp:', C.DIM)} {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print()
        print(paint("  CATEGORY BREAKDOWN", C.BOLD, C.BRIGHT_CYAN))
        print(paint("  " + "-" * (width - 4), C.DIM))
        for key, meta in CATEGORY_META.items():
            sc = self.scores[key]
            mx = meta["max"]
            pct = (sc / mx * 100) if mx else 0
            label = meta["label"]
            bar = self.bar(sc, mx, 20)
            status_color = C.GREEN if pct >= 90 else (C.CYAN if pct >= 75 else (C.YELLOW if pct >= 60 else C.RED))
            print(f"  {label:<32} {bar} {paint(f'{sc:>2}/{mx:<2}', status_color)} {paint(f'{pct:>5.1f}%', C.DIM)}")
        print(paint("  " + "-" * (width - 4), C.DIM))
        total = self.total_score
        pct = total / TOTAL_MAX * 100
        g = self.grade
        gc = self.grade_color(g)
        tbar = self.bar(total, TOTAL_MAX, 30)
        print(f"  {'TOTAL':<32} {tbar} {paint(f'{total:>2}/{TOTAL_MAX}', C.BOLD, gc)} {paint(f'{pct:>5.1f}%', C.DIM)}")
        print()
        grade_line = f"  GRADE: {g}"
        print(f"{paint(grade_line, C.BOLD, gc, C.BG_DARK if USE_COLOR else None) if USE_COLOR else paint(grade_line, C.BOLD, gc)}")
        print()
        self._print_issue_group("ERRORS", self.errors, C.RED, lambda: paint("  ✓ No errors found", C.GREEN))
        self._print_issue_group("WARNINGS", self.warnings, C.YELLOW, lambda: paint("  ✓ No warnings", C.GREEN))
        self._print_recommendations()
        print(paint("=" * width, C.BRIGHT_BLUE))
        print()

    def _print_issue_group(self, title, items, color, empty_fn):
        print(paint(f"  {title} ({len(items)})", C.BOLD, color))
        if not items:
            print(empty_fn())
        else:
            for i, item in enumerate(items, 1):
                cat = item.get("category", "")
                msg = item.get("message", "")
                label = CATEGORY_META.get(cat, {}).get("label", cat)
                print(f"  {paint(f'[{i:02d}]', color)} {paint(label, C.DIM)} — {msg}")
        print()

    def _print_recommendations(self):
        print(paint(f"  RECOMMENDATIONS ({len(self.recommendations)})", C.BOLD, C.MAGENTA))
        if not self.recommendations:
            print(paint("  ✓ Nothing to improve", C.GREEN))
        else:
            for i, item in enumerate(self.recommendations, 1):
                print(f"  {paint(f'[{i:02d}]', C.MAGENTA)} {item.get('message', '')}")
        print()

    def export(self, fmt):
        fmt = (fmt or "none").lower()
        if fmt == "none":
            return None
        report = self.build_report()
        formats = [fmt] if fmt != "all" else ["json", "csv", "html"]
        written = []
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_dir = os.path.dirname(os.path.abspath(__file__))
        for f in formats:
            if f == "json":
                path = os.path.join(base_dir, f"htmlvalidator_report_{stamp}.json")
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(report, fh, indent=2, ensure_ascii=False)
                written.append(path)
            elif f == "csv":
                path = os.path.join(base_dir, f"htmlvalidator_report_{stamp}.csv")
                with open(path, "w", encoding="utf-8", newline="") as fh:
                    w = csv.writer(fh)
                    w.writerow(["section", "category", "item", "value"])
                    w.writerow(["summary", "total", "score", f"{report['total_score']}/{report['max_score']}"])
                    w.writerow(["summary", "total", "grade", report["grade"]])
                    w.writerow(["summary", "target", "url", report["final_url"]])
                    w.writerow(["summary", "target", "http_status", str(report["http_status"])])
                    for cat in report["categories"]:
                        w.writerow(["category", cat["label"], "score", f"{cat['score']}/{cat['max']}"])
                        for d in cat["details"]:
                            w.writerow(["detail", cat["label"], "note", d])
                    for e in report["errors"]:
                        w.writerow(["error", e.get("category", ""), "message", e.get("message", "")])
                    for wn in report["warnings"]:
                        w.writerow(["warning", wn.get("category", ""), "message", wn.get("message", "")])
                    for r in report["recommendations"]:
                        w.writerow(["recommendation", r.get("category", ""), "message", r.get("message", "")])
                written.append(path)
            elif f == "html":
                path = os.path.join(base_dir, f"htmlvalidator_report_{stamp}.html")
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(self.render_html(report))
                written.append(path)
        return written

    def render_html(self, report):
        def esc(s):
            return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))
        rows = []
        for cat in report["categories"]:
            pct = (cat["score"] / cat["max"] * 100) if cat["max"] else 0
            if pct >= 90:
                bar_color = "#3ddc84"
            elif pct >= 75:
                bar_color = "#39c5cf"
            elif pct >= 60:
                bar_color = "#e6c07b"
            else:
                bar_color = "#ff5f56"
            details = "".join(f"<li>{esc(d)}</li>" for d in cat["details"]) or "<li class='muted'>No notes</li>"
            rows.append(f"""
            <tr>
              <td>{esc(cat['label'])}</td>
              <td class="score">{cat['score']} / {cat['max']}</td>
              <td>
                <div class="bar"><div class="fill" style="width:{pct:.0f}%;background:{bar_color}"></div></div>
                <span class="pct">{pct:.1f}%</span>
              </td>
              <td class="details"><ul>{details}</ul></td>
            </tr>""")
        errors_html = "".join(f"<li><span class='cat'>{esc(CATEGORY_META.get(e['category'],{}).get('label', e['category']))}</span> {esc(e['message'])}</li>" for e in report["errors"]) or "<li class='muted'>None</li>"
        warns_html = "".join(f"<li><span class='cat'>{esc(CATEGORY_META.get(w['category'],{}).get('label', w['category']))}</span> {esc(w['message'])}</li>" for w in report["warnings"]) or "<li class='muted'>None</li>"
        recs_html = "".join(f"<li>{esc(r['message'])}</li>" for r in report["recommendations"]) or "<li class='muted'>None</li>"
        grade = report["grade"]
        grade_color = {"A+": "#3ddc84", "A": "#3ddc84", "B": "#39c5cf", "C": "#e6c07b", "D": "#ffae57", "F": "#ff5f56"}.get(grade, "#e6edf3")
        total_pct = report["total_score"] / report["max_score"] * 100
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HTMLValidator Report — {esc(grade)}</title>
<style>
  :root {{
    --bg: #0d1117;
    --panel: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --accent: #58a6ff;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
    padding: 2rem;
  }}
  .wrap {{ max-width: 1000px; margin: 0 auto; }}
  header {{
    border-bottom: 1px solid var(--border);
    padding-bottom: 1.5rem;
    margin-bottom: 1.5rem;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 1rem;
    flex-wrap: wrap;
  }}
  h1 {{ font-size: 1.5rem; margin: 0 0 .25rem; }}
  .sub {{ color: var(--muted); font-size: .9rem; }}
  .grade {{
    font-size: 3rem;
    font-weight: 800;
    color: {grade_color};
    border: 2px solid {grade_color};
    border-radius: 12px;
    padding: .25rem 1.25rem;
    line-height: 1.2;
  }}
  .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: .75rem; margin-bottom: 1.5rem; }}
  .meta div {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: .75rem 1rem; }}
  .meta .k {{ color: var(--muted); font-size: .75rem; text-transform: uppercase; letter-spacing: .05em; }}
  .meta .v {{ font-weight: 600; word-break: break-all; }}
  .total-bar {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem; }}
  .total-bar .label {{ display: flex; justify-content: space-between; margin-bottom: .5rem; font-weight: 600; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  th, td {{ padding: .7rem .9rem; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }}
  th {{ background: #21262d; font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }}
  tr:last-child td {{ border-bottom: none; }}
  td.score {{ font-variant-numeric: tabular-nums; white-space: nowrap; font-weight: 600; }}
  .bar {{ display: inline-block; width: 120px; height: 8px; background: #21262d; border-radius: 4px; overflow: hidden; vertical-align: middle; margin-right: .5rem; }}
  .fill {{ height: 100%; border-radius: 4px; }}
  .pct {{ color: var(--muted); font-size: .85rem; }}
  td.details ul {{ margin: 0; padding-left: 1.1rem; font-size: .85rem; color: var(--muted); }}
  .muted {{ color: var(--muted); }}
  section {{ margin-top: 1.75rem; }}
  h2 {{ font-size: 1.1rem; border-bottom: 1px solid var(--border); padding-bottom: .4rem; }}
  ul.issues {{ list-style: none; padding: 0; margin: 0; }}
  ul.issues li {{ background: var(--panel); border: 1px solid var(--border); border-left: 3px solid var(--accent); border-radius: 6px; padding: .55rem .8rem; margin-bottom: .45rem; font-size: .9rem; }}
  ul.errors li {{ border-left-color: #ff5f56; }}
  ul.warnings li {{ border-left-color: #e6c07b; }}
  ul.recs li {{ border-left-color: #3ddc84; }}
  .cat {{ display: inline-block; color: var(--muted); font-size: .75rem; text-transform: uppercase; letter-spacing: .04em; margin-right: .5rem; }}
  footer {{ margin-top: 2rem; color: var(--muted); font-size: .8rem; text-align: center; border-top: 1px solid var(--border); padding-top: 1rem; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>HTMLValidator v1.0</h1>
      <div class="sub">Standards compliance &amp; best-practice analysis</div>
    </div>
    <div class="grade">{esc(grade)}</div>
  </header>
  <div class="meta">
    <div><div class="k">Target</div><div class="v">{esc(report['final_url'])}</div></div>
    <div><div class="k">HTTP Status</div><div class="v">{esc(report['http_status'])}</div></div>
    <div><div class="k">Score</div><div class="v">{report['total_score']} / {report['max_score']}</div></div>
    <div><div class="k">Generated</div><div class="v">{esc(report['generated_at'])}</div></div>
  </div>
  <div class="total-bar">
    <div class="label"><span>Overall score</span><span>{report['total_score']} / {report['max_score']} ({total_pct:.1f}%)</span></div>
    <div class="bar" style="width:100%;height:12px;"><div class="fill" style="width:{total_pct:.0f}%;background:{grade_color}"></div></div>
  </div>
  <section>
    <h2>Category Breakdown</h2>
    <table>
      <thead><tr><th>Category</th><th>Score</th><th>Progress</th><th>Notes</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </section>
  <section>
    <h2>Errors ({len(report['errors'])})</h2>
    <ul class="issues errors">{errors_html}</ul>
  </section>
  <section>
    <h2>Warnings ({len(report['warnings'])})</h2>
    <ul class="issues warnings">{warns_html}</ul>
  </section>
  <section>
    <h2>Recommendations ({len(report['recommendations'])})</h2>
    <ul class="issues recs">{recs_html}</ul>
  </section>
  <footer>Generated by HTMLValidator v1.0 on {esc(report['generated_at'])}</footer>
</div>
</body>
</html>"""


def build_banner():
    lines = []
    lines.append(paint("=" * 78, C.BRIGHT_BLUE))
    for i, line in enumerate(BANNER_LINES):
        lines.append(gradient_text(line, start_hue=(i * 0.08) % 1.0))
    lines.append(paint(" " * 10 + "HTML Standards · Semantics · Accessibility · SEO · Security", C.DIM, C.CYAN))
    lines.append(paint(" " * 24 + "v1.0 — HTML Validation Analyzer", C.WHITE, C.BOLD))
    lines.append(paint("=" * 78, C.BRIGHT_BLUE))
    return "\n".join(lines)


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="htmlvalidator",
        description="HTMLValidator v1.0 — HTML standards compliance and best-practice analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Grades: A+ (95-100) · A (90-94) · B (75-89) · C (60-74) · D (40-59) · F (0-39)",
    )
    p.add_argument("-u", "--url", required=True, help="Target URL to validate")
    p.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    p.add_argument("--export", choices=["all", "json", "csv", "html", "none"], default="none", help="Export format (default: none)")
    p.add_argument("--no-color", action="store_true", help="Disable colored output")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    return p.parse_args(argv)


def normalize_url(url):
    if not re.match(r"^https?://", url, re.I):
        if url.startswith("//"):
            return "https:" + url
        return "https://" + url
    return url


def main(argv=None):
    global USE_COLOR
    args = parse_args(argv)
    USE_COLOR = not args.no_color
    if not USE_COLOR:
        for k, v in list(C.__dict__.items()):
            if k.isupper() and isinstance(v, str) and v.startswith("\033"):
                setattr(C, k, "")
    print(build_banner())
    url = normalize_url(args.url)
    print(paint(f"  Target : ", C.DIM) + url)
    print(paint(f"  Timeout: ", C.DIM) + f"{args.timeout}s")
    print(paint(f"  Export : ", C.DIM) + args.export)
    print(paint(f"  Color  : ", C.DIM) + ("on" if USE_COLOR else "off"))
    print()
    if not _have_requests:
        print(paint("  [!] requests could not be installed — aborting.", C.RED))
        return 2
    if not _have_bs4:
        print(paint("  [!] beautifulsoup4 could not be installed — parsing limited.", C.YELLOW))
    validator = HTMLValidator(url, timeout=args.timeout, verbose=args.verbose)
    print(paint("  Running checks", C.BRIGHT_CYAN, C.BOLD) + paint(" ...", C.DIM))
    validator.run_all()
    validator.print_report()
    if args.export and args.export != "none":
        try:
            paths = validator.export(args.export)
            if paths:
                print(paint("  Exported:", C.BOLD, C.GREEN))
                for pth in paths:
                    print(paint(f"    → {pth}", C.GREEN))
                print()
        except Exception as e:
            print(paint(f"  Export failed: {e}", C.RED))
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
