#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse


def _ensure(pkg, import_name=None):
    name = import_name or pkg
    try:
        __import__(name)
        return True
    except ImportError:
        pass
    try:
        import subprocess
        print(f"[+] Installing missing package: {pkg}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])
        __import__(name)
        return True
    except Exception as exc:
        print(f"[!] Could not install {pkg}: {exc}")
        return False


_ensure("requests")
_ensure("beautifulsoup4", "bs4")
_HAS_PIL = _ensure("Pillow", "PIL")

import requests
from bs4 import BeautifulSoup

if _HAS_PIL:
    try:
        from PIL import Image
    except Exception:
        _HAS_PIL = False


VERSION = "3.0"
MAX_NETWORK_IMAGES = 25
MAX_DEEP_IMAGES = 12
MAX_IMAGE_BYTES = 6 * 1024 * 1024
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36 ImageAnalyzer/3.0"

MODERN_FORMATS = {"webp", "avif", "svg"}
LEGACY_FORMATS = {"jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "ico"}
COMPRESSED_FORMATS = {"jpg", "jpeg", "png", "gif", "webp", "avif", "svg"}
GENERIC_ALT_WORDS = {
    "image", "img", "photo", "picture", "graphic", "icon", "banner", "logo",
    "screenshot", "thumbnail", "screen", "untitled", "pic", "photograph",
    "illustration", "clipart", "stock", "generic", "sample", "placeholder",
}
GENERIC_NAME_RE = re.compile(
    r"^(?:img|image|photo|picture|dsc|screen(?:shot)?|untitled|pic|icon|logo|banner|asset|file)[-_ ]?\d*$",
    re.I,
)
EXT_RE = re.compile(r"\.([a-z0-9]{2,5})(?:[?#]|$)", re.I)
SRCSET_RE = re.compile(r"([^\s,]+)(?:\s+([0-9.]+[wx]))?", re.I)

AVIF_RES = [
    re.compile(r"\.avif(?:[?#]|$)", re.I),
    re.compile(r"[?&](?:f|fm|format)=avif\b", re.I),
    re.compile(r"image/avif", re.I),
    re.compile(r"/avif(?:/|$)", re.I),
]
AUTO_OPT_RES = [
    re.compile(r"q_auto", re.I),
    re.compile(r"[?&/]q=auto\b", re.I),
    re.compile(r"quality=auto", re.I),
    re.compile(r"f_auto", re.I),
    re.compile(r"[?&]auto=format\b", re.I),
    re.compile(r"[?&]format=auto\b", re.I),
    re.compile(r"[?&]fm=auto\b", re.I),
    re.compile(r"[?&]auto=webp\b", re.I),
    re.compile(r"[?&]dpr=auto\b", re.I),
    re.compile(r"[?&]qlt=auto\b", re.I),
]
AI_TRANSFORM_RES = [
    re.compile(r"e_enhance", re.I),
    re.compile(r"e_upscale", re.I),
    re.compile(r"e_improve", re.I),
    re.compile(r"e_art\b", re.I),
    re.compile(r"gen_fill", re.I),
    re.compile(r"e_gen_fill", re.I),
    re.compile(r"e_background", re.I),
    re.compile(r"e_restore", re.I),
    re.compile(r"e_removebg", re.I),
    re.compile(r"bg-remove", re.I),
    re.compile(r"e_generic_upscale", re.I),
    re.compile(r"e_neural", re.I),
    re.compile(r"[?&]ai=", re.I),
    re.compile(r"[?&]effect=enhance", re.I),
]
SMART_CROP_RES = [
    re.compile(r"crop=faces", re.I),
    re.compile(r"fit=facearea", re.I),
    re.compile(r"g_face", re.I),
    re.compile(r"faceindex", re.I),
    re.compile(r"fp-x", re.I),
    re.compile(r"fp-y", re.I),
    re.compile(r"crop=entropy", re.I),
    re.compile(r"crop=focalpoint", re.I),
    re.compile(r"c_fill,g_face", re.I),
    re.compile(r"[?&]crop=edges", re.I),
]
CDN_TRANSFORM_RES = [
    re.compile(r"cdn-cgi/image/", re.I),
    re.compile(r"[?&]w=\d+", re.I),
    re.compile(r"[?&]width=\d+", re.I),
    re.compile(r"[?&]h=\d+", re.I),
    re.compile(r"[?&]height=\d+", re.I),
    re.compile(r"[?&]dpr=[\d.]+", re.I),
    re.compile(r"[?&]resize=", re.I),
    re.compile(r"[?&]fit=", re.I),
    re.compile(r"[?&]scale=", re.I),
    re.compile(r"[?&]size=", re.I),
    re.compile(r"[?&]w_\d+", re.I),
    re.compile(r"[?&]h_\d+", re.I),
    re.compile(r"c_fill", re.I),
    re.compile(r"[?&]tr=w-", re.I),
    re.compile(r"[?&]q=\d+", re.I),
    re.compile(r"[?&]fm=[a-z0-9]+", re.I),
    re.compile(r"[?&]auto=format\b", re.I),
]
AUTO_FORMAT_RES = [
    re.compile(r"f_auto", re.I),
    re.compile(r"[?&]auto=format\b", re.I),
    re.compile(r"[?&]fm=auto\b", re.I),
    re.compile(r"[?&]format=auto\b", re.I),
    re.compile(r"[?&]auto=webp\b", re.I),
    re.compile(r"[?&]auto=avif\b", re.I),
]

BANNER_LINES = [
    "██╗███╗   ███╗ █████╗  ██████╗ ███████╗ █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗",
    "██║████╗ ████║██╔══██╗██╔════╝ ██╔════╝██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝",
    "██║██╔████╔██║███████║██║  ███╗█████╗  ███████║██╔██╗ ██║███████║██║   ╚████╔╝ ",
    "██║██║╚██╔╝██║██╔══██║██║   ██║██╔══╝  ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝  ",
    "██║██║ ╚═╝ ██║██║  ██║╚██████╔╝███████╗██║  ██║██║ ╚████║██║  ██║██║   ██║   ",
    "╚═╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝   ╚═╝   ",
    "███████╗███████╗██████╗ ",
    "╚══███╔╝██╔════╝██╔══██╗",
    "  ███╔╝ █████╗  ██████╔╝",
    " ███╔╝  ██╔══╝  ██╔══██╗",
    "███████╗███████╗██║  ██║",
    "╚══════╝╚══════╝╚═╝  ╚═╝",
]

BANNER_COLORS = ["36", "34", "35", "33", "31", "32", "36", "34", "35", "33", "31", "32"]


class Palette:
    def __init__(self, enabled=True):
        self.enabled = enabled

    def wrap(self, code, text):
        if not self.enabled:
            return str(text)
        return f"\033[{code}m{text}\033[0m"

    def bold(self, text):
        return self.wrap("1", text)

    def dim(self, text):
        return self.wrap("2", text)

    def red(self, text):
        return self.wrap("31", text)

    def green(self, text):
        return self.wrap("32", text)

    def yellow(self, text):
        return self.wrap("33", text)

    def blue(self, text):
        return self.wrap("34", text)

    def magenta(self, text):
        return self.wrap("35", text)

    def cyan(self, text):
        return self.wrap("36", text)

    def white(self, text):
        return self.wrap("37", text)

    def bg_green(self, text):
        return self.wrap("42;30", text)

    def bg_yellow(self, text):
        return self.wrap("43;30", text)

    def bg_red(self, text):
        return self.wrap("41;37", text)


def banner(palette):
    lines = []
    for idx, line in enumerate(BANNER_LINES):
        color = BANNER_COLORS[idx % len(BANNER_COLORS)]
        lines.append(palette.wrap(color, line))
    lines.append(palette.bold(palette.cyan(f"        ImageAnalyzer v{VERSION} - Image Optimization Analyzer")))
    lines.append(palette.dim("        Analyzes formats, quality, delivery, caching, AI optimization and accessibility"))
    lines.append("")
    return "\n".join(lines)


class Finding:
    def __init__(self, name, earned, maximum, message, recommendation=""):
        self.name = name
        self.earned = max(0.0, min(float(earned), float(maximum)))
        self.maximum = float(maximum)
        self.message = message
        self.recommendation = recommendation

    @property
    def status(self):
        if self.maximum <= 0:
            return "pass"
        ratio = self.earned / self.maximum
        if ratio >= 0.999:
            return "pass"
        if ratio >= 0.5:
            return "warn"
        return "fail"

    def to_dict(self):
        return {
            "name": self.name,
            "earned": round(self.earned, 2),
            "max": round(self.maximum, 2),
            "status": self.status,
            "message": self.message,
            "recommendation": self.recommendation,
        }


class CategoryResult:
    def __init__(self, key, title, maximum):
        self.key = key
        self.title = title
        self.maximum = float(maximum)
        self.findings = []

    @property
    def earned(self):
        return round(sum(f.earned for f in self.findings), 2)

    @property
    def status(self):
        ratio = self.earned / self.maximum if self.maximum else 1.0
        if ratio >= 0.999:
            return "pass"
        if ratio >= 0.7:
            return "warn"
        return "fail"

    def add(self, name, earned, maximum, message, recommendation=""):
        self.findings.append(Finding(name, earned, maximum, message, recommendation))

    def to_dict(self):
        return {
            "key": self.key,
            "title": self.title,
            "earned": self.earned,
            "max": round(self.maximum, 2),
            "status": self.status,
            "findings": [f.to_dict() for f in self.findings],
        }


class ImageInfo:
    def __init__(self, src, tag="img", in_picture=False):
        self.src = src
        self.abs_url = ""
        self.tag = tag
        self.in_picture = in_picture
        self.alt = None
        self.title = None
        self.width = None
        self.height = None
        self.loading = None
        self.decoding = None
        self.fetchpriority = None
        self.srcset = None
        self.sizes = None
        self.has_srcset = False
        self.has_sizes = False
        self.ext = ""
        self.format = ""
        self.size_bytes = None
        self.content_type = ""
        self.cache_control = ""
        self.content_encoding = ""
        self.etag = False
        self.etag_weak = False
        self.expires = False
        self.last_modified = False
        self.vary = ""
        self.cache_max_age = None
        self.cache_s_max_age = None
        self.cache_immutable = False
        self.cache_public = False
        self.cache_no_store = False
        self.cache_must_revalidate = False
        self.cache_swrv = False
        self.cache_status = ""
        self.age_seconds = None
        self.cdn_headers = []
        self.is_data = False
        self.is_inline_svg = False
        self.index = 0
        self.deep = False
        self.md5 = ""
        self.progressive = None
        self.has_exif = None
        self.has_icc = None
        self.dpi = None
        self.bpp = None
        self.natural_width = None
        self.natural_height = None
        self.webp_version = ""
        self.avif_hint = False
        self.has_auto_opt = False
        self.has_ai_transform = False
        self.has_smart_crop = False
        self.has_resize_param = False
        self.has_auto_format = False
        self.fetch_ok = False

    @property
    def fmt(self):
        if self.is_inline_svg or self.ext == "svg":
            return "svg"
        if self.content_type:
            ct = self.content_type.split(";")[0].strip().lower()
            mapping = {
                "image/jpeg": "jpg",
                "image/jpg": "jpg",
                "image/png": "png",
                "image/gif": "gif",
                "image/webp": "webp",
                "image/avif": "avif",
                "image/svg+xml": "svg",
                "image/bmp": "bmp",
                "image/tiff": "tiff",
                "image/x-icon": "ico",
                "image/vnd.microsoft.icon": "ico",
            }
            if ct in mapping:
                return mapping[ct]
        return self.ext or "unknown"

    @property
    def is_modern(self):
        return self.fmt in MODERN_FORMATS

    @property
    def is_legacy(self):
        return self.fmt in LEGACY_FORMATS

    @property
    def cache_hit(self):
        if self.cache_status and "hit" in str(self.cache_status).lower():
            return True
        if self.age_seconds and self.age_seconds > 0:
            return True
        return False


def match_any(patterns, text):
    if not text:
        return False
    return any(p.search(text) for p in patterns)


def parse_cache_control(value):
    info = {
        "max_age": None,
        "s_max_age": None,
        "immutable": False,
        "public": False,
        "private": False,
        "no_store": False,
        "no_cache": False,
        "must_revalidate": False,
        "stale_while_revalidate": None,
        "directives": [],
    }
    if not value:
        return info
    for part in value.split(","):
        token = part.strip()
        if not token:
            continue
        info["directives"].append(token)
        low = token.lower()
        if low == "immutable":
            info["immutable"] = True
        elif low == "public":
            info["public"] = True
        elif low == "private":
            info["private"] = True
        elif low == "no-store":
            info["no_store"] = True
        elif low == "no-cache":
            info["no_cache"] = True
        elif low == "must-revalidate":
            info["must_revalidate"] = True
        elif low.startswith("max-age="):
            try:
                info["max_age"] = int(low.split("=", 1)[1].strip().strip('"'))
            except ValueError:
                pass
        elif low.startswith("s-maxage="):
            try:
                info["s_max_age"] = int(low.split("=", 1)[1].strip().strip('"'))
            except ValueError:
                pass
        elif low.startswith("stale-while-revalidate="):
            try:
                info["stale_while_revalidate"] = int(low.split("=", 1)[1].strip().strip('"'))
            except ValueError:
                pass
    return info


def assess_bpp(fmt, bpp):
    if bpp is None:
        return (False, False, False)
    if fmt in ("jpg", "jpeg"):
        return (0.4 <= bpp <= 2.5, bpp > 2.5, bpp < 0.15)
    if fmt == "png":
        return (1.0 <= bpp <= 8.0, bpp > 10.0, bpp < 0.3)
    if fmt in ("webp", "avif"):
        return (0.15 <= bpp <= 1.5, bpp > 2.0, bpp < 0.08)
    if fmt == "gif":
        return (0.2 <= bpp <= 4.0, bpp > 6.0, bpp < 0.1)
    return (0.2 <= bpp <= 3.0, bpp > 4.0, bpp < 0.1)


def parse_srcset(value):
    candidates = []
    if not value:
        return candidates
    for match in SRCSET_RE.finditer(value):
        url = match.group(1).strip()
        desc = match.group(2)
        weight = 0.0
        if desc:
            try:
                weight = float(desc[:-1]) if desc.lower().endswith("x") else float(desc[:-1])
            except ValueError:
                weight = 0.0
        if url:
            candidates.append((url, desc or "", weight))
    return candidates


def pct(part, whole):
    if not whole:
        return 0.0
    return (part / whole) * 100.0


def human_size(num):
    if num is None:
        return "n/a"
    units = ["B", "KB", "MB", "GB"]
    size = float(num)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


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


def status_icon(status):
    if status == "pass":
        return "[OK]"
    if status == "warn":
        return "[!!]"
    return "[XX]"


class ImageAnalyzer:
    def __init__(self, url, timeout=15, verbose=False, palette=None):
        self.url = url
        self.timeout = timeout
        self.verbose = verbose
        self.palette = palette or Palette(False)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
        self.html = ""
        self.soup = None
        self.page_bytes = 0
        self.images = []
        self.unique_urls = []
        self.og_image = False
        self.twitter_image = False
        self.jsonld_imageobject = False
        self.image_sitemap = None
        self.categories = []
        self.total_score = 0.0
        self.recommendations = []
        self.errors = []
        self.started_at = None
        self.fetch_time = 0.0
        self.duplicate_groups = []
        self.final_url = url

    def log(self, message):
        if self.verbose:
            print(self.palette.dim(f"    > {message}"))

    def fetch_page(self):
        self.started_at = datetime.now(timezone.utc)
        parsed = urlparse(self.url)
        if not parsed.scheme:
            self.url = "https://" + self.url
        response = self.session.get(self.url, timeout=self.timeout, allow_redirects=True)
        response.raise_for_status()
        self.final_url = response.url
        response.encoding = response.apparent_encoding or response.encoding
        self.html = response.text
        self.page_bytes = len(response.content)
        self.soup = BeautifulSoup(self.html, "html.parser")
        self.log(f"Page fetched: {self.final_url} ({human_size(self.page_bytes)})")

    def extract_images(self):
        seen = set()
        idx = 0

        def add(src, tag="img", in_picture=False, elem=None):
            nonlocal idx
            if not src:
                return
            src = src.strip()
            if not src or src.startswith("data:"):
                info = ImageInfo(src, tag=tag, in_picture=in_picture)
                info.is_data = True
                info.size_bytes = len(src)
                if elem is not None:
                    self._fill_attrs(info, elem)
                info.index = idx
                idx += 1
                self.images.append(info)
                return
            if src.startswith("#"):
                return
            abs_url = urljoin(self.final_url, src)
            if abs_url in seen:
                return
            seen.add(abs_url)
            info = ImageInfo(src, tag=tag, in_picture=in_picture)
            info.abs_url = abs_url
            if elem is not None:
                self._fill_attrs(info, elem)
            if abs_url.lower().startswith("data:image/svg"):
                info.is_inline_svg = True
            ext_match = EXT_RE.search(urlparse(abs_url).path)
            if ext_match:
                info.ext = ext_match.group(1).lower()
            info.index = idx
            idx += 1
            self.images.append(info)

        for tag in self.soup.find_all(["img", "source"]):
            in_picture = tag.name == "source" and tag.parent is not None and tag.parent.name == "picture"
            if tag.name == "img":
                src = tag.get("src")
                srcset = tag.get("srcset")
                if not src and srcset:
                    candidates = parse_srcset(srcset)
                    if candidates:
                        chosen = max(candidates, key=lambda c: c[2])
                        src = chosen[0]
                add(src, tag="img", in_picture=bool(tag.find_parent("picture")), elem=tag)
                if srcset:
                    for cand in parse_srcset(srcset):
                        if cand[0] and not cand[0].startswith("data:"):
                            add(cand[0], tag="srcset", in_picture=bool(tag.find_parent("picture")))
            else:
                srcset = tag.get("srcset")
                src = tag.get("src")
                if src:
                    add(src, tag="source", in_picture=in_picture, elem=tag)
                if srcset:
                    for cand in parse_srcset(srcset):
                        if cand[0]:
                            add(cand[0], tag="source", in_picture=in_picture)

        og = self.soup.find("meta", attrs={"property": "og:image"}) or self.soup.find(
            "meta", attrs={"name": "og:image"}
        )
        if og and og.get("content"):
            self.og_image = True
            add(og.get("content"), tag="og:image")

        tw = self.soup.find("meta", attrs={"property": "twitter:image"}) or self.soup.find(
            "meta", attrs={"name": "twitter:image"}
        )
        if tw and tw.get("content"):
            self.twitter_image = True

        for script in self.soup.find_all("script", attrs={"type": re.compile("ld\\+json", re.I)}):
            text = script.string or script.get_text() or ""
            if "ImageObject" in text:
                self.jsonld_imageobject = True
                break

        self.images = [i for i in self.images if not i.is_data or i.src]
        for pos, image in enumerate(self.images):
            image.index = pos
        self.unique_urls = []
        recorded = set()
        for image in self.images:
            if not image.is_data and image.abs_url and image.abs_url not in recorded:
                recorded.add(image.abs_url)
                self.unique_urls.append(image)
        self.log(f"Extracted {len(self.images)} image references ({len(self.unique_urls)} unique)")

    def _fill_attrs(self, info, elem):
        info.alt = elem.get("alt")
        info.title = elem.get("title")
        info.width = elem.get("width")
        info.height = elem.get("height")
        info.loading = (elem.get("loading") or "").lower() or None
        info.decoding = (elem.get("decoding") or "").lower() or None
        info.fetchpriority = (elem.get("fetchpriority") or "").lower() or None
        info.srcset = elem.get("srcset")
        info.sizes = elem.get("sizes")
        info.has_srcset = bool(info.srcset)
        info.has_sizes = bool(info.sizes)
        if elem.name == "img" and not info.src:
            info.src = elem.get("src") or ""
        if info.src and info.src.startswith("data:"):
            info.is_data = True
            info.size_bytes = len(info.src)

    def _scan_url_signals(self):
        for image in self.images:
            url = image.abs_url or ""
            if not url:
                continue
            image.avif_hint = match_any(AVIF_RES, url)
            image.has_auto_opt = match_any(AUTO_OPT_RES, url)
            image.has_ai_transform = match_any(AI_TRANSFORM_RES, url)
            image.has_smart_crop = match_any(SMART_CROP_RES, url)
            image.has_resize_param = match_any(CDN_TRANSFORM_RES, url)
            image.has_auto_format = match_any(AUTO_FORMAT_RES, url)
            low = url.lower()
            if "webp2" in low or "webp-2" in low or "webp_2" in low:
                image.webp_version = "2.0"

    def probe_images(self):
        fetched = 0
        for image in self.unique_urls:
            if fetched >= MAX_NETWORK_IMAGES:
                self.log("Network probe limit reached")
                break
            try:
                head_ok = False
                try:
                    head = self.session.head(image.abs_url, timeout=self.timeout, allow_redirects=True)
                    if head.status_code < 400:
                        head_ok = True
                        self._apply_headers(image, head)
                except requests.RequestException:
                    head_ok = False
                if not head_ok or image.size_bytes is None:
                    resp = self.session.get(
                        image.abs_url,
                        timeout=self.timeout,
                        allow_redirects=True,
                        stream=True,
                        headers={"Range": "bytes=0-0"},
                    )
                    if resp.status_code in (200, 206):
                        self._apply_headers(image, resp)
                        if image.size_bytes is None and resp.status_code == 200:
                            cl = resp.headers.get("Content-Length")
                            if cl and cl.isdigit():
                                image.size_bytes = int(cl)
                    resp.close()
                image.fetch_ok = True
                fetched += 1
                self.log(f"Probed {image.abs_url} -> {human_size(image.size_bytes)} {image.fmt}")
            except requests.RequestException as exc:
                self.errors.append(f"{image.abs_url}: {exc}")
                self.log(f"Probe failed {image.abs_url}: {exc}")

    def _apply_headers(self, image, response):
        headers = response.headers
        image.content_type = headers.get("Content-Type", "") or image.content_type
        length = headers.get("Content-Length")
        if length and str(length).isdigit():
            if response.status_code == 206:
                content_range = headers.get("Content-Range", "")
                if "/" in content_range:
                    total = content_range.split("/")[-1]
                    if total.isdigit():
                        image.size_bytes = int(total)
            else:
                image.size_bytes = int(length)
        cc = headers.get("Cache-Control", "") or image.cache_control
        image.cache_control = cc
        parsed_cc = parse_cache_control(cc)
        image.cache_max_age = parsed_cc["max_age"]
        image.cache_s_max_age = parsed_cc["s_max_age"]
        image.cache_immutable = parsed_cc["immutable"]
        image.cache_public = parsed_cc["public"]
        image.cache_no_store = parsed_cc["no_store"]
        image.cache_must_revalidate = parsed_cc["must_revalidate"]
        image.cache_swrv = parsed_cc["stale_while_revalidate"] is not None
        image.vary = headers.get("Vary", "") or image.vary
        image.content_encoding = headers.get("Content-Encoding", "") or image.content_encoding
        if headers.get("ETag"):
            image.etag = True
            image.etag_weak = str(headers.get("ETag")).startswith("W/")
        if headers.get("Expires"):
            image.expires = True
        if headers.get("Last-Modified"):
            image.last_modified = True
        cache_status = headers.get("X-Cache") or headers.get("CF-Cache-Status") or headers.get("X-Cache-Hits") or ""
        if cache_status:
            image.cache_status = str(cache_status)
        age = headers.get("Age")
        if age is not None and str(age).isdigit():
            image.age_seconds = int(age)
        if image.cache_status and str(image.cache_status).isdigit() and int(image.cache_status) > 0:
            if "hit" not in image.cache_status.lower():
                image.cache_status = "HIT"
        for key in headers:
            low = key.lower()
            if low in (
                "cf-cache-status", "cf-ray", "x-cache", "x-amz-cf-id", "x-fastly-request-id",
                "server", "x-imgix", "x-cache-hits", "age", "x-edge-location", "akamai-grn",
            ):
                image.cdn_headers.append(low)

    def deep_inspect(self):
        inspected = 0
        hashes = {}
        for image in self.unique_urls:
            if inspected >= MAX_DEEP_IMAGES:
                break
            if not image.fetch_ok or not image.abs_url:
                continue
            if image.is_inline_svg or image.fmt == "svg":
                continue
            try:
                resp = self.session.get(image.abs_url, timeout=self.timeout, allow_redirects=True, stream=True)
                if resp.status_code >= 400:
                    resp.close()
                    continue
                data = b""
                for chunk in resp.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    data += chunk
                    if len(data) > MAX_IMAGE_BYTES:
                        break
                resp.close()
                if not data:
                    continue
                image.deep = True
                inspected += 1
                digest = hashlib.md5(data).hexdigest()
                image.md5 = digest
                hashes.setdefault(digest, []).append(image.abs_url)
                self._analyze_bytes(image, data)
                self.log(f"Deep inspected {image.abs_url}")
            except requests.RequestException as exc:
                self.errors.append(f"deep {image.abs_url}: {exc}")

        self.duplicate_groups = [urls for urls in hashes.values() if len(urls) > 1]
        if not hasattr(self, "duplicate_groups"):
            self.duplicate_groups = []

    def _analyze_bytes(self, image, data):
        fmt = image.fmt
        if data[:3] == b"\xff\xd8\xff":
            fmt = "jpg"
        elif data[:8] == b"\x89PNG\r\n\x1a\n":
            fmt = "png"
        elif data[:6] in (b"GIF87a", b"GIF89a"):
            fmt = "gif"
        elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            fmt = "webp"
        elif data[4:12] == b"ftypavif" or data[4:8] == b"ftyp":
            if b"avif" in data[:32] or b"avis" in data[:32]:
                fmt = "avif"
        image.content_type = image.content_type or {
            "jpg": "image/jpeg", "png": "image/png", "gif": "image/gif",
            "webp": "image/webp", "avif": "image/avif",
        }.get(fmt, image.content_type)

        if fmt == "jpg":
            pos = 2
            while pos + 4 < len(data):
                if data[pos] != 0xFF:
                    pos += 1
                    continue
                marker = data[pos + 1]
                if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
                    pos += 2
                    continue
                if pos + 4 > len(data):
                    break
                seg_len = int.from_bytes(data[pos + 2:pos + 4], "big")
                if marker in range(0xC0, 0xD0) and marker not in (0xC4, 0xC8, 0xCC):
                    image.progressive = marker == 0xC2
                    if seg_len >= 5 and pos + 9 < len(data):
                        try:
                            height = int.from_bytes(data[pos + 5:pos + 7], "big")
                            width = int.from_bytes(data[pos + 7:pos + 9], "big")
                            if width and height:
                                image.natural_width = width
                                image.natural_height = height
                                image.bpp = (len(data) * 8) / float(width * height)
                        except Exception:
                            pass
                if marker == 0xE0 and data[pos + 4:pos + 9] == b"JFIF\x00":
                    try:
                        units = data[pos + 11]
                        xd = int.from_bytes(data[pos + 12:pos + 14], "big")
                        yd = int.from_bytes(data[pos + 14:pos + 16], "big")
                        if units == 1 and xd:
                            image.dpi = (xd, yd)
                    except Exception:
                        pass
                if marker == 0xE1 and data[pos + 4:pos + 10] == b"Exif\x00\x00":
                    image.has_exif = True
                if marker == 0xE2 and b"ICC_PROFILE" in data[pos + 4:pos + 20]:
                    image.has_icc = True
                if marker == 0xDA:
                    break
                pos += 2 + seg_len
            if image.has_exif is None:
                image.has_exif = False
            if image.has_icc is None:
                image.has_icc = False
        elif fmt == "png":
            image.progressive = False
            image.has_exif = b"eXIf" in data[:4096]
            image.has_icc = b"iCCP" in data[:4096]
            try:
                width = int.from_bytes(data[16:20], "big")
                height = int.from_bytes(data[20:24], "big")
                if width and height:
                    image.natural_width = width
                    image.natural_height = height
                    image.bpp = (len(data) * 8) / float(width * height)
                pHYs = data.find(b"pHYs")
                if pHYs > 0:
                    ppux = int.from_bytes(data[pHYs + 4:pHYs + 8], "big")
                    ppuy = int.from_bytes(data[pHYs + 8:pHYs + 12], "big")
                    unit = data[pHYs + 12]
                    if unit == 1:
                        image.dpi = (ppux, ppuy)
            except Exception:
                pass
        elif fmt == "webp":
            image.has_exif = b"EXIF" in data[:2048]
            image.has_icc = b"ICCP" in data[:2048] or b"ICC_PROFILE" in data[:2048]
            image.progressive = False
            has_vpxx = False
            has_anim = False
            has_alpha = False
            pos = 12
            while pos + 8 <= len(data) and pos < 1048576:
                fourcc = data[pos:pos + 4]
                if not all(32 <= b < 127 for b in fourcc):
                    break
                size = int.from_bytes(data[pos + 4:pos + 8], "little")
                if size <= 0 or size > len(data):
                    break
                if fourcc == b"VP8X" and pos + 18 <= len(data):
                    has_vpxx = True
                    flags = data[pos + 8]
                    has_anim = has_anim or bool(flags & 0x02)
                    has_alpha = has_alpha or bool(flags & 0x10)
                    cw = int.from_bytes(data[pos + 12:pos + 15], "little") + 1
                    ch = int.from_bytes(data[pos + 15:pos + 18], "little") + 1
                    if 0 < cw < 100000 and 0 < ch < 100000:
                        image.natural_width = cw
                        image.natural_height = ch
                elif fourcc in (b"ANIM", b"ANMF"):
                    has_anim = True
                elif fourcc == b"ALPH":
                    has_alpha = True
                pos += 8 + size + (size & 1)
            if image.webp_version != "2.0":
                if b"webp2" in data[:128].lower():
                    image.webp_version = "2.0"
                elif has_vpxx or has_anim or has_alpha:
                    image.webp_version = "extended"
                else:
                    image.webp_version = "1.0"
        elif fmt == "gif":
            image.has_exif = False
            image.has_icc = b"ICCR" in data[:2048] or b"ICCP" in data[:2048]
            image.progressive = None
        elif fmt == "avif":
            image.has_exif = b"Exif" in data[:4096]
            image.has_icc = b"colr" in data[:4096] or b"iCCP" in data[:4096]

        if _HAS_PIL:
            try:
                with Image.open(__import__("io").BytesIO(data)) as pil_img:
                    if pil_img.format == "JPEG":
                        image.progressive = bool(pil_img.info.get("progressive") or pil_img.info.get("progression"))
                    exif = pil_img.getexif()
                    if exif:
                        image.has_exif = True
                        if image.dpi is None and pil_img.info.get("dpi"):
                            image.dpi = tuple(pil_img.info.get("dpi"))
                    elif image.has_exif is None:
                        image.has_exif = False
                    if pil_img.info.get("icc_profile"):
                        image.has_icc = True
                    if image.natural_width is None and pil_img.width:
                        image.natural_width = pil_img.width
                        image.natural_height = pil_img.height
                    if image.bpp is None and pil_img.width and pil_img.height:
                        image.bpp = (len(data) * 8) / float(pil_img.width * pil_img.height)
                    if pil_img.format == "WEBP":
                        if image.webp_version != "2.0":
                            if getattr(pil_img, "is_animated", False):
                                image.webp_version = "extended"
                            elif not image.webp_version:
                                image.webp_version = "1.0"
            except Exception:
                pass

        if image.has_exif is None:
            image.has_exif = False
        if image.has_icc is None:
            image.has_icc = False

    def check_image_sitemap(self):
        candidates = []
        for path in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap.txt"):
            candidates.append(urljoin(self.final_url, path))
        parsed_robots = urljoin(self.final_url, "/robots.txt")
        try:
            resp = self.session.get(parsed_robots, timeout=self.timeout)
            if resp.status_code == 200:
                for match in re.finditer(r"(?i)sitemap:\s*(\S+)", resp.text):
                    candidates.append(match.group(1))
        except requests.RequestException:
            pass
        checked = 0
        for sm_url in candidates:
            if checked >= 4:
                break
            try:
                resp = self.session.get(sm_url, timeout=self.timeout)
                checked += 1
                if resp.status_code == 200 and ("<urlset" in resp.text or "<sitemapindex" in resp.text):
                    if "<image:loc" in resp.text or "images" in resp.text.lower() and "<image" in resp.text:
                        self.image_sitemap = sm_url
                        return
                    if "<sitemapindex" not in resp.text and "<image" in resp.text:
                        self.image_sitemap = sm_url
                        return
            except requests.RequestException:
                continue

    def run_checks(self):
        self.categories = [
            self.check_formats(),
            self.check_format_support(),
            self.check_sizes(),
            self.check_responsive(),
            self.check_lazy(),
            self.check_accessibility(),
            self.check_seo(),
            self.check_optimization(),
            self.check_ai_optimization(),
            self.check_performance(),
            self.check_cdn(),
            self.check_caching(),
            self.check_metadata(),
        ]
        self.total_score = round(sum(c.earned for c in self.categories), 2)
        self.recommendations = []
        seen_recs = set()
        for cat in self.categories:
            for finding in cat.findings:
                if finding.status == "pass" or not finding.recommendation:
                    continue
                key = finding.recommendation.strip().lower()
                if key in seen_recs:
                    continue
                seen_recs.add(key)
                priority = "HIGH" if finding.status == "fail" else "MED"
                self.recommendations.append(f"[{priority}] {cat.title}: {finding.recommendation}")

    def _empty_category(self, key, title, maximum, reason):
        cat = CategoryResult(key, title, maximum)
        cat.add("Not applicable", maximum, maximum, reason)
        return cat

    def check_formats(self):
        title = "Image Formats"
        cat = CategoryResult("formats", title, 10)
        images = [i for i in self.images if not i.is_data]
        total = len(images)
        if total == 0:
            return self._empty_category("formats", title, 10, "No external images found on page")

        modern = [i for i in images if i.is_modern]
        legacy = [i for i in images if i.is_legacy]
        modern_pct = pct(len(modern), total)
        legacy_pct = pct(len(legacy), total)

        if modern_pct >= 60:
            e = 4
            msg = f"{len(modern)}/{total} images use modern formats ({modern_pct:.0f}%)"
        elif modern_pct >= 30:
            e = 3
            msg = f"{len(modern)}/{total} images use modern formats ({modern_pct:.0f}%)"
        elif modern_pct > 0:
            e = 2
            msg = f"Only {modern_pct:.0f}% modern format usage (WebP/AVIF/SVG)"
        else:
            e = 0
            msg = "No modern image formats (WebP/AVIF/SVG) detected"
        rec = "" if e >= 3 else "Convert JPEG/PNG images to WebP or AVIF for 25-50% smaller files"
        cat.add("Modern format usage", e, 4, msg, rec)

        legacy_set = sorted({i.fmt for i in legacy})
        if legacy_pct == 0:
            e = 3
            msg = "No legacy format dependency"
        elif legacy_pct <= 40:
            e = 2.5
            msg = f"Legacy formats ({', '.join(legacy_set)}) at {legacy_pct:.0f}%"
        elif legacy_pct <= 70:
            e = 1.5
            msg = f"Legacy formats dominate: {legacy_pct:.0f}% ({', '.join(legacy_set)})"
        else:
            e = 0.5
            msg = f"Almost all images are legacy formats ({', '.join(legacy_set) or 'unknown'})"
        rec = "" if e >= 2.5 else "Migrate remaining JPEG/PNG/GIF assets to modern formats with fallbacks"
        cat.add("Legacy format usage", e, 3, msg, rec)

        if legacy:
            formats = sorted({i.fmt for i in images})
            hint = f"Formats in use: {', '.join(formats)}"
            if "jpg" in formats or "jpeg" in formats:
                e = 0.75
                msg = hint + " - JPEG conversion candidates found"
                rec = "Serve AVIF/WebP variants via <picture> with JPEG fallback"
            else:
                e = 1.0
                msg = hint + " - conversion opportunity assessed"
                rec = "Evaluate remaining assets for modern format delivery"
        else:
            e = 1.5
            msg = "All images already in optimization-friendly formats"
            rec = ""
        cat.add("Format optimization", e, 1.5, msg, rec)

        distinct = sorted({i.fmt for i in images if i.fmt != "unknown"})
        diversity = len(distinct)
        if diversity >= 3:
            e = 0.75
            msg = f"Format diversity: {diversity} types ({', '.join(distinct)})"
            rec = "Consider consolidating formats to simplify delivery pipelines"
        elif diversity == 2:
            e = 1.25
            msg = f"Format diversity: {diversity} types ({', '.join(distinct)})"
            rec = ""
        else:
            e = 1.5
            msg = f"Single format in use ({distinct[0] if distinct else 'unknown'})"
            rec = ""
        cat.add("Format diversity", e, 1.5, msg, rec)
        return cat

    def check_format_support(self):
        title = "Format Support (AVIF/WebP 2.0)"
        cat = CategoryResult("format_support", title, 7)
        images = [i for i in self.images if not i.is_data]
        if not images:
            return self._empty_category("format_support", title, 7, "No images found")

        avif_served = [i for i in images if i.fmt == "avif"]
        avif_hints = [i for i in images if i.avif_hint]
        avif_sources = [
            s for s in self.soup.find_all("source")
            if "image/avif" in (s.get("type") or "").lower()
        ]
        avif_total = len({id(i) for i in avif_served} | {id(i) for i in avif_hints})

        if avif_served and avif_sources:
            e = 3.5
            msg = f"AVIF served ({len(avif_served)} asset(s)) with <picture> type negotiation ({len(avif_sources)} source(s))"
            rec = ""
        elif avif_served:
            e = 2.8
            msg = f"{len(avif_served)} AVIF asset(s) served; consider adding <picture> AVIF source fallbacks"
            rec = "Wrap AVIF candidates in <picture> with WebP/JPEG fallback for broader support"
        elif avif_sources or avif_hints:
            e = 1.8
            msg = f"AVIF referenced ({avif_total} hint(s), {len(avif_sources)} source tag(s)) but no AVIF body observed"
            rec = "Verify AVIF variants are actually generated and reachable"
        else:
            e = 0
            msg = "No AVIF format support detected (no AVIF files, sources, or parameters)"
            rec = "Adopt AVIF encoding - typically 30-50% smaller than JPEG at similar quality"
        cat.add("AVIF format support detection", e, 3.5, msg, rec)

        webps = [i for i in images if i.fmt == "webp"]
        webp2 = [i for i in webps if i.webp_version == "2.0"]
        extended = [i for i in webps if i.webp_version == "extended"]
        webp_share = pct(len(webps), len(images))

        if webp2:
            e = 3.5
            msg = f"WebP 2.0 detected on {len(webp2)} asset(s) (of {len(webps)} WebP)"
            rec = ""
        elif extended:
            e = 2.4
            msg = f"No WebP 2.0; {len(extended)}/{len(webps)} WebP use extended features (alpha/animation/VP8X)"
            rec = "WebP 2.0 is still emerging - current extended WebP features are well applied"
        elif webps:
            e = 2.0 if webp_share >= 30 else 1.4
            msg = f"{len(webps)} WebP 1.x asset(s) ({webp_share:.0f}% of images); WebP 2.0 not detected"
            rec = "Track WebP 2.0 support and negotiate via CDN format parameters when available"
        else:
            e = 0
            msg = "No WebP assets detected - WebP 2.0 support not applicable"
            rec = "Serve WebP images first; WebP 2.0 can follow when browser support lands"
        cat.add("WebP 2.0 detection", e, 3.5, msg, rec)
        return cat

    def check_sizes(self):
        title = "Image Sizes"
        cat = CategoryResult("sizes", title, 12)
        images = [i for i in self.images if not i.is_data]
        if not images:
            return self._empty_category("sizes", title, 12, "No images found")

        known = [i for i in images if i.size_bytes]
        data_bytes = sum(i.size_bytes or 0 for i in self.images if i.is_data)
        total_bytes = sum(i.size_bytes or 0 for i in known) + data_bytes

        if known:
            avg = total_bytes / max(len(known), 1)
            if avg <= 50 * 1024:
                e = 2
                msg = f"Average image size {human_size(avg)} - excellent"
            elif avg <= 150 * 1024:
                e = 1.5
                msg = f"Average image size {human_size(avg)} - acceptable"
            elif avg <= 400 * 1024:
                e = 0.9
                msg = f"Average image size {human_size(avg)} - too large"
            else:
                e = 0
                msg = f"Average image size {human_size(avg)} - critically large"
            rec = "" if e >= 1.5 else "Resize and recompress images; target under 100 KB average"
        else:
            e = 1
            msg = "Could not determine average image size (no Content-Length headers)"
            rec = "Ensure your server exposes Content-Length for image assets"
        cat.add("File size analysis", e, 2, msg, rec)

        if known:
            largest = max(known, key=lambda i: i.size_bytes or 0)
            lb = largest.size_bytes or 0
            if lb <= 300 * 1024:
                e = 1.5
                msg = f"Largest image {human_size(lb)} ({urlparse(largest.abs_url).path})"
            elif lb <= 1024 * 1024:
                e = 0.9
                msg = f"Largest image {human_size(lb)} - should be split or resized"
            else:
                e = 0
                msg = f"Largest image {human_size(lb)} - severe payload"
            rec = "" if e >= 1.5 else "Compress or art-direct the largest asset; use responsive variants"
        else:
            e = 0.75
            msg = "Largest image unknown"
            rec = ""
        cat.add("Largest image", e, 1.5, msg, rec)

        over100 = [i for i in known if (i.size_bytes or 0) > 100 * 1024]
        over500 = [i for i in known if (i.size_bytes or 0) > 500 * 1024]
        over1m = [i for i in known if (i.size_bytes or 0) > 1024 * 1024]
        e = 3.0
        parts = []
        rec_bits = []
        if over1m:
            e -= 1.5
            parts.append(f"{len(over1m)} over 1MB")
            rec_bits.append("recompress all images above 1MB immediately")
        if over500:
            e -= 0.9
            parts.append(f"{len(over500)} over 500KB")
            rec_bits.append("target sub-500KB for hero images")
        if over100:
            e -= 0.6
            parts.append(f"{len(over100)} over 100KB")
            rec_bits.append("compress or resize images above 100KB")
        if parts:
            msg = "Oversized images: " + ", ".join(parts)
            rec = "; ".join(rec_bits)
        else:
            msg = f"No oversized images among {len(known)} measured assets"
            rec = ""
        cat.add("Oversized image detection", max(e, 0), 3, msg, rec)

        if total_bytes:
            if total_bytes <= 300 * 1024:
                e = 2
                msg = f"Total image weight {human_size(total_bytes)} - lean"
            elif total_bytes <= 1024 * 1024:
                e = 1.5
                msg = f"Total image weight {human_size(total_bytes)} - reasonable"
            elif total_bytes <= 3 * 1024 * 1024:
                e = 0.9
                msg = f"Total image weight {human_size(total_bytes)} - heavy"
            else:
                e = 0
                msg = f"Total image weight {human_size(total_bytes)} - excessive"
            rec = "" if e >= 1.5 else "Lazy-load offscreen media, remove unused images, and enable CDN compression"
        else:
            e = 1
            msg = "Total image weight unknown"
            rec = "Configure Content-Length or image CDN reporting"
        cat.add("Total image weight", e, 2, msg, rec)

        page_total = self.page_bytes + total_bytes
        img_share = pct(total_bytes, page_total)
        if img_share <= 40:
            e = 1.5
            msg = f"Images are {img_share:.1f}% of page weight ({human_size(total_bytes)} of {human_size(page_total)})"
        elif img_share <= 65:
            e = 0.9
            msg = f"Images are {img_share:.1f}% of page weight - high share"
        else:
            e = 0.3
            msg = f"Images dominate the page at {img_share:.1f}% of total weight"
        rec = "" if e >= 1.5 else "Reduce image payload; aim for images under 40% of total page weight"
        cat.add("Image weight per page", e, 1.5, msg, rec)

        large_dims = []
        for image in images:
            nw = image.natural_width or 0
            nh = image.natural_height or 0
            try:
                dw = int(image.width) if image.width else 0
                dh = int(image.height) if image.height else 0
            except (TypeError, ValueError):
                dw = dh = 0
            if max(nw, dw) >= 2000 or max(nh, dh) >= 2000:
                large_dims.append(image)
        if large_dims:
            sample = large_dims[0]
            dims = f"{sample.natural_width or sample.width}x{sample.natural_height or sample.height}"
            e = 0.5
            msg = f"{len(large_dims)} image(s) at 2000px+ (e.g. {dims}) - resize for delivery"
            rec = "Resize images >=2000px via CDN transforms or responsive srcset variants"
        elif any(i.natural_width or i.width for i in images):
            e = 2
            msg = "No images at or above 2000px intrinsic/display dimensions"
            rec = ""
        else:
            e = 1
            msg = "Intrinsic dimensions unknown (image bodies not inspected)"
            rec = "Enable image probing so oversized dimensions can be detected"
        cat.add("Large dimension detection (>=2000px)", e, 2, msg, rec)
        return cat

    def check_responsive(self):
        title = "Responsive Images"
        cat = CategoryResult("responsive", title, 11)
        imgs = [i for i in self.images if i.tag == "img"]
        if not imgs:
            return self._empty_category("responsive", title, 11, "No <img> elements found")

        total = len(imgs)
        with_srcset = [i for i in imgs if i.has_srcset]
        with_sizes = [i for i in imgs if i.has_sizes]
        with_dims = [i for i in imgs if i.width and i.height]
        in_picture = [i for i in imgs if i.in_picture]
        responsive = [i for i in imgs if i.has_srcset or i.in_picture]

        srcset_pct = pct(len(with_srcset), total)
        if srcset_pct >= 70:
            e = 3
            msg = f"srcset on {len(with_srcset)}/{total} images ({srcset_pct:.0f}%)"
        elif srcset_pct >= 40:
            e = 2.1
            msg = f"srcset on {len(with_srcset)}/{total} images ({srcset_pct:.0f}%)"
        elif srcset_pct > 0:
            e = 1.1
            msg = f"srcset only on {srcset_pct:.0f}% of images"
        else:
            e = 0
            msg = "No srcset attributes found"
        rec = "" if e >= 2.1 else "Add srcset/sizes to serve correctly scaled variants per viewport"
        cat.add("srcset attribute usage", e, 3, msg, rec)

        picture_pct = pct(len(in_picture), total)
        rec = ""
        if picture_pct >= 40:
            e = 1.5
            msg = f"<picture> used for {len(in_picture)} images ({picture_pct:.0f}%)"
        elif picture_pct > 0:
            e = 0.9
            msg = f"<picture> used for {picture_pct:.0f}% of images"
        elif with_srcset:
            e = 0.75
            msg = "No <picture> elements, but srcset provides responsive delivery"
            rec = "Use <picture> when format negotiation (AVIF/WebP fallback) is needed"
        else:
            e = 0
            msg = "No <picture> elements found"
            rec = "Wrap art-directed or format-negotiated images in <picture>"
        if e >= 1.5:
            rec = ""
        cat.add("picture element usage", e, 1.5, msg, rec)

        sizes_pct = pct(len(with_sizes), total)
        rec = ""
        if sizes_pct >= 60:
            e = 1.5
            msg = f"sizes attribute on {sizes_pct:.0f}% of images"
        elif sizes_pct > 0:
            e = 0.9
            msg = f"sizes attribute only on {sizes_pct:.0f}% of images"
        elif not with_srcset:
            e = 0.6
            msg = "sizes not needed - no srcset present"
            rec = "Introduce srcset with sizes for responsive delivery"
        else:
            e = 0.3
            msg = "srcset present but sizes attribute missing on many images"
            rec = "Add sizes attributes so browsers pick the right srcset candidate"
        if with_srcset and sizes_pct < 60 and e < 1.5:
            rec = rec or "Add sizes attributes to all srcset images"
        elif e >= 1.5:
            rec = ""
        cat.add("sizes attribute usage", e, 1.5, msg, rec)

        dims_pct = pct(len(with_dims), total)
        if dims_pct >= 90:
            e = 2
            msg = f"width/height set on {dims_pct:.0f}% of images - layout stable"
        elif dims_pct >= 60:
            e = 1.4
            msg = f"width/height set on {dims_pct:.0f}% of images"
        elif dims_pct > 0:
            e = 0.7
            msg = f"width/height missing on many images ({dims_pct:.0f}% set)"
        else:
            e = 0
            msg = "No width/height attributes - layout shifts likely"
        rec = "" if e >= 1.4 else "Add explicit width/height (or aspect-ratio) to prevent Cumulative Layout Shift"
        cat.add("Width/height attributes", e, 2, msg, rec)

        missing_intrinsic = [i for i in imgs if not (i.width and i.height)]
        css_mismatch = 0
        if self.soup is not None:
            for tag in self.soup.find_all("img"):
                style = tag.get("style") or ""
                m = re.search(r"width\s*:\s*(\d+)px", style, re.I)
                if m and tag.get("width"):
                    try:
                        if int(m.group(1)) != int(tag.get("width")):
                            css_mismatch += 1
                    except (TypeError, ValueError):
                        pass
        if css_mismatch:
            e = 0.5
            msg = f"{css_mismatch} image(s) with CSS display width differing from HTML width attribute"
            rec = "Align CSS display size with the declared intrinsic width/height attributes"
        elif missing_intrinsic:
            e = 0.7
            msg = f"{len(missing_intrinsic)}/{total} <img> missing intrinsic width/height dimensions"
            rec = "Declare intrinsic width/height on every <img> so CSS sizing cannot drift"
        else:
            e = 1.5
            msg = "All <img> elements declare intrinsic dimensions; no CSS/HTML width mismatch"
            rec = ""
        cat.add("Intrinsic dimensions & CSS match", e, 1.5, msg, rec)

        resp_pct = pct(len(responsive), total)
        if resp_pct >= 70:
            e = 1.5
            msg = f"{resp_pct:.0f}% of images are responsive (srcset or <picture>)"
        elif resp_pct >= 40:
            e = 1.0
            msg = f"{resp_pct:.0f}% of images are responsive"
        elif resp_pct > 0:
            e = 0.45
            msg = f"Only {resp_pct:.0f}% of images adapt to viewports"
        else:
            e = 0
            msg = "No responsive images detected"
        rec = "" if e >= 1.5 else "Deliver one responsive image source set for every content image"
        cat.add("Responsive image detection", e, 1.5, msg, rec)
        return cat

    def check_lazy(self):
        title = "Lazy Loading"
        cat = CategoryResult("lazy", title, 7)
        imgs = [i for i in self.images if i.tag == "img"]
        if not imgs:
            return self._empty_category("lazy", title, 7, "No <img> elements found")

        total = len(imgs)
        lazy = [i for i in imgs if i.loading == "lazy"]
        eager = [i for i in imgs if i.loading == "eager"]
        none_attr = [i for i in imgs if not i.loading]
        lazy_pct = pct(len(lazy), total)

        if lazy_pct >= 60:
            e = 2.5
            msg = f"loading=\"lazy\" on {len(lazy)}/{total} images ({lazy_pct:.0f}%)"
        elif lazy_pct >= 30:
            e = 1.8
            msg = f"loading=\"lazy\" on {lazy_pct:.0f}% of images"
        elif lazy_pct > 0:
            e = 0.9
            msg = f"Lazy loading only on {lazy_pct:.0f}% of images"
        else:
            e = 0
            msg = "No loading=\"lazy\" attributes found"
        rec = "" if e >= 1.8 else "Add loading=\"lazy\" to images below the fold to defer offscreen downloads"
        cat.add("loading=\"lazy\" attribute usage", e, 2.5, msg, rec)

        if lazy_pct >= 50:
            e = 2
            msg = f"Lazy loading coverage {lazy_pct:.0f}%"
        elif lazy_pct >= 25:
            e = 1.3
            msg = f"Lazy loading coverage {lazy_pct:.0f}% - partial"
        elif lazy_pct > 0:
            e = 0.7
            msg = f"Lazy loading coverage low at {lazy_pct:.0f}%"
        else:
            e = 0
            msg = "No lazy loading coverage"
        rec = "" if e >= 2 else "Raise lazy coverage for non-critical images (target 60%+ on content pages)"
        cat.add("Lazy loading coverage percentage", e, 2, msg, rec)

        if eager:
            eager_ok = all(i.index < 3 for i in eager) or len(eager) <= 3
            if eager_ok:
                e = 1
                msg = f"{len(eager)} image(s) marked loading=\"eager\" (hero/critical assets)"
            else:
                e = 0.5
                msg = f"{len(eager)} eager images - some may not need priority loading"
            rec = "" if e >= 1 else "Restrict loading=\"eager\" to above-the-fold hero images only"
        elif none_attr:
            e = 0.75
            msg = f"No explicit eager flags; {len(none_attr)} image(s) default to eager loading"
            rec = "Set loading explicitly: eager for hero, lazy for the rest"
        else:
            e = 1
            msg = "Loading strategy fully explicit"
            rec = ""
        cat.add("loading=\"eager\" usage", e, 1, msg, rec)

        fold_cut = min(3, total)
        below = imgs[fold_cut:]
        if below:
            below_lazy = [i for i in below if i.loading == "lazy"]
            cov = pct(len(below_lazy), len(below))
            if cov >= 80:
                e = 1.5
                msg = f"{cov:.0f}% of below-the-fold images are lazy ({len(below_lazy)}/{len(below)})"
            elif cov >= 40:
                e = 0.9
                msg = f"Below-the-fold lazy coverage {cov:.0f}%"
            else:
                e = 0.3
                msg = f"Below-the-fold images mostly eager ({cov:.0f}% lazy)"
            rec = "" if e >= 1.5 else f"Add loading=\"lazy\" to the {len(below) - len(below_lazy)} below-fold image(s)"
        else:
            e = 1.5
            msg = "All images appear above the fold"
            rec = ""
        cat.add("Below-the-fold image lazy loading", e, 1.5, msg, rec)
        return cat

    def check_accessibility(self):
        title = "Accessibility"
        cat = CategoryResult("accessibility", title, 9)
        imgs = [i for i in self.images if i.tag == "img"]
        if not imgs:
            return self._empty_category("accessibility", title, 9, "No <img> elements found")

        total = len(imgs)
        has_alt = [i for i in imgs if i.alt is not None]
        alt_pct = pct(len(has_alt), total)

        if alt_pct >= 95:
            e = 3.5
            msg = f"Alt text present on {alt_pct:.0f}% of images"
        elif alt_pct >= 70:
            e = 2.5
            msg = f"Alt text present on {alt_pct:.0f}% of images"
        elif alt_pct > 0:
            e = 1.0
            msg = f"Alt text missing on {total - len(has_alt)} image(s) ({alt_pct:.0f}% covered)"
        else:
            e = 0
            msg = "No alt attributes found at all"
        rec = "" if e >= 2.5 else f"Add descriptive alt text to the {total - len(has_alt)} image(s) missing it"
        cat.add("Alt text completeness", e, 3.5, msg, rec)

        non_empty = [i for i in has_alt if (i.alt or "").strip()]
        decorative = [i for i in has_alt if (i.alt or "").strip() == "" or (i.alt or "").lower() in ("none", "n/a")]
        generic = [
            i for i in non_empty
            if len((i.alt or "").split()) < 3 or (i.alt or "").strip().lower() in GENERIC_ALT_WORDS
            or (i.alt or "").strip().lower().split()[0] in GENERIC_ALT_WORDS
            and len((i.alt or "").split()) <= 2
        ]
        descriptive = [i for i in non_empty if i not in generic]
        quality_pool = non_empty or []
        if quality_pool:
            good_ratio = pct(len(descriptive), len(quality_pool))
            if good_ratio >= 75:
                e = 2.5
                msg = f"{len(descriptive)}/{len(quality_pool)} alt texts are descriptive"
            elif good_ratio >= 45:
                e = 1.7
                msg = f"Alt quality mixed - {good_ratio:.0f}% descriptive"
            else:
                e = 0.7
                msg = f"Most alt texts are generic ({good_ratio:.0f}% descriptive)"
            rec = "" if e >= 1.7 else "Write specific alt text (subject + context), 3+ meaningful words"
        else:
            e = 1.25
            msg = "No non-empty alt texts to evaluate"
            rec = "Provide meaningful alt text for informative images"
        cat.add("Alt text quality", e, 2.5, msg, rec)

        soup_imgs = self.soup.find_all("img")
        role_present = any(
            (img.get("role") or "").lower() in ("presentation", "none")
            for img in soup_imgs
        )
        aria_hidden = any(
            (img.get("aria-hidden") or "").lower() == "true"
            for img in soup_imgs
        )
        dec_count = len(decorative) + (1 if role_present else 0) + (1 if aria_hidden else 0)
        if decorative or role_present or aria_hidden:
            e = 1.5
            msg = f"{dec_count} decorative image(s) handled via empty alt, role, or aria-hidden"
            rec = ""
        elif any((i.alt or "").strip() for i in has_alt):
            e = 0.75
            msg = "No explicitly marked decorative images - verify none are mislabeled"
            rec = "Mark purely decorative images with alt=\"\" or role=\"presentation\""
        else:
            e = 0.5
            msg = "Decorative image handling not detected"
            rec = "Use alt=\"\" for decorative images so screen readers skip them"
        cat.add("Decorative image handling", e, 1.5, msg, rec)

        figures = self.soup.find_all("figure")
        figcaps = self.soup.find_all("figcaption")
        if figures and figcaps:
            e = 1.5
            msg = f"{len(figures)} <figure> and {len(figcaps)} <figcaption> used for image context"
            rec = ""
        elif figures:
            e = 0.75
            msg = f"{len(figures)} <figure> elements but no <figcaption>"
            rec = "Pair figures with figcaptions to caption images accessibly"
        elif imgs:
            e = 0.25
            msg = "No <figure>/<figcaption> structure for images"
            rec = "Wrap meaningful images and diagrams in <figure> with <figcaption>"
        else:
            e = 1.5
            msg = "Not applicable"
            rec = ""
        cat.add("Image figure/figcaption usage", e, 1.5, msg, rec)
        return cat

    def check_seo(self):
        title = "SEO"
        cat = CategoryResult("seo", title, 9)
        images = [i for i in self.images if not i.is_data and i.abs_url]
        if not images:
            return self._empty_category("seo", title, 9, "No image URLs found")

        def filename_of(url):
            path = urlparse(url).path
            return os.path.basename(path) or path

        descriptive = 0
        generic_names = []
        for image in images:
            name = filename_of(image.abs_url)
            stem = re.sub(r"\.[a-z0-9]+$", "", name, flags=re.I)
            if GENERIC_NAME_RE.match(stem) or stem.isdigit() or len(stem) < 4:
                generic_names.append(name)
            elif re.search(r"[-_]", stem) or len(stem.split()) >= 2:
                descriptive += 1
            elif len(stem) >= 8:
                descriptive += 1
            else:
                generic_names.append(name)
        total_named = len(images)
        desc_pct = pct(descriptive, total_named)
        if desc_pct >= 75:
            e = 3
            msg = f"{descriptive}/{total_named} filenames are descriptive ({desc_pct:.0f}%)"
        elif desc_pct >= 40:
            e = 2
            msg = f"Filename quality mixed - {desc_pct:.0f}% descriptive"
        else:
            e = 0.5
            msg = f"Generic filenames dominate (examples: {', '.join(generic_names[:3]) or 'n/a'})"
        rec = "" if e >= 2 else "Rename assets with hyphenated, descriptive keywords (e.g. red-running-shoes.webp)"
        cat.add("Image filenames", e, 3, msg, rec)

        exts = sorted({i.ext for i in images if i.ext})
        modern_ext = [x for x in exts if x in MODERN_FORMATS]
        bad_ext = [x for x in exts if x in ("jpg", "jpeg", "gif", "bmp")]
        if modern_ext and not bad_ext:
            e = 1.5
            msg = f"Modern extensions in use: {', '.join(exts)}"
            rec = ""
        elif modern_ext:
            e = 1.05
            msg = f"Mixed extensions: {', '.join(exts)}"
            rec = "Standardize on modern extensions (.webp/.avif) with explicit fallbacks"
        elif exts:
            e = 0.6
            msg = f"Legacy extensions only: {', '.join(exts)}"
            rec = "Serve WebP/AVIF files and update references accordingly"
        else:
            e = 0.75
            msg = "Extensions not determinable from URLs"
            rec = ""
        cat.add("Image file extension usage", e, 1.5, msg, rec)

        imgs = [i for i in self.images if i.tag == "img"]
        with_title = [i for i in imgs if i.title]
        title_pct = pct(len(with_title), len(imgs)) if imgs else 0
        if not imgs:
            e = 0.5
            msg = "No images to evaluate for title attributes"
            rec = ""
        elif title_pct >= 50:
            e = 1.0
            msg = f"title attribute on {title_pct:.0f}% of images"
            rec = ""
        elif title_pct > 0:
            e = 0.6
            msg = f"title attribute on {title_pct:.0f}% of images"
            rec = "Add title attributes for tooltips on linked/icon images where helpful"
        else:
            e = 0.3
            msg = "No title attributes on images"
            rec = "Consider title attributes for images inside links or icon buttons"
        cat.add("Image title attribute", e, 1, msg, rec)

        if self.image_sitemap:
            e = 1.5
            msg = f"Image sitemap found at {self.image_sitemap}"
            rec = ""
        else:
            e = 0
            msg = "No image entries detected in sitemap"
            rec = "Include <image:loc> entries in your sitemap so images get indexed"
        cat.add("Image sitemap detection", e, 1.5, msg, rec)

        if self.jsonld_imageobject and self.og_image:
            e = 2
            msg = "ImageObject JSON-LD and og:image both present"
            rec = ""
        elif self.jsonld_imageobject:
            e = 1.6
            msg = "ImageObject structured data (JSON-LD) detected; og:image missing"
            rec = "Add og:image meta tag for social sharing previews"
        elif self.og_image:
            e = 1.0
            msg = "og:image present but no ImageObject structured data"
            rec = "Add ImageObject JSON-LD for richer image search results"
        elif self.twitter_image:
            e = 0.5
            msg = "twitter:image present but no og:image or ImageObject"
            rec = "Add og:image and ImageObject JSON-LD alongside twitter:image"
        else:
            e = 0
            msg = "No ImageObject structured data, og:image, or twitter:image"
            rec = "Add ImageObject JSON-LD and og:image meta tags"
        cat.add("Image structured data (ImageObject)", e, 2, msg, rec)
        return cat

    def check_optimization(self):
        title = "Image Optimization"
        cat = CategoryResult("optimization", title, 8)
        images = [i for i in self.images if not i.is_data]
        if not images:
            return self._empty_category("optimization", title, 8, "No images found")

        fmts = {i.fmt for i in images}
        uncompressed = fmts & {"bmp", "tiff", "tif"}
        compressed = [i for i in images if i.fmt in COMPRESSED_FORMATS]
        opt_headers = any(
            "content-encoding" in h or h in ("cf-image", "x-imgix", "x-cache")
            for i in images
            for h in i.cdn_headers
        ) or any(i.content_encoding for i in images)
        auto_count = len([i for i in images if i.has_auto_opt])
        comp_ratio = pct(len(compressed), len(images))
        if uncompressed:
            e = 0.8
            msg = f"Uncompressed formats present: {', '.join(sorted(uncompressed))}"
            rec = "Convert BMP/TIFF assets to WebP or AVIF"
        elif comp_ratio >= 90:
            e = 2.5
            msg = f"{comp_ratio:.0f}% of images use compressed formats"
            rec = ""
        else:
            e = 1.6
            msg = f"{comp_ratio:.0f}% compressed format coverage"
            rec = "Deliver all raster images in compressed formats"
        if opt_headers and e < 2.5:
            msg += "; server/CDN image compression headers observed"
        if auto_count:
            msg += f"; {auto_count} asset(s) use automatic quality/format parameters"
        cat.add("Compression detection", e, 2.5, msg, rec)

        measured = [i for i in images if i.bpp is not None]
        over_delivered = []
        for image in images:
            if not image.natural_width or not image.natural_height:
                continue
            try:
                dw = int(image.width) if image.width else None
                dh = int(image.height) if image.height else None
            except (TypeError, ValueError):
                dw = dh = None
            if dw and dh and dw > 0 and dh > 0:
                if image.natural_width >= dw * 2 and image.natural_height >= dh * 2:
                    over_delivered.append(image)
        if measured:
            goods = overs = unders = 0
            for image in measured:
                good, over, under = assess_bpp(image.fmt, image.bpp)
                if good:
                    goods += 1
                if over:
                    overs += 1
                if under:
                    unders += 1
            ratio = pct(goods, len(measured))
            if ratio >= 70 and not overs:
                e = 2.5
                msg = f"Estimated quality well balanced across {len(measured)} sampled image(s)"
                rec = ""
            elif overs:
                e = 1.2
                msg = f"{overs} image(s) appear poorly compressed (high bits-per-pixel)"
                rec = "Re-encode over-quality images; JPEG quality 75-85 is usually sufficient"
            elif unders:
                e = 1.2
                msg = f"{unders} image(s) look over-compressed (visible artifacts likely)"
                rec = "Raise quality slightly on over-compressed assets"
            else:
                e = 1.7
                msg = f"Quality estimates acceptable ({ratio:.0f}% in target range)"
                rec = ""
            if over_delivered:
                e = min(e, 1.8)
                msg += f"; {len(over_delivered)} image(s) served at 2x+ their displayed dimensions"
                rec = rec or "Serve images no larger than their rendered CSS dimensions"
        else:
            e = 1.25
            msg = "Quality estimation requires image downloads; limited sample available"
            rec = "Serve images with measurable dimensions so quality can be assessed"
        cat.add("Image quality estimation", e, 2.5, msg, rec)

        jpegs = [i for i in images if i.fmt == "jpg" and i.deep]
        if jpegs:
            prog = [i for i in jpegs if i.progressive]
            ratio = pct(len(prog), len(jpegs))
            if ratio >= 80:
                e = 1.5
                msg = f"{len(prog)}/{len(jpegs)} sampled JPEGs are progressive"
                rec = ""
            elif ratio > 0:
                e = 0.9
                msg = f"Only {ratio:.0f}% of sampled JPEGs are progressive"
                rec = "Re-encode remaining baseline JPEGs as progressive (-progressive)"
            else:
                e = 0.3
                msg = "No progressive JPEGs detected in sample"
                rec = "Enable progressive encoding for all JPEG assets"
        elif any(i.fmt == "jpg" for i in images):
            e = 0.9
            msg = "JPEGs present but not deep-sampled for progressive check"
            rec = "Use progressive JPEG encoding"
        else:
            e = 1.5
            msg = "No JPEG assets - progressive check not applicable"
            rec = ""
        cat.add("Progressive JPEG detection", e, 1.5, msg, rec)

        deep = [i for i in images if i.deep and i.md5]
        groups = getattr(self, "duplicate_groups", [])
        dup_urls = set()
        for group in groups:
            dup_urls.update(group)
        if deep:
            dup_count = len(dup_urls)
            if dup_count == 0:
                e = 1.5
                msg = f"No duplicate images found across {len(deep)} deep-scanned asset(s)"
                rec = ""
            else:
                e = 0.4
                msg = f"{dup_count} duplicate image reference(s) in {len(groups)} group(s)"
                rec = "Deduplicate repeated assets and serve one canonical URL"
        else:
            e = 0.75
            msg = "Deduplication scan limited (no downloadable image bodies)"
            rec = "Ensure images are publicly fetchable for dedup analysis"
        cat.add("Image deduplication detection", e, 1.5, msg, rec)
        return cat

    def check_ai_optimization(self):
        title = "AI Optimization"
        cat = CategoryResult("ai", title, 5)
        images = [i for i in self.images if not i.is_data and i.abs_url]
        if not images:
            return self._empty_category("ai", title, 5, "No image URLs to scan for optimization parameters")

        auto = [i for i in images if i.has_auto_opt]
        ai_tf = [i for i in images if i.has_ai_transform]
        smart = [i for i in images if i.has_smart_crop]

        auto_pct = pct(len(auto), len(images))
        if auto_pct >= 60:
            e = 2
            msg = f"Automatic quality/format optimization on {auto_pct:.0f}% of images (q_auto/f_auto/quality=auto)"
            rec = ""
        elif auto_pct >= 30:
            e = 1.4
            msg = f"Automatic optimization parameters on {auto_pct:.0f}% of images"
            rec = "Apply q_auto/f_auto (or quality=auto/format=auto) to remaining image URLs"
        elif auto_pct > 0:
            e = 0.8
            msg = f"Only {len(auto)} image(s) use automatic optimization parameters"
            rec = "Adopt automatic quality/format parameters across your image CDN"
        else:
            e = 0
            msg = "No automatic quality/format optimization parameters detected"
            rec = "Use automatic quality/format parameters (q_auto / quality=auto / f_auto)"
        cat.add("Automatic image optimization parameters", e, 2, msg, rec)

        ai_pct = pct(len(ai_tf), len(images))
        if ai_pct >= 30:
            e = 2
            msg = f"AI/generative transforms on {ai_pct:.0f}% of images (enhance/upscale/gen_fill/ai=...)"
            rec = ""
        elif ai_pct > 0:
            e = 1.2
            msg = f"AI transform parameters found on {len(ai_tf)} image(s)"
            rec = "Extend AI enhancement/upscale transforms across more source assets"
        else:
            e = 0
            msg = "No AI or generative image transform parameters detected"
            rec = "Consider AI pipelines (e_upscale, e_enhance, ai=enhance) for undersized sources"
        cat.add("AI enhancement & generative transforms", e, 2, msg, rec)

        smart_pct = pct(len(smart), len(images))
        if smart_pct >= 40:
            e = 1
            msg = f"Smart/face-aware cropping on {smart_pct:.0f}% of images"
            rec = ""
        elif smart_pct > 0:
            e = 0.6
            msg = f"Smart cropping used on {len(smart)} image(s)"
            rec = "Use face/smart-aware cropping (crop=faces, fit=facearea, g_face) site-wide"
        else:
            e = 0
            msg = "No smart or face-aware crop parameters detected"
            rec = "Use face/smart-aware cropping (crop=faces, fit=facearea, g_face) for responsive crops"
        cat.add("Smart crop / face-aware transforms", e, 1, msg, rec)
        return cat

    def check_performance(self):
        title = "Performance Impact"
        cat = CategoryResult("performance", title, 7)
        imgs = [i for i in self.images if i.tag == "img"]
        if not imgs:
            return self._empty_category("performance", title, 7, "No <img> elements found")

        count = len(imgs)
        if count <= 15:
            e = 1.5
            msg = f"{count} images on page - light"
        elif count <= 30:
            e = 1.1
            msg = f"{count} images on page - moderate"
        elif count <= 50:
            e = 0.6
            msg = f"{count} images on page - heavy"
        else:
            e = 0.15
            msg = f"{count} images on page - excessive"
        rec = "" if e >= 1.1 else "Trim decorative assets, sprite repeated icons, or paginate galleries"
        cat.add("Image count per page", e, 1.5, msg, rec)

        total_bytes = sum(i.size_bytes or 0 for i in self.images if not i.is_data)
        data_bytes = sum(i.size_bytes or 0 for i in self.images if i.is_data)
        total_bytes += data_bytes
        page_total = self.page_bytes + total_bytes
        share = pct(total_bytes, page_total)
        if share <= 35:
            e = 1.5
            msg = f"Images account for {share:.1f}% of page weight"
        elif share <= 55:
            e = 1
            msg = f"Images account for {share:.1f}% of page weight - high"
        else:
            e = 0.3
            msg = f"Images account for {share:.1f}% of page weight - dominant cost"
        rec = "" if e >= 1.5 else "Cut image bytes: compress, resize, modern formats, CDN transforms"
        cat.add("Image weight percentage of page", e, 1.5, msg, rec)

        fold = imgs[:min(3, len(imgs))]
        blocking = [
            i for i in fold
            if i.loading != "lazy" and i.decoding != "async" and i.fetchpriority not in ("low",)
        ]
        preloads = [
            link for link in self.soup.find_all("link")
            if "preload" in (link.get("rel") or "") and (link.get("as") or "") == "image"
        ]
        hero_preloaded = bool(preloads)
        if not fold:
            e = 1.5
            msg = "No above-the-fold images detected"
            rec = ""
        else:
            blocking_score = len(blocking)
            if hero_preloaded and blocking_score > 0:
                blocking_score = max(blocking_score - 1, 0)
            if blocking_score == 0:
                e = 1.5
                msg = "No render-blocking image patterns above the fold"
                if hero_preloaded:
                    msg += " (hero image preloaded)"
                rec = ""
            elif blocking_score <= 2:
                e = 0.9
                msg = f"{len(blocking)} above-the-fold image(s) may delay first paint"
                if hero_preloaded:
                    msg += "; hero preload already in place"
                rec = "Preload the LCP hero image and mark non-critical images async"
            else:
                e = 0.3
                msg = f"{len(blocking)} above-the-fold images compete for initial bandwidth"
                rec = "Inline critical visuals or preload only the true LCP image"
        cat.add("Render-blocking images", e, 1.5, msg, rec)

        cut = min(3, len(imgs))
        above, below = imgs[:cut], imgs[cut:]
        good_order = 0
        order_total = 0
        for image in above:
            order_total += 1
            if image.loading in (None, "eager") or image.fetchpriority == "high":
                good_order += 1
        for image in below:
            order_total += 1
            if image.loading == "lazy":
                good_order += 1
        if order_total:
            ratio = pct(good_order, order_total)
            if ratio >= 80:
                e = 1.5
                msg = f"Loading order optimized ({ratio:.0f}% correct priority)"
                rec = ""
            elif ratio >= 50:
                e = 1.0
                msg = f"Loading order partially optimized ({ratio:.0f}%)"
                rec = "Prioritize above-the-fold images and defer the rest"
            else:
                e = 0.35
                msg = f"Poor image loading order ({ratio:.0f}% correct)"
                rec = "Set fetchpriority=high on hero image and loading=lazy elsewhere"
        else:
            e = 0.75
            msg = "Loading order not determinable"
            rec = ""
        cat.add("Image loading order", e, 1.5, msg, rec)

        prefetch_hints = [
            link for link in self.soup.find_all("link")
            if "prefetch" in (link.get("rel") or "") and (link.get("as") or "") == "image"
        ]
        if preloads:
            e = 1
            msg = f"{len(preloads)} LCP hero preload hint(s) (link rel=preload as=image)"
            if prefetch_hints:
                msg += f"; {len(prefetch_hints)} image prefetch hint(s)"
            rec = ""
        elif prefetch_hints:
            e = 0.5
            msg = f"{len(prefetch_hints)} image prefetch hint(s) but no preload for the LCP hero"
            rec = "Use rel=preload as=image for the LCP hero instead of prefetch"
        else:
            e = 0
            msg = "No preload/prefetch hints for LCP hero images"
            rec = "Add <link rel=preload as=image> for the LCP hero image"
        cat.add("LCP hero preload/prefetch hints", e, 1, msg, rec)
        return cat

    def check_cdn(self):
        title = "CDN & Delivery"
        cat = CategoryResult("cdn", title, 5)
        images = [i for i in self.images if not i.is_data and i.abs_url]
        if not images:
            return self._empty_category("cdn", title, 5, "No image URLs found")

        cdn_patterns = [
            "cloudinary", "imgix", "akamaized", "edgekey", "edgesuite", "akamai",
            "cloudfront", "fastly", "bunny.net", "cdn.", "imgcdn", "imagekit",
            "pixboost", "swiperizer", "wp.com", "netlify", "vercel", "shopifycdn",
            "fbcdn", "cdninstagram", "gstatic", "unsplash", "pexels", "media.",
            "cdn-cgi", "imgix",
        ]
        cdn_hits = []
        for image in images:
            host = urlparse(image.abs_url).netloc.lower()
            if any(pat in host for pat in cdn_patterns):
                cdn_hits.append(host)
            if "cdn-cgi/image/" in image.abs_url.lower() and host not in cdn_hits:
                cdn_hits.append(host)
            if image.cdn_headers and any(
                h in ("cf-cache-status", "x-cache", "x-fastly-request-id", "akamai-grn", "x-amz-cf-id")
                for h in image.cdn_headers
            ):
                if host not in cdn_hits:
                    cdn_hits.append(host)
        cdn_ratio = pct(len(set(cdn_hits)), len({urlparse(i.abs_url).netloc for i in images}))
        distinct_hosts = sorted(set(urlparse(i.abs_url).netloc for i in images))
        if len(set(cdn_hits)) >= 1 and (len(distinct_hosts) == 1 or cdn_ratio >= 50):
            e = 2
            detected = ", ".join(sorted(set(cdn_hits))[:3])
            msg = f"Image CDN detected: {detected}"
            rec = ""
        elif cdn_hits:
            e = 1.3
            msg = f"Partial CDN usage: {', '.join(sorted(set(cdn_hits))[:3])}"
            rec = "Serve all images through a single CDN with edge caching"
        else:
            e = 0
            msg = "No image CDN detected"
            rec = "Put images behind a CDN (Cloudinary, Fastly, CloudFront, imgix...)"
        cat.add("Image CDN detection", e, 2, msg, rec)

        resized = [i for i in images if i.has_resize_param]
        auto_fmt = [i for i in images if i.has_auto_format]
        resize_pct = pct(len(resized), len(images))
        fmt_pct = pct(len(auto_fmt), len(images))
        if resize_pct >= 50 and fmt_pct >= 40:
            e = 1
            msg = f"On-the-fly transforms on {resize_pct:.0f}% of images; auto-format on {fmt_pct:.0f}%"
            rec = ""
        elif resized and auto_fmt:
            e = 0.7
            msg = f"CDN optimization partial (resize {resize_pct:.0f}%, auto-format {fmt_pct:.0f}%)"
            rec = "Add width/height/dpr and auto=format parameters to remaining image URLs"
        elif resized or auto_fmt:
            e = 0.5
            which = "resize parameters" if resized else "auto-format delivery"
            msg = f"{which} present ({max(resize_pct, fmt_pct):.0f}% of images) but incomplete"
            rec = "Combine on-the-fly resizing with auto format negotiation on your image CDN"
        elif cdn_hits:
            e = 0.3
            msg = "CDN present but no on-the-fly transform or auto-format parameters observed"
            rec = "Enable edge resizing and format negotiation (f_auto / auto=format) on the CDN"
        else:
            e = 0
            msg = "No image CDN optimization signals detected"
            rec = "Use an image CDN with on-the-fly resize and automatic format delivery"
        cat.add("Image CDN optimization", e, 1, msg, rec)

        modern_tf = [i for i in images if i.has_resize_param or i.has_auto_format]
        modern_pct = pct(len(modern_tf), len(images))
        if modern_pct >= 50:
            e = 1
            msg = f"Modern CDN transform params (w/h/q/fm/auto=format/dpr) on {modern_pct:.0f}% of images"
            rec = ""
        elif modern_pct > 0:
            e = 0.6
            msg = f"Modern transform params on {len(modern_tf)}/{len(images)} images ({modern_pct:.0f}%)"
            rec = "Extend w/h/q/fm/auto=format/dpr params across all image URLs"
        else:
            e = 0
            msg = "No modern CDN image transform parameters (w=, h=, q=, fm=, auto=format, dpr=)"
            rec = "Add w, h, q, fm and dpr parameters so the CDN resizes and re-encodes at the edge"
        cat.add("Modern CDN transform parameters", e, 1, msg, rec)

        encoding = [i for i in images if i.content_encoding]
        compress_signals = encoding[:]
        for image in images:
            if any(h in ("cf-cache-status", "x-cache", "age") for h in image.cdn_headers) and image.fetch_ok:
                compress_signals.append(image)
            if image.fmt in ("svg",) and image.fetch_ok:
                compress_signals.append(image)
        if encoding:
            e = 1
            msg = f"Content-Encoding observed on {len(encoding)} image response(s)"
            rec = ""
        elif compress_signals:
            e = 0.7
            msg = "CDN/edge delivery signals present (varnish/edge caching headers)"
            rec = "Verify Accept-Encoding negotiation for SVG/text-like images"
        else:
            probed_count = len([i for i in images if i.fetch_ok])
            if probed_count:
                e = 0.3
                msg = "No compression or edge headers on image responses"
                rec = "Enable gzip/brotli for SVG and ensure CDN compresses transfer encoding"
            else:
                e = 0.5
                msg = "Image responses not probed for compression headers"
                rec = "Enable transfer compression at the CDN/origin for image endpoints"
        cat.add("Image compression headers", e, 1, msg, rec)
        return cat

    def check_caching(self):
        title = "Caching Analysis"
        cat = CategoryResult("caching", title, 6)
        images = [i for i in self.images if not i.is_data and i.abs_url]
        if not images:
            return self._empty_category("caching", title, 6, "No image URLs found")
        probed = [i for i in images if i.fetch_ok]
        if not probed:
            cat.add("Cache-Control policy", 0.5, 2, "No image responses probed for cache headers", "Enable probing so Cache-Control policies can be verified")
            cat.add("Cache validators", 0.3, 1.5, "Validators unknown without response headers", "Expose ETag or Last-Modified on image responses")
            cat.add("CDN cache hit signals", 0.3, 1.5, "Cache hit status unknown without response headers", "Serve images from an edge cache with HIT tracking headers")
            cat.add("Cache freshness & Vary", 0.2, 1, "Vary/freshness unknown without response headers", "Set Vary: Accept and long-lived freshness directives for images")
            return cat

        with_cc = [i for i in probed if i.cache_control]
        year_ok = [i for i in probed if i.cache_immutable or (i.cache_max_age or 0) >= 31536000]
        day_ok = [i for i in probed if i.cache_immutable or (i.cache_max_age or 0) >= 86400]
        hour_ok = [i for i in probed if i.cache_immutable or (i.cache_max_age or 0) >= 3600]
        no_store = [i for i in probed if i.cache_no_store]
        pct_year = pct(len(year_ok), len(probed))
        pct_day = pct(len(day_ok), len(probed))
        pct_hour = pct(len(hour_ok), len(probed))
        pct_nostore = pct(len(no_store), len(probed))

        if pct_year >= 70:
            e = 2
            msg = f"{pct_year:.0f}% of images use immutable or max-age of 1 year+"
            rec = ""
        elif pct_day >= 60:
            e = 1.6
            msg = f"{pct_day:.0f}% of images cached for 1 day or longer"
            rec = "Use max-age=31536000, immutable for fingerprinted image assets"
        elif pct_hour >= 50:
            e = 1.1
            msg = f"{pct_hour:.0f}% of images have max-age of 1 hour+"
            rec = "Extend image cache lifetimes; immutable + 1 year for versioned assets"
        elif with_cc:
            e = 0.5
            msg = f"Cache-Control present on {len(with_cc)}/{len(probed)} images but lifetimes are short"
            rec = "Add Cache-Control: public, max-age=31536000, immutable to image responses"
        else:
            e = 0
            msg = "No Cache-Control headers observed on images"
            rec = "Enable browser caching headers for all image assets"
        if pct_nostore >= 30 and e > 0.5:
            e = 0.3
            msg += f"; {pct_nostore:.0f}% send no-store (uncacheable)"
            rec = "Remove no-store from public image responses"
        cat.add("Cache-Control policy", e, 2, msg, rec)

        etags = [i for i in probed if i.etag]
        last_mods = [i for i in probed if i.last_modified]
        expires = [i for i in probed if i.expires]
        strong_etags = [i for i in etags if not i.etag_weak]
        both = [i for i in probed if i.etag and i.last_modified]
        if both or (len(etags) + len(last_mods) + len(expires)) >= len(probed):
            e = 1.5
            detail = []
            if etags:
                detail.append(f"{len(etags)} ETag ({len(strong_etags)} strong)")
            if last_mods:
                detail.append(f"{len(last_mods)} Last-Modified")
            if expires:
                detail.append(f"{len(expires)} Expires")
            msg = "Cache validators present: " + ", ".join(detail)
            rec = ""
        elif etags or last_mods or expires:
            e = 1.0
            msg = f"Partial validators: {len(etags)} ETag, {len(last_mods)} Last-Modified, {len(expires)} Expires"
            rec = "Add both ETag and Last-Modified validators to image responses"
        else:
            e = 0
            msg = "No cache validators (ETag/Last-Modified/Expires) on images"
            rec = "Add ETag validators so browsers can revalidate images cheaply"
        cat.add("Cache validators", e, 1.5, msg, rec)

        hits = [i for i in probed if i.cache_hit]
        statuses = sorted({str(i.cache_status) for i in probed if i.cache_status})
        hit_pct = pct(len(hits), len(probed))
        if hit_pct >= 50:
            e = 1.5
            status_hint = f" (statuses: {', '.join(statuses[:3])})" if statuses else ""
            msg = f"CDN cache HIT signals on {hit_pct:.0f}% of probed images{status_hint}"
            rec = ""
        elif hit_pct > 0:
            e = 1.0
            msg = f"Cache HIT signals on {len(hits)}/{len(probed)} images"
            rec = "Warm the CDN cache and route all image traffic through the edge"
        elif statuses:
            e = 0.6
            msg = f"Cache status headers present but no HITs observed ({', '.join(statuses[:3])})"
            rec = "Investigate why edge caches miss (query variance, no-store, short TTLs)"
        else:
            e = 0.3
            msg = "No CDN cache status or Age headers observed"
            rec = "Enable CDN cache status headers (X-Cache, CF-Cache-Status, Age)"
        cat.add("CDN cache hit signals", e, 1.5, msg, rec)

        vary_accept = [i for i in probed if "accept" in (i.vary or "").lower()]
        swrv = [i for i in probed if i.cache_swrv]
        smax = [i for i in probed if i.cache_s_max_age is not None]
        public = [i for i in probed if i.cache_public]
        e = 0.0
        bits = []
        if vary_accept:
            e += 0.4
            bits.append(f"Vary: Accept on {len(vary_accept)}")
        if swrv or smax:
            e += 0.3
            bits.append("stale-while-revalidate/s-maxage present")
        if public:
            e += 0.3
            bits.append(f"public on {len(public)}")
        if bits:
            e = round(min(e, 1.0), 2)
            msg = "Freshness signals: " + "; ".join(bits)
            rec = ""
        else:
            e = 0
            msg = "No Vary: Accept, s-maxage, or stale-while-revalidate directives found"
            rec = "Add Vary: Accept (for format negotiation) and stale-while-revalidate for smoother revalidation"
        cat.add("Cache freshness & Vary", e, 1, msg, rec)
        return cat

    def check_metadata(self):
        title = "Image Metadata"
        cat = CategoryResult("metadata", title, 4)
        deep = [i for i in self.images if i.deep and i.fmt in ("jpg", "png", "webp", "avif")]
        if not deep:
            sampled = [i for i in self.images if i.fetch_ok and not i.is_data and i.fmt != "svg"]
            if not sampled:
                return self._empty_category("metadata", title, 4, "No downloadable images available for metadata scan")
            e = 0.75
            msg = "Metadata scan limited - image bodies not downloadable"
            rec = "Allow direct image downloads so EXIF/ICC metadata can be inspected"
            cat.add("EXIF data presence", e, 1.5, msg, rec)
            cat.add("Color profile detection", 0.6, 1.25, "Color profile unknown without image bodies", "Embed sRGB ICC profiles on exported images")
            cat.add("DPI metadata", 0.6, 1.25, "DPI unknown without image bodies", "Strip or set consistent DPI metadata at export")
            return cat

        with_exif = [i for i in deep if i.has_exif]
        if with_exif:
            e = 0.3
            msg = f"{len(with_exif)}/{len(deep)} sampled images contain EXIF metadata"
            rec = "Strip EXIF (GPS, camera) from production images to reduce payload and protect privacy"
        else:
            e = 1.5
            msg = f"No EXIF data in {len(deep)} sampled images - clean export"
            rec = ""
        cat.add("EXIF data presence", e, 1.5, msg, rec)

        with_icc = [i for i in deep if i.has_icc]
        ratio = pct(len(with_icc), len(deep))
        if ratio >= 60:
            e = 1.25
            msg = f"{ratio:.0f}% of sampled images embed a color profile (ICC)"
            rec = ""
        elif ratio > 0:
            e = 0.85
            msg = f"Color profiles inconsistent ({ratio:.0f}% embedded)"
            rec = "Standardize on sRGB ICC profiles for consistent rendering"
        else:
            e = 0.4
            msg = "No ICC color profiles detected in sample"
            rec = "Embed sRGB color profiles so colors render consistently across devices"
        cat.add("Color profile detection", e, 1.25, msg, rec)

        with_dpi = [i for i in deep if i.dpi]
        if with_dpi:
            sample = with_dpi[0].dpi
            e = 1.25
            msg = f"DPI metadata present (e.g. {sample[0]}x{sample[1]}) on {len(with_dpi)} image(s)"
            rec = ""
        else:
            e = 0.6
            msg = "No DPI metadata detected in sample"
            rec = "Set 72 DPI for screen assets or strip DPI when irrelevant"
        cat.add("DPI metadata", e, 1.25, msg, rec)
        return cat

    def analyze(self):
        self.fetch_page()
        self.extract_images()
        self._scan_url_signals()
        self.probe_images()
        self.deep_inspect()
        self.check_image_sitemap()
        self.run_checks()

    def total_image_bytes(self):
        total = 0
        for image in self.images:
            if image.size_bytes:
                total += image.size_bytes
        return total

    def dashboard_metrics(self):
        non_data = [i for i in self.images if not i.is_data]
        with_size = [i for i in non_data if i.size_bytes]
        total_bytes = self.total_image_bytes()
        modern = [i for i in non_data if i.is_modern]
        avif = [i for i in non_data if i.fmt == "avif"]
        webp = [i for i in non_data if i.fmt == "webp"]
        webp2 = [i for i in non_data if i.webp_version == "2.0"]
        ai = [i for i in non_data if i.has_ai_transform or i.has_smart_crop]
        auto = [i for i in non_data if i.has_auto_opt]
        probed = [i for i in non_data if i.fetch_ok]
        cacheable = [i for i in probed if i.cache_immutable or (i.cache_max_age or 0) > 0]
        hits = [i for i in probed if i.cache_hit]
        page_total = self.page_bytes + total_bytes
        avg = int(total_bytes / len(with_size)) if with_size else 0
        return {
            "score": round(self.total_score, 1),
            "grade": grade_for(self.total_score),
            "image_count": len(self.images),
            "unique": len(self.unique_urls),
            "total_bytes": total_bytes,
            "total_weight": human_size(total_bytes),
            "avg_bytes": avg,
            "avg_weight": human_size(avg),
            "modern_count": len(modern),
            "modern_pct": round(pct(len(modern), len(non_data)), 1),
            "avif_count": len(avif),
            "webp_count": len(webp),
            "webp2_count": len(webp2),
            "ai_count": len(ai),
            "auto_count": len(auto),
            "cacheable_pct": round(pct(len(cacheable), len(probed)), 1),
            "cache_hit_pct": round(pct(len(hits), len(probed)), 1),
            "image_share": round(pct(total_bytes, page_total), 1),
            "probed": len(probed),
            "rec_count": len(self.recommendations),
            "error_count": len(self.errors),
        }

    def summary_dict(self):
        return {
            "tool": f"ImageAnalyzer v{VERSION}",
            "url": self.url,
            "final_url": getattr(self, "final_url", self.url),
            "analyzed_at": (self.started_at or datetime.now(timezone.utc)).isoformat(),
            "page_bytes": self.page_bytes,
            "image_count": len(self.images),
            "unique_images": len(self.unique_urls),
            "total_image_bytes": self.total_image_bytes(),
            "total_image_weight": human_size(self.total_image_bytes()),
            "total_score": self.total_score,
            "max_score": 100,
            "grade": grade_for(self.total_score),
            "dashboard": self.dashboard_metrics(),
            "categories": [c.to_dict() for c in self.categories],
            "recommendations": self.recommendations,
            "errors": self.errors[:20],
        }

    def print_report(self):
        p = self.palette
        print(p.bold(p.cyan("\n" + "=" * 72)))
        print(p.bold(f"  IMAGE ANALYSIS REPORT (v{VERSION})"))
        print(p.bold(p.cyan("=" * 72)))
        print(f"  Target : {p.white(getattr(self, 'final_url', self.url))}")
        print(f"  Page   : {human_size(self.page_bytes)}  |  Images: {len(self.images)} ({len(self.unique_urls)} unique)")
        print(f"  Weight : {p.yellow(human_size(self.total_image_bytes()))} total image payload")
        print(p.bold(p.cyan("-" * 72)))

        m = self.dashboard_metrics()
        dash_rows = [
            ("Score", f"{m['score']:.1f}/100 ({m['grade']})", "Image weight", m["total_weight"]),
            ("Images", f"{m['image_count']} ({m['unique']} unique)", "Avg size", m["avg_weight"]),
            ("Modern formats", f"{m['modern_pct']:.0f}%", "Page share", f"{m['image_share']:.1f}%"),
            ("AVIF assets", str(m["avif_count"]), "WebP assets", str(m["webp_count"])),
            ("WebP 2.0 assets", str(m["webp2_count"]), "AI optimized", str(m["ai_count"])),
            ("Auto quality opt", str(m["auto_count"]), "Cache max-age", f"{m['cacheable_pct']:.0f}%"),
            ("CDN cache hits", f"{m['cache_hit_pct']:.0f}%", "Recommendations", str(m["rec_count"])),
        ]
        print(p.bold(p.cyan("  IMAGE OPTIMIZATION DASHBOARD")))
        print(p.dim("  +" + "-" * 68 + "+"))
        for l_lab, l_val, r_lab, r_val in dash_rows:
            left = f"{str(l_lab):<16}{str(l_val):<18}"
            right = f"{str(r_lab):<16}{str(r_val):<18}"
            print(f"  | {left}{right}|")
        print(p.dim("  +" + "-" * 68 + "+"))
        print(p.bold(p.cyan("-" * 72)))

        for cat in self.categories:
            icon = status_icon(cat.status)
            if cat.status == "pass":
                icon_s = p.green(icon)
            elif cat.status == "warn":
                icon_s = p.yellow(icon)
            else:
                icon_s = p.red(icon)
            title = p.bold(p.white(f"{cat.title}"))
            score = p.bold(f"{cat.earned:.1f}/{cat.maximum:.0f}")
            print(f" {icon_s} {title:<32} {score:>10}")
            for finding in cat.findings:
                if finding.status == "pass":
                    mark = p.green(status_icon("pass"))
                elif finding.status == "warn":
                    mark = p.yellow(status_icon("warn"))
                else:
                    mark = p.red(status_icon("fail"))
                indent = f"      {mark} {finding.name}: {finding.message} ({finding.earned:.1f}/{finding.maximum:.1f})"
                print(indent)
                if self.verbose and finding.recommendation and finding.status != "pass":
                    print(p.dim(f"           -> {finding.recommendation}"))
        print(p.bold(p.cyan("-" * 72)))

        grade = grade_for(self.total_score)
        if self.total_score >= 90:
            grade_s = p.bg_green(p.bold(f" GRADE: {grade} "))
        elif self.total_score >= 60:
            grade_s = p.bg_yellow(p.bold(f" GRADE: {grade} "))
        else:
            grade_s = p.bg_red(p.bold(f" GRADE: {grade} "))

        bar_len = 30
        filled = int(round((self.total_score / 100) * bar_len))
        bar = "#" * filled + "-" * (bar_len - filled)
        if self.total_score >= 90:
            bar_s = p.green(bar)
        elif self.total_score >= 60:
            bar_s = p.yellow(bar)
        else:
            bar_s = p.red(bar)

        score_text = f"{self.total_score:.1f} / 100"
        print(f"\n  TOTAL SCORE: {p.bold(p.white(score_text))}   {grade_s}")
        print(f"  [{bar_s}] {self.total_score:.1f}%\n")

        if self.recommendations:
            print(p.bold(p.yellow("  RECOMMENDATIONS")))
            for idx, rec in enumerate(self.recommendations, 1):
                print(f"   {p.cyan(f'{idx:02d}').ljust(4)} {rec}")
            print()
        else:
            print(p.green("  All checks passed - images are well optimized.\n"))

        print(p.bold(p.cyan("  IMAGE WEIGHT BREAKDOWN")))
        by_fmt = {}
        for image in self.images:
            fmt = image.fmt
            by_fmt.setdefault(fmt, {"count": 0, "bytes": 0})
            by_fmt[fmt]["count"] += 1
            by_fmt[fmt]["bytes"] += image.size_bytes or 0
        if by_fmt:
            total_ref = max(self.total_image_bytes(), 1)
            for fmt, data in sorted(by_fmt.items(), key=lambda kv: kv[1]["bytes"], reverse=True):
                share = pct(data["bytes"], total_ref)
                avg = data["bytes"] // max(data["count"], 1)
                print(f"    {fmt:<8} {data['count']:>3} file(s)  {human_size(data['bytes']):>10}  ({share:5.1f}%)  avg {human_size(avg):>9}")
        else:
            print("    No image weight data available")

        ranked = sorted(
            [i for i in self.images if i.size_bytes and i.abs_url],
            key=lambda x: x.size_bytes or 0,
            reverse=True,
        )[:5]
        if ranked:
            print(p.bold(p.cyan("  TOP HEAVIEST IMAGES")))
            for rank, image in enumerate(ranked, 1):
                path = urlparse(image.abs_url).path or "/"
                if len(path) > 44:
                    path = path[:41] + "..."
                print(f"    {rank:>2}. {human_size(image.size_bytes):>10}  {image.fmt:<6} {path}")

        if self.verbose and self.errors:
            print(p.yellow(f"\n  Warnings ({len(self.errors)}):"))
            for err in self.errors[:10]:
                print(p.dim(f"    - {err}"))
        print(p.bold(p.cyan("=" * 72)) + "\n")

class Exporter:
    def __init__(self, analyzer, palette):
        self.analyzer = analyzer
        self.palette = palette

    def export_all(self, fmt):
        exported = []
        if fmt in ("all", "json"):
            exported.append(self.export_json())
        if fmt in ("all", "csv"):
            exported.append(self.export_csv())
        if fmt in ("all", "html"):
            exported.append(self.export_html())
        return exported

    def export_json(self):
        path = "imageanalyzer_report.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.analyzer.summary_dict(), fh, indent=2, ensure_ascii=False)
        return path

    def export_csv(self):
        path = "imageanalyzer_report.csv"
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["Category", "Key", "Score", "Max", "Status", "Finding", "Points", "FindingMax", "FindingStatus", "Message", "Recommendation"])
            for cat in self.analyzer.categories:
                for finding in cat.findings:
                    writer.writerow([
                        cat.title, cat.key, cat.earned, cat.maximum, cat.status,
                        finding.name, finding.earned, finding.maximum, finding.status,
                        finding.message, finding.recommendation,
                    ])
            writer.writerow([])
            writer.writerow(["TOTAL", "", self.analyzer.total_score, 100, grade_for(self.analyzer.total_score)])
        return path

    def export_html(self):
        path = "imageanalyzer_report.html"
        data = self.analyzer.summary_dict()
        css = """
:root { color-scheme: dark; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #0d1117; color: #e6edf3; font-family: "Segoe UI", system-ui, sans-serif; padding: 32px; line-height: 1.5; }
.container { max-width: 960px; margin: 0 auto; }
header { border-bottom: 1px solid #30363d; padding-bottom: 20px; margin-bottom: 24px; }
h1 { font-size: 26px; letter-spacing: 0.5px; color: #58a6ff; }
.meta { color: #8b949e; font-size: 13px; margin-top: 8px; word-break: break-all; }
.scorebox { display: flex; gap: 24px; align-items: center; background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 20px; margin-bottom: 28px; }
.score { font-size: 48px; font-weight: 700; }
.grade { font-size: 30px; font-weight: 700; padding: 6px 16px; border-radius: 8px; }
.grade-A\2B, .grade-A { background: #238636; color: #fff; }
.grade-B { background: #9e6a03; color: #fff; }
.grade-C { background: #bb8009; color: #fff; }
.grade-D { background: #da3633; color: #fff; }
.grade-F { background: #8b1a1a; color: #fff; }
.bar { height: 10px; background: #21262d; border-radius: 5px; overflow: hidden; margin-top: 14px; }
.bar > span { display: block; height: 100%; background: linear-gradient(90deg, #1f6feb, #3fb950); }
.dash { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; margin: 0 0 24px; }
.tile { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 14px 16px; }
.tlabel { color: #8b949e; font-size: 12px; margin-bottom: 6px; }
.tvalue { color: #f0f6fc; font-size: 20px; font-weight: 700; }
.cat { background: #161b22; border: 1px solid #30363d; border-radius: 10px; margin-bottom: 14px; overflow: hidden; }
.cat h2 { font-size: 15px; padding: 14px 18px; display: flex; justify-content: space-between; background: #1c2128; }
.cat h2 .pts { color: #58a6ff; }
.findings { padding: 8px 18px 14px; }
.finding { display: flex; gap: 12px; padding: 7px 0; border-bottom: 1px solid #21262d; font-size: 13.5px; }
.finding:last-child { border-bottom: none; }
.tag { flex: 0 0 auto; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 20px; height: fit-content; }
.pass { background: #1a7f37; color: #fff; }
.warn { background: #9e6a03; color: #fff; }
.fail { background: #da3633; color: #fff; }
.fname { flex: 0 0 220px; color: #f0f6fc; }
.fmsg { flex: 1; color: #8b949e; }
.fpts { flex: 0 0 70px; text-align: right; color: #8b949e; }
h3 { margin: 26px 0 12px; color: #58a6ff; font-size: 17px; }
ol { padding-left: 22px; }
li { margin-bottom: 8px; font-size: 14px; color: #c9d1d9; }
.weight { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 16px 18px; }
.weight table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
.weight th, .weight td { text-align: left; padding: 8px 6px; border-bottom: 1px solid #21262d; }
.weight th { color: #8b949e; font-weight: 600; }
footer { margin-top: 30px; color: #484f58; font-size: 12px; text-align: center; }
@media (max-width: 720px) { .finding { flex-wrap: wrap; } .fname { flex-basis: 100%; } body { padding: 16px; } }
"""
        grade_class = "grade-" + data["grade"].replace("+", "")
        dash = data.get("dashboard", {})
        by_fmt = {}
        for image in self.analyzer.images:
            fmt = image.fmt
            by_fmt.setdefault(fmt, {"count": 0, "bytes": 0})
            by_fmt[fmt]["count"] += 1
            by_fmt[fmt]["bytes"] += image.size_bytes or 0

        weight_rows = ""
        total_ref = max(self.analyzer.total_image_bytes(), 1)
        for fmt, info in sorted(by_fmt.items(), key=lambda kv: kv[1]["bytes"], reverse=True):
            share = pct(info["bytes"], total_ref)
            avg = info["bytes"] // max(info["count"], 1)
            weight_rows += (
                f"<tr><td>{fmt}</td><td>{info['count']}</td>"
                f"<td>{human_size(info['bytes'])}</td><td>{share:.1f}%</td>"
                f"<td>{human_size(avg)}</td></tr>"
            )

        tiles = [
            ("Score", f"{data['total_score']:.1f}/100"),
            ("Grade", data["grade"]),
            ("Image weight", data["total_image_weight"]),
            ("Images", f"{data['image_count']} ({data['unique_images']} unique)"),
            ("Modern formats", f"{dash.get('modern_pct', 0)}%"),
            ("AVIF / WebP", f"{dash.get('avif_count', 0)} / {dash.get('webp_count', 0)}"),
            ("AI optimized", str(dash.get("ai_count", 0))),
            ("Cache max-age", f"{dash.get('cacheable_pct', 0)}%"),
            ("CDN cache hits", f"{dash.get('cache_hit_pct', 0)}%"),
            ("Recommendations", str(dash.get("rec_count", 0))),
        ]
        tile_html = "".join(
            f"<div class='tile'><div class='tlabel'>{label}</div><div class='tvalue'>{value}</div></div>"
            for label, value in tiles
        )

        cat_blocks = ""
        for cat in data["categories"]:
            finding_html = ""
            for finding in cat["findings"]:
                finding_html += (
                    f"<div class='finding'>"
                    f"<span class='tag {finding['status']}'>{finding['status'].upper()}</span>"
                    f"<span class='fname'>{finding['name']}</span>"
                    f"<span class='fmsg'>{finding['message']}</span>"
                    f"<span class='fpts'>{finding['earned']}/{finding['max']}</span>"
                    f"</div>"
                )
            cat_blocks += (
                f"<section class='cat'>"
                f"<h2><span>{cat['title']}</span>"
                f"<span class='pts'>{cat['earned']} / {cat['max']}</span></h2>"
                f"<div class='findings'>{finding_html}</div></section>"
            )

        rec_items = ""
        for idx, rec in enumerate(data["recommendations"], 1):
            rec_items += f"<li>{idx}. {rec}</li>"
        if not rec_items:
            rec_items = "<li>All checks passed - images are well optimized.</li>"

        html = (
            "<!DOCTYPE html>\n<html lang='en'>\n<head>\n<meta charset='utf-8'>\n"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
            f"<title>ImageAnalyzer Report - {data['grade']}</title>\n"
            f"<style>{css}</style>\n</head>\n<body>\n<div class='container'>\n"
            f"<header><h1>ImageAnalyzer v{VERSION} - Optimization Report</h1>"
            f"<div class='meta'>URL: {data['final_url']}<br>"
            f"Analyzed: {data['analyzed_at']}<br>"
            f"Images: {data['image_count']} ({data['unique_images']} unique) | "
            f"Image weight: {data['total_image_weight']} | Page: {human_size(data['page_bytes'])}</div></header>\n"
            f"<div class='scorebox'><div class='score'>{data['total_score']:.1f}<span style='font-size:20px;color:#8b949e'>/100</span></div>"
            f"<div><div class='grade {grade_class}'>{data['grade']}</div>"
            f"<div class='bar'><span style='width:{data['total_score']}%'></span></div></div></div>\n"
            f"<div class='dash'>{tile_html}</div>\n"
            f"{cat_blocks}\n"
            f"<h3>Recommendations</h3>\n<ol>{rec_items}</ol>\n"
            f"<h3>Total Image Weight by Format</h3>\n<div class='weight'><table>"
            f"<tr><th>Format</th><th>Files</th><th>Size</th><th>Share</th><th>Avg</th></tr>"
            f"{weight_rows or '<tr><td colspan=5>No data</td></tr>'}</table></div>\n"
            f"<footer>Generated by ImageAnalyzer v{VERSION}</footer>\n"
            f"</div>\n</body>\n</html>\n"
        )
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        return path


def build_parser():
    parser = argparse.ArgumentParser(
        prog="imageanalyzer",
        description=f"ImageAnalyzer v{VERSION} - website image optimization analyzer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL to analyze")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument(
        "--export",
        choices=["all", "json", "csv", "html", "none"],
        default="none",
        help="Export format for the report",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version=f"ImageAnalyzer {VERSION}")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    palette = Palette(enabled=not args.no_color)
    print(banner(palette))
    analyzer = ImageAnalyzer(args.url, timeout=args.timeout, verbose=args.verbose, palette=palette)
    try:
        analyzer.analyze()
    except requests.exceptions.MissingSchema:
        print(palette.red("[!] Invalid URL - include http:// or https://"))
        return 2
    except requests.exceptions.Timeout:
        print(palette.red(f"[!] Request timed out after {args.timeout}s"))
        return 2
    except requests.exceptions.ConnectionError as exc:
        print(palette.red(f"[!] Connection failed: {exc}"))
        return 2
    except requests.exceptions.HTTPError as exc:
        print(palette.red(f"[!] HTTP error: {exc}"))
        return 2
    except requests.exceptions.RequestException as exc:
        print(palette.red(f"[!] Request failed: {exc}"))
        return 2
    except KeyboardInterrupt:
        print(palette.yellow("\n[!] Interrupted"))
        return 130

    analyzer.print_report()

    if args.export != "none":
        exporter = Exporter(analyzer, palette)
        try:
            paths = exporter.export_all(args.export)
            for path in paths:
                print(palette.green(f"[+] Report exported: {path}"))
        except OSError as exc:
            print(palette.red(f"[!] Export failed: {exc}"))
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
