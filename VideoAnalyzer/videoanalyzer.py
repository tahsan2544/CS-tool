#!/usr/bin/env python3

import argparse
import csv
import io
import json
import re
import sys
from datetime import datetime, timezone
from html import escape
from urllib.parse import urlparse

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
MAX_TOTAL = 160

GRADE_BANDS = [
    (95, "A+"),
    (90, "A"),
    (75, "B"),
    (60, "C"),
    (40, "D"),
    (0, "F"),
]

DIMENSIONS = {
    "SEO": ("seo", "metadata"),
    "Accessibility": ("accessibility",),
    "Performance": ("performance", "delivery", "caching"),
    "Quality": ("quality", "compression", "formats"),
    "Streaming": ("streaming",),
    "Embedding": ("embedding", "hosting"),
    "Engagement": ("sharing", "interactivity", "analytics"),
}

ACTIONS = {
    "HTML5 video element detection": "Add a native <video> element (or a standards-based player) so the video is present in the DOM.",
    "iframe embed detection": "Embed the player via an iframe from a known video platform or your player host.",
    "Video player detection": "Use a recognized player library (Video.js, JW Player, Plyr, etc.) for consistent controls and events.",
    "Responsive video detection": "Wrap the video in a responsive container (aspect-ratio or embed-responsive classes) so it scales on all viewports.",
    "Video poster attribute": "Set a poster image on <video> so a frame shows before playback starts.",
    "VideoObject structured data": "Add JSON-LD VideoObject schema with name, description, thumbnailUrl, uploadDate, and duration.",
    "Video title quality": "Write a descriptive video title between 10 and 70 characters.",
    "Video description quality": "Provide a video description of at least 50 characters that explains the content.",
    "Video thumbnail/poster": "Add a thumbnail or poster image (og:image or VideoObject thumbnailUrl).",
    "Video duration metadata": "Declare the video duration in schema (ISO 8601, e.g. PT4M13S) or video:duration meta.",
    "Video upload date": "Include uploadDate/datePublished in VideoObject schema or article:published_time meta.",
    "Video schema validation": "Complete the VideoObject schema with the recommended fields (contentUrl, embedUrl, etc.).",
    "Open Graph video tags": "Add og:video / og:video:secure_url / og:video:type meta tags for social and rich previews.",
    "Video rich snippet readiness": "Combine duration, upload date, thumbnail, and embed URL so the video is eligible for rich results.",
    "Captions/subtitles detection": "Provide WebVTT captions via a track kind=captions element or your player's caption system.",
    "Audio description detection": "Offer audio descriptions (track kind=descriptions) for visually conveyed information.",
    "Video transcript detection": "Publish a full text transcript near the player (visible or expandable).",
    "Video controls accessibility": "Expose player controls (native controls attribute or an ARIA-aware custom control bar).",
    "Keyboard navigation support": "Ensure the player is keyboard operable (tabindex, focus styles, key handlers).",
    "Caption language attributes": "Add srclang and label attributes to caption tracks so screen readers announce the language.",
    "Player ARIA labelling": "Give the video/player an aria-label or role so assistive tech can identify it.",
    "Modern format usage": "Serve MP4 (H.264), WebM, or adaptive (HLS/DASH) formats instead of none or legacy-only.",
    "Legacy format usage": "Drop legacy containers (FLV/AVI/WMV) and transcode to MP4/WebM.",
    "Format compatibility analysis": "Include MP4 or HLS so Safari and older clients can play the video.",
    "Adaptive streaming detection": "Adopt HLS or DASH so playback adapts to each viewer's bandwidth.",
    "Video preload strategy": "Set preload=metadata or preload=none to avoid downloading video before the user plays it.",
    "Lazy loading detection": "Lazy-load the player (loading=lazy, IntersectionObserver, or data-src pattern) until it scrolls into view.",
    "Video file size estimation": "Keep the page payload lean; defer heavy player resources and measure transferred bytes.",
    "Video quality options": "Expose multiple quality options (720p/1080p/auto) in the player.",
    "Resource hints for media hosts": "Add preconnect/dns-prefetch for the media/CDN origin to speed up connection setup.",
    "Third-party script weight": "Reduce third-party scripts on video pages; defer or remove ones the player does not need.",
    "Video title attribute": "Add title or aria-label to the video/iframe so the embed is identifiable.",
    "Video description": "Add og:description or a VideoObject description for the video.",
    "Video keywords/tags": "Add video keywords/tags (meta keywords, video:tag, or schema keywords).",
    "Video duration format": "Use a machine-readable duration (e.g. PT1H2M30S) containing digits.",
    "Video resolution metadata": "Declare width/height or resolution labels (e.g. 1920x1080) for the video.",
    "Open Graph video metadata": "Complete og:video tags (url, width, height, type) for embeds and previews.",
    "Schema media URLs": "Add contentUrl and embedUrl to VideoObject so crawlers can locate the media.",
    "Social sharing buttons detection": "Add share controls (Twitter/Facebook/LinkedIn/copy link) near the player.",
    "Video share links": "Provide shareable link or copy-to-clipboard actions for the video.",
    "Embed code availability": "Offer an embeddable iframe snippet (oEmbed or copy-embed UI).",
    "YouTube embedding": "Embed via YouTube (ideally youtube-nocookie.com) if the video lives on YouTube.",
    "Vimeo embedding": "Embed via player.vimeo.com with privacy-enhanced mode where possible.",
    "Self-hosted detection": "Serve a direct media URL (mp4/webm/m3u8/mpd) for self-hosted playback.",
    "Video CDN detection": "Serve video through a CDN and surface CDN headers/hosts.",
    "Video hosting platform detection": "Use a known video hosting platform or a self-hosted direct source.",
    "Chapters detection": "Add a chapters track or timestamp markers so viewers can jump between sections.",
    "Interactive video elements": "Consider hotspots/interactive layers if the content benefits from them.",
    "Video annotations": "Add in-video annotations/notes overlay when they aid comprehension.",
    "Video tracking detection": "Wire the player to analytics (GA4/gtag, GTM, Segment, etc.) for play events.",
    "Video completion tracking": "Track completion/progress milestones (25/50/75/100%).",
    "Video impression tracking": "Track impressions/views and viewability of the player.",
    "HLS manifest detection": "Publish an HLS (.m3u8) playlist for adaptive streaming.",
    "DASH manifest detection": "Publish an MPEG-DASH (.mpd) manifest as an alternative adaptive format.",
    "Adaptive bitrate ladder": "Encode multiple renditions (e.g. 240p-1080p) and expose them as stream variants.",
    "Manifest quality signals": "Declare codecs/resolution/bandwidth in the manifest or player config for smarter selection.",
    "Progressive fallback source": "Keep an MP4/WebM fallback for clients that cannot play HLS/DASH.",
    "Resolution ladder options": "Offer at least two resolution renditions, including one at 720p or higher.",
    "High resolution availability": "Provide a 1080p+ rendition for large screens and high-DPI displays.",
    "Quality selector UI": "Expose a quality/resolution picker in the player settings menu.",
    "Poster/thumbnail presence": "Attach a poster image so the player shows a frame before playback.",
    "Codec option hints": "Prefer modern codecs (AV1, VP9, HEVC) with H.264 as the compatibility baseline.",
    "Audio track options": "Support alternate audio tracks/languages where the content warrants it.",
    "Modern container usage": "Transcode to MP4/WebM (or HLS/DASH segments) instead of legacy containers.",
    "Efficient codec hints": "Use efficient codecs (AV1/VP9/HEVC/H.264) to reduce bitrate at equal quality.",
    "Poster image optimization": "Serve posters/thumbnails as WebP/AVIF with explicit dimensions or srcset.",
    "Segmented delivery": "Switch to HLS/DASH so viewers download only the segments they need.",
    "CDN header detection": "Serve through a CDN that exposes cache/edge headers (Age, X-Cache, Via, CF-Cache-Status).",
    "HTTP/2+ protocol": "Enable HTTP/2 or HTTP/3 on the origin to speed up player and manifest requests.",
    "Range request support": "Enable byte-range requests (Accept-Ranges: bytes) so players can seek efficiently.",
    "Mixed content safety": "Serve media over HTTPS to avoid mixed-content blocking.",
    "Cache-Control presence": "Send Cache-Control headers on media and manifest responses.",
    "Effective cache policy": "Set a public max-age (or immutable) policy for versioned media assets.",
    "Cache validators": "Provide ETag or Last-Modified validators for conditional requests.",
    "Edge/CDN cache evidence": "Enable edge caching so repeat views are served from the CDN.",
}

LOW_EFFORT_LABELS = {
    "Video poster attribute",
    "Video title quality",
    "Video description quality",
    "Video title attribute",
    "Video description",
    "Video keywords/tags",
    "Video duration metadata",
    "Video duration format",
    "Video upload date",
    "Video resolution metadata",
    "Open Graph video tags",
    "Open Graph video metadata",
    "Video rich snippet readiness",
    "Caption language attributes",
    "Player ARIA labelling",
    "Video controls accessibility",
    "Keyboard navigation support",
    "iframe embed detection",
    "Video preload strategy",
    "Lazy loading detection",
    "Resource hints for media hosts",
    "Video share links",
    "Embed code availability",
    "Video file size estimation",
    "Video impression tracking",
    "Video completion tracking",
    "Poster/thumbnail presence",
    "Poster image optimization",
    "Cache-Control presence",
    "Mixed content safety",
    "Video thumbnail/poster",
}

HIGH_EFFORT_LABELS = {
    "HLS manifest detection",
    "DASH manifest detection",
    "Adaptive bitrate ladder",
    "Segmented delivery",
    "Progressive fallback source",
    "Resolution ladder options",
    "Codec option hints",
    "Audio track options",
    "Video tracking detection",
    "Video completion tracking",
    "Interactive video elements",
    "Chapters detection",
    "Format compatibility analysis",
    "Adaptive streaming detection",
}

PRIORITY_BY_CATEGORY = {
    "seo": "high",
    "accessibility": "high",
    "performance": "high",
    "quality": "medium",
    "streaming": "medium",
    "metadata": "medium",
    "embedding": "medium",
    "formats": "medium",
    "delivery": "medium",
    "caching": "low",
    "compression": "low",
    "sharing": "low",
    "hosting": "low",
    "interactivity": "low",
    "analytics": "low",
}


class Palette:
    def __init__(self, enabled=True):
        self.enabled = enabled

    def _w(self, code, text):
        if not self.enabled:
            return str(text)
        return f"\033[{code}m{text}\033[0m"

    def bold(self, t):
        return self._w("1", t)

    def red(self, t):
        return self._w("31", t)

    def green(self, t):
        return self._w("32", t)

    def yellow(self, t):
        return self._w("33", t)

    def blue(self, t):
        return self._w("34", t)

    def magenta(self, t):
        return self._w("35", t)

    def cyan(self, t):
        return self._w("36", t)

    def white(self, t):
        return self._w("37", t)

    def gray(self, t):
        return self._w("90", t)

    def bright_red(self, t):
        return self._w("91", t)

    def bright_green(self, t):
        return self._w("92", t)

    def bright_yellow(self, t):
        return self._w("93", t)

    def bright_blue(self, t):
        return self._w("94", t)

    def bright_magenta(self, t):
        return self._w("95", t)

    def bright_cyan(self, t):
        return self._w("96", t)

    def bg_red(self, t):
        return self._w("41;97;1", t)

    def bg_green(self, t):
        return self._w("42;97;1", t)

    def bg_yellow(self, t):
        return self._w("43;97;1", t)

    def bg_blue(self, t):
        return self._w("44;97;1", t)

    def bg_magenta(self, t):
        return self._w("45;97;1", t)


BANNER_LINES = [
    "██╗   ██╗ ██████╗ ██╗██████╗     ██╗   ██╗███╗   ██╗██╗███╗   ██╗",
    "██║   ██║██╔═══██╗██║██╔══██╗    ██║   ██║████╗  ██║██║████╗  ██║",
    "██║   ██║██║   ██║██║██║  ██║    ██║   ██║██╔██╗ ██║██║██╔██╗ ██║",
    "╚██╗ ██╔╝██║   ██║██║██║  ██║    ╚██╗ ██╔╝██║╚██╗██║██║██║╚██╗██║",
    " ╚████╔╝ ╚██████╔╝██║██████╔╝     ╚████╔╝ ██║ ╚████║██║██║ ╚████║",
    "  ╚═══╝   ╚═════╝ ╚═╝╚═════╝       ╚═══╝  ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝",
]


class CheckResult:
    def __init__(self, category, title, max_points):
        self.category = category
        self.title = title
        self.max_points = max_points
        self.points = 0
        self.items = []
        self.findings = []
        self.warnings = []

    def add(self, label, points, max_points, passed, detail=""):
        awarded = points if passed else 0
        self.points += awarded
        self.items.append({
            "label": label,
            "awarded": awarded,
            "max": max_points,
            "passed": bool(passed),
            "detail": detail,
        })

    def find(self, message):
        self.findings.append(message)

    def warn(self, message):
        self.warnings.append(message)

    def clamp(self):
        if self.points > self.max_points:
            self.points = self.max_points
        if self.points < 0:
            self.points = 0


class VideoAnalyzer:
    def __init__(self, url, timeout=15, verbose=False, color=True):
        self.url = url
        self.timeout = timeout
        self.verbose = verbose
        self.pal = Palette(color)
        self.raw_html = ""
        self.soup = None
        self.response = None
        self.results = []
        self.inventory = {
            "video_elements": 0,
            "iframes": 0,
            "players": [],
            "sources": [],
            "captions": [],
            "platforms": [],
            "formats": [],
            "qualities": [],
            "thumbnails": [],
            "scripts": 0,
            "streaming_manifests": [],
            "streaming_protocols": [],
            "cache_headers": {},
            "http_version": "",
        }
        self.structured_data = []
        self.meta = {}
        self._recommendations = None
        self._roadmap = None

    def log(self, message):
        if self.verbose:
            print(self.pal.gray(f"  [debug] {message}"))

    def fetch(self):
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        try:
            self.log(f"GET {self.url}")
            self.response = requests.get(
                self.url, headers=headers, timeout=self.timeout, allow_redirects=True
            )
            self.raw_html = self.response.text or ""
            self.soup = BeautifulSoup(self.raw_html, "html.parser")
            self.log(f"status={self.response.status_code} bytes={len(self.raw_html)}")
            return True
        except requests.exceptions.Timeout:
            print(self.pal.red(f"Request timed out after {self.timeout}s"))
            return False
        except requests.exceptions.RequestException as exc:
            print(self.pal.red(f"Request failed: {exc}"))
            return False
        except Exception as exc:
            print(self.pal.red(f"Fetch error: {exc}"))
            return False

    def collect_inventory(self):
        if self.soup is None:
            return
        soup = self.soup

        videos = soup.find_all("video")
        self.inventory["video_elements"] = len(videos)
        for v in videos:
            for attr in ("src", "poster", "preload", "controls", "autoplay", "loop", "muted"):
                if v.has_attr(attr):
                    val = v.get(attr)
                    self.log(f"video[{attr}]={val}")
            for track in v.find_all("track"):
                src = track.get("src", "")
                kind = track.get("kind", "")
                if src:
                    self.inventory["captions"].append({"src": src, "kind": kind, "element": "track"})
            for source in v.find_all("source"):
                src = source.get("src", "")
                if src:
                    self.inventory["sources"].append({
                        "src": src,
                        "type": source.get("type", ""),
                        "label": source.get("data-label", source.get("label", "")),
                    })
                    self._note_format(src)
            src = v.get("src", "")
            if src:
                self.inventory["sources"].append({"src": src, "type": "", "label": ""})
                self._note_format(src)
            label = v.get("aria-label") or v.get("title") or ""
            if label:
                self.log(f"video aria-label={label}")

        iframes = soup.find_all("iframe")
        self.inventory["iframes"] = len(iframes)
        for frame in iframes:
            src = frame.get("src", "") or ""
            title = frame.get("title", "") or ""
            self.log(f"iframe src={src} title={title}")
            self._note_platform(src)
            self._note_format(src)
            if src:
                self.inventory["sources"].append({"src": src, "type": "iframe", "label": title})

        text = self.raw_html.lower()
        for player in ("jwplayer", "video.js", "videojs", "plyr", "flowplayer", "mediaelement", "clappr", "shaka"):
            if player in text:
                self.inventory["players"].append(player)

        for platform, keys in {
            "YouTube": ("youtube.com/embed", "youtube-nocookie.com", "youtu.be/"),
            "Vimeo": ("player.vimeo.com", "vimeo.com/video"),
            "Dailymotion": ("dailymotion.com/embed", "dai.ly/"),
            "Twitch": ("player.twitch.tv", "twitch.tv/embed"),
            "Wistia": ("fast.wistia.net", "wistia.com/medias"),
            "Vidyard": ("play.vidyard.com", "vidyard.com"),
            "Brightcove": ("brightcove.com", "bcsecure"),
            "Kaltura": ("kaltura.com", "kaltura.com/"),
        }.items():
            if any(k in text for k in keys):
                if platform not in self.inventory["platforms"]:
                    self.inventory["platforms"].append(platform)

        for fmt in ("webm", "mp4", "m3u8", "mpd", "flv", "avi", "mov", "ogv", "wmv", "mkv"):
            if f".{fmt}" in text or f"video/{fmt}" in text:
                if fmt not in self.inventory["formats"]:
                    self.inventory["formats"].append(fmt)

        for quality in ("2160p", "1440p", "1080p", "720p", "480p", "360p", "240p",
                        "4k", "1080", "720", "480", "hd", "sd", "uhd"):
            if re.search(rf"(?:^|[^0-9a-z]){re.escape(quality)}(?:[^0-9a-z]|$)", text):
                if quality not in self.inventory["qualities"]:
                    self.inventory["qualities"].append(quality)

        for tag in soup.find_all("img"):
            src = tag.get("src", "") or ""
            if any(x in src.lower() for x in ("thumb", "poster", "preview", "video", "frame", "cover")):
                self.inventory["thumbnails"].append(src)

        self.inventory["scripts"] = len(soup.find_all("script"))

        for script in soup.find_all("script"):
            stype = (script.get("type") or "").lower()
            if "ld+json" in stype:
                raw = script.string or script.get_text() or ""
                self._parse_ld_json(raw)
            if script.get("src"):
                ssrc = script.get("src", "").lower()
                if any(x in ssrc for x in ("analytics", "gtag", "ga(", "segment", "mixpanel",
                                           "amplitude", "hotjar", "matomo", "snowplow", "pendo",
                                           "fullstory", "heap", "kissmetrics", "wistia", "vimeo")):
                    self.log(f"analytics-ish script: {ssrc}")

        for meta in soup.find_all("meta"):
            key = meta.get("name") or meta.get("property") or meta.get("itemprop") or ""
            content = meta.get("content") or ""
            if key:
                self.meta[key.lower()] = content

        for link in soup.find_all("link"):
            rel = " ".join(link.get("rel") or [])
            href = link.get("href") or ""
            if "thumbnail" in rel.lower() or "og:image" in (link.get("type") or ""):
                self.inventory["thumbnails"].append(href)

        self._collect_streaming_and_headers(text)

    def _collect_streaming_and_headers(self, text):
        manifests = self.inventory["streaming_manifests"]
        for s in self.inventory["sources"]:
            src = s.get("src") or ""
            low = src.lower()
            if (".m3u8" in low or ".mpd" in low) and src not in manifests:
                manifests.append(src)
        for pattern in (
            r"""https?://[^\s"'<>]+\.m3u8[^\s"'<>]*""",
            r"""["']([^"']+\.m3u8[^"']*)["']""",
        ):
            for m in re.findall(pattern, self.raw_html, re.I):
                if isinstance(m, tuple):
                    m = m[0]
                if m and m not in manifests:
                    manifests.append(m)
        for pattern in (
            r"""https?://[^\s"'<>]+\.mpd[^\s"'<>]*""",
            r"""["']([^"']+\.mpd[^"']*)["']""",
        ):
            for m in re.findall(pattern, self.raw_html, re.I):
                if isinstance(m, tuple):
                    m = m[0]
                if m and m not in manifests:
                    manifests.append(m)

        protos = self.inventory["streaming_protocols"]
        if (".m3u8" in text or "mpegurl" in text or "hls" in text) and "HLS" not in protos:
            protos.append("HLS")
        if (".mpd" in text or "dash+xml" in text) and "DASH" not in protos:
            protos.append("DASH")

        if self.response is not None:
            hdrs = self.response.headers
            cache_headers = self.inventory["cache_headers"]
            for h in (
                "cache-control", "cdn-cache-control", "surrogate-control", "etag",
                "last-modified", "age", "x-cache", "x-cache-hits", "cf-cache-status",
                "accept-ranges", "via", "content-encoding", "server",
            ):
                val = hdrs.get(h)
                if val:
                    cache_headers[h.lower()] = val
            hv = str(getattr(self.response, "http_version", "") or "")
            self.inventory["http_version"] = hv

    def _parse_ld_json(self, raw):
        raw = raw.strip()
        if not raw:
            return
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return
        stack = [data] if isinstance(data, dict) else list(data) if isinstance(data, list) else []
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                self.structured_data.append(node)
                if "@graph" in node and isinstance(node["@graph"], list):
                    stack.extend(node["@graph"])
                for key in ("video", "itemListElement"):
                    if key in node and isinstance(node[key], (dict, list)):
                        if isinstance(node[key], dict):
                            stack.append(node[key])
                        else:
                            stack.extend(x for x in node[key] if isinstance(x, dict))
            elif isinstance(node, list):
                stack.extend(x for x in node if isinstance(x, (dict, list)))

    def _note_format(self, src):
        low = (src or "").lower()
        for fmt, keys in {
            "webm": (".webm", "video/webm"),
            "mp4": (".mp4", "video/mp4", "video/mpeg"),
            "hls": (".m3u8", "application/vnd.apple.mpegurl", "hls"),
            "dash": (".mpd", "application/dash+xml", "dash"),
            "flv": (".flv", "video/flv"),
            "avi": (".avi",),
            "mov": (".mov", "video/quicktime"),
            "ogv": (".ogv", "video/ogg"),
        }.items():
            if any(k in low for k in keys):
                if fmt not in self.inventory["formats"]:
                    self.inventory["formats"].append(fmt)

    def _note_platform(self, src):
        low = (src or "").lower()
        mapping = {
            "YouTube": ("youtube.com", "youtu.be", "youtube-nocookie.com"),
            "Vimeo": ("vimeo.com",),
            "Dailymotion": ("dailymotion.com", "dai.ly"),
            "Twitch": ("twitch.tv",),
            "Wistia": ("wistia",),
            "Vidyard": ("vidyard.com",),
            "Brightcove": ("brightcove", "bcsecure"),
            "Kaltura": ("kaltura", "kirby", "ndcodetv"),
        }
        for platform, keys in mapping.items():
            if any(k in low for k in keys) and platform not in self.inventory["platforms"]:
                self.inventory["platforms"].append(platform)

    def _find_video_object(self):
        for node in self.structured_data:
            ntype = str(node.get("@type", "")).lower()
            if "videoobject" in ntype:
                return node
            if "itemtype" in str(node.get("@context", "")).lower() and "videoobject" in ntype:
                return node
        for node in self.structured_data:
            if isinstance(node.get("video"), dict):
                return node["video"]
        return {}

    def _page_text(self):
        if self.soup is None:
            return ""
        clone = BeautifulSoup(self.raw_html, "html.parser")
        for tag in clone(["script", "style", "noscript"]):
            tag.decompose()
        return re.sub(r"\s+", " ", clone.get_text(" ", strip=True))

    def check_embedding(self):
        r = CheckResult("embedding", "Video Embedding", 15)
        soup = self.soup
        text_l = self.raw_html.lower()

        has_html5 = False
        if soup is not None:
            videos = soup.find_all("video")
            if videos:
                has_html5 = True
                r.find(f"HTML5 <video> element(s): {len(videos)}")
            sources = soup.find_all("source")
            if sources and not has_html5:
                has_html5 = True
                r.find(f"<source> element(s) without video tag: {len(sources)}")
        r.add("HTML5 video element detection", 3, 3, has_html5,
              "video/source elements found" if has_html5 else "no <video> element")

        has_iframe = False
        if soup is not None:
            for frame in soup.find_all("iframe"):
                src = (frame.get("src") or "").lower()
                if any(x in src for x in ("youtube", "vimeo", "dailymotion", "twitch", "wistia",
                                          "vidyard", "brightcove", "kaltura", "player", "embed")):
                    has_iframe = True
                    r.find(f"iframe embed: {src[:80]}")
        if not has_iframe and "iframe" in text_l:
            has_iframe = bool(re.search(r"youtube|vimeo|embed", text_l))
        r.add("iframe embed detection", 3, 3, has_iframe,
              "player iframe present" if has_iframe else "no video iframe")

        players = self.inventory["players"]
        has_player = bool(players)
        r.add("Video player detection", 3, 3, has_player,
              f"players: {', '.join(players)}" if players else "no known JS player")

        responsive = False
        if soup is not None:
            for v in soup.find_all("video"):
                cls = " ".join(v.get("class") or []).lower()
                if any(x in cls for x in ("responsive", "embed-responsive", "fluid", "ratio", "w-full", "video-responsive")):
                    responsive = True
                    r.find(f"responsive class on video: {cls}")
                parent_cls = ""
                if v.parent and hasattr(v.parent, "get"):
                    parent_cls = " ".join(v.parent.get("class") or []).lower()
                if any(x in parent_cls for x in ("responsive", "embed-responsive", "ratio", "fluid")):
                    responsive = True
                    r.find(f"responsive wrapper: {parent_cls}")
            style_tag = soup.find("style")
            css = style_tag.get_text() if style_tag else ""
            if "video" in css and ("max-width" in css or "aspect-ratio" in css):
                responsive = True
                r.find("CSS suggests responsive video styling")
            for frame in soup.find_all("iframe"):
                fcls = " ".join(frame.get("class") or []).lower()
                if any(x in fcls for x in ("responsive", "embed-responsive", "ratio")):
                    responsive = True
        if not responsive and ("max-width: 100%" in text_l or "aspect-ratio" in text_l):
            responsive = True
            r.find("page CSS uses max-width/aspect-ratio (likely responsive)")
        r.add("Responsive video detection", 2, 2, responsive,
              "responsive styling found" if responsive else "no responsive hint")

        has_poster = False
        if soup is not None:
            for v in soup.find_all("video"):
                if v.get("poster"):
                    has_poster = True
                    r.find(f"poster: {v.get('poster')[:80]}")
        r.add("Video poster attribute", 4, 4, has_poster,
              "poster set" if has_poster else "no poster attribute")

        r.clamp()
        return r

    def check_seo(self):
        r = CheckResult("seo", "Video SEO", 18)
        vo = self._find_video_object()
        text_l = self.raw_html.lower()

        has_vo = bool(vo)
        r.add("VideoObject structured data", 3, 3, has_vo,
              "JSON-LD VideoObject found" if has_vo else "no VideoObject schema")

        title = ""
        if vo:
            title = str(vo.get("name") or vo.get("headline") or "")
        if not title:
            title = self.meta.get("og:title", "") or (self.soup.title.get_text().strip() if self.soup and self.soup.title else "")
        title_ok = bool(title) and 10 <= len(title) <= 70
        r.add("Video title quality", 2, 2, title_ok,
              f"len={len(title)}" if title else "missing")
        if title:
            r.find(f"title: {title[:90]}")
        if title and not title_ok:
            r.warn(f"Title length {len(title)} outside 10-70 chars")

        description = ""
        if vo:
            description = str(vo.get("description") or "")
        if not description:
            description = self.meta.get("og:description", "") or self.meta.get("description", "")
        desc_ok = bool(description) and len(description) >= 50
        r.add("Video description quality", 2, 2, desc_ok,
              f"len={len(description)}" if description else "missing")
        if description:
            r.find(f"description: {description[:90]}")

        thumb = ""
        if vo:
            thumb = vo.get("thumbnailUrl") or vo.get("thumbnailURL") or ""
            if isinstance(thumb, list):
                thumb = thumb[0] if thumb else ""
            thumb = str(thumb)
        if not thumb:
            thumb = self.meta.get("og:image", "")
        if not thumb and self.inventory["thumbnails"]:
            thumb = self.inventory["thumbnails"][0]
        if not thumb and self.soup is not None:
            for v in self.soup.find_all("video"):
                if v.get("poster"):
                    thumb = v.get("poster")
                    break
        thumb_ok = bool(thumb)
        r.add("Video thumbnail/poster", 2, 2, thumb_ok,
              thumb[:80] if thumb else "none")
        if thumb:
            r.find(f"thumbnail: {thumb[:90]}")

        duration = str(vo.get("duration", "")) if vo else ""
        if not duration:
            duration = self.meta.get("video:duration", "") or ""
        dur_ok = bool(duration)
        r.add("Video duration metadata", 2, 2, dur_ok,
              duration if duration else "not in schema")
        if duration:
            r.find(f"duration: {duration}")

        upload = str(vo.get("uploadDate", "") or vo.get("datePublished", "") or vo.get("dateCreated", "")) if vo else ""
        if not upload:
            upload = self.meta.get("article:published_time", "") or ""
        upload_ok = bool(upload)
        r.add("Video upload date", 2, 2, upload_ok,
              upload if upload else "not in schema")
        if upload:
            r.find(f"uploadDate: {upload}")

        schema_fields = ["name", "description", "thumbnailUrl", "uploadDate", "duration", "contentUrl", "embedUrl"]
        present = [f for f in schema_fields if f in vo]
        schema_ok = has_vo and len(present) >= 4
        r.add("Video schema validation", 2, 2, schema_ok,
              f"{len(present)}/{len(schema_fields)} recommended fields")
        if has_vo and len(present) < 4:
            missing = [f for f in schema_fields if f not in vo]
            r.warn(f"Schema missing fields: {', '.join(missing)}")

        og_video = (
            self.meta.get("og:video")
            or self.meta.get("og:video:url")
            or self.meta.get("og:video:secure_url")
            or ""
        )
        og_ok = bool(og_video)
        r.add("Open Graph video tags", 2, 2, og_ok,
              str(og_video)[:80] if og_ok else "no og:video tags")
        if og_ok:
            r.find(f"og:video: {str(og_video)[:80]}")

        rich_ready = has_vo and bool(duration) and bool(upload) and thumb_ok and len(present) >= 4
        r.add("Video rich snippet readiness", 1, 1, rich_ready,
              "schema fields support rich results" if rich_ready else "incomplete rich-result signals")
        if not rich_ready:
            r.warn("Rich-result eligibility incomplete (need duration, uploadDate, thumbnail, schema fields)")

        r.clamp()
        return r

    def check_accessibility(self):
        r = CheckResult("accessibility", "Video Accessibility", 18)
        soup = self.soup
        text_l = self.raw_html.lower()

        caption_hits = []
        if soup is not None:
            for track in soup.find_all("track"):
                src = track.get("src", "") or ""
                kind = (track.get("kind") or "").lower()
                if any(x in (src.lower()) for x in (".vtt", ".srt")) or kind in ("captions", "subtitles", "descriptions", "chapters"):
                    caption_hits.append(f"track kind={kind or 'n/a'} src={src[:70]}")
            for tag in soup.find_all(["a", "link", "source", "video"]):
                href = (tag.get("href") or tag.get("src") or "").lower()
                if href.endswith(".vtt") or href.endswith(".srt"):
                    caption_hits.append(href[:80])
        for ext in (".vtt", ".srt", "captions", "subtitles", "closed caption", "cc"):
            if ext in text_l:
                caption_hits.append(f"page text match: {ext}")
                break
        captions_ok = bool(caption_hits)
        r.add("Captions/subtitles detection", 4, 4, captions_ok,
              "; ".join(caption_hits[:3]) if caption_hits else "no captions found")
        for hit in caption_hits[:5]:
            r.find(f"caption: {hit}")

        audio_desc = False
        if soup is not None:
            for track in soup.find_all("track"):
                if (track.get("kind") or "").lower() == "descriptions":
                    audio_desc = True
                    r.find(f"audio description track: {track.get('src', '')[:70]}")
        if "audio description" in text_l or "audiodesc" in text_l:
            audio_desc = True
            r.find("audio description referenced on page")
        r.add("Audio description detection", 2, 2, audio_desc,
              "audio descriptions present" if audio_desc else "none detected")

        transcript = False
        transcript_hint = ""
        for sel in ("transcript", ".transcript", "#transcript", "video-transcript", "sr-transcript", "details"):
            if sel.startswith((".", "#")):
                if soup is not None and soup.select_one(sel):
                    transcript = True
                    transcript_hint = f"selector {sel}"
                    break
        if not transcript and "transcript" in text_l:
            transcript = True
            transcript_hint = "word 'transcript' on page"
        r.add("Video transcript detection", 4, 4, transcript,
              transcript_hint if transcript else "no transcript")
        if transcript:
            r.find(f"transcript: {transcript_hint}")

        controls = False
        if soup is not None:
            videos = soup.find_all("video")
            if videos and any(v.has_attr("controls") or v.has_attr("controlslist") for v in videos):
                controls = True
                r.find("native controls present")
            if any(f.has_attr("title") for f in soup.find_all("iframe")):
                r.find("iframe has title attribute")
        if not controls and any(x in text_l for x in ("controls", "plyr", "video.js", "jwplayer")):
            controls = True
            r.find("player library implies controls")
        r.add("Video controls accessibility", 3, 3, controls,
              "controls available" if controls else "no controls detected")

        keyboard = False
        if soup is not None:
            for el in soup.find_all(attrs={"tabindex": True}):
                keyboard = True
                r.find(f"tabindex on <{el.name}>")
                break
            for el in soup.find_all(["a", "button", "video", "iframe", "div", "span"]):
                if el.get("aria-label") or el.get("role"):
                    if any(x in (el.get("role") or "") for x in ("button", "slider", "application")) or el.name in ("video", "button", "a"):
                        keyboard = True
                        r.find(f"role/aria on <{el.name}>")
                        break
            for v in soup.find_all("video"):
                if v.get("tabindex") is not None:
                    keyboard = True
        if not keyboard and ("keydown" in text_l or "keyup" in text_l or "onkey" in text_l):
            keyboard = True
            r.find("keyboard handlers referenced")
        r.add("Keyboard navigation support", 2, 2, keyboard,
              "keyboard hooks found" if keyboard else "no keyboard affordances")

        lang_ok = False
        lang_detail = "no srclang/label on tracks"
        if soup is not None:
            with_lang = [t for t in soup.find_all("track") if (t.get("srclang") or t.get("label"))]
            if with_lang:
                lang_ok = True
                t0 = with_lang[0]
                lang_detail = f"srclang={t0.get('srclang', '')} label={str(t0.get('label', ''))[:40]}"
        r.add("Caption language attributes", 1, 1, lang_ok, lang_detail)

        aria = False
        aria_detail = "no aria-label/title/role on player"
        if soup is not None:
            for v in soup.find_all("video"):
                if v.get("aria-label") or v.get("title") or v.get("role"):
                    aria = True
                    aria_detail = f"video label: {str(v.get('aria-label') or v.get('title'))[:60]}"
                    break
            if not aria:
                for f in soup.find_all("iframe"):
                    if f.get("title") or f.get("aria-label"):
                        aria = True
                        aria_detail = f"iframe title: {str(f.get('title') or f.get('aria-label'))[:60]}"
                        break
            if not aria:
                for el in soup.find_all(attrs={"aria-label": True}):
                    cls = " ".join(el.get("class") or []).lower()
                    if any(x in cls for x in ("player", "video", "media")):
                        aria = True
                        aria_detail = f"aria-label on <{el.name} class={cls[:50]}>"
                        break
        r.add("Player ARIA labelling", 2, 2, aria, aria_detail)
        if aria:
            r.find(f"aria: {aria_detail}")

        r.clamp()
        return r

    def check_formats(self):
        r = CheckResult("formats", "Video Formats", 10)
        formats = set(self.inventory["formats"])
        text_l = self.raw_html.lower()

        modern = {"webm", "mp4", "hls", "dash", "ogv"}
        found_modern = sorted(formats & modern)
        if not found_modern:
            if "video/mp4" in text_l:
                found_modern.append("mp4")
            if "video/webm" in text_l:
                found_modern.append("webm")
            if ".m3u8" in text_l or "hls" in text_l:
                found_modern.append("hls")
            if ".mpd" in text_l or "dash" in text_l:
                found_modern.append("dash")
        modern_ok = bool(found_modern)
        r.add("Modern format usage", 3, 3, modern_ok,
              ", ".join(found_modern) if found_modern else "none")
        for f in found_modern:
            r.find(f"modern format: {f}")

        legacy = {"flv", "avi", "mov", "wmv", "mkv"}
        found_legacy = sorted(formats & legacy)
        legacy_present = bool(found_legacy)
        r.add("Legacy format usage", 2, 2, not legacy_present,
              ", ".join(found_legacy) if found_legacy else "no legacy formats")
        if legacy_present:
            r.warn(f"legacy formats present: {', '.join(found_legacy)}")

        compat_ok = False
        compat_detail = "unknown"
        if "mp4" in formats or "hls" in formats:
            compat_ok = True
            compat_detail = "mp4/hls broad compatibility"
        elif "webm" in formats and "mp4" not in formats:
            compat_ok = False
            compat_detail = "webm-only may miss Safari/older clients"
        elif formats:
            compat_ok = False
            compat_detail = f"formats: {', '.join(sorted(formats))}"
        r.add("Format compatibility analysis", 3, 3, compat_ok, compat_detail)

        adaptive = sorted(formats & {"hls", "dash"})
        has_adaptive = bool(adaptive)
        r.add("Adaptive streaming detection", 2, 2, has_adaptive,
              ", ".join(adaptive) if adaptive else "no HLS/DASH")
        if has_adaptive:
            r.find(f"adaptive streaming: {', '.join(adaptive)}")

        r.clamp()
        return r

    def check_performance(self):
        r = CheckResult("performance", "Video Performance", 14)
        soup = self.soup
        text_l = self.raw_html.lower()

        preload = None
        if soup is not None:
            for v in soup.find_all("video"):
                if v.has_attr("preload"):
                    preload = (v.get("preload") or "").lower()
                    break
        if preload is None:
            preload = "unspecified"
        good_preload = preload in ("none", "metadata")
        r.add("Video preload strategy", 3, 3, good_preload or preload == "auto",
              f"preload={preload}")
        if preload == "auto":
            r.warn("preload=auto may cost bandwidth before playback")
        elif good_preload:
            r.find(f"preload={preload} (bandwidth-friendly)")

        lazy = False
        if soup is not None:
            for v in soup.find_all("video"):
                attrs = {k.lower() for k in v.attrs.keys()}
                if "loading" in attrs and (v.get("loading") or "").lower() == "lazy":
                    lazy = True
                    r.find("video loading=lazy")
                break
            if any(f.get("loading") == "lazy" for f in soup.find_all("iframe")):
                lazy = True
                r.find("iframe loading=lazy")
            if soup.find(attrs={"data-src": True}):
                src_count = len(soup.find_all(attrs={"data-src": True}))
                if src_count:
                    lazy = True
                    r.find(f"data-src lazy pattern x{src_count}")
        if not lazy and ("lazyload" in text_l or "lazy-load" in text_l or "intersectionobserver" in text_l):
            lazy = True
            r.find("lazy loading library/hook referenced")
        r.add("Lazy loading detection", 2, 2, lazy,
              "lazy loading detected" if lazy else "no lazy loading")

        size_kb = None
        size_detail = "not measurable from HTML"
        if self.response is not None:
            clen = self.response.headers.get("content-length") or self.response.headers.get("Content-Length")
            if clen and str(clen).isdigit():
                size_kb = int(clen) // 1024
                size_detail = f"page approx {size_kb} KB"
        size_ok = True
        if size_kb is not None and size_kb > 3000:
            size_ok = False
            r.warn(f"large page payload: {size_kb} KB")
        r.add("Video file size estimation", 2, 2, True, size_detail)

        qualities = self.inventory["qualities"]
        has_quality = bool(qualities)
        r.add("Video quality options", 3, 3, has_quality,
              ", ".join(qualities[:6]) if qualities else "no quality labels")
        if qualities:
            r.find(f"quality options: {', '.join(qualities[:8])}")

        hints = []
        if soup is not None:
            for link in soup.find_all("link", href=True):
                rel = " ".join(link.get("rel") or []).lower()
                if any(x in rel for x in ("preconnect", "dns-prefetch", "preload")):
                    hints.append(rel.split()[0] + ":" + (link.get("href") or "")[:50])
        hint_ok = bool(hints)
        r.add("Resource hints for media hosts", 2, 2, hint_ok,
              ", ".join(hints[:3]) if hints else "no preconnect/dns-prefetch/preload hints")
        if hints:
            r.find(f"resource hints: {', '.join(hints[:3])}")

        ext_scripts = []
        if soup is not None:
            for s in soup.find_all("script", src=True):
                ext_scripts.append(s.get("src") or "")
        scount = len(ext_scripts)
        scripts_ok = scount <= 15
        r.add("Third-party script weight", 2, 2, scripts_ok, f"{scount} script tag(s) with src")
        if not scripts_ok:
            r.warn(f"{scount} external scripts on page; defer/trim non-player scripts")

        r.clamp()
        return r

    def check_metadata(self):
        r = CheckResult("metadata", "Video Metadata", 14)
        soup = self.soup
        text_l = self.raw_html.lower()

        title_attr = False
        title_detail = ""
        if soup is not None:
            for v in soup.find_all("video"):
                if v.get("title") or v.get("aria-label"):
                    title_attr = True
                    title_detail = f"title/aria-label: {(v.get('title') or v.get('aria-label'))[:70]}"
                    break
            if not title_attr:
                for f in soup.find_all("iframe"):
                    if f.get("title"):
                        title_attr = True
                        title_detail = f"iframe title: {f.get('title')[:70]}"
                        break
        if not title_attr:
            t = self.meta.get("og:title") or (soup.title.get_text().strip() if soup and soup.title else "")
            if t:
                title_attr = True
                title_detail = f"page title: {t[:70]}"
        r.add("Video title attribute", 2, 2, title_attr,
              title_detail if title_attr else "missing")

        desc = self.meta.get("og:description") or self.meta.get("description") or ""
        vo = self._find_video_object()
        if not desc and vo:
            desc = str(vo.get("description") or "")
        desc_ok = bool(desc)
        r.add("Video description", 2, 2, desc_ok,
              f"len={len(desc)}" if desc else "missing")
        if desc:
            r.find(f"description: {desc[:90]}")

        keywords = ""
        kw_keys = ("keywords", "news_keywords", "video:tag", "video:keywords", "article:tag")
        for k in kw_keys:
            if self.meta.get(k):
                keywords = self.meta[k]
                break
        if not keywords and vo:
            tags = vo.get("keywords") or vo.get("genre") or ""
            if isinstance(tags, list):
                tags = ", ".join(str(t) for t in tags)
            keywords = str(tags)
        if not keywords and "keywords" in text_l:
            kw = soup.find("meta", attrs={"name": "keywords"}) if soup else None
            if kw:
                keywords = kw.get("content", "")
        kw_ok = bool(keywords.strip())
        r.add("Video keywords/tags", 2, 2, kw_ok,
              str(keywords)[:70] if kw_ok else "none")

        duration = ""
        if vo:
            duration = str(vo.get("duration") or "")
        if not duration:
            duration = self.meta.get("video:duration", "") or ""
        dur_ok = bool(duration) and bool(re.search(r"\d", duration))
        r.add("Video duration format", 2, 2, dur_ok,
              duration if duration else "missing")
        if duration:
            r.find(f"duration: {duration}")

        resolution = ""
        for q in self.inventory["qualities"]:
            if re.search(r"\d{3,4}p|\d{3,4}", q):
                resolution = q
                break
        if not resolution and vo:
            res = vo.get("width") or vo.get("height")
            if res:
                resolution = f"{vo.get('width', '?')}x{vo.get('height', '?')}"
        res_ok = bool(resolution)
        r.add("Video resolution metadata", 2, 2, res_ok,
              resolution if resolution else "unknown")

        og_video = (
            self.meta.get("og:video")
            or self.meta.get("og:video:url")
            or self.meta.get("og:video:secure_url")
            or ""
        )
        og_ok = bool(og_video)
        r.add("Open Graph video metadata", 2, 2, og_ok,
              str(og_video)[:80] if og_ok else "og:video missing")

        media_urls = []
        if vo:
            for k in ("contentUrl", "embedUrl"):
                if vo.get(k):
                    media_urls.append(k)
        media_ok = len(media_urls) >= 1
        r.add("Schema media URLs", 2, 2, media_ok,
              ", ".join(media_urls) if media_urls else "contentUrl/embedUrl not in schema")
        if media_urls:
            r.find(f"schema media: {', '.join(media_urls)}")

        r.clamp()
        return r

    def check_streaming(self):
        r = CheckResult("streaming", "Video Streaming (HLS/DASH)", 12)
        formats = set(self.inventory["formats"])
        protos = self.inventory.get("streaming_protocols") or []
        manifests = self.inventory.get("streaming_manifests") or []
        text_l = self.raw_html.lower()

        hls = ("hls" in formats) or ("HLS" in protos) or ".m3u8" in text_l or "mpegurl" in text_l
        r.add("HLS manifest detection", 3, 3, hls,
              "HLS (.m3u8) referenced" if hls else "no HLS manifest")
        if hls:
            r.find("streaming protocol: HLS")
            if manifests:
                r.find(f"hls manifest: {manifests[0][:80]}")

        dash = ("dash" in formats) or ("DASH" in protos) or ".mpd" in text_l or "dash+xml" in text_l
        r.add("DASH manifest detection", 3, 3, dash,
              "DASH (.mpd) referenced" if dash else "no DASH manifest")
        if dash:
            r.find("streaming protocol: DASH")

        ladder = 0
        ladder += len(re.findall(r"RESOLUTION\s*=\s*\d{2,4}x\d{2,4}", self.raw_html, re.I))
        ladder += len(re.findall(r"BANDWIDTH\s*=\s*\d+", self.raw_html, re.I))
        ladder += len(re.findall(r"""["'](?:bandwidth|bitrate)["']\s*[:=]""", self.raw_html, re.I))
        ladder += len(re.findall(r"""["'](?:width|height)["']\s*[:=]\s*\d+""", self.raw_html, re.I))
        ladder_ok = ladder >= 2
        r.add("Adaptive bitrate ladder", 2, 2, ladder_ok, f"{ladder} variant hint(s)")
        if ladder_ok:
            r.find(f"variant hints: {ladder}")

        signals = []
        if re.search(r"codecs\s*=", self.raw_html, re.I):
            signals.append("codecs attribute")
        if re.search(r"EXT-X-VERSION", self.raw_html):
            signals.append("HLS version tag")
        if re.search(r"EXT-X-STREAM-INF", self.raw_html):
            signals.append("HLS variants")
        if re.search(r"mimeType\s*[:=]", self.raw_html, re.I):
            signals.append("DASH mimeType")
        if re.search(r"frameRate\s*[:=]", self.raw_html, re.I):
            signals.append("frameRate")
        r.add("Manifest quality signals", 2, 2, bool(signals),
              ", ".join(signals) if signals else "no codec/variant metadata")
        if signals:
            r.find(f"manifest signals: {', '.join(signals)}")

        fallback = bool(formats & {"mp4", "webm", "ogv"}) or "video/mp4" in text_l or "video/webm" in text_l
        r.add("Progressive fallback source", 2, 2, fallback,
              "mp4/webm fallback present" if fallback else "no progressive fallback")
        if fallback:
            r.find("progressive fallback available for non-adaptive clients")

        r.clamp()
        return r

    def check_quality(self):
        r = CheckResult("quality", "Video Quality", 12)
        qualities = self.inventory["qualities"]
        text_l = self.raw_html.lower()
        soup = self.soup

        res_nums = set()
        for q in qualities:
            m = re.search(r"(\d{3,4})", q)
            if m:
                res_nums.add(int(m.group(1)))
        for m in re.finditer(r"\b(\d{3,4})p\b", self.raw_html, re.I):
            res_nums.add(int(m.group(1)))
        ladder_ok = len(res_nums) >= 2 or (len(res_nums) == 1 and max(res_nums) >= 720)
        ladder_detail = ", ".join(f"{n}p" for n in sorted(res_nums)[:6]) if res_nums else "no resolution labels"
        r.add("Resolution ladder options", 3, 3, ladder_ok, ladder_detail)
        if res_nums:
            r.find(f"resolutions: {', '.join(str(n) for n in sorted(res_nums))}")

        high_keys = ("1080p", "1440p", "2160p", "4k", "uhd", "hdr", "dolby vision")
        high = any(q in qualities for q in ("1080p", "1440p", "2160p", "4k", "uhd")) or any(
            x in text_l for x in high_keys
        )
        r.add("High resolution availability", 1, 1, bool(high),
              "1080p+ / 4K hint found" if high else "no high-res hint")

        sel = False
        sel_detail = "no quality selector"
        if soup is not None:
            try:
                if soup.select("[class*=quality], [data-quality], [id*=quality], [class*=resolution-menu]"):
                    sel = True
                    sel_detail = "quality selector element found"
            except Exception:
                pass
        if not sel and "quality" in text_l and len(qualities) >= 2:
            sel = True
            sel_detail = "quality options referenced in page text"
        if not sel and self.inventory["players"] and "auto" in text_l and len(qualities) >= 2:
            sel = True
            sel_detail = "player library with quality options"
        r.add("Quality selector UI", 2, 2, sel, sel_detail)

        poster = False
        poster_detail = "no poster/thumbnail"
        if soup is not None:
            for v in soup.find_all("video"):
                if v.get("poster"):
                    poster = True
                    poster_detail = f"poster: {str(v.get('poster'))[:70]}"
                    break
        if not poster and self.inventory["thumbnails"]:
            poster = True
            poster_detail = f"thumbnail: {self.inventory['thumbnails'][0][:70]}"
        r.add("Poster/thumbnail presence", 2, 2, poster, poster_detail)

        codec_keys = ("av1", "av01", "vp9", "vp09", "h264", "h.264", "h265", "h.265", "hevc", "codecs=")
        codecs = [k for k in codec_keys if k in text_l]
        r.add("Codec option hints", 2, 2, bool(codecs),
              ", ".join(codecs[:5]) if codecs else "no codec hints")
        if codecs:
            r.find(f"codecs: {', '.join(codecs)}")

        audio_keys = (
            "audio track", "audio tracks", "multi-audio", "dolby", "5.1",
            "stereo", "aac", "eac3", "spatial audio", "language audio",
        )
        audio = [k for k in audio_keys if k in text_l]
        r.add("Audio track options", 2, 2, bool(audio),
              ", ".join(audio[:4]) if audio else "no alternate audio hints")
        if audio:
            r.find(f"audio options: {', '.join(audio[:4])}")

        r.clamp()
        return r

    def check_compression(self):
        r = CheckResult("compression", "Video Compression", 8)
        formats = set(self.inventory["formats"])
        text_l = self.raw_html.lower()

        modern = sorted(formats & {"mp4", "webm", "hls", "dash", "ogv"})
        if not modern and "video/mp4" in text_l:
            modern = ["mp4"]
        r.add("Modern container usage", 2, 2, bool(modern),
              ", ".join(modern) if modern else "no modern containers detected")
        if modern:
            r.find(f"modern containers: {', '.join(modern)}")

        codec_keys = ("av1", "vp9", "h265", "h.265", "hevc", "h264", "h.264", "avc1", "av01", "vp09")
        found_codecs = [k for k in codec_keys if k in text_l]
        efficient = [k for k in ("av1", "av01", "vp9", "vp09", "h265", "h.265", "hevc") if k in text_l]
        codec_ok = bool(found_codecs)
        r.add("Efficient codec hints", 2, 2, codec_ok,
              ", ".join(found_codecs[:5]) if found_codecs else "no codec hints in markup")
        if efficient:
            r.find(f"efficient codecs: {', '.join(efficient)}")

        poster_opt = False
        poster_detail = "no optimized poster hint"
        if self.soup is not None:
            posters = []
            for v in self.soup.find_all("video"):
                if v.get("poster"):
                    posters.append(v.get("poster"))
            posters.extend(self.inventory["thumbnails"] or [])
            for p in posters:
                pl = (p or "").lower()
                if any(x in pl for x in (".webp", ".avif")):
                    poster_opt = True
                    poster_detail = f"modern poster format: {p[:70]}"
                    break
                if any(x in pl for x in (".jpg", ".jpeg", ".png")):
                    poster_opt = True
                    poster_detail = f"raster poster: {p[:70]}"
                    break
            if not poster_opt:
                for img in self.soup.find_all("img"):
                    src = (img.get("src") or "").lower()
                    if any(x in src for x in ("thumb", "poster", "video", "preview")):
                        if img.get("srcset") or (img.get("width") and img.get("height")):
                            poster_opt = True
                            poster_detail = "thumbnail with dimensions/srcset"
                            break
        r.add("Poster image optimization", 2, 2, poster_opt, poster_detail)

        seg = bool(formats & {"hls", "dash"}) or "hls" in text_l or "dash" in text_l
        r.add("Segmented delivery", 2, 2, seg,
              "HLS/DASH segmented delivery" if seg else "progressive download only")
        if seg:
            r.find("segmented delivery reduces per-request payload")

        r.clamp()
        return r

    def check_delivery(self):
        r = CheckResult("delivery", "Video Delivery", 8)
        ch = self.inventory.get("cache_headers") or {}
        text_l = self.raw_html.lower()

        cdn_hits = []
        for k in (
            "age", "x-cache", "x-cache-hits", "cf-cache-status", "via",
            "x-amz-cf-pop", "x-amz-cf-id", "x-fastly-request-id", "x-served-by",
        ):
            if k in ch:
                cdn_hits.append(k)
        server_val = str(ch.get("server") or "").lower()
        for name in ("cloudfront", "akamai", "fastly", "cloudflare", "bunny", "varnish", "cloudinary"):
            if name in server_val:
                cdn_hits.append(f"server:{name}")
        for key in ("cdn.", "cloudfront", "akamai", "fastly", "bunnycdn"):
            if key in text_l and key not in cdn_hits:
                cdn_hits.append(key)
        r.add("CDN header detection", 2, 2, bool(cdn_hits),
              ", ".join(sorted(set(cdn_hits))[:5]) if cdn_hits else "no CDN signals")
        if cdn_hits:
            r.find(f"cdn signals: {', '.join(sorted(set(cdn_hits))[:6])}")

        hv = (self.inventory.get("http_version") or "").strip().upper()
        hv_ok = True
        if hv:
            hv_ok = ("HTTP/2" in hv) or ("HTTP/3" in hv) or hv in ("2", "3")
        hv_detail = hv or "unknown (not penalized)"
        r.add("HTTP/2+ protocol", 2, 2, hv_ok, hv_detail)
        if hv and not hv_ok:
            r.warn(f"origin serving {hv}; enable HTTP/2 or HTTP/3")

        ar = str(ch.get("accept-ranges") or "").lower()
        ar_ok = "bytes" in ar
        r.add("Range request support", 2, 2, ar_ok,
              ar if ar else "accept-ranges not observed on HTML response")

        mixed = False
        if self.url.lower().startswith("https://"):
            for m in re.finditer(r"""(?:src|href|poster|url)\s*=\s*["'](http://[^"']+)["]""", self.raw_html, re.I):
                u = m.group(1).lower()
                if any(x in u for x in (".mp4", ".webm", ".m3u8", ".mpd", ".mp3", ".vtt", "video", "media", "stream")):
                    mixed = True
                    r.warn(f"insecure media URL: {m.group(1)[:80]}")
                    break
            r.add("Mixed content safety", 2, 2, not mixed,
                  "no http:// media on HTTPS page" if not mixed else "insecure media URL(s) found")
        else:
            r.add("Mixed content safety", 2, 2, True,
                  "page is HTTP; mixed-content rule not applicable")

        r.clamp()
        return r

    def check_caching(self):
        r = CheckResult("caching", "Video Caching", 6)
        ch = self.inventory.get("cache_headers") or {}
        cc = str(ch.get("cache-control") or "").strip()

        r.add("Cache-Control presence", 2, 2, bool(cc),
              cc if cc else "no cache-control header observed")
        if cc:
            r.find(f"cache-control: {cc[:90]}")

        eff = False
        eff_detail = "no policy"
        if cc:
            low = cc.lower()
            m = re.search(r"max-age\s*=\s*(\d+)", low)
            if "immutable" in low:
                eff = True
                eff_detail = "immutable"
            elif m and int(m.group(1)) >= 60:
                eff = True
                eff_detail = f"max-age={m.group(1)}"
            elif "public" in low:
                eff = True
                eff_detail = "public"
            else:
                eff_detail = low[:70]
        r.add("Effective cache policy", 2, 2, eff, eff_detail)

        validators = bool(ch.get("etag") or ch.get("last-modified"))
        v_detail = ", ".join(k for k in ("etag", "last-modified") if k in ch) or "none"
        r.add("Cache validators", 1, 1, validators, v_detail)

        edge_keys = ("age", "x-cache", "x-cache-hits", "cf-cache-status", "cdn-cache-control", "surrogate-control")
        edge_hits = [k for k in edge_keys if k in ch]
        r.add("Edge/CDN cache evidence", 1, 1, bool(edge_hits),
              ", ".join(edge_hits) if edge_hits else "no edge cache headers")
        for k in edge_hits:
            r.find(f"{k}: {str(ch.get(k))[:60]}")

        r.clamp()
        return r

    def check_sharing(self):
        r = CheckResult("sharing", "Video Sharing", 5)
        soup = self.soup
        text_l = self.raw_html.lower()

        share_selectors = [
            ".share", ".social-share", ".sharing", "[class*=share]",
            "[class*=social]", ".addthis", ".shariff", ".addtoany",
        ]
        share_count = 0
        if soup is not None:
            seen = set()
            for sel in share_selectors:
                try:
                    for el in soup.select(sel):
                        key = id(el)
                        if key not in seen:
                            seen.add(key)
                            share_count += 1
                except Exception:
                    pass
            for a in soup.find_all("a", href=True):
                href = a["href"].lower()
                if any(x in href for x in ("twitter.com/share", "facebook.com/sharer",
                                           "linkedin.com/sharing", "wa.me", "mailto:",
                                           "/share", "addthis", "addtoany")):
                    share_count += 1
        share_ok = share_count > 0 or any(x in text_l for x in ("share on", "share this", "social share", "addtoany", "addthis"))
        r.add("Social sharing buttons detection", 2, 2, share_ok,
              f"{share_count} share element(s)" if share_count else "none")
        if share_ok:
            r.find("share UI detected")

        share_link = False
        if "share" in text_l or "sharer" in text_l or "clipboard" in text_l:
            share_link = True
            r.find("share links / copy actions referenced")
        r.add("Video share links", 1, 1, share_link,
              "present" if share_link else "absent")

        embed_code = False
        if any(x in text_l for x in ("embed code", "embed this", "<iframe", "copy embed", "oembed")):
            embed_code = True
            r.find("embed code / iframe snippet available")
        r.add("Embed code availability", 2, 2, embed_code,
              "available" if embed_code else "not offered")

        r.clamp()
        return r

    def check_hosting(self):
        r = CheckResult("hosting", "Video Hosting", 10)
        text_l = self.raw_html.lower()
        platforms = self.inventory["platforms"]

        yt = "YouTube" in platforms or any(x in text_l for x in ("youtube.com/embed", "youtu.be/", "youtube-nocookie"))
        r.add("YouTube embedding", 3, 3, yt,
              "YouTube embed found" if yt else "no YouTube embed")
        if yt:
            r.find("platform: YouTube")

        vm = "Vimeo" in platforms or "player.vimeo.com" in text_l
        r.add("Vimeo embedding", 2, 2, vm,
              "Vimeo embed found" if vm else "no Vimeo embed")
        if vm:
            r.find("platform: Vimeo")

        self_hosted = False
        if self.soup is not None:
            if self.soup.find("video"):
                for src_tag in list(self.soup.find_all("video")) + list(self.soup.find_all("source")):
                    src = (src_tag.get("src") or "").lower()
                    if src and not any(p in src for p in ("youtube", "vimeo", "dailymotion", "wistia",
                                                          "brightcove", "vidyard", "kaltura")):
                        if src.startswith(("http", "//", "/", "./", "../")) or src.endswith((".mp4", ".webm", ".m3u8", ".mpd")):
                            self_hosted = True
                            r.find(f"self-hosted src: {src[:80]}")
                            break
            if not self_hosted and self.soup.find("video") and not platforms:
                self_hosted = True
                r.find("video tag without third-party platform")
        if not self_hosted and re.search(r"https?://[^\"'\s]+\.(mp4|webm|m3u8|mpd)", text_l):
            self_hosted = True
            r.find("direct media URL in page")
        r.add("Self-hosted detection", 2, 2, self_hosted,
              "self-hosted media" if self_hosted else "no direct media")

        cdn_keys = ("cdn.", "cloudfront", "akamai", "fastly", "bunnycdn", "cloudinary",
                    "imgix", "jsdelivr", "unpkg", "hls", "m3u8", "maxcdn", "edgecast",
                    "level3", "limelight", "highwinds", "bilibili", "byteoversea",
                    "video-src", "media.", "static.", "assets.")
        cdn_hits = [k for k in cdn_keys if k in text_l]
        if self.response is not None:
            for h in ("server", "via", "x-cache", "cf-ray", "x-amz-cf", "age"):
                if self.response.headers.get(h):
                    cdn_hits.append(f"header:{h}")
        cdn_ok = bool(cdn_hits)
        r.add("Video CDN detection", 1, 1, cdn_ok,
              ", ".join(sorted(set(cdn_hits))[:5]) if cdn_hits else "no CDN hints")

        other = [p for p in platforms if p not in ("YouTube", "Vimeo")]
        host_ok = bool(platforms) or self_hosted
        r.add("Video hosting platform detection", 2, 2, host_ok,
              ", ".join(platforms + (["self-hosted"] if self_hosted else [])) if host_ok else "undetermined")
        if other:
            r.find(f"other platforms: {', '.join(other)}")

        r.clamp()
        return r

    def check_interactivity(self):
        r = CheckResult("interactivity", "Video Interactivity", 5)
        text_l = self.raw_html.lower()
        soup = self.soup

        chapters = False
        if soup is not None:
            for track in soup.find_all("track"):
                if (track.get("kind") or "").lower() == "chapters" or ".vtt" in (track.get("src") or "").lower() and "chapter" in (track.get("src") or "").lower():
                    chapters = True
                    r.find(f"chapters track: {track.get('src', '')[:70]}")
                    break
            for el in soup.select("[class*=chapter], .timestamps, [data-chapters]"):
                chapters = True
                r.find(f"chapter UI: {el.name} class={el.get('class')}")
                break
        if not chapters and re.search(r"chapters?|timestamps?|timecode", text_l):
            if re.search(r"\b\d{1,2}:\d{2}(:\d{2})?\b", text_l):
                chapters = True
                r.find("timestamp/chapter markers in page text")
        r.add("Chapters detection", 3, 3, chapters,
              "chapters found" if chapters else "none")

        interactive = False
        if any(x in text_l for x in ("interactive video", "hotspot", "annotation", "in-video",
                                     "choose your", "branching", "360 video", "vr video", "panorama")):
            interactive = True
            r.find("interactive video language detected")
        if soup is not None:
            for el in soup.select("[class*=hotspot], [class*=annotation], [data-hotspot], [class*=interactive-video]"):
                interactive = True
                r.find(f"interactive element: {el.name}")
                break
        r.add("Interactive video elements", 1, 1, interactive,
              "present" if interactive else "none")

        annotations = False
        if "annotation" in text_l and "video" in text_l:
            annotations = True
            r.find("video annotations referenced")
        if soup is not None and soup.select("[class*=annotation], [data-annotation], .note-overlay"):
            annotations = True
            r.find("annotation DOM nodes found")
        r.add("Video annotations", 1, 1, annotations,
              "present" if annotations else "none")

        r.clamp()
        return r

    def check_analytics(self):
        r = CheckResult("analytics", "Video Analytics", 5)
        text_l = self.raw_html.lower()

        track_keys = ("gtag(", "ga(", "dataLayer", "analytics", "track(", "fbq(", "trackEvent",
                      "matomo", "matomoTracker", "_paq", "mixpanel", "amplitude", "segment",
                      "heap(", "fullstory", "hotjar", "clarity(", "woopra", "rakam")
        track_hits = [k for k in track_keys if k.lower() in text_l.lower()]
        if self.soup is not None:
            for script in self.soup.find_all("script"):
                src = (script.get("src") or "").lower()
                if any(x in src for x in ("analytics", "gtag", "gtm", "segment", "mixpanel",
                                          "amplitude", "matomo", "hotjar", "clarity")):
                    track_hits.append(f"script:{src[-40:]}")
        track_ok = bool(track_hits)
        r.add("Video tracking detection", 3, 3, track_ok,
              ", ".join(sorted(set(track_hits))[:4]) if track_hits else "no analytics")
        if track_ok:
            r.find(f"tracking: {', '.join(sorted(set(track_hits))[:5])}")

        completion = False
        for key in ("video_complete", "video_complete", "ended", "complete", "watched",
                    "video_end", "progress", "25%", "50%", "75%", "95%", "percent",
                    "completion", "video_play", "play", "pause"):
            if key in text_l and ("video" in text_l or "player" in text_l):
                completion = True
                r.find(f"completion-related hook: {key}")
                break
        r.add("Video completion tracking", 1, 1, completion,
              "detected" if completion else "not detected")

        impression = False
        for key in ("impression", "view", "impressions", "video_view", "videoview",
                    "player_impression", "exposure", "visibility", "viewability"):
            if key in text_l:
                impression = True
                r.find(f"impression hook: {key}")
                break
        if not impression and self.soup is not None:
            if self.soup.select("[data-analytics], [data-event], [data-track], [data-ga]"):
                impression = True
                r.find("data-analytics/event attributes present")
        r.add("Video impression tracking", 1, 1, impression,
              "detected" if impression else "not detected")

        r.clamp()
        return r

    def run_all(self):
        if not self.fetch():
            return False
        self.collect_inventory()
        checks = [
            self.check_embedding,
            self.check_seo,
            self.check_accessibility,
            self.check_formats,
            self.check_performance,
            self.check_metadata,
            self.check_streaming,
            self.check_quality,
            self.check_compression,
            self.check_delivery,
            self.check_caching,
            self.check_sharing,
            self.check_hosting,
            self.check_interactivity,
            self.check_analytics,
        ]
        for fn in checks:
            try:
                res = fn()
                self.results.append(res)
            except Exception as exc:
                res = CheckResult("error", fn.__name__.replace("check_", ""), 0)
                res.warn(f"checker crashed: {exc}")
                self.results.append(res)
                if self.verbose:
                    import traceback
                    traceback.print_exc()
        return True

    def total_score(self):
        return sum(r.points for r in self.results)

    def max_score(self):
        return sum(r.max_points for r in self.results) or MAX_TOTAL

    def grade(self):
        mx = self.max_score()
        pct = (self.total_score() / mx * 100.0) if mx else 0.0
        for threshold, letter in GRADE_BANDS:
            if pct >= threshold:
                return letter
        return "F"

    def grade_color(self, pal, grade):
        if grade.startswith("A"):
            return pal.bright_green(grade)
        if grade == "B":
            return pal.bright_cyan(grade)
        if grade == "C":
            return pal.bright_yellow(grade)
        if grade == "D":
            return pal.bright_red(grade)
        return pal.red(grade)

    def score_color(self, pal, points, mx):
        if mx == 0:
            return pal.gray(str(points))
        pct = points / mx
        if pct >= 0.9:
            return pal.bright_green(f"{points}/{mx}")
        if pct >= 0.7:
            return pal.bright_cyan(f"{points}/{mx}")
        if pct >= 0.5:
            return pal.bright_yellow(f"{points}/{mx}")
        if pct >= 0.3:
            return pal.bright_red(f"{points}/{mx}")
        return pal.red(f"{points}/{mx}")

    def dimension_scores(self):
        out = {}
        for name, cats in DIMENSIONS.items():
            pts = sum(r.points for r in self.results if r.category in cats)
            mx = sum(r.max_points for r in self.results if r.category in cats)
            pct = int(round(pts / mx * 100)) if mx else 0
            out[name] = {"points": pts, "max": mx, "percent": pct}
        return out

    def recommendations(self):
        if self._recommendations is None:
            self._recommendations = self._build_recommendations()
        return self._recommendations

    def _build_recommendations(self):
        recs = []
        for res in self.results:
            base = PRIORITY_BY_CATEGORY.get(res.category, "medium")
            for item in res.items:
                if item["passed"]:
                    continue
                lost = item["max"] - item["awarded"]
                if lost <= 0:
                    lost = item["max"]
                priority = base
                if lost >= 4 and priority != "high":
                    priority = "high"
                label = item["label"]
                default_action = (
                    f"Fix '{label}' in {res.title} to recover up to {item['max']} points."
                )
                action = ACTIONS.get(label, default_action)
                if label in HIGH_EFFORT_LABELS:
                    effort = "high"
                elif label in LOW_EFFORT_LABELS:
                    effort = "low"
                else:
                    effort = "medium"
                recs.append({
                    "priority": priority,
                    "category": res.category,
                    "category_title": res.title,
                    "title": label,
                    "action": action,
                    "points_lost": lost,
                    "effort": effort,
                    "detail": item.get("detail") or "",
                })
        rank = {"high": 0, "medium": 1, "low": 2}
        recs.sort(key=lambda x: (rank.get(x["priority"], 2), -x["points_lost"], x["category"]))
        return recs

    def roadmap(self):
        if self._roadmap is None:
            self._roadmap = self._build_roadmap()
        return self._roadmap

    def _build_roadmap(self):
        recs = self.recommendations()
        quick = [x for x in recs if x["effort"] == "low"]
        core = [x for x in recs if x["effort"] == "medium"]
        advanced = [x for x in recs if x["effort"] == "high"]

        def phase(name, focus, items):
            return {
                "name": name,
                "focus": focus,
                "items": items,
                "points": sum(i["points_lost"] for i in items),
            }

        return [
            phase("Phase 1: Quick Wins", "attribute, metadata, and markup fixes", quick),
            phase("Phase 2: Core Improvements", "player, performance, and structural work", core),
            phase("Phase 3: Advanced Optimization", "streaming architecture and long-term gains", advanced),
        ]

def _bar_color(pct):
    if pct >= 80:
        return "#22c55e"
    if pct >= 50:
        return "#38bdf8"
    if pct >= 30:
        return "#facc15"
    return "#ef4444"


def _pct_color(pal, pct):
    if pct >= 80:
        return pal.bright_green
    if pct >= 50:
        return pal.bright_cyan
    if pct >= 30:
        return pal.bright_yellow
    return pal.bright_red


def print_banner(pal):
    colors = [
        pal.bright_magenta, pal.bright_blue, pal.bright_cyan,
        pal.bright_green, pal.bright_yellow, pal.bright_red,
    ]
    for i, line in enumerate(BANNER_LINES):
        print(colors[i % len(colors)](line))
    print(pal.white(
        f"  VideoAnalyzer v{VERSION} — SEO · Accessibility · Streaming · Quality · Delivery · Performance"
    ))
    print(pal.gray("  " + "─" * 64))
    print()


def print_inventory(pal, inv, url):
    print(pal.bold(pal.bright_cyan("  ▸ Video Content Inventory")))
    print(pal.gray("  " + "─" * 60))
    rows = [
        ("Target URL", url),
        ("HTML5 <video> elements", str(inv["video_elements"])),
        ("iframe elements", str(inv["iframes"])),
        ("Detected players", ", ".join(inv["players"]) or "—"),
        ("Detected platforms", ", ".join(inv["platforms"]) or "—"),
        ("Media sources", str(len(inv["sources"]))),
        ("Captions/subtitles", str(len(inv["captions"]))),
        ("Formats found", ", ".join(inv["formats"]) or "—"),
        ("Quality options", ", ".join(inv["qualities"]) or "—"),
        ("Streaming protocols", ", ".join(inv.get("streaming_protocols") or []) or "—"),
        ("Streaming manifests", str(len(inv.get("streaming_manifests") or []))),
        ("Cache headers observed", str(len(inv.get("cache_headers") or {}))),
        ("HTTP version", inv.get("http_version") or "—"),
        ("Thumbnails", str(len(inv["thumbnails"]))),
        ("Script tags", str(inv["scripts"])),
    ]
    width = max(len(k) for k, _ in rows)
    for k, v in rows:
        print(f"    {pal.gray(k.ljust(width))}  {pal.white(v)}")
    print()


def print_dashboard(pal, analyzer, url):
    dims = analyzer.dimension_scores()
    total = analyzer.total_score()
    mx = analyzer.max_score()
    grade = analyzer.grade()
    pct = int(round(total / mx * 100)) if mx else 0
    inv = analyzer.inventory

    print(pal.bold(pal.bright_cyan("  ▸ Video Analysis Dashboard")))
    print(pal.gray("  " + "─" * 60))
    print(
        f"    {pal.white('Overall')}   {pct}%   grade {analyzer.grade_color(pal, grade)}   "
        f"({total}/{mx} pts)"
    )
    print(f"    {pal.gray('Target  ')}  {pal.bright_cyan(url)}")
    print()

    bar_len = 28
    for name, d in dims.items():
        filled = int(round(d["percent"] / 100 * bar_len))
        filled = max(0, min(bar_len, filled))
        bar = "█" * filled + "░" * (bar_len - filled)
        color = _pct_color(pal, d["percent"])
        print(
            f"    {name.ljust(14)} {color(bar)} {d['percent']:>3}%  "
            f"({d['points']}/{d['max']})"
        )
    print()

    formats = ", ".join(inv["formats"]) or "—"
    protocols = ", ".join(inv.get("streaming_protocols") or []) or "—"
    platforms = ", ".join(inv["platforms"]) or "—"
    players = ", ".join(inv["players"]) or "—"
    print(
        f"    {pal.gray('Content ')}  videos={inv['video_elements']}  "
        f"iframes={inv['iframes']}  captions={len(inv['captions'])}  "
        f"thumbnails={len(inv['thumbnails'])}"
    )
    print(f"    {pal.gray('Delivery')}  formats={formats}  protocols={protocols}  http={inv.get('http_version') or '—'}")
    print(
        f"    {pal.gray('Hosting ')}  platforms={platforms}  "
        f"players={players}  cache_headers={len(inv.get('cache_headers') or {})}"
    )
    print()


def print_results(pal, results, verbose, analyzer=None):
    print(pal.bold(pal.bright_cyan("  ▸ Category Breakdown")))
    print(pal.gray("  " + "─" * 60))
    if not results:
        print(pal.gray("    no results"))
        print()
        return
    width = max(len(r.title) for r in results)
    for r in results:
        color = pal.bright_green if r.max_points and r.points / r.max_points >= 0.8 else (
            pal.bright_cyan if r.max_points and r.points / r.max_points >= 0.5 else pal.bright_yellow
        )
        bar_len = 20
        filled = int(round((r.points / r.max_points) * bar_len)) if r.max_points else 0
        bar = "█" * filled + "░" * (bar_len - filled)
        if analyzer is not None:
            score_str = analyzer.score_color(pal, r.points, r.max_points)
        else:
            score_str = f"{r.points}/{r.max_points}"
        print(f"    {color(r.title.ljust(width))}  {color(bar)}  {score_str}")
        for item in r.items:
            mark = pal.green("✔") if item["passed"] else pal.red("✘")
            pts = pal.gray(f"{item['awarded']}/{item['max']}")
            print(f"        {mark} {pal.white(item['label'].ljust(36))} {pts}")
            if item["detail"] and (verbose or not item["passed"]):
                print(pal.gray(f"          {item['detail']}"))
        if verbose:
            for f in r.findings:
                print(pal.gray(f"          · {f}"))
        for w in r.warnings:
            print(pal.yellow(f"          ⚠ {w}"))
    print()


def print_summary(pal, analyzer):
    total = analyzer.total_score()
    grade = analyzer.grade()
    dims = analyzer.dimension_scores()

    print(pal.bold(pal.bright_cyan("  ▸ Assessment Summary")))
    print(pal.gray("  " + "─" * 60))
    if grade in ("A+", "A"):
        box = pal.bg_green
    elif grade == "B":
        box = pal.bg_blue
    elif grade == "C":
        box = pal.bg_yellow
    else:
        box = pal.bg_red
    print(f"    {pal.white('TOTAL SCORE')}   {box(f'  {total} / {analyzer.max_score()}  ')}   {box(f'  GRADE {grade}  ')}")
    print()

    for key in ("SEO", "Accessibility", "Performance", "Quality"):
        d = dims.get(key)
        if not d:
            continue
        label = key.ljust(14)
        pct_str = str(d["percent"]) + "%"
        print(f"    {pal.white(label)} {pal.cyan(pct_str)}  ({d['points']}/{d['max']})")

    recs = analyzer.recommendations()
    recoverable = sum(rec["points_lost"] for rec in recs)
    rec_line = f"+{recoverable} pts across {len(recs)} open recommendation(s)"
    print(f"    {pal.white('Recoverable ')} {pal.yellow(rec_line)}")
    print()

    all_findings = []
    all_warnings = []
    for r in analyzer.results:
        all_findings.extend(r.findings)
        all_warnings.extend(r.warnings)

    if all_findings:
        print(pal.bold(pal.bright_cyan("  ▸ Key Findings")))
        print(pal.gray("  " + "─" * 60))
        for f in all_findings[:15]:
            print(f"    {pal.bright_green('▸')} {pal.white(f)}")
        if len(all_findings) > 15:
            print(pal.gray(f"    … and {len(all_findings) - 15} more"))
        print()

    if all_warnings:
        print(pal.bold(pal.bright_yellow("  ▸ Warnings")))
        print(pal.gray("  " + "─" * 60))
        for w in all_warnings[:15]:
            print(f"    {pal.bright_yellow('!')} {pal.white(w)}")
        if len(all_warnings) > 15:
            print(pal.gray(f"    … and {len(all_warnings) - 15} more"))
        print()


def print_recommendations(pal, recs, verbose=False):
    print(pal.bold(pal.bright_cyan("  ▸ Recommendations")))
    print(pal.gray("  " + "─" * 60))
    if not recs:
        print(f"    {pal.bright_green('✔')} {pal.white('No outstanding issues — video implementation looks solid.')}")
        print()
        return
    show = recs if verbose else recs[:12]
    prio_color = {
        "high": pal.bright_red,
        "medium": pal.bright_yellow,
        "low": pal.bright_cyan,
    }
    for i, rec in enumerate(show, 1):
        c = prio_color.get(rec["priority"], pal.white)
        idx = str(i) + "."
        prio = "[" + c(rec["priority"].upper()) + "]"
        impact = (
            "impact: +" + str(rec["points_lost"]) + " pts · effort: "
            + rec["effort"] + " · " + rec["category"]
        )
        print(f"    {pal.gray(idx)} {prio} {pal.white(rec['title'])}")
        print(f"        {pal.gray(rec['action'])}")
        print(f"        {pal.gray(impact)}")
    if len(recs) > len(show):
        print(pal.gray(f"    … and {len(recs) - len(show)} more (use -v to show all)"))
    print()


def print_roadmap(pal, roadmap):
    print(pal.bold(pal.bright_cyan("  ▸ Optimization Roadmap")))
    print(pal.gray("  " + "─" * 60))
    for phase in roadmap:
        print(f"    {pal.bright_magenta(phase['name'])}  {pal.gray('· ' + phase['focus'])}")
        pts_line = "recoverable points: +" + str(phase["points"])
        print(f"    {pal.gray(pts_line)}")
        if not phase["items"]:
            print(f"      {pal.green('(nothing pending)')}")
        for i, it in enumerate(phase["items"], 1):
            idx = str(i) + "."
            cat = "[" + it["category"] + "]"
            print(f"      {pal.gray(idx)} {pal.white(it['title'])} {pal.gray(cat)}")
        print()


def build_export(analyzer):
    return {
        "tool": "VideoAnalyzer",
        "version": VERSION,
        "url": analyzer.url,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_score": analyzer.total_score(),
        "max_score": analyzer.max_score(),
        "grade": analyzer.grade(),
        "dashboard": analyzer.dimension_scores(),
        "categories": [
            {
                "category": r.category,
                "title": r.title,
                "points": r.points,
                "max_points": r.max_points,
                "items": r.items,
                "findings": r.findings,
                "warnings": r.warnings,
            }
            for r in analyzer.results
        ],
        "recommendations": analyzer.recommendations(),
        "roadmap": analyzer.roadmap(),
        "inventory": analyzer.inventory,
        "structured_data": [
            {k: v for k, v in node.items() if isinstance(v, (str, int, float, list, dict, bool, type(None)))}
            for node in analyzer.structured_data[:20]
        ],
        "meta": analyzer.meta,
    }


def export_json(analyzer, path):
    data = build_export(analyzer)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False, default=str)
    return path


def export_csv(analyzer, path):
    data = build_export(analyzer)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["section", "category", "name", "points", "max", "passed", "detail"])
        writer.writerow(["summary", "total", data["grade"], data["total_score"], data["max_score"], "", data["url"]])
        for name, d in data["dashboard"].items():
            writer.writerow(["dashboard", "dimension", name, d["points"], d["max"], "", str(d["percent"]) + "%"])
        for cat in data["categories"]:
            writer.writerow([
                "category", cat["category"], cat["title"],
                cat["points"], cat["max_points"], "", "",
            ])
            for item in cat["items"]:
                writer.writerow([
                    "check", cat["category"], item["label"],
                    item["awarded"], item["max"],
                    "yes" if item["passed"] else "no",
                    item["detail"],
                ])
        for rec in data["recommendations"]:
            writer.writerow([
                "recommendation", rec["category"], rec["title"],
                rec["points_lost"], "", rec["priority"], rec["action"],
            ])
        for phase in data["roadmap"]:
            writer.writerow([
                "roadmap", phase["name"], phase["focus"],
                phase["points"], len(phase["items"]), "", "",
            ])
        inv = data["inventory"]
        for key in ("video_elements", "iframes", "players", "platforms", "formats",
                    "qualities", "captions", "sources", "thumbnails", "scripts",
                    "streaming_protocols", "streaming_manifests", "cache_headers",
                    "http_version"):
            val = inv.get(key, "")
            if isinstance(val, list):
                if key == "sources":
                    val = f"{len(val)} item(s)"
                else:
                    val = "; ".join(str(x) for x in val)
            elif isinstance(val, dict):
                val = "; ".join(f"{k}={v}" for k, v in val.items())
            writer.writerow(["inventory", key, val, "", "", "", ""])
    return path


def export_html(analyzer, path):
    data = build_export(analyzer)
    grade = escape(str(data["grade"]))
    total = data["total_score"]
    mx = data["max_score"]
    url = escape(str(data["url"]))
    generated = escape(str(data["generated_at"]))
    dims = data["dashboard"]

    cat_rows = []
    for cat in data["categories"]:
        pct = int((cat["points"] / cat["max_points"]) * 100) if cat["max_points"] else 0
        bar_color = _bar_color(pct)
        parts = []
        for it in cat["items"]:
            cls = "ok" if it["passed"] else "fail"
            mark = "✔" if it["passed"] else "✘"
            detail_html = ""
            if it["detail"]:
                detail_html = "<span class='detail'>" + escape(it["detail"]) + "</span>"
            parts.append(
                "<li class='" + cls + "'>"
                "<span class='mark'>" + mark + "</span>"
                "<span class='label'>" + escape(it["label"]) + "</span>"
                "<span class='pts'>" + str(it["awarded"]) + "/" + str(it["max"]) + "</span>"
                + detail_html +
                "</li>"
            )
        items_html = "".join(parts)
        warns_html = ""
        if cat["warnings"]:
            wparts = "".join("<li class='warn'>⚠ " + escape(w) + "</li>" for w in cat["warnings"])
            warns_html = "<ul class='warnings'>" + wparts + "</ul>"
        cat_rows.append(
            "<section class='cat'>"
            "<header><h2>" + escape(cat["title"]) + "</h2>"
            "<span class='pts'>" + str(cat["points"]) + "/" + str(cat["max_points"]) + "</span></header>"
            "<div class='bar'><div class='fill' style='width:" + str(pct) + "%;background:"
            + bar_color + "'></div></div>"
            "<ul class='checks'>" + items_html + "</ul>"
            + warns_html +
            "</section>"
        )

    dim_cells = []
    for name, d in dims.items():
        pct_d = d["percent"]
        dim_cells.append(
            "<div class='dim'>"
            "<div class='dimhead'><span>" + escape(str(name)) + "</span><span>"
            + str(pct_d) + "%</span></div>"
            "<div class='bar'><div class='fill' style='width:" + str(pct_d)
            + "%;background:" + _bar_color(pct_d) + "'></div></div>"
            "<div class='dimsub'>" + str(d["points"]) + "/" + str(d["max"]) + " pts</div>"
            "</div>"
        )
    dims_html = "".join(dim_cells)

    recs = data["recommendations"]
    rec_parts = []
    for rec in recs:
        rec_parts.append(
            "<li class='rec'>"
            "<span class='prio prio-" + escape(rec["priority"]) + "'>"
            + escape(rec["priority"].upper()) + "</span>"
            "<strong>" + escape(rec["title"]) + "</strong>"
            "<span class='meta'>+" + str(rec["points_lost"]) + " pts · "
            + escape(rec["effort"]) + " effort · " + escape(rec["category"]) + "</span>"
            "<p>" + escape(rec["action"]) + "</p>"
            "</li>"
        )
    if rec_parts:
        rec_html = (
            "<div class='panel'><h2>Recommendations</h2><ul class='recs'>"
            + "".join(rec_parts) + "</ul></div>"
        )
    else:
        rec_html = (
            "<div class='panel'><h2>Recommendations</h2>"
            "<p class='good'>No outstanding issues detected.</p></div>"
        )

    phase_blocks = []
    for phase in data["roadmap"]:
        if phase["items"]:
            lis = ""
            for it in phase["items"]:
                lis += (
                    "<li><strong>" + escape(it["title"]) + "</strong> "
                    "<span class='meta'>" + escape(it["category"]) + " · +"
                    + str(it["points_lost"]) + " pts</span>"
                    "<p>" + escape(it["action"]) + "</p></li>"
                )
        else:
            lis = "<li class='good'>Nothing pending in this phase.</li>"
        note = phase["focus"] + " · recoverable +" + str(phase["points"]) + " pts"
        phase_blocks.append(
            "<div class='phase'><h3>" + escape(phase["name"]) + "</h3>"
            "<p class='phasenote'>" + escape(note) + "</p>"
            "<ol class='phaselist'>" + lis + "</ol></div>"
        )
    roadmap_html = (
        "<div class='panel'><h2>Optimization Roadmap</h2>"
        + "".join(phase_blocks) + "</div>"
    )

    inv = data["inventory"]
    inv_rows = [
        ("HTML5 video elements", inv.get("video_elements", 0)),
        ("Iframes", inv.get("iframes", 0)),
        ("Players", ", ".join(inv.get("players") or []) or "—"),
        ("Platforms", ", ".join(inv.get("platforms") or []) or "—"),
        ("Formats", ", ".join(inv.get("formats") or []) or "—"),
        ("Qualities", ", ".join(inv.get("qualities") or []) or "—"),
        ("Streaming protocols", ", ".join(inv.get("streaming_protocols") or []) or "—"),
        ("Streaming manifests", len(inv.get("streaming_manifests") or [])),
        ("Cache headers", len(inv.get("cache_headers") or {})),
        ("HTTP version", inv.get("http_version") or "—"),
        ("Captions", len(inv.get("captions") or [])),
        ("Sources", len(inv.get("sources") or [])),
        ("Thumbnails", len(inv.get("thumbnails") or [])),
        ("Script tags", inv.get("scripts", 0)),
    ]
    inv_html = "".join(
        f"<tr><td>{escape(str(k))}</td><td>{escape(str(v))}</td></tr>"
        for k, v in inv_rows
    )

    if grade.startswith("A"):
        grade_bg = "#16a34a"
    elif grade == "B":
        grade_bg = "#0284c7"
    elif grade == "C":
        grade_bg = "#ca8a04"
    else:
        grade_bg = "#dc2626"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VideoAnalyzer Report — {url}</title>
<style>
  :root {{
    --bg: #0b1020;
    --panel: #121a2f;
    --panel2: #0e1526;
    --border: #1f2a44;
    --text: #e6edf7;
    --muted: #8b97ad;
    --green: #22c55e;
    --red: #ef4444;
    --yellow: #facc15;
    --blue: #38bdf8;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
    line-height: 1.5;
    padding: 32px 20px;
  }}
  .wrap {{ max-width: 980px; margin: 0 auto; }}
  header.top {{
    background: linear-gradient(135deg, #101832, #0d1330);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 28px;
    margin-bottom: 24px;
    display: flex;
    flex-wrap: wrap;
    gap: 24px;
    align-items: center;
    justify-content: space-between;
  }}
  .brand h1 {{ font-size: 1.6rem; letter-spacing: 0.5px; }}
  .brand p {{ color: var(--muted); font-size: 0.9rem; margin-top: 4px; word-break: break-all; }}
  .scorebox {{ text-align: center; }}
  .scorebox .num {{ font-size: 2.4rem; font-weight: 700; }}
  .scorebox .grade {{
    display: inline-block; margin-top: 8px;
    background: {grade_bg};
    padding: 6px 18px;
    border-radius: 999px;
    font-weight: 700;
    font-size: 1.2rem;
  }}
  .panel {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px;
    margin-bottom: 24px;
  }}
  .panel h2 {{ color: var(--blue); font-size: 1.05rem; margin-bottom: 14px; }}
  .dims {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; }}
  .dim {{
    background: var(--panel2);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 12px;
  }}
  .dimhead {{
    display: flex; justify-content: space-between;
    font-size: 0.85rem; color: var(--muted); margin-bottom: 8px;
  }}
  .dimhead span:last-child {{ color: var(--text); font-weight: 700; }}
  .dimsub {{ font-size: 0.75rem; color: var(--muted); margin-top: 6px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .cat {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px;
  }}
  .cat header {{ display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 10px; }}
  .cat h2 {{ font-size: 1rem; color: var(--blue); font-weight: 600; }}
  .cat .pts {{ font-weight: 700; color: var(--text); }}
  .bar {{ height: 8px; background: #0a0f1d; border-radius: 6px; overflow: hidden; margin-bottom: 12px; }}
  .fill {{ height: 100%; border-radius: 6px; }}
  .checks {{ list-style: none; }}
  .checks li {{ display: flex; flex-wrap: wrap; gap: 8px; padding: 6px 0; border-bottom: 1px solid #141c30; font-size: 0.88rem; }}
  .checks li:last-child {{ border-bottom: none; }}
  .checks .mark {{ width: 16px; }}
  li.ok .mark {{ color: var(--green); }}
  li.fail .mark {{ color: var(--red); }}
  .checks .label {{ flex: 1; }}
  .checks .pts {{ color: var(--muted); font-variant-numeric: tabular-nums; }}
  .checks .detail {{ flex-basis: 100%; color: var(--muted); font-size: 0.8rem; padding-left: 24px; }}
  .warnings {{ list-style: none; margin-top: 10px; }}
  .warnings li {{ color: var(--yellow); font-size: 0.85rem; padding: 3px 0; }}
  .recs {{ list-style: none; }}
  .recs li {{ border-bottom: 1px solid #141c30; padding: 10px 0; }}
  .recs li:last-child {{ border-bottom: none; }}
  .prio {{
    display: inline-block; font-size: 0.7rem; font-weight: 700;
    padding: 2px 8px; border-radius: 999px; margin-right: 8px;
  }}
  .prio-high {{ background: #7f1d1d; color: #fecaca; }}
  .prio-medium {{ background: #713f12; color: #fef08a; }}
  .prio-low {{ background: #0c4a6e; color: #bae6fd; }}
  .recs .meta {{ display: block; color: var(--muted); font-size: 0.78rem; margin-top: 3px; }}
  .recs p {{ color: var(--text); font-size: 0.88rem; margin-top: 4px; }}
  .good {{ color: var(--green); }}
  .phase {{ margin-bottom: 16px; }}
  .phase h3 {{ font-size: 0.95rem; color: #e9d5ff; }}
  .phasenote {{ color: var(--muted); font-size: 0.8rem; margin: 4px 0 8px; }}
  .phaselist {{ margin-left: 18px; }}
  .phaselist li {{ margin-bottom: 8px; font-size: 0.88rem; }}
  .phaselist .meta {{ color: var(--muted); font-size: 0.78rem; }}
  .phaselist p {{ color: var(--muted); font-size: 0.82rem; margin-top: 2px; }}
  .inv {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px;
    margin-top: 8px;
  }}
  .inv h2 {{ color: var(--blue); font-size: 1.05rem; margin-bottom: 12px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid var(--border); }}
  td:first-child {{ color: var(--muted); width: 45%; }}
  footer {{ text-align: center; color: var(--muted); font-size: 0.8rem; margin-top: 28px; }}
  @media (max-width: 640px) {{
    header.top {{ flex-direction: column; text-align: center; }}
    .brand p {{ word-break: break-word; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div class="brand">
      <h1>VideoAnalyzer v{escape(str(VERSION))}</h1>
      <p>{url}</p>
      <p>Generated {generated}</p>
    </div>
    <div class="scorebox">
      <div class="num">{total}<span style="color:var(--muted);font-size:1.2rem">/{mx}</span></div>
      <div class="grade">{grade}</div>
    </div>
  </header>
  <div class="panel">
    <h2>Analysis Dashboard</h2>
    <div class="dims">{dims_html}</div>
  </div>
  <div class="grid">{''.join(cat_rows)}</div>
  {rec_html}
  {roadmap_html}
  <div class="inv">
    <h2>Video Content Inventory</h2>
    <table>{inv_html}</table>
  </div>
  <footer>VideoAnalyzer v{escape(str(VERSION))} · report generated automatically</footer>
</div>
</body>
</html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return path


def main():
    parser = argparse.ArgumentParser(
        prog="VideoAnalyzer",
        description=(
            "VideoAnalyzer v2.0 — analyzes video content for SEO, accessibility, embedding, "
            "streaming (HLS/DASH), quality, compression, delivery, caching, and performance."
        ),
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
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version=f"VideoAnalyzer {VERSION}")
    args = parser.parse_args()

    color = not args.no_color
    pal = Palette(color)

    url = args.url
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url

    print_banner(pal)
    print(f"  {pal.white('Target:')} {pal.bright_cyan(url)}")
    print(f"  {pal.white('Timeout:')} {pal.gray(str(args.timeout) + 's')}")
    print(f"  {pal.white('Export:')} {pal.gray(args.export)}")
    print()

    analyzer = VideoAnalyzer(url, timeout=args.timeout, verbose=args.verbose, color=color)

    if not analyzer.run_all():
        sys.exit(1)

    print_inventory(pal, analyzer.inventory, url)
    print_dashboard(pal, analyzer, url)
    print_results(pal, analyzer.results, args.verbose, analyzer)
    print_summary(pal, analyzer)
    print_recommendations(pal, analyzer.recommendations(), args.verbose)
    print_roadmap(pal, analyzer.roadmap())

    if args.export != "none":
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = urlparse(url).netloc.replace(":", "_") or "video"
        base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
        written = []
        fmts = ["json", "csv", "html"] if args.export == "all" else [args.export]
        for fmt in fmts:
            path = f"videoanalyzer_{base}_{stamp}.{fmt}"
            try:
                if fmt == "json":
                    export_json(analyzer, path)
                elif fmt == "csv":
                    export_csv(analyzer, path)
                elif fmt == "html":
                    export_html(analyzer, path)
                written.append(path)
            except Exception as exc:
                print(pal.red(f"  Export {fmt} failed: {exc}"))
        if written:
            print(pal.bold(pal.bright_cyan("  ▸ Export")))
            print(pal.gray("  " + "─" * 60))
            for w in written:
                print(f"    {pal.bright_green('✔')} {pal.white(w)}")
            print()

    print(pal.gray("  " + "─" * 64))
    print(pal.gray(f"  VideoAnalyzer v{VERSION} · analysis complete"))
    print()


if __name__ == "__main__":
    main()

