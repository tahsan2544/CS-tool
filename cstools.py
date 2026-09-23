#!/usr/bin/env python3
"""
CS-Tool — Unified website measurement & analysis CLI.
Nineteen tools. One entry point. Measure, audit, upgrade.
"""

import os
import sys
import argparse
import subprocess
import json
import re
from datetime import datetime

APP_NAME = "CS-Tool"
APP_VERSION = "1.2.0"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOADSTORM = os.path.join(SCRIPT_DIR, "LoadStorm", "loadstorm.py")
SEO = os.path.join(SCRIPT_DIR, "SEOChecker", "seocheck.py")
SECURITY = os.path.join(SCRIPT_DIR, "SecurityChecker", "securitycheck.py")
PERF = os.path.join(SCRIPT_DIR, "PerfAnalyzer", "perfanalyzer.py")
UPTIME = os.path.join(SCRIPT_DIR, "UptimeChecker", "uptimechecker.py")
MOBILE = os.path.join(SCRIPT_DIR, "MobileAnalyzer", "mobileanalyzer.py")
CONTENT = os.path.join(SCRIPT_DIR, "ContentAnalyzer", "contentanalyzer.py")
NETWORK = os.path.join(SCRIPT_DIR, "NetworkAnalyzer", "networkanalyzer.py")
ACCESS = os.path.join(SCRIPT_DIR, "AccessibilityAnalyzer", "accessibilityanalyzer.py")
IMAGE = os.path.join(SCRIPT_DIR, "ImageAnalyzer", "imageanalyzer.py")
API = os.path.join(SCRIPT_DIR, "APIAnalyzer", "apianalyzer.py")
VIDEO = os.path.join(SCRIPT_DIR, "VideoAnalyzer", "videoanalyzer.py")
SCHEMA = os.path.join(SCRIPT_DIR, "SchemaAnalyzer", "schemaanalyzer.py")
EMAIL = os.path.join(SCRIPT_DIR, "EmailAnalyzer", "emailanalyzer.py")
SITEMAP = os.path.join(SCRIPT_DIR, "SitemapAnalyzer", "sitemapanalyzer.py")
HTMLV = os.path.join(SCRIPT_DIR, "HTMLValidator", "htmlvalidator.py")
CDN = os.path.join(SCRIPT_DIR, "CDNAnalyzer", "cdnanalyzer.py")
COOKIES = os.path.join(SCRIPT_DIR, "CookieAnalyzer", "cookieanalyzer.py")
UPGRADE = os.path.join(SCRIPT_DIR, "UpgradeAdvisor", "upgradetool.py")

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except ImportError:
    class _Fake:
        def __getattr__(self, n): return ''
    Fore = Style = _Fake()

# ── Palette ──────────────────────────────────────────────────────────────────
# Brand: electric blue + magenta. Status: green/amber/red. Body: white/dim.
C = {
    "brand":   Fore.LIGHTBLUE_EX + Style.BRIGHT,
    "accent":  Fore.LIGHTMAGENTA_EX + Style.BRIGHT,
    "gold":    Fore.LIGHTYELLOW_EX + Style.BRIGHT,
    "ok":      Fore.LIGHTGREEN_EX + Style.BRIGHT,
    "warn":    Fore.LIGHTYELLOW_EX,
    "bad":     Fore.LIGHTRED_EX + Style.BRIGHT,
    "dim":     Style.DIM,
    "head":    Fore.CYAN + Style.BRIGHT,
    "cmd":     Fore.LIGHTGREEN_EX,
    "desc":    Fore.WHITE,
    "rule":    Fore.BLUE,
    "reset":   Style.RESET_ALL,
}

def _dim(s):
    return f"{C['dim']}{s}{C['reset']}"

def _rule(ch="─", n=68):
    return f"{C['rule']}{Style.DIM}{ch * n}{C['reset']}"

def _tag(text, color="accent"):
    return f"{C[color]}{text}{C['reset']}"

def _cmd(text):
    return f"{C['cmd']}{Style.BRIGHT}{text}{C['reset']}"

BANNER = f"""{C['brand']}
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║{C['accent']}   ██████╗██╗     ██╗   ██╗███████╗███████╗ ██╗     {C['brand']}              ║
    ║{C['accent']}  ██╔════╝██║     ██║   ██║██╔════╝██╔════╝██║     {C['brand']}               ║
    ║{C['accent']}  ██║     ██║     ██║   ██║█████╗  █████╗  ██║     {C['brand']}               ║
    ║{C['accent']}  ██║     ██║     ██║   ██║██╔══╝  ██╔══╝  ██║     {C['brand']}               ║
    ║{C['accent']}  ╚██████╗███████╗╚██████╔╝███████╗███████╗███████╗ {C['brand']}              ║
    ║{C['accent']}   ╚═════╝╚══════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝{C['brand']}               ║
    ║                                                                  ║
    ║{C['gold']}  CS-Tool{C['brand']}  ·  {C['desc']}Website Measurement Suite{C['brand']}  ·  {C['gold']}v{APP_VERSION}{C['brand']}                ║
    ║{C['dim']}  19 tools · one CLI · measure → audit → upgrade{C['brand']}                  ║
    ╠══════════════════════════════════════════════════════════════════╣
    ║{C['gold']}  ◆ META{C['brand']}                                                          ║
    ║{C['brand']}    {C['cmd']}scan{C['brand']}       {C['desc']} run all analyzers on a URL{C['brand']}                        ║
    ║{C['brand']}    {C['cmd']}upgrade{C['brand']}    {C['desc']} prioritized what-to-upgrade roadmap{C['brand']}               ║
    ║{C['brand']}    {C['cmd']}list{C['brand']}       {C['desc']} show every command{C['brand']}                                ║
    ║                                                                  ║
    ║{C['gold']}  ◆ CORE ANALYZERS{C['brand']}                                                ║
    ║{C['brand']}    {C['cmd']}seo{C['brand']}        {C['desc']} search visibility & rankings{C['brand']}                      ║
    ║{C['brand']}    {C['cmd']}security{C['brand']}   {C['desc']} headers, SSL, vulns, compliance{C['brand']}                   ║
    ║{C['brand']}    {C['cmd']}perf{C['brand']}       {C['desc']} Core Web Vitals & budgets{C['brand']}                         ║
    ║{C['brand']}    {C['cmd']}uptime{C['brand']}     {C['desc']} availability & response time{C['brand']}                      ║
    ║{C['brand']}    {C['cmd']}loadstorm{C['brand']}  {C['desc']} load & stress testing{C['brand']}                             ║
    ║                                                                  ║
    ║{C['gold']}  ◆ CONTENT · MEDIA · DATA{C['brand']}                                        ║
    ║{C['brand']}    {C['cmd']}content{C['brand']}    {C['desc']} readability, quality, structure{C['brand']}                   ║
    ║{C['brand']}    {C['cmd']}html{C['brand']}       {C['desc']} HTML standards validation{C['brand']}                         ║
    ║{C['brand']}    {C['cmd']}schema{C['brand']}     {C['desc']} structured data / Schema.org{C['brand']}                      ║
    ║{C['brand']}    {C['cmd']}sitemap{C['brand']}    {C['desc']} crawlability & indexability{C['brand']}                       ║
    ║{C['brand']}    {C['cmd']}image{C['brand']}      {C['desc']} image optimization{C['brand']}                                ║
    ║{C['brand']}    {C['cmd']}video{C['brand']}      {C['desc']} video SEO & accessibility{C['brand']}                         ║
    ║                                                                  ║
    ║{C['gold']}  ◆ PLATFORM{C['brand']}                                                      ║
    ║{C['brand']}    {C['cmd']}mobile{C['brand']}     {C['desc']} responsive, PWA, touch{C['brand']}                            ║
    ║{C['brand']}    {C['cmd']}access{C['brand']}     {C['desc']} WCAG 2.1/2.2 accessibility{C['brand']}                        ║
    ║{C['brand']}    {C['cmd']}network{C['brand']}    {C['desc']} DNS, TLS, ports, latency{C['brand']}                          ║
    ║{C['brand']}    {C['cmd']}cdn{C['brand']}        {C['desc']} CDN detection & caching{C['brand']}                           ║
    ║{C['brand']}    {C['cmd']}api{C['brand']}        {C['desc']} REST / GraphQL quality{C['brand']}                            ║
    ║{C['brand']}    {C['cmd']}email{C['brand']}      {C['desc']} SPF · DKIM · DMARC deliverability{C['brand']}                 ║
    ║{C['brand']}    {C['cmd']}cookies{C['brand']}    {C['desc']} GDPR / CCPA cookie privacy{C['brand']}                        ║
    ║                                                                  ║
    ╠══════════════════════════════════════════════════════════════════╣
    ║{C['dim']}  python cstools.py <command> -u https://example.com{C['brand']}              ║
    ║{C['dim']}  python cstools.py upgrade -u https://example.com{C['brand']}                ║
    ║{C['dim']}  python cstools.py scan -u https://example.com --export all{C['brand']}      ║
    ╚══════════════════════════════════════════════════════════════════╝{C['reset']}
"""

EPILOG = f"""{C['head']}examples:{C['reset']}
  {_cmd('python cstools.py')} {C['desc']}seo -u https://example.com{C['reset']}
  {_cmd('python cstools.py')} {C['desc']}security -u https://example.com --export all{C['reset']}
  {_cmd('python cstools.py')} {C['desc']}perf -u https://example.com -t 30{C['reset']}
  {_cmd('python cstools.py')} {C['desc']}upgrade -u https://example.com --export all{C['reset']}
  {_cmd('python cstools.py')} {C['desc']}scan -u https://example.com --export all{C['reset']}
  {_cmd('python cstools.py')} {C['desc']}list{C['reset']}

{C['head']}command groups:{C['reset']}
  {C['gold']}meta{C['reset']}        scan · upgrade · list
  {C['gold']}core{C['reset']}        seo · security · perf · uptime · loadstorm
  {C['gold']}content{C['reset']}     content · html · schema · sitemap · image · video
  {C['gold']}platform{C['reset']}    mobile · access · network · cdn · api · email · cookies

{C['dim']}Docs: https://github.com/tahsan2544/CS-tool{C['reset']}
{C['dim']}Report issues: https://github.com/tahsan2544/CS-tool/issues{C['reset']}
"""

TOOLS = [
    {
        "name": "LoadStorm",
        "command": "loadstorm",
        "path": LOADSTORM,
        "description": "Load & Stress Testing - Multi-URL, WebSocket, Scenarios, 10M+ Users",
    },
    {
        "name": "SEOChecker",
        "command": "seo",
        "path": SEO,
        "description": "SEO Quality Analysis - Structured Data, Sitemap, Links, Readability",
    },
    {
        "name": "SecurityChecker",
        "command": "security",
        "path": SECURITY,
        "description": "Security Analysis - Headers, SSL, CORS, Vulnerabilities, Compliance",
    },
    {
        "name": "PerfAnalyzer",
        "command": "perf",
        "path": PERF,
        "description": "Performance Analysis - Core Web Vitals, TTFB, Resources, Caching",
    },
    {
        "name": "UptimeChecker",
        "command": "uptime",
        "path": UPTIME,
        "description": "Uptime Monitoring - Response Time, DNS Health, SSL, Availability",
    },
    {
        "name": "MobileAnalyzer",
        "command": "mobile",
        "path": MOBILE,
        "description": "Mobile Analysis - Viewport, Responsive, Touch, Mobile Performance",
    },
    {
        "name": "ContentAnalyzer",
        "command": "content",
        "path": CONTENT,
        "description": "Content Quality - Readability, Accessibility, SEO, Structure",
    },
    {
        "name": "NetworkAnalyzer",
        "command": "network",
        "path": NETWORK,
        "description": "Network Diagnostics - DNS, TCP, SSL, CDN, Latency, Ports",
    },
    {
        "name": "AccessibilityAnalyzer",
        "command": "access",
        "path": ACCESS,
        "description": "Accessibility - WCAG 2.1, ARIA, Screen Readers, Keyboard Navigation",
    },
    {
        "name": "ImageAnalyzer",
        "command": "image",
        "path": IMAGE,
        "description": "Image Optimization - Format, Size, Responsive, Lazy Loading",
    },
    {
        "name": "APIAnalyzer",
        "command": "api",
        "path": API,
        "description": "API Testing - REST, GraphQL, Auth, Rate Limits, Documentation",
    },
    {
        "name": "VideoAnalyzer",
        "command": "video",
        "path": VIDEO,
        "description": "Video Analysis - SEO, Accessibility, Embedding, Performance",
    },
    {
        "name": "SchemaAnalyzer",
        "command": "schema",
        "path": SCHEMA,
        "description": "Structured Data - JSON-LD, Microdata, RDFa, Schema.org",
    },
    {
        "name": "EmailAnalyzer",
        "command": "email",
        "path": EMAIL,
        "description": "Email Deliverability - SPF, DKIM, DMARC, MX, BIMI",
    },
    {
        "name": "SitemapAnalyzer",
        "command": "sitemap",
        "path": SITEMAP,
        "description": "Sitemap & Crawlability - robots.txt, sitemaps, indexability",
    },
    {
        "name": "HTMLValidator",
        "command": "html",
        "path": HTMLV,
        "description": "HTML Validation - Standards, Semantic, Best Practices",
    },
    {
        "name": "CDNAnalyzer",
        "command": "cdn",
        "path": CDN,
        "description": "CDN Analysis - CDN Detection, Caching, Edge Performance",
    },
    {
        "name": "CookieAnalyzer",
        "command": "cookies",
        "path": COOKIES,
        "description": "Cookie Privacy - GDPR, CCPA, Consent Management",
    },
    {
        "name": "UpgradeAdvisor",
        "command": "upgrade",
        "path": UPGRADE,
        "description": "Upgrade Roadmap - Prioritized what-to-upgrade for better rating",
    },
]


def run_tool(tool_path, extra_args):
    if not os.path.exists(tool_path):
        print(f"{C['bad']}[ERROR] Tool not found: {tool_path}{C['reset']}")
        return 1
    cmd = [sys.executable, tool_path] + extra_args
    result = subprocess.run(cmd)
    return result.returncode


def cmd_loadstorm(args):
    extra = []
    if args.url:
        extra += ["-u", args.url]
    if args.count is not None:
        extra += ["-c", str(args.count)]
    if args.duration is not None:
        extra += ["-d", str(args.duration)]
    if args.concurrency is not None:
        extra += ["-C", str(args.concurrency)]
    if args.pattern:
        extra += ["-p", args.pattern]
    if args.method:
        extra += ["-m", args.method]
    if args.header:
        for h in args.header:
            extra += ["-H", h]
    if args.body:
        extra += ["-b", args.body]
    if args.timeout is not None:
        extra += ["-t", str(args.timeout)]
    if args.batch_size is not None:
        extra += ["-B", str(args.batch_size)]
    if args.no_keep_alive:
        extra.append("--no-keep-alive")
    if args.rate_limit is not None:
        extra += ["--rate-limit", str(args.rate_limit)]
    if args.payload_file:
        extra += ["--payload-file", args.payload_file]
    if args.proxy:
        extra += ["--proxy", args.proxy]
    if args.no_follow:
        extra.append("--no-follow")
    if args.no_color:
        extra.append("--no-color")
    if args.cache_bust:
        extra.append("--cache-bust")
    if args.jitter is not None:
        extra += ["--jitter", str(args.jitter)]
    if args.random_path:
        extra.append("--random-path")
    if args.random_referer:
        extra.append("--random-referer")
    if args.yes:
        extra.append("-y")
    if args.export:
        extra += ["--export", args.export]
    if args.urls:
        extra += ["--urls", args.urls]
    if args.websocket:
        extra.append("--websocket")
    if args.validate_status is not None:
        extra += ["--validate-status", str(args.validate_status)]
    if args.validate_contains:
        extra += ["--validate-contains", args.validate_contains]
    if args.validate_max_time is not None:
        extra += ["--validate-max-time", str(args.validate_max_time)]
    if args.geo_sim:
        extra.append("--geo-sim")
    if args.adaptive:
        extra.append("--adaptive")
    if args.scenario:
        extra += ["--scenario", args.scenario]
    return run_tool(LOADSTORM, extra)


def cmd_seo(args):
    extra = []
    if args.url:
        extra += ["-u", args.url]
    if args.timeout is not None:
        extra += ["-t", str(args.timeout)]
    if args.export:
        extra += ["--export", args.export]
    if args.no_color:
        extra.append("--no-color")
    if args.check_links:
        extra.append("--check-links")
    if args.batch:
        extra += ["--batch", args.batch]
    return run_tool(SEO, extra)


def cmd_security(args):
    extra = []
    if args.url:
        extra += ["-u", args.url]
    if args.timeout is not None:
        extra += ["-t", str(args.timeout)]
    if args.export:
        extra += ["--export", args.export]
    if args.no_color:
        extra.append("--no-color")
    return run_tool(SECURITY, extra)


def cmd_perf(args):
    extra = []
    if args.url:
        extra += ["-u", args.url]
    if args.timeout is not None:
        extra += ["-t", str(args.timeout)]
    if args.export:
        extra += ["--export", args.export]
    if args.no_color:
        extra.append("--no-color")
    if args.verbose:
        extra.append("-v")
    return run_tool(PERF, extra)


def cmd_uptime(args):
    extra = []
    if args.url:
        extra += ["-u", args.url]
    if args.timeout is not None:
        extra += ["-t", str(args.timeout)]
    if args.count is not None:
        extra += ["-c", str(args.count)]
    if args.interval is not None:
        extra += ["-i", str(args.interval)]
    if args.export:
        extra += ["--export", args.export]
    if args.no_color:
        extra.append("--no-color")
    if args.expect:
        extra += ["--expect", args.expect]
    return run_tool(UPTIME, extra)


def cmd_mobile(args):
    extra = []
    if args.url:
        extra += ["-u", args.url]
    if args.timeout is not None:
        extra += ["-t", str(args.timeout)]
    if args.export:
        extra += ["--export", args.export]
    if args.no_color:
        extra.append("--no-color")
    return run_tool(MOBILE, extra)


def cmd_content(args):
    extra = []
    if args.url:
        extra += ["-u", args.url]
    if args.timeout is not None:
        extra += ["-t", str(args.timeout)]
    if args.export:
        extra += ["--export", args.export]
    if args.no_color:
        extra.append("--no-color")
    if args.verbose:
        extra.append("-v")
    return run_tool(CONTENT, extra)


def cmd_network(args):
    extra = []
    if args.url:
        extra += ["-u", args.url]
    if args.timeout is not None:
        extra += ["-t", str(args.timeout)]
    if args.export:
        extra += ["--export", args.export]
    if args.no_color:
        extra.append("--no-color")
    if args.verbose:
        extra.append("-v")
    return run_tool(NETWORK, extra)


def cmd_access(args):
    extra = []
    if args.url:
        extra += ["-u", args.url]
    if args.timeout is not None:
        extra += ["-t", str(args.timeout)]
    if args.export:
        extra += ["--export", args.export]
    if args.no_color:
        extra.append("--no-color")
    if args.verbose:
        extra.append("-v")
    if args.level:
        extra += ["--level", args.level]
    return run_tool(ACCESS, extra)


def cmd_image(args):
    extra = []
    if args.url:
        extra += ["-u", args.url]
    if args.timeout is not None:
        extra += ["-t", str(args.timeout)]
    if args.export:
        extra += ["--export", args.export]
    if args.no_color:
        extra.append("--no-color")
    if args.verbose:
        extra.append("-v")
    return run_tool(IMAGE, extra)


def cmd_api(args):
    extra = []
    if args.url:
        extra += ["-u", args.url]
    if args.timeout is not None:
        extra += ["-t", str(args.timeout)]
    if args.export:
        extra += ["--export", args.export]
    if args.no_color:
        extra.append("--no-color")
    if args.verbose:
        extra.append("-v")
    if args.api_key:
        extra += ["--api-key", args.api_key]
    if args.auth_type:
        extra += ["--auth-type", args.auth_type]
    return run_tool(API, extra)


def cmd_video(args):
    extra = []
    if args.url:
        extra += ["-u", args.url]
    if args.timeout is not None:
        extra += ["-t", str(args.timeout)]
    if args.export:
        extra += ["--export", args.export]
    if args.no_color:
        extra.append("--no-color")
    if args.verbose:
        extra.append("-v")
    return run_tool(VIDEO, extra)


def cmd_schema(args):
    extra = []
    if args.url:
        extra += ["-u", args.url]
    if args.timeout is not None:
        extra += ["-t", str(args.timeout)]
    if args.export:
        extra += ["--export", args.export]
    if args.no_color:
        extra.append("--no-color")
    if args.verbose:
        extra.append("-v")
    return run_tool(SCHEMA, extra)


def cmd_email(args):
    extra = []
    if args.url:
        extra += ["-u", args.url]
    if args.timeout is not None:
        extra += ["-t", str(args.timeout)]
    if args.export:
        extra += ["--export", args.export]
    if args.no_color:
        extra.append("--no-color")
    if args.verbose:
        extra.append("-v")
    if args.selector:
        extra += ["--selector", args.selector]
    return run_tool(EMAIL, extra)


def cmd_sitemap(args):
    extra = []
    if args.url:
        extra += ["-u", args.url]
    if args.timeout is not None:
        extra += ["-t", str(args.timeout)]
    if args.export:
        extra += ["--export", args.export]
    if args.no_color:
        extra.append("--no-color")
    if args.verbose:
        extra.append("-v")
    return run_tool(SITEMAP, extra)


def cmd_html(args):
    extra = []
    if args.url:
        extra += ["-u", args.url]
    if args.timeout is not None:
        extra += ["-t", str(args.timeout)]
    if args.export:
        extra += ["--export", args.export]
    if args.no_color:
        extra.append("--no-color")
    if args.verbose:
        extra.append("-v")
    return run_tool(HTMLV, extra)


def cmd_cdn(args):
    extra = []
    if args.url:
        extra += ["-u", args.url]
    if args.timeout is not None:
        extra += ["-t", str(args.timeout)]
    if args.export:
        extra += ["--export", args.export]
    if args.no_color:
        extra.append("--no-color")
    if args.verbose:
        extra.append("-v")
    return run_tool(CDN, extra)


def cmd_cookies(args):
    extra = []
    if args.url:
        extra += ["-u", args.url]
    if args.timeout is not None:
        extra += ["-t", str(args.timeout)]
    if args.export:
        extra += ["--export", args.export]
    if args.no_color:
        extra.append("--no-color")
    if args.verbose:
        extra.append("-v")
    return run_tool(COOKIES, extra)


def cmd_upgrade(args):
    extra = []
    if args.url:
        extra += ["-u", args.url]
    if args.timeout is not None:
        extra += ["-t", str(args.timeout)]
    if args.export:
        extra += ["--export", args.export]
    if args.no_color:
        extra.append("--no-color")
    if args.verbose:
        extra.append("-v")
    only = getattr(args, "only", None)
    if only:
        extra.append("--only")
        extra.extend(only)
    return run_tool(UPGRADE, extra)


def cmd_list(args):
    by_cmd = {t["command"]: t for t in TOOLS}
    groups = [
        ("META", ["scan", "upgrade", "list"]),
        ("CORE ANALYZERS", ["seo", "security", "perf", "uptime", "loadstorm"]),
        ("CONTENT · MEDIA · DATA", ["content", "html", "schema", "sitemap", "image", "video"]),
        ("PLATFORM", ["mobile", "access", "network", "cdn", "api", "email", "cookies"]),
    ]
    print(f"\n  {_rule('═', 78)}")
    print(f"  {_tag(APP_NAME, 'gold')} {C['head']}available tools {C['dim']}· {sum(len(c) for _, c in groups)} commands{C['reset']}")
    print(f"  {_rule('═', 78)}")
    for title, cmds in groups:
        print(f"\n  {C['gold']}{title}{C['reset']}")
        for cmd in cmds:
            tool = by_cmd.get(cmd)
            if tool is None:
                extra = {
                    "scan": ("Scanner", "Run every analyzer on one URL"),
                    "list": ("List", "Show this tool listing"),
                }.get(cmd, (cmd, ""))
                print(f"    {_cmd(f'{cmd:<11}')} {C['desc']}{extra[0]:<22} {C['dim']}{extra[1]}{C['reset']}")
            else:
                print(f"    {_cmd(f'{cmd:<11}')} {C['desc']}{tool['name']:<22} {C['dim']}{tool['description']}{C['reset']}")
    print(f"\n  {C['head']}usage:{C['reset']}")
    for ex in (
        "python cstools.py <command> [options]",
        "python cstools.py seo -u https://example.com --export all",
        "python cstools.py upgrade -u https://example.com --export all",
        "python cstools.py scan -u https://example.com --export all",
    ):
        print(f"    {_dim(ex)}")
    print(f"  {_rule('═', 78)}\n")
    return 0


def extract_score_from_output(output, pattern):
    match = re.search(pattern, output, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def cmd_scan(args):
    url = args.url
    if not url:
        print(f"{C['bad']}[ERROR] URL is required for scan command. Use: cstools scan -u <url>{C['reset']}")
        return 1

    export = args.export or "none"
    print(f"{C['brand']}{Style.BRIGHT}{'═' * 70}{C['reset']}")
    print(f"{C['brand']}{Style.BRIGHT}  {APP_NAME} full scan{C['reset']}{C['dim']}  {url}{C['reset']}")
    print(f"{C['dim']}  started {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C['reset']}")
    print(f"{C['brand']}{Style.BRIGHT}{'═' * 70}{C['reset']}\n")

    results = {}

    print(f"\n{C['brand']}[1/17] {C['gold']}Running SEO Analysis...{C['reset']}")
    seo_args = ["-u", url]
    if export != "none":
        seo_args += ["--export", export]
    if args.no_color:
        seo_args.append("--no-color")
    seo_result = subprocess.run(
        [sys.executable, SEO] + seo_args,
        capture_output=True, text=True
    )
    seo_output = seo_result.stdout
    seo_score = extract_score_from_output(r'Score:\s*\w?(\d+/\d+)', seo_output)
    if not seo_score:
        seo_score = extract_score_from_output(r'(\d+)/(\d+)\s*\(?\d+%?\)?', seo_output)
    results["seo"] = {
        "output": seo_output,
        "returncode": seo_result.returncode,
        "score": seo_score,
    }

    print(f"\n{C['brand']}[2/17] {C['gold']}Running Security Analysis...{C['reset']}")
    sec_args = ["-u", url]
    if export != "none":
        sec_args += ["--export", export]
    if args.no_color:
        sec_args.append("--no-color")
    sec_result = subprocess.run(
        [sys.executable, SECURITY] + sec_args,
        capture_output=True, text=True
    )
    sec_output = sec_result.stdout
    sec_score = extract_score_from_output(r'Score:\s*(\d+)/100', sec_output)
    sec_grade = extract_score_from_output(r'Grade:\s*(\w)', sec_output)
    results["security"] = {
        "output": sec_output,
        "returncode": sec_result.returncode,
        "score": sec_score,
        "grade": sec_grade,
    }

    print(f"\n{C['brand']}[3/17] {C['gold']}Running Performance Analysis...{C['reset']}")
    perf_args = ["-u", url]
    if export != "none":
        perf_args += ["--export", export]
    if args.no_color:
        perf_args.append("--no-color")
    perf_result = subprocess.run(
        [sys.executable, PERF] + perf_args,
        capture_output=True, text=True
    )
    perf_output = perf_result.stdout
    perf_score = extract_score_from_output(r'Score:\s*(\d+)/100', perf_output)
    perf_grade = extract_score_from_output(r'Grade:\s*(\w)', perf_output)
    results["perf"] = {
        "output": perf_output,
        "returncode": perf_result.returncode,
        "score": perf_score,
        "grade": perf_grade,
    }

    print(f"\n{C['brand']}[4/17] {C['gold']}Running Uptime Check...{C['reset']}")
    uptime_args = ["-u", url]
    if export != "none":
        uptime_args += ["--export", export]
    if args.no_color:
        uptime_args.append("--no-color")
    uptime_result = subprocess.run(
        [sys.executable, UPTIME] + uptime_args,
        capture_output=True, text=True
    )
    uptime_output = uptime_result.stdout
    uptime_score = extract_score_from_output(r'Score:\s*(\d+)/100', uptime_output)
    uptime_verdict = extract_score_from_output(r'Verdict:\s*(\w+)', uptime_output)
    results["uptime"] = {
        "output": uptime_output,
        "returncode": uptime_result.returncode,
        "score": uptime_score,
        "verdict": uptime_verdict,
    }

    print(f"\n{C['brand']}[5/17] {C['gold']}Running Mobile Analysis...{C['reset']}")
    mobile_args = ["-u", url]
    if export != "none":
        mobile_args += ["--export", export]
    if args.no_color:
        mobile_args.append("--no-color")
    mobile_result = subprocess.run(
        [sys.executable, MOBILE] + mobile_args,
        capture_output=True, text=True
    )
    mobile_output = mobile_result.stdout
    mobile_score = extract_score_from_output(r'Score:\s*(\d+)/100', mobile_output)
    mobile_grade = extract_score_from_output(r'Grade:\s*(\w)', mobile_output)
    mobile_verdict = extract_score_from_output(r'Mobile.Friendly:\s*(\w+)', mobile_output)
    results["mobile"] = {
        "output": mobile_output,
        "returncode": mobile_result.returncode,
        "score": mobile_score,
        "grade": mobile_grade,
        "verdict": mobile_verdict,
    }

    print(f"\n{C['brand']}[6/17] {C['gold']}Running Content Analysis...{C['reset']}")
    content_args = ["-u", url]
    if export != "none":
        content_args += ["--export", export]
    if args.no_color:
        content_args.append("--no-color")
    content_result = subprocess.run(
        [sys.executable, CONTENT] + content_args,
        capture_output=True, text=True
    )
    content_output = content_result.stdout
    content_score = extract_score_from_output(r'Score:\s*(\d+)/100', content_output)
    content_grade = extract_score_from_output(r'Grade:\s*(\w)', content_output)
    results["content"] = {
        "output": content_output,
        "returncode": content_result.returncode,
        "score": content_score,
        "grade": content_grade,
    }

    print(f"\n{C['brand']}[7/17] {C['gold']}Running Network Diagnostics...{C['reset']}")
    network_args = ["-u", url]
    if export != "none":
        network_args += ["--export", export]
    if args.no_color:
        network_args.append("--no-color")
    network_result = subprocess.run(
        [sys.executable, NETWORK] + network_args,
        capture_output=True, text=True
    )
    network_output = network_result.stdout
    network_score = extract_score_from_output(r'Score:\s*(\d+)/100', network_output)
    network_grade = extract_score_from_output(r'Grade:\s*(\w)', network_output)
    results["network"] = {
        "output": network_output,
        "returncode": network_result.returncode,
        "score": network_score,
        "grade": network_grade,
    }

    print(f"\n{C['brand']}[8/17] {C['gold']}Running Accessibility Analysis...{C['reset']}")
    access_args = ["-u", url]
    if export != "none":
        access_args += ["--export", export]
    if args.no_color:
        access_args.append("--no-color")
    access_result = subprocess.run(
        [sys.executable, ACCESS] + access_args,
        capture_output=True, text=True
    )
    access_output = access_result.stdout
    access_score = extract_score_from_output(r'Score:\s*(\d+)/100', access_output)
    access_grade = extract_score_from_output(r'Grade:\s*(\w+)', access_output)
    wcag_level = extract_score_from_output(r'WCAG\s+Level:\s*(\w+)', access_output)
    results["access"] = {
        "output": access_output,
        "returncode": access_result.returncode,
        "score": access_score,
        "grade": access_grade,
        "wcag_level": wcag_level,
    }

    print(f"\n{C['brand']}[9/17] {C['gold']}Running Image Analysis...{C['reset']}")
    image_args = ["-u", url]
    if export != "none":
        image_args += ["--export", export]
    if args.no_color:
        image_args.append("--no-color")
    image_result = subprocess.run(
        [sys.executable, IMAGE] + image_args,
        capture_output=True, text=True
    )
    image_output = image_result.stdout
    image_score = extract_score_from_output(r'Score:\s*(\d+)/100', image_output)
    image_grade = extract_score_from_output(r'Grade:\s*(\w+)', image_output)
    results["image"] = {
        "output": image_output,
        "returncode": image_result.returncode,
        "score": image_score,
        "grade": image_grade,
    }

    print(f"\n{C['brand']}[10/17] {C['gold']}Running API Analysis...{C['reset']}")
    api_args = ["-u", url]
    if export != "none":
        api_args += ["--export", export]
    if args.no_color:
        api_args.append("--no-color")
    api_result = subprocess.run(
        [sys.executable, API] + api_args,
        capture_output=True, text=True
    )
    api_output = api_result.stdout
    api_score = extract_score_from_output(r'Score:\s*(\d+)/100', api_output)
    api_grade = extract_score_from_output(r'Grade:\s*(\w+)', api_output)
    results["api"] = {
        "output": api_output,
        "returncode": api_result.returncode,
        "score": api_score,
        "grade": api_grade,
    }

    print(f"\n{C['brand']}[11/17] {C['gold']}Running Video Analysis...{C['reset']}")
    video_args = ["-u", url]
    if export != "none":
        video_args += ["--export", export]
    if args.no_color:
        video_args.append("--no-color")
    video_result = subprocess.run(
        [sys.executable, VIDEO] + video_args,
        capture_output=True, text=True
    )
    video_output = video_result.stdout
    video_score = extract_score_from_output(r'Score:\s*(\d+)/100', video_output)
    video_grade = extract_score_from_output(r'Grade:\s*(\w+)', video_output)
    results["video"] = {
        "output": video_output,
        "returncode": video_result.returncode,
        "score": video_score,
        "grade": video_grade,
    }

    print(f"\n{C['brand']}[12/17] {C['gold']}Running Schema Analysis...{C['reset']}")
    schema_args = ["-u", url]
    if export != "none":
        schema_args += ["--export", export]
    if args.no_color:
        schema_args.append("--no-color")
    schema_result = subprocess.run(
        [sys.executable, SCHEMA] + schema_args,
        capture_output=True, text=True
    )
    schema_output = schema_result.stdout
    schema_score = extract_score_from_output(r'Score:\s*(\d+)/100', schema_output)
    schema_grade = extract_score_from_output(r'Grade:\s*(\w+)', schema_output)
    results["schema"] = {
        "output": schema_output,
        "returncode": schema_result.returncode,
        "score": schema_score,
        "grade": schema_grade,
    }

    print(f"\n{C['brand']}[13/17] {C['gold']}Running Email Deliverability...{C['reset']}")
    email_args = ["-u", url]
    if export != "none":
        email_args += ["--export", export]
    if args.no_color:
        email_args.append("--no-color")
    email_result = subprocess.run(
        [sys.executable, EMAIL] + email_args,
        capture_output=True, text=True
    )
    email_output = email_result.stdout
    email_score = extract_score_from_output(r'Score:\s*(\d+)/100', email_output)
    email_grade = extract_score_from_output(r'Grade:\s*(\w+)', email_output)
    results["email"] = {
        "output": email_output,
        "returncode": email_result.returncode,
        "score": email_score,
        "grade": email_grade,
    }

    print(f"\n{C['brand']}[14/17] {C['gold']}Running Sitemap & Crawlability...{C['reset']}")
    sitemap_args = ["-u", url]
    if export != "none":
        sitemap_args += ["--export", export]
    if args.no_color:
        sitemap_args.append("--no-color")
    sitemap_result = subprocess.run(
        [sys.executable, SITEMAP] + sitemap_args,
        capture_output=True, text=True
    )
    sitemap_output = sitemap_result.stdout
    sitemap_score = extract_score_from_output(r'Score:\s*(\d+)/100', sitemap_output)
    sitemap_grade = extract_score_from_output(r'Grade:\s*(\w+)', sitemap_output)
    results["sitemap"] = {
        "output": sitemap_output,
        "returncode": sitemap_result.returncode,
        "score": sitemap_score,
        "grade": sitemap_grade,
    }

    print(f"\n{C['brand']}[15/17] {C['gold']}Running HTML Validation...{C['reset']}")
    html_args = ["-u", url]
    if export != "none":
        html_args += ["--export", export]
    if args.no_color:
        html_args.append("--no-color")
    html_result = subprocess.run(
        [sys.executable, HTMLV] + html_args,
        capture_output=True, text=True
    )
    html_output = html_result.stdout
    html_score = extract_score_from_output(r'TOTAL\s+█+\s*(\d+)/100', html_output) or extract_score_from_output(r'(\d+)/100', html_output)
    html_grade = extract_score_from_output(r'GRADE:\s*(\w+)', html_output)
    results["html"] = {
        "output": html_output,
        "returncode": html_result.returncode,
        "score": html_score,
        "grade": html_grade,
    }

    print(f"\n{C['brand']}[16/17] {C['gold']}Running CDN Analysis...{C['reset']}")
    cdn_args = ["-u", url]
    if export != "none":
        cdn_args += ["--export", export]
    if args.no_color:
        cdn_args.append("--no-color")
    cdn_result = subprocess.run(
        [sys.executable, CDN] + cdn_args,
        capture_output=True, text=True
    )
    cdn_output = cdn_result.stdout
    cdn_score = extract_score_from_output(r'TOTAL:\s*(\d+(?:\.\d+)?)/100', cdn_output) or extract_score_from_output(r'(\d+)/100', cdn_output)
    cdn_grade = extract_score_from_output(r'GRADE:\s*(\w+)', cdn_output)
    results["cdn"] = {
        "output": cdn_output,
        "returncode": cdn_result.returncode,
        "score": cdn_score,
        "grade": cdn_grade,
    }

    print(f"\n{C['brand']}[17/17] {C['gold']}Running Cookie Privacy...{C['reset']}")
    cookies_args = ["-u", url]
    if export != "none":
        cookies_args += ["--export", export]
    if args.no_color:
        cookies_args.append("--no-color")
    cookies_result = subprocess.run(
        [sys.executable, COOKIES] + cookies_args,
        capture_output=True, text=True
    )
    cookies_output = cookies_result.stdout
    cookies_score = extract_score_from_output(r'Total Score:\s*(\d+)/100', cookies_output) or extract_score_from_output(r'(\d+)/100', cookies_output)
    cookies_grade = extract_score_from_output(r'Grade:\s*(\w+)', cookies_output)
    results["cookies"] = {
        "output": cookies_output,
        "returncode": cookies_result.returncode,
        "score": cookies_score,
        "grade": cookies_grade,
    }

    print(f"{C['brand']}{Style.BRIGHT}{'═' * 70}{C['reset']}")
    print(f"{C['brand']}{Style.BRIGHT}  COMBINED SCAN RESULTS{C['reset']}")
    print(f"{C['brand']}{Style.BRIGHT}{'═' * 70}{C['reset']}")
    print(f"  {C['desc']}Target:{C['reset']}   {_dim(url)}")
    print(f"  {C['desc']}Time:{C['reset']}     {_dim(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")
    print(f"{C['rule']}{Style.DIM}{'─' * 70}{C['reset']}\n")

    print(f"  {Fore.GREEN}{Style.BRIGHT}SEO Analysis{Style.RESET_ALL}")
    if seo_score:
        print(f"    Score: {Fore.YELLOW}{seo_score}{Style.RESET_ALL}")
    if results["seo"]["returncode"] == 0:
        print(f"    Status: {Fore.GREEN}Completed{Style.RESET_ALL}")
    else:
        print(f"    Status: {Fore.RED}Failed{Style.RESET_ALL}")

    critical_sec = len(re.findall(r'\[CRITICAL\]', sec_output))
    high_sec = len(re.findall(r'\[HIGH\]', sec_output))
    medium_sec = len(re.findall(r'\[MEDIUM\]', sec_output))

    print(f"\n  {Fore.GREEN}{Style.BRIGHT}Security Analysis{Style.RESET_ALL}")
    if sec_score:
        print(f"    Score: {Fore.YELLOW}{sec_score}/100{Style.RESET_ALL}")
    if sec_grade:
        print(f"    Grade: {Fore.YELLOW}{sec_grade}{Style.RESET_ALL}")
    if results["security"]["returncode"] == 0:
        print(f"    Status: {Fore.GREEN}Completed{Style.RESET_ALL}")
    else:
        print(f"    Status: {Fore.RED}Failed{Style.RESET_ALL}")
    if critical_sec > 0:
        print(f"    {Fore.RED}Critical: {critical_sec}{Style.RESET_ALL}")
    if high_sec > 0:
        print(f"    {Fore.RED}High: {high_sec}{Style.RESET_ALL}")
    if medium_sec > 0:
        print(f"    {Fore.YELLOW}Medium: {medium_sec}{Style.RESET_ALL}")

    print(f"\n  {Fore.GREEN}{Style.BRIGHT}Performance Analysis{Style.RESET_ALL}")
    if perf_score:
        print(f"    Score: {Fore.YELLOW}{perf_score}/100{Style.RESET_ALL}")
    if perf_grade:
        print(f"    Grade: {Fore.YELLOW}{perf_grade}{Style.RESET_ALL}")
    if results["perf"]["returncode"] == 0:
        print(f"    Status: {Fore.GREEN}Completed{Style.RESET_ALL}")
    else:
        print(f"    Status: {Fore.RED}Failed{Style.RESET_ALL}")

    print(f"\n  {Fore.GREEN}{Style.BRIGHT}Uptime Check{Style.RESET_ALL}")
    if uptime_score:
        print(f"    Score: {Fore.YELLOW}{uptime_score}/100{Style.RESET_ALL}")
    if uptime_verdict:
        v_color = Fore.GREEN if uptime_verdict == "UP" else (Fore.YELLOW if uptime_verdict == "DEGRADED" else Fore.RED)
        print(f"    Status: {v_color}{uptime_verdict}{Style.RESET_ALL}")
    if results["uptime"]["returncode"] == 0:
        print(f"    Check:  {Fore.GREEN}Completed{Style.RESET_ALL}")
    else:
        print(f"    Check:  {Fore.RED}Failed{Style.RESET_ALL}")

    print(f"\n  {Fore.GREEN}{Style.BRIGHT}Mobile Analysis{Style.RESET_ALL}")
    if mobile_score:
        print(f"    Score: {Fore.YELLOW}{mobile_score}/100{Style.RESET_ALL}")
    if mobile_grade:
        print(f"    Grade: {Fore.YELLOW}{mobile_grade}{Style.RESET_ALL}")
    if mobile_verdict:
        mf_color = Fore.GREEN if mobile_verdict == "YES" else (Fore.YELLOW if mobile_verdict == "PARTIAL" else Fore.RED)
        print(f"    Mobile Friendly: {mf_color}{mobile_verdict}{Style.RESET_ALL}")
    if results["mobile"]["returncode"] == 0:
        print(f"    Status: {Fore.GREEN}Completed{Style.RESET_ALL}")
    else:
        print(f"    Status: {Fore.RED}Failed{Style.RESET_ALL}")

    print(f"\n  {Fore.GREEN}{Style.BRIGHT}Content Analysis{Style.RESET_ALL}")
    if content_score:
        print(f"    Score: {Fore.YELLOW}{content_score}/100{Style.RESET_ALL}")
    if content_grade:
        print(f"    Grade: {Fore.YELLOW}{content_grade}{Style.RESET_ALL}")
    if results["content"]["returncode"] == 0:
        print(f"    Status: {Fore.GREEN}Completed{Style.RESET_ALL}")
    else:
        print(f"    Status: {Fore.RED}Failed{Style.RESET_ALL}")

    print(f"\n  {Fore.GREEN}{Style.BRIGHT}Network Diagnostics{Style.RESET_ALL}")
    if network_score:
        print(f"    Score: {Fore.YELLOW}{network_score}/100{Style.RESET_ALL}")
    if network_grade:
        print(f"    Grade: {Fore.YELLOW}{network_grade}{Style.RESET_ALL}")
    if results["network"]["returncode"] == 0:
        print(f"    Status: {Fore.GREEN}Completed{Style.RESET_ALL}")
    else:
        print(f"    Status: {Fore.RED}Failed{Style.RESET_ALL}")

    print(f"\n  {Fore.GREEN}{Style.BRIGHT}Accessibility Analysis{Style.RESET_ALL}")
    if access_score:
        print(f"    Score: {Fore.YELLOW}{access_score}/100{Style.RESET_ALL}")
    if access_grade:
        print(f"    Grade: {Fore.YELLOW}{access_grade}{Style.RESET_ALL}")
    if wcag_level:
        print(f"    WCAG Level: {Fore.YELLOW}{wcag_level}{Style.RESET_ALL}")
    if results["access"]["returncode"] == 0:
        print(f"    Status: {Fore.GREEN}Completed{Style.RESET_ALL}")
    else:
        print(f"    Status: {Fore.RED}Failed{Style.RESET_ALL}")

    print(f"\n  {Fore.GREEN}{Style.BRIGHT}Image Analysis{Style.RESET_ALL}")
    if image_score:
        print(f"    Score: {Fore.YELLOW}{image_score}/100{Style.RESET_ALL}")
    if image_grade:
        print(f"    Grade: {Fore.YELLOW}{image_grade}{Style.RESET_ALL}")
    if results["image"]["returncode"] == 0:
        print(f"    Status: {Fore.GREEN}Completed{Style.RESET_ALL}")
    else:
        print(f"    Status: {Fore.RED}Failed{Style.RESET_ALL}")

    print(f"\n  {Fore.GREEN}{Style.BRIGHT}API Analysis{Style.RESET_ALL}")
    if api_score:
        print(f"    Score: {Fore.YELLOW}{api_score}/100{Style.RESET_ALL}")
    if api_grade:
        print(f"    Grade: {Fore.YELLOW}{api_grade}{Style.RESET_ALL}")
    if results["api"]["returncode"] == 0:
        print(f"    Status: {Fore.GREEN}Completed{Style.RESET_ALL}")
    else:
        print(f"    Status: {Fore.RED}Failed{Style.RESET_ALL}")

    print(f"\n  {Fore.GREEN}{Style.BRIGHT}Video Analysis{Style.RESET_ALL}")
    if video_score:
        print(f"    Score: {Fore.YELLOW}{video_score}/100{Style.RESET_ALL}")
    if video_grade:
        print(f"    Grade: {Fore.YELLOW}{video_grade}{Style.RESET_ALL}")
    if results["video"]["returncode"] == 0:
        print(f"    Status: {Fore.GREEN}Completed{Style.RESET_ALL}")
    else:
        print(f"    Status: {Fore.RED}Failed{Style.RESET_ALL}")

    print(f"\n  {Fore.GREEN}{Style.BRIGHT}Schema Analysis{Style.RESET_ALL}")
    if schema_score:
        print(f"    Score: {Fore.YELLOW}{schema_score}/100{Style.RESET_ALL}")
    if schema_grade:
        print(f"    Grade: {Fore.YELLOW}{schema_grade}{Style.RESET_ALL}")
    if results["schema"]["returncode"] == 0:
        print(f"    Status: {Fore.GREEN}Completed{Style.RESET_ALL}")
    else:
        print(f"    Status: {Fore.RED}Failed{Style.RESET_ALL}")

    print(f"\n  {Fore.GREEN}{Style.BRIGHT}Email Deliverability{Style.RESET_ALL}")
    if email_score:
        print(f"    Score: {Fore.YELLOW}{email_score}/100{Style.RESET_ALL}")
    if email_grade:
        print(f"    Grade: {Fore.YELLOW}{email_grade}{Style.RESET_ALL}")
    if results["email"]["returncode"] == 0:
        print(f"    Status: {Fore.GREEN}Completed{Style.RESET_ALL}")
    else:
        print(f"    Status: {Fore.RED}Failed{Style.RESET_ALL}")

    print(f"\n  {Fore.GREEN}{Style.BRIGHT}Sitemap & Crawlability{Style.RESET_ALL}")
    if sitemap_score:
        print(f"    Score: {Fore.YELLOW}{sitemap_score}/100{Style.RESET_ALL}")
    if sitemap_grade:
        print(f"    Grade: {Fore.YELLOW}{sitemap_grade}{Style.RESET_ALL}")
    if results["sitemap"]["returncode"] == 0:
        print(f"    Status: {Fore.GREEN}Completed{Style.RESET_ALL}")
    else:
        print(f"    Status: {Fore.RED}Failed{Style.RESET_ALL}")

    print(f"\n  {Fore.GREEN}{Style.BRIGHT}HTML Validation{Style.RESET_ALL}")
    if html_score:
        print(f"    Score: {Fore.YELLOW}{html_score}/100{Style.RESET_ALL}")
    if html_grade:
        print(f"    Grade: {Fore.YELLOW}{html_grade}{Style.RESET_ALL}")
    if results["html"]["returncode"] == 0:
        print(f"    Status: {Fore.GREEN}Completed{Style.RESET_ALL}")
    else:
        print(f"    Status: {Fore.RED}Failed{Style.RESET_ALL}")

    print(f"\n  {Fore.GREEN}{Style.BRIGHT}CDN Analysis{Style.RESET_ALL}")
    if cdn_score:
        print(f"    Score: {Fore.YELLOW}{cdn_score}/100{Style.RESET_ALL}")
    if cdn_grade:
        print(f"    Grade: {Fore.YELLOW}{cdn_grade}{Style.RESET_ALL}")
    if results["cdn"]["returncode"] == 0:
        print(f"    Status: {Fore.GREEN}Completed{Style.RESET_ALL}")
    else:
        print(f"    Status: {Fore.RED}Failed{Style.RESET_ALL}")

    print(f"\n  {Fore.GREEN}{Style.BRIGHT}Cookie Privacy{Style.RESET_ALL}")
    if cookies_score:
        print(f"    Score: {Fore.YELLOW}{cookies_score}/100{Style.RESET_ALL}")
    if cookies_grade:
        print(f"    Grade: {Fore.YELLOW}{cookies_grade}{Style.RESET_ALL}")
    if results["cookies"]["returncode"] == 0:
        print(f"    Status: {Fore.GREEN}Completed{Style.RESET_ALL}")
    else:
        print(f"    Status: {Fore.RED}Failed{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")

    if export and export != "none":
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        combined = {
            "scan_type": "full",
            "target_url": url,
            "timestamp": datetime.now().isoformat(),
            "seo_score": seo_score,
            "security_score": sec_score,
            "security_grade": sec_grade,
            "perf_score": perf_score,
            "perf_grade": perf_grade,
            "uptime_score": uptime_score,
            "uptime_verdict": uptime_verdict,
            "mobile_score": mobile_score,
            "mobile_grade": mobile_grade,
            "mobile_verdict": mobile_verdict,
            "content_score": content_score,
            "content_grade": content_grade,
            "network_score": network_score,
            "network_grade": network_grade,
            "access_score": access_score,
            "access_grade": access_grade,
            "wcag_level": wcag_level,
            "image_score": image_score,
            "image_grade": image_grade,
            "api_score": api_score,
            "api_grade": api_grade,
            "video_score": video_score,
            "video_grade": video_grade,
            "schema_score": schema_score,
            "schema_grade": schema_grade,
            "email_score": email_score,
            "email_grade": email_grade,
            "sitemap_score": sitemap_score,
            "sitemap_grade": sitemap_grade,
        }
        report_file = f"combined_report_{ts}.json"
        with open(report_file, "w") as f:
            json.dump(combined, f, indent=2)
        print(f"\n  {Fore.GREEN}[+] Combined report saved: {report_file}{Style.RESET_ALL}")

    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cstools",
        description=f"{APP_NAME} — unified website measurement & analysis CLI ({APP_VERSION})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    sp_loadstorm = subparsers.add_parser("loadstorm", help="Run load/stress testing", add_help=False)
    sp_loadstorm.add_argument("-u", "--url", help="Target URL")
    sp_loadstorm.add_argument("-c", "--count", type=int, help="Virtual users")
    sp_loadstorm.add_argument("-d", "--duration", type=int, help="Duration in seconds")
    sp_loadstorm.add_argument("-C", "--concurrency", type=int, help="Max concurrent connections")
    sp_loadstorm.add_argument("-p", "--pattern", choices=["constant", "ramp", "spike", "wave", "stepped", "pulse", "targeted", "staircase", "elastic", "random_chaos"], help="Attack pattern")
    sp_loadstorm.add_argument("-m", "--method", choices=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"], help="HTTP method")
    sp_loadstorm.add_argument("-H", "--header", action="append", help="Custom headers")
    sp_loadstorm.add_argument("-b", "--body", help="Request body")
    sp_loadstorm.add_argument("-t", "--timeout", type=int, help="Request timeout")
    sp_loadstorm.add_argument("-B", "--batch-size", type=int, help="Users per batch")
    sp_loadstorm.add_argument("--no-keep-alive", action="store_true", help="Disable keep-alive")
    sp_loadstorm.add_argument("--rate-limit", type=int, help="Requests/sec per user")
    sp_loadstorm.add_argument("--payload-file", help="Payload file")
    sp_loadstorm.add_argument("--proxy", help="Proxy URL")
    sp_loadstorm.add_argument("--no-follow", action="store_true", help="No redirect following")
    sp_loadstorm.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_loadstorm.add_argument("--cache-bust", action="store_true", help="Enable cache busting")
    sp_loadstorm.add_argument("--jitter", type=int, help="Random delay in ms")
    sp_loadstorm.add_argument("--random-path", action="store_true", help="Random URL paths")
    sp_loadstorm.add_argument("--random-referer", action="store_true", help="Random Referer headers")
    sp_loadstorm.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")
    sp_loadstorm.add_argument("--export", default="all", choices=["all", "json", "csv", "html", "none"], help="Export format")
    sp_loadstorm.add_argument("--urls", help="File with multiple URLs")
    sp_loadstorm.add_argument("--websocket", action="store_true", help="WebSocket mode")
    sp_loadstorm.add_argument("--validate-status", type=int, help="Validate response status")
    sp_loadstorm.add_argument("--validate-contains", help="Validate response contains text")
    sp_loadstorm.add_argument("--validate-max-time", type=float, help="Validate max response time")
    sp_loadstorm.add_argument("--geo-sim", action="store_true", help="Geographic simulation")
    sp_loadstorm.add_argument("--adaptive", action="store_true", help="Adaptive rate control")
    sp_loadstorm.add_argument("--scenario", help="Scenario chain JSON file")
    sp_loadstorm.set_defaults(func=cmd_loadstorm)

    sp_seo = subparsers.add_parser("seo", help="Run SEO analysis", add_help=False)
    sp_seo.add_argument("-u", "--url", help="URL to analyze")
    sp_seo.add_argument("-t", "--timeout", type=int, help="Request timeout")
    sp_seo.add_argument("--export", default="none", choices=["all", "json", "csv", "html", "none"], help="Export format")
    sp_seo.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_seo.add_argument("--check-links", action="store_true", help="Check broken links")
    sp_seo.add_argument("--batch", help="File with URLs to analyze")
    sp_seo.set_defaults(func=cmd_seo)

    sp_security = subparsers.add_parser("security", help="Run security analysis", add_help=False)
    sp_security.add_argument("-u", "--url", help="Target URL")
    sp_security.add_argument("-t", "--timeout", type=int, help="Request timeout")
    sp_security.add_argument("--export", default="none", choices=["all", "json", "csv", "html", "none"], help="Export format")
    sp_security.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_security.set_defaults(func=cmd_security)

    sp_perf = subparsers.add_parser("perf", help="Run performance analysis", add_help=False)
    sp_perf.add_argument("-u", "--url", help="Target URL")
    sp_perf.add_argument("-t", "--timeout", type=int, help="Request timeout")
    sp_perf.add_argument("--export", default="none", choices=["all", "json", "csv", "html", "none"], help="Export format")
    sp_perf.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_perf.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    sp_perf.set_defaults(func=cmd_perf)

    sp_uptime = subparsers.add_parser("uptime", help="Run uptime check", add_help=False)
    sp_uptime.add_argument("-u", "--url", help="Target URL")
    sp_uptime.add_argument("-t", "--timeout", type=int, help="Request timeout")
    sp_uptime.add_argument("-c", "--count", type=int, help="Number of checks")
    sp_uptime.add_argument("-i", "--interval", type=int, help="Seconds between checks")
    sp_uptime.add_argument("--export", default="none", choices=["all", "json", "csv", "html", "none"], help="Export format")
    sp_uptime.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_uptime.add_argument("--expect", help="Expect this string in response")
    sp_uptime.set_defaults(func=cmd_uptime)

    sp_mobile = subparsers.add_parser("mobile", help="Run mobile analysis", add_help=False)
    sp_mobile.add_argument("-u", "--url", help="Target URL")
    sp_mobile.add_argument("-t", "--timeout", type=int, help="Request timeout")
    sp_mobile.add_argument("--export", default="none", choices=["all", "json", "csv", "html", "none"], help="Export format")
    sp_mobile.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_mobile.set_defaults(func=cmd_mobile)

    sp_content = subparsers.add_parser("content", help="Run content analysis", add_help=False)
    sp_content.add_argument("-u", "--url", help="Target URL")
    sp_content.add_argument("-t", "--timeout", type=int, help="Request timeout")
    sp_content.add_argument("--export", default="none", choices=["all", "json", "csv", "html", "none"], help="Export format")
    sp_content.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_content.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    sp_content.set_defaults(func=cmd_content)

    sp_network = subparsers.add_parser("network", help="Run network diagnostics", add_help=False)
    sp_network.add_argument("-u", "--url", help="Target URL")
    sp_network.add_argument("-t", "--timeout", type=int, help="Request timeout")
    sp_network.add_argument("--export", default="none", choices=["all", "json", "csv", "html", "none"], help="Export format")
    sp_network.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_network.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    sp_network.set_defaults(func=cmd_network)

    sp_access = subparsers.add_parser("access", help="Run accessibility analysis", add_help=False)
    sp_access.add_argument("-u", "--url", help="Target URL")
    sp_access.add_argument("-t", "--timeout", type=int, help="Request timeout")
    sp_access.add_argument("--export", default="none", choices=["all", "json", "csv", "html", "none"], help="Export format")
    sp_access.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_access.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    sp_access.add_argument("--level", default="AA", choices=["A", "AA", "AAA"], help="WCAG compliance level")
    sp_access.set_defaults(func=cmd_access)

    sp_image = subparsers.add_parser("image", help="Run image analysis", add_help=False)
    sp_image.add_argument("-u", "--url", help="Target URL")
    sp_image.add_argument("-t", "--timeout", type=int, help="Request timeout")
    sp_image.add_argument("--export", default="none", choices=["all", "json", "csv", "html", "none"], help="Export format")
    sp_image.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_image.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    sp_image.set_defaults(func=cmd_image)

    sp_api = subparsers.add_parser("api", help="Run API analysis", add_help=False)
    sp_api.add_argument("-u", "--url", help="Target URL")
    sp_api.add_argument("-t", "--timeout", type=int, help="Request timeout")
    sp_api.add_argument("--export", default="none", choices=["all", "json", "csv", "html", "none"], help="Export format")
    sp_api.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_api.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    sp_api.add_argument("--api-key", help="API key for authentication")
    sp_api.add_argument("--auth-type", default="none", choices=["none", "bearer", "basic", "apikey"], help="Auth type")
    sp_api.set_defaults(func=cmd_api)

    sp_video = subparsers.add_parser("video", help="Run video analysis", add_help=False)
    sp_video.add_argument("-u", "--url", help="Target URL")
    sp_video.add_argument("-t", "--timeout", type=int, help="Request timeout")
    sp_video.add_argument("--export", default="none", choices=["all", "json", "csv", "html", "none"], help="Export format")
    sp_video.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_video.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    sp_video.set_defaults(func=cmd_video)

    sp_schema = subparsers.add_parser("schema", help="Run structured data analysis", add_help=False)
    sp_schema.add_argument("-u", "--url", help="Target URL")
    sp_schema.add_argument("-t", "--timeout", type=int, help="Request timeout")
    sp_schema.add_argument("--export", default="none", choices=["all", "json", "csv", "html", "none"], help="Export format")
    sp_schema.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_schema.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    sp_schema.set_defaults(func=cmd_schema)

    sp_email = subparsers.add_parser("email", help="Run email deliverability analysis", add_help=False)
    sp_email.add_argument("-u", "--url", help="Target domain (e.g. example.com)")
    sp_email.add_argument("-t", "--timeout", type=int, help="Request timeout")
    sp_email.add_argument("--export", default="none", choices=["all", "json", "csv", "html", "none"], help="Export format")
    sp_email.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_email.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    sp_email.add_argument("--selector", help="DKIM selector to test")
    sp_email.set_defaults(func=cmd_email)

    sp_sitemap = subparsers.add_parser("sitemap", help="Run sitemap & crawlability analysis", add_help=False)
    sp_sitemap.add_argument("-u", "--url", help="Target URL")
    sp_sitemap.add_argument("-t", "--timeout", type=int, help="Request timeout")
    sp_sitemap.add_argument("--export", default="none", choices=["all", "json", "csv", "html", "none"], help="Export format")
    sp_sitemap.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_sitemap.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    sp_sitemap.set_defaults(func=cmd_sitemap)

    sp_html = subparsers.add_parser("html", help="Run HTML validation", add_help=False)
    sp_html.add_argument("-u", "--url", help="Target URL")
    sp_html.add_argument("-t", "--timeout", type=int, help="Request timeout")
    sp_html.add_argument("--export", default="none", choices=["all", "json", "csv", "html", "none"], help="Export format")
    sp_html.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_html.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    sp_html.set_defaults(func=cmd_html)

    sp_cdn = subparsers.add_parser("cdn", help="Run CDN analysis", add_help=False)
    sp_cdn.add_argument("-u", "--url", help="Target URL")
    sp_cdn.add_argument("-t", "--timeout", type=int, help="Request timeout")
    sp_cdn.add_argument("--export", default="none", choices=["all", "json", "csv", "html", "none"], help="Export format")
    sp_cdn.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_cdn.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    sp_cdn.set_defaults(func=cmd_cdn)

    sp_cookies = subparsers.add_parser("cookies", help="Run cookie privacy analysis", add_help=False)
    sp_cookies.add_argument("-u", "--url", help="Target URL")
    sp_cookies.add_argument("-t", "--timeout", type=int, help="Request timeout")
    sp_cookies.add_argument("--export", default="none", choices=["all", "json", "csv", "html", "none"], help="Export format")
    sp_cookies.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_cookies.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    sp_cookies.set_defaults(func=cmd_cookies)

    sp_upgrade = subparsers.add_parser("upgrade", help="Prioritized upgrade roadmap for better rating", add_help=False)
    sp_upgrade.add_argument("-u", "--url", help="Target URL")
    sp_upgrade.add_argument("-t", "--timeout", type=int, help="Per-tool timeout")
    sp_upgrade.add_argument("--export", default="none", choices=["all", "json", "html", "none"], help="Export format")
    sp_upgrade.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_upgrade.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    sp_upgrade.add_argument("--only", nargs="*", help="Run only these tools by label")
    sp_upgrade.set_defaults(func=cmd_upgrade)

    sp_scan = subparsers.add_parser("scan", help="Run all tools on a URL", add_help=False)
    sp_scan.add_argument("-u", "--url", required=True, help="Target URL")
    sp_scan.add_argument("--export", default="none", choices=["all", "json", "csv", "html", "none"], help="Export format")
    sp_scan.add_argument("--no-color", action="store_true", help="Disable colors")
    sp_scan.set_defaults(func=cmd_scan)

    sp_list = subparsers.add_parser("list", help="List available tools", add_help=False)
    sp_list.set_defaults(func=cmd_list)

    return parser


def main():
    if len(sys.argv) == 1:
        print(BANNER)
        parser = build_parser()
        parser.print_help()
        sys.exit(0)

    parser = build_parser()
    args = parser.parse_args()

    if not hasattr(args, "func"):
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    if args.command != "list":
        print(BANNER)

    rc = args.func(args)
    sys.exit(rc)


if __name__ == "__main__":
    main()
