#!/usr/bin/env python3
"""
UpgradeAdvisor v1.0 — What to upgrade on your website for a better rating.

Runs the CS-Tool suite, aggregates every tool's score into one overall
site rating, then produces a prioritized upgrade roadmap: what to fix,
in what order, how much rating each fix is worth, and how hard it is.
"""

import os
import re
import sys
import json
import argparse
import subprocess
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SCRIPT_DIR)

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except ImportError:
    class _Fake:
        def __getattr__(self, n): return ''
    Fore = Style = _Fake()

VERSION = "UpgradeAdvisor v1.0"

# name, command label, script path relative to ROOT, arg style
TOOLS = [
    ("SEO",           "seo",      "SEOChecker/seocheck.py",            "url"),
    ("Security",      "security", "SecurityChecker/securitycheck.py",  "url"),
    ("Performance",   "perf",     "PerfAnalyzer/perfanalyzer.py",      "url"),
    ("Uptime",        "uptime",   "UptimeChecker/uptimechecker.py",    "url"),
    ("Mobile",        "mobile",   "MobileAnalyzer/mobileanalyzer.py",  "url"),
    ("Content",       "content",  "ContentAnalyzer/contentanalyzer.py","url"),
    ("Network",       "network",  "NetworkAnalyzer/networkanalyzer.py","url"),
    ("Accessibility", "access",   "AccessibilityAnalyzer/accessibilityanalyzer.py", "url"),
    ("Image",         "image",    "ImageAnalyzer/imageanalyzer.py",    "url"),
    ("API",           "api",      "APIAnalyzer/apianalyzer.py",        "url"),
    ("Video",         "video",    "VideoAnalyzer/videoanalyzer.py",    "url"),
    ("Schema",        "schema",   "SchemaAnalyzer/schemaanalyzer.py",  "url"),
    ("Sitemap",       "sitemap",  "SitemapAnalyzer/sitemapanalyzer.py","url"),
    ("HTML",          "html",     "HTMLValidator/htmlvalidator.py",    "url"),
    ("CDN",           "cdn",      "CDNAnalyzer/cdnanalyzer.py",        "url"),
    ("Cookies",       "cookies",  "CookieAnalyzer/cookieanalyzer.py",  "url"),
]

# Score-extraction patterns per tool, tried in order. First match wins.
# Each: list of (regex, denominator_or_None_for_percent)
SCORE_PATTERNS = {
    "seo": [
        (r"Final Score:\s*[A-F]?[\d.]+/(\d+)", None),   # captured later with value
        (r"Final Score:\s*[A-F]?(\d+)/(\d+)", None),
        (r"OVERALL\s+█+\s*(\d+)%", None),
    ],
    "security": [
        (r"Overall Score:\s*(\d+)/100", None),
        (r"Score:\s*(\d+)/100", None),
    ],
    "perf": [
        (r"PERFORMANCE SCORE\s*\n?.*?(\d+(?:\.\d+)?)\s*/\s*100", None),
        (r"Lighthouse\s+█+\s*(\d+)/100", None),
        (r"Lighthouse Score \(simulated\)\s+(\d+)/100", None),
        (r"Score:\s*(\d+)/100", None),
    ],
    "uptime": [
        (r"Avg Score:\s*(\d+)/100", None),
        (r"Score:\s*(\d+)/100", None),
    ],
    "mobile": [
        (r"Mobile Readiness Score:\s*([\d.]+)%", None),
        (r"Score:\s*(\d+)/100", None),
    ],
    "content": [
        (r"TOTAL\s+█+\s*([\d.]+)/(\d+)", None),
        (r"Overall\s+█+\s*([\d.]+)/(\d+)", None),
        (r"Score:\s*([\d.]+)/(\d+)", None),
    ],
    "network": [
        (r"Network Score:\s*(\d+)/100", None),
        (r"Composite Score:\s*(\d+(?:\.\d+)?)/100", None),
        (r"Score:\s*(\d+)/100", None),
        (r"Grade:\s*([A-F][+-]?)", None),
    ],
    "access": [
        (r"Composite score:\s*(\d+(?:\.\d+)?)\s*/\s*100", None),
        (r"Score:\s*(\d+(?:\.\d+)?)/100", None),
        (r"Raw Score:\s*(\d+(?:\.\d+)?)\s*/\s*100", None),
    ],
    "image": [
        (r"TOTAL SCORE:\s*(\d+(?:\.\d+)?)\s*/\s*100", None),
        (r"Score\s+(\d+(?:\.\d+)?)\s*/\s*100", None),
        (r"Score:\s*(\d+(?:\.\d+)?)/100", None),
    ],
    "api": [
        (r"TOTAL:\s*(\d+(?:\.\d+)?)\s*/\s*100", None),
        (r"Score:\s*(\d+(?:\.\d+)?)/100", None),
    ],
    "video": [
        (r"TOTAL SCORE\s+\n?\s*(\d+)\s*/\s*(\d+)", None),
        (r"Overall\s+(\d+)%", None),
        (r"Score:\s*(\d+)/(\d+)", None),
    ],
    "schema": [
        (r"TOTAL\s+(\d+(?:\.\d+)?)\s+(\d+)\s+(\d+(?:\.\d+)?)%", None),
        (r"Score:\s*(\d+(?:\.\d+)?)/(\d+)", None),
    ],
    "sitemap": [
        (r"SCORE:\s*(\d+(?:\.\d+)?)\s*/\s*100", None),
        (r"TOTAL\s+█+\s*(\d+(?:\.\d+)?)/100", None),
        (r"Score:\s*(\d+(?:\.\d+)?)/100", None),
    ],
    "html": [
        (r"TOTAL\s+█+\s*(\d+)/100", None),
        (r"Score:\s*(\d+)/100", None),
    ],
    "cdn": [
        (r"TOTAL:\s*(\d+(?:\.\d+)?)\s*/\s*100", None),
        (r"Score:\s*(\d+(?:\.\d+)?)/100", None),
    ],
    "cookies": [
        (r"Total Score:\s*(\d+)/100", None),
        (r"Score:\s*(\d+)/100", None),
    ],
}

# Relative weights for the overall site rating (sum ≈ 100)
WEIGHTS = {
    "seo": 12, "security": 12, "perf": 12, "uptime": 4, "mobile": 8,
    "content": 8, "network": 5, "access": 7, "image": 4, "api": 4,
    "video": 3, "schema": 6, "sitemap": 4, "html": 3, "cdn": 3, "cookies": 2,
}

# upgrade rules: (category, keyword-matchers on tool or issue text,
#                 title, effort, description-template)
# Estimated points are computed dynamically from score gap to 90.
def grade(score):
    if score is None:
        return "?"
    if score >= 95: return "A+"
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


def bar(score, width=20):
    if score is None:
        return "?" * width
    filled = int(round(score / 100 * width))
    return "█" * filled + "░" * (width - filled)


def color_for(score):
    if score is None: return Style.DIM
    if score >= 90: return Fore.GREEN
    if score >= 70: return Fore.YELLOW
    if score >= 50: return Fore.LIGHTRED_EX
    return Fore.RED


def run_tool(script_rel, url, timeout, no_color):
    path = os.path.join(ROOT, script_rel)
    if not os.path.exists(path):
        return None, f"script missing: {script_rel}"
    args = [sys.executable, path, "-u", url, "-t", str(timeout)]
    if no_color:
        args.append("--no-color")
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout + 30)
        return r.stdout + r.stderr, None
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except Exception as e:
        return None, str(e)


def parse_score(tool_key, output):
    """Return (score_0_to_100, raw_matched_text) or (None, None)."""
    if not output:
        return None, None
    for regex, _ in SCORE_PATTERNS.get(tool_key, []):
        m = re.search(regex, output, re.IGNORECASE | re.MULTILINE)
        if not m:
            continue
        groups = m.groups()
        # Cases:
        # 1 group  -> value over 100 (or a percent)
        # 2 groups -> value/max  -> normalize to 100
        try:
            if len(groups) >= 2 and groups[1] is not None:
                val, mx = float(groups[0]), float(groups[1])
                if mx == 0:
                    continue
                return round(val / mx * 100, 1), m.group(0).strip()
            val = float(groups[0])
            # percent patterns already 0-100; raw "/563" style handled by 2-group
            if val > 100:
                # treat as something over unknown max -> skip unless known max nearby
                continue
            return round(val, 1), m.group(0).strip()
        except (ValueError, IndexError):
            continue
    # grade-only fallback
    m = re.search(r"\bGrade:\s*([A-F][+-]?)", output, re.IGNORECASE)
    if m:
        g = m.group(1).upper()
        mapping = {"A+": 97, "A": 93, "B": 82, "C": 74, "D": 65, "F": 30}
        return mapping.get(g[0], None), m.group(0).strip()
    return None, None


def parse_issues(tool_key, output, limit=6):
    """Pull top actionable issue lines from a tool's output."""
    if not output:
        return []
    issues = []
    patterns = [
        r"\[\s*(?:CRITICAL|HIGH|MEDIUM|LOW|P1|P2|P3)\s*\]\s*(.+)",
        r"^\s*(?:[-•]\s*)?(?:FAIL|MISSING|ERROR)\s*[:\-]\s*(.+)",
        r"^\s*\d+\.\s*\[(?:CRITICAL|HIGH|MEDIUM|LOW)\]\s*(.+)",
        r"^\s*[-•]\s+([A-Z][^.]{15,120}\.)",
    ]
    seen = set()
    for pat in patterns:
        for m in re.finditer(pat, output, re.IGNORECASE | re.MULTILINE):
            text = " ".join(m.group(1).split())
            key = text.lower()[:60]
            if key in seen or len(text) < 15:
                continue
            seen.add(key)
            issues.append(text)
            if len(issues) >= limit:
                return issues
    return issues


def build_roadmap(scores, issues_by_tool):
    """Turn scores into a prioritized upgrade list."""
    items = []
    for key, sc in scores.items():
        if sc is None:
            continue
        gap = max(0.0, 90.0 - sc)  # points to reach an A
        if gap <= 0:
            continue
        # weight: how much this tool moves the overall rating
        w = WEIGHTS.get(key, 3) / 100.0
        impact = round(gap * w, 1)  # overall-rating points gained at full fix
        # effort heuristic
        if gap >= 50:
            effort = "High"
        elif gap >= 25:
            effort = "Medium"
        else:
            effort = "Low"
        sample = issues_by_tool.get(key, [])[:3]
        items.append({
            "tool": key,
            "score": sc,
            "grade": grade(sc),
            "gap": round(gap, 1),
            "impact": impact,
            "effort": effort,
            "issues": sample,
        })
    # priority = impact / effort-cost
    effort_cost = {"Low": 1, "Medium": 2, "High": 4}
    for it in items:
        it["priority"] = round(it["impact"] / effort_cost[it["effort"]], 2)
    items.sort(key=lambda x: (-x["priority"], -x["impact"]))
    return items


def overall_rating(scores):
    total_w, acc = 0, 0.0
    for key, w in WEIGHTS.items():
        sc = scores.get(key)
        if sc is None:
            continue
        acc += sc * w
        total_w += w
    if total_w == 0:
        return None, 0
    return round(acc / total_w, 1), total_w


def print_report(url, scores, issues, roadmap, overall, coverage, elapsed):
    c = Style.BRIGHT
    print(f"\n{c}{Fore.CYAN}{'='*78}{Style.RESET_ALL}")
    print(f"{c}{Fore.CYAN}  {VERSION} — UPGRADE ROADMAP FOR: {url}{Style.RESET_ALL}")
    print(f"{c}{Fore.CYAN}  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  Tools run: {coverage}/16  |  {elapsed:.1f}s{Style.RESET_ALL}")
    print(f"{c}{Fore.CYAN}{'='*78}{Style.RESET_ALL}\n")

    # Overall rating
    ov = overall if overall is not None else 0
    oc = color_for(ov)
    print(f"  {c}OVERALL SITE RATING{Style.RESET_ALL}")
    print(f"  {oc}{c}{ov:.1f} / 100   Grade {grade(ov)}{Style.RESET_ALL}")
    print(f"  {oc}  {bar(ov, 40)}  {ov:.0f}%{Style.RESET_ALL}")
    target = 90
    print(f"  {Fore.WHITE}  Distance to A (90): {max(0, round(target - ov, 1))} points{Style.RESET_ALL}\n")

    # Per-tool scorecard
    print(f"  {c}{Fore.YELLOW}SCORECARD BY TOOL{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}{'Tool':<15} {'Score':>7} {'Grade':>6}  {'Bar':<22} {'Status'}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}{'-'*74}{Style.RESET_ALL}")
    ordered = sorted(scores.items(), key=lambda kv: (kv[1] is None, -(kv[1] or 0)))
    for key, sc in ordered:
        if sc is None:
            print(f"  {Fore.WHITE}{key:<15} {'n/a':>7} {'?':>6}  {Style.DIM}{'·'*22}{Style.RESET_ALL}  {Style.DIM}not scored{Style.RESET_ALL}")
            continue
        gc = color_for(sc)
        status = "OK" if sc >= 80 else ("Needs work" if sc >= 60 else "Priority")
        print(f"  {gc}{key:<15} {sc:>6.1f} {grade(sc):>6}  {gc}{bar(sc, 22)}{Style.RESET_ALL}  {gc}{status}{Style.RESET_ALL}")

    # Upgrade roadmap
    print(f"\n  {c}{Fore.YELLOW}{'='*74}{Style.RESET_ALL}")
    print(f"  {c}{Fore.YELLOW}  WHAT TO UPGRADE (prioritized — biggest rating gain first){Style.RESET_ALL}")
    print(f"  {c}{Fore.YELLOW}{'='*74}{Style.RESET_ALL}\n")

    if not roadmap:
        print(f"  {Fore.GREEN}Nothing critical to upgrade — all scored tools are at 90+.{Style.RESET_ALL}")
    else:
        print(f"  {Fore.CYAN}{'#':<4}{'Upgrade area':<15}{'Now':>6}{'Gain':>7} {'Effort':<8}{'Priority':<9} Why{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}{'-'*74}{Style.RESET_ALL}")
        for i, it in enumerate(roadmap, 1):
            gc = color_for(it["score"])
            ec = {"Low": Fore.GREEN, "Medium": Fore.YELLOW, "High": Fore.RED}[it["effort"]]
            why = it["issues"][0][:44] if it["issues"] else "score below target (90)"
            print(f"  {i:<4}{it['tool']:<15}{gc}{it['score']:>5.1f}{Style.RESET_ALL}"
                  f" {Fore.GREEN}+{it['impact']:>5.1f}{Style.RESET_ALL}"
                  f" {ec}{it['effort']:<8}{Style.RESET_ALL}"
                  f" {gc}{it['priority']:>7.2f}{Style.RESET_ALL}  {Fore.WHITE}{why}{Style.RESET_ALL}")

        # Quick wins section
        quick = [it for it in roadmap if it["effort"] == "Low"]
        if quick:
            print(f"\n  {c}{Fore.GREEN}QUICK WINS (low effort, do these first){Style.RESET_ALL}")
            for it in quick:
                print(f"    {Fore.GREEN}+{Style.RESET_ALL} {it['tool']}: from {it['score']:.0f} → potential +{it['impact']:.1f} overall")
                for iss in it["issues"][:2]:
                    print(f"        {Style.DIM}· {iss}{Style.RESET_ALL}")

        # Biggest projects
        big = sorted(roadmap, key=lambda x: -x["impact"])[:3]
        print(f"\n  {c}{Fore.LIGHTYELLOW_EX}BIGGEST RATING MOVES (plan these){Style.RESET_ALL}")
        for it in big:
            print(f"    {Fore.LIGHTYELLOW_EX}▸{Style.RESET_ALL} {it['tool']}: +{it['impact']:.1f} overall if brought to 90 "
                  f"({it['effort']} effort, now {it['score']:.0f})")
            for iss in it["issues"][:2]:
                print(f"        {Style.DIM}· {iss}{Style.RESET_ALL}")

    # Summary line
    total_potential = round(sum(it["impact"] for it in roadmap), 1)
    projected = round(min(97.0, ov + total_potential * 0.7), 1)
    print(f"\n  {c}{Fore.MAGENTA}{'='*74}{Style.RESET_ALL}")
    print(f"  {c}{Fore.MAGENTA}  POTENTIAL: fixing all listed items ≈ +{total_potential} raw, "
          f"projected rating → {projected} ({grade(projected)}){Style.RESET_ALL}")
    print(f"  {c}{Fore.MAGENTA}{'='*74}{Style.RESET_ALL}\n")


def export_report(path_base, url, scores, roadmap, overall, issues):
    data = {
        "tool": VERSION,
        "url": url,
        "generated": datetime.now().isoformat(),
        "overall_rating": overall,
        "overall_grade": grade(overall),
        "scores": scores,
        "grades": {k: grade(v) for k, v in scores.items()},
        "roadmap": roadmap,
        "issues": issues,
    }
    paths = []
    jp = path_base + ".json"
    with open(jp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    paths.append(jp)

    hp = path_base + ".html"
    rows = "\n".join(
        f"<tr><td>{i['tool']}</td><td>{i['score']}</td><td>{i['grade']}</td>"
        f"<td>+{i['impact']}</td><td>{i['effort']}</td><td>{i['priority']}</td>"
        f"<td>{'; '.join(i['issues'])}</td></tr>"
        for i in roadmap
    )
    sc_rows = "\n".join(
        f"<tr><td>{k}</td><td>{v if v is not None else 'n/a'}</td><td>{grade(v)}</td></tr>"
        for k, v in sorted(scores.items())
    )
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Upgrade Roadmap — {url}</title>
<style>
body{{background:#0d1117;color:#e6edf3;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;padding:32px;}}
h1{{color:#58a6ff}} h2{{color:#d2a8ff;margin-top:32px}}
table{{border-collapse:collapse;width:100%;margin-top:12px}}
th,td{{border:1px solid #30363d;padding:8px 10px;text-align:left;font-size:13px}}
th{{background:#161b22;color:#79c0ff}}
.overall{{font-size:40px;color:#58a6ff;font-weight:bold}}
.bar{{background:#21262d;height:18px;border-radius:4px;overflow:hidden}}
.bar>i{{display:block;height:100%;background:linear-gradient(90deg,#f85149,#d29922,#3fb950)}}
.tag{{padding:2px 8px;border-radius:10px;font-size:12px}}
.low{{background:#1a7f37}} .med{{background:#9e6a03}} .high{{background:#da3633}}
</style></head><body>
<h1>Upgrade Roadmap</h1><p>{url} · {datetime.now().strftime('%Y-%m-%d %H:%M')} · {VERSION}</p>
<div class="overall">{overall}/100 · Grade {grade(overall)}</div>
<div class="bar" style="max-width:480px"><i style="width:{overall}%"></i></div>
<h2>What to upgrade (prioritized)</h2>
<table><tr><th>#</th><th>Area</th><th>Now</th><th>Gain</th><th>Effort</th><th>Priority</th><th>Why</th></tr>
{rows}</table>
<h2>Scorecard</h2>
<table><tr><th>Tool</th><th>Score</th><th>Grade</th></tr>{sc_rows}</table>
</body></html>"""
    with open(hp, "w", encoding="utf-8") as f:
        f.write(html)
    paths.append(hp)
    return paths


def build_parser():
    p = argparse.ArgumentParser(
        prog="upgrade",
        description="Aggregate all CS-Tool scores and print a prioritized upgrade roadmap.",
    )
    p.add_argument("-u", "--url", required=True, help="Target URL")
    p.add_argument("-t", "--timeout", type=int, default=60, help="Per-tool timeout (default 60)")
    p.add_argument("--export", default="none", choices=["all", "json", "html", "none"],
                   help="Export format")
    p.add_argument("--no-color", action="store_true", help="Disable colors")
    p.add_argument("-v", "--verbose", action="store_true", help="Show tool errors")
    p.add_argument("--only", nargs="*", help="Run only these tools (by label, e.g. seo security)")
    return p


def main():
    args = build_parser().parse_args()
    url = args.url
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url

    import time
    t0 = time.time()
    print(f"{Fore.CYAN}{Style.BRIGHT} {VERSION} — collecting scores from CS-Tool…{Style.RESET_ALL}")
    print(f"{Fore.CYAN} Target: {url}{Style.RESET_ALL}\n")

    selected = [t for t in TOOLS if not args.only or t[1] in args.only]
    scores, issues_by_tool = {}, {}
    for i, (label, key, script, _) in enumerate(selected, 1):
        print(f"  [{i}/{len(selected)}] {label:<14} …", end="", flush=True)
        output, err = run_tool(script, url, args.timeout, args.no_color)
        sc, raw = parse_score(key, output)
        scores[key] = sc
        if output:
            issues_by_tool[key] = parse_issues(key, output)
        if sc is not None:
            print(f" {color_for(sc)}{sc:.1f} ({grade(sc)}){Style.RESET_ALL}"
                  + (f"  {Style.DIM}[{raw}]{Style.RESET_ALL}" if raw and args.verbose else ""))
        else:
            print(f" {Style.DIM}no score{' ('+err+')' if err else ''}{Style.RESET_ALL}")
            if err and args.verbose:
                print(f"      {Style.DIM}{err}{Style.RESET_ALL}")

    coverage = sum(1 for v in scores.values() if v is not None)
    overall, _w = overall_rating(scores)
    roadmap = build_roadmap(scores, issues_by_tool)
    elapsed = time.time() - t0

    print_report(url, scores, issues_by_tool, roadmap, overall, coverage, elapsed)

    if args.export != "none":
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(os.getcwd(), f"upgrade_roadmap_{stamp}")
        wanted = []
        if args.export in ("json", "all"):
            wanted.append("json")
        if args.export in ("html", "all"):
            wanted.append("html")
        # export_report writes both; filter after
        paths = export_report(base, url, scores, roadmap, overall or 0, issues_by_tool)
        for p in paths:
            if args.export == "json" and not p.endswith(".json"):
                try: os.remove(p)
                except OSError: pass
                continue
            if args.export == "html" and not p.endswith(".html"):
                try: os.remove(p)
                except OSError: pass
                continue
            print(f"{Fore.GREEN}[export]{Style.RESET_ALL} Wrote {p}")

    sys.exit(0 if (overall or 0) >= 70 else 1)


if __name__ == "__main__":
    main()
