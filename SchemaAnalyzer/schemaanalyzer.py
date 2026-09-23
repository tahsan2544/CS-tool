#!/usr/bin/env python3

import argparse
import csv
import io
import json
import os
import re
import sys
import datetime

try:
    import requests
except ImportError:
    os.system(f"{sys.executable} -m pip install requests -q")
    import requests

try:
    from bs4 import BeautifulSoup
except ImportError:
    os.system(f"{sys.executable} -m pip install beautifulsoup4 -q")
    from bs4 import BeautifulSoup

VERSION = "1.0"
BANNER = r"""
   ███████╗ ██████╗ █████╗ ███╗   ██╗ ██████╗ ███████╗ ██████╗  █████╗  ██████╗██╗  ██╗
   ██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝ ██╔════╝██╔═══██╗██╔══██╗██╔════╝██║  ██║
   ███████╗██║     ███████║██╔██╗ ██║██║  ███╗█████╗  ██║   ██║███████║██║     ███████║
   ╚════██║██║     ██╔══██║██║╚██╗██║██║   ██║██╔══╝  ██║   ██║██╔══██║██║     ██╔══██║
   ███████║╚██████╗██║  ██║██║ ╚████║╚██████╔╝███████╗╚██████╔╝██║  ██║╚██████╗██║  ██║
   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                         v1.0  -  Structured Data Analyzer
"""

DEPRECATED_PROPERTIES = ["isBasedOnUrl", "containedIn", "serviceInput", "serviceOutput"]
NEW_PROPERTIES = ["foundingDate", "slogan", "knowsAbout", "isAccessibleForFree", "subOrganization"]

SCHEMA_TYPES = [
    "Organization",
    "Person",
    "WebSite",
    "Article",
    "BlogPosting",
    "Product",
    "BreadcrumbList",
    "FAQPage",
    "HowTo",
    "Event",
    "LocalBusiness",
]

DETECTABLE_TYPES = [
    "Organization",
    "Person",
    "WebSite",
    "Article",
    "Product",
    "BreadcrumbList",
    "FAQPage",
    "HowTo",
    "Event",
    "LocalBusiness",
]

REQUIRED_PROPS = {
    "Organization": ["name", "url"],
    "Person": ["name"],
    "WebSite": ["name", "url"],
    "Article": ["headline", "datePublished", "author", "image"],
    "BlogPosting": ["headline", "datePublished", "author"],
    "Product": ["name", "image", "offers"],
    "BreadcrumbList": ["itemListElement"],
    "FAQPage": ["mainEntity"],
    "HowTo": ["name", "step"],
    "Event": ["name", "startDate", "location"],
    "LocalBusiness": ["name", "address"],
}

RECOMMENDED_PROPS = {
    "Organization": ["logo", "sameAs", "contactPoint", "address", "description"],
    "Person": ["jobTitle", "worksFor", "sameAs", "image", "url"],
    "WebSite": ["description", "potentialAction", "inLanguage"],
    "Article": ["description", "publisher", "mainEntityOfPage", "inLanguage"],
    "BlogPosting": ["description", "publisher", "mainEntityOfPage"],
    "Product": ["description", "brand", "aggregateRating", "review", "sku", "offers"],
    "BreadcrumbList": ["name", "item"],
    "FAQPage": ["name"],
    "HowTo": ["image", "description", "totalTime", "supply", "tool"],
    "Event": ["description", "image", "offers", "performer", "endAt"],
    "LocalBusiness": ["telephone", "openingHoursSpecification", "geo", "image", "priceRange"],
}

ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$")
URL_RE = re.compile(r"^https?://", re.IGNORECASE)


class Colors:
    def __init__(self, enabled=True):
        e = enabled
        self.reset = "\033[0m" if e else ""
        self.bold = "\033[1m" if e else ""
        self.dim = "\033[2m" if e else ""
        self.red = "\033[91m" if e else ""
        self.green = "\033[92m" if e else ""
        self.yellow = "\033[93m" if e else ""
        self.blue = "\033[94m" if e else ""
        self.magenta = "\033[95m" if e else ""
        self.cyan = "\033[96m" if e else ""
        self.white = "\033[97m" if e else ""
        self.bgblue = "\033[44m" if e else ""
        self.bgcyan = "\033[46m" if e else ""


def grade_for(score):
    if score >= 95:
        return "A+", "green"
    if score >= 90:
        return "A", "green"
    if score >= 75:
        return "B", "cyan"
    if score >= 60:
        return "C", "yellow"
    if score >= 40:
        return "D", "magenta"
    return "F", "red"


class SchemaAnalyzer:
    def __init__(self, url, timeout=15, verbose=False, color=True):
        self.url = url
        self.timeout = timeout
        self.verbose = verbose
        self.colors = Colors(color)
        self.color_enabled = color
        self.html = ""
        self.soup = None
        self.jsonld_scripts = []
        self.jsonld_parsed = []
        self.jsonld_errors = []
        self.microdata_items = []
        self.microdata_attrs = {"itemscope": 0, "itemprop": 0, "itemtype": 0}
        self.microdata_nested = 0
        self.rdfa_attrs = {"typeof": 0, "property": 0, "vocab": 0, "prefix": 0}
        self.schemas = []
        self.results = []
        self.issues = []
        self.total = 0
        self.max_total = 100
        self.letter = "F"
        self.letter_color = "red"
        self.fetched = False

    def c(self, name, text):
        color = getattr(self.colors, name, "")
        return f"{color}{text}{self.colors.reset}"

    def log(self, message):
        if self.verbose:
            print(self.c("dim", f"  [debug] {message}"))

    def fetch(self):
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; SchemaAnalyzer/1.0; +https://example.local)",
            "Accept": "text/html,application/xhtml+xml",
        }
        self.log(f"GET {self.url} timeout={self.timeout}")
        resp = requests.get(self.url, headers=headers, timeout=self.timeout)
        resp.raise_for_status()
        self.html = resp.text
        self.soup = BeautifulSoup(self.html, "html.parser")
        self.fetched = True
        self.log(f"fetched {len(self.html)} bytes")

    def extract_jsonld(self):
        scripts = self.soup.find_all("script", attrs={"type": lambda v: v and "ld+json" in v.lower()})
        self.jsonld_scripts = [s.string or s.get_text() or "" for s in scripts]
        self.log(f"found {len(self.jsonld_scripts)} JSON-LD script tags")
        for idx, raw in enumerate(self.jsonld_scripts):
            if not raw.strip():
                self.jsonld_errors.append(f"block {idx + 1}: empty")
                continue
            try:
                data = json.loads(raw)
                self.jsonld_parsed.append(data)
                self.log(f"block {idx + 1}: valid JSON")
            except json.JSONDecodeError as exc:
                self.jsonld_errors.append(f"block {idx + 1}: {exc}")
                self.log(f"block {idx + 1}: JSON error {exc}")

    @staticmethod
    def normalize_type(value):
        if isinstance(value, list):
            return [SchemaAnalyzer.normalize_type(v) for v in value]
        if not isinstance(value, str):
            return value
        value = value.strip()
        if value.startswith("http://schema.org/") or value.startswith("https://schema.org/"):
            return value.rsplit("/", 1)[-1]
        if value.startswith("schema:"):
            return value.split(":", 1)[1]
        return value

    @staticmethod
    def flatten_jsonld(data, out=None):
        if out is None:
            out = []
        if isinstance(data, list):
            for item in data:
                SchemaAnalyzer.flatten_jsonld(item, out)
        elif isinstance(data, dict):
            graph = data.get("@graph")
            if isinstance(graph, list):
                for item in graph:
                    SchemaAnalyzer.flatten_jsonld(item, out)
            else:
                out.append(data)
        return out

    def collect_schemas(self):
        for block in self.jsonld_parsed:
            for obj in self.flatten_jsonld(block):
                if not isinstance(obj, dict):
                    continue
                raw_type = obj.get("@type")
                norm = self.normalize_type(raw_type)
                types = norm if isinstance(norm, list) else [norm]
                types = [t for t in types if isinstance(t, str)]
                entry = {"type": types[0] if types else None, "types": types, "data": obj, "source": "jsonld"}
                self.schemas.append(entry)
        for item in self.microdata_items:
            if item.get("type"):
                self.schemas.append({"type": item["type"], "types": [item["type"]], "data": item.get("props", {}), "source": "microdata"})
        for item in self.rdfa_items if hasattr(self, "rdfa_items") else []:
            if item.get("type"):
                self.schemas.append({"type": item["type"], "types": [item["type"]], "data": item.get("props", {}), "source": "rdfa"})

    def extract_microdata(self):
        scopes = self.soup.find_all(attrs={"itemscope": True})
        self.microdata_attrs["itemscope"] = len(scopes)
        props = self.soup.find_all(attrs={"itemprop": True})
        self.microdata_attrs["itemprop"] = len(props)
        types = self.soup.find_all(attrs={"itemtype": True})
        self.microdata_attrs["itemtype"] = len(types)
        schema_typed = 0
        for el in types:
            itemtype = (el.get("itemtype") or "").strip()
            if "schema.org" in itemtype:
                schema_typed += 1
                normalized = itemtype.rstrip("/").rsplit("/", 1)[-1]
            else:
                normalized = None
            scope_el = el if el.has_attr("itemscope") else el.find_parent(attrs={"itemscope": True})
            prop_map = {}
            if scope_el is not None:
                for p in scope_el.find_all(attrs={"itemprop": True}):
                    name = p.get("itemprop")
                    value = p.get("content") or p.get("href") or p.get("src") or p.get_text(strip=True)
                    prop_map[name] = value
                if scope_el.find_all(attrs={"itemscope": True}):
                    self.microdata_nested += 1
            self.microdata_items.append({"type": normalized, "raw_type": itemtype, "props": prop_map})
        self.microdata_attrs["schema_itemtype"] = schema_typed
        self.log(f"microdata scopes={self.microdata_attrs['itemscope']} props={self.microdata_attrs['itemprop']} typed={schema_typed}")

    def extract_rdfa(self):
        typeofs = self.soup.find_all(attrs={"typeof": True})
        props = self.soup.find_all(attrs={"property": True})
        vocabs = self.soup.find_all(attrs={"vocab": True})
        prefixes = self.soup.find_all(attrs={"prefix": True})
        self.rdfa_attrs = {
            "typeof": len(typeofs),
            "property": len(props),
            "vocab": len(vocabs),
            "prefix": len(prefixes),
        }
        self.rdfa_items = []
        for el in typeofs:
            raw = (el.get("typeof") or "").strip()
            normalized = raw
            if "schema.org" in raw or raw.startswith("schema:"):
                normalized = raw.rstrip("/").rsplit("/", 1)[-1]
                if normalized.startswith("schema:"):
                    normalized = normalized.split(":", 1)[1]
            prop_map = {}
            for p in el.find_all(attrs={"property": True}):
                name = p.get("property")
                value = p.get("content") or p.get("href") or p.get("src") or p.get_text(strip=True)
                prop_map[name] = value
            self.rdfa_items.append({"type": normalized, "raw_type": raw, "props": prop_map})
        self.log(f"rdfa typeof={len(typeofs)} property={len(props)} vocab={len(vocabs)} prefix={len(prefixes)}")

    @staticmethod
    def is_valid_url_value(value):
        if isinstance(value, str):
            return bool(URL_RE.match(value.strip()))
        if isinstance(value, dict):
            u = value.get("url") or value.get("@id")
            return isinstance(u, str) and bool(URL_RE.match(u.strip()))
        if isinstance(value, list):
            return bool(value) and all(SchemaAnalyzer.is_valid_url_value(v) for v in value)
        return False

    @staticmethod
    def is_valid_image(value):
        if isinstance(value, str):
            return bool(URL_RE.match(value.strip())) or value.startswith("images/")
        if isinstance(value, dict):
            u = value.get("url") or value.get("@id") or value.get("contentUrl")
            return isinstance(u, str) and bool(URL_RE.match(u.strip()))
        if isinstance(value, list):
            return any(SchemaAnalyzer.is_valid_image(v) for v in value)
        return False

    @staticmethod
    def is_valid_date(value):
        if isinstance(value, str):
            return bool(ISO_RE.match(value.strip()))
        if isinstance(value, dict):
            return SchemaAnalyzer.is_valid_date(value.get("value") or value.get("@value") or "")
        return False

    @staticmethod
    def is_valid_date_time(value):
        if isinstance(value, str):
            v = value.strip()
            if ISO_RE.match(v):
                return True
            try:
                datetime.datetime.fromisoformat(v.replace("Z", "+00:00"))
                return True
            except ValueError:
                return False
        return False

    @staticmethod
    def has_schema_org_context(parsed_blocks):
        for block in parsed_blocks:
            ctx = None
            if isinstance(block, dict):
                ctx = block.get("@context")
            elif isinstance(block, list):
                for item in block:
                    if isinstance(item, dict) and item.get("@context"):
                        ctx = item.get("@context")
                        break
            if isinstance(ctx, str) and "schema.org" in ctx:
                return True
            if isinstance(ctx, list):
                for part in ctx:
                    if isinstance(part, str) and "schema.org" in part:
                        return True
                    if isinstance(part, dict):
                        for v in part.values():
                            if isinstance(v, str) and "schema.org" in v:
                                return True
        return False

    @staticmethod
    def context_uses_https(parsed_blocks):
        for block in parsed_blocks:
            if isinstance(block, dict):
                ctx = block.get("@context")
                if isinstance(ctx, str) and ctx.startswith("https://schema.org"):
                    return True
                if isinstance(ctx, list):
                    for part in ctx:
                        if isinstance(part, str) and part.startswith("https://schema.org"):
                            return True
        return False

    @staticmethod
    def walk_types(node, found):
        if isinstance(node, dict):
            raw = node.get("@type")
            if raw is not None:
                norm = SchemaAnalyzer.normalize_type(raw)
                for t in (norm if isinstance(norm, list) else [norm]):
                    if isinstance(t, str) and t:
                        found.add(t)
            for v in node.values():
                SchemaAnalyzer.walk_types(v, found)
        elif isinstance(node, list):
            for v in node:
                SchemaAnalyzer.walk_types(v, found)

    def present_types(self):
        found = set()
        for entry in self.schemas:
            for t in entry.get("types") or []:
                if t:
                    found.add(t)
            if entry.get("type"):
                found.add(entry["type"])
            self.walk_types(entry.get("data"), found)
        for block in self.jsonld_parsed:
            self.walk_types(block, found)
        for item in self.microdata_items:
            if item.get("type"):
                found.add(item["type"])
            self.walk_types(item.get("props"), found)
        for item in getattr(self, "rdfa_items", []):
            if item.get("type"):
                found.add(item["type"])
        return found

    def schemas_of_type(self, type_name):
        out = []
        for entry in self.schemas:
            types = entry.get("types") or []
            if type_name in types or entry.get("type") == type_name:
                out.append(entry)
        for item in self.microdata_items:
            if item.get("type") == type_name:
                out.append({"type": type_name, "types": [type_name], "data": item.get("props", {}), "source": "microdata"})
        return out

    def add_result(self, category, name, score, max_score, details, issues=None):
        issues = issues or []
        entry = {
            "category": category,
            "name": name,
            "score": round(float(score), 2),
            "max": max_score,
            "percent": round(100.0 * float(score) / max_score, 1) if max_score else 0.0,
            "details": details,
            "issues": issues,
        }
        self.results.append(entry)
        self.issues.extend(issues)
        return entry

    def check_jsonld(self):
        details = []
        issues = []
        score = 0
        count = len(self.jsonld_scripts)
        if count > 0:
            score += 4
            details.append(f"Found {count} JSON-LD script block(s)")
        else:
            issues.append({"category": "JSON-LD", "severity": "high", "message": "No <script type=\"application/ld+json\"> blocks found", "remediation": "Add a JSON-LD block in the page head with schema.org markup"})
        valid = len(self.jsonld_parsed)
        if count > 0 and valid > 0:
            score += 4
            details.append(f"{valid}/{count} block(s) parse as valid JSON")
        if count > 0 and self.jsonld_errors:
            for err in self.jsonld_errors:
                issues.append({"category": "JSON-LD", "severity": "high", "message": f"Invalid JSON in {err}", "remediation": "Fix JSON syntax (trailing commas, unquoted keys, single quotes)"})
        elif count > 0 and valid == count:
            details.append("All JSON-LD blocks are parseable")
        if self.has_schema_org_context(self.jsonld_parsed):
            score += 3
            details.append("@context references schema.org")
        elif count > 0:
            issues.append({"category": "JSON-LD", "severity": "high", "message": "@context does not reference schema.org", "remediation": "Set \"@context\": \"https://schema.org\" on every JSON-LD object"})
        has_type = any(isinstance(b, dict) and b.get("@type") for b in self.jsonld_parsed)
        if has_type:
            score += 2
            types = sorted(self.present_types())
            details.append("@" + "type detected: " + (", ".join(types) if types else "present"))
        elif count > 0:
            issues.append({"category": "JSON-LD", "severity": "medium", "message": "@type missing on JSON-LD objects", "remediation": "Add \"@type\" (e.g. Organization, WebSite, Article) to each entity"})
        if count > 1:
            score += 2
            details.append("Multiple JSON-LD blocks handled correctly")
        elif count == 1:
            score += 1
            details.append("Single JSON-LD block detected")
        self.add_result("jsonld", "JSON-LD Detection", min(score, 15), 15, details, issues)

    def check_microdata(self):
        details = []
        issues = []
        score = 0
        md = self.microdata_attrs
        if md["itemscope"] > 0:
            score += 3
            details.append(f"itemscope found on {md['itemscope']} element(s)")
        if md["itemprop"] > 0:
            score += 3
            details.append(f"itemprop found on {md['itemprop']} element(s)")
        if md.get("schema_itemtype", 0) > 0:
            score += 2
            details.append(f"itemtype with schema.org URL on {md['schema_itemtype']} element(s)")
        elif md["itemtype"] > 0:
            details.append("itemtype present but not schema.org URLs")
            issues.append({"category": "Microdata", "severity": "medium", "message": "itemtype values are not schema.org URLs", "remediation": "Use full URLs like https://schema.org/Organization"})
        if self.microdata_nested > 0:
            score += 2
            details.append(f"Nested microdata detected ({self.microdata_nested} nested scope(s))")
        if md["itemscope"] == 0 and md["itemprop"] == 0:
            details.append("No Microdata markers found on page")
            issues.append({"category": "Microdata", "severity": "low", "message": "No Microdata (itemscope/itemprop) markup detected", "remediation": "Prefer JSON-LD; add Microdata only if legacy consumers require it"})
        self.add_result("microdata", "Microdata Detection", min(score, 10), 10, details, issues)

    def check_rdfa(self):
        details = []
        issues = []
        score = 0
        rd = self.rdfa_attrs
        if rd["typeof"] > 0:
            score += 2
            details.append(f"typeof found on {rd['typeof']} element(s)")
        if rd["property"] > 0:
            score += 1
            details.append(f"property found on {rd['property']} element(s)")
        if rd["vocab"] > 0:
            score += 1
            details.append(f"vocab found on {rd['vocab']} element(s)")
        if rd["prefix"] > 0:
            score += 1
            details.append(f"prefix found on {rd['prefix']} element(s)")
        if rd["typeof"] == 0 and rd["property"] == 0:
            details.append("No RDFa markers found on page")
            issues.append({"category": "RDFa", "severity": "low", "message": "No RDFa (typeof/property) markup detected", "remediation": "Add RDFa only if required; JSON-LD is preferred for most sites"})
        self.add_result("rdfa", "RDFa Detection", min(score, 5), 5, details, issues)

    def check_types(self):
        details = []
        issues = []
        found = self.present_types()
        matched = []
        for t in DETECTABLE_TYPES:
            if t in found or (t == "Article" and "BlogPosting" in found):
                matched.append(t)
        per = 15.0 / len(DETECTABLE_TYPES)
        score = per * len(matched)
        if matched:
            details.append("Detected: " + ", ".join(matched))
        missing = [t for t in DETECTABLE_TYPES if t not in matched]
        if missing:
            details.append("Not detected: " + ", ".join(missing))
            issues.append({"category": "Schema Types", "severity": "medium", "message": "Missing common schema types: " + ", ".join(missing), "remediation": "Add the types relevant to your pages (e.g. Organization + WebSite on every page)"})
        if not matched:
            issues.append({"category": "Schema Types", "severity": "high", "message": "No common schema.org types detected", "remediation": "Implement at least Organization and WebSite JSON-LD"})
        self.add_result("types", "Common Schema Types", round(min(score, 15), 2), 15, details, issues)

    def check_validation(self):
        details = []
        issues = []
        schema_objs = [e for e in self.schemas if e.get("type")]
        if not schema_objs:
            issues.append({"category": "Validation", "severity": "high", "message": "No typed schema objects available for validation", "remediation": "Add JSON-LD objects with @type and @context"})
            self.add_result("validation", "Schema Validation", 0, 15, ["Skipped: no typed schemas"], issues)
            return
        req_total = 0
        req_ok = 0
        for entry in schema_objs:
            for t in entry.get("types") or []:
                required = REQUIRED_PROPS.get(t, [])
                if not required:
                    continue
                data = entry.get("data") or {}
                for rp in required:
                    req_total += 1
                    value = data.get(rp)
                    if value not in (None, "", [], {}):
                        req_ok += 1
                    else:
                        issues.append({"category": "Validation", "severity": "high", "message": f"{t}: missing required property '{rp}'", "remediation": f"Add '{rp}' to the {t} entity"})
        req_ratio = (req_ok / req_total) if req_total else 0.0
        score = 5 * req_ratio
        details.append(f"Required properties: {req_ok}/{req_total} present ({round(req_ratio * 100)}%)")
        type_checks = 0
        type_ok = 0
        url_checks = 0
        url_ok = 0
        date_checks = 0
        date_ok = 0
        img_checks = 0
        img_ok = 0
        url_keys = {"url", "sameAs", "mainEntityOfPage", "item", "target", "contentUrl", "@id"}
        date_keys = {"datePublished", "dateModified", "startDate", "endDate", "foundingDate", "birthDate", "deathDate", "validFrom", "validThrough"}
        for entry in schema_objs:
            data = entry.get("data") or {}
            t = entry.get("type") or "Thing"
            for key, value in data.items():
                if key.startswith("@"):
                    continue
                if key in ("name", "description", "headline", "sku", "priceCurrency", "telephone"):
                    type_checks += 1
                    if isinstance(value, (str, int, float)) or (isinstance(value, list) and all(isinstance(v, (str, dict)) for v in value)):
                        type_ok += 1
                    else:
                        issues.append({"category": "Validation", "severity": "medium", "message": f"{t}.{key} has unexpected type {type(value).__name__}", "remediation": f"Use a string value for {key}"})
                if key in url_keys:
                    url_checks += 1
                    if self.is_valid_url_value(value):
                        url_ok += 1
                    else:
                        issues.append({"category": "Validation", "severity": "medium", "message": f"{t}.{key} is not an absolute http(s) URL", "remediation": f"Use an absolute URL starting with https:// for {key}"})
                if key in date_keys:
                    date_checks += 1
                    if self.is_valid_date(value) or self.is_valid_date_time(value):
                        date_ok += 1
                    else:
                        issues.append({"category": "Validation", "severity": "medium", "message": f"{t}.{key} is not ISO 8601 (got {value!r})", "remediation": "Use ISO 8601, e.g. 2026-01-15 or 2026-01-15T10:00:00Z"})
                if key == "image":
                    img_checks += 1
                    if self.is_valid_image(value):
                        img_ok += 1
                    else:
                        issues.append({"category": "Validation", "severity": "medium", "message": f"{t}.image URL is invalid or relative", "remediation": "Provide an absolute image URL or ImageObject with url"})
        type_ratio = (type_ok / type_checks) if type_checks else 1.0
        url_ratio = (url_ok / url_checks) if url_checks else 1.0
        date_ratio = (date_ok / date_checks) if date_checks else 1.0
        img_ratio = (img_ok / img_checks) if img_checks else 1.0
        score += 3 * type_ratio
        score += 3 * url_ratio
        score += 2 * date_ratio
        score += 2 * img_ratio
        details.append(f"Property type checks: {type_ok}/{type_checks}")
        details.append(f"Absolute URL checks: {url_ok}/{url_checks}")
        details.append(f"ISO 8601 date checks: {date_ok}/{date_checks}")
        details.append(f"Image URL checks: {img_ok}/{img_checks}")
        self.add_result("validation", "Schema Validation", round(min(score, 15), 2), 15, details, issues)

    def check_rich_snippets(self):
        details = []
        issues = []
        score = 0
        found = self.present_types()
        org_ok = False
        for entry in self.schemas_of_type("Organization"):
            data = entry.get("data") or {}
            if data.get("name") and (data.get("url") or data.get("logo")):
                org_ok = True
                break
        website_ok = any((e.get("data") or {}).get("name") for e in self.schemas_of_type("WebSite"))
        product_ok = any((e.get("data") or {}).get("offers") for e in self.schemas_of_type("Product"))
        article_ok = any((e.get("data") or {}).get("datePublished") for e in self.schemas_of_type("Article") + self.schemas_of_type("BlogPosting"))
        search_ok = org_ok or website_ok or product_ok or article_ok
        if search_ok:
            score += 4
            details.append("Eligible for search rich results (Organization/WebSite/Product/Article signals present)")
        else:
            issues.append({"category": "Rich Snippets", "severity": "high", "message": "Insufficient signals for search rich result eligibility", "remediation": "Add Organization + WebSite JSON-LD with name, url, logo"})
        faq_ok = bool(self.schemas_of_type("FAQPage"))
        howto_ok = bool(self.schemas_of_type("HowTo"))
        if faq_ok or howto_ok:
            score += 3
            details.append("Featured snippet potential: " + ("FAQPage" if faq_ok else "") + (" and " if faq_ok and howto_ok else "") + ("HowTo" if howto_ok else ""))
        else:
            details.append("No FAQPage/HowTo found for featured snippet potential")
            issues.append({"category": "Rich Snippets", "severity": "low", "message": "No FAQPage or HowTo schema for featured snippets", "remediation": "Add FAQPage or HowTo markup on relevant pages"})
        kp_score = 0
        if org_ok:
            kp_score += 1
            for entry in self.schemas_of_type("Organization"):
                data = entry.get("data") or {}
                if data.get("sameAs"):
                    kp_score += 1
                if data.get("logo") or data.get("image"):
                    kp_score += 1
                break
        score += min(kp_score, 3)
        if kp_score >= 2:
            details.append("Knowledge panel signals: Organization identity present")
        else:
            details.append("Weak knowledge panel signals")
            issues.append({"category": "Rich Snippets", "severity": "medium", "message": "Knowledge panel signals weak (missing sameAs/logo)", "remediation": "Add sameAs social/Wikidata links and a logo to Organization"})
        self.add_result("rich_snippets", "Rich Snippet Potential", round(min(score, 10), 2), 10, details, issues)

    def check_completeness(self):
        details = []
        issues = []
        schema_objs = [e for e in self.schemas if e.get("type")]
        if not schema_objs:
            issues.append({"category": "Completeness", "severity": "high", "message": "No schemas to measure completeness", "remediation": "Implement schema.org JSON-LD entities"})
            self.add_result("completeness", "Structured Data Completeness", 0, 10, ["Skipped: no schemas"], issues)
            return
        req_total = 0
        req_hit = 0
        rec_total = 0
        rec_hit = 0
        opt_used = 0
        for entry in schema_objs:
            data = entry.get("data") or {}
            keys = set(data.keys())
            for t in entry.get("types") or []:
                for rp in REQUIRED_PROPS.get(t, []):
                    req_total += 1
                    if rp in keys and data.get(rp) not in (None, "", [], {}):
                        req_hit += 1
                known = set(REQUIRED_PROPS.get(t, [])) | set(RECOMMENDED_PROPS.get(t, []))
                for rp in RECOMMENDED_PROPS.get(t, []):
                    rec_total += 1
                    if rp in keys and data.get(rp) not in (None, "", [], {}):
                        rec_hit += 1
                extra = [k for k in keys if not k.startswith("@") and k not in known]
                if extra:
                    opt_used += len(extra)
        req_ratio = (req_hit / req_total) if req_total else 0.0
        rec_ratio = (rec_hit / rec_total) if rec_total else 0.0
        opt_score = min(opt_used / 5.0, 1.0)
        score = 5 * req_ratio + 3 * rec_ratio + 2 * opt_score
        details.append(f"Required field coverage: {req_hit}/{req_total} ({round(req_ratio * 100)}%)")
        details.append(f"Recommended field coverage: {rec_hit}/{rec_total} ({round(rec_ratio * 100)}%)")
        details.append(f"Optional property usage: {opt_used} extra propert(ies)")
        if req_ratio < 1.0:
            issues.append({"category": "Completeness", "severity": "medium", "message": "Required field coverage below 100%", "remediation": "Fill all required properties for each implemented type"})
        if rec_ratio < 0.5:
            issues.append({"category": "Completeness", "severity": "low", "message": "Recommended fields largely unused", "remediation": "Add recommended properties (logo, sameAs, description, image)"})
        self.add_result("completeness", "Structured Data Completeness", round(min(score, 10), 2), 10, details, issues)

    def check_version(self):
        details = []
        issues = []
        score = 0
        if self.context_uses_https(self.jsonld_parsed):
            score += 2
            details.append("@context uses https://schema.org")
        elif self.has_schema_org_context(self.jsonld_parsed):
            score += 1
            details.append("@context uses schema.org over http (prefer https)")
            issues.append({"category": "Version", "severity": "low", "message": "schema.org context loaded over http", "remediation": "Use \"@context\": \"https://schema.org\""})
        else:
            details.append("No schema.org @context detected")
        if not self.schemas:
            details.append("No schema objects present to evaluate vocabulary currency")
            issues.append({"category": "Version", "severity": "medium", "message": "No schema.org vocabulary found", "remediation": "Add JSON-LD with \"@context\": \"https://schema.org\""})
            self.add_result("version", "Schema.org Version", 0, 5, details, issues)
            return
        deprecated_found = []
        new_found = []
        for entry in self.schemas:
            data = entry.get("data") or {}
            for key in data.keys():
                if key in DEPRECATED_PROPERTIES:
                    deprecated_found.append(key)
                if key in NEW_PROPERTIES:
                    new_found.append(key)
        if not deprecated_found:
            score += 2
            details.append("No deprecated properties in use")
        else:
            uniq = sorted(set(deprecated_found))
            issues.append({"category": "Version", "severity": "medium", "message": "Deprecated property usage: " + ", ".join(uniq), "remediation": "Replace deprecated properties with current schema.org equivalents"})
            details.append("Deprecated: " + ", ".join(uniq))
        if new_found:
            score += 1
            details.append("Modern property adoption: " + ", ".join(sorted(set(new_found))))
        else:
            details.append("No newer schema.org properties (e.g. foundingDate, slogan) detected")
        if self.jsonld_parsed:
            details.append("Vocabulary: schema.org (living standard, no fixed version number)")
        self.add_result("version", "Schema.org Version", round(min(score, 5), 2), 5, details, issues)

    def check_multi_format(self):
        details = []
        issues = []
        formats = []
        if self.jsonld_scripts:
            formats.append("JSON-LD")
        if self.microdata_attrs["itemscope"] > 0:
            formats.append("Microdata")
        if self.rdfa_attrs["typeof"] > 0:
            formats.append("RDFa")
        diversity = len(formats)
        score = (diversity / 3.0) * 5 if diversity else 0
        if formats:
            details.append("Formats detected: " + ", ".join(formats))
        else:
            details.append("No structured data formats detected")
            issues.append({"category": "Multi-Format", "severity": "high", "message": "No structured data format detected", "remediation": "Implement JSON-LD first"})
        type_sets = {}
        if self.jsonld_parsed:
            type_sets["JSON-LD"] = {t for t in self.present_types() if t}
        md_types = {i["type"] for i in self.microdata_items if i.get("type")}
        if md_types:
            type_sets["Microdata"] = md_types
        rd_types = {i["type"] for i in getattr(self, "rdfa_items", []) if i.get("type")}
        if rd_types:
            type_sets["RDFa"] = rd_types
        conflicts = []
        if len(type_sets) > 1:
            keys = list(type_sets.keys())
            for i in range(len(keys)):
                for j in range(i + 1, len(keys)):
                    a = type_sets[keys[i]]
                    b = type_sets[keys[j]]
                    if a and b and a != b and not (a & b):
                        conflicts.append(f"{keys[i]} vs {keys[j]}: disjoint types")
            if conflicts:
                issues.append({"category": "Multi-Format", "severity": "medium", "message": "Format conflicts: " + "; ".join(conflicts), "remediation": "Keep one primary format (JSON-LD) to avoid conflicting entity signals"})
                score += 0
                details.append("Conflicts: " + "; ".join(conflicts))
            else:
                score += 3
                details.append("Format consistency: overlapping/no conflicting types")
        elif len(type_sets) == 1:
            score += 3
            details.append("Single format in use; no internal conflicts")
        else:
            details.append("No typed formats to compare for consistency")
        self.add_result("multi_format", "Multi-Format Detection", round(min(score, 10), 2), 10, details, issues)

    def check_entities(self):
        details = []
        issues = []
        score = 0
        same_as = []
        for entry in self.schemas:
            data = entry.get("data") or {}
            val = data.get("sameAs")
            if isinstance(val, str):
                same_as.append(val)
            elif isinstance(val, list):
                same_as.extend([v for v in val if isinstance(v, str)])
        for item in self.microdata_items:
            val = (item.get("props") or {}).get("sameAs")
            if isinstance(val, str):
                same_as.append(val)
        same_as = list(dict.fromkeys(same_as))
        if same_as:
            score += 2
            details.append(f"sameAs links found: {len(same_as)}")
        else:
            issues.append({"category": "Entities", "severity": "medium", "message": "No sameAs links found", "remediation": "Add sameAs to Organization pointing at social profiles and Wikidata"})
        social_hosts = ["facebook.com", "twitter.com", "x.com", "linkedin.com", "instagram.com", "youtube.com", "github.com", "pinterest.com"]
        wikidata = [u for u in same_as if "wikidata.org" in u]
        socials = [u for u in same_as if any(h in u for h in social_hosts)]
        if wikidata:
            score += 1
            details.append("Wikidata entity linked")
        if socials:
            score += 1
            details.append(f"Social profile links: {len(socials)}")
        if not wikidata and not socials and same_as:
            details.append("sameAs present but no Wikidata/social profiles recognized")
        elif not wikidata:
            issues.append({"category": "Entities", "severity": "low", "message": "No Wikidata QID in sameAs", "remediation": "Link your Organization to its Wikidata item via sameAs"})
        org = None
        for entry in self.schemas_of_type("Organization"):
            org = entry.get("data") or {}
            break
        connectivity = 0
        if org:
            if org.get("url"):
                connectivity += 1
            if org.get("logo") or org.get("image"):
                connectivity += 1
            if org.get("sameAs"):
                connectivity += 1
            if org.get("identifier") or org.get("@id"):
                connectivity += 1
        score += min(connectivity, 1) if connectivity >= 2 else 0
        if connectivity >= 2:
            details.append("Knowledge graph connectivity: Organization has identity fields (url/logo/sameAs)")
        else:
            details.append("Weak knowledge graph connectivity")
            details.append(f"Entity identity signals: {connectivity}/4")
        self.add_result("entities", "Entity Linking", round(min(score, 5), 2), 5, details, issues)

    def analyze(self):
        self.fetch()
        self.extract_jsonld()
        self.extract_microdata()
        self.extract_rdfa()
        self.collect_schemas()
        self.check_jsonld()
        self.check_microdata()
        self.check_rdfa()
        self.check_types()
        self.check_validation()
        self.check_rich_snippets()
        self.check_completeness()
        self.check_version()
        self.check_multi_format()
        self.check_entities()
        self.total = round(sum(r["score"] for r in self.results), 2)
        self.letter, self.letter_color = grade_for(self.total)
        return self

    def summary_dict(self):
        return {
            "tool": "SchemaAnalyzer",
            "version": VERSION,
            "url": self.url,
            "generated_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_score": self.total,
            "max_score": self.max_total,
            "grade": self.letter,
            "categories": self.results,
            "schema_types": sorted(t for t in self.present_types() if t),
            "format_counts": {
                "jsonld_blocks": len(self.jsonld_scripts),
                "jsonld_valid": len(self.jsonld_parsed),
                "microdata_items": len(self.microdata_items),
                "rdfa_items": len(getattr(self, "rdfa_items", [])),
            },
            "issues": self.issues,
        }

    def print_report(self):
        c = self.colors
        print()
        print(f"{c.bgblue}{c.bold}{c.white}  SchemaAnalyzer v{VERSION} — Analysis Report  {c.reset}")
        print(f"  Target: {self.c('cyan', self.url)}")
        print()
        header = f"  {'Category':<32}{'Score':>10}{'/Max':>7}{'%':>7}  {'Grade bar'}"
        print(self.c("bold", header))
        print("  " + "-" * 78)
        for r in self.results:
            bar_len = 20
            filled = int(round((r["score"] / r["max"]) * bar_len)) if r["max"] else 0
            bar = "#" * filled + "-" * (bar_len - filled)
            pct = r["percent"]
            if pct >= 90:
                color = "green"
            elif pct >= 70:
                color = "cyan"
            elif pct >= 50:
                color = "yellow"
            else:
                color = "red"
            line = f"  {r['name']:<32}{r['score']:>10.2f}{r['max']:>7}{pct:>6.1f}%  "
            print(line + self.c(color, f"[{bar}]"))
        print("  " + "-" * 78)
        grade_txt = self.c(self.letter_color, f"{self.letter}")
        print(f"  {'TOTAL':<32}{self.total:>10.2f}{self.max_total:>7}{100.0 * self.total / self.max_total:>6.1f}%  Grade: {grade_txt}")
        print()
        print(self.c("bold", "  Schema Type Inventory"))
        types = sorted(t for t in self.present_types() if t)
        if types:
            print("    " + ", ".join(self.c("magenta", t) for t in types))
        else:
            print("    " + self.c("red", "No schema types detected"))
        fmt = self.summary_dict()["format_counts"]
        print(f"    JSON-LD blocks: {fmt['jsonld_blocks']} (valid: {fmt['jsonld_valid']}) | Microdata items: {fmt['microdata_items']} | RDFa items: {fmt['rdfa_items']}")
        print()
        print(self.c("bold", "  Validation Issues & Remediation"))
        if not self.issues:
            print("    " + self.c("green", "No issues detected."))
        else:
            order = {"high": 0, "medium": 1, "low": 2}
            for issue in sorted(self.issues, key=lambda i: order.get(i.get("severity"), 3)):
                sev = issue.get("severity", "low")
                sev_color = {"high": "red", "medium": "yellow", "low": "cyan"}.get(sev, "white")
                print(f"    [{self.c(sev_color, sev.upper()):}] {issue['category']}: {issue['message']}")
                print(f"        -> {self.c('green', issue['remediation'])}")
        print()
        print(self.c("bold", "  Rich Snippet Potential Assessment"))
        rs = next((r for r in self.results if r["category"] == "rich_snippets"), None)
        if rs:
            for d in rs["details"]:
                print(f"    - {d}")
            pct_txt = f"{rs['percent']:.0f}%"
            print(f"    Assessment: {self.c(self.letter_color, pct_txt)} of rich snippet potential")
        print()
        print(self.c("bold", "  Category Details"))
        for r in self.results:
            print(f"    {self.c('blue', r['name'])} ({r['score']}/{r['max']})")
            for d in r["details"]:
                print(f"      - {d}")
        print()

    def export(self, fmt):
        if fmt == "none":
            return []
        written = []
        base = "schemaanalyzer_report"
        if fmt in ("json", "all"):
            path = f"{base}.json"
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(self.summary_dict(), fh, indent=2, ensure_ascii=False)
            written.append(path)
        if fmt in ("csv", "all"):
            path = f"{base}.csv"
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["category", "name", "score", "max", "percent"])
            for r in self.results:
                writer.writerow([r["category"], r["name"], r["score"], r["max"], r["percent"]])
            writer.writerow(["total", "TOTAL", self.total, self.max_total, round(100.0 * self.total / self.max_total, 2)])
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(buf.getvalue())
            written.append(path)
        if fmt in ("html", "all"):
            path = f"{base}.html"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.render_html())
            written.append(path)
        return written

    def render_html(self):
        data = self.summary_dict()
        rows = []
        for r in data["categories"]:
            pct = r["percent"]
            if pct >= 90:
                color = "#3ddc97"
            elif pct >= 70:
                color = "#4cc9f0"
            elif pct >= 50:
                color = "#f4d35e"
            else:
                color = "#f25f5c"
            rows.append(
                "<tr><td>" + r["name"] + "</td>"
                + "<td class='num'>" + str(r["score"]) + "</td>"
                + "<td class='num'>" + str(r["max"]) + "</td>"
                + "<td class='num'>" + str(r["percent"]) + "%</td>"
                + "<td><div class='bar'><span style=\"width:" + str(pct) + "%;background:" + color + "\"></span></div></td></tr>"
            )
        type_list = ", ".join(data["schema_types"]) if data["schema_types"] else "None"
        issue_html = []
        if data["issues"]:
            for issue in data["issues"]:
                sev = issue.get("severity", "low")
                issue_html.append(
                    "<div class='issue " + sev + "'><strong>[" + sev.upper() + "] " + issue["category"] + "</strong>: "
                    + issue["message"] + "<br><span class='fix'>Fix: " + issue["remediation"] + "</span></div>"
                )
        else:
            issue_html.append("<div class='issue ok'>No issues detected.</div>")
        grade_color = {"A+": "#3ddc97", "A": "#3ddc97", "B": "#4cc9f0", "C": "#f4d35e", "D": "#f09c2c", "F": "#f25f5c"}.get(data["grade"], "#ffffff")
        css = """
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #0d1117; color: #e6edf3; font-family: 'Segoe UI', system-ui, sans-serif; padding: 40px 24px; line-height: 1.5; }
    .wrap { max-width: 960px; margin: 0 auto; }
    header { border-bottom: 1px solid #30363d; padding-bottom: 24px; margin-bottom: 28px; }
    h1 { font-size: 1.6rem; font-weight: 650; letter-spacing: -0.02em; }
    h1 span { color: #58a6ff; }
    .meta { color: #8b949e; font-size: 0.9rem; margin-top: 6px; }
    .scorebox { display: flex; gap: 32px; align-items: center; margin: 24px 0 32px; flex-wrap: wrap; }
    .bigscore { font-size: 3.2rem; font-weight: 700; }
    .biggrade { font-size: 2rem; font-weight: 700; }
    h2 { font-size: 1.1rem; margin: 32px 0 14px; color: #79c0ff; font-weight: 600; }
    table { width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }
    th, td { padding: 10px 14px; text-align: left; font-size: 0.92rem; border-bottom: 1px solid #21262d; }
    th { background: #21262d; color: #8b949e; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.04em; }
    tr:last-child td { border-bottom: none; }
    td.num { text-align: right; font-variant-numeric: tabular-nums; }
    .bar { background: #21262d; height: 8px; border-radius: 4px; overflow: hidden; min-width: 120px; }
    .bar span { display: block; height: 100%; border-radius: 4px; }
    .issue { background: #161b22; border-left: 3px solid #f25f5c; padding: 12px 16px; margin-bottom: 10px; border-radius: 0 6px 6px 0; font-size: 0.9rem; }
    .issue.medium { border-left-color: #f4d35e; }
    .issue.low { border-left-color: #4cc9f0; }
    .issue.ok { border-left-color: #3ddc97; }
    .fix { color: #8b949e; font-size: 0.85rem; }
    .types { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px 18px; font-size: 0.95rem; }
    .types strong { color: #d2a8ff; }
    footer { margin-top: 40px; color: #484f58; font-size: 0.8rem; border-top: 1px solid #21262d; padding-top: 16px; }
    """
        html = (
            "<!DOCTYPE html>\n<html lang='en'>\n<head>\n<meta charset='utf-8'>\n"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
            "<title>SchemaAnalyzer Report</title>\n<style>" + css + "</style>\n</head>\n<body>\n"
            "<div class='wrap'>\n<header>\n<h1><span>SchemaAnalyzer</span> v" + VERSION + " — Structured Data Report</h1>\n"
            "<div class='meta'>Target: " + data["url"] + "<br>Generated: " + data["generated_at"] + "</div>\n</header>\n"
            "<div class='scorebox'>\n"
            "<div><div class='meta'>Total score</div><div class='bigscore' style='color:" + grade_color + "'>" + str(data["total_score"]) + "<span style='font-size:1.2rem;color:#8b949e'>/" + str(data["max_score"]) + "</span></div></div>\n"
            "<div><div class='meta'>Grade</div><div class='biggrade' style='color:" + grade_color + "'>" + data["grade"] + "</div></div>\n"
            "</div>\n"
            "<h2>Category Breakdown</h2>\n<table>\n<thead><tr><th>Category</th><th class='num'>Score</th><th class='num'>Max</th><th class='num'>%</th><th>Progress</th></tr></thead>\n<tbody>\n"
            + "\n".join(rows)
            + "\n</tbody>\n</table>\n"
            "<h2>Schema Type Inventory</h2>\n<div class='types'><strong>" + type_list + "</strong></div>\n"
            "<h2>Validation Issues &amp; Remediation</h2>\n" + "\n".join(issue_html) + "\n"
            "<footer>Generated by SchemaAnalyzer v" + VERSION + "</footer>\n</div>\n</body>\n</html>"
        )
        return html


def build_parser():
    parser = argparse.ArgumentParser(
        prog="SchemaAnalyzer",
        description="SchemaAnalyzer v1.0 — deep-analyze schema.org structured data (JSON-LD, Microdata, RDFa).",
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL to analyze")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--export", choices=["all", "json", "csv", "html", "none"], default="none", help="Export format (default: none)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    return parser


def main():
    args = build_parser().parse_args()
    color = not args.no_color
    colors = Colors(color)
    print(f"{colors.bgblue}{colors.bold}{colors.white} {VERSION} SchemaAnalyzer — schema.org structured data deep analysis {colors.reset}")
    print(colors.dim(BANNER))
    if not args.url.lower().startswith(("http://", "https://")):
        args.url = "https://" + args.url
    analyzer = SchemaAnalyzer(url=args.url, timeout=args.timeout, verbose=args.verbose, color=color)
    try:
        analyzer.analyze()
    except requests.exceptions.RequestException as exc:
        print(f"{colors.red}[error]{colors.reset} Failed to fetch URL: {exc}")
        sys.exit(2)
    except Exception as exc:
        print(f"{colors.red}[error]{colors.reset} Analysis failed: {exc}")
        if args.verbose:
            raise
        sys.exit(1)
    analyzer.print_report()
    if args.export != "none":
        paths = analyzer.export(args.export)
        for p in paths:
            print(f"{colors.green}[export]{colors.reset} Wrote {p}")
    sys.exit(0 if analyzer.total >= 60 else 1)


if __name__ == "__main__":
    main()
