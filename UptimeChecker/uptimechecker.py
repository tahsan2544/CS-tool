#!/usr/bin/env python3
import sys
import os
import argparse
import time
import socket
import ssl
import json
import csv
import statistics
import random
import subprocess
import re
import struct
import hashlib
import base64
import textwrap
import math
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    os.system(sys.executable + " -m pip install requests -q")
    import requests

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
except ImportError:
    os.system(sys.executable + " -m pip install rich -q")
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box

VERSION = "7.0"
console = Console()

BANNER = r"""
[bold cyan]
   __                __            __         __   ____      __
  / /_  ____  ____  / /____  _____/ /_  ___  / /_ / __ \____/ /_
 / __ \/ __ \/ __ \/ __/ _ \/ ___/ __ \/ _ \/ __// / / / __  / _ \
/ /_/ / /_/ / / / / /_/  __/ /__/ / / /  __/ /_ / /_/ / /_/ /  __/
\____/ .___/_/ /_/\__/\___/\___/_/ /_/\___/\__/ \____/\__,_/\___/
    /_/
[/bold cyan][bold white]v{version}[/bold white]""".format(version=VERSION)

HELP_TEXT = """[bold cyan]UptimeChecker v{version}[/bold cyan] \u2014 Multi-protocol uptime, DNS, SSL & network monitor with multi-region, SLO/error-budget, incident ops, predictive analytics, RUM, A/B & feature-flag monitoring, dependency chains, incident automation, ROI analysis, service dependency mapping, cascading failure detection, maintenance windows, alert fatigue reduction & on-call simulation

[bold white]Usage:[/bold white]
  python uptimechecker.py -u <url> [options]
  python uptimechecker.py --tcp host:port [options]
  python uptimechecker.py --smtp host [options]
  python uptimechecker.py --ftp host [options]
  python uptimechecker.py --ssh host [options]
  python uptimechecker.py --ping host [options]
  python uptimechecker.py --dns hostname [options]

[bold white]Examples:[/bold white]
  python uptimechecker.py -u https://example.com
  python uptimechecker.py -u https://example.com -c 5 -i 2
  python uptimechecker.py -u https://api.example.com/health --export json
  python uptimechecker.py -u https://example.com --extended-checks
  python uptimechecker.py -u https://example.com --sla-target 99.99
  python uptimechecker.py -u https://example.com --multi-region
  python uptimechecker.py -u https://example.com --multi-region --regions us-east-1,eu-west-1
  python uptimechecker.py -u https://example.com --analytics
  python uptimechecker.py -u https://example.com --analytics --exec-summary
  python uptimechecker.py -u https://example.com --slo-target 99.95 --slo-period 30
  python uptimechecker.py -u https://example.com --full-report --postmortem
  python uptimechecker.py -u https://example.com --deep-dive
  python uptimechecker.py --tcp example.com:443 -c 3
  python uptimechecker.py --smtp mail.example.com --port 587
  python uptimechecker.py --ftp ftp.example.com
  python uptimechecker.py --ssh example.com -p 22
  python uptimechecker.py --ping 8.8.8.8 -c 5
  python uptimechecker.py --dns example.com --dns-record A
  python uptimechecker.py -u https://example.com --webhook https://hooks.slack.com/xxx
  python uptimechecker.py -u https://example.com --health-endpoint /api/health
  python uptimechecker.py -u https://example.com --rum --ab-test --feature-flags
  python uptimechecker.py -u https://example.com --dependency-chain --incident-automation
  python uptimechecker.py -u https://example.com --stakeholders oncall,manager --roi
  python uptimechecker.py -u https://example.com --synthetic-journey
  python uptimechecker.py -u https://example.com --full-report --incident-automation --roi
  python uptimechecker.py -u https://example.com --service-map
  python uptimechecker.py -u https://example.com --cascade-detect
  python uptimechecker.py -u https://example.com --maintenance-window 02:00-04:00
  python uptimechecker.py -u https://example.com --alert-fatigue --oncall-sim
  python uptimechecker.py -u https://example.com --full-report --service-map --cascade-detect --alert-fatigue --oncall-sim
""".format(version=VERSION)

DNS_SERVERS = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
    "Level3": "4.2.2.1",
}

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA", "PTR"]

REGIONS = {
    "us-east-1": {"name": "US East (Virginia)", "dns": "8.8.8.8", "offset_h": -5, "lat": 37.4, "lon": -79.4},
    "us-west-2": {"name": "US West (Oregon)", "dns": "8.8.4.4", "offset_h": -8, "lat": 45.5, "lon": -122.7},
    "eu-west-1": {"name": "EU West (Ireland)", "dns": "1.1.1.1", "offset_h": 0, "lat": 53.3, "lon": -6.3},
    "eu-central-1": {"name": "EU Central (Frankfurt)", "dns": "9.9.9.9", "offset_h": 1, "lat": 50.1, "lon": 8.7},
    "ap-southeast-1": {"name": "Asia Pacific (Singapore)", "dns": "101.6.6.6", "offset_h": 8, "lat": 1.3, "lon": 103.8},
    "ap-northeast-1": {"name": "Asia Pacific (Tokyo)", "dns": "168.126.63.1", "offset_h": 9, "lat": 35.7, "lon": 139.7},
    "sa-east-1": {"name": "South America (Sao Paulo)", "dns": "200.160.0.8", "offset_h": -3, "lat": -23.5, "lon": -46.6},
    "ap-south-1": {"name": "Asia Pacific (Mumbai)", "dns": "49.36.128.100", "offset_h": 5.5, "lat": 19.1, "lon": 72.9},
}

CDN_SIGNATURES = {
    "Cloudflare": {"headers": ["cf-ray", "cf-cache-status", "cf-connecting-ip"], "cookies": ["__cflb", "__cfuid"]},
    "Akamai": {"headers": ["x-akamai-transformed", "x-akamai-request-id"], "cookies": []},
    "Fastly": {"headers": ["x-fastly-request-id", "x-served-by", "x-cache-hits"], "cookies": []},
    "Amazon CloudFront": {"headers": ["x-amz-cf-id", "x-amz-cf-pop"], "cookies": []},
    "KeyCDN": {"headers": ["x-ks-client-id"], "cookies": []},
    "StackPath": {"headers": ["x-hw", "x-spx"], "cookies": []},
    "Incapsula/Imperva": {"headers": ["x-iinfo", "x-cdn"], "cookies": ["incap_ses", "visid_incap"]},
    "Sucuri": {"headers": ["x-sucuri-id", "x-sucuri-cache"], "cookies": []},
}

LB_SIGNATURES = {
    "AWS ALB/NLB": {"cookies": ["AWSALB", "AWSALBTG", "AWSALBCORS"], "headers": ["x-amzn-trace-id", "x-amzn-requestid"]},
    "F5 BIG-IP": {"cookies": ["BIGipServer", "TS0"], "headers": []},
    "HAProxy": {"cookies": ["SERVERID", "haproxy"], "headers": []},
    "Nginx Upstream": {"cookies": ["route"], "headers": []},
    "Envoy": {"headers": ["x-envoy-upstream-service-time"], "cookies": []},
    "Google Cloud LB": {"headers": ["x-cloud-trace-context"], "cookies": []},
}

TECH_PATTERNS = {
    "Apache": {"server": ["Apache"]},
    "Nginx": {"server": ["nginx"]},
    "IIS": {"server": ["Microsoft-IIS"]},
    "LiteSpeed": {"server": ["LiteSpeed"]},
    "Caddy": {"server": ["Caddy"]},
    "Node.js": {"x-powered-by": ["Express", "Node.js"]},
    "PHP": {"x-powered-by": ["PHP"]},
    "ASP.NET": {"x-powered-by": ["ASP.NET"]},
    "Python": {"x-powered-by": ["Python"]},
    "Ruby": {"x-powered-by": ["Phusion Passenger", "Ruby"]},
}

FRONTEND_TECH = {
    "React": ["react", "__NEXT_DATA__", "_next/static"],
    "Vue.js": ["vue.js", "vue.min.js", "vue.runtime"],
    "Angular": ["ng-version", "angular.js", "angular.min.js"],
    "Next.js": ["__NEXT_DATA__", "_next/static", "next.js"],
    "Nuxt.js": ["__nuxt", "_nuxt/", "nuxt.js"],
    "WordPress": ["wp-content", "wp-includes", "wordpress"],
    "Drupal": ["drupal.js", "drupal.min.js", "sites/default/files"],
    "Joomla": ["joomla", "com_content"],
}


class CircuitBreaker:
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

    def __init__(self, failure_threshold=5, recovery_timeout=60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.state = self.CLOSED
        self.last_failure_time = None

    def record_success(self):
        self.failure_count = 0
        self.state = self.CLOSED

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = self.OPEN

    def can_execute(self):
        if self.state == self.CLOSED:
            return True
        if self.state == self.OPEN:
            if self.last_failure_time is not None:
                if time.time() - self.last_failure_time >= self.recovery_timeout:
                    self.state = self.HALF_OPEN
                    return True
            return False
        return True


class Incident:
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"

    def __init__(self, start_time, reason):
        self.start_time = start_time
        self.end_time = None
        self.reason = reason
        self.failures = 1
        self.status = "OPEN"
        self.root_cause = self._guess_root_cause(reason)
        self.root_cause_category = self._categorize_root_cause(reason)
        self.severity = self._classify_severity(reason)
        self.group_id = None
        self.resolution_notes = ""
        self.resolved_by = "auto"
        self.impact_checks_total = 0
        self.impact_checks_failed = 0

    def _guess_root_cause(self, reason):
        reason_lower = reason.lower().replace("_", " ")
        if "timeout" in reason_lower:
            return "Server overload or network latency"
        elif "connection" in reason_lower:
            return "Service crash or firewall change"
        elif "503" in reason_lower or "502" in reason_lower:
            return "Backend service failure"
        elif "dns" in reason_lower:
            return "DNS misconfiguration or propagation delay"
        elif "ssl" in reason_lower or "certificate" in reason_lower:
            return "Certificate expiry or misconfiguration"
        elif "redirect" in reason_lower:
            return "Redirect loop detected"
        elif "smtp" in reason_lower:
            return "Mail server unreachable"
        elif "ftp" in reason_lower:
            return "FTP service failure"
        elif "ssh" in reason_lower:
            return "SSH daemon not responding"
        return "Unknown root cause"

    def _categorize_root_cause(self, reason):
        reason_lower = reason.lower().replace("_", " ")
        categories = {
            "network": ["timeout", "connection", "dns", "resolve"],
            "server": ["503", "502", "500", "error", "crash"],
            "certificate": ["ssl", "certificate", "tls"],
            "configuration": ["redirect", "loop", "misconfiguration"],
            "service": ["smtp", "ftp", "ssh", "unreachable"],
        }
        for category, keywords in categories.items():
            for kw in keywords:
                if kw in reason_lower:
                    return category
        return "unknown"

    def _classify_severity(self, reason):
        reason_lower = reason.lower().replace("_", " ")
        if any(kw in reason_lower for kw in ["timeout", "connection refused", "503", "502", "unreachable"]):
            return self.SEVERITY_CRITICAL
        elif any(kw in reason_lower for kw in ["500", "error", "crash"]):
            return self.SEVERITY_HIGH
        elif any(kw in reason_lower for kw in ["slow", "degraded", "redirect"]):
            return self.SEVERITY_MEDIUM
        return self.SEVERITY_LOW

    def update_impact(self, total_checks, failed_checks):
        self.impact_checks_total = total_checks
        self.impact_checks_failed = failed_checks

    def get_impact_score(self):
        if self.impact_checks_total == 0:
            return 0
        return round((self.impact_checks_failed / self.impact_checks_total) * 100, 1)

    def close(self, end_time):
        self.end_time = end_time
        self.status = "RESOLVED"

    def duration(self):
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time

    def to_dict(self):
        start_str = datetime.fromtimestamp(self.start_time).strftime("%Y-%m-%d %H:%M:%S")
        if self.end_time:
            end_str = datetime.fromtimestamp(self.end_time).strftime("%Y-%m-%d %H:%M:%S")
        else:
            end_str = "Ongoing"
        return {
            "start": start_str,
            "end": end_str,
            "reason": self.reason,
            "root_cause": self.root_cause,
            "root_cause_category": self.root_cause_category,
            "severity": self.severity,
            "group_id": self.group_id,
            "failures": self.failures,
            "status": self.status,
            "duration_seconds": round(self.duration(), 1),
            "impact_score": self.get_impact_score(),
            "impact_checks_failed": self.impact_checks_failed,
            "impact_checks_total": self.impact_checks_total,
            "resolution_notes": self.resolution_notes,
            "resolved_by": self.resolved_by,
        }


class IncidentTracker:
    def __init__(self):
        self.incidents = []
        self.current_incident = None
        self.group_counter = 0

    def start_incident(self, timestamp, reason):
        if self.current_incident is None:
            self.current_incident = Incident(timestamp, reason)
            self.group_counter += 1
            self.current_incident.group_id = "INC-" + str(self.group_counter).zfill(4)

    def end_incident(self, timestamp):
        if self.current_incident is not None:
            self.current_incident.close(timestamp)
            self.incidents.append(self.current_incident)
            self.current_incident = None

    def add_failure(self):
        if self.current_incident is not None:
            self.current_incident.failures += 1

    def get_open_incident(self):
        return self.current_incident

    def to_list(self):
        result = [inc.to_dict() for inc in self.incidents]
        if self.current_incident:
            result.append(self.current_incident.to_dict())
        return result

    def group_by_root_cause(self):
        groups = {}
        all_incidents = list(self.incidents)
        if self.current_incident:
            all_incidents.append(self.current_incident)
        for inc in all_incidents:
            cat = inc.root_cause_category
            if cat not in groups:
                groups[cat] = []
            groups[cat].append(inc.to_dict())
        return groups

    def group_by_severity(self):
        groups = {}
        all_incidents = list(self.incidents)
        if self.current_incident:
            all_incidents.append(self.current_incident)
        for inc in all_incidents:
            sev = inc.severity
            if sev not in groups:
                groups[sev] = []
            groups[sev].append(inc.to_dict())
        return groups

    def get_resolution_stats(self):
        resolved = [inc for inc in self.incidents if inc.status == "RESOLVED"]
        if not resolved:
            return {"avg_resolution_time": 0, "total_resolved": 0, "total_open": len(self.incidents)}
        durations = [inc.duration() for inc in resolved]
        return {
            "avg_resolution_time": statistics.mean(durations),
            "total_resolved": len(resolved),
            "total_open": len([inc for inc in self.incidents if inc.status != "RESOLVED"]),
        }


class DNSRecordStore:
    def __init__(self, filepath=None):
        if filepath is None:
            filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dns_records.json")
        self.filepath = filepath
        self.records = self._load()

    def _load(self):
        try:
            with open(self.filepath, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save(self):
        with open(self.filepath, "w") as f:
            json.dump(self.records, f, indent=2, default=str)

    def update(self, hostname, record_type, values):
        key = hostname + ":" + record_type
        old = self.records.get(key, {})
        old_values = old.get("values", [])
        changed = set(values) != set(old_values) if old_values else False
        self.records[key] = {
            "values": values,
            "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "previous": old_values if changed else old.get("previous", []),
            "change_count": old.get("change_count", 0) + (1 if changed and old_values else 0),
        }
        self.save()
        return changed, old_values

    def get_history(self, hostname, record_type):
        key = hostname + ":" + record_type
        return self.records.get(key, {})


class MultiRegionMonitor:
    def __init__(self, hostname, protocol="http", timeout=10, target_url=None):
        self.hostname = hostname
        self.protocol = protocol
        self.timeout = timeout
        self.target_url = target_url
        self.region_results = {}

    def check_all_regions(self, regions=None):
        if regions is None:
            regions = list(REGIONS.keys())
        for region_id in regions:
            if region_id not in REGIONS:
                continue
            region = REGIONS[region_id]
            self.region_results[region_id] = self._check_region(region_id, region)
        return self.region_results

    def _check_region(self, region_id, region):
        result = {
            "region_id": region_id,
            "region_name": region["name"],
            "dns_server": region["dns"],
            "dns_resolution_ms": -1,
            "dns_resolved": False,
            "dns_records": [],
            "tcp_reachable": False,
            "tcp_response_ms": -1,
            "http_available": False,
            "http_response_ms": -1,
            "http_status": 0,
            "error": None,
        }
        start = time.time()
        try:
            proc = subprocess.run(
                ["dig", "@" + region["dns"], "+short", self.hostname],
                capture_output=True, text=True, timeout=self.timeout
            )
            elapsed = (time.time() - start) * 1000
            records = [l.strip() for l in proc.stdout.strip().split("\n") if l.strip()]
            result["dns_resolution_ms"] = round(elapsed, 1)
            result["dns_resolved"] = len(records) > 0
            result["dns_records"] = records[:5]
        except Exception as e:
            result["error"] = "DNS: " + str(e)[:60]
            return result

        if result["dns_records"]:
            target_ip = result["dns_records"][0]
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                tcp_start = time.time()
                sock.connect((target_ip, 80 if self.protocol == "http" else 443))
                tcp_elapsed = (time.time() - tcp_start) * 1000
                result["tcp_reachable"] = True
                result["tcp_response_ms"] = round(tcp_elapsed, 1)
                sock.close()
            except Exception:
                pass

            if self.protocol == "http" and self.target_url:
                try:
                    http_start = time.time()
                    resp = requests.get(
                        self.target_url,
                        timeout=self.timeout,
                        headers={"User-Agent": "UptimeChecker/" + VERSION + " (region:" + region_id + ")"},
                        allow_redirects=True
                    )
                    http_elapsed = (time.time() - http_start) * 1000
                    result["http_available"] = 200 <= resp.status_code < 400
                    result["http_response_ms"] = round(http_elapsed, 1)
                    result["http_status"] = resp.status_code
                except Exception:
                    pass
        return result

    def get_availability_scores(self):
        scores = {}
        for region_id, result in self.region_results.items():
            score = 0
            if result["dns_resolved"]:
                score += 30
            if result["tcp_reachable"]:
                score += 30
            if result["http_available"]:
                score += 40
            elif result["http_status"] > 0:
                score += 10
            scores[region_id] = score
        return scores

    def get_latency_comparison(self):
        comparison = {}
        for region_id, result in self.region_results.items():
            latencies = {}
            if result["dns_resolution_ms"] >= 0:
                latencies["dns"] = result["dns_resolution_ms"]
            if result["tcp_response_ms"] >= 0:
                latencies["tcp"] = result["tcp_response_ms"]
            if result["http_response_ms"] >= 0:
                latencies["http"] = result["http_response_ms"]
            total = sum(latencies.values())
            latencies["total"] = round(total, 1)
            comparison[region_id] = latencies
        return comparison

    def get_cdn_edge_comparison(self):
        edges = {}
        for region_id, result in self.region_results.items():
            if result["http_response_ms"] >= 0:
                edges[region_id] = {
                    "region_name": REGIONS[region_id]["name"],
                    "response_ms": result["http_response_ms"],
                    "available": result["http_available"],
                }
        return edges

    def get_summary(self):
        scores = self.get_availability_scores()
        latencies = self.get_latency_comparison()
        if not self.region_results:
            return {"total_regions": 0, "available_regions": 0, "avg_latency": 0, "score": 0}
        available = sum(1 for s in scores.values() if s >= 80)
        http_latencies = [latencies[rid].get("http", 0) for rid in latencies if latencies[rid].get("http", 0) > 0]
        avg_latency = statistics.mean(http_latencies) if http_latencies else 0
        overall_score = statistics.mean(scores.values()) if scores else 0
        return {
            "total_regions": len(self.region_results),
            "available_regions": available,
            "avg_latency": round(avg_latency, 1),
            "score": round(overall_score, 1),
        }


class AdvancedAnalytics:
    def __init__(self, results, sla_target=99.9):
        self.results = results
        self.sla_target = sla_target

    def uptime_trend_analysis(self):
        if len(self.results) < 2:
            return {"trend": "insufficient_data", "windows": [], "total_checks": len(self.results)}
        statuses = []
        for r in self.results:
            sc = r.get("status", {}).get("status_code", 0)
            statuses.append(1 if 200 <= sc < 400 else 0)
        window_size = max(1, len(statuses) // 5) if len(statuses) >= 5 else 1
        windows = []
        for i in range(0, len(statuses), window_size):
            chunk = statuses[i:i + window_size]
            uptime = (sum(chunk) / len(chunk)) * 100 if chunk else 0
            windows.append(round(uptime, 2))
        if len(windows) >= 2:
            recent = windows[-1]
            earlier = windows[0]
            diff = recent - earlier
            if diff > 5:
                trend = "improving"
            elif diff < -5:
                trend = "degrading"
            else:
                trend = "stable"
        else:
            trend = "stable"
        return {"trend": trend, "windows": windows, "total_checks": len(self.results)}

    def detect_performance_regression(self):
        times = [r.get("timing", {}).get("total", 0) for r in self.results if r.get("timing", {}).get("total", 0) > 0]
        if len(times) < 3:
            return {"regression_detected": False, "reason": "insufficient_data", "slope": 0, "confidence": 0}
        n = len(times)
        x_vals = list(range(n))
        x_mean = statistics.mean(x_vals)
        y_mean = statistics.mean(times)
        num = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_vals, times))
        den = sum((x - x_mean) ** 2 for x in x_vals)
        slope = num / den if den != 0 else 0
        y_var = sum((y - y_mean) ** 2 for y in times)
        if y_var == 0:
            r_squared = 0
        else:
            ss_res = sum((y - (slope * x + y_mean - slope * x_mean)) ** 2 for x, y in zip(x_vals, times))
            r_squared = 1 - (ss_res / y_var)
        confidence = round(r_squared * 100, 1)
        regression = slope > 50 and confidence > 50
        if regression:
            reason = "Response times increasing by {:.1f}ms per check (confidence: {:.0f}%)".format(slope, confidence)
        elif slope < -50 and confidence > 50:
            reason = "Response times improving by {:.1f}ms per check (confidence: {:.0f}%)".format(abs(slope), confidence)
        else:
            reason = "No significant regression detected"
        return {
            "regression_detected": regression,
            "slope": round(slope, 2),
            "confidence": confidence,
            "reason": reason,
            "avg_response": round(y_mean, 1),
        }

    def detect_anomalies(self):
        times = [r.get("timing", {}).get("total", 0) for r in self.results if r.get("timing", {}).get("total", 0) > 0]
        if len(times) < 3:
            return {"anomalies": [], "count": 0, "mean": 0, "stdev": 0}
        mean = statistics.mean(times)
        stdev = statistics.stdev(times) if len(times) > 1 else 0
        if stdev == 0:
            return {"anomalies": [], "count": 0, "mean": round(mean, 1), "stdev": 0}
        anomalies = []
        for i, r in enumerate(self.results):
            t = r.get("timing", {}).get("total", 0)
            if t <= 0:
                continue
            z_score = (t - mean) / stdev
            if abs(z_score) > 2.0:
                anomalies.append({
                    "index": i + 1,
                    "timestamp": r.get("timestamp", ""),
                    "response_ms": round(t, 1),
                    "z_score": round(z_score, 2),
                    "type": "slow" if z_score > 0 else "fast",
                })
        return {"anomalies": anomalies, "count": len(anomalies), "mean": round(mean, 1), "stdev": round(stdev, 1)}

    def capacity_planning_hints(self):
        times = [r.get("timing", {}).get("total", 0) for r in self.results if r.get("timing", {}).get("total", 0) > 0]
        if len(times) < 2:
            return {"hints": ["Collect more data points for capacity planning"], "avg_ms": 0, "p95_ms": 0, "max_ms": 0}
        mean = statistics.mean(times)
        max_time = max(times)
        p95 = EnhancedStats.percentile(times, 95)
        hints = []
        if mean > 2000:
            hints.append("Average response time ({:.0f}ms) exceeds 2s threshold".format(mean))
        if max_time > mean * 3:
            hints.append("Peak response time ({:.0f}ms) is {:.1f}x the average".format(max_time, max_time / mean))
        if p95 > 3000:
            hints.append("P95 latency ({:.0f}ms) indicates capacity issues under load".format(p95))
        n = len(times)
        if n >= 4:
            first_half = times[:n // 2]
            second_half = times[n // 2:]
            avg_first = statistics.mean(first_half)
            avg_second = statistics.mean(second_half)
            growth = ((avg_second - avg_first) / avg_first) * 100 if avg_first > 0 else 0
            if growth > 20:
                hints.append("Response times growing {:.0f}% between halves - consider scaling".format(growth))
        if not hints:
            hints.append("Current capacity appears adequate")
        return {"hints": hints, "avg_ms": round(mean, 1), "p95_ms": round(p95, 1), "max_ms": round(max_time, 1)}

    def scale_recommendation(self, headroom_target_pct=30):
        times = [r.get("timing", {}).get("total", 0) for r in self.results if r.get("timing", {}).get("total", 0) > 0]
        if len(times) < 2:
            return {"action": "insufficient_data", "confidence": 0,
                    "target_capacity_ms": 0, "current_p95_ms": 0, "rationale": "Need more samples"}
        p95 = EnhancedStats.percentile(times, 95)
        target_capacity = p95 * (1 + headroom_target_pct / 100.0)
        n = len(times)
        x_vals = list(range(n))
        x_mean = statistics.mean(x_vals)
        y_mean = statistics.mean(times)
        den = sum((x - x_mean) ** 2 for x in x_vals)
        slope = (sum((x - x_mean) * (y - y_mean) for x, y in zip(x_vals, times)) / den) if den else 0.0
        if slope > 50 and p95 > 2000:
            action = "SCALE_OUT"
            rationale = "P95 {:.0f}ms with rising slope {:.1f}ms/check - add capacity now".format(p95, slope)
            confidence = min(95, 50 + slope)
        elif p95 > 3000:
            action = "SCALE_OUT"
            rationale = "P95 {:.0f}ms exceeds 3s - capacity constrained".format(p95)
            confidence = 80
        elif slope < -50:
            action = "SCALE_IN_CANDIDATE"
            rationale = "Latency improving ({:.1f}ms/check) - evaluate scale-in during low traffic".format(slope)
            confidence = 60
        elif p95 < 500:
            action = "HOLD_OR_SCALE_IN"
            rationale = "P95 {:.0f}ms well within budget - over-provisioning possible".format(p95)
            confidence = 70
        else:
            action = "HOLD"
            rationale = "P95 {:.0f}ms stable - current capacity adequate".format(p95)
            confidence = 65
        return {
            "action": action,
            "confidence": round(confidence, 1),
            "target_capacity_ms": round(target_capacity, 1),
            "current_p95_ms": round(p95, 1),
            "slope_ms_per_check": round(slope, 2),
            "headroom_target_pct": headroom_target_pct,
            "rationale": rationale,
        }

    def sla_breach_prediction(self):
        statuses = [1 if 200 <= r.get("status", {}).get("status_code", 0) < 400 else 0 for r in self.results]
        if len(statuses) < 2:
            return {"will_breach": False, "confidence": 0, "reason": "insufficient_data",
                    "current_uptime": 0, "projected_uptime": 0, "slope": 0, "sla_target": self.sla_target}
        current_uptime = (sum(statuses) / len(statuses)) * 100
        n = len(statuses)
        x_vals = list(range(n))
        x_mean = statistics.mean(x_vals)
        y_mean = statistics.mean(statuses)
        num = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_vals, statuses))
        den = sum((x - x_mean) ** 2 for x in x_vals)
        slope = num / den if den != 0 else 0
        projected_checks = max(10, n)
        future_statuses = list(statuses)
        for i in range(projected_checks):
            next_val = y_mean + slope * (n + i)
            future_statuses.append(max(0, min(1, next_val)))
        projected_uptime = (sum(future_statuses) / len(future_statuses)) * 100
        will_breach = projected_uptime < self.sla_target
        if slope < -0.01:
            confidence = min(95, 50 + abs(slope) * 500)
            reason = "Uptime trend declining ({:.2f}%/check)".format(slope * 100)
        elif current_uptime < self.sla_target:
            confidence = 80
            reason = "Current uptime ({:.2f}%) below SLA target ({:.3f}%)".format(current_uptime, self.sla_target)
        else:
            confidence = max(10, 60 - abs(slope) * 200)
            reason = "Uptime stable or improving"
        return {
            "will_breach": will_breach,
            "current_uptime": round(current_uptime, 2),
            "projected_uptime": round(projected_uptime, 2),
            "slope": round(slope * 100, 4),
            "confidence": round(confidence, 1),
            "reason": reason,
            "sla_target": self.sla_target,
        }

    def predictive_refinement(self):
        base = self.sla_breach_prediction()
        regression = self.detect_performance_regression()
        anomalies = self.detect_anomalies()
        risk_score = 0.0
        factors = []
        if base.get("will_breach"):
            risk_score += 40
            factors.append("SLA breach projected at {:.2f}%".format(base.get("projected_uptime", 0)))
        if regression.get("regression_detected"):
            risk_score += 25
            factors.append("Performance regression contributing to risk")
        if anomalies.get("count", 0) >= 3:
            risk_score += 15
            factors.append("{} latency anomalies inflate uncertainty".format(anomalies.get("count", 0)))
        if base.get("slope", 0) < -0.5:
            risk_score += 20
            factors.append("Steep uptime decline slope")
        risk_score = min(100.0, risk_score)
        if risk_score >= 70:
            band = "SEVERE"
        elif risk_score >= 45:
            band = "ELEVATED"
        elif risk_score >= 20:
            band = "GUARDED"
        else:
            band = "STABLE"
        if not factors:
            factors.append("No compounding predictive signals detected")
        return {
            "risk_score": round(risk_score, 1),
            "risk_band": band,
            "factors": factors,
            "base_will_breach": base.get("will_breach", False),
            "regression_active": regression.get("regression_detected", False),
            "anomaly_count": anomalies.get("count", 0),
            "confidence": base.get("confidence", 0),
        }

    def capacity_planning_refinement(self):
        times = [r.get("timing", {}).get("total", 0) for r in self.results
                 if r.get("timing", {}).get("total", 0) > 0]
        if len(times) < 3:
            return {"available": False, "note": "Need at least 3 latency samples",
                    "headroom_pct": 0, "projected_headroom_pct": 0,
                    "recommendations": ["Collect more data for refined capacity planning"]}
        p50 = EnhancedStats.percentile(times, 50)
        p95 = EnhancedStats.percentile(times, 95)
        p99 = EnhancedStats.percentile(times, 99)
        n = len(times)
        x_vals = list(range(n))
        x_mean = statistics.mean(x_vals)
        y_mean = statistics.mean(times)
        den = sum((x - x_mean) ** 2 for x in x_vals)
        slope = (sum((x - x_mean) * (y - y_mean) for x, y in zip(x_vals, times)) / den) if den else 0.0
        budget_ms = max(p95 * 1.5, 1000.0)
        headroom_pct = max(0.0, ((budget_ms - p95) / budget_ms) * 100.0)
        projected_p95 = p95 + slope * max(10, n // 2)
        projected_headroom = max(0.0, ((budget_ms - projected_p95) / budget_ms) * 100.0)
        recommendations = []
        if headroom_pct < 20:
            recommendations.append("Less than 20% headroom at P95 - scale out before next peak")
        if projected_headroom < headroom_pct - 10:
            recommendations.append("Headroom shrinking under current latency trend - plan capacity add")
        if p99 > p95 * 2:
            recommendations.append("P99 is {:.1f}x P95 - investigate tail latency before adding capacity".format(p99 / max(p95, 1)))
        if slope < -10:
            recommendations.append("Latency improving - consider deferred capacity spend")
        if not recommendations:
            recommendations.append("Capacity posture healthy at current load")
        if projected_headroom >= 40:
            posture = "COMFORTABLE"
        elif projected_headroom >= 20:
            posture = "ADEQUATE"
        else:
            posture = "TIGHT"
        return {
            "available": True,
            "p50_ms": round(p50, 1),
            "p95_ms": round(p95, 1),
            "p99_ms": round(p99, 1),
            "slope_ms_per_check": round(slope, 2),
            "budget_ms": round(budget_ms, 1),
            "headroom_pct": round(headroom_pct, 1),
            "projected_headroom_pct": round(projected_headroom, 1),
            "posture": posture,
            "recommendations": recommendations,
        }


class EnhancedStats:
    @staticmethod
    def percentile(times, p):
        if not times:
            return 0.0
        sorted_times = sorted(times)
        k = (len(sorted_times) - 1) * (p / 100.0)
        f = int(k)
        c = f + 1
        if c >= len(sorted_times):
            return sorted_times[-1]
        d = k - f
        return sorted_times[f] + d * (sorted_times[c] - sorted_times[f])

    @staticmethod
    def response_percentiles(times):
        if not times:
            return {"p50": 0, "p90": 0, "p95": 0, "p99": 0}
        return {
            "p50": EnhancedStats.percentile(times, 50),
            "p90": EnhancedStats.percentile(times, 90),
            "p95": EnhancedStats.percentile(times, 95),
            "p99": EnhancedStats.percentile(times, 99),
        }

    @staticmethod
    def calculate_mtbf(results):
        if len(results) < 2:
            return None
        failure_indices = []
        for i, r in enumerate(results):
            is_failure = r.get("status", {}).get("status_code", 0) >= 500 or r.get("error")
            if is_failure:
                failure_indices.append(i)
        if len(failure_indices) < 2:
            return None
        intervals = [failure_indices[i + 1] - failure_indices[i] for i in range(len(failure_indices) - 1)]
        return statistics.mean(intervals) if intervals else None

    @staticmethod
    def calculate_mttr(results):
        if len(results) < 2:
            return None
        recovery_times = []
        in_failure = False
        failure_start = 0
        for i, r in enumerate(results):
            is_failure = r.get("status", {}).get("status_code", 0) >= 500 or r.get("error")
            if is_failure and not in_failure:
                in_failure = True
                failure_start = i
            elif not is_failure and in_failure:
                recovery_times.append(i - failure_start)
                in_failure = False
        return statistics.mean(recovery_times) if recovery_times else None

    @staticmethod
    def error_rate(results):
        if not results:
            return 0.0
        errors = sum(1 for r in results if r.get("status", {}).get("status_code", 0) >= 400 or r.get("error"))
        return (errors / len(results)) * 100

    @staticmethod
    def response_time_trend(results):
        times = [r.get("timing", {}).get("total", 0) for r in results if r.get("timing", {}).get("total", 0) > 0]
        if len(times) < 2:
            return 0.0
        n = len(times)
        x_vals = list(range(n))
        x_mean = statistics.mean(x_vals)
        y_mean = statistics.mean(times)
        num = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_vals, times))
        den = sum((x - x_mean) ** 2 for x in x_vals)
        return num / den if den != 0 else 0.0

    @staticmethod
    def error_rate_trend(results):
        if not results:
            return []
        cumulative = []
        errors = 0
        for i, r in enumerate(results, 1):
            if r.get("status", {}).get("status_code", 0) >= 400 or r.get("error"):
                errors += 1
            cumulative.append((errors / i) * 100)
        return cumulative

    @staticmethod
    def sla_compliance(uptime_pct, target=99.9):
        if uptime_pct >= target:
            return True, "COMPLIANT"
        return False, "NON-COMPLIANT"

    @staticmethod
    def format_sla_uptime(uptime_pct):
        if uptime_pct >= 99.999:
            return "99.999% (five nines)"
        elif uptime_pct >= 99.99:
            return "99.99% (four nines)"
        elif uptime_pct >= 99.9:
            return "99.9% (three nines)"
        elif uptime_pct >= 99:
            return "99% (two nines)"
        else:
            return "{:.4f}%".format(uptime_pct)


class SLOTracker:
    def __init__(self, slo_target=99.9, period_days=30):
        self.slo_target = slo_target
        self.period_days = period_days

    def evaluate(self, results, interval_seconds=5):
        period_minutes = self.period_days * 24 * 60
        allowed = period_minutes * (1 - self.slo_target / 100.0)
        budget = {
            "allowed_minutes": round(allowed, 2),
            "consumed_minutes": 0.0,
            "remaining_minutes": round(allowed, 2),
            "consumed_pct": 0.0,
            "status": "NO_DATA",
        }
        if not results:
            return {
                "slo_target": self.slo_target,
                "period_days": self.period_days,
                "actual_uptime": 0.0,
                "met": False,
                "elapsed_minutes": 0.0,
                "error_budget": budget,
                "burn_rate": 0.0,
                "projected_exhaustion_minutes": None,
            }
        successes = 0
        for r in results:
            sc = r.get("status", {}).get("status_code", 0)
            if 200 <= sc < 400 and not r.get("error"):
                successes += 1
        actual = (successes / len(results)) * 100.0
        elapsed = (len(results) * max(interval_seconds, 1)) / 60.0
        observed_fraction = 1 - (actual / 100.0)
        allowed_fraction = 1 - (self.slo_target / 100.0)
        consumed = elapsed * observed_fraction
        remaining = max(0.0, allowed - consumed)
        consumed_pct = (consumed / allowed) * 100.0 if allowed > 0 else 100.0
        consumed_pct = min(consumed_pct, 100.0)
        burn = 0.0
        if allowed_fraction > 0:
            burn = observed_fraction / allowed_fraction
        if remaining <= 0:
            status = "EXHAUSTED"
        elif burn >= 10 or consumed_pct >= 75:
            status = "CRITICAL"
        elif burn >= 2 or consumed_pct >= 50:
            status = "WARNING"
        else:
            status = "OK"
        projection = None
        if remaining <= 0:
            projection = 0.0
        elif observed_fraction > 0 and elapsed > 0:
            projection = remaining / observed_fraction
        budget = {
            "allowed_minutes": round(allowed, 2),
            "consumed_minutes": round(consumed, 2),
            "remaining_minutes": round(remaining, 2),
            "consumed_pct": round(consumed_pct, 2),
            "status": status,
        }
        return {
            "slo_target": self.slo_target,
            "period_days": self.period_days,
            "actual_uptime": round(actual, 4),
            "met": actual >= self.slo_target,
            "elapsed_minutes": round(elapsed, 2),
            "error_budget": budget,
            "burn_rate": round(burn, 3),
            "projected_exhaustion_minutes": round(projection, 1) if projection is not None else None,
        }


class CostOptimizer:
    def __init__(self, interval=5, count=1, multi_region=False, extended_checks=False):
        self.interval = interval
        self.count = count
        self.multi_region = multi_region
        self.extended_checks = extended_checks

    def analyze(self, stats, slo=None):
        hints = []
        checks_per_day = 86400.0 / max(self.interval, 1)
        monthly_checks = checks_per_day * 30
        avg_ms = stats.get("avg_time", 0)
        p95 = stats.get("percentiles", {}).get("p95", 0)
        error_rate = stats.get("error_rate", 0)
        if error_rate < 0.5 and p95 < 1000:
            hints.append("Stable latency and low error rate - consider a longer check interval to reduce probe volume")
        if error_rate > 5:
            hints.append("High error rate ({:.1f}%) - fix reliability before scaling capacity to avoid wasted spend".format(error_rate))
        if avg_ms > 2000:
            hints.append("Slow average response ({:.0f}ms) - caching or CDN offload could cut origin load and cost".format(avg_ms))
        if p95 > 0 and p95 < 300:
            hints.append("P95 latency ({:.0f}ms) is far under common thresholds - capacity may be over-provisioned".format(p95))
        if self.multi_region:
            hints.append("Multi-region probing active - disable regions that are not earning their monitoring cost")
        if self.extended_checks:
            hints.append("Extended checks enabled - schedule deep scans periodically instead of running them every check")
        if slo and not slo.get("met", True):
            hints.append("SLO not met - prioritize reliability investment over cost reduction this period")
        if not hints:
            hints.append("Probe configuration appears cost-efficient for current reliability needs")
        efficiency = 100.0
        if error_rate > 0:
            efficiency = max(0.0, 100.0 - error_rate * 5)
        waste_score = 0.0
        if p95 > 0 and p95 < 300:
            waste_score += 30
        if error_rate < 0.5:
            waste_score += 20
        if self.multi_region:
            waste_score += 15
        if self.extended_checks:
            waste_score += 15
        if self.interval < 5:
            waste_score += 20
        waste_score = min(100.0, waste_score)
        recommended_interval = self.interval
        if error_rate < 0.5 and p95 < 1000 and self.interval < 15:
            recommended_interval = min(60, self.interval * 3)
        checks_saved_per_day = int((86400.0 / max(self.interval, 1)) -
                                   (86400.0 / max(recommended_interval, 1)))
        if checks_saved_per_day < 0:
            checks_saved_per_day = 0
        monthly_savings_pct = 0.0
        if recommended_interval > self.interval:
            monthly_savings_pct = round(
                (1 - (self.interval / recommended_interval)) * 100, 1)
        refined = {
            "waste_score": round(waste_score, 1),
            "recommended_interval_seconds": recommended_interval,
            "checks_saved_per_day": checks_saved_per_day,
            "estimated_monthly_savings_pct": monthly_savings_pct,
            "reliability_priority": bool(slo and not slo.get("met", True)),
        }
        return {
            "hints": hints,
            "checks_per_day": int(checks_per_day),
            "estimated_monthly_checks": int(monthly_checks),
            "probe_efficiency_score": round(efficiency, 1),
            "avg_ms": round(avg_ms, 1),
            "p95_ms": round(p95, 1),
            "refined": refined,
        }


class RootCauseAnalyzer:
    def __init__(self):
        self.knowledge_base = {
            "network": [
                "Check upstream ISP and network path health",
                "Verify firewall and security group rules",
                "Inspect DNS resolution and resolver health",
            ],
            "server": [
                "Review application error logs around incident window",
                "Check backend service health endpoints",
                "Verify load balancer target group health",
            ],
            "certificate": [
                "Renew or reissue the TLS certificate",
                "Validate certificate chain installation",
                "Check certificate transparency log entries",
            ],
            "configuration": [
                "Review recent deployment and configuration changes",
                "Validate redirect rules for loops or misroutes",
                "Check reverse proxy and CDN configuration",
            ],
            "service": [
                "Verify the daemon or process is running",
                "Check port bindings and listen backlog",
                "Review service resource limits and restarts",
            ],
            "unknown": [
                "Collect additional telemetry around the failure window",
                "Enable verbose logging for the affected component",
                "Correlate failures with the deployment timeline",
            ],
        }

    def analyze(self, incident, results=None):
        category = incident.get("root_cause_category", "unknown")
        severity = incident.get("severity", "LOW")
        failures = incident.get("failures", 1)
        primary = incident.get("root_cause", "Unknown root cause")
        hypotheses = [{
            "cause": primary,
            "likelihood": "high",
            "evidence": "Matched failure signature: " + str(incident.get("reason", ""))[:80],
        }]
        if failures >= 3:
            hypotheses.append({
                "cause": "Sustained outage rather than a transient blip",
                "likelihood": "medium",
                "evidence": "{} consecutive failed checks recorded".format(failures),
            })
        if category == "unknown":
            hypotheses.append({
                "cause": "Insufficient signal to classify automatically",
                "likelihood": "low",
                "evidence": "Root cause keyword matching did not fire",
            })
        recommended = list(self.knowledge_base.get(category, self.knowledge_base["unknown"]))
        chain = [
            "Trigger: " + str(incident.get("reason", "unknown failure")),
            "Category classification: " + category,
            "Severity assessed: " + severity,
            "Impact: {:.1f}% of observed checks failed".format(incident.get("impact_score", 0)),
            "Probable root cause: " + primary,
        ]
        return {
            "primary_cause": primary,
            "category": category,
            "hypotheses": hypotheses,
            "causal_chain": chain,
            "recommended_actions": recommended,
            "confidence": "low" if category == "unknown" else "high",
            "evidence_samples": [r.get("timestamp", "") for r in (results or [])[:3]],
        }


class IncidentPostMortemGenerator:
    def __init__(self, target_label="", stats=None, sla_target=99.9, slo_target=99.9, interval=5):
        self.target_label = target_label
        self.stats = stats or {}
        self.sla_target = sla_target
        self.slo_target = slo_target
        self.interval = interval

    def generate(self, incident, results=None):
        analyzer = RootCauseAnalyzer()
        rca = analyzer.analyze(incident, results)
        duration = incident.get("duration_seconds", 0)
        failures = incident.get("failures", 1)
        impact = incident.get("impact_score", 0)
        severity = incident.get("severity", "LOW")
        status = incident.get("status", "UNKNOWN")
        title = "Post-mortem for {} ({})".format(incident.get("group_id", "INC-????"), severity)
        timeline = [
            {"time": incident.get("start", "unknown"), "event": "Incident opened: " + str(incident.get("reason", ""))},
        ]
        if failures > 1:
            timeline.append({
                "time": "-",
                "event": "{} additional failed checks recorded during the incident".format(failures - 1),
            })
        timeline.append({"time": str(incident.get("end", "Ongoing")), "event": "Incident status: " + status})
        action_items = []
        for i, action in enumerate(rca["recommended_actions"], 1):
            action_items.append({"id": i, "action": action, "priority": "high" if severity in ("CRITICAL", "HIGH") else "medium"})
        action_items.append({
            "id": len(action_items) + 1,
            "action": "Add or tighten monitoring coverage for this failure mode",
            "priority": "medium",
        })
        duration_min = duration / 60.0
        downtime_cost = duration_min * (impact / 100.0)
        lines = []
        lines.append("# " + title)
        lines.append("")
        lines.append("Target: " + str(self.target_label))
        lines.append("Severity: " + severity)
        lines.append("Status: " + status)
        lines.append("Duration: {:.1f}s ({:.2f} min)".format(duration, duration_min))
        lines.append("Impact score: {:.1f}% of checks failed".format(impact))
        lines.append("")
        lines.append("## Summary")
        lines.append("A {} severity failure affected {} check(s) on {}.".format(severity.lower(), failures, self.target_label))
        lines.append("Detected cause: " + rca["primary_cause"])
        lines.append("Classification confidence: " + rca["confidence"])
        lines.append("")
        lines.append("## Timeline")
        for entry in timeline:
            lines.append("- " + str(entry["time"]) + ": " + entry["event"])
        lines.append("")
        lines.append("## Root Cause Analysis")
        lines.append("Causal chain:")
        for idx, step in enumerate(rca["causal_chain"], 1):
            lines.append("  {}. {}".format(idx, step))
        lines.append("Hypotheses:")
        for hyp in rca["hypotheses"]:
            lines.append("- [{}] {} (evidence: {})".format(hyp["likelihood"], hyp["cause"], hyp["evidence"]))
        lines.append("")
        lines.append("## Action Items")
        for item in action_items:
            lines.append("- [{}] (priority: {}) {}".format(item["id"], item["priority"], item["action"]))
        lines.append("")
        lines.append("## Corrective Metrics")
        lines.append("Estimated impact-weighted downtime units: {:.2f}".format(downtime_cost))
        lines.append("SLA target: {:.3f}% | SLO target: {:.3f}%".format(self.sla_target, self.slo_target))
        if self.stats:
            lines.append("Session error rate: {:.2f}%".format(self.stats.get("error_rate", 0)))
        markdown = "\n".join(lines)
        return {
            "incident_id": incident.get("group_id", "?"),
            "title": title,
            "severity": severity,
            "status": status,
            "duration_seconds": duration,
            "duration_minutes": round(duration_min, 2),
            "impact_score": impact,
            "summary": "Detected cause: " + rca["primary_cause"],
            "timeline": timeline,
            "root_cause_analysis": rca,
            "action_items": action_items,
            "impact_weighted_downtime": round(downtime_cost, 2),
            "markdown": markdown,
        }

    def generate_all(self, incidents, results=None):
        generated = []
        for inc in incidents:
            if inc.get("status") == "OPEN":
                continue
            generated.append(self.generate(inc, results))
        return generated


class IncidentCorrelationEngine:
    def __init__(self, window_seconds=300):
        self.window_seconds = window_seconds

    @staticmethod
    def _parse_ts(value):
        try:
            return datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S").timestamp()
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _max_severity(sevs):
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        best = "LOW"
        for s in sevs:
            if s in order and order.index(s) > order.index(best):
                best = s
        return best

    def correlate(self, incidents):
        if not incidents:
            return {
                "clusters": [], "correlated_pairs": 0,
                "cascade_detected": False, "shared_categories": {},
                "window_seconds": self.window_seconds,
            }
        timed = []
        for inc in incidents:
            ts = self._parse_ts(inc.get("start"))
            if ts is not None:
                timed.append((ts, inc))
        timed.sort(key=lambda item: item[0])
        groups = []
        current = []
        current_start = None
        for ts, inc in timed:
            if not current:
                current = [inc]
                current_start = ts
                continue
            if ts - current_start <= self.window_seconds:
                current.append(inc)
            else:
                groups.append(current)
                current = [inc]
                current_start = ts
        if current:
            groups.append(current)
        out_clusters = []
        cascade = False
        category_totals = {}
        for idx, group in enumerate(groups, 1):
            cats = set(inc.get("root_cause_category", "unknown") for inc in group)
            sevs = [inc.get("severity", "LOW") for inc in group]
            is_cascade = len(group) > 1 and len(cats) > 1
            if is_cascade:
                cascade = True
            for inc in group:
                cat = inc.get("root_cause_category", "unknown")
                category_totals[cat] = category_totals.get(cat, 0) + 1
            starts = [self._parse_ts(inc.get("start")) for inc in group]
            starts = [s for s in starts if s is not None]
            span = (max(starts) - min(starts)) if len(starts) >= 2 else 0
            out_clusters.append({
                "cluster_id": "CORR-" + str(idx).zfill(3),
                "incident_ids": [inc.get("group_id", "?") for inc in group],
                "size": len(group),
                "categories": sorted(cats),
                "max_severity": self._max_severity(sevs),
                "span_seconds": round(span, 1),
                "cascade_suspected": is_cascade,
            })
        return {
            "clusters": out_clusters,
            "correlated_pairs": sum(1 for c in out_clusters if c["size"] > 1),
            "cascade_detected": cascade,
            "shared_categories": category_totals,
            "window_seconds": self.window_seconds,
        }


class EscalationPolicySimulator:
    DEFAULT_POLICY = [
        {"tier": 1, "role": "Primary On-Call", "delay_minutes": 0,
         "severities": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
        {"tier": 2, "role": "Secondary On-Call", "delay_minutes": 5,
         "severities": ["CRITICAL", "HIGH"]},
        {"tier": 3, "role": "Engineering Manager", "delay_minutes": 15,
         "severities": ["CRITICAL"]},
        {"tier": 4, "role": "Director / VP", "delay_minutes": 30,
         "severities": ["CRITICAL"]},
    ]

    def __init__(self, policy=None):
        self.policy = policy or self.DEFAULT_POLICY

    def simulate(self, incidents):
        simulations = []
        role_pages = {}
        for inc in incidents:
            sev = inc.get("severity", "LOW")
            duration_min = inc.get("duration_seconds", 0) / 60.0
            notified = []
            for level in self.policy:
                if sev not in level["severities"]:
                    continue
                if duration_min >= level["delay_minutes"]:
                    notified.append({
                        "tier": level["tier"],
                        "role": level["role"],
                        "notified_at_minutes": level["delay_minutes"],
                    })
                    role_pages[level["role"]] = role_pages.get(level["role"], 0) + 1
            tiers = [n["tier"] for n in notified]
            max_tier = max(tiers) if tiers else 0
            simulations.append({
                "incident_id": inc.get("group_id", "?"),
                "severity": sev,
                "duration_minutes": round(duration_min, 2),
                "tiers_notified": notified,
                "max_tier_reached": max_tier,
                "escalated": max_tier > 1,
                "would_page_exec": any(t >= 4 for t in tiers),
            })
        return {
            "policy": [{"tier": p["tier"], "role": p["role"], "delay_minutes": p["delay_minutes"]}
                       for p in self.policy],
            "simulations": simulations,
            "stats": {
                "incidents_evaluated": len(incidents),
                "escalated_count": sum(1 for s in simulations if s["escalated"]),
                "exec_page_count": sum(1 for s in simulations if s["would_page_exec"]),
                "role_page_counts": role_pages,
            },
        }


class ServiceDependencyMapper:
    def __init__(self, origin_host=None, timeout=8, extra_edges=None):
        self.origin_host = origin_host
        self.timeout = timeout
        self.nodes = {}
        self.edges = []
        if extra_edges:
            for edge in extra_edges:
                self.add_edge(edge.get("source", ""), edge.get("target", ""),
                              edge.get("kind", "depends_on"), edge.get("critical", True))

    def add_node(self, node_id, label=None, kind="service", critical=True, tier=1):
        if not node_id:
            return
        self.nodes[node_id] = {
            "id": node_id,
            "label": label or node_id,
            "kind": kind,
            "critical": bool(critical),
            "tier": int(tier),
            "health": "unknown",
            "latency_ms": -1,
            "dependents": [],
            "dependencies": [],
        }

    def add_edge(self, source, target, kind="depends_on", critical=True):
        if not source or not target:
            return
        self.add_node(source)
        self.add_node(target)
        if source not in self.nodes[target]["dependencies"]:
            self.nodes[target]["dependencies"].append(source)
        if target not in self.nodes[source]["dependents"]:
            self.nodes[source]["dependents"].append(target)
        self.edges.append({"source": source, "target": target, "kind": kind,
                           "critical": bool(critical)})

    def ingest_chain(self, chain_report):
        if not chain_report:
            return
        for hop in chain_report.get("chain", []):
            host = hop.get("host", "")
            if not host:
                continue
            self.add_node(host, label=host, kind=hop.get("role", "dependency"),
                          critical=hop.get("role") == "origin",
                          tier=0 if hop.get("role") == "origin" else 1)
            self.nodes[host]["health"] = "up" if hop.get("healthy") else "down"
            self.nodes[host]["latency_ms"] = hop.get("hop_latency_ms", -1)
            if hop.get("role") == "origin" and self.origin_host is None:
                self.origin_host = host
        origin = self.origin_host
        for hop in chain_report.get("chain", []):
            host = hop.get("host", "")
            if host and origin and host != origin:
                self.add_edge(origin, host, kind="loads", critical=False)

    def _probe_node(self, node_id):
        start = time.time()
        try:
            socket.getaddrinfo(node_id, None)
            dns_ms = round((time.time() - start) * 1000, 1)
        except Exception:
            node = self.nodes.get(node_id, {})
            node["health"] = "down"
            node["latency_ms"] = -1
            return
        tcp_ms = -1
        for port in (443, 80):
            try:
                tcp_start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((node_id, port))
                tcp_ms = round((time.time() - tcp_start) * 1000, 1)
                sock.close()
                break
            except Exception:
                continue
        node = self.nodes.get(node_id, {})
        node["latency_ms"] = round(dns_ms + max(tcp_ms, 0), 1)
        node["health"] = "up" if tcp_ms >= 0 else "degraded"

    def map(self, probe=True):
        if probe:
            for node_id in list(self.nodes.keys()):
                self._probe_node(node_id)
        down_nodes = [nid for nid, n in self.nodes.items() if n.get("health") == "down"]
        blast_radius = set(down_nodes)
        changed = True
        while changed:
            changed = False
            for edge in self.edges:
                if edge["target"] in blast_radius and edge["source"] not in blast_radius:
                    if edge["critical"]:
                        blast_radius.add(edge["source"])
                        changed = True
        critical_down = [nid for nid in blast_radius
                         if self.nodes.get(nid, {}).get("critical")]
        tiers = {}
        for nid, node in self.nodes.items():
            tiers.setdefault(node.get("tier", 1), []).append(nid)
        return {
            "origin": self.origin_host,
            "nodes": list(self.nodes.values()),
            "edges": list(self.edges),
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "down_nodes": down_nodes,
            "blast_radius": sorted(blast_radius),
            "blast_radius_count": len(blast_radius),
            "critical_at_risk": sorted(critical_down),
            "tiers": {str(k): v for k, v in sorted(tiers.items())},
            "status": "HEALTHY" if not down_nodes else (
                "AT_RISK" if critical_down else "DEGRADED"),
        }


class CascadingFailureDetector:
    def __init__(self, propagation_window_seconds=300, min_depth=2):
        self.propagation_window_seconds = propagation_window_seconds
        self.min_depth = min_depth

    @staticmethod
    def _parse_ts(value):
        try:
            return datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S").timestamp()
        except (ValueError, TypeError):
            return None

    def detect(self, incidents, dependency_map=None):
        incidents = [i for i in (incidents or [])]
        timed = []
        for inc in incidents:
            ts = self._parse_ts(inc.get("start"))
            if ts is not None:
                timed.append((ts, inc))
        timed.sort(key=lambda item: item[0])
        chains = []
        used = set()
        for i, (ts_i, inc_i) in enumerate(timed):
            key_i = inc_i.get("group_id", id(inc_i))
            if key_i in used:
                continue
            chain = [inc_i]
            last_ts = ts_i
            used.add(key_i)
            for j in range(i + 1, len(timed)):
                ts_j, inc_j = timed[j]
                key_j = inc_j.get("group_id", id(inc_j))
                if key_j in used:
                    continue
                if ts_j - last_ts > self.propagation_window_seconds:
                    break
                prev_cat = chain[-1].get("root_cause_category", "unknown")
                cat = inc_j.get("root_cause_category", "unknown")
                related = (cat != prev_cat) or (
                    dependency_map and self._linked(inc_i, inc_j, dependency_map))
                if related:
                    chain.append(inc_j)
                    used.add(key_j)
                    last_ts = ts_j
            if len(chain) >= self.min_depth:
                cats = [c.get("root_cause_category", "unknown") for c in chain]
                chains.append({
                    "chain_id": "CAS-" + str(len(chains) + 1).zfill(3),
                    "depth": len(chain),
                    "incident_ids": [c.get("group_id", "?") for c in chain],
                    "categories": cats,
                    "severities": [c.get("severity", "LOW") for c in chain],
                    "start": chain[0].get("start", ""),
                    "end": chain[-1].get("end", "Ongoing"),
                    "span_seconds": round(last_ts - ts_i, 1),
                    "origin_incident": chain[0].get("group_id", "?"),
                    "max_severity": self._max_sev([c.get("severity", "LOW") for c in chain]),
                    "propagation_steps": max(0, len(chain) - 1),
                })
        max_depth = max((c["depth"] for c in chains), default=0)
        return {
            "detected": bool(chains),
            "chains": chains,
            "chain_count": len(chains),
            "max_depth": max_depth,
            "min_depth_required": self.min_depth,
            "window_seconds": self.propagation_window_seconds,
            "risk": "HIGH" if max_depth >= 3 else ("MEDIUM" if chains else "LOW"),
            "incidents_evaluated": len(timed),
        }

    @staticmethod
    def _linked(inc_a, inc_b, dependency_map):
        origin = dependency_map.get("origin")
        if not origin:
            return False
        blast = set(dependency_map.get("blast_radius", []))
        cat_a = inc_a.get("root_cause_category", "unknown")
        cat_b = inc_b.get("root_cause_category", "unknown")
        if cat_a != "unknown" and cat_b != "unknown" and cat_a != cat_b and blast:
            return True
        return False

    @staticmethod
    def _max_sev(sevs):
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        best = "LOW"
        for s in sevs:
            if s in order and order.index(s) > order.index(best):
                best = s
        return best


class MaintenanceWindowManager:
    def __init__(self, windows=None):
        self.windows = list(windows or [])
        self.events = []

    @staticmethod
    def parse_spec(spec):
        try:
            start_s, end_s = str(spec).split("-", 1)
            sh, sm = [int(x) for x in start_s.strip().split(":")[:2]]
            eh, em = [int(x) for x in end_s.strip().split(":")[:2]]
            start_min = sh * 60 + sm
            end_min = eh * 60 + em
            if start_min > end_min:
                end_min += 24 * 60
            return {"spec": str(spec), "start_minutes": start_min, "end_minutes": end_min}
        except (ValueError, AttributeError):
            return None

    def add_window(self, spec, label=None, days=None, repeat_weekly=False):
        parsed = self.parse_spec(spec) if isinstance(spec, str) else spec
        if not parsed:
            return None
        window = {
            "id": "MW-" + str(len(self.windows) + 1).zfill(3),
            "label": label or parsed.get("spec", "window"),
            "start_minutes": parsed.get("start_minutes", 0),
            "end_minutes": parsed.get("end_minutes", 0),
            "days": days,
            "repeat_weekly": bool(repeat_weekly),
            "suppressed_alerts": 0,
            "active": False,
        }
        self.windows.append(window)
        return window

    def active_window(self, when=None):
        now = when or datetime.now()
        current = now.hour * 60 + now.minute
        weekday = now.weekday()
        for window in self.windows:
            days = window.get("days")
            if days is not None and weekday not in days:
                continue
            start = window.get("start_minutes", 0)
            end = window.get("end_minutes", 0)
            if start <= end:
                in_window = start <= current <= end
            else:
                in_window = current >= start or current <= end
            if in_window:
                return window
        return None

    def in_maintenance(self, when=None):
        return self.active_window(when) is not None

    def should_suppress(self, severity="LOW", when=None):
        window = self.active_window(when)
        if window is None:
            return False, None
        suppress = severity in ("LOW", "MEDIUM")
        if suppress:
            window["suppressed_alerts"] = window.get("suppressed_alerts", 0) + 1
        return suppress, window

    def record_event(self, kind, detail):
        self.events.append({
            "kind": kind,
            "detail": detail,
            "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

    def summarize(self):
        active = self.active_window()
        upcoming = None
        now_min = datetime.now().hour * 60 + datetime.now().minute
        best_delta = None
        for window in self.windows:
            start = window.get("start_minutes", 0)
            delta = start - now_min
            if delta < 0:
                delta += 24 * 60
            if best_delta is None or delta < best_delta:
                best_delta = delta
                upcoming = window
        return {
            "total_windows": len(self.windows),
            "active": active is not None,
            "active_window": active,
            "upcoming_window": upcoming,
            "minutes_until_next": best_delta,
            "suppressed_total": sum(w.get("suppressed_alerts", 0) for w in self.windows),
            "events": list(self.events),
            "windows": list(self.windows),
        }


class AlertFatigueReducer:
    def __init__(self, dedupe_window_seconds=300, max_alerts_per_window=3,
                 quiet_severities=None, burst_window_seconds=60):
        self.dedupe_window_seconds = dedupe_window_seconds
        self.max_alerts_per_window = max_alerts_per_window
        self.quiet_severities = set(quiet_severities or ["LOW"])
        self.burst_window_seconds = burst_window_seconds
        self.history = []
        self.suppressed = []
        self.sent = []

    @staticmethod
    def _fingerprint(incident):
        base = "{}|{}".format(incident.get("root_cause_category", "unknown"),
                              incident.get("severity", "LOW"))
        try:
            return hashlib.sha1(base.encode("utf-8")).hexdigest()[:16]
        except Exception:
            return base

    def evaluate(self, incident, now=None):
        now = now or time.time()
        severity = incident.get("severity", "LOW")
        fingerprint = self._fingerprint(incident)
        recent = [h for h in self.history if now - h["at"] <= self.dedupe_window_seconds
                  and h["fingerprint"] == fingerprint]
        burst = [h for h in self.history if now - h["at"] <= self.burst_window_seconds]
        reason = None
        if severity in self.quiet_severities and not recent:
            reason = "quiet_severity"
        elif recent:
            reason = "duplicate_within_window"
        elif len(burst) >= self.max_alerts_per_window:
            reason = "burst_rate_limited"
        record = {"fingerprint": fingerprint, "at": now, "severity": severity,
                  "incident_id": incident.get("group_id", "?"),
                  "decision": "suppressed" if reason else "sent", "reason": reason}
        self.history.append(record)
        if reason:
            self.suppressed.append(record)
            return {"sent": False, "suppressed": True, "reason": reason,
                    "fingerprint": fingerprint, "severity": severity}
        self.sent.append(record)
        return {"sent": True, "suppressed": False, "reason": None,
                "fingerprint": fingerprint, "severity": severity}

    def stats(self):
        total = len(self.sent) + len(self.suppressed)
        suppression_pct = round((len(self.suppressed) / total) * 100, 1) if total else 0.0
        reasons = {}
        for record in self.suppressed:
            key = record.get("reason") or "unknown"
            reasons[key] = reasons.get(key, 0) + 1
        return {
            "total_evaluated": total,
            "alerts_sent": len(self.sent),
            "alerts_suppressed": len(self.suppressed),
            "suppression_pct": suppression_pct,
            "suppression_reasons": reasons,
            "noise_score": round(100.0 - suppression_pct, 1),
            "quiet_severities": sorted(self.quiet_severities),
        }


class OnCallSimulator:
    DEFAULT_SCHEDULE = [
        {"tier": 1, "role": "Primary On-Call", "shift_hours": 12,
         "rotation": ["engineer-a", "engineer-b"], "severities": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
        {"tier": 2, "role": "Secondary On-Call", "shift_hours": 24,
         "rotation": ["engineer-c", "engineer-d"], "severities": ["CRITICAL", "HIGH"]},
        {"tier": 3, "role": "Incident Commander", "shift_hours": 72,
         "rotation": ["ic-primary"], "severities": ["CRITICAL"]},
    ]

    def __init__(self, schedule=None, ack_timeout_minutes=5):
        self.schedule = schedule or self.DEFAULT_SCHEDULE
        self.ack_timeout_minutes = ack_timeout_minutes

    @staticmethod
    def _who_is_on(shift, at_epoch):
        rotation = shift.get("rotation") or ["unassigned"]
        shift_seconds = max(1, int(shift.get("shift_hours", 12))) * 3600
        index = int(at_epoch // shift_seconds) % len(rotation)
        return rotation[index], index

    def simulate(self, incidents, start_epoch=None):
        start_epoch = start_epoch or time.time()
        results = []
        role_pages = {}
        unacked = 0
        for inc in incidents or []:
            severity = inc.get("severity", "LOW")
            duration_min = inc.get("duration_seconds", 0) / 60.0
            try:
                inc_start = datetime.strptime(str(inc.get("start", "")),
                                              "%Y-%m-%d %H:%M:%S").timestamp()
            except (ValueError, TypeError):
                inc_start = start_epoch
            notified = []
            for shift in self.schedule:
                if severity not in shift.get("severities", []):
                    continue
                oncall, slot = self._who_is_on(shift, inc_start)
                handoff_epoch = (int(inc_start // (max(1, int(shift.get("shift_hours", 12))) * 3600)) + 1) * \
                    max(1, int(shift.get("shift_hours", 12))) * 3600
                handoff_during = duration_min * 60 >= (handoff_epoch - inc_start)
                next_oncall = None
                if handoff_during:
                    next_oncall, _ = self._who_is_on(shift, handoff_epoch)
                ack_minutes = min(duration_min, float(shift.get("ack_delay_minutes", 1)))
                acked = duration_min >= ack_minutes
                if not acked:
                    unacked += 1
                role_pages[shift.get("role", "?")] = role_pages.get(shift.get("role", "?"), 0) + 1
                notified.append({
                    "tier": shift.get("tier", 1),
                    "role": shift.get("role", "?"),
                    "oncall": oncall,
                    "rotation_slot": slot,
                    "ack_minutes": round(ack_minutes, 2),
                    "acked": acked,
                    "handoff_during_incident": handoff_during,
                    "next_oncall": next_oncall,
                })
            results.append({
                "incident_id": inc.get("group_id", "?"),
                "severity": severity,
                "duration_minutes": round(duration_min, 2),
                "responders": notified,
                "max_tier": max((r["tier"] for r in notified), default=0),
                "handoffs": sum(1 for r in notified if r.get("handoff_during_incident")),
                "all_acked": all(r.get("acked") for r in notified) if notified else False,
            })
        acked_count = sum(1 for r in results if r["all_acked"] and r["responders"])
        coverage_gaps = unacked
        return {
            "schedule": [{"tier": s.get("tier"), "role": s.get("role"),
                          "shift_hours": s.get("shift_hours"),
                          "rotation": list(s.get("rotation", []))}
                         for s in self.schedule],
            "simulations": results,
            "stats": {
                "incidents_evaluated": len(results),
                "role_pages": role_pages,
                "acked_count": acked_count,
                "unacked_events": coverage_gaps,
                "ack_rate_pct": round((acked_count / len(results)) * 100, 1) if results else 0.0,
                "handoff_events": sum(r.get("handoffs", 0) for r in results),
                "ack_timeout_minutes": self.ack_timeout_minutes,
            },
        }


class PredictiveAnalytics:
    def __init__(self, results, interval=5, sla_target=99.9):
        self.results = results
        self.interval = interval
        self.sla_target = sla_target

    @staticmethod
    def _linear_fit(values):
        n = len(values)
        if n < 2:
            return 0.0, (values[0] if values else 0.0)
        x_vals = list(range(n))
        x_mean = statistics.mean(x_vals)
        y_mean = statistics.mean(values)
        den = sum((x - x_mean) ** 2 for x in x_vals)
        if den == 0:
            return 0.0, y_mean
        slope = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_vals, values)) / den
        intercept = y_mean - slope * x_mean
        return slope, intercept

    @staticmethod
    def _response_times(results):
        return [r.get("timing", {}).get("total", 0)
                for r in results if r.get("timing", {}).get("total", 0) > 0]

    @staticmethod
    def _statuses(results):
        out = []
        for r in results:
            sc = r.get("status", {}).get("status_code", 0)
            out.append(1 if 200 <= sc < 400 else 0)
        return out

    def predictive_failure_analysis(self):
        times = self._response_times(self.results)
        statuses = self._statuses(self.results)
        factors = []
        score = 0.0
        if len(statuses) >= 2:
            half = max(1, len(statuses) // 2)
            recent_err = (1 - (sum(statuses[-half:]) / half)) * 100
            early_err = (1 - (sum(statuses[:half]) / half)) * 100
            if recent_err - early_err > 10:
                score += 30
                factors.append("Recent error rate rose from {:.1f}% to {:.1f}%".format(early_err, recent_err))
            elif recent_err > 20:
                score += 20
                factors.append("Elevated recent error rate: {:.1f}%".format(recent_err))
        if len(times) >= 3:
            slope, _ = self._linear_fit(times)
            if slope > 50:
                score += 25
                factors.append("Latency increasing {:.1f}ms per check".format(slope))
            mean_t = statistics.mean(times)
            stdev_t = statistics.stdev(times) if len(times) > 1 else 0
            if stdev_t > 0:
                recent_z = (times[-1] - mean_t) / stdev_t
                if recent_z > 2:
                    score += 20
                    factors.append("Latest sample z-score {:.1f} indicates instability".format(recent_z))
        if statuses and statuses[-1] == 0:
            score += 25
            factors.append("Most recent check failed")
        score = min(99.0, score)
        if score >= 70:
            level = "CRITICAL"
        elif score >= 45:
            level = "HIGH"
        elif score >= 20:
            level = "MEDIUM"
        else:
            level = "LOW"
        if not factors:
            factors.append("No strong predictive signals detected")
        return {
            "failure_probability": round(score, 1),
            "risk_level": level,
            "factors": factors,
            "horizon": "next 1-3 checks",
        }

    def trend_extrapolation(self, horizon=10):
        times = self._response_times(self.results)
        statuses = self._statuses(self.results)
        if len(times) < 2 or len(statuses) < 2:
            return {
                "horizon": horizon,
                "latency_projection": [],
                "uptime_projection": [],
                "direction": "insufficient_data",
                "confidence": 0.0,
                "latency_slope": 0.0,
            }
        slope, intercept = self._linear_fit(times)
        latency_proj = [max(0.0, slope * (len(times) + i) + intercept) for i in range(horizon)]
        s_slope, s_intercept = self._linear_fit([float(s) for s in statuses])
        uptime_proj = []
        for i in range(horizon):
            val = s_slope * (len(statuses) + i) + s_intercept
            uptime_proj.append(min(100.0, max(0.0, val * 100.0)))
        y_mean = statistics.mean(times)
        ss_tot = sum((y - y_mean) ** 2 for y in times)
        ss_res = sum((y - (slope * i + intercept)) ** 2 for i, y in enumerate(times))
        r2 = 0.0 if ss_tot == 0 else max(0.0, 1.0 - (ss_res / ss_tot))
        if slope > 10:
            direction = "degrading"
        elif slope < -10:
            direction = "improving"
        else:
            direction = "stable"
        return {
            "horizon": horizon,
            "latency_projection": [round(v, 1) for v in latency_proj],
            "uptime_projection": [round(v, 3) for v in uptime_proj],
            "direction": direction,
            "confidence": round(r2 * 100, 1),
            "latency_slope": round(slope, 2),
        }

    def seasonal_pattern_detection(self, buckets=4):
        times = self._response_times(self.results)
        if len(times) < buckets * 2:
            return {
                "pattern": "insufficient_data",
                "bucket_means": [],
                "deviations_pct": [],
                "peak_bucket": -1,
                "trough_bucket": -1,
                "strength": 0.0,
                "note": "Need at least {} samples for seasonal analysis".format(buckets * 2),
            }
        size = len(times) // buckets
        bucket_means = []
        for b in range(buckets):
            chunk = times[b * size:(b + 1) * size]
            if chunk:
                bucket_means.append(statistics.mean(chunk))
        if not bucket_means:
            return {
                "pattern": "insufficient_data",
                "bucket_means": [],
                "deviations_pct": [],
                "peak_bucket": -1,
                "trough_bucket": -1,
                "strength": 0.0,
                "note": "Bucketing produced no data",
            }
        overall = statistics.mean(bucket_means)
        if overall <= 0:
            deviations = [0.0 for _ in bucket_means]
        else:
            deviations = [((m - overall) / overall) * 100.0 for m in bucket_means]
        peak = max(range(len(bucket_means)), key=lambda i: bucket_means[i])
        trough = min(range(len(bucket_means)), key=lambda i: bucket_means[i])
        spread = (max(deviations) - min(deviations)) if deviations else 0.0
        if spread < 10:
            pattern = "uniform"
        else:
            signs = [1 if d >= 0 else -1 for d in deviations]
            flips = sum(1 for i in range(1, len(signs)) if signs[i] != signs[i - 1])
            if len(signs) >= 3 and flips >= len(signs) - 2:
                pattern = "cyclic"
            elif deviations[peak] > 15:
                pattern = "peak_period" if peak >= len(deviations) // 2 else "early_peak"
            else:
                pattern = "gradual_shift"
        return {
            "pattern": pattern,
            "bucket_means": [round(m, 1) for m in bucket_means],
            "deviations_pct": [round(d, 1) for d in deviations],
            "peak_bucket": peak,
            "trough_bucket": trough,
            "strength": round(min(100.0, spread * 2), 1),
            "note": "Buckets are sequential check windows (relative seasonality)",
        }

    def capacity_utilization_forecast(self, capacity_limit_ms=3000, horizon=20):
        times = self._response_times(self.results)
        limit = max(capacity_limit_ms, 1)
        if not times:
            return {
                "utilization_pct": 0.0,
                "current_avg_ms": 0.0,
                "capacity_limit_ms": limit,
                "headroom_ms": limit,
                "checks_until_breach": None,
                "projected_ms": [],
                "status": "NO_DATA",
            }
        avg = statistics.mean(times)
        slope, intercept = self._linear_fit(times)
        projected = [max(0.0, slope * (len(times) + i) + intercept) for i in range(horizon)]
        utilization = (avg / limit) * 100.0
        breach_at = None
        if slope > 0:
            x = (limit - intercept) / slope
            if x > len(times):
                breach_at = int(math.ceil(x - len(times)))
        if utilization < 70:
            status = "OK"
        elif utilization < 90:
            status = "WARNING"
        else:
            status = "CRITICAL"
        return {
            "utilization_pct": round(utilization, 1),
            "current_avg_ms": round(avg, 1),
            "capacity_limit_ms": limit,
            "headroom_ms": round(max(0.0, limit - avg), 1),
            "checks_until_breach": breach_at,
            "projected_ms": [round(v, 1) for v in projected],
            "status": status,
        }

    def ensemble_failure_forecast(self, horizon=5):
        times = self._response_times(self.results)
        statuses = self._statuses(self.results)
        models = []
        if len(statuses) >= 2:
            recent_window = statuses[-max(1, len(statuses) // 3):]
            recent_fail = 1 - (sum(recent_window) / len(recent_window))
            models.append(("recent_error_rate", recent_fail))
        if len(times) >= 3:
            slope, _ = self._linear_fit(times)
            latency_risk = min(1.0, max(0.0, slope / 200.0))
            models.append(("latency_slope", latency_risk))
        if len(statuses) >= 3:
            s_slope, _ = self._linear_fit([float(s) for s in statuses])
            status_risk = min(1.0, max(0.0, -s_slope))
            models.append(("status_trend", status_risk))
        if statuses:
            models.append(("latest_check", 0.0 if statuses[-1] == 1 else 1.0))
        if not models:
            return {"probability": 0.0, "risk_level": "LOW", "model_votes": [],
                    "horizon": "next {} checks".format(horizon), "confidence": 0.0}
        votes = [{"model": name, "risk": round(risk * 100, 1)} for name, risk in models]
        combined = statistics.mean([r for _, r in models]) * 100
        if combined >= 70:
            level = "CRITICAL"
        elif combined >= 45:
            level = "HIGH"
        elif combined >= 20:
            level = "MEDIUM"
        else:
            level = "LOW"
        agreement = 1.0 - (statistics.pstdev([r for _, r in models]) if len(models) > 1 else 0.0)
        return {
            "probability": round(min(99.0, combined), 1),
            "risk_level": level,
            "model_votes": votes,
            "horizon": "next {} checks".format(horizon),
            "confidence": round(max(0.0, min(100.0, agreement * 100)), 1),
        }

    def time_to_breach_forecast(self, budget_minutes=None):
        statuses = self._statuses(self.results)
        if len(statuses) < 3 or budget_minutes is None:
            return {"checks_until_sla_breach": None, "minutes_until_sla_breach": None,
                    "basis": "insufficient_data"}
        s_slope, s_intercept = self._linear_fit([float(s) for s in statuses])
        target = self.sla_target / 100.0
        checks_ahead = None
        if s_slope < -1e-9:
            for i in range(1, 5000):
                projected = s_slope * (len(statuses) + i) + s_intercept
                window = list(statuses) + [max(0.0, min(1.0, projected))] * i
                if (sum(window) / len(window)) * 100.0 < self.sla_target:
                    checks_ahead = i
                    break
        if checks_ahead is None:
            return {"checks_until_sla_breach": None, "minutes_until_sla_breach": None,
                    "basis": "no_declining_trend"}
        minutes = checks_ahead * max(self.interval, 1) / 60.0
        return {
            "checks_until_sla_breach": checks_ahead,
            "minutes_until_sla_breach": round(minutes, 1),
            "budget_minutes": budget_minutes,
            "basis": "linear_status_extrapolation",
        }

    def sla_forecast_refinement(self, period_days=30):
        statuses = self._statuses(self.results)
        if len(statuses) < 2:
            return {"available": False, "note": "Insufficient data for SLA forecast",
                    "horizons": [], "sla_target": self.sla_target}
        current = (sum(statuses) / len(statuses)) * 100.0
        slope, intercept = self._linear_fit([float(s) for s in statuses])
        checks_per_day = 86400.0 / max(self.interval, 1)
        horizons = []
        for label, days in (("24h", 1), ("7d", 7), ("30d", 30)):
            future_checks = int(min(checks_per_day * days, 5000))
            projected_values = []
            for i in range(min(future_checks, 500)):
                val = slope * (len(statuses) + i) + intercept
                projected_values.append(min(1.0, max(0.0, val)))
            if projected_values:
                window = statuses + projected_values
                projected = (sum(window) / len(window)) * 100.0
            else:
                projected = current
            horizons.append({
                "label": label,
                "days": days,
                "projected_uptime": round(projected, 4),
                "target": self.sla_target,
                "compliant": projected >= self.sla_target,
                "delta_vs_target": round(projected - self.sla_target, 4),
            })
        breach_horizon = None
        for horizon in horizons:
            if not horizon["compliant"]:
                breach_horizon = horizon["label"]
                break
        trend = "improving" if slope > 0.001 else ("degrading" if slope < -0.001 else "stable")
        return {
            "available": True,
            "current_uptime": round(current, 3),
            "slope_per_check": round(slope * 100, 5),
            "trend": trend,
            "horizons": horizons,
            "first_breach_horizon": breach_horizon,
            "sla_target": self.sla_target,
            "period_days": period_days,
            "confidence": min(95.0, max(20.0, 50.0 + abs(slope) * 400)),
        }

    def cost_optimization_refinement(self, interval=None, multi_region=False, extended_checks=False):
        effective_interval = interval if interval is not None else max(self.interval, 1)
        times = self._response_times(self.results)
        statuses = self._statuses(self.results)
        checks_per_day = 86400.0 / max(effective_interval, 1)
        monthly_checks = checks_per_day * 30
        error_rate = ((1 - (sum(statuses) / len(statuses))) * 100) if statuses else 0.0
        p95 = EnhancedStats.percentile(times, 95) if times else 0
        candidates = []
        for candidate in (effective_interval, effective_interval * 2, effective_interval * 5,
                          effective_interval * 10, 60, 300):
            candidate = int(candidate)
            if candidate <= effective_interval:
                continue
            saved_pct = round((1 - (effective_interval / candidate)) * 100, 1)
            candidates.append({
                "interval_seconds": candidate,
                "monthly_checks": int((86400.0 / candidate) * 30),
                "volume_reduction_pct": saved_pct,
            })
        deduped = {}
        for candidate in candidates:
            deduped.setdefault(candidate["interval_seconds"], candidate)
        candidates = sorted(deduped.values(), key=lambda c: c["interval_seconds"])
        safe_to_reduce = error_rate < 1.0 and p95 < 1500
        recommendation = None
        if safe_to_reduce and candidates:
            recommendation = candidates[min(2, len(candidates) - 1)]
        elif candidates:
            recommendation = candidates[0]
        overhead_flags = []
        if multi_region:
            overhead_flags.append("multi_region_probe_overhead")
        if extended_checks:
            overhead_flags.append("extended_check_overhead")
        if effective_interval < 5:
            overhead_flags.append("sub_5s_interval_high_volume")
        efficiency_score = 100.0
        if error_rate > 1:
            efficiency_score -= min(40.0, error_rate * 4)
        if p95 > 2000:
            efficiency_score -= 15
        if overhead_flags:
            efficiency_score -= 5 * len(overhead_flags)
        efficiency_score = max(0.0, efficiency_score)
        return {
            "available": True,
            "current_interval_seconds": effective_interval,
            "monthly_probe_volume": int(monthly_checks),
            "candidates": candidates[:5],
            "recommended": recommendation,
            "safe_to_reduce_interval": safe_to_reduce,
            "overhead_flags": overhead_flags,
            "efficiency_score": round(efficiency_score, 1),
            "error_rate_pct": round(error_rate, 2),
            "p95_ms": round(p95, 1),
        }

    def roi_refinement(self, hourly_downtime_cost=500.0, monitoring_monthly_cost=100.0):
        statuses = self._statuses(self.results)
        if not statuses:
            return {"available": False, "note": "No status data for ROI refinement"}
        current = (sum(statuses) / len(statuses)) * 100.0
        failure_fraction = max(0.0, (100.0 - current) / 100.0)
        monthly_hours = 720.0
        at_risk = failure_fraction * monthly_hours * hourly_downtime_cost
        scenarios = []
        for label, capture in (("conservative", 0.4), ("expected", 0.65), ("aggressive", 0.9)):
            avoided = round(at_risk * capture, 2)
            net = round(avoided - monitoring_monthly_cost, 2)
            roi_pct = round((net / monitoring_monthly_cost) * 100, 1) if monitoring_monthly_cost else 0.0
            scenarios.append({
                "scenario": label,
                "capture_rate_pct": capture * 100,
                "avoided_cost_monthly": avoided,
                "net_benefit_monthly": net,
                "roi_pct": roi_pct,
                "positive": net > 0,
            })
        best = max(scenarios, key=lambda s: s["net_benefit_monthly"]) if scenarios else None
        breakeven_capture = 0.0
        if at_risk > 0:
            breakeven_capture = min(1.0, monitoring_monthly_cost / at_risk)
        return {
            "available": True,
            "monthly_downtime_risk": round(at_risk, 2),
            "scenarios": scenarios,
            "best_scenario": best,
            "breakeven_capture_rate_pct": round(breakeven_capture * 100, 1),
            "hourly_downtime_cost": hourly_downtime_cost,
            "monitoring_monthly_cost": monitoring_monthly_cost,
            "current_uptime": round(current, 3),
        }


class SyntheticJourneyMonitor:
    def __init__(self, base_url, timeout=15, expect=None, headers=None):
        self.base_url = base_url
        self.timeout = timeout
        self.expect = expect
        self.headers = headers or {}
        self.journeys = []

    def default_journey(self):
        return [{"name": "load_root", "method": "GET", "url": self.base_url,
                 "expect_status": [200, 399], "expect_text": self.expect}]

    def run_journey(self, steps=None):
        steps = steps or self.default_journey()
        step_results = []
        total_ms = 0.0
        journey_ok = True
        for step in steps:
            step_result = {
                "name": step.get("name", "step"),
                "method": step.get("method", "GET").upper(),
                "url": step.get("url", self.base_url),
                "success": False,
                "status_code": 0,
                "response_ms": 0.0,
                "assertions": [],
                "error": None,
            }
            headers = {"User-Agent": "UptimeChecker/" + VERSION}
            headers.update(self.headers)
            start = time.time()
            try:
                method = step_result["method"]
                url = step_result["url"]
                if method == "POST":
                    resp = requests.post(url, headers=headers, timeout=self.timeout,
                                         data=step.get("body"))
                elif method == "PUT":
                    resp = requests.put(url, headers=headers, timeout=self.timeout,
                                        data=step.get("body"))
                elif method == "HEAD":
                    resp = requests.head(url, headers=headers, timeout=self.timeout)
                else:
                    resp = requests.get(url, headers=headers, timeout=self.timeout,
                                        allow_redirects=True)
                elapsed = (time.time() - start) * 1000
                total_ms += elapsed
                step_result["status_code"] = resp.status_code
                step_result["response_ms"] = round(elapsed, 1)
                expect_status = step.get("expect_status", [200, 399])
                status_ok = expect_status[0] <= resp.status_code <= expect_status[1]
                step_result["assertions"].append(
                    {"name": "status_range", "passed": status_ok,
                     "detail": "{} in [{}, {}]".format(resp.status_code, expect_status[0], expect_status[1])})
                expect_text = step.get("expect_text")
                if expect_text:
                    text_ok = expect_text.lower() in resp.text.lower()
                    step_result["assertions"].append(
                        {"name": "body_contains", "passed": text_ok, "detail": expect_text[:40]})
                max_ms = step.get("max_ms")
                if max_ms:
                    time_ok = elapsed <= max_ms
                    step_result["assertions"].append(
                        {"name": "latency_budget", "passed": time_ok,
                         "detail": "{:.0f}ms <= {}ms".format(elapsed, max_ms)})
                step_result["success"] = all(a["passed"] for a in step_result["assertions"])
            except requests.exceptions.Timeout:
                step_result["error"] = "TIMEOUT"
            except Exception as e:
                step_result["error"] = str(e)[:100]
            if not step_result["success"]:
                journey_ok = False
            step_results.append(step_result)
        summary = {
            "journey_success": journey_ok,
            "steps_total": len(step_results),
            "steps_passed": sum(1 for s in step_results if s["success"]),
            "total_ms": round(total_ms, 1),
            "steps": step_results,
        }
        self.journeys.append(summary)
        return summary

    def get_summary(self):
        if not self.journeys:
            return {"journeys_run": 0, "success_rate": 0.0, "avg_ms": 0.0}
        successes = sum(1 for j in self.journeys if j["journey_success"])
        avg_ms = statistics.mean([j["total_ms"] for j in self.journeys])
        return {
            "journeys_run": len(self.journeys),
            "success_rate": round((successes / len(self.journeys)) * 100, 1),
            "avg_ms": round(avg_ms, 1),
            "last": self.journeys[-1],
        }


class RealUserMonitor:
    def __init__(self, results=None, rum_samples=None):
        self.results = results or []
        self.rum_samples = rum_samples or []

    @staticmethod
    def core_web_vitals_from_timing(timing):
        ttfb = timing.get("ttfb") or timing.get("dns_resolution") or timing.get("total", 0)
        total = timing.get("total", 0)
        fcp = max(ttfb, total * 0.4) if total else ttfb
        lcp = max(fcp, total * 0.8) if total else fcp
        inp = total * 0.25 if total else 0
        cls = 0.0
        return {"ttfb_ms": round(ttfb, 1), "fcp_ms": round(fcp, 1),
                "lcp_ms": round(lcp, 1), "inp_ms": round(inp, 1), "cls": cls}

    @staticmethod
    def vitals_grade(metric, value):
        if metric == "ttfb":
            return "good" if value <= 800 else ("needs_improvement" if value <= 1800 else "poor")
        if metric == "fcp":
            return "good" if value <= 1800 else ("needs_improvement" if value <= 3000 else "poor")
        if metric == "lcp":
            return "good" if value <= 2500 else ("needs_improvement" if value <= 4000 else "poor")
        if metric == "inp":
            return "good" if value <= 200 else ("needs_improvement" if value <= 500 else "poor")
        if metric == "cls":
            return "good" if value <= 0.1 else ("needs_improvement" if value <= 0.25 else "poor")
        return "unknown"

    def ingest_samples(self, samples):
        if isinstance(samples, list):
            self.rum_samples.extend(samples)

    def analyze(self):
        derived = []
        for r in self.results:
            timing = r.get("timing", {}) or {}
            if timing.get("total", 0) <= 0:
                continue
            vitals = self.core_web_vitals_from_timing(timing)
            derived.append(vitals)
        samples = self.rum_samples
        if not samples and not derived:
            return {"available": False, "sample_count": 0, "apdex": 0.0,
                    "vitals": {}, "grades": {}, "notes": "No RUM samples or timings available"}
        merged = []
        for s in samples:
            if isinstance(s, dict):
                merged.append({
                    "ttfb_ms": float(s.get("ttfb_ms", s.get("ttfb", 0)) or 0),
                    "fcp_ms": float(s.get("fcp_ms", s.get("fcp", 0)) or 0),
                    "lcp_ms": float(s.get("lcp_ms", s.get("lcp", 0)) or 0),
                    "inp_ms": float(s.get("inp_ms", s.get("inp", 0)) or 0),
                    "cls": float(s.get("cls", 0) or 0),
                })
        merged.extend(derived)
        if not merged:
            return {"available": False, "sample_count": 0, "apdex": 0.0,
                    "vitals": {}, "grades": {}, "notes": "No usable RUM samples"}
        def avg(key):
            vals = [m[key] for m in merged if m.get(key) is not None]
            return round(statistics.mean(vals), 1) if vals else 0.0
        vitals = {"ttfb_ms": avg("ttfb_ms"), "fcp_ms": avg("fcp_ms"),
                  "lcp_ms": avg("lcp_ms"), "inp_ms": avg("inp_ms"), "cls": avg("cls")}
        grades = {k.replace("_ms", ""): self.vitals_grade(k.replace("_ms", ""), v)
                  for k, v in vitals.items()}
        latencies = [m["lcp_ms"] for m in merged if m.get("lcp_ms")]
        satisfied = sum(1 for v in latencies if v <= 2500)
        tolerating = sum(1 for v in latencies if 2500 < v <= 4200)
        frustrated = sum(1 for v in latencies if v > 4200)
        total = max(1, len(latencies))
        apdex = round((satisfied + (tolerating / 2.0)) / total, 3)
        poor_count = sum(1 for g in grades.values() if g == "poor")
        return {
            "available": True,
            "sample_count": len(merged),
            "vitals": vitals,
            "grades": grades,
            "apdex": apdex,
            "user_breakdown": {"satisfied": satisfied, "tolerating": tolerating,
                               "frustrated": frustrated},
            "poor_vitals": poor_count,
            "notes": "Vitals derived from synthetic timings when no external RUM feed supplied",
        }


class ABTestMonitor:
    VARIANT_HEADERS = ["x-variant", "x-experiment-variant", "x-ab-test", "x-assignment",
                       "xbucket", "x-bucket", "x-experiment-id"]
    VARIANT_BODY_PATTERNS = [r"data-variant=[\"']([A-Za-z0-9_-]+)[\"']",
                             r"data-ab-test=[\"']([A-Za-z0-9_-]+)[\"']",
                             r"window\.__VARIANT__\s*=\s*[\"']([A-Za-z0-9_-]+)[\"']"]

    def __init__(self):
        self.observations = []
        self.variant_stats = {}

    def observe(self, headers, body="", url=""):
        headers_lower = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        variant = None
        experiment = None
        for h in self.VARIANT_HEADERS:
            if h in headers_lower:
                variant = headers_lower[h]
                break
        if "x-experiment-name" in headers_lower:
            experiment = headers_lower["x-experiment-name"]
        elif "x-experiment-id" in headers_lower:
            experiment = headers_lower["x-experiment-id"]
        if variant is None and body:
            for pattern in self.VARIANT_BODY_PATTERNS:
                match = re.search(pattern, body)
                if match:
                    variant = match.group(1)
                    break
        if variant is None:
            return None
        if experiment is None:
            experiment = "default"
        timing = None
        record = {"experiment": experiment, "variant": variant, "url": url,
                  "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        self.observations.append(record)
        key = experiment + "::" + variant
        stats = self.variant_stats.setdefault(key, {"experiment": experiment,
                                                    "variant": variant,
                                                    "assignments": 0, "latencies": []})
        stats["assignments"] += 1
        return record

    def record_latency(self, experiment, variant, latency_ms):
        key = experiment + "::" + variant
        stats = self.variant_stats.get(key)
        if stats is not None and latency_ms > 0:
            stats["latencies"].append(latency_ms)

    def analyze(self):
        if not self.variant_stats:
            return {"detected": False, "experiments": [], "notes": "No A/B variants observed"}
        experiments = {}
        for stats in self.variant_stats.values():
            experiments.setdefault(stats["experiment"], []).append(stats)
        experiment_reports = []
        for exp_name, variants in experiments.items():
            total_assign = sum(v["assignments"] for v in variants)
            variant_rows = []
            for v in variants:
                share = (v["assignments"] / total_assign * 100) if total_assign else 0
                avg_lat = statistics.mean(v["latencies"]) if v["latencies"] else 0
                variant_rows.append({
                    "variant": v["variant"],
                    "assignments": v["assignments"],
                    "traffic_share_pct": round(share, 1),
                    "avg_latency_ms": round(avg_lat, 1),
                })
            shares = [row["traffic_share_pct"] for row in variant_rows]
            imbalance = round(max(shares) - min(shares), 1) if len(shares) > 1 else 0.0
            latencies = [row["avg_latency_ms"] for row in variant_rows if row["avg_latency_ms"] > 0]
            latency_spread = round(max(latencies) - min(latencies), 1) if len(latencies) > 1 else 0.0
            experiment_reports.append({
                "experiment": exp_name,
                "variants": variant_rows,
                "total_assignments": total_assign,
                "traffic_imbalance_pct": imbalance,
                "latency_spread_ms": latency_spread,
                "warning": "uneven traffic split" if imbalance > 40 else (
                    "latency disparity between variants" if latency_spread > 300 else None),
            })
        return {"detected": True, "experiments": experiment_reports,
                "total_observations": len(self.observations),
                "notes": "Variant assignments observed from response headers/body markers"}


class FeatureFlagMonitor:
    FLAG_HEADER_PREFIX = "x-flag"
    FLAG_BODY_PATTERNS = [r"data-flag-([A-Za-z0-9_-]+)=[\"'](on|off|true|false|enabled|disabled)[\"']",
                          r"window\.flags\.([A-Za-z0-9_-]+)\s*=\s*[\"']?(on|off|true|false|enabled|disabled)[\"']?"]

    def __init__(self):
        self.history = []
        self.flags = {}

    def observe(self, headers, body=""):
        headers_lower = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        observed = {}
        for key, val in headers_lower.items():
            if key.startswith(self.FLAG_HEADER_PREFIX):
                flag_name = key[len(self.FLAG_HEADER_PREFIX):].lstrip("-_") or "default"
                observed[flag_name] = val.strip().lower()
        if body:
            for pattern in self.FLAG_BODY_PATTERNS:
                for match in re.finditer(pattern, body, re.IGNORECASE):
                    observed[match.group(1)] = match.group(2).strip().lower()
        if not observed:
            return None
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.history.append({"timestamp": timestamp, "flags": dict(observed)})
        for name, state in observed.items():
            entry = self.flags.setdefault(name, {"name": name, "state": state,
                                                 "first_seen": timestamp,
                                                 "last_seen": timestamp,
                                                 "changes": 0, "states": []})
            if entry["state"] != state:
                entry["changes"] += 1
                entry["states"].append({"from": entry["state"], "to": state,
                                        "at": timestamp})
                entry["state"] = state
            entry["last_seen"] = timestamp
        return observed

    def analyze(self):
        if not self.flags:
            return {"detected": False, "flags": [], "flapping": [],
                    "notes": "No feature flags observed"}
        flag_rows = []
        flapping = []
        for entry in self.flags.values():
            row = {
                "name": entry["name"],
                "state": entry["state"],
                "changes": entry["changes"],
                "last_seen": entry["last_seen"],
                "enabled": entry["state"] in ("on", "true", "enabled"),
            }
            flag_rows.append(row)
            if entry["changes"] >= 2:
                flapping.append(entry["name"])
        return {
            "detected": True,
            "flags": sorted(flag_rows, key=lambda r: r["name"]),
            "flapping": flapping,
            "total_flags": len(flag_rows),
            "enabled_count": sum(1 for r in flag_rows if r["enabled"]),
            "notes": "Flag state changes tracked across checks",
        }


class DependencyChainMonitor:
    def __init__(self, hostname, timeout=10, deps=None):
        self.hostname = hostname
        self.timeout = timeout
        self.deps = deps or []
        self.chain_results = []

    def build_chain(self, deps=None):
        deps = deps if deps is not None else self.deps
        chain = [{"hop": 0, "host": self.hostname, "role": "origin", "type": "self"}]
        seen = {self.hostname}
        for idx, dep in enumerate(deps, 1):
            domain = dep.get("domain") if isinstance(dep, dict) else str(dep)
            if domain and domain not in seen:
                seen.add(domain)
                chain.append({"hop": idx, "host": domain,
                              "role": "dependency",
                              "type": dep.get("type", "asset") if isinstance(dep, dict) else "asset"})
        return chain

    def _probe_host(self, host):
        result = {"host": host, "dns_ms": -1, "resolved": False,
                  "tcp_ms": -1, "tcp_ok": False, "error": None}
        start = time.time()
        try:
            socket.getaddrinfo(host, None)
            result["dns_ms"] = round((time.time() - start) * 1000, 1)
            result["resolved"] = True
        except Exception as e:
            result["error"] = "DNS: " + str(e)[:60]
            return result
        try:
            tcp_start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, 443))
            result["tcp_ms"] = round((time.time() - tcp_start) * 1000, 1)
            result["tcp_ok"] = True
            sock.close()
        except Exception:
            try:
                tcp_start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((host, 80))
                result["tcp_ms"] = round((time.time() - tcp_start) * 1000, 1)
                result["tcp_ok"] = True
                sock.close()
            except Exception as e:
                result["error"] = "TCP: " + str(e)[:60]
        return result

    def run(self, deps=None):
        chain = self.build_chain(deps)
        results = []
        critical_path_ms = 0.0
        for hop in chain:
            probe = self._probe_host(hop["host"])
            entry = dict(hop)
            entry.update(probe)
            entry["healthy"] = bool(probe.get("resolved")) and bool(probe.get("tcp_ok"))
            hop_latency = max(probe.get("dns_ms", 0), 0) + max(probe.get("tcp_ms", 0), 0)
            entry["hop_latency_ms"] = round(hop_latency, 1)
            critical_path_ms += hop_latency
            results.append(entry)
        self.chain_results = results
        healthy = sum(1 for r in results if r["healthy"])
        unhealthy_hosts = [r["host"] for r in results if not r["healthy"]]
        single_points = []
        if unhealthy_hosts:
            single_points = unhealthy_hosts
        return {
            "chain": results,
            "hops": len(results),
            "healthy_hops": healthy,
            "chain_health_pct": round((healthy / len(results)) * 100, 1) if results else 0.0,
            "critical_path_ms": round(critical_path_ms, 1),
            "unhealthy_hosts": unhealthy_hosts,
            "single_points_of_failure": single_points,
            "status": "HEALTHY" if healthy == len(results) and results else (
                "DEGRADED" if healthy > 0 else "DOWN"),
        }


class RunbookLibrary:
    def __init__(self):
        self.runbooks = {
            "network": {
                "id": "RB-NET-01", "title": "Network path degradation",
                "steps": [
                    "Confirm failure from a second region or probe vantage point",
                    "Check upstream ISP / transit status pages",
                    "Verify firewall and security group rules for recent changes",
                    "Inspect DNS resolution and resolver health",
                    "Capture traceroute/mtr to the affected host",
                ],
                "estimated_minutes": 15,
            },
            "server": {
                "id": "RB-SRV-01", "title": "Backend server failure",
                "steps": [
                    "Check application error logs around the incident window",
                    "Verify process/health endpoints on affected instances",
                    "Review load balancer target health and drain state",
                    "Roll back the most recent deployment if correlated",
                    "Scale out or restart affected workers",
                ],
                "estimated_minutes": 20,
            },
            "certificate": {
                "id": "RB-CRT-01", "title": "TLS certificate issue",
                "steps": [
                    "Confirm certificate expiry date and chain completeness",
                    "Renew or reissue the certificate",
                    "Reload the edge/reverse proxy to pick up the new cert",
                    "Validate the chain with an external TLS checker",
                    "Enable expiry alerting if not already present",
                ],
                "estimated_minutes": 10,
            },
            "configuration": {
                "id": "RB-CFG-01", "title": "Configuration / redirect problem",
                "steps": [
                    "Review recent deployment and configuration changes",
                    "Validate redirect rules for loops or misroutes",
                    "Check reverse proxy and CDN configuration",
                    "Revert the offending change",
                    "Add a regression check for the misconfiguration",
                ],
                "estimated_minutes": 15,
            },
            "service": {
                "id": "RB-SVC-01", "title": "Downstream service failure",
                "steps": [
                    "Verify the daemon or process is running",
                    "Check port bindings and listen backlog",
                    "Review resource limits, CPU/memory and restart counts",
                    "Fail over to the standby instance if available",
                    "Notify the owning team of dependency degradation",
                ],
                "estimated_minutes": 20,
            },
            "unknown": {
                "id": "RB-GEN-01", "title": "General triage",
                "steps": [
                    "Collect telemetry around the failure window",
                    "Enable verbose logging for the affected component",
                    "Correlate failures with the deployment timeline",
                    "Escalate to the primary on-call with collected evidence",
                ],
                "verification": ["Confirm service returns to normal for 3 consecutive checks",
                                 "Notify stakeholders of resolution"],
                "estimated_minutes": 25,
            },
            "cascade": {
                "id": "RB-CAS-01", "title": "Cascading failure containment",
                "steps": [
                    "Identify the origin incident in the cascade chain",
                    "Isolate the failing dependency to stop propagation",
                    "Enable circuit breakers on downstream callers",
                    "Shift traffic to standby or healthy region",
                    "Verify blast radius stops expanding",
                    "Coordinate rollback of the triggering change",
                ],
                "verification": ["Cascade chain shows no new incidents for 5 minutes",
                                 "All critical-tier nodes report healthy"],
                "estimated_minutes": 30,
            },
            "maintenance": {
                "id": "RB-MNT-01", "title": "Planned maintenance validation",
                "steps": [
                    "Confirm the maintenance window is registered and active",
                    "Suppress non-critical alerts for the window duration",
                    "Validate pre-maintenance backup or snapshot",
                    "Execute maintenance checklist steps",
                    "Run post-maintenance health checks",
                    "End maintenance window and re-enable alerting",
                ],
                "verification": ["All checks pass after window closes",
                                 "No suppressed alerts remained unresolved"],
                "estimated_minutes": 45,
            },
        }

    def get_runbook(self, category):
        return self.runbooks.get(category, self.runbooks["unknown"])

    def attach(self, incident):
        category = incident.get("root_cause_category", "unknown")
        runbook = self.get_runbook(category)
        return {
            "runbook_id": runbook["id"],
            "title": runbook["title"],
            "category": category,
            "steps": list(runbook["steps"]),
            "verification": list(runbook.get("verification", [])),
            "estimated_minutes": runbook["estimated_minutes"],
            "incident_id": incident.get("group_id", "?"),
            "severity": incident.get("severity", "LOW"),
            "suggested_owner": self._suggest_owner(incident),
        }

    @staticmethod
    def _suggest_owner(incident):
        category = incident.get("root_cause_category", "unknown")
        severity = incident.get("severity", "LOW")
        owners = {
            "network": "Network Engineering",
            "server": "Platform Engineering",
            "certificate": "Security Engineering",
            "configuration": "Release Engineering",
            "service": "Service Owner",
            "cascade": "Incident Commander",
            "maintenance": "Operations",
        }
        if severity == "CRITICAL":
            return "Incident Commander + " + owners.get(category, "On-Call")
        return owners.get(category, "On-Call")


class CommunicationTemplates:
    TEMPLATES = {
        "initial": ("[INCIDENT] {incident_id} {severity} - {target}\n"
                    "Started: {start}\nReason: {reason}\n"
                    "Impact: {impact}% of checks failing\n"
                    "Next update in 15 minutes."),
        "update": ("[UPDATE] {incident_id} remains {status}\n"
                   "Duration: {duration}s | Failures: {failures}\n"
                   "Root cause hypothesis: {root_cause}\n"
                   "Mitigation in progress."),
        "resolution": ("[RESOLVED] {incident_id} - {target}\n"
                       "Duration: {duration}s | Peak impact: {impact}%\n"
                       "Root cause: {root_cause}\n"
                       "Post-mortem will follow."),
        "escalation": ("[ESCALATION] {incident_id} escalated to {tier}\n"
                       "Severity: {severity} | Duration: {duration}s\n"
                       "Action required: review runbook and acknowledge."),
        "status_page": ("[STATUS PAGE] {incident_id} - {target}\n"
                        "Current status: {status} | Severity: {severity}\n"
                        "Started: {start} | Impact: {impact}%\n"
                        "We are investigating and will post updates every 15 minutes."),
        "handoff": ("[HANDOFF] {incident_id} - {target}\n"
                    "Severity: {severity} | Duration: {duration}s\n"
                    "Root cause hypothesis: {root_cause}\n"
                    "All context and runbook attached - please acknowledge."),
        "maintenance": ("[MAINTENANCE] {incident_id} - {target}\n"
                        "Scheduled window active. Non-critical alerts suppressed.\n"
                        "Expected completion: {duration}s\n"
                        "Normal alerting resumes when the window closes."),
        "all_clear": ("[ALL CLEAR] {incident_id} - {target}\n"
                      "Service has been stable for the observation period.\n"
                      "Final duration: {duration}s | Peak impact: {impact}%\n"
                      "Post-mortem scheduled - no further action required."),
    }

    @classmethod
    def render(cls, template_name, context):
        template = cls.TEMPLATES.get(template_name)
        if template is None:
            return ""
        safe_context = {k: ("" if v is None else v) for k, v in context.items()}
        try:
            return template.format(**safe_context)
        except (KeyError, IndexError, ValueError):
            return template

    @classmethod
    def available(cls):
        return list(cls.TEMPLATES.keys())


class IncidentResponseAutomation:
    def __init__(self, runbooks=None, enabled=True):
        self.enabled = enabled
        self.runbooks = runbooks or RunbookLibrary()
        self.actions = []

    def _record(self, incident_id, action, detail, status="done"):
        self.actions.append({
            "incident_id": incident_id,
            "action": action,
            "detail": detail,
            "status": status,
            "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

    def respond(self, incident, fatigue_reducer=None):
        if not self.enabled:
            return {"executed": [], "skipped": True}
        incident_id = incident.get("group_id", "?")
        severity = incident.get("severity", "LOW")
        executed = []
        fatigue_decision = None
        if fatigue_reducer is not None:
            try:
                fatigue_decision = fatigue_reducer.evaluate(incident)
            except Exception:
                fatigue_decision = None
            if fatigue_decision and fatigue_decision.get("suppressed"):
                self._record(incident_id, "fatigue_suppressed",
                             "Alert suppressed: " + str(fatigue_decision.get("reason", "unknown")),
                             status="suppressed")
                return {"executed": ["fatigue_suppressed"], "runbook": None,
                        "skipped": False, "fatigue": fatigue_decision}
        self._record(incident_id, "acknowledge", "Auto-acknowledged by UptimeChecker automation")
        executed.append("acknowledge")
        self._record(incident_id, "classify",
                     "Severity {} / category {}".format(severity, incident.get("root_cause_category", "unknown")))
        executed.append("classify")
        runbook = self.runbooks.attach(incident)
        self._record(incident_id, "attach_runbook",
                     "{} - {} (owner: {})".format(runbook["runbook_id"], runbook["title"],
                                                  runbook.get("suggested_owner", "On-Call")))
        executed.append("attach_runbook")
        if severity in ("CRITICAL", "HIGH"):
            self._record(incident_id, "page_oncall", "Paged primary on-call for {} severity".format(severity))
            executed.append("page_oncall")
        if severity == "CRITICAL":
            self._record(incident_id, "open_war_room", "Virtual war room opened for critical incident")
            executed.append("open_war_room")
        if incident.get("impact_score", 0) >= 50:
            self._record(incident_id, "enable_mitigation", "Mitigation playbook triggered (impact >= 50%)")
            executed.append("enable_mitigation")
        if severity in ("CRITICAL", "HIGH"):
            self._record(incident_id, "start_sla_clock",
                         "SLA response clock started for {} severity".format(severity))
            executed.append("start_sla_clock")
        self._record(incident_id, "assign_owner",
                     "Routed to " + str(runbook.get("suggested_owner", "On-Call")))
        executed.append("assign_owner")
        return {"executed": executed, "runbook": runbook, "skipped": False,
                "fatigue": fatigue_decision}

    def resolve(self, incident):
        if not self.enabled:
            return {"executed": [], "skipped": True}
        incident_id = incident.get("group_id", "?")
        executed = []
        self._record(incident_id, "verify_recovery", "Successive passing checks confirmed recovery")
        executed.append("verify_recovery")
        self._record(incident_id, "verify_runbook",
                     "Runbook verification checklist opened for sign-off")
        executed.append("verify_runbook")
        self._record(incident_id, "close_incident", "Incident marked resolved")
        executed.append("close_incident")
        self._record(incident_id, "update_stakeholders", "Resolution notice queued for stakeholders")
        executed.append("update_stakeholders")
        self._record(incident_id, "schedule_postmortem", "Post-mortem task queued")
        executed.append("schedule_postmortem")
        self._record(incident_id, "stop_sla_clock", "SLA response clock stopped")
        executed.append("stop_sla_clock")
        return {"executed": executed, "skipped": False}

    def get_actions(self, incident_id=None):
        if incident_id is None:
            return list(self.actions)
        return [a for a in self.actions if a["incident_id"] == incident_id]


class StakeholderNotifier:
    SEVERITY_CHANNELS = {
        "CRITICAL": ["oncall", "engineering_manager", "director"],
        "HIGH": ["oncall", "engineering_manager"],
        "MEDIUM": ["oncall"],
        "LOW": ["oncall"],
    }

    def __init__(self, stakeholders=None, webhook_url=None):
        self.stakeholders = stakeholders or []
        self.webhook_url = webhook_url
        self.sent = []

    def resolve_recipients(self, severity):
        default_roles = self.SEVERITY_CHANNELS.get(severity, ["oncall"])
        recipients = []
        for entry in self.stakeholders:
            role, _, addr = entry.partition(":")
            recipients.append({"role": role.strip(), "address": addr.strip() or role.strip()})
        if not recipients:
            recipients = [{"role": role, "address": role} for role in default_roles]
        return recipients

    def notify(self, incident, template_name="initial", extra_context=None):
        severity = incident.get("severity", "LOW")
        context = {
            "incident_id": incident.get("group_id", "?"),
            "severity": severity,
            "target": incident.get("target", "unknown"),
            "start": incident.get("start", "unknown"),
            "reason": incident.get("reason", "unknown"),
            "impact": incident.get("impact_score", 0),
            "status": incident.get("status", "OPEN"),
            "duration": incident.get("duration_seconds", 0),
            "failures": incident.get("failures", 1),
            "root_cause": incident.get("root_cause", "unknown"),
            "tier": severity,
        }
        if extra_context:
            context.update(extra_context)
        message = CommunicationTemplates.render(template_name, context)
        recipients = self.resolve_recipients(severity)
        default_roles = self.SEVERITY_CHANNELS.get(severity, ["oncall"])
        record = {
            "incident_id": incident.get("group_id", "?"),
            "template": template_name,
            "severity": severity,
            "recipients": recipients,
            "target_roles": default_roles,
            "message": message,
            "channel": "webhook" if self.webhook_url else "simulated",
            "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "priority": self._priority(severity, template_name),
            "delivery": "simulated",
        }
        if self.webhook_url:
            try:
                requests.post(self.webhook_url,
                              json={"text": message, "event": "STAKEHOLDER_" + template_name.upper(),
                                    "incident_id": record["incident_id"],
                                    "severity": severity,
                                    "priority": record["priority"]},
                              timeout=10)
                record["delivery"] = "sent"
            except Exception:
                record["delivery"] = "failed"
        else:
            record["delivery"] = "simulated"
        self.sent.append(record)
        return record

    @staticmethod
    def _priority(severity, template_name):
        if severity == "CRITICAL":
            return "P1"
        if severity == "HIGH":
            return "P2"
        if severity == "MEDIUM":
            return "P3"
        if template_name in ("resolution", "all_clear"):
            return "P4"
        return "P4"

    def notify_batch(self, incidents, template_name="status_page"):
        records = []
        for inc in incidents or []:
            try:
                records.append(self.notify(inc, template_name))
            except Exception:
                continue
        return records

    def digest(self):
        if not self.sent:
            return {"total": 0, "by_priority": {}, "by_template": {}, "delivery_rate_pct": 100.0}
        by_priority = {}
        by_template = {}
        delivered = 0
        for record in self.sent:
            pri = record.get("priority", "P4")
            by_priority[pri] = by_priority.get(pri, 0) + 1
            tpl = record.get("template", "unknown")
            by_template[tpl] = by_template.get(tpl, 0) + 1
            if record.get("delivery") in ("sent", "simulated"):
                delivered += 1
        return {
            "total": len(self.sent),
            "by_priority": by_priority,
            "by_template": by_template,
            "delivery_rate_pct": round((delivered / len(self.sent)) * 100, 1),
        }

    def get_sent(self):
        return list(self.sent)


class ROIAnalyzer:
    def __init__(self, hourly_downtime_cost=500.0, monitoring_monthly_cost=100.0,
                 interval=5, count=1):
        self.hourly_downtime_cost = hourly_downtime_cost
        self.monitoring_monthly_cost = monitoring_monthly_cost
        self.interval = interval
        self.count = count

    def analyze(self, stats, incidents, slo=None, uptime_pct=100.0):
        total_seconds = max(1, self.count * max(self.interval, 1))
        observed_downtime_frac = max(0.0, (100.0 - uptime_pct) / 100.0)
        observed_downtime_hours = (total_seconds / 3600.0) * observed_downtime_frac
        incident_minutes = sum(i.get("duration_seconds", 0) for i in incidents) / 60.0
        incident_hours = incident_minutes / 60.0
        cost_of_downtime_observed = round(observed_downtime_hours * self.hourly_downtime_cost, 2)
        monthly_hours = 720.0
        projected_monthly_downtime_hours = observed_downtime_frac * monthly_hours
        projected_monthly_risk = round(projected_monthly_downtime_hours * self.hourly_downtime_cost, 2)
        mitigation_efficiency = 0.6
        monthly_value = round(projected_monthly_risk * mitigation_efficiency, 2)
        monitoring_cost = self.monitoring_monthly_cost
        monthly_checks = int((86400.0 / max(self.interval, 1)) * 30)
        net_benefit = round(monthly_value - monitoring_cost, 2)
        roi_pct = round((net_benefit / monitoring_cost) * 100, 1) if monitoring_cost > 0 else 0.0
        payback_ratio = round(monthly_value / monitoring_cost, 2) if monitoring_cost > 0 else 0.0
        error_rate = stats.get("error_rate", 0)
        efficiency = max(0.0, 100.0 - error_rate * 5)
        short_window = total_seconds < 60
        if slo and not slo.get("met", True):
            slo_note = "SLO missed - reliability spend should take priority over cost cuts"
        else:
            slo_note = "SLO met - monitoring investment is protecting commitments"
        if short_window:
            confidence_note = "Short observation window - monthly extrapolation is directional only"
        else:
            confidence_note = "Projection based on observed downtime rate over the check window"
        verdict = "POSITIVE" if net_benefit > 0 else "REVIEW"
        if short_window and abs(roi_pct) > 1000:
            verdict = "REVIEW"
        return {
            "hourly_downtime_cost": self.hourly_downtime_cost,
            "observed_downtime_hours": round(observed_downtime_hours, 6),
            "incident_hours": round(incident_hours, 6),
            "cost_of_downtime_observed": cost_of_downtime_observed,
            "projected_monthly_risk": projected_monthly_risk,
            "estimated_avoided_cost_monthly": monthly_value,
            "mitigation_assumption_pct": mitigation_efficiency * 100,
            "monitoring_cost_monthly": monitoring_cost,
            "net_benefit_monthly": net_benefit,
            "roi_pct": roi_pct,
            "payback_ratio": payback_ratio,
            "monthly_probe_volume": monthly_checks,
            "reliability_efficiency": round(efficiency, 1),
            "slo_note": slo_note,
            "confidence_note": confidence_note,
            "short_window": short_window,
            "verdict": verdict,
        }


class ReportGenerator:
    def __init__(self, target_label="", protocol="http", sla_target=99.9, slo_target=99.9):
        self.target_label = target_label
        self.protocol = protocol
        self.sla_target = sla_target
        self.slo_target = slo_target

    def executive_summary(self, verdict, uptime_pct, avg_score, stats, analytics, incidents, slo, check_count=0):
        lines = []
        verdict_line = "STATUS: " + verdict
        if verdict == "UP":
            verdict_line = "[bold green]" + verdict_line + "[/bold green]"
        elif verdict == "DEGRADED":
            verdict_line = "[bold yellow]" + verdict_line + "[/bold yellow]"
        else:
            verdict_line = "[bold red]" + verdict_line + "[/bold red]"
        lines.append(verdict_line)
        lines.append("Target: " + str(self.target_label) + " (" + self.protocol.upper() + ")")
        lines.append("Uptime: {:.2f}% | Score: {:.0f}/100 | Avg Response: {:.0f}ms | Error Rate: {:.2f}%".format(
            uptime_pct, avg_score, stats.get("avg_time", 0), stats.get("error_rate", 0)))
        sla_compliant, sla_status = EnhancedStats.sla_compliance(uptime_pct, self.sla_target)
        sla_color = "green" if sla_compliant else "red"
        lines.append("SLA ({:.3f}%): [bold {}]{}[/bold {}]".format(
            self.sla_target, sla_color, sla_status, sla_color))
        if slo:
            budget = slo.get("error_budget", {})
            met_str = "MET" if slo.get("met") else "NOT MET"
            met_color = "green" if slo.get("met") else "red"
            lines.append("SLO ({:.3f}%): [bold {}]{}[/bold {}] | Error budget remaining: {:.1f} min ({})".format(
                slo.get("slo_target", self.slo_target), met_color, met_str, met_color,
                budget.get("remaining_minutes", 0), budget.get("status", "N/A")))
        lines.append("Checks: {} | MTBF: {} | MTTR: {}".format(
            check_count,
            "{:.1f}".format(stats["mtbf"]) if stats.get("mtbf") is not None else "n/a",
            "{:.1f}".format(stats["mttr"]) if stats.get("mttr") is not None else "n/a"))
        open_incidents = sum(1 for i in incidents if i.get("status") == "OPEN")
        lines.append("Incidents: {} total | {} open".format(len(incidents), open_incidents))
        lines.append("")
        lines.append("[bold white]Top risks[/bold white]")
        risks = []
        regression = analytics.get("regression", {})
        if regression.get("regression_detected"):
            risks.append("Performance regression: " + str(regression.get("reason", "")))
        predictive = analytics.get("predictive", {})
        if predictive.get("failure_probability", 0) >= 45:
            risks.append("Elevated failure risk: {:.0f}% ({})".format(
                predictive.get("failure_probability", 0), predictive.get("risk_level", "LOW")))
        sla_pred = analytics.get("sla_prediction", {})
        if sla_pred.get("will_breach"):
            risks.append("SLA breach projected at {:.2f}% vs target {:.3f}%".format(
                sla_pred.get("projected_uptime", 0), sla_pred.get("sla_target", self.sla_target)))
        if slo and slo.get("error_budget", {}).get("status") in ("CRITICAL", "EXHAUSTED"):
            risks.append("Error budget {} - consume remaining {:.1f} min carefully".format(
                slo["error_budget"]["status"], slo["error_budget"].get("remaining_minutes", 0)))
        correlation = analytics.get("correlation", {})
        if correlation.get("cascade_detected"):
            risks.append("Correlated multi-cause incident cascade detected")
        if not risks:
            risks.append("No critical risks identified in this window")
        for risk in risks:
            lines.append("  - " + risk)
        lines.append("")
        lines.append("[bold white]Recommendations[/bold white]")
        recommendations = []
        cost = analytics.get("cost", {})
        for hint in cost.get("hints", [])[:2]:
            recommendations.append(hint)
        capacity = analytics.get("capacity", {})
        for hint in capacity.get("hints", [])[:1]:
            recommendations.append(hint)
        if sla_pred.get("will_breach"):
            recommendations.append("Harden availability controls before the projected SLA breach")
        if incidents:
            recommendations.append("Review post-mortems and close open action items")
        if not recommendations:
            recommendations.append("Continue current monitoring cadence - service is within objectives")
        for rec in recommendations[:5]:
            lines.append("  - " + rec)
        roi = analytics.get("roi")
        if roi:
            lines.append("")
            lines.append("[bold white]Monitoring ROI[/bold white]")
            lines.append("  Monthly net benefit: ${:,.2f} | ROI: {:.0f}% | Payback: {:.1f}x".format(
                roi.get("net_benefit_monthly", 0), roi.get("roi_pct", 0), roi.get("payback_ratio", 0)))
            lines.append("  Verdict: {} | {}".format(roi.get("verdict", "N/A"), roi.get("slo_note", "")))
            if roi.get("confidence_note"):
                lines.append("  Note: " + str(roi.get("confidence_note")))
        rum = analytics.get("rum")
        if rum and rum.get("available"):
            vitals = rum.get("vitals", {})
            lines.append("")
            lines.append("[bold white]Real User Experience[/bold white]")
            lines.append("  Samples: {} | Apdex: {:.3f} | LCP: {:.0f}ms ({})".format(
                rum.get("sample_count", 0), rum.get("apdex", 0),
                vitals.get("lcp_ms", 0), rum.get("grades", {}).get("lcp", "n/a")))
            if rum.get("poor_vitals", 0) > 0:
                lines.append("  [bold yellow]{} vitals in poor range[/bold yellow]".format(rum.get("poor_vitals", 0)))
        synth = analytics.get("synthetic")
        if synth and synth.get("journeys_run", 0) > 0:
            lines.append("")
            lines.append("[bold white]Synthetic Journeys[/bold white]")
            lines.append("  Journeys: {} | Success rate: {:.1f}% | Avg: {:.0f}ms".format(
                synth.get("journeys_run", 0), synth.get("success_rate", 0), synth.get("avg_ms", 0)))
        dep_chain = analytics.get("dependency_chain")
        if dep_chain and dep_chain.get("hops", 0) > 0:
            lines.append("")
            lines.append("[bold white]Dependency Chain[/bold white]")
            lines.append("  Health: {:.1f}% | Hops: {}/{} | Critical path: {:.0f}ms | Status: {}".format(
                dep_chain.get("chain_health_pct", 0), dep_chain.get("healthy_hops", 0),
                dep_chain.get("hops", 0), dep_chain.get("critical_path_ms", 0),
                dep_chain.get("status", "N/A")))
        flags = analytics.get("feature_flags")
        if flags and flags.get("detected"):
            lines.append("  Feature flags: {} tracked ({} enabled, {} flapping)".format(
                flags.get("total_flags", 0), flags.get("enabled_count", 0),
                len(flags.get("flapping", []))))
        ab = analytics.get("ab_tests")
        if ab and ab.get("detected"):
            warned = sum(1 for e in ab.get("experiments", []) if e.get("warning"))
            lines.append("  A/B experiments: {} ({} with warnings)".format(
                len(ab.get("experiments", [])), warned))
        automation = analytics.get("incident_response")
        if automation and automation.get("actions"):
            lines.append("  Automation actions executed: {}".format(len(automation.get("actions", []))))
        notifications = analytics.get("notifications")
        if notifications:
            lines.append("  Stakeholder notifications sent: {}".format(len(notifications)))
        fatigue = analytics.get("alert_fatigue")
        if fatigue and fatigue.get("total_evaluated", 0) > 0:
            lines.append("")
            lines.append("[bold white]Alert Hygiene[/bold white]")
            lines.append("  Evaluated: {} | Sent: {} | Suppressed: {} ({:.1f}% noise removed)".format(
                fatigue.get("total_evaluated", 0), fatigue.get("alerts_sent", 0),
                fatigue.get("alerts_suppressed", 0), fatigue.get("suppression_pct", 0)))
            lines.append("  Noise score: {:.1f}/100".format(fatigue.get("noise_score", 0)))
        service_map = analytics.get("service_map")
        if service_map and service_map.get("node_count", 0) > 0:
            lines.append("")
            lines.append("[bold white]Service Dependency Map[/bold white]")
            lines.append("  Nodes: {} | Edges: {} | Status: {} | Blast radius: {} node(s)".format(
                service_map.get("node_count", 0), service_map.get("edge_count", 0),
                service_map.get("status", "N/A"), service_map.get("blast_radius_count", 0)))
            if service_map.get("critical_at_risk"):
                lines.append("  [bold red]Critical services at risk: {}[/bold red]".format(
                    ", ".join(service_map["critical_at_risk"])))
        cascade = analytics.get("cascade")
        if cascade and cascade.get("detected"):
            lines.append("")
            lines.append("[bold yellow]Cascading Failure Detected[/bold yellow]")
            lines.append("  Chains: {} | Max depth: {} | Risk: {}".format(
                cascade.get("chain_count", 0), cascade.get("max_depth", 0),
                cascade.get("risk", "LOW")))
        oncall = analytics.get("oncall")
        if oncall and oncall.get("stats", {}).get("incidents_evaluated", 0) > 0:
            oc_stats = oncall.get("stats", {})
            lines.append("")
            lines.append("[bold white]On-Call Simulation[/bold white]")
            lines.append("  Ack rate: {:.1f}% | Unacked events: {} | Handoffs: {}".format(
                oc_stats.get("ack_rate_pct", 0), oc_stats.get("unacked_events", 0),
                oc_stats.get("handoff_events", 0)))
        maintenance = analytics.get("maintenance")
        if maintenance and maintenance.get("total_windows", 0) > 0:
            lines.append("")
            lines.append("[bold white]Maintenance Windows[/bold white]")
            lines.append("  Windows: {} | Active now: {} | Suppressed alerts: {}".format(
                maintenance.get("total_windows", 0),
                "yes" if maintenance.get("active") else "no",
                maintenance.get("suppressed_total", 0)))
        forecast = analytics.get("sla_forecast_refined")
        if forecast and forecast.get("available"):
            lines.append("")
            lines.append("[bold white]SLA Forecast (Refined)[/bold white]")
            lines.append("  Trend: {} | First breach horizon: {}".format(
                forecast.get("trend", "n/a"),
                forecast.get("first_breach_horizon") or "none within 30d"))
            for horizon in forecast.get("horizons", []):
                mark = "OK" if horizon.get("compliant") else "AT RISK"
                lines.append("    {}: {:.3f}% vs {:.3f}% - {}".format(
                    horizon.get("label", "?"), horizon.get("projected_uptime", 0),
                    horizon.get("target", 0), mark))
        roi_ref = analytics.get("roi_refined")
        if roi_ref and roi_ref.get("available"):
            best = roi_ref.get("best_scenario") or {}
            lines.append("")
            lines.append("[bold white]ROI Scenarios (Refined)[/bold white]")
            lines.append("  Monthly downtime risk: ${:,.2f} | Breakeven capture: {:.1f}%".format(
                roi_ref.get("monthly_downtime_risk", 0),
                roi_ref.get("breakeven_capture_rate_pct", 0)))
            lines.append("  Best scenario: {} (net ${:,.2f}/mo, ROI {:.0f}%)".format(
                best.get("scenario", "n/a"), best.get("net_benefit_monthly", 0),
                best.get("roi_pct", 0)))
        return lines

    def technical_deep_dive(self, stats, analytics, slo, incidents):
        lines = []
        pcts = stats.get("percentiles", {})
        lines.append("[bold white]Latency distribution[/bold white]")
        lines.append("  Avg {:.1f}ms | P50 {:.1f}ms | P90 {:.1f}ms | P95 {:.1f}ms | P99 {:.1f}ms | Max {:.1f}ms".format(
            stats.get("avg_time", 0), pcts.get("p50", 0), pcts.get("p90", 0),
            pcts.get("p95", 0), pcts.get("p99", 0), stats.get("max_time", 0)))
        trend = stats.get("response_time_trend", 0)
        if trend > 1:
            lines.append("  Latency trend: [red]+{:.2f} ms/check (degrading)[/red]".format(trend))
        elif trend < -1:
            lines.append("  Latency trend: [green]{:.2f} ms/check (improving)[/green]".format(trend))
        else:
            lines.append("  Latency trend: stable")
        lines.append("")
        lines.append("[bold white]Reliability[/bold white]")
        lines.append("  Error rate: {:.2f}%".format(stats.get("error_rate", 0)))
        lines.append("  MTBF: {} | MTTR: {}".format(
            "{:.1f} checks".format(stats["mtbf"]) if stats.get("mtbf") is not None else "n/a",
            "{:.1f} checks".format(stats["mttr"]) if stats.get("mttr") is not None else "n/a"))
        if slo:
            budget = slo.get("error_budget", {})
            lines.append("  SLO: {:.3f}% target, actual {:.2f}%, met={}".format(
                slo.get("slo_target", 0), slo.get("actual_uptime", 0), slo.get("met")))
            lines.append("  Error budget: {:.1f}/{:.1f} min used ({}), burn rate {:.2f}x".format(
                budget.get("consumed_minutes", 0), budget.get("allowed_minutes", 0),
                budget.get("status", "N/A"), slo.get("burn_rate", 0)))
        regression = analytics.get("regression", {})
        lines.append("")
        lines.append("[bold white]Regression & anomalies[/bold white]")
        lines.append("  Regression: {} (slope {:.2f} ms/check, confidence {:.0f}%)".format(
            "DETECTED" if regression.get("regression_detected") else "none",
            regression.get("slope", 0), regression.get("confidence", 0)))
        anomalies = analytics.get("anomalies", {})
        lines.append("  Anomalies: {} (mean {:.0f}ms, stdev {:.0f}ms)".format(
            anomalies.get("count", 0), anomalies.get("mean", 0), anomalies.get("stdev", 0)))
        predictive = analytics.get("predictive", {})
        lines.append("")
        lines.append("[bold white]Predictive signals[/bold white]")
        lines.append("  Failure probability: {:.1f}% ({}) over {}".format(
            predictive.get("failure_probability", 0),
            predictive.get("risk_level", "LOW"),
            predictive.get("horizon", "n/a")))
        for factor in predictive.get("factors", [])[:4]:
            lines.append("  - " + factor)
        seasonality = analytics.get("seasonality", {})
        lines.append("  Seasonal pattern: {} (strength {:.0f})".format(
            seasonality.get("pattern", "n/a"), seasonality.get("strength", 0)))
        cap_forecast = analytics.get("capacity_forecast", {})
        if cap_forecast.get("status") == "NO_DATA":
            lines.append("  Capacity utilization: insufficient latency samples to forecast")
        else:
            breach = cap_forecast.get("checks_until_breach")
            if breach is not None:
                breach_txt = "breach projected in {} checks".format(breach)
            else:
                breach_txt = "no breach projected at current trend"
            lines.append("  Capacity utilization: {:.1f}% of {:.0f}ms limit ({}); {}".format(
                cap_forecast.get("utilization_pct", 0),
                cap_forecast.get("capacity_limit_ms", 0),
                cap_forecast.get("status", "N/A"),
                breach_txt))
        lines.append("")
        lines.append("[bold white]Incident operations[/bold white]")
        correlation = analytics.get("correlation", {})
        lines.append("  Correlation clusters: {} | correlated pairs: {} | cascade: {}".format(
            len(correlation.get("clusters", [])),
            correlation.get("correlated_pairs", 0),
            "YES" if correlation.get("cascade_detected") else "no"))
        escalation = analytics.get("escalation", {})
        esc_stats = escalation.get("stats", {})
        lines.append("  Escalation sim: {}/{} escalated, {} would page executives".format(
            esc_stats.get("escalated_count", 0),
            esc_stats.get("incidents_evaluated", 0),
            esc_stats.get("exec_page_count", 0)))
        sev_counts = {}
        for inc in incidents:
            sev = inc.get("severity", "LOW")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        if sev_counts:
            parts = ["{}={}".format(s, sev_counts[s]) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if s in sev_counts]
            lines.append("  Severity mix: " + ", ".join(parts))
        rum = analytics.get("rum")
        lines.append("")
        lines.append("[bold white]Real user monitoring[/bold white]")
        if rum and rum.get("available"):
            vitals = rum.get("vitals", {})
            grades = rum.get("grades", {})
            lines.append("  Samples: {} | Apdex: {:.3f}".format(rum.get("sample_count", 0), rum.get("apdex", 0)))
            lines.append("  TTFB: {:.0f}ms ({}) | FCP: {:.0f}ms ({}) | LCP: {:.0f}ms ({})".format(
                vitals.get("ttfb_ms", 0), grades.get("ttfb", "n/a"),
                vitals.get("fcp_ms", 0), grades.get("fcp", "n/a"),
                vitals.get("lcp_ms", 0), grades.get("lcp", "n/a")))
            lines.append("  INP: {:.0f}ms ({}) | CLS: {:.3f} ({})".format(
                vitals.get("inp_ms", 0), grades.get("inp", "n/a"),
                vitals.get("cls", 0), grades.get("cls", "n/a")))
            breakdown = rum.get("user_breakdown", {})
            if breakdown:
                lines.append("  User segments: {} satisfied / {} tolerating / {} frustrated".format(
                    breakdown.get("satisfied", 0), breakdown.get("tolerating", 0),
                    breakdown.get("frustrated", 0)))
        else:
            lines.append("  " + str(rum.get("notes", "RUM data unavailable")) if rum else "RUM not enabled")
        synth = analytics.get("synthetic")
        lines.append("")
        lines.append("[bold white]Synthetic monitoring[/bold white]")
        if synth and synth.get("journeys_run", 0) > 0:
            lines.append("  Journeys run: {} | Success rate: {:.1f}% | Avg duration: {:.0f}ms".format(
                synth.get("journeys_run", 0), synth.get("success_rate", 0), synth.get("avg_ms", 0)))
            last = synth.get("last") or {}
            if last:
                lines.append("  Last journey: {}/{} steps passed in {:.0f}ms".format(
                    last.get("steps_passed", 0), last.get("steps_total", 0), last.get("total_ms", 0)))
                for step in last.get("steps", [])[:5]:
                    mark = "[green]ok[/green]" if step.get("success") else "[red]fail[/red]"
                    lines.append("    - {} {} {:.0f}ms".format(
                        step.get("name", "?"), mark, step.get("response_ms", 0)))
        else:
            lines.append("  No synthetic journeys executed this session")
        dep_chain = analytics.get("dependency_chain")
        lines.append("")
        lines.append("[bold white]Dependency chain[/bold white]")
        if dep_chain and dep_chain.get("hops", 0) > 0:
            lines.append("  Status: {} | Chain health: {:.1f}% | Critical path: {:.0f}ms".format(
                dep_chain.get("status", "N/A"), dep_chain.get("chain_health_pct", 0),
                dep_chain.get("critical_path_ms", 0)))
            for hop in dep_chain.get("chain", [])[:8]:
                hop_mark = "[green]ok[/green]" if hop.get("healthy") else "[red]fail[/red]"
                lines.append("    hop {}: {} {} {:.0f}ms".format(
                    hop.get("hop", 0), hop.get("host", "?"), hop_mark,
                    hop.get("hop_latency_ms", 0)))
            spof = dep_chain.get("single_points_of_failure", [])
            if spof:
                lines.append("  [bold red]Single points of failure:[/bold red] " + ", ".join(spof))
        else:
            lines.append("  Dependency chain monitoring not enabled")
        flags = analytics.get("feature_flags")
        if flags and flags.get("detected"):
            lines.append("")
            lines.append("[bold white]Feature flags[/bold white]")
            for flag in flags.get("flags", [])[:8]:
                state_color = "green" if flag.get("enabled") else "dim"
                flapping_note = " [yellow](flapping)[/yellow]" if flag.get("name") in flags.get("flapping", []) else ""
                lines.append("  - {}: [{}]{}[/{}]{} changes={}".format(
                    flag.get("name", "?"), state_color, flag.get("state", "?"), state_color,
                    flapping_note, flag.get("changes", 0)))
        ab = analytics.get("ab_tests")
        if ab and ab.get("detected"):
            lines.append("")
            lines.append("[bold white]A/B test monitoring[/bold white]")
            for exp in ab.get("experiments", [])[:5]:
                lines.append("  Experiment: {} ({} assignments)".format(
                    exp.get("experiment", "?"), exp.get("total_assignments", 0)))
                for variant in exp.get("variants", []):
                    lines.append("    - {}: {:.1f}% traffic, {:.0f}ms avg".format(
                        variant.get("variant", "?"), variant.get("traffic_share_pct", 0),
                        variant.get("avg_latency_ms", 0)))
                if exp.get("warning"):
                    lines.append("  [yellow]Warning: {}[/yellow]".format(exp["warning"]))
        automation = analytics.get("incident_response")
        if automation and automation.get("actions"):
            lines.append("")
            lines.append("[bold white]Incident response automation[/bold white]")
            action_counts = {}
            for action in automation.get("actions", []):
                name = action.get("action", "unknown")
                action_counts[name] = action_counts.get(name, 0) + 1
            parts = ["{}x {}".format(cnt, name) for name, cnt in sorted(action_counts.items())]
            lines.append("  " + ", ".join(parts))
            runbook_map = automation.get("runbooks_attached", {})
            for inc_id, rb in list(runbook_map.items())[:3]:
                lines.append("  {} -> {} ({}, est {}m)".format(
                    inc_id, rb.get("runbook_id", "?"), rb.get("title", "?"),
                    rb.get("estimated_minutes", 0)))
        notifications = analytics.get("notifications")
        if notifications:
            lines.append("")
            lines.append("[bold white]Stakeholder notifications[/bold white]")
            for note in notifications[:5]:
                recips = ", ".join(r.get("role", "?") for r in note.get("recipients", []))
                lines.append("  {} [{}] -> {} ({})".format(
                    note.get("incident_id", "?"), note.get("template", "?"),
                    recips, note.get("delivery", "?")))
        fatigue = analytics.get("alert_fatigue")
        if fatigue and fatigue.get("total_evaluated", 0) > 0:
            lines.append("")
            lines.append("[bold white]Alert fatigue analysis[/bold white]")
            lines.append("  Sent: {} | Suppressed: {} | Suppression rate: {:.1f}%".format(
                fatigue.get("alerts_sent", 0), fatigue.get("alerts_suppressed", 0),
                fatigue.get("suppression_pct", 0)))
            reasons = fatigue.get("suppression_reasons", {})
            if reasons:
                parts = ["{}={}".format(k, v) for k, v in sorted(reasons.items())]
                lines.append("  Suppression reasons: " + ", ".join(parts))
        service_map = analytics.get("service_map")
        if service_map and service_map.get("node_count", 0) > 0:
            lines.append("")
            lines.append("[bold white]Service dependency map (refined)[/bold white]")
            lines.append("  {} nodes / {} edges | status {} | blast radius {}".format(
                service_map.get("node_count", 0), service_map.get("edge_count", 0),
                service_map.get("status", "N/A"), service_map.get("blast_radius_count", 0)))
            tier_info = service_map.get("tiers", {})
            for tier_id in sorted(tier_info.keys()):
                members = tier_info[tier_id]
                lines.append("    Tier {}: {}".format(tier_id, ", ".join(str(m) for m in members[:6])))
            down = service_map.get("down_nodes", [])
            if down:
                lines.append("  [red]Down: {}[/red]".format(", ".join(str(d) for d in down)))
        cascade = analytics.get("cascade")
        if cascade:
            lines.append("")
            lines.append("[bold white]Cascading failure detection[/bold white]")
            lines.append("  Detected: {} | Chains: {} | Max depth: {} | Risk: {}".format(
                "YES" if cascade.get("detected") else "no",
                cascade.get("chain_count", 0), cascade.get("max_depth", 0),
                cascade.get("risk", "LOW")))
            for chain in cascade.get("chains", [])[:4]:
                lines.append("    {} depth={} sev={} span={:.0f}s: {}".format(
                    chain.get("chain_id", "?"), chain.get("depth", 0),
                    chain.get("max_severity", "?"), chain.get("span_seconds", 0),
                    " -> ".join(str(c) for c in chain.get("categories", []))))
        maintenance = analytics.get("maintenance")
        if maintenance and maintenance.get("total_windows", 0) > 0:
            lines.append("")
            lines.append("[bold white]Maintenance window automation[/bold white]")
            lines.append("  Windows: {} | Active: {} | Suppressed: {} | Next in {} min".format(
                maintenance.get("total_windows", 0),
                "YES" if maintenance.get("active") else "no",
                maintenance.get("suppressed_total", 0),
                maintenance.get("minutes_until_next") if maintenance.get("minutes_until_next") is not None else "n/a"))
            for window in maintenance.get("windows", [])[:5]:
                lines.append("    {} [{}]: suppressed {}".format(
                    window.get("id", "?"), window.get("label", "?"),
                    window.get("suppressed_alerts", 0)))
        oncall = analytics.get("oncall")
        if oncall and oncall.get("stats", {}).get("incidents_evaluated", 0) > 0:
            oc_stats = oncall.get("stats", {})
            lines.append("")
            lines.append("[bold white]On-call simulation (refined)[/bold white]")
            lines.append("  Ack rate: {:.1f}% | Role pages: {} | Unacked: {} | Handoffs: {}".format(
                oc_stats.get("ack_rate_pct", 0),
                ", ".join("{}:{}".format(r, c) for r, c in oc_stats.get("role_pages", {}).items()) or "none",
                oc_stats.get("unacked_events", 0), oc_stats.get("handoff_events", 0)))
            for sim in oncall.get("simulations", [])[:5]:
                responders = ", ".join(
                    "{}@{}".format(r.get("oncall", "?"), r.get("role", "?"))
                    for r in sim.get("responders", []))
                lines.append("    {} [{}] ack={} handoffs={}: {}".format(
                    sim.get("incident_id", "?"), sim.get("severity", "?"),
                    "yes" if sim.get("all_acked") else "no",
                    sim.get("handoffs", 0), responders or "none"))
        cap_refine = analytics.get("capacity_refined")
        if cap_refine and cap_refine.get("available"):
            lines.append("")
            lines.append("[bold white]Capacity planning (refined)[/bold white]")
            lines.append("  P50 {:.0f}ms | P95 {:.0f}ms | P99 {:.0f}ms | Headroom {:.1f}% -> {:.1f}% [{}]".format(
                cap_refine.get("p50_ms", 0), cap_refine.get("p95_ms", 0),
                cap_refine.get("p99_ms", 0), cap_refine.get("headroom_pct", 0),
                cap_refine.get("projected_headroom_pct", 0), cap_refine.get("posture", "n/a")))
            for rec in cap_refine.get("recommendations", [])[:4]:
                lines.append("  - " + rec)
        cost_refine = analytics.get("cost_refined")
        if cost_refine and cost_refine.get("available"):
            lines.append("")
            lines.append("[bold white]Cost optimization (refined)[/bold white]")
            lines.append("  Efficiency: {:.1f}/100 | Monthly volume: {:,} | Safe to reduce: {}".format(
                cost_refine.get("efficiency_score", 0),
                cost_refine.get("monthly_probe_volume", 0),
                "yes" if cost_refine.get("safe_to_reduce_interval") else "no"))
            recommended = cost_refine.get("recommended")
            if recommended:
                lines.append("  Recommended interval: {}s ({:,} checks/mo, -{}% volume)".format(
                    recommended.get("interval_seconds", 0),
                    recommended.get("monthly_checks", 0),
                    recommended.get("volume_reduction_pct", 0)))
            flags = cost_refine.get("overhead_flags", [])
            if flags:
                lines.append("  Overhead flags: " + ", ".join(flags))
        forecast = analytics.get("sla_forecast_refined")
        if forecast and forecast.get("available"):
            lines.append("")
            lines.append("[bold white]SLA forecast (refined deep dive)[/bold white]")
            lines.append("  Current {:.3f}% | slope {:.4f}%/check | confidence {:.0f}%".format(
                forecast.get("current_uptime", 0), forecast.get("slope_per_check", 0),
                forecast.get("confidence", 0)))
            for horizon in forecast.get("horizons", []):
                lines.append("    {} projected {:.4f}% vs {:.3f}% - {} (delta {:+.4f})".format(
                    horizon.get("label", "?"), horizon.get("projected_uptime", 0),
                    horizon.get("target", 0),
                    "COMPLIANT" if horizon.get("compliant") else "AT RISK",
                    horizon.get("delta_vs_target", 0)))
        pred_refine = analytics.get("predictive_refined")
        if pred_refine:
            lines.append("")
            lines.append("[bold white]Predictive analytics (refined)[/bold white]")
            band = pred_refine.get("risk_band", "STABLE")
            band_color = "red" if band in ("SEVERE", "ELEVATED") else (
                "yellow" if band == "GUARDED" else "green")
            lines.append("  Risk band: [bold {}]{}[/bold {}] (score {:.1f}/100, confidence {:.0f}%)".format(
                band_color, band, band_color,
                pred_refine.get("risk_score", 0), pred_refine.get("confidence", 0)))
            for factor in pred_refine.get("factors", [])[:5]:
                lines.append("  - " + factor)
        roi_refine = analytics.get("roi_refined")
        if roi_refine and roi_refine.get("available"):
            lines.append("")
            lines.append("[bold white]ROI analysis (refined scenarios)[/bold white]")
            lines.append("  Monthly downtime risk: ${:,.2f} at {:.3f}% uptime".format(
                roi_refine.get("monthly_downtime_risk", 0),
                roi_refine.get("current_uptime", 0)))
            for scenario in roi_refine.get("scenarios", []):
                mark = "[green]positive[/green]" if scenario.get("positive") else "[red]negative[/red]"
                lines.append("    {}: capture {:.0f}% -> net ${:,.2f}/mo (ROI {:.0f}%) {}".format(
                    scenario.get("scenario", "?"), scenario.get("capture_rate_pct", 0),
                    scenario.get("net_benefit_monthly", 0), scenario.get("roi_pct", 0), mark))
            lines.append("  Breakeven capture rate: {:.1f}%".format(
                roi_refine.get("breakeven_capture_rate_pct", 0)))
        return lines

    def trend_analysis_with_projections(self, analytics):
        lines = []
        trend = analytics.get("uptime_trend", {})
        projection = analytics.get("projection", {})
        regression = analytics.get("regression", {})
        lines.append("Uptime trend: " + str(trend.get("trend", "unknown")).upper() +
                     " | checks: {}".format(trend.get("total_checks", 0)))
        windows = trend.get("windows", [])
        if windows:
            lines.append("Uptime windows: " + " -> ".join("{:.1f}%".format(w) for w in windows[-6:]))
        direction = projection.get("direction", "insufficient_data")
        dir_color = "green" if direction == "improving" else ("red" if direction == "degrading" else "cyan")
        lines.append("Latency extrapolation: [bold {}]{}[/bold {}] (slope {:.2f} ms/check, confidence {:.0f}%)".format(
            dir_color, direction.upper(), dir_color,
            projection.get("latency_slope", 0), projection.get("confidence", 0)))
        lat_proj = projection.get("latency_projection", [])
        if lat_proj:
            preview = ", ".join("{:.0f}".format(v) for v in lat_proj[:8])
            lines.append("Latency projection (next {}): [{}]".format(len(lat_proj), preview))
        up_proj = projection.get("uptime_projection", [])
        if up_proj:
            preview = ", ".join("{:.2f}%".format(v) for v in up_proj[:8])
            lines.append("Uptime projection (next {}): [{}]".format(len(up_proj), preview))
        if regression.get("regression_detected"):
            lines.append("[bold red]Regression anchors the projection - treat future latency as an upper risk band[/bold red]")
        seasonality = analytics.get("seasonality", {})
        if seasonality.get("pattern") not in (None, "insufficient_data"):
            lines.append("Seasonality: {} (peak bucket {}, strength {:.0f})".format(
                seasonality.get("pattern"), seasonality.get("peak_bucket"),
                seasonality.get("strength", 0)))
            if seasonality.get("bucket_means"):
                means = ", ".join("{:.0f}".format(m) for m in seasonality["bucket_means"])
                lines.append("Bucket means: [{}]".format(means))
        ensemble = analytics.get("predictive_ensemble")
        if ensemble and ensemble.get("model_votes"):
            lines.append("Ensemble failure forecast: {:.1f}% ({}, confidence {:.0f}%)".format(
                ensemble.get("probability", 0), ensemble.get("risk_level", "LOW"),
                ensemble.get("confidence", 0)))
            for vote in ensemble.get("model_votes", []):
                lines.append("  model {}: {:.1f}% risk".format(vote.get("model", "?"), vote.get("risk", 0)))
        rolling = analytics.get("rolling_stats")
        if rolling and rolling.get("available"):
            lines.append("Rolling avg (last {}): {:.0f}ms vs overall {:.0f}ms (momentum {:+.1f}%)".format(
                rolling.get("window", 0), rolling.get("recent_avg_ms", 0),
                rolling.get("overall_avg_ms", 0), rolling.get("momentum_pct", 0)))
        scale_rec = analytics.get("scale_recommendation")
        if scale_rec and scale_rec.get("action") not in (None, "insufficient_data"):
            lines.append("Capacity action: [bold {}]{}[/bold {}] - {}".format(
                "yellow" if "SCALE" in scale_rec.get("action", "") else "cyan",
                scale_rec.get("action", "?"),
                "yellow" if "SCALE" in scale_rec.get("action", "") else "cyan",
                scale_rec.get("rationale", "")))
        pred_refine = analytics.get("predictive_refined")
        if pred_refine:
            band = pred_refine.get("risk_band", "STABLE")
            band_color = "red" if band in ("SEVERE", "ELEVATED") else (
                "yellow" if band == "GUARDED" else "green")
            lines.append("Refined predictive band: [bold {}]{}[/bold {}] (score {:.1f})".format(
                band_color, band, band_color, pred_refine.get("risk_score", 0)))
            for factor in pred_refine.get("factors", [])[:3]:
                lines.append("  - " + factor)
        cap_refine = analytics.get("capacity_refined")
        if cap_refine and cap_refine.get("available"):
            lines.append("Refined capacity headroom: {:.1f}% now -> {:.1f}% projected [{}]".format(
                cap_refine.get("headroom_pct", 0),
                cap_refine.get("projected_headroom_pct", 0),
                cap_refine.get("posture", "n/a")))
        cascade = analytics.get("cascade")
        if cascade and cascade.get("detected"):
            lines.append("[bold yellow]Cascade risk: {} chain(s), max depth {}[/bold yellow]".format(
                cascade.get("chain_count", 0), cascade.get("max_depth", 0)))
        return lines

    def sla_compliance_forecast(self, analytics, slo, uptime_pct):
        lines = []
        sla_pred = analytics.get("sla_prediction", {})
        lines.append("Current uptime: {:.2f}% | SLA target: {:.3f}% | SLO target: {:.3f}%".format(
            uptime_pct, self.sla_target, self.slo_target))
        compliant, status = EnhancedStats.sla_compliance(uptime_pct, self.sla_target)
        color = "green" if compliant else "red"
        lines.append("Current compliance: [bold {}]{}[/bold {}]".format(color, status, color))
        if sla_pred:
            breach_color = "red" if sla_pred.get("will_breach") else "green"
            lines.append("Projected uptime: [bold {}]{:.2f}%[/bold {}] | breach risk: [bold {}]{}[/bold {}] | confidence {:.0f}%".format(
                breach_color, sla_pred.get("projected_uptime", 0), breach_color,
                breach_color, "YES" if sla_pred.get("will_breach") else "NO",
                breach_color, sla_pred.get("confidence", 0)))
            lines.append("Trend: {:.4f}%/check | {}".format(
                sla_pred.get("slope", 0), sla_pred.get("reason", "")))
        if slo:
            budget = slo.get("error_budget", {})
            budget_color = "green" if budget.get("status") == "OK" else (
                "yellow" if budget.get("status") in ("WARNING", "CRITICAL") else "red")
            lines.append("Error budget: [bold {}]{}[/bold {}] - {:.1f} min remaining of {:.1f} min".format(
                budget_color, budget.get("status", "N/A"), budget_color,
                budget.get("remaining_minutes", 0), budget.get("allowed_minutes", 0)))
            lines.append("Burn rate: {:.2f}x nominal".format(slo.get("burn_rate", 0)))
            exhaustion = slo.get("projected_exhaustion_minutes")
            if exhaustion is not None:
                if exhaustion <= 0:
                    lines.append("[bold red]Error budget already exhausted[/bold red]")
                else:
                    lines.append("Projected budget exhaustion in {:.1f} minutes of equivalent runtime".format(exhaustion))
        forecast = analytics.get("capacity_forecast", {})
        if forecast.get("utilization_pct"):
            lines.append("Latency capacity utilization: {:.1f}% (headroom {:.0f}ms)".format(
                forecast.get("utilization_pct", 0), forecast.get("headroom_ms", 0)))
        windows = analytics.get("sla_windows")
        if windows and windows.get("windows"):
            lines.append("")
            lines.append("[bold white]Multi-window SLA forecast[/bold white]")
            for w in windows.get("windows", []):
                color = "green" if w.get("compliant") else "red"
                lines.append("  {}: projected {:.3f}% vs target {:.3f}% - [{}]{}[/{}]".format(
                    w.get("label", "?"), w.get("projected_uptime", 0), w.get("target", 0),
                    color, "COMPLIANT" if w.get("compliant") else "AT RISK", color))
        ttb = analytics.get("time_to_breach")
        if ttb and ttb.get("checks_until_sla_breach") is not None:
            lines.append("Time to SLA breach: {} checks (~{} minutes) on current trend".format(
                ttb.get("checks_until_sla_breach"), ttb.get("minutes_until_sla_breach")))
        elif ttb and ttb.get("basis") == "no_declining_trend":
            lines.append("Time to SLA breach: no declining trend detected - breach not projected")
        budget_forecast = analytics.get("error_budget_forecast")
        if budget_forecast:
            lines.append("Error budget forecast: {} at period end ({:.1f} min projected unused)".format(
                budget_forecast.get("status", "N/A"),
                budget_forecast.get("projected_remaining_minutes", 0)))
        roi = analytics.get("roi")
        if roi:
            lines.append("Monitoring ROI: {:.0f}% (net ${:,.2f}/month, {})".format(
                roi.get("roi_pct", 0), roi.get("net_benefit_monthly", 0),
                roi.get("verdict", "N/A")))
        forecast = analytics.get("sla_forecast_refined")
        if forecast and forecast.get("available"):
            lines.append("")
            lines.append("[bold white]Refined multi-horizon SLA forecast[/bold white]")
            lines.append("  Trend: {} | slope {:.4f}%/check | confidence {:.0f}%".format(
                forecast.get("trend", "n/a").upper(),
                forecast.get("slope_per_check", 0), forecast.get("confidence", 0)))
            for horizon in forecast.get("horizons", []):
                color = "green" if horizon.get("compliant") else "red"
                lines.append("  {}: {:.4f}% vs {:.3f}% - [{}]{}[/{}] (delta {:+.4f})".format(
                    horizon.get("label", "?"), horizon.get("projected_uptime", 0),
                    horizon.get("target", 0), color,
                    "COMPLIANT" if horizon.get("compliant") else "AT RISK", color,
                    horizon.get("delta_vs_target", 0)))
            first_breach = forecast.get("first_breach_horizon")
            if first_breach:
                lines.append("  [bold yellow]First projected breach within: {}[/bold yellow]".format(first_breach))
            else:
                lines.append("  [bold green]No breach projected within 30 days at current trend[/bold green]")
        roi_refine = analytics.get("roi_refined")
        if roi_refine and roi_refine.get("available"):
            lines.append("Breakeven capture rate: {:.1f}% (monitoring pays for itself above this)".format(
                roi_refine.get("breakeven_capture_rate_pct", 0)))
        return lines


class UptimeChecker:
    def __init__(self, url=None, timeout=15, count=1, interval=5, export="none",
                 no_color=False, follow_redirects=True, expect=None,
                 circuit_breaker_threshold=5, exponential_backoff=False,
                 jitter=False, extended_checks=False, sla_target=99.9,
                 protocol="http", tcp_target=None, smtp_host=None, smtp_port=587,
                 ftp_host=None, ssh_host=None, ssh_port=22, ping_host=None,
                 dns_host=None, dns_record_type="A", webhook=None,
                 health_endpoint=None, synthetic_method="GET",
                 synthetic_body=None, synthetic_headers=None,
                  doh_server=None, multi_region=False, regions=None,
                  analytics=False, slo_target=None, slo_period_days=30,
                  exec_summary=False, deep_dive=False,
                  postmortem=False, full_report=False,
                  rum=False, rum_file=None, ab_test=False,
                  feature_flags=False, dependency_chain=False,
                  incident_automation=False, stakeholders=None,
                   roi=False, synthetic_journey=False,
                   hourly_downtime_cost=500.0,
                   service_map=False, cascade_detect=False,
                   maintenance_windows=None, alert_fatigue=False,
                   oncall_sim=False):
        self.url = url
        if url and not url.startswith("http") and protocol == "http":
            self.url = "https://" + url
        self.timeout = timeout
        self.count = count
        self.interval = interval
        self.export = export
        self.no_color = no_color
        self.follow_redirects = follow_redirects
        self.expect = expect
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.exponential_backoff = exponential_backoff
        self.jitter = jitter
        self.extended_checks = extended_checks
        self.sla_target = sla_target
        self.protocol = protocol
        self.tcp_target = tcp_target
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.ftp_host = ftp_host
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ping_host = ping_host
        self.dns_host = dns_host
        self.dns_record_type = dns_record_type
        self.webhook = webhook
        self.health_endpoint = health_endpoint
        self.synthetic_method = synthetic_method
        self.synthetic_body = synthetic_body
        self.synthetic_headers = synthetic_headers or {}
        self.doh_server = doh_server or "https://cloudflare-dns.com/dns-query"
        self.multi_region = multi_region
        self.regions = regions or list(REGIONS.keys())
        self.analytics = analytics
        self.slo_target = slo_target if slo_target is not None else sla_target
        self.slo_period_days = slo_period_days
        self.exec_summary = exec_summary
        self.deep_dive = deep_dive
        self.postmortem = postmortem
        self.full_report = full_report
        self.postmortems = []
        self.results = []
        self.dns_info = {}
        self.ssl_info = {}
        self.headers_info = {}
        self.redirect_chain = []
        self.content_info = {}
        self.score = 100
        self.circuit_breaker = CircuitBreaker(failure_threshold=circuit_breaker_threshold)
        self.incident_tracker = IncidentTracker()
        self.extended_info = {}
        self.dependencies = []
        self.dns_store = DNSRecordStore()
        self.hostname = None
        self.target_label = ""
        self.multi_region_monitor = None
        self.analytics_results = {}
        self.rum_enabled = rum
        self.rum_file = rum_file
        self.ab_test_enabled = ab_test
        self.feature_flags_enabled = feature_flags
        self.dependency_chain_enabled = dependency_chain
        self.incident_automation_enabled = incident_automation
        self.stakeholders = stakeholders or []
        self.roi_enabled = roi
        self.synthetic_journey_enabled = synthetic_journey
        self.hourly_downtime_cost = hourly_downtime_cost
        self.service_map_enabled = service_map
        self.cascade_detect_enabled = cascade_detect
        self.alert_fatigue_enabled = alert_fatigue
        self.oncall_sim_enabled = oncall_sim
        self.maintenance_manager = MaintenanceWindowManager()
        for window_spec in (maintenance_windows or []):
            try:
                self.maintenance_manager.add_window(window_spec)
            except Exception:
                pass
        self.dependency_mapper = None
        self.cascade_detector = CascadingFailureDetector()
        self.alert_reducer = AlertFatigueReducer()
        self.oncall_simulator = OnCallSimulator()
        self.rum_monitor = RealUserMonitor()
        self.ab_monitor = ABTestMonitor()
        self.flag_monitor = FeatureFlagMonitor()
        self.dependency_chain_monitor = None
        self.response_automation = IncidentResponseAutomation(enabled=incident_automation)
        self.runbook_library = RunbookLibrary()
        self.notifier = StakeholderNotifier(self.stakeholders, self.webhook)
        self.roi_analyzer = ROIAnalyzer(hourly_downtime_cost=hourly_downtime_cost,
                                        interval=interval, count=count)
        self.synthetic_journey_monitor = None
        self.automation_runbooks = {}
        self._resolution_notified_ids = set()
        self._last_response_headers = {}
        self._last_response_body = ""
        if rum and rum_file:
            try:
                with open(rum_file, "r") as rf:
                    loaded = json.load(rf)
                if isinstance(loaded, list):
                    self.rum_monitor.ingest_samples(loaded)
            except (OSError, json.JSONDecodeError):
                pass

    def _resolve_target(self):
        if self.protocol == "http" and self.url:
            parsed = urlparse(self.url)
            self.hostname = parsed.hostname
        elif self.protocol == "tcp" and self.tcp_target:
            parts = self.tcp_target.split(":")
            self.hostname = parts[0]
        elif self.protocol == "smtp" and self.smtp_host:
            self.hostname = self.smtp_host
        elif self.protocol == "ftp" and self.ftp_host:
            self.hostname = self.ftp_host
        elif self.protocol == "ssh" and self.ssh_host:
            self.hostname = self.ssh_host
        elif self.protocol == "ping" and self.ping_host:
            self.hostname = self.ping_host
        elif self.protocol == "dns" and self.dns_host:
            self.hostname = self.dns_host
        else:
            self.hostname = "unknown"

    def parse_url(self):
        if self.url:
            parsed = urlparse(self.url)
            self.scheme = parsed.scheme
            self.hostname = parsed.hostname
            self.port = parsed.port or (443 if self.scheme == "https" else 80)
            self.path = parsed.path or "/"
        self._resolve_target()
        self.target_label = self._get_target_label()
        return True

    def _get_target_label(self):
        if self.protocol == "http":
            return self.url or "N/A"
        elif self.protocol == "tcp":
            return self.tcp_target or "N/A"
        elif self.protocol == "smtp":
            return "smtp://{}:{}".format(self.smtp_host, self.smtp_port)
        elif self.protocol == "ftp":
            return "ftp://{}".format(self.ftp_host)
        elif self.protocol == "ssh":
            return "ssh://{}:{}".format(self.ssh_host, self.ssh_port)
        elif self.protocol == "ping":
            return "icmp://{}".format(self.ping_host)
        elif self.protocol == "dns":
            return "dns://{}".format(self.dns_host)
        return "N/A"

    def check_http_status(self, resp, index):
        status = resp.status_code
        if 200 <= status < 300:
            category = "OK"
        elif 300 <= status < 400:
            category = "REDIRECT"
        elif 400 <= status < 500:
            category = "CLIENT ERROR"
        elif status >= 500:
            category = "SERVER ERROR"
        else:
            category = "INFORMATIONAL"
        return {"status_code": status, "category": category}

    def check_response_time(self, resp):
        timing = {}
        if hasattr(resp, "raw") and resp.raw is not None:
            try:
                raw = resp.raw._original_response
                if hasattr(raw, "timings"):
                    t = raw.timings
                    timing["dns_resolution"] = t.get("dns", 0) * 1000
                    timing["tcp_connect"] = t.get("connect", 0) * 1000
                    timing["ssl_handshake"] = t.get("appconnect", 0) * 1000
                    timing["ttfb"] = t.get("starttransfer", 0) * 1000
            except Exception:
                pass
        timing["total"] = resp.elapsed.total_seconds() * 1000
        return timing

    def check_tcp(self):
        if not self.tcp_target:
            return {"available": False, "error": "No TCP target specified"}
        parts = self.tcp_target.split(":")
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 443
        start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            elapsed = (time.time() - start) * 1000
            sock.close()
            banner = self._grab_tcp_banner(host, port)
            return {"available": True, "host": host, "port": port,
                    "response_time_ms": round(elapsed, 1), "banner": banner}
        except socket.timeout:
            return {"available": False, "host": host, "port": port, "error": "TIMEOUT"}
        except ConnectionRefusedError:
            return {"available": False, "host": host, "port": port, "error": "CONNECTION_REFUSED"}
        except Exception as e:
            return {"available": False, "host": host, "port": port, "error": str(e)[:100]}

    def _grab_tcp_banner(self, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            sock.send(b"\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            sock.close()
            return banner[:200] if banner else ""
        except Exception:
            return ""

    def check_smtp(self):
        host = self.smtp_host
        port = self.smtp_port
        start = time.time()
        result = {"available": False, "host": host, "port": port,
                  "banner": "", "starttls": False, "auth_methods": [],
                  "response_time_ms": 0, "error": None}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            elapsed = (time.time() - start) * 1000
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            result["banner"] = banner[:200]
            result["response_time_ms"] = round(elapsed, 1)
            if banner.startswith("220"):
                result["available"] = True
            sock.send(b"EHLO uptimechecker.local\r\n")
            ehlo_resp = sock.recv(4096).decode("utf-8", errors="replace")
            ehlo_lower = ehlo_resp.lower()
            if "starttls" in ehlo_lower:
                result["starttls"] = True
                sock.send(b"STARTTLS\r\n")
                tls_resp = sock.recv(1024).decode("utf-8", errors="replace")
                if tls_resp.startswith("220"):
                    ctx = ssl.create_default_context()
                    sock = ctx.wrap_socket(sock, server_hostname=host)
            for line in ehlo_resp.split("\r\n"):
                if line.upper().startswith("250-AUTH"):
                    auth_part = line.split(" ", 1)
                    if len(auth_part) > 1:
                        result["auth_methods"] = auth_part[1].strip().split()
            sock.send(b"QUIT\r\n")
            try:
                sock.recv(1024)
            except Exception:
                pass
            sock.close()
        except socket.timeout:
            result["error"] = "TIMEOUT"
        except ConnectionRefusedError:
            result["error"] = "CONNECTION_REFUSED"
        except Exception as e:
            result["error"] = str(e)[:100]
        return result

    def check_ftp(self):
        host = self.ftp_host
        start = time.time()
        result = {"available": False, "host": host, "port": 21,
                  "banner": "", "anonymous_login": False,
                  "tls_support": False, "response_time_ms": 0, "error": None}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, 21))
            elapsed = (time.time() - start) * 1000
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            result["banner"] = banner[:200]
            result["response_time_ms"] = round(elapsed, 1)
            if banner.startswith("220"):
                result["available"] = True
            sock.send(b"FEAT\r\n")
            feat_resp = sock.recv(4096).decode("utf-8", errors="replace").upper()
            if "TLS" in feat_resp or "SSL" in feat_resp:
                result["tls_support"] = True
            sock.send(b"USER anonymous\r\n")
            user_resp = sock.recv(1024).decode("utf-8", errors="replace")
            if "331" in user_resp:
                sock.send(b"PASS anonymous@\r\n")
                pass_resp = sock.recv(1024).decode("utf-8", errors="replace")
                if "230" in pass_resp:
                    result["anonymous_login"] = True
            sock.send(b"QUIT\r\n")
            try:
                sock.recv(1024)
            except Exception:
                pass
            sock.close()
        except socket.timeout:
            result["error"] = "TIMEOUT"
        except ConnectionRefusedError:
            result["error"] = "CONNECTION_REFUSED"
        except Exception as e:
            result["error"] = str(e)[:100]
        return result

    def check_ssh(self):
        host = self.ssh_host
        port = self.ssh_port
        start = time.time()
        result = {"available": False, "host": host, "port": port,
                  "banner": "", "protocol_version": "", "key_exchange": [],
                  "response_time_ms": 0, "error": None}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            elapsed = (time.time() - start) * 1000
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            result["banner"] = banner[:200]
            result["response_time_ms"] = round(elapsed, 1)
            if banner.startswith("SSH-"):
                result["available"] = True
                parts = banner.split("-")
                if len(parts) >= 3:
                    result["protocol_version"] = parts[1] + "-" + parts[2]
                sock.send(("SSH-2.0-UptimeChecker_" + VERSION + "\r\n").encode())
                try:
                    server_kex = sock.recv(4096).decode("utf-8", errors="replace")
                    kex_match = re.findall(r"kex_algorithms:(.+)", server_kex)
                    if kex_match:
                        result["key_exchange"] = kex_match[0].strip().split(",")
                except Exception:
                    pass
            sock.close()
        except socket.timeout:
            result["error"] = "TIMEOUT"
        except ConnectionRefusedError:
            result["error"] = "CONNECTION_REFUSED"
        except Exception as e:
            result["error"] = str(e)[:100]
        return result

    def check_ping(self):
        host = self.ping_host
        result = {"available": False, "host": host, "packets_sent": 0,
                  "packets_received": 0, "loss_pct": 100.0,
                  "min_rtt": 0, "max_rtt": 0, "avg_rtt": 0, "error": None}
        try:
            ping_count = min(self.count, 5)
            proc = subprocess.run(
                ["ping", "-c", str(ping_count), "-W", str(self.timeout), host],
                capture_output=True, text=True, timeout=self.timeout * ping_count + 5
            )
            output = proc.stdout
            stats_match = re.search(r"(\d+) packets transmitted.*?(\d+) received.*?(\d+(?:\.\d+)?)% packet loss", output)
            if stats_match:
                result["packets_sent"] = int(stats_match.group(1))
                result["packets_received"] = int(stats_match.group(2))
                result["loss_pct"] = float(stats_match.group(3))
                result["available"] = result["packets_received"] > 0
            rtt_match = re.search(r"min/avg/max(?:/mdev)?\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)", output)
            if rtt_match:
                result["min_rtt"] = float(rtt_match.group(1))
                result["avg_rtt"] = float(rtt_match.group(2))
                result["max_rtt"] = float(rtt_match.group(3))
            elif not stats_match:
                result["error"] = "Ping failed: " + proc.stderr.strip()[:100] if proc.stderr else "No response"
        except Exception as e:
            result["error"] = str(e)[:100]
        return result

    def check_dns(self):
        info = {"a_records": [], "aaaa_records": [], "ns_records": [],
                "mx_records": [], "txt_records": [], "cname_records": [],
                "soa_record": {}, "srv_records": [], "caa_records": [],
                "resolution_time": 0, "round_robin": False,
                "propagation": {}, "dnssec": {},
                "spf_record": "", "dkim_record": "",
                "dns_over_https": {}, "ttl_analysis": {},
                "record_changes": {}, "multi_provider": {}}
        start = time.time()
        try:
            ipv4 = socket.getaddrinfo(self.hostname, None, socket.AF_INET)
            info["a_records"] = list(set(r[4][0] for r in ipv4))
        except socket.gaierror:
            pass
        try:
            ipv6 = socket.getaddrinfo(self.hostname, None, socket.AF_INET6)
            info["aaaa_records"] = list(set(r[4][0] for r in ipv6))
        except socket.gaierror:
            pass
        info["resolution_time"] = (time.time() - start) * 1000
        info["round_robin"] = len(info["a_records"]) > 1
        self._query_dig_records(info)
        if self.extended_checks:
            info["propagation"] = self._check_dns_propagation()
            info["dnssec"] = self._check_dnssec()
            info["dns_over_https"] = self._check_doh()
            info["ttl_analysis"] = self._analyze_dns_ttl()
            info["record_changes"] = self._detect_record_changes(info)
            info["multi_provider"] = self._multi_provider_dns_compare()
        return info

    def _query_dig_records(self, info):
        for rtype, key in [("NS", "ns_records"), ("MX", "mx_records"), ("TXT", "txt_records"),
                           ("CNAME", "cname_records"), ("SRV", "srv_records"), ("CAA", "caa_records")]:
            try:
                result = subprocess.run(
                    ["dig", "+short", rtype, self.hostname],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    if rtype == "NS":
                        info[key].append(line.rstrip("."))
                    elif rtype == "MX":
                        parts = line.split()
                        if len(parts) == 2:
                            info[key].append({"priority": parts[0], "host": parts[1].rstrip(".")})
                    elif rtype == "TXT":
                        txt = line.strip().strip('"')
                        if txt:
                            info[key].append(txt)
                            if txt.startswith("v=spf1"):
                                info["spf_record"] = txt
                    elif rtype == "SRV":
                        parts = line.split()
                        if len(parts) >= 4:
                            info[key].append({"priority": parts[0], "weight": parts[1],
                                              "port": parts[2], "target": parts[3].rstrip(".")})
                    elif rtype == "CAA":
                        parts = line.split()
                        if len(parts) >= 3:
                            info[key].append({"flags": parts[0], "tag": parts[1],
                                              "value": parts[2].strip('"')})
                    else:
                        info[key].append(line.rstrip("."))
            except Exception:
                pass
        try:
            result = subprocess.run(
                ["dig", "+short", "SOA", self.hostname],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split("\n"):
                parts = line.strip().split()
                if len(parts) >= 7:
                    info["soa_record"] = {
                        "primary_ns": parts[0].rstrip("."), "admin": parts[1].rstrip("."),
                        "serial": parts[2], "refresh": parts[3], "retry": parts[4],
                        "expire": parts[5], "minimum_ttl": parts[6]}
        except Exception:
            pass
        for selector in ["default", "google", "selector1", "selector2", "k1", "mandrill"]:
            try:
                query_domain = selector + "._domainkey." + self.hostname
                result = subprocess.run(
                    ["dig", "+short", "TXT", query_domain],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.strip().split("\n"):
                    txt = line.strip().strip('"')
                    if txt and ("v=DKIM1" in txt or "k=rsa" in txt):
                        info["dkim_record"] = txt
                        break
                if info["dkim_record"]:
                    break
            except Exception:
                pass

    def _check_dns_propagation(self):
        propagation = {}
        for server_name, server_ip in DNS_SERVERS.items():
            try:
                result = subprocess.run(
                    ["dig", "@" + server_ip, "+short", self.hostname],
                    capture_output=True, text=True, timeout=5
                )
                records = [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
                known = set(self.dns_info.get("a_records", []))
                propagation[server_name] = {"server": server_ip, "records": records,
                                            "consistent": set(records) == known if known else True}
            except Exception:
                propagation[server_name] = {"server": server_ip, "records": [], "consistent": False}
        return propagation

    def _check_dnssec(self):
        info = {"supported": False, "status": "UNKNOWN", "details": "", "chain": []}
        try:
            result = subprocess.run(
                ["dig", "+dnssec", "+short", self.hostname],
                capture_output=True, text=True, timeout=5
            )
            output = result.stdout.lower()
            if "rrsig" in output or "dnskey" in output:
                info["supported"] = True
                info["status"] = "SECURED"
                info["details"] = "DNSSEC signatures detected"
            elif "nsec" in output:
                info["supported"] = True
                info["status"] = "OPTED_OUT"
                info["details"] = "NSEC record found (domain not signed)"
            else:
                info["status"] = "NOT_SECURED"
                info["details"] = "No DNSSEC records found"
            try:
                chain_result = subprocess.run(
                    ["dig", "+dnssec", "+multi", "DNSKEY", self.hostname],
                    capture_output=True, text=True, timeout=5
                )
                for line in chain_result.stdout.strip().split("\n"):
                    if "dnskey" in line.lower() or "rrsig" in line.lower():
                        info["chain"].append(line.strip()[:100])
            except Exception:
                pass
        except Exception:
            info["status"] = "CHECK_FAILED"
            info["details"] = "Unable to query DNSSEC status"
        return info

    def _check_doh(self):
        result = {"supported": False, "records": {}, "latency_ms": 0, "error": None}
        try:
            start = time.time()
            resp = requests.get(
                self.doh_server,
                params={"name": self.hostname, "type": "A"},
                headers={"Accept": "application/dns-json"},
                timeout=self.timeout,
            )
            elapsed = (time.time() - start) * 1000
            result["latency_ms"] = round(elapsed, 1)
            if resp.status_code == 200:
                result["supported"] = True
                data = resp.json()
                answers = data.get("Answer", [])
                result["records"] = {
                    "status": data.get("Status", 0),
                    "answer_count": len(answers),
                    "answers": [{"name": a.get("name", ""), "type": a.get("type", 0),
                                 "data": a.get("data", "")} for a in answers[:10]]}
            else:
                result["error"] = "HTTP " + str(resp.status_code)
        except Exception as e:
            result["error"] = str(e)[:100]
        return result

    def _analyze_dns_ttl(self):
        result = {"records": {}, "avg_ttl": 0, "warning": ""}
        ttl_values = []
        for rtype in ["A", "AAAA", "NS", "MX", "TXT"]:
            try:
                output = subprocess.run(
                    ["dig", "+noall", "+answer", "+ttlid", rtype, self.hostname],
                    capture_output=True, text=True, timeout=5
                )
                for line in output.stdout.strip().split("\n"):
                    parts = line.strip().split()
                    if len(parts) >= 5:
                        try:
                            ttl = int(parts[1])
                            result["records"][rtype] = ttl
                            ttl_values.append(ttl)
                        except (ValueError, IndexError):
                            pass
            except Exception:
                pass
        if ttl_values:
            result["avg_ttl"] = statistics.mean(ttl_values)
            if result["avg_ttl"] < 60:
                result["warning"] = "Very low TTL detected; frequent changes may cause DNS issues"
            elif result["avg_ttl"] < 300:
                result["warning"] = "Low TTL detected; may increase DNS query load"
        return result

    def _detect_record_changes(self, info):
        changes = {}
        for rtype, key in [("A", "a_records"), ("AAAA", "aaaa_records"), ("NS", "ns_records"),
                           ("MX", "mx_records"), ("TXT", "txt_records")]:
            values = info.get(key, [])
            if rtype == "MX":
                values = [m.get("host", "") for m in values]
            changed, previous = self.dns_store.update(self.hostname, rtype, values)
            if changed:
                changes[rtype] = {"previous": previous, "current": values}
        return changes

    def _multi_provider_dns_compare(self):
        result = {}
        providers_to_check = [("Google", "8.8.8.8"), ("Cloudflare", "1.1.1.1"), ("Quad9", "9.9.9.9")]
        primary_records = set(self.dns_info.get("a_records", []))
        for name, ip in providers_to_check:
            try:
                proc = subprocess.run(
                    ["dig", "@" + ip, "+short", self.hostname],
                    capture_output=True, text=True, timeout=5
                )
                records = set(l.strip() for l in proc.stdout.strip().split("\n") if l.strip())
                result[name] = {"server": ip, "records": list(records),
                                "matches_primary": records == primary_records if primary_records else True}
            except Exception:
                result[name] = {"server": ip, "records": [], "matches_primary": False}
        return result

    def check_ssl(self):
        if self.protocol != "http":
            if self.protocol in ("tcp", "smtp"):
                pass
            else:
                return None
        target_host = self.hostname
        target_port = getattr(self, "port", 443)
        if self.protocol == "smtp":
            target_port = self.smtp_port
        info = {"valid": False, "issuer": "", "subject": "", "sans": [],
                "expiry": "", "days_until_expiry": 0, "status": "UNKNOWN",
                "chain_valid": False, "chain_depth": 0, "ocsp_status": "UNKNOWN",
                "ct_logs": [], "hsts_preload": False,
                "protocol_versions": [], "cipher_suite": "",
                "key_size": 0, "signature_algorithm": ""}
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=target_host) as s:
                s.settimeout(self.timeout)
                s.connect((target_host, target_port))
                cert = s.getpeercert()
                info["valid"] = True
                cipher_info = s.cipher()
                if cipher_info:
                    info["cipher_suite"] = cipher_info[0] if cipher_info[0] else ""
                    info["key_size"] = cipher_info[2] if len(cipher_info) > 2 else 0
                info["protocol_versions"] = [str(s.version())] if hasattr(s, "version") and s.version() else []
                issuer_parts = []
                for rdn in cert.get("issuer", ()):
                    for attr in rdn:
                        if attr[0] in ("organizationName", "commonName"):
                            issuer_parts.append(attr[1])
                info["issuer"] = " / ".join(issuer_parts) if issuer_parts else "Unknown"
                subject_parts = []
                for rdn in cert.get("subject", ()):
                    for attr in rdn:
                        if attr[0] == "commonName":
                            subject_parts.append(attr[1])
                info["subject"] = " / ".join(subject_parts) if subject_parts else "Unknown"
                san_ext = [e for e in cert.get("subjectAltName", ()) if e[0] == "DNS"]
                info["sans"] = [e[1] for e in san_ext]
                expiry_str = cert.get("notAfter", "")
                if expiry_str:
                    expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                    expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
                    info["expiry"] = expiry_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                    days = (expiry_dt - datetime.now(timezone.utc)).days
                    info["days_until_expiry"] = days
                    if days < 0:
                        info["status"] = "EXPIRED"
                    elif days < 7:
                        info["status"] = "CRITICAL"
                    elif days < 30:
                        info["status"] = "WARNING"
                    else:
                        info["status"] = "VALID"
                if self.extended_checks:
                    info["chain_valid"] = self._validate_ssl_chain()
                    info["ocsp_status"] = self._check_ocsp()
                    info["ct_logs"] = self._check_ct_logs()
        except ssl.SSLCertVerificationError:
            info["status"] = "INVALID"
            info["valid"] = False
        except Exception:
            info["status"] = "ERROR"
        return info

    def _validate_ssl_chain(self):
        target_host = self.hostname
        target_port = getattr(self, "port", 443)
        try:
            connect_str = target_host + ":" + str(target_port)
            result = subprocess.run(
                ["openssl", "s_client", "-connect", connect_str,
                 "-showcerts", "-servername", target_host],
                input="", capture_output=True, text=True, timeout=10
            )
            output = result.stdout
            verify_return = "Verify return code: 0" in output
            cert_count = output.count("BEGIN CERTIFICATE")
            return {"valid": verify_return, "depth": cert_count}
        except Exception:
            return {"valid": False, "depth": 0}

    def _check_ocsp(self):
        target_host = self.hostname
        target_port = getattr(self, "port", 443)
        try:
            connect_str = target_host + ":" + str(target_port)
            result = subprocess.run(
                ["openssl", "s_client", "-connect", connect_str,
                 "-status", "-servername", target_host],
                input="", capture_output=True, text=True, timeout=10
            )
            output = result.stdout.lower()
            if "ocsp response status: successful" in output:
                if "cert status: good" in output:
                    return "GOOD"
                elif "cert status: revoked" in output:
                    return "REVOKED"
                return "SUCCESSFUL"
            elif "no ocsp response" in output:
                return "NO_RESPONSE"
            return "UNKNOWN"
        except Exception:
            return "CHECK_FAILED"

    def _check_ct_logs(self):
        ct_logs = []
        target_host = self.hostname
        target_port = getattr(self, "port", 443)
        try:
            connect_str = target_host + ":" + str(target_port)
            result = subprocess.run(
                ["openssl", "s_client", "-connect", connect_str,
                 "-servername", target_host],
                input="", capture_output=True, text=True, timeout=10
            )
            output = result.stdout
            if "SCT" in output or "Signed Certificate Timestamp" in output:
                ct_logs.append("SCT found in certificate")
            if "CT Precertificate SCTs" in output:
                ct_logs.append("CT Precertificate SCTs extension present")
        except Exception:
            pass
        if not ct_logs:
            ct_logs.append("No CT logs detected via openssl")
        return ct_logs

    def _check_hsts_preload(self):
        hsts_header = self.headers_info.get("strict_transport_security", "Not specified")
        if hsts_header == "Not specified":
            return {"enabled": False, "preload": False, "on_list": False}
        hsts_lower = hsts_header.lower()
        includes_subdomains = "includesubdomains" in hsts_lower
        has_preload = "preload" in hsts_lower
        on_preload_list = False
        try:
            api_url = "https://hstspreload.org/api/v2/status?domain=" + self.hostname
            resp = requests.get(api_url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                on_preload_list = data.get("status") == "present"
        except Exception:
            pass
        return {"enabled": True, "includes_subdomains": includes_subdomains,
                "preload": has_preload, "on_list": on_preload_list}

    def check_redirects(self, resp):
        chain = []
        if self.follow_redirects and resp.history:
            for r in resp.history:
                chain.append({"url": r.url, "status": r.status_code, "time": r.elapsed.total_seconds() * 1000})
            chain.append({"url": resp.url, "status": resp.status_code, "time": resp.elapsed.total_seconds() * 1000})
        http_to_https = False
        www_redirect = False
        if chain:
            original = urlparse(self.url)
            final = urlparse(chain[-1]["url"])
            if original.scheme == "http" and final.scheme == "https":
                http_to_https = True
            if original.hostname and final.hostname:
                if original.hostname.replace("www.", "") == final.hostname.replace("www.", ""):
                    if original.hostname != final.hostname:
                        www_redirect = True
        return {"chain": chain, "hop_count": len(chain), "http_to_https": http_to_https,
                "www_redirect": www_redirect, "final_url": resp.url}

    def check_content(self, resp):
        info = {"page_size": len(resp.content), "page_size_human": self._human_size(len(resp.content)),
                "content_type": resp.headers.get("Content-Type", "Unknown"),
                "has_expected_content": True, "is_error_page": False}
        if self.expect:
            info["has_expected_content"] = self.expect.lower() in resp.text.lower()
        if resp.status_code >= 400:
            info["is_error_page"] = True
        return info

    def check_headers(self, resp):
        h = resp.headers
        return {"server": h.get("Server", "Not specified"),
                "x_powered_by": h.get("X-Powered-By", "Not specified"),
                "cache_control": h.get("Cache-Control", "Not specified"),
                "content_type": h.get("Content-Type", "Not specified"),
                "connection": h.get("Connection", "Not specified"),
                "strict_transport_security": h.get("Strict-Transport-Security", "Not specified"),
                "x_content_type_options": h.get("X-Content-Type-Options", "Not specified"),
                "x_frame_options": h.get("X-Frame-Options", "Not specified"),
                "content_security_policy": h.get("Content-Security-Policy", "Not specified"),
                "alt_svc": h.get("Alt-Svc", "Not specified")}

    def detect_cdn(self, resp):
        detected = []
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        cookie_names = [c.name.lower() for c in resp.cookies]
        for cdn_name, signatures in CDN_SIGNATURES.items():
            found = False
            for header in signatures.get("headers", []):
                if header.lower() in headers_lower:
                    detected.append(cdn_name)
                    found = True
                    break
            if not found:
                for cookie in signatures.get("cookies", []):
                    if cookie.lower() in cookie_names:
                        detected.append(cdn_name)
                        break
        return detected

    def detect_load_balancer(self, resp):
        detected = []
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        cookie_names = [c.name.lower() for c in resp.cookies]
        for lb_name, signatures in LB_SIGNATURES.items():
            found = False
            for header in signatures.get("headers", []):
                if header.lower() in headers_lower:
                    detected.append(lb_name)
                    found = True
                    break
            if not found:
                for cookie in signatures.get("cookies", []):
                    if cookie.lower() in cookie_names:
                        detected.append(lb_name)
                        break
        return detected

    def detect_technologies(self, resp):
        technologies = []
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        for tech_name, patterns in TECH_PATTERNS.items():
            for pattern_type, keywords in patterns.items():
                for keyword in keywords:
                    header_val = headers_lower.get(pattern_type, "")
                    if keyword.lower() in header_val.lower():
                        technologies.append(tech_name)
                        break
        try:
            body = resp.text.lower()
            for tech, patterns in FRONTEND_TECH.items():
                for pattern in patterns:
                    if pattern in body:
                        if tech not in technologies:
                            technologies.append(tech)
                        break
        except Exception:
            pass
        return list(set(technologies))

    def check_http2_http3(self):
        info = {"http2": False, "http3": False, "http3_alt_svc": ""}
        try:
            result = subprocess.run(
                ["curl", "-sI", "--http2", "-o", "/dev/null", "-w", "%{http_version}", self.url],
                capture_output=True, text=True, timeout=10
            )
            version = result.stdout.strip()
            info["http2"] = version == "2"
        except Exception:
            pass
        alt_svc = self.headers_info.get("alt_svc", "")
        if alt_svc and "h3" in alt_svc.lower():
            info["http3"] = True
            info["http3_alt_svc"] = alt_svc
        return info

    def check_mx_health(self):
        mx_records = self.dns_info.get("mx_records", [])
        if not mx_records:
            return {"records": [], "reachable": False, "details": "No MX records found"}
        results = []
        for mx in mx_records:
            host = mx.get("host", "")
            priority = mx.get("priority", "0")
            reachable = False
            try:
                result = subprocess.run(["dig", "+short", "A", host],
                                        capture_output=True, text=True, timeout=5)
                if result.stdout.strip():
                    reachable = True
            except Exception:
                pass
            results.append({"host": host, "priority": priority, "resolves": reachable})
        any_reachable = any(r["resolves"] for r in results)
        return {"records": results, "reachable": any_reachable}

    def detect_maintenance_window(self, resp):
        indicators = []
        status = resp.status_code
        body_lower = resp.text.lower() if hasattr(resp, "text") else ""
        if status == 503:
            indicators.append("HTTP 503 Service Unavailable")
        if status == 502:
            indicators.append("HTTP 502 Bad Gateway")
        maintenance_keywords = ["maintenance", "scheduled maintenance", "under maintenance",
                                "we'll be back", "back soon", "temporarily unavailable",
                                "service unavailable", "planned outage", "system maintenance"]
        for keyword in maintenance_keywords:
            if keyword in body_lower:
                indicators.append("Keyword: " + keyword)
                break
        return {"detected": len(indicators) > 0, "indicators": indicators}

    def track_dependencies(self, resp):
        deps = []
        try:
            body = resp.text
            scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)
            links = re.findall(r'<link[^>]+href=["\']([^"\']+)["\']', body, re.IGNORECASE)
            images = re.findall(r'<img[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)
            all_urls = scripts + links + images
            seen_domains = set()
            for url in all_urls:
                if url.startswith("//") or url.startswith("http"):
                    parsed_url = urlparse(url if url.startswith("http") else "https:" + url)
                    domain = parsed_url.hostname
                    if domain and domain != self.hostname and domain not in seen_domains:
                        seen_domains.add(domain)
                        dep_type = "script" if url in scripts else ("stylesheet" if url in links else "image")
                        deps.append({"domain": domain, "type": dep_type})
        except Exception:
            pass
        return deps

    def check_geographic_response(self):
        regions = {}
        for server_name, server_ip in list(DNS_SERVERS.items())[:3]:
            start = time.time()
            try:
                result = subprocess.run(
                    ["dig", "@" + server_ip, "+short", "+stats", self.hostname],
                    capture_output=True, text=True, timeout=5
                )
                elapsed = (time.time() - start) * 1000
                resolved = bool(result.stdout.strip())
                regions[server_name] = {"server_ip": server_ip, "resolved": resolved,
                                        "response_time_ms": round(elapsed, 1)}
            except Exception:
                regions[server_name] = {"server_ip": server_ip, "resolved": False, "response_time_ms": -1}
        return regions

    def check_synthetic(self, url=None, method="GET", body=None, headers=None):
        check_url = url or self.url
        if not check_url:
            return {"success": False, "error": "No URL specified"}
        synth_headers = {"User-Agent": "UptimeChecker/" + VERSION}
        if self.synthetic_headers:
            synth_headers.update(self.synthetic_headers)
        if headers:
            synth_headers.update(headers)
        start = time.time()
        result = {"url": check_url, "method": method, "success": False,
                  "status_code": 0, "response_time_ms": 0, "error": None,
                  "response_size": 0, "content_match": False,
                  "assertions": [], "assertions_passed": 0, "assertions_total": 0,
                  "grade": "F"}
        try:
            if method.upper() == "GET":
                resp = requests.get(check_url, headers=synth_headers, timeout=self.timeout,
                                    allow_redirects=self.follow_redirects)
            elif method.upper() == "POST":
                resp = requests.post(check_url, headers=synth_headers, data=body,
                                     timeout=self.timeout, allow_redirects=self.follow_redirects)
            elif method.upper() == "PUT":
                resp = requests.put(check_url, headers=synth_headers, data=body,
                                    timeout=self.timeout, allow_redirects=self.follow_redirects)
            elif method.upper() == "DELETE":
                resp = requests.delete(check_url, headers=synth_headers, timeout=self.timeout)
            elif method.upper() == "HEAD":
                resp = requests.head(check_url, headers=synth_headers, timeout=self.timeout)
            else:
                resp = requests.get(check_url, headers=synth_headers, timeout=self.timeout)
            elapsed = (time.time() - start) * 1000
            result["status_code"] = resp.status_code
            result["response_time_ms"] = round(elapsed, 1)
            result["response_size"] = len(resp.content)
            result["success"] = 200 <= resp.status_code < 400
            if self.expect:
                result["content_match"] = self.expect.lower() in resp.text.lower()
            assertions = []
            assertions.append({"name": "status_2xx_3xx", "passed": result["success"],
                               "detail": "HTTP {}".format(resp.status_code)})
            if self.expect:
                assertions.append({"name": "content_expectation", "passed": result["content_match"],
                                   "detail": self.expect[:40]})
            assertions.append({"name": "latency_budget", "passed": elapsed <= 5000,
                               "detail": "{:.0f}ms <= 5000ms".format(elapsed)})
            result["assertions"] = assertions
            result["assertions_total"] = len(assertions)
            result["assertions_passed"] = sum(1 for a in assertions if a["passed"])
            if result["assertions_passed"] == result["assertions_total"]:
                if elapsed <= 1000:
                    result["grade"] = "A"
                elif elapsed <= 2500:
                    result["grade"] = "B"
                else:
                    result["grade"] = "C"
            elif result["success"]:
                result["grade"] = "D"
            else:
                result["grade"] = "F"
            result["success"] = result["success"] and (
                not self.expect or result["content_match"])
        except requests.exceptions.Timeout:
            result["error"] = "TIMEOUT"
        except requests.exceptions.ConnectionError:
            result["error"] = "CONNECTION_ERROR"
        except Exception as e:
            result["error"] = str(e)[:100]
        return result

    def send_webhook(self, event, details):
        if not self.webhook:
            return
        payload = {
            "text": "UptimeChecker v" + VERSION + " - " + event,
            "event": event, "host": self.hostname, "target": self.target_label,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "details": details}
        try:
            requests.post(self.webhook, json=payload, timeout=10)
        except Exception:
            pass

    def calculate_score(self, check_result):
        score = 100
        status = check_result.get("status", {}).get("status_code", 0)
        if status >= 500:
            score -= 20
        elif status >= 400:
            score -= 10
        timing = check_result.get("timing", {})
        total_time = timing.get("total", 0)
        if total_time > 5000:
            score -= 10
        elif total_time > 3000:
            score -= 5
        ssl_info = check_result.get("ssl")
        if ssl_info:
            if ssl_info["status"] == "EXPIRED":
                score -= 15
            elif ssl_info["status"] == "CRITICAL":
                score -= 15
            elif ssl_info["status"] == "WARNING":
                score -= 10
            elif ssl_info["status"] == "INVALID":
                score -= 15
        if not check_result.get("content", {}).get("has_expected_content", True):
            score -= 10
        if status == 0:
            score -= 25
        extended = check_result.get("extended", {})
        if extended:
            if extended.get("maintenance_window", {}).get("detected"):
                score -= 15
            if not extended.get("http23", {}).get("http2"):
                score -= 2
        if check_result.get("tcp"):
            if not check_result["tcp"].get("available"):
                score -= 30
        if check_result.get("smtp"):
            if not check_result["smtp"].get("available"):
                score -= 30
        if check_result.get("ftp"):
            if not check_result["ftp"].get("available"):
                score -= 30
        if check_result.get("ssh"):
            if not check_result["ssh"].get("available"):
                score -= 30
        if check_result.get("ping"):
            if not check_result["ping"].get("available"):
                score -= 25
            elif check_result["ping"].get("loss_pct", 0) > 20:
                score -= 10
        return max(0, min(100, score))

    def _handle_incident(self, reason):
        newly_opened = False
        provisional_severity = "LOW"
        reason_lower = str(reason).lower()
        if any(kw in reason_lower for kw in ("timeout", "connection refused", "unreachable", "503", "502")):
            provisional_severity = "CRITICAL"
        elif any(kw in reason_lower for kw in ("500", "error", "crash")):
            provisional_severity = "HIGH"
        elif any(kw in reason_lower for kw in ("slow", "degraded", "redirect")):
            provisional_severity = "MEDIUM"
        in_maintenance, active_window = self.maintenance_manager.should_suppress(provisional_severity)
        if in_maintenance:
            self.maintenance_manager.record_event(
                "suppressed_alert",
                "Suppressed {} severity alert during window {}".format(
                    provisional_severity, active_window.get("label", "?") if active_window else "?"))
        if self.incident_tracker.current_incident:
            self.incident_tracker.add_failure()
        else:
            self.incident_tracker.start_incident(time.time(), reason)
            newly_opened = True
        incident = self.incident_tracker.get_open_incident()
        if incident is None:
            return
        incident_dict = incident.to_dict()
        incident_dict["target"] = self.target_label
        fatigue_decision = None
        if self.alert_fatigue_enabled:
            try:
                fatigue_decision = self.alert_reducer.evaluate(incident_dict)
            except Exception:
                fatigue_decision = None
        should_notify = (not in_maintenance) and (
            fatigue_decision is None or fatigue_decision.get("sent", True))
        if self.webhook and should_notify:
            self.send_webhook("FAILURE", {"reason": reason,
                                          "maintenance_suppressed": in_maintenance})
        if newly_opened and should_notify:
            if self.incident_automation_enabled:
                try:
                    response = self.response_automation.respond(
                        incident_dict,
                        fatigue_reducer=self.alert_reducer if self.alert_fatigue_enabled else None)
                    if response.get("runbook"):
                        self.automation_runbooks[incident_dict.get("group_id", "?")] = response["runbook"]
                except Exception:
                    pass
            try:
                template = "maintenance" if in_maintenance else "initial"
                self.notifier.notify(incident_dict, template)
            except Exception:
                pass
        elif newly_opened and in_maintenance:
            self.maintenance_manager.record_event(
                "incident_opened_suppressed",
                "Incident {} opened during maintenance - notifications held".format(
                    incident_dict.get("group_id", "?")))

    def _finalize_incident_notifications(self):
        for inc in self.incident_tracker.to_list():
            if inc.get("status") == "OPEN":
                continue
            inc_id = inc.get("group_id", "?")
            if inc_id in self._resolution_notified_ids:
                continue
            self._resolution_notified_ids.add(inc_id)
            inc["target"] = self.target_label
            if self.maintenance_manager.in_maintenance():
                self.maintenance_manager.record_event(
                    "resolution_suppressed",
                    "Resolution for {} held during maintenance".format(inc_id))
                continue
            if self.alert_fatigue_enabled:
                try:
                    decision = self.alert_reducer.evaluate(inc)
                    if decision and decision.get("suppressed"):
                        continue
                except Exception:
                    pass
            if self.incident_automation_enabled:
                try:
                    self.response_automation.resolve(inc)
                except Exception:
                    pass
            try:
                self.notifier.notify(inc, "resolution")
            except Exception:
                pass

    def _update_incident_impact(self):
        total = len(self.results)
        if total == 0:
            return
        failed = sum(1 for r in self.results
                     if r.get("status", {}).get("status_code", 0) < 200
                     or r.get("status", {}).get("status_code", 0) >= 400
                     or r.get("error"))
        if self.incident_tracker.current_incident:
            self.incident_tracker.current_incident.update_impact(total, failed)

    def run_single_check(self, index):
        result = {
            "index": index,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": self.target_label,
            "protocol": self.protocol,
            "status": {}, "timing": {}, "dns": {}, "ssl": None,
            "redirects": {}, "content": {}, "headers": {}, "score": 100,
            "error": None, "extended": {},
            "tcp": None, "smtp": None, "ftp": None, "ssh": None,
            "ping": None, "synthetic": None}
        try:
            if self.protocol == "http":
                self._run_http_check(result, index)
            elif self.protocol == "tcp":
                self._run_tcp_check(result)
            elif self.protocol == "smtp":
                self._run_smtp_check(result)
            elif self.protocol == "ftp":
                self._run_ftp_check(result)
            elif self.protocol == "ssh":
                self._run_ssh_check(result)
            elif self.protocol == "ping":
                self._run_ping_check(result)
            elif self.protocol == "dns":
                self._run_dns_check(result)
            status_code = result["status"].get("status_code", 0)
            check_failed = bool(result.get("error")) or not (200 <= status_code < 400)
            if check_failed:
                self.circuit_breaker.record_failure()
                reason = result.get("error")
                if not reason:
                    if status_code:
                        reason = "HTTP " + str(status_code)
                    else:
                        reason = result["status"].get("category", "Check failed")
                self._handle_incident(str(reason))
            else:
                self.circuit_breaker.record_success()
                if self.incident_tracker.current_incident:
                    self.incident_tracker.end_incident(time.time())
                    if self.webhook:
                        dur = round(self.incident_tracker.incidents[-1].duration(), 1) if self.incident_tracker.incidents else 0
                        self.send_webhook("RECOVERED", {"duration": dur})
        except requests.exceptions.Timeout:
            result["error"] = "TIMEOUT"
            result["status"] = {"status_code": 0, "category": "TIMEOUT"}
            self.circuit_breaker.record_failure()
            self._handle_incident("Timeout")
        except requests.exceptions.ConnectionError:
            result["error"] = "CONNECTION_ERROR"
            result["status"] = {"status_code": 0, "category": "CONNECTION ERROR"}
            self.circuit_breaker.record_failure()
            self._handle_incident("Connection Error")
        except requests.exceptions.TooManyRedirects:
            result["error"] = "TOO_MANY_REDIRECTS"
            result["status"] = {"status_code": 0, "category": "REDIRECT LOOP"}
            self.circuit_breaker.record_failure()
            self._handle_incident("Redirect Loop")
        except Exception as e:
            result["error"] = str(e)
            result["status"] = {"status_code": 0, "category": "ERROR"}
            self.circuit_breaker.record_failure()
            err_msg = str(e)[:50]
            self._handle_incident("Error: " + err_msg)
        result["score"] = self.calculate_score(result)
        self._update_incident_impact()
        return result

    def _run_http_check(self, result, index):
        headers = {"User-Agent": "UptimeChecker/" + VERSION}
        if self.health_endpoint and self.url:
            base = self.url.rstrip("/")
            self.url = base + self.health_endpoint
            result["target"] = self.url
        if self.synthetic_headers:
            headers.update(self.synthetic_headers)
        resp = requests.get(
            self.url, timeout=self.timeout, allow_redirects=self.follow_redirects, headers=headers)
        result["status"] = self.check_http_status(resp, index)
        result["timing"] = self.check_response_time(resp)
        if self.ab_test_enabled:
            try:
                self.ab_monitor.observe(dict(resp.headers), resp.text[:8000], resp.url)
                total_ms = result.get("timing", {}).get("total", 0)
                if total_ms > 0:
                    variant_headers = {k.lower(): v for k, v in resp.headers.items()}
                    for h in ABTestMonitor.VARIANT_HEADERS:
                        if h in variant_headers and "x-experiment-name" in variant_headers:
                            self.ab_monitor.record_latency(
                                variant_headers.get("x-experiment-name", "default"),
                                variant_headers[h], total_ms)
                            break
            except Exception:
                pass
        if self.feature_flags_enabled:
            try:
                self.flag_monitor.observe(dict(resp.headers), resp.text[:8000])
            except Exception:
                pass
        self._last_response_headers = dict(resp.headers)
        try:
            self._last_response_body = resp.text[:20000]
        except Exception:
            self._last_response_body = ""
        if index == 1:
            result["dns"] = self.check_dns()
            self.dns_info = result["dns"]
            result["ssl"] = self.check_ssl()
            self.ssl_info = result["ssl"] or {}
            result["headers"] = self.check_headers(resp)
            self.headers_info = result["headers"]
            result["redirects"] = self.check_redirects(resp)
            self.redirect_chain = result["redirects"]
            if self.extended_checks:
                result["extended"]["cdn"] = self.detect_cdn(resp)
                result["extended"]["load_balancer"] = self.detect_load_balancer(resp)
                result["extended"]["technologies"] = self.detect_technologies(resp)
                result["extended"]["http23"] = self.check_http2_http3()
                result["extended"]["mx_health"] = self.check_mx_health()
                result["extended"]["maintenance_window"] = self.detect_maintenance_window(resp)
                result["extended"]["dependencies"] = self.track_dependencies(resp)
                result["extended"]["geographic"] = self.check_geographic_response()
                result["extended"]["hsts_preload"] = self._check_hsts_preload()
                self.extended_info = result["extended"]
                self.dependencies = result["extended"].get("dependencies", [])
            if self.dependency_chain_enabled:
                if self.dependencies or not self.dependency_chain_monitor:
                    self.dependency_chain_monitor = DependencyChainMonitor(
                        self.hostname, self.timeout, self.dependencies)
                try:
                    chain_data = self.dependency_chain_monitor.run()
                    result["extended"]["dependency_chain"] = chain_data
                    self.extended_info = result["extended"]
                except Exception:
                    pass
            if self.synthetic_journey_enabled:
                try:
                    self.synthetic_journey_monitor = SyntheticJourneyMonitor(
                        self.url, self.timeout, self.expect, self.synthetic_headers)
                    journey = self.synthetic_journey_monitor.run_journey()
                    result["synthetic_journey"] = journey
                except Exception:
                    pass
            if self.synthetic_method and self.synthetic_method.upper() != "GET":
                result["synthetic"] = self.check_synthetic(method=self.synthetic_method, body=self.synthetic_body)
        else:
            result["dns"] = self.dns_info
            result["ssl"] = self.ssl_info if self.ssl_info else None
            result["headers"] = self.headers_info
            result["redirects"] = self.redirect_chain
            result["extended"] = self.extended_info
        result["content"] = self.check_content(resp)
        self.content_info = result["content"]

    def _run_tcp_check(self, result):
        result["tcp"] = self.check_tcp()
        if result["tcp"].get("available"):
            result["status"] = {"status_code": 200, "category": "OK"}
        else:
            result["status"] = {"status_code": 0, "category": "TCP FAIL"}
            result["error"] = result["tcp"].get("error", "TCP connection failed")

    def _run_smtp_check(self, result):
        result["smtp"] = self.check_smtp()
        if result["smtp"].get("available"):
            result["status"] = {"status_code": 200, "category": "OK"}
        else:
            result["status"] = {"status_code": 0, "category": "SMTP FAIL"}
            result["error"] = result["smtp"].get("error", "SMTP connection failed")

    def _run_ftp_check(self, result):
        result["ftp"] = self.check_ftp()
        if result["ftp"].get("available"):
            result["status"] = {"status_code": 200, "category": "OK"}
        else:
            result["status"] = {"status_code": 0, "category": "FTP FAIL"}
            result["error"] = result["ftp"].get("error", "FTP connection failed")

    def _run_ssh_check(self, result):
        result["ssh"] = self.check_ssh()
        if result["ssh"].get("available"):
            result["status"] = {"status_code": 200, "category": "OK"}
        else:
            result["status"] = {"status_code": 0, "category": "SSH FAIL"}
            result["error"] = result["ssh"].get("error", "SSH connection failed")

    def _run_ping_check(self, result):
        result["ping"] = self.check_ping()
        if result["ping"].get("available"):
            result["status"] = {"status_code": 200, "category": "OK"}
        else:
            result["status"] = {"status_code": 0, "category": "PING FAIL"}
            result["error"] = result["ping"].get("error", "Ping failed")
        result["timing"] = {"total": result["ping"].get("avg_rtt", 0)}

    def _run_dns_check(self, result):
        result["dns"] = self.check_dns()
        self.dns_info = result["dns"]
        if result["dns"].get("a_records") or result["dns"].get("aaaa_records"):
            result["status"] = {"status_code": 200, "category": "OK"}
        else:
            result["status"] = {"status_code": 0, "category": "DNS FAIL"}
            result["error"] = "DNS resolution failed"

    def run(self):
        self.parse_url()
        if self.webhook:
            self.send_webhook("MONITORING_STARTED", {"target": self.target_label, "count": self.count})
        results = []
        for i in range(self.count):
            if not self.circuit_breaker.can_execute():
                if not self.no_color:
                    console.print("[bold red]Circuit breaker OPEN \u2014 stopping monitoring[/bold red]")
                else:
                    print("Circuit breaker OPEN \u2014 stopping monitoring")
                break
            r = self.run_single_check(i + 1)
            results.append(r)
            if i < self.count - 1:
                wait_time = self.interval
                if self.exponential_backoff:
                    wait_time = min(self.interval * (2 ** i), 300)
                if self.jitter:
                    jitter_amount = wait_time * 0.2
                    wait_time += random.uniform(-jitter_amount, jitter_amount)
                    wait_time = max(0.5, wait_time)
                time.sleep(wait_time)
        self.results = results
        if self.incident_tracker.current_incident:
            self.incident_tracker.end_incident(time.time())
        try:
            self._finalize_incident_notifications()
        except Exception:
            pass
        if self.multi_region and self.protocol == "http" and self.hostname:
            self.multi_region_monitor = MultiRegionMonitor(
                self.hostname, self.protocol, self.timeout, self.url)
            self.multi_region_monitor.check_all_regions(self.regions)
        v6_requested = any([self.rum_enabled, self.ab_test_enabled, self.feature_flags_enabled,
                            self.dependency_chain_enabled, self.incident_automation_enabled,
                            self.roi_enabled, self.synthetic_journey_enabled])
        v7_requested = any([self.service_map_enabled, self.cascade_detect_enabled,
                            self.alert_fatigue_enabled, self.oncall_sim_enabled,
                            len(self.maintenance_manager.windows) > 0])
        if self.analytics or v6_requested or v7_requested:
            self.analytics_results = self._run_analytics()
        if not self.analytics_results and (self.postmortem or self.exec_summary or self.deep_dive or self.full_report):
            self.analytics_results = self._run_analytics()
        resolved_incidents = [i for i in self.incident_tracker.to_list() if i.get("status") != "OPEN"]
        if resolved_incidents and (self.postmortem or self.analytics or self.full_report):
            self.postmortems = self._generate_postmortems()
        self.display_results()
        if self.export != "none":
            self.export_results()
        if self.webhook:
            verdict, uptime_pct, avg_score = self.get_verdict()
            self.send_webhook("MONITORING_COMPLETE", {
                "verdict": verdict, "uptime_pct": round(uptime_pct, 2),
                "avg_score": round(avg_score, 1), "checks": len(results)})

    def _run_analytics(self):
        analytics = AdvancedAnalytics(self.results, self.sla_target)
        stats = self.get_stats()
        slo_tracker = SLOTracker(self.slo_target, self.slo_period_days)
        slo_data = slo_tracker.evaluate(self.results, self.interval)
        cost = CostOptimizer(self.interval, self.count, self.multi_region, self.extended_checks)
        cost_data = cost.analyze(stats, slo_data)
        predictive = PredictiveAnalytics(self.results, self.interval, self.sla_target)
        correlation = IncidentCorrelationEngine().correlate(self.incident_tracker.to_list())
        escalation = EscalationPolicySimulator().simulate(self.incident_tracker.to_list())
        incidents = self.incident_tracker.to_list()
        verdict, uptime_pct, _avg = self.get_verdict()
        ensemble = predictive.ensemble_failure_forecast()
        ttb = predictive.time_to_breach_forecast(
            budget_minutes=slo_data.get("error_budget", {}).get("allowed_minutes"))
        scale_rec = analytics.scale_recommendation()
        all_times = [r.get("timing", {}).get("total", 0) for r in self.results
                     if r.get("timing", {}).get("total", 0) > 0]
        rolling = {"available": False}
        if len(all_times) >= 3:
            window = max(2, len(all_times) // 3)
            recent = all_times[-window:]
            recent_avg = statistics.mean(recent)
            overall_avg = statistics.mean(all_times)
            momentum = ((recent_avg - overall_avg) / overall_avg * 100.0) if overall_avg > 0 else 0.0
            rolling = {"available": True, "window": window,
                       "recent_avg_ms": round(recent_avg, 1),
                       "overall_avg_ms": round(overall_avg, 1),
                       "momentum_pct": round(momentum, 1)}
        sla_windows = self._build_sla_windows(uptime_pct)
        budget = slo_data.get("error_budget", {})
        error_budget_forecast = None
        if budget:
            remaining = budget.get("remaining_minutes", 0)
            consumed_pct = budget.get("consumed_pct", 0)
            if consumed_pct > 0 and budget.get("allowed_minutes", 0) > 0:
                projected_used = min(budget.get("allowed_minutes", 0),
                                     consumed_pct / 100.0 * budget.get("allowed_minutes", 0) * 2)
                projected_remaining = max(0.0, budget.get("allowed_minutes", 0) - projected_used)
                status = "EXHAUSTED" if projected_remaining <= 0 else (
                    "AT_RISK" if projected_remaining < budget.get("allowed_minutes", 0) * 0.25 else "OK")
                error_budget_forecast = {
                    "status": status,
                    "projected_remaining_minutes": round(projected_remaining, 1),
                    "basis": "burn_rate_extrapolation",
                }
        roi_data = None
        if self.roi_enabled:
            try:
                roi_data = self.roi_analyzer.analyze(stats, incidents, slo_data, uptime_pct)
            except Exception:
                roi_data = None
        rum_data = None
        if self.rum_enabled:
            try:
                self.rum_monitor.results = self.results
                rum_data = self.rum_monitor.analyze()
            except Exception:
                rum_data = None
        ab_data = None
        if self.ab_test_enabled:
            try:
                ab_data = self.ab_monitor.analyze()
            except Exception:
                ab_data = None
        flag_data = None
        if self.feature_flags_enabled:
            try:
                flag_data = self.flag_monitor.analyze()
            except Exception:
                flag_data = None
        dep_chain_data = None
        if self.dependency_chain_enabled and self.dependency_chain_monitor:
            try:
                dep_chain_data = self.dependency_chain_monitor.run()
            except Exception:
                dep_chain_data = None
        synth_data = None
        if self.synthetic_journey_monitor and self.synthetic_journey_monitor.journeys:
            synth_data = self.synthetic_journey_monitor.get_summary()
        elif self.synthetic_journey_enabled:
            synth_data = {"journeys_run": 0, "success_rate": 0.0, "avg_ms": 0.0}
        service_map_data = None
        if self.service_map_enabled or self.dependency_chain_enabled:
            try:
                self.dependency_mapper = ServiceDependencyMapper(
                    origin_host=self.hostname, timeout=self.timeout)
                dep_chain_for_map = None
                if self.dependency_chain_enabled and self.dependency_chain_monitor:
                    dep_chain_for_map = dep_chain_data
                if dep_chain_for_map:
                    self.dependency_mapper.ingest_chain(dep_chain_for_map)
                origin_id = self.hostname or self.target_label or "origin"
                if self.dependencies:
                    if origin_id not in self.dependency_mapper.nodes:
                        self.dependency_mapper.add_node(
                            origin_id, kind="origin", critical=True, tier=0)
                    for dep in self.dependencies:
                        dep_host = dep.get("domain", "")
                        if dep_host and dep_host != origin_id:
                            self.dependency_mapper.add_edge(
                                origin_id, dep_host, kind="depends_on", critical=True)
                            dep_node = self.dependency_mapper.nodes.get(dep_host)
                            if dep_node and dep_node.get("health") == "unknown":
                                dep_node["health"] = "up"
                                dep_node["latency_ms"] = 0
                if not self.dependency_mapper.nodes:
                    self.dependency_mapper.add_node(
                        origin_id, kind="origin", critical=True, tier=0)
                if origin_id in self.dependency_mapper.nodes and self.results:
                    last = self.results[-1]
                    status_code = (last.get("status") or {}).get("status_code") or 0
                    origin_ok = (not last.get("error")) and status_code and status_code < 500
                    self.dependency_mapper.nodes[origin_id]["health"] = "up" if origin_ok else "down"
                service_map_data = self.dependency_mapper.map(probe=True)
            except Exception:
                service_map_data = None
        cascade_data = None
        if self.cascade_detect_enabled or (service_map_data and service_map_data.get("node_count", 0) > 0):
            try:
                cascade_data = self.cascade_detector.detect(incidents, service_map_data)
            except Exception:
                cascade_data = None
        maintenance_data = None
        if len(self.maintenance_manager.windows) > 0:
            try:
                maintenance_data = self.maintenance_manager.summarize()
            except Exception:
                maintenance_data = None
        alert_fatigue_data = None
        if self.alert_fatigue_enabled:
            try:
                alert_fatigue_data = self.alert_reducer.stats()
            except Exception:
                alert_fatigue_data = None
        oncall_data = None
        if self.oncall_sim_enabled:
            try:
                oncall_data = self.oncall_simulator.simulate(incidents)
            except Exception:
                oncall_data = None
        predictive_refined = None
        try:
            predictive_refined = analytics.predictive_refinement()
        except Exception:
            predictive_refined = None
        capacity_refined = None
        try:
            capacity_refined = analytics.capacity_planning_refinement()
        except Exception:
            capacity_refined = None
        cost_refined = None
        try:
            cost_refined = predictive.cost_optimization_refinement(
                interval=self.interval, multi_region=self.multi_region,
                extended_checks=self.extended_checks)
        except Exception:
            cost_refined = None
        roi_refined = None
        try:
            roi_refined = predictive.roi_refinement(
                hourly_downtime_cost=self.hourly_downtime_cost,
                monitoring_monthly_cost=self.roi_analyzer.monitoring_monthly_cost)
        except Exception:
            roi_refined = None
        sla_forecast_refined = None
        try:
            sla_forecast_refined = predictive.sla_forecast_refinement(self.slo_period_days)
        except Exception:
            sla_forecast_refined = None
        return {
            "uptime_trend": analytics.uptime_trend_analysis(),
            "regression": analytics.detect_performance_regression(),
            "anomalies": analytics.detect_anomalies(),
            "capacity": analytics.capacity_planning_hints(),
            "sla_prediction": analytics.sla_breach_prediction(),
            "slo": slo_data,
            "error_budget": slo_data.get("error_budget", {}),
            "cost": cost_data,
            "predictive": predictive.predictive_failure_analysis(),
            "projection": predictive.trend_extrapolation(),
            "seasonality": predictive.seasonal_pattern_detection(),
            "capacity_forecast": predictive.capacity_utilization_forecast(),
            "correlation": correlation,
            "escalation": escalation,
            "predictive_ensemble": ensemble,
            "time_to_breach": ttb,
            "scale_recommendation": scale_rec,
            "rolling_stats": rolling,
            "sla_windows": sla_windows,
            "error_budget_forecast": error_budget_forecast,
            "roi": roi_data,
            "rum": rum_data,
            "ab_tests": ab_data,
            "feature_flags": flag_data,
            "dependency_chain": dep_chain_data,
            "synthetic": synth_data,
            "service_map": service_map_data,
            "cascade": cascade_data,
            "maintenance": maintenance_data,
            "alert_fatigue": alert_fatigue_data,
            "oncall": oncall_data,
            "predictive_refined": predictive_refined,
            "capacity_refined": capacity_refined,
            "cost_refined": cost_refined,
            "roi_refined": roi_refined,
            "sla_forecast_refined": sla_forecast_refined,
            "incident_response": {
                "enabled": self.incident_automation_enabled,
                "actions": self.response_automation.get_actions(),
                "runbooks_attached": dict(self.automation_runbooks),
            },
            "runbooks": self.runbook_library.runbooks,
            "notifications": self.notifier.get_sent(),
            "notification_digest": self.notifier.digest(),
        }

    def _build_sla_windows(self, current_uptime):
        prediction = None
        try:
            analytics = AdvancedAnalytics(self.results, self.sla_target)
            prediction = analytics.sla_breach_prediction()
        except Exception:
            prediction = None
        projected = prediction.get("projected_uptime", current_uptime) if prediction else current_uptime
        windows = []
        for label, target, dampen in (
            ("short_term_next_window", self.sla_target, 1.0),
            ("medium_term_period", max(self.sla_target - 0.01, 90.0), 0.999),
            ("long_term_commitment", max(self.sla_target - 0.05, 90.0), 0.995),
        ):
            blended = current_uptime * (1 - dampen * 0.3) + projected * (dampen * 0.3)
            windows.append({
                "label": label,
                "target": round(target, 3),
                "projected_uptime": round(blended, 4),
                "compliant": blended >= target,
            })
        return {"windows": windows, "base_uptime": round(current_uptime, 3),
                "projected_uptime": round(projected, 3)}

    def _generate_postmortems(self):
        gen = IncidentPostMortemGenerator(
            target_label=self.target_label,
            stats=self.get_stats(),
            sla_target=self.sla_target,
            slo_target=self.slo_target,
            interval=self.interval,
        )
        return gen.generate_all(self.incident_tracker.to_list(), self.results)

    def _build_report_generator(self):
        return ReportGenerator(
            target_label=self.target_label,
            protocol=self.protocol,
            sla_target=self.sla_target,
            slo_target=self.slo_target,
        )

    def get_verdict(self):
        scores = [r["score"] for r in self.results]
        avg_score = statistics.mean(scores) if scores else 0
        up_count = sum(1 for r in self.results
                       if r["status"].get("status_code", 0) >= 200
                       and r["status"].get("status_code", 0) < 400)
        uptime_pct = (up_count / len(self.results) * 100) if self.results else 0
        if uptime_pct >= 99:
            return "UP", uptime_pct, avg_score
        elif uptime_pct >= 50:
            return "DEGRADED", uptime_pct, avg_score
        else:
            return "DOWN", uptime_pct, avg_score

    def get_stats(self):
        all_times = [r.get("timing", {}).get("total", 0) for r in self.results
                     if r.get("timing", {}).get("total", 0) > 0]
        all_scores = [r["score"] for r in self.results]
        statuses = [r["status"].get("status_code", 0) for r in self.results]
        percentiles = EnhancedStats.response_percentiles(all_times)
        mtbf = EnhancedStats.calculate_mtbf(self.results)
        mttr = EnhancedStats.calculate_mttr(self.results)
        error_rate = EnhancedStats.error_rate(self.results)
        rt_trend = EnhancedStats.response_time_trend(self.results)
        err_trend = EnhancedStats.error_rate_trend(self.results)
        return {
            "avg_time": statistics.mean(all_times) if all_times else 0,
            "min_time": min(all_times) if all_times else 0,
            "max_time": max(all_times) if all_times else 0,
            "median_time": statistics.median(all_times) if all_times else 0,
            "avg_score": statistics.mean(all_scores) if all_scores else 0,
            "status_counts": {s: statuses.count(s) for s in set(statuses)},
            "percentiles": percentiles,
            "mtbf": mtbf, "mttr": mttr, "error_rate": error_rate,
            "response_time_trend": rt_trend, "error_rate_trend": err_trend}

    def display_results(self):
        if self.no_color:
            self._display_plain()
            return
        self._display_rich()

    def _display_rich(self):
        verdict, uptime_pct, avg_score = self.get_verdict()
        stats = self.get_stats()
        console.print(BANNER)
        console.print()
        self._display_status_page(verdict, uptime_pct, stats)
        table = Table(title="Check Results", box=box.ROUNDED, border_style="cyan")
        table.add_column("#", style="bold", width=4)
        table.add_column("Timestamp", width=20)
        table.add_column("Protocol", width=8)
        table.add_column("Status", width=14)
        table.add_column("Response Time", width=14)
        table.add_column("Score", width=8)
        table.add_column("Result", width=10)
        for r in self.results:
            sc = r["status"].get("status_code", 0)
            if 200 <= sc < 300:
                status_str = "[bold green]" + str(sc) + "[/bold green]"
            elif 300 <= sc < 400:
                status_str = "[bold yellow]" + str(sc) + "[/bold yellow]"
            elif sc >= 400:
                status_str = "[bold red]" + str(sc) + "[/bold red]"
            elif r.get("error"):
                status_str = "[bold red]FAIL[/bold red]"
            else:
                status_str = "[bold red]" + str(sc) + "[/bold red]"
            rt = r.get("timing", {}).get("total", 0)
            if rt > 3000:
                rt_str = "[bold red]" + "{:.0f}".format(rt) + "ms[/bold red]"
            elif rt > 1000:
                rt_str = "[bold yellow]" + "{:.0f}".format(rt) + "ms[/bold yellow]"
            elif rt > 0:
                rt_str = "[bold green]" + "{:.0f}".format(rt) + "ms[/bold green]"
            else:
                rt_str = "N/A"
            sc_val = r["score"]
            if sc_val >= 80:
                sc_str = "[bold green]" + str(sc_val) + "[/bold green]"
            elif sc_val >= 60:
                sc_str = "[bold yellow]" + str(sc_val) + "[/bold yellow]"
            else:
                sc_str = "[bold red]" + str(sc_val) + "[/bold red]"
            if verdict == "UP":
                res_str = "[bold green]OK[/bold green]"
            elif verdict == "DEGRADED":
                res_str = "[bold yellow]WARN[/bold yellow]"
            else:
                res_str = "[bold red]FAIL[/bold red]"
            proto_str = r.get("protocol", "http").upper()[:4]
            table.add_row(str(r["index"]), r["timestamp"], proto_str, status_str, rt_str, sc_str, res_str)
        console.print(table)
        console.print()
        if self.protocol == "http":
            self._display_http_details_rich()
        elif self.protocol == "tcp":
            self._display_tcp_details_rich()
        elif self.protocol == "smtp":
            self._display_smtp_details_rich()
        elif self.protocol == "ftp":
            self._display_ftp_details_rich()
        elif self.protocol == "ssh":
            self._display_ssh_details_rich()
        elif self.protocol == "ping":
            self._display_ping_details_rich()
        elif self.protocol == "dns":
            self._display_dns_details_rich()
        timing_table = Table(title="Response Timing", box=box.ROUNDED, border_style="cyan")
        timing_table.add_column("Metric", style="bold", width=25)
        timing_table.add_column("Value", width=20)
        timing_table.add_row("Average", "{:.1f}".format(stats["avg_time"]) + "ms")
        timing_table.add_row("Minimum", "{:.1f}".format(stats["min_time"]) + "ms")
        timing_table.add_row("Maximum", "{:.1f}".format(stats["max_time"]) + "ms")
        timing_table.add_row("Median (P50)", "{:.1f}".format(stats["percentiles"]["p50"]) + "ms")
        timing_table.add_row("P90", "{:.1f}".format(stats["percentiles"]["p90"]) + "ms")
        timing_table.add_row("P95", "{:.1f}".format(stats["percentiles"]["p95"]) + "ms")
        timing_table.add_row("P99", "{:.1f}".format(stats["percentiles"]["p99"]) + "ms")
        if self.results and self.results[0].get("timing", {}).get("dns_resolution"):
            val = self.results[0]["timing"]["dns_resolution"]
            timing_table.add_row("DNS Resolution", "{:.1f}".format(val) + "ms")
        if self.results and self.results[0].get("timing", {}).get("tcp_connect"):
            val = self.results[0]["timing"]["tcp_connect"]
            timing_table.add_row("TCP Connect", "{:.1f}".format(val) + "ms")
        if self.results and self.results[0].get("timing", {}).get("ssl_handshake"):
            val = self.results[0]["timing"]["ssl_handshake"]
            timing_table.add_row("SSL Handshake", "{:.1f}".format(val) + "ms")
        if self.results and self.results[0].get("timing", {}).get("ttfb"):
            val = self.results[0]["timing"]["ttfb"]
            timing_table.add_row("TTFB", "{:.1f}".format(val) + "ms")
        trend = stats["response_time_trend"]
        if trend > 1:
            trend_str = "[bold red]+{:.1f} ms/check (degrading)[/bold red]".format(trend)
        elif trend < -1:
            trend_str = "[bold green]{:.1f} ms/check (improving)[/bold green]".format(trend)
        else:
            trend_str = "Stable"
        timing_table.add_row("Trend", trend_str)
        console.print(timing_table)
        console.print()
        self._display_incident_analysis()
        self._display_availability_calendar(stats)
        self._display_sla_report(uptime_pct, stats)
        if self.multi_region and self.multi_region_monitor:
            self._display_multi_region_results()
        if self.analytics_results:
            self._display_advanced_analytics()
        if self.analytics_results:
            self._display_v5_monitoring_insights()
            self._display_predictive_analytics()
            self._display_incident_ops()
            self._display_v6_monitoring()
            self._display_v7_monitoring()
            self._display_trend_projections()
            self._display_sla_compliance_forecast(uptime_pct)
        if self.postmortems:
            self._display_postmortems()
        if (self.exec_summary or self.full_report) and self.analytics_results:
            self._display_executive_dashboard(verdict, uptime_pct, avg_score, stats)
        if (self.deep_dive or self.full_report) and self.analytics_results:
            self._display_technical_deep_dive(stats)
        if stats["response_time_trend"] != 0 or stats["error_rate_trend"]:
            self._display_performance_trend(stats)
        console.print(Panel(
            self._build_summary_verdict(verdict, uptime_pct, avg_score, stats),
            title="Summary",
            border_style="green" if verdict == "UP" else ("yellow" if verdict == "DEGRADED" else "red"),
            box=box.DOUBLE))

    def _display_incident_analysis(self):
        incidents = self.incident_tracker.to_list()
        if not incidents:
            return
        inc_table = Table(title="Incident Timeline", box=box.ROUNDED, border_style="red")
        inc_table.add_column("ID", width=10)
        inc_table.add_column("Start", width=19)
        inc_table.add_column("End", width=19)
        inc_table.add_column("Severity", width=10)
        inc_table.add_column("Reason", width=25)
        inc_table.add_column("Root Cause", width=30)
        inc_table.add_column("Impact", width=10)
        inc_table.add_column("Status", width=12)
        for inc in incidents:
            sev = inc.get("severity", "UNKNOWN")
            if sev == "CRITICAL":
                sev_str = "[bold red]" + sev + "[/bold red]"
            elif sev == "HIGH":
                sev_str = "[bold yellow]" + sev + "[/bold yellow]"
            elif sev == "MEDIUM":
                sev_str = "[cyan]" + sev + "[/cyan]"
            else:
                sev_str = "[dim]" + sev + "[/dim]"
            if inc["status"] == "OPEN":
                status_color = "[bold red]OPEN[/bold red]"
            else:
                status_color = "[bold green]RESOLVED[/bold green]"
            impact = inc.get("impact_score", 0)
            impact_str = "{:.0f}%".format(impact)
            if impact > 50:
                impact_str = "[bold red]" + impact_str + "[/bold red]"
            elif impact > 20:
                impact_str = "[bold yellow]" + impact_str + "[/bold yellow]"
            inc_table.add_row(
                inc.get("group_id", "?"), inc["start"], str(inc["end"]),
                sev_str, inc["reason"], inc.get("root_cause", "Unknown"),
                impact_str, status_color)
        console.print(inc_table)
        console.print()
        groups = self.incident_tracker.group_by_root_cause()
        if groups:
            grp_table = Table(title="Incidents by Root Cause", box=box.ROUNDED, border_style="yellow")
            grp_table.add_column("Category", style="bold", width=20)
            grp_table.add_column("Count", width=8)
            grp_table.add_column("Incidents", width=50)
            for cat, incs in sorted(groups.items(), key=lambda x: -len(x[1])):
                ids = [i.get("group_id", "?") for i in incs]
                grp_table.add_row(cat, str(len(incs)), ", ".join(ids))
            console.print(grp_table)
            console.print()
        sev_groups = self.incident_tracker.group_by_severity()
        if sev_groups:
            sev_table = Table(title="Incidents by Severity", box=box.ROUNDED, border_style="red")
            sev_table.add_column("Severity", style="bold", width=15)
            sev_table.add_column("Count", width=8)
            sev_table.add_column("Affected Checks", width=40)
            for sev, incs in sorted(sev_groups.items()):
                total_failed = sum(i.get("impact_checks_failed", 0) for i in incs)
                sev_table.add_row(sev, str(len(incs)), str(total_failed) + " checks affected")
            console.print(sev_table)
            console.print()
        res_stats = self.incident_tracker.get_resolution_stats()
        if res_stats["total_resolved"] > 0:
            console.print("  [bold cyan]Resolution Stats:[/bold cyan] Avg: {:.1f}s | Resolved: {} | Open: {}".format(
                res_stats["avg_resolution_time"], res_stats["total_resolved"], res_stats["total_open"]))
            console.print()

    def _display_multi_region_results(self):
        monitor = self.multi_region_monitor
        summary = monitor.get_summary()
        scores = monitor.get_availability_scores()
        latencies = monitor.get_latency_comparison()
        console.print(Panel(
            "Regions: {}/{} available | Avg latency: {:.0f}ms | Score: {:.0f}/100".format(
                summary["available_regions"], summary["total_regions"],
                summary["avg_latency"], summary["score"]),
            title="Multi-Region Monitoring",
            border_style="cyan", box=box.HEAVY))
        console.print()
        region_table = Table(title="Region Results", box=box.ROUNDED, border_style="cyan")
        region_table.add_column("Region", style="bold", width=28)
        region_table.add_column("DNS", width=10)
        region_table.add_column("DNS Time", width=10)
        region_table.add_column("TCP", width=10)
        region_table.add_column("TCP Time", width=10)
        region_table.add_column("HTTP", width=10)
        region_table.add_column("HTTP Time", width=12)
        region_table.add_column("Score", width=8)
        for region_id, result in monitor.region_results.items():
            region_name = REGIONS[region_id]["name"]
            dns_ok = "[bold green]OK[/bold green]" if result["dns_resolved"] else "[bold red]FAIL[/bold red]"
            dns_time = "{:.0f}ms".format(result["dns_resolution_ms"]) if result["dns_resolution_ms"] >= 0 else "N/A"
            tcp_ok = "[bold green]OK[/bold green]" if result["tcp_reachable"] else "[bold red]FAIL[/bold red]"
            tcp_time = "{:.0f}ms".format(result["tcp_response_ms"]) if result["tcp_response_ms"] >= 0 else "N/A"
            http_ok = "[bold green]OK[/bold green]" if result["http_available"] else "[bold red]FAIL[/bold red]"
            http_time = "{:.0f}ms".format(result["http_response_ms"]) if result["http_response_ms"] >= 0 else "N/A"
            sc = scores.get(region_id, 0)
            if sc >= 80:
                sc_str = "[bold green]" + str(sc) + "[/bold green]"
            elif sc >= 50:
                sc_str = "[bold yellow]" + str(sc) + "[/bold yellow]"
            else:
                sc_str = "[bold red]" + str(sc) + "[/bold red]"
            region_table.add_row(region_name, dns_ok, dns_time, tcp_ok, tcp_time,
                                 http_ok, http_time, sc_str)
        console.print(region_table)
        console.print()
        self._display_region_ascii_map(monitor)
        cdn_edges = monitor.get_cdn_edge_comparison()
        if len(cdn_edges) > 1:
            edge_table = Table(title="CDN Edge Performance", box=box.ROUNDED, border_style="cyan")
            edge_table.add_column("Region", style="bold", width=28)
            edge_table.add_column("Response", width=12)
            edge_table.add_column("Bar", width=30)
            max_ms = max(e["response_ms"] for e in cdn_edges.values()) if cdn_edges else 1
            for region_id, edge in cdn_edges.items():
                bar_len = int((edge["response_ms"] / max(max_ms, 1)) * 28)
                bar = "[" + "#" * bar_len + "." * (28 - bar_len) + "]"
                if edge["response_ms"] < max_ms * 0.3:
                    bar_color = "green"
                elif edge["response_ms"] < max_ms * 0.7:
                    bar_color = "yellow"
                else:
                    bar_color = "red"
                edge_table.add_row(
                    edge["region_name"],
                    "{:.0f}ms".format(edge["response_ms"]),
                    "[" + "[bold " + bar_color + "]" + "#" * bar_len + "[/bold " + bar_color + "]" + "." * (28 - bar_len) + "]")
            console.print(edge_table)
            console.print()

    def _display_region_ascii_map(self, monitor):
        lines = ["  Geographic Availability Map", "  " + "-" * 55]
        region_map = {
            "us-east-1": "[NA-E]",
            "us-west-2": "[NA-W]",
            "eu-west-1": "[EU-W]",
            "eu-central-1": "[EU-C]",
            "ap-southeast-1": "[AP-S]",
            "ap-northeast-1": "[AP-N]",
            "sa-east-1": "[SA- ]",
            "ap-south-1": "[AP-I]",
        }
        for region_id, result in monitor.region_results.items():
            prefix = region_map.get(region_id, "[???]")
            resolved = result.get("dns_resolved", False)
            rt = result.get("dns_resolution_ms", -1)
            if resolved and rt >= 0:
                if rt < 100:
                    indicator = "[bold green]*[/bold green]"
                elif rt < 300:
                    indicator = "[yellow]*[/yellow]"
                else:
                    indicator = "[red]*[/red]"
                lines.append(prefix + " " + indicator + " " + region_id + " ({:.0f}ms)".format(rt))
            else:
                lines.append(prefix + " [red]x[/red] " + region_id + " (unreachable)")
        lines.append("  " + "-" * 55)
        lines.append("  [green]*[/green] <100ms  [yellow]*[/yellow] <300ms  [red]*[/red] >300ms  [red]x[/red] down")
        console.print(Panel("\n".join(lines), title="Geo Map", border_style="cyan", box=box.ROUNDED))

    def _display_advanced_analytics(self):
        analytics = self.analytics_results
        trend = analytics.get("uptime_trend", {})
        regression = analytics.get("regression", {})
        anomalies = analytics.get("anomalies", {})
        capacity = analytics.get("capacity", {})
        sla_pred = analytics.get("sla_prediction", {})
        trend_color = "green" if trend.get("trend") == "improving" else (
            "red" if trend.get("trend") == "degrading" else "cyan")
        trend_lines = []
        trend_lines.append("Uptime Trend: [bold " + trend_color + "]" + trend.get("trend", "unknown").upper() + "[/bold " + trend_color + "]")
        trend_lines.append("Total Checks: " + str(trend.get("total_checks", 0)))
        windows = trend.get("windows", [])
        if windows:
            window_str = " -> ".join("{:.1f}%".format(w) for w in windows[-5:])
            trend_lines.append("Windows: " + window_str)
        console.print(Panel("\n".join(trend_lines), title="Uptime Trend Analysis", border_style="cyan", box=box.ROUNDED))
        console.print()
        reg_color = "red" if regression.get("regression_detected") else "green"
        reg_lines = []
        reg_lines.append("Performance Regression: [bold " + reg_color + "]" +
                         ("DETECTED" if regression.get("regression_detected") else "None") +
                         "[/bold " + reg_color + "]")
        reg_lines.append("Slope: " + "{:.2f}".format(regression.get("slope", 0)) + " ms/check")
        reg_lines.append("Confidence: " + "{:.0f}%".format(regression.get("confidence", 0)))
        reg_lines.append("Avg Response: " + "{:.0f}".format(regression.get("avg_response", 0)) + "ms")
        reg_lines.append(regression.get("reason", ""))
        console.print(Panel("\n".join(reg_lines), title="Performance Regression Detection",
                            border_style="cyan", box=box.ROUNDED))
        console.print()
        if anomalies.get("count", 0) > 0:
            anom_table = Table(title="Anomaly Detection ({} found)".format(anomalies["count"]),
                               box=box.ROUNDED, border_style="yellow")
            anom_table.add_column("#", width=6)
            anom_table.add_column("Timestamp", width=20)
            anom_table.add_column("Response", width=12)
            anom_table.add_column("Z-Score", width=10)
            anom_table.add_column("Type", width=8)
            for a in anomalies.get("anomalies", []):
                type_str = "[bold red]SLOW[/bold red]" if a["type"] == "slow" else "[bold green]FAST[/bold green]"
                anom_table.add_row(str(a["index"]), a["timestamp"],
                                   "{:.0f}ms".format(a["response_ms"]),
                                   "{:.2f}".format(a["z_score"]), type_str)
            console.print(anom_table)
            console.print("  Mean: {:.0f}ms | StDev: {:.0f}ms".format(
                anomalies.get("mean", 0), anomalies.get("stdev", 0)))
            console.print()
        cap_lines = []
        cap_lines.append("Avg: {:.0f}ms | P95: {:.0f}ms | Max: {:.0f}ms".format(
            capacity.get("avg_ms", 0), capacity.get("p95_ms", 0), capacity.get("max_ms", 0)))
        for hint in capacity.get("hints", []):
            cap_lines.append("  -> " + hint)
        console.print(Panel("\n".join(cap_lines), title="Capacity Planning Hints",
                            border_style="cyan", box=box.ROUNDED))
        console.print()
        pred_color = "red" if sla_pred.get("will_breach") else "green"
        pred_lines = []
        pred_lines.append("SLA Breach Prediction: [bold " + pred_color + "]" +
                          ("YES" if sla_pred.get("will_breach") else "NO") +
                          "[/bold " + pred_color + "]")
        pred_lines.append("Target: " + "{:.3f}".format(sla_pred.get("sla_target", 99.9)) + "%")
        pred_lines.append("Current: " + "{:.2f}".format(sla_pred.get("current_uptime", 0)) + "%")
        pred_lines.append("Projected: " + "{:.2f}".format(sla_pred.get("projected_uptime", 0)) + "%")
        pred_lines.append("Trend: " + "{:.4f}%/check".format(sla_pred.get("slope", 0)))
        pred_lines.append("Confidence: " + "{:.0f}%".format(sla_pred.get("confidence", 0)))
        pred_lines.append(sla_pred.get("reason", ""))
        console.print(Panel("\n".join(pred_lines), title="SLA Breach Prediction",
                            border_style=pred_color, box=box.ROUNDED))
        console.print()

    def _display_v5_monitoring_insights(self):
        analytics = self.analytics_results
        slo = analytics.get("slo", {})
        budget = analytics.get("error_budget", {})
        if slo:
            budget_status = budget.get("status", "N/A")
            budget_color = "green" if budget_status == "OK" else (
                "yellow" if budget_status in ("WARNING", "CRITICAL") else "red")
            met_str = "[bold green]MET[/bold green]" if slo.get("met") else "[bold red]NOT MET[/bold red]"
            slo_lines = [
                "SLO target: " + "{:.3f}".format(slo.get("slo_target", 0)) + "% over " + str(slo.get("period_days", 0)) + " days",
                "Actual uptime: " + "{:.2f}".format(slo.get("actual_uptime", 0)) + "% | SLO: " + met_str,
                "Error budget: [bold " + budget_color + "]" + budget_status + "[/bold " + budget_color + "]",
                "Budget used: " + "{:.1f}".format(budget.get("consumed_minutes", 0)) + " / " +
                "{:.1f}".format(budget.get("allowed_minutes", 0)) + " min (" +
                "{:.1f}".format(budget.get("consumed_pct", 0)) + "%)",
                "Remaining: " + "{:.1f}".format(budget.get("remaining_minutes", 0)) + " min",
                "Burn rate: " + "{:.2f}".format(slo.get("burn_rate", 0)) + "x nominal",
            ]
            exhaustion = slo.get("projected_exhaustion_minutes")
            if exhaustion is not None:
                if exhaustion <= 0:
                    slo_lines.append("[bold red]Error budget exhausted[/bold red]")
                else:
                    slo_lines.append("Projected exhaustion: " + "{:.1f}".format(exhaustion) + " min equivalent runtime")
            console.print(Panel("\n".join(slo_lines), title="SLO & Error Budget Tracking",
                                border_style=budget_color if budget_color != "green" else "cyan", box=box.ROUNDED))
            console.print()
        cost = analytics.get("cost", {})
        if cost:
            cost_lines = [
                "Probe rate: " + str(cost.get("checks_per_day", 0)) + "/day | " +
                "{:,}".format(cost.get("estimated_monthly_checks", 0)) + "/month",
                "Efficiency score: " + "{:.0f}".format(cost.get("probe_efficiency_score", 0)) + "/100",
            ]
            for hint in cost.get("hints", []):
                cost_lines.append("  -> " + hint)
            console.print(Panel("\n".join(cost_lines), title="Cost Optimization Hints",
                                border_style="cyan", box=box.ROUNDED))
            console.print()
        cap_forecast = analytics.get("capacity_forecast", {})
        if cap_forecast and cap_forecast.get("status") != "NO_DATA":
            fc_status = cap_forecast.get("status", "OK")
            fc_color = "green" if fc_status == "OK" else ("yellow" if fc_status == "WARNING" else "red")
            fc_lines = [
                "Utilization: [bold " + fc_color + "]" + "{:.1f}".format(cap_forecast.get("utilization_pct", 0)) +
                "%[/bold " + fc_color + "] of " + "{:.0f}".format(cap_forecast.get("capacity_limit_ms", 0)) + "ms limit",
                "Current avg: " + "{:.0f}".format(cap_forecast.get("current_avg_ms", 0)) + "ms | headroom: " +
                "{:.0f}".format(cap_forecast.get("headroom_ms", 0)) + "ms",
            ]
            breach = cap_forecast.get("checks_until_breach")
            if breach is not None:
                fc_lines.append("Projected capacity breach in " + str(breach) + " checks")
            else:
                fc_lines.append("No capacity breach projected at current trend")
            proj = cap_forecast.get("projected_ms", [])
            if proj:
                fc_lines.append("Projection: [" + ", ".join("{:.0f}".format(v) for v in proj[:8]) + "]")
            console.print(Panel("\n".join(fc_lines), title="Capacity Utilization Forecast",
                                border_style=fc_color, box=box.ROUNDED))
            console.print()

    def _display_predictive_analytics(self):
        analytics = self.analytics_results
        predictive = analytics.get("predictive", {})
        if not predictive:
            return
        risk = predictive.get("risk_level", "LOW")
        risk_color = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "red"}.get(risk, "cyan")
        pred_lines = [
            "Failure probability: [bold " + risk_color + "]" +
            "{:.1f}".format(predictive.get("failure_probability", 0)) + "%[/bold " + risk_color + "] (" + risk + ")",
            "Horizon: " + str(predictive.get("horizon", "n/a")),
        ]
        for factor in predictive.get("factors", []):
            pred_lines.append("  -> " + factor)
        console.print(Panel("\n".join(pred_lines), title="Predictive Failure Analysis",
                            border_style=risk_color, box=box.ROUNDED))
        console.print()
        seasonality = analytics.get("seasonality", {})
        if seasonality and seasonality.get("pattern") != "insufficient_data":
            season_lines = [
                "Pattern: [bold cyan]" + str(seasonality.get("pattern", "none")).upper() + "[/bold cyan]",
                "Strength: " + "{:.0f}".format(seasonality.get("strength", 0)) + "/100",
                "Peak bucket: " + str(seasonality.get("peak_bucket")) + " | Trough bucket: " + str(seasonality.get("trough_bucket")),
            ]
            means = seasonality.get("bucket_means", [])
            if means:
                season_lines.append("Bucket means: [" + ", ".join("{:.0f}".format(m) for m in means) + "]")
            devs = seasonality.get("deviations_pct", [])
            if devs:
                season_lines.append("Deviations: [" + ", ".join("{:+.1f}%".format(d) for d in devs) + "]")
            if seasonality.get("note"):
                season_lines.append(seasonality["note"])
            console.print(Panel("\n".join(season_lines), title="Seasonal Pattern Detection",
                                border_style="cyan", box=box.ROUNDED))
            console.print()

    def _display_incident_ops(self):
        analytics = self.analytics_results
        correlation = analytics.get("correlation", {})
        if correlation:
            corr_lines = [
                "Window: " + str(correlation.get("window_seconds", 0)) + "s | Clusters: " +
                str(len(correlation.get("clusters", []))) +
                " | Correlated pairs: " + str(correlation.get("correlated_pairs", 0)),
                "Cascade detected: " + ("[bold red]YES[/bold red]" if correlation.get("cascade_detected") else "[bold green]NO[/bold green]"),
            ]
            shared = correlation.get("shared_categories", {})
            if shared:
                parts = ["{}={}".format(cat, cnt) for cat, cnt in sorted(shared.items(), key=lambda x: -x[1])]
                corr_lines.append("Shared root causes: " + ", ".join(parts))
            clusters = correlation.get("clusters", [])
            if clusters:
                corr_table = Table(title="Incident Correlation Clusters", box=box.ROUNDED, border_style="yellow")
                corr_table.add_column("Cluster", width=12)
                corr_table.add_column("Members", width=25)
                corr_table.add_column("Size", width=6)
                corr_table.add_column("Categories", width=25)
                corr_table.add_column("Max Sev", width=10)
                corr_table.add_column("Cascade", width=10)
                for cluster in clusters:
                    cascade_str = "[bold red]YES[/bold red]" if cluster.get("cascade_suspected") else "no"
                    corr_table.add_row(
                        cluster.get("cluster_id", "?"),
                        ", ".join(cluster.get("incident_ids", [])),
                        str(cluster.get("size", 0)),
                        ", ".join(cluster.get("categories", [])),
                        cluster.get("max_severity", "?"),
                        cascade_str)
                console.print(Panel("\n".join(corr_lines), title="Incident Correlation Engine",
                                    border_style="yellow", box=box.ROUNDED))
                console.print()
                console.print(corr_table)
                console.print()
            else:
                console.print(Panel("\n".join(corr_lines), title="Incident Correlation Engine",
                                    border_style="cyan", box=box.ROUNDED))
                console.print()
        escalation = analytics.get("escalation", {})
        if escalation and escalation.get("simulations"):
            esc_stats = escalation.get("stats", {})
            esc_lines = [
                "Evaluated: " + str(esc_stats.get("incidents_evaluated", 0)) +
                " | Escalated: " + str(esc_stats.get("escalated_count", 0)) +
                " | Exec pages: " + str(esc_stats.get("exec_page_count", 0)),
            ]
            role_counts = esc_stats.get("role_page_counts", {})
            if role_counts:
                parts = ["{}: {}".format(role, cnt) for role, cnt in role_counts.items()]
                esc_lines.append("Page counts: " + ", ".join(parts))
            console.print(Panel("\n".join(esc_lines), title="Escalation Policy Simulation",
                                border_style="cyan", box=box.ROUNDED))
            console.print()
            esc_table = Table(title="Escalation Simulation", box=box.ROUNDED, border_style="cyan")
            esc_table.add_column("Incident", width=12)
            esc_table.add_column("Severity", width=10)
            esc_table.add_column("Duration", width=12)
            esc_table.add_column("Max Tier", width=10)
            esc_table.add_column("Notified Roles", width=45)
            for sim in escalation.get("simulations", []):
                roles = ", ".join(n["role"] for n in sim.get("tiers_notified", [])) or "none"
                tier = sim.get("max_tier_reached", 0)
                tier_str = str(tier) if tier > 0 else "0"
                esc_table.add_row(
                    sim.get("incident_id", "?"),
                    sim.get("severity", "?"),
                    "{:.1f}m".format(sim.get("duration_minutes", 0)),
                    tier_str,
                    roles[:60])
            console.print(esc_table)
            console.print()

    def _display_trend_projections(self):
        generator = self._build_report_generator()
        lines = generator.trend_analysis_with_projections(self.analytics_results)
        console.print(Panel("\n".join(lines), title="Trend Analysis with Projections",
                            border_style="cyan", box=box.ROUNDED))
        console.print()

    def _display_v6_monitoring(self):
        analytics = self.analytics_results
        if not analytics:
            return
        rum = analytics.get("rum")
        if rum:
            if rum.get("available"):
                vitals = rum.get("vitals", {})
                grades = rum.get("grades", {})
                rum_lines = [
                    "Samples: " + str(rum.get("sample_count", 0)) +
                    " | Apdex: " + "{:.3f}".format(rum.get("apdex", 0)),
                ]
                for key in ("ttfb", "fcp", "lcp", "inp", "cls"):
                    val = vitals.get(key + "_ms", vitals.get(key, 0))
                    grade = grades.get(key, "n/a")
                    grade_color = {"good": "green", "needs_improvement": "yellow", "poor": "red"}.get(grade, "cyan")
                    if key == "cls":
                        rum_lines.append("  {}: {:.3f} [{}]{}[/{}]".format(
                            key.upper(), val if val is not None else 0, grade_color, grade, grade_color))
                    else:
                        rum_lines.append("  {}: {:.0f}ms [{}]{}[/{}]".format(
                            key.upper(), val or 0, grade_color, grade, grade_color))
                breakdown = rum.get("user_breakdown", {})
                if breakdown:
                    rum_lines.append("  Users: {} satisfied / {} tolerating / {} frustrated".format(
                        breakdown.get("satisfied", 0), breakdown.get("tolerating", 0),
                        breakdown.get("frustrated", 0)))
                console.print(Panel("\n".join(rum_lines), title="Real User Monitoring (RUM)",
                                    border_style="cyan", box=box.ROUNDED))
                console.print()
            else:
                console.print(Panel(str(rum.get("notes", "RUM unavailable")),
                                    title="Real User Monitoring (RUM)",
                                    border_style="dim", box=box.ROUNDED))
                console.print()
        synth = analytics.get("synthetic")
        if synth is not None:
            if synth.get("journeys_run", 0) > 0:
                last = synth.get("last") or {}
                synth_lines = [
                    "Journeys: " + str(synth.get("journeys_run", 0)) +
                    " | Success rate: " + "{:.1f}".format(synth.get("success_rate", 0)) + "%" +
                    " | Avg: " + "{:.0f}".format(synth.get("avg_ms", 0)) + "ms",
                    "Last journey: " + str(last.get("steps_passed", 0)) + "/" +
                    str(last.get("steps_total", 0)) + " steps passed",
                ]
                for step in last.get("steps", [])[:6]:
                    mark = "[green]ok[/green]" if step.get("success") else "[red]fail[/red]"
                    synth_lines.append("  - " + str(step.get("name", "?")) + " " + mark + " " +
                                       "{:.0f}ms".format(step.get("response_ms", 0)))
                    for assertion in step.get("assertions", [])[:3]:
                        a_mark = "[green]pass[/green]" if assertion.get("passed") else "[red]fail[/red]"
                        synth_lines.append("      " + str(assertion.get("name", "?")) + ": " + a_mark)
                synth_color = "green" if synth.get("success_rate", 0) >= 90 else "yellow"
                console.print(Panel("\n".join(synth_lines), title="Synthetic Journey Monitoring",
                                    border_style=synth_color, box=box.ROUNDED))
                console.print()
        ab = analytics.get("ab_tests")
        if ab and ab.get("detected"):
            ab_lines = ["Observations: " + str(ab.get("total_observations", 0))]
            ab_table = Table(title="A/B Test Monitoring", box=box.ROUNDED, border_style="magenta")
            ab_table.add_column("Experiment", style="bold", width=22)
            ab_table.add_column("Variant", width=14)
            ab_table.add_column("Assignments", width=12)
            ab_table.add_column("Traffic %", width=10)
            ab_table.add_column("Avg Latency", width=12)
            ab_table.add_column("Warning", width=30)
            for exp in ab.get("experiments", []):
                for variant in exp.get("variants", []):
                    warn = exp.get("warning") or ""
                    warn_str = "[yellow]" + warn + "[/yellow]" if warn else ""
                    ab_table.add_row(
                        exp.get("experiment", "?"),
                        variant.get("variant", "?"),
                        str(variant.get("assignments", 0)),
                        "{:.1f}".format(variant.get("traffic_share_pct", 0)),
                        "{:.0f}ms".format(variant.get("avg_latency_ms", 0)),
                        warn_str[:30])
            console.print(Panel("\n".join(ab_lines), title="A/B Test Monitor",
                                border_style="magenta", box=box.ROUNDED))
            console.print()
            console.print(ab_table)
            console.print()
        elif ab is not None:
            console.print(Panel(str(ab.get("notes", "No A/B variants observed")),
                                title="A/B Test Monitor", border_style="dim", box=box.ROUNDED))
            console.print()
        flags = analytics.get("feature_flags")
        if flags and flags.get("detected"):
            flag_table = Table(title="Feature Flag Monitoring", box=box.ROUNDED, border_style="magenta")
            flag_table.add_column("Flag", style="bold", width=28)
            flag_table.add_column("State", width=12)
            flag_table.add_column("Changes", width=10)
            flag_table.add_column("Last Seen", width=20)
            for flag in flags.get("flags", []):
                enabled = flag.get("enabled", False)
                state_str = "[bold green]ON[/bold green]" if enabled else "[dim]OFF[/dim]"
                if flag.get("name") in flags.get("flapping", []):
                    state_str += " [bold yellow]FLAP[/bold yellow]"
                flag_table.add_row(
                    flag.get("name", "?"), state_str,
                    str(flag.get("changes", 0)), str(flag.get("last_seen", "")))
            console.print(Panel(
                "Tracked: {} | Enabled: {} | Flapping: {}".format(
                    flags.get("total_flags", 0), flags.get("enabled_count", 0),
                    ", ".join(flags.get("flapping", [])) or "none"),
                title="Feature Flag Monitor", border_style="magenta", box=box.ROUNDED))
            console.print()
            console.print(flag_table)
            console.print()
        elif flags is not None:
            console.print(Panel(str(flags.get("notes", "No feature flags observed")),
                                title="Feature Flag Monitor", border_style="dim", box=box.ROUNDED))
            console.print()
        dep_chain = analytics.get("dependency_chain")
        if dep_chain and dep_chain.get("hops", 0) > 0:
            chain_table = Table(title="Dependency Chain", box=box.ROUNDED, border_style="cyan")
            chain_table.add_column("Hop", width=5)
            chain_table.add_column("Host", style="bold", width=40)
            chain_table.add_column("Role", width=12)
            chain_table.add_column("DNS", width=10)
            chain_table.add_column("TCP", width=10)
            chain_table.add_column("Latency", width=10)
            chain_table.add_column("Health", width=10)
            for hop in dep_chain.get("chain", []):
                dns_str = "{:.0f}ms".format(hop.get("dns_ms", 0)) if hop.get("dns_ms", -1) >= 0 else "FAIL"
                tcp_str = "{:.0f}ms".format(hop.get("tcp_ms", 0)) if hop.get("tcp_ms", -1) >= 0 else "FAIL"
                health_str = "[bold green]OK[/bold green]" if hop.get("healthy") else "[bold red]FAIL[/bold red]"
                chain_table.add_row(
                    str(hop.get("hop", 0)), str(hop.get("host", "")),
                    str(hop.get("role", "")), dns_str, tcp_str,
                    "{:.0f}ms".format(hop.get("hop_latency_ms", 0)), health_str)
            console.print(Panel(
                "Status: {} | Health: {:.1f}% | Hops: {} | Critical path: {:.0f}ms".format(
                    dep_chain.get("status", "N/A"), dep_chain.get("chain_health_pct", 0),
                    dep_chain.get("hops", 0), dep_chain.get("critical_path_ms", 0)),
                title="Dependency Chain Monitor",
                border_style="green" if dep_chain.get("status") == "HEALTHY" else "yellow",
                box=box.ROUNDED))
            console.print()
            console.print(chain_table)
            spof = dep_chain.get("single_points_of_failure", [])
            if spof:
                console.print("  [bold red]Single points of failure:[/bold red] " + ", ".join(spof))
                console.print()
        automation = analytics.get("incident_response")
        if automation and automation.get("enabled"):
            actions = automation.get("actions", [])
            auto_lines = ["Automation actions: " + str(len(actions))]
            if actions:
                action_counts = {}
                for action in actions:
                    name = action.get("action", "unknown")
                    action_counts[name] = action_counts.get(name, 0) + 1
                parts = ["{}x {}".format(cnt, name) for name, cnt in sorted(action_counts.items())]
                auto_lines.append("Executed: " + ", ".join(parts))
            runbooks = automation.get("runbooks_attached", {})
            for inc_id, rb in list(runbooks.items())[:5]:
                auto_lines.append("  {} -> {} ({}, est {} min)".format(
                    inc_id, rb.get("runbook_id", "?"), rb.get("title", "?"),
                    rb.get("estimated_minutes", 0)))
            if not actions and not runbooks:
                auto_lines.append("No incidents triggered automation this session")
            console.print(Panel("\n".join(auto_lines), title="Incident Response Automation",
                                border_style="yellow", box=box.ROUNDED))
            console.print()
        notifications = analytics.get("notifications")
        if notifications:
            note_table = Table(title="Stakeholder Notifications", box=box.ROUNDED, border_style="yellow")
            note_table.add_column("Incident", width=12)
            note_table.add_column("Template", width=12)
            note_table.add_column("Severity", width=10)
            note_table.add_column("Recipients", width=35)
            note_table.add_column("Delivery", width=12)
            for note in notifications:
                recips = ", ".join(r.get("role", "?") for r in note.get("recipients", []))
                note_table.add_row(
                    note.get("incident_id", "?"), note.get("template", "?"),
                    note.get("severity", "?"), recips[:35], note.get("delivery", "?"))
            console.print(note_table)
            console.print()
        elif self.incident_automation_enabled:
            console.print(Panel("No stakeholder notifications sent this session",
                                title="Stakeholder Notifications",
                                border_style="dim", box=box.ROUNDED))
            console.print()
        roi = analytics.get("roi")
        if roi:
            roi_color = "green" if roi.get("verdict") == "POSITIVE" else "yellow"
            roi_lines = [
                "Verdict: [bold " + roi_color + "]" + str(roi.get("verdict", "N/A")) + "[/bold " + roi_color + "]",
                "Monthly monitoring cost: $" + "{:,.2f}".format(roi.get("monitoring_cost_monthly", 0)),
                "Estimated avoided downtime cost: $" + "{:,.2f}".format(roi.get("estimated_avoided_cost_monthly", 0)),
                "Net benefit: $" + "{:,.2f}".format(roi.get("net_benefit_monthly", 0)) +
                " | ROI: " + "{:.0f}".format(roi.get("roi_pct", 0)) + "%" +
                " | Payback: " + "{:.1f}".format(roi.get("payback_ratio", 0)) + "x",
                "Observed downtime cost this run: $" + "{:,.2f}".format(roi.get("cost_of_downtime_observed", 0)),
                "Projected monthly downtime risk: $" + "{:,.2f}".format(roi.get("projected_monthly_risk", 0)) +
                " (assumes {:.0f}% mitigation)".format(roi.get("mitigation_assumption_pct", 0)),
                str(roi.get("slo_note", "")),
                str(roi.get("confidence_note", "")),
            ]
            console.print(Panel("\n".join(roi_lines), title="ROI Analysis",
                                border_style=roi_color, box=box.ROUNDED))
            console.print()
        cost = analytics.get("cost", {})
        refined = cost.get("refined")
        if refined:
            refined_lines = [
                "Waste score: " + "{:.0f}".format(refined.get("waste_score", 0)) + "/100",
                "Recommended interval: " + str(refined.get("recommended_interval_seconds", 0)) + "s" +
                " (saves " + str(refined.get("checks_saved_per_day", 0)) + " checks/day, " +
                "{:.1f}".format(refined.get("estimated_monthly_savings_pct", 0)) + "% volume)",
            ]
            console.print(Panel("\n".join(refined_lines), title="Cost Optimization (Refined)",
                                border_style="cyan", box=box.ROUNDED))
            console.print()

    def _display_v7_monitoring(self):
        analytics = self.analytics_results
        if not analytics:
            return
        service_map = analytics.get("service_map")
        if service_map and service_map.get("node_count", 0) > 0:
            status = service_map.get("status", "N/A")
            status_color = "green" if status == "HEALTHY" else (
                "yellow" if status == "DEGRADED" else "red")
            map_lines = [
                "Nodes: {} | Edges: {} | Status: [bold {}]{}[/bold {}]".format(
                    service_map.get("node_count", 0), service_map.get("edge_count", 0),
                    status_color, status, status_color),
                "Blast radius: {} node(s) | Critical at risk: {}".format(
                    service_map.get("blast_radius_count", 0),
                    ", ".join(service_map.get("critical_at_risk", [])) or "none"),
            ]
            for tier_id in sorted(service_map.get("tiers", {}).keys()):
                members = service_map["tiers"][tier_id]
                map_lines.append("  Tier {}: {}".format(tier_id, ", ".join(str(m) for m in members[:8])))
            console.print(Panel("\n".join(map_lines), title="Service Dependency Map",
                                border_style=status_color, box=box.ROUNDED))
            console.print()
            map_table = Table(title="Dependency Nodes", box=box.ROUNDED, border_style="cyan")
            map_table.add_column("Node", style="bold", width=35)
            map_table.add_column("Kind", width=14)
            map_table.add_column("Tier", width=6)
            map_table.add_column("Critical", width=9)
            map_table.add_column("Health", width=10)
            map_table.add_column("Latency", width=10)
            for node in service_map.get("nodes", [])[:20]:
                health = node.get("health", "unknown")
                if health == "up":
                    health_str = "[bold green]UP[/bold green]"
                elif health == "degraded":
                    health_str = "[bold yellow]DEGRADED[/bold yellow]"
                elif health == "down":
                    health_str = "[bold red]DOWN[/bold red]"
                else:
                    health_str = "[dim]unknown[/dim]"
                latency = node.get("latency_ms", -1)
                latency_str = "{:.0f}ms".format(latency) if latency >= 0 else "n/a"
                map_table.add_row(
                    str(node.get("id", "?"))[:35], str(node.get("kind", "?")),
                    str(node.get("tier", "?")),
                    "yes" if node.get("critical") else "no",
                    health_str, latency_str)
            console.print(map_table)
            console.print()
            if service_map.get("edges"):
                edge_table = Table(title="Dependency Edges", box=box.ROUNDED, border_style="cyan")
                edge_table.add_column("Source", style="bold", width=35)
                edge_table.add_column("Target", width=35)
                edge_table.add_column("Kind", width=14)
                edge_table.add_column("Critical", width=9)
                for edge in service_map.get("edges", [])[:20]:
                    edge_table.add_row(
                        str(edge.get("source", "?"))[:35],
                        str(edge.get("target", "?"))[:35],
                        str(edge.get("kind", "?")),
                        "yes" if edge.get("critical") else "no")
                console.print(edge_table)
                console.print()
        cascade = analytics.get("cascade")
        if cascade:
            detected = cascade.get("detected", False)
            cascade_color = "red" if cascade.get("risk") == "HIGH" else (
                "yellow" if detected else "green")
            cascade_lines = [
                "Detected: [bold {}]{}[/bold {}] | Chains: {} | Max depth: {} | Risk: {}".format(
                    cascade_color, "YES" if detected else "no", cascade_color,
                    cascade.get("chain_count", 0), cascade.get("max_depth", 0),
                    cascade.get("risk", "LOW")),
                "Window: {}s | Min depth: {} | Incidents evaluated: {}".format(
                    cascade.get("window_seconds", 0), cascade.get("min_depth_required", 0),
                    cascade.get("incidents_evaluated", 0)),
            ]
            console.print(Panel("\n".join(cascade_lines), title="Cascading Failure Detection",
                                border_style=cascade_color, box=box.ROUNDED))
            console.print()
            if cascade.get("chains"):
                chain_table = Table(title="Cascade Chains", box=box.ROUNDED, border_style="red")
                chain_table.add_column("Chain", width=12)
                chain_table.add_column("Depth", width=6)
                chain_table.add_column("Origin", width=12)
                chain_table.add_column("Max Sev", width=10)
                chain_table.add_column("Span", width=10)
                chain_table.add_column("Path", width=50)
                for chain in cascade.get("chains", [])[:10]:
                    chain_table.add_row(
                        chain.get("chain_id", "?"), str(chain.get("depth", 0)),
                        chain.get("origin_incident", "?"), chain.get("max_severity", "?"),
                        "{:.0f}s".format(chain.get("span_seconds", 0)),
                        " -> ".join(str(c) for c in chain.get("categories", []))[:50])
                console.print(chain_table)
                console.print()
        maintenance = analytics.get("maintenance")
        if maintenance and maintenance.get("total_windows", 0) > 0:
            active = maintenance.get("active", False)
            maint_color = "yellow" if active else "cyan"
            maint_lines = [
                "Windows configured: {} | Active now: [bold {}]{}[/bold {}]".format(
                    maintenance.get("total_windows", 0), maint_color,
                    "YES" if active else "no", maint_color),
                "Suppressed alerts: {} | Next window in: {}".format(
                    maintenance.get("suppressed_total", 0),
                    "{} min".format(maintenance.get("minutes_until_next"))
                    if maintenance.get("minutes_until_next") is not None else "n/a"),
            ]
            if active and maintenance.get("active_window"):
                window = maintenance["active_window"]
                maint_lines.append("Active: {} [{}]".format(
                    window.get("id", "?"), window.get("label", "?")))
            console.print(Panel("\n".join(maint_lines), title="Maintenance Window Automation",
                                border_style=maint_color, box=box.ROUNDED))
            console.print()
            maint_table = Table(title="Maintenance Windows", box=box.ROUNDED, border_style="yellow")
            maint_table.add_column("ID", width=10)
            maint_table.add_column("Label", width=25)
            maint_table.add_column("Window", width=14)
            maint_table.add_column("Suppressed", width=12)
            for window in maintenance.get("windows", []):
                start_h, start_m = divmod(window.get("start_minutes", 0), 60)
                end_h, end_m = divmod(window.get("end_minutes", 0), 60)
                spec = "{:02d}:{:02d}-{:02d}:{:02d}".format(start_h, start_m, end_h, end_m)
                maint_table.add_row(
                    window.get("id", "?"), str(window.get("label", "?"))[:25],
                    spec, str(window.get("suppressed_alerts", 0)))
            for event in maintenance.get("events", [])[:8]:
                maint_table.add_row(event.get("at", "")[-8:], str(event.get("kind", ""))[:25],
                                    "", str(event.get("detail", ""))[:30])
            console.print(maint_table)
            console.print()
        fatigue = analytics.get("alert_fatigue")
        if fatigue and fatigue.get("total_evaluated", 0) > 0:
            suppression = fatigue.get("suppression_pct", 0)
            fatigue_color = "green" if suppression >= 30 else (
                "yellow" if suppression >= 10 else "cyan")
            fatigue_lines = [
                "Evaluated: {} | Sent: {} | Suppressed: {} ([bold {}]{:.1f}% removed[/bold {}])".format(
                    fatigue.get("total_evaluated", 0), fatigue.get("alerts_sent", 0),
                    fatigue.get("alerts_suppressed", 0),
                    fatigue_color, suppression, fatigue_color),
                "Noise score: {:.1f}/100 | Quiet severities: {}".format(
                    fatigue.get("noise_score", 0),
                    ", ".join(fatigue.get("quiet_severities", [])) or "none"),
            ]
            reasons = fatigue.get("suppression_reasons", {})
            if reasons:
                parts = ["{}={}".format(k, v) for k, v in sorted(reasons.items())]
                fatigue_lines.append("Reasons: " + ", ".join(parts))
            console.print(Panel("\n".join(fatigue_lines), title="Alert Fatigue Reduction",
                                border_style=fatigue_color, box=box.ROUNDED))
            console.print()
        oncall = analytics.get("oncall")
        if oncall and oncall.get("stats", {}).get("incidents_evaluated", 0) > 0:
            oc_stats = oncall.get("stats", {})
            ack_rate = oc_stats.get("ack_rate_pct", 0)
            oc_color = "green" if ack_rate >= 90 else ("yellow" if ack_rate >= 70 else "red")
            oc_lines = [
                "Ack rate: [bold {}]{:.1f}%[/bold {}] | Unacked: {} | Handoffs: {}".format(
                    oc_color, ack_rate, oc_color,
                    oc_stats.get("unacked_events", 0), oc_stats.get("handoff_events", 0)),
                "Role pages: {}".format(
                    ", ".join("{}: {}".format(r, c)
                              for r, c in oc_stats.get("role_pages", {}).items()) or "none"),
            ]
            console.print(Panel("\n".join(oc_lines), title="On-Call Simulation",
                                border_style=oc_color, box=box.ROUNDED))
            console.print()
            oc_table = Table(title="On-Call Pages", box=box.ROUNDED, border_style="cyan")
            oc_table.add_column("Incident", width=12)
            oc_table.add_column("Severity", width=10)
            oc_table.add_column("Tier", width=6)
            oc_table.add_column("Role", width=22)
            oc_table.add_column("On-Call", width=16)
            oc_table.add_column("Ack", width=8)
            oc_table.add_column("Handoff", width=10)
            for sim in oncall.get("simulations", []):
                for responder in sim.get("responders", []):
                    ack_str = "[green]yes[/green]" if responder.get("acked") else "[red]no[/red]"
                    handoff_str = "[yellow]yes[/yellow]" if responder.get("handoff_during_incident") else "no"
                    oc_table.add_row(
                        sim.get("incident_id", "?"), sim.get("severity", "?"),
                        str(responder.get("tier", "?")), str(responder.get("role", "?"))[:22],
                        str(responder.get("oncall", "?"))[:16], ack_str, handoff_str)
            console.print(oc_table)
            console.print()
            schedule = oncall.get("schedule", [])
            if schedule:
                sched_lines = []
                for shift in schedule:
                    sched_lines.append("Tier {}: {} ({}h shift) rotation: {}".format(
                        shift.get("tier", "?"), shift.get("role", "?"),
                        shift.get("shift_hours", "?"),
                        ", ".join(shift.get("rotation", []))))
                console.print(Panel("\n".join(sched_lines), title="On-Call Schedule",
                                    border_style="cyan", box=box.ROUNDED))
                console.print()
        pred_refine = analytics.get("predictive_refined")
        if pred_refine:
            band = pred_refine.get("risk_band", "STABLE")
            band_color = "red" if band in ("SEVERE", "ELEVATED") else (
                "yellow" if band == "GUARDED" else "green")
            pred_lines = [
                "Risk band: [bold {}]{}[/bold {}] | Score: {:.1f}/100 | Confidence: {:.0f}%".format(
                    band_color, band, band_color,
                    pred_refine.get("risk_score", 0), pred_refine.get("confidence", 0)),
            ]
            for factor in pred_refine.get("factors", []):
                pred_lines.append("  - " + factor)
            console.print(Panel("\n".join(pred_lines), title="Predictive Analytics (Refined)",
                                border_style=band_color, box=box.ROUNDED))
            console.print()
        cap_refine = analytics.get("capacity_refined")
        if cap_refine and cap_refine.get("available"):
            posture = cap_refine.get("posture", "n/a")
            posture_color = "green" if posture == "COMFORTABLE" else (
                "yellow" if posture == "ADEQUATE" else "red")
            cap_lines = [
                "P50: {:.0f}ms | P95: {:.0f}ms | P99: {:.0f}ms | Slope: {:+.2f} ms/check".format(
                    cap_refine.get("p50_ms", 0), cap_refine.get("p95_ms", 0),
                    cap_refine.get("p99_ms", 0), cap_refine.get("slope_ms_per_check", 0)),
                "Headroom: {:.1f}% -> {:.1f}% projected | Posture: [bold {}]{}[/bold {}]".format(
                    cap_refine.get("headroom_pct", 0),
                    cap_refine.get("projected_headroom_pct", 0),
                    posture_color, posture, posture_color),
            ]
            for rec in cap_refine.get("recommendations", []):
                cap_lines.append("  -> " + rec)
            console.print(Panel("\n".join(cap_lines), title="Capacity Planning (Refined)",
                                border_style=posture_color, box=box.ROUNDED))
            console.print()
        cost_refine = analytics.get("cost_refined")
        if cost_refine and cost_refine.get("available"):
            cost_lines = [
                "Efficiency: {:.1f}/100 | Monthly volume: {:,} checks".format(
                    cost_refine.get("efficiency_score", 0),
                    cost_refine.get("monthly_probe_volume", 0)),
                "Safe to reduce interval: {}".format(
                    "yes" if cost_refine.get("safe_to_reduce_interval") else "no"),
            ]
            recommended = cost_refine.get("recommended")
            if recommended:
                cost_lines.append("Recommended: {}s -> {:,} checks/mo ({:.1f}% reduction)".format(
                    recommended.get("interval_seconds", 0),
                    recommended.get("monthly_checks", 0),
                    recommended.get("volume_reduction_pct", 0)))
            flags = cost_refine.get("overhead_flags", [])
            if flags:
                cost_lines.append("Overhead flags: " + ", ".join(flags))
            console.print(Panel("\n".join(cost_lines), title="Cost Optimization (Refined)",
                                border_style="cyan", box=box.ROUNDED))
            console.print()
        roi_refine = analytics.get("roi_refined")
        if roi_refine and roi_refine.get("available"):
            roi_lines = [
                "Monthly downtime risk: ${:,.2f} at {:.3f}% uptime".format(
                    roi_refine.get("monthly_downtime_risk", 0),
                    roi_refine.get("current_uptime", 0)),
                "Breakeven capture rate: {:.1f}%".format(
                    roi_refine.get("breakeven_capture_rate_pct", 0)),
            ]
            for scenario in roi_refine.get("scenarios", []):
                color = "green" if scenario.get("positive") else "red"
                roi_lines.append("  {}: capture {:.0f}% -> net [bold {}]${:,.2f}[/bold {}] (ROI {:.0f}%)".format(
                    str(scenario.get("scenario", "?")).capitalize(),
                    scenario.get("capture_rate_pct", 0), color,
                    scenario.get("net_benefit_monthly", 0), color,
                    scenario.get("roi_pct", 0)))
            console.print(Panel("\n".join(roi_lines), title="ROI Analysis (Refined)",
                                border_style="green" if (roi_refine.get("best_scenario") or {}).get("positive") else "yellow",
                                box=box.ROUNDED))
            console.print()
        forecast = analytics.get("sla_forecast_refined")
        if forecast and forecast.get("available"):
            trend = forecast.get("trend", "stable")
            trend_color = "green" if trend == "improving" else (
                "red" if trend == "degrading" else "cyan")
            forecast_lines = [
                "Current: {:.3f}% | Slope: {:+.4f}%/check | Trend: [bold {}]{}[/bold {}]".format(
                    forecast.get("current_uptime", 0), forecast.get("slope_per_check", 0),
                    trend_color, trend.upper(), trend_color),
            ]
            for horizon in forecast.get("horizons", []):
                color = "green" if horizon.get("compliant") else "red"
                forecast_lines.append("  {}: {:.4f}% vs {:.3f}% - [{}]{}[/{}] (delta {:+.4f})".format(
                    horizon.get("label", "?"), horizon.get("projected_uptime", 0),
                    horizon.get("target", 0), color,
                    "COMPLIANT" if horizon.get("compliant") else "AT RISK", color,
                    horizon.get("delta_vs_target", 0)))
            first_breach = forecast.get("first_breach_horizon")
            if first_breach:
                forecast_lines.append("[bold yellow]First projected breach within: {}[/bold yellow]".format(first_breach))
            else:
                forecast_lines.append("[bold green]No breach projected within 30 days[/bold green]")
            console.print(Panel("\n".join(forecast_lines), title="SLA Forecast (Refined)",
                                border_style="red" if first_breach else "green",
                                box=box.ROUNDED))
            console.print()
        digest = analytics.get("notification_digest")
        if digest and digest.get("total", 0) > 0:
            digest_lines = [
                "Total notifications: {} | Delivery rate: {:.1f}%".format(
                    digest.get("total", 0), digest.get("delivery_rate_pct", 0)),
            ]
            by_priority = digest.get("by_priority", {})
            if by_priority:
                digest_lines.append("By priority: " + ", ".join(
                    "{}={}".format(p, c) for p, c in sorted(by_priority.items())))
            by_template = digest.get("by_template", {})
            if by_template:
                digest_lines.append("By template: " + ", ".join(
                    "{}={}".format(t, c) for t, c in sorted(by_template.items())))
            console.print(Panel("\n".join(digest_lines), title="Stakeholder Notification Digest",
                                border_style="cyan", box=box.ROUNDED))
            console.print()

    def _display_sla_compliance_forecast(self, uptime_pct):
        generator = self._build_report_generator()
        slo = self.analytics_results.get("slo", {})
        lines = generator.sla_compliance_forecast(self.analytics_results, slo, uptime_pct)
        sla_pred = self.analytics_results.get("sla_prediction", {})
        border = "red" if sla_pred.get("will_breach") else "green"
        console.print(Panel("\n".join(lines), title="SLA Compliance Forecast",
                            border_style=border, box=box.ROUNDED))
        console.print()

    def _display_executive_dashboard(self, verdict, uptime_pct, avg_score, stats):
        generator = self._build_report_generator()
        incidents = self.incident_tracker.to_list()
        slo = self.analytics_results.get("slo", {})
        lines = generator.executive_summary(
            verdict, uptime_pct, avg_score, stats,
            self.analytics_results, incidents, slo, len(self.results))
        console.print(Panel("\n".join(lines), title="Executive Summary Dashboard",
                            border_style="green" if verdict == "UP" else (
                                "yellow" if verdict == "DEGRADED" else "red"),
                            box=box.DOUBLE))
        console.print()

    def _display_technical_deep_dive(self, stats):
        generator = self._build_report_generator()
        incidents = self.incident_tracker.to_list()
        slo = self.analytics_results.get("slo", {})
        lines = generator.technical_deep_dive(stats, self.analytics_results, slo, incidents)
        console.print(Panel("\n".join(lines), title="Technical Deep Dive Report",
                            border_style="cyan", box=box.HEAVY))
        console.print()

    def _display_postmortems(self):
        if not self.postmortems:
            return
        pm_table = Table(title="Incident Post-Mortems ({} generated)".format(len(self.postmortems)),
                         box=box.ROUNDED, border_style="red")
        pm_table.add_column("Incident", width=12)
        pm_table.add_column("Severity", width=10)
        pm_table.add_column("Duration", width=12)
        pm_table.add_column("Impact", width=10)
        pm_table.add_column("Root Cause", width=35)
        pm_table.add_column("Actions", width=8)
        for pm in self.postmortems:
            sev = pm.get("severity", "?")
            if sev == "CRITICAL":
                sev_str = "[bold red]" + sev + "[/bold red]"
            elif sev == "HIGH":
                sev_str = "[bold yellow]" + sev + "[/bold yellow]"
            else:
                sev_str = sev
            pm_table.add_row(
                pm.get("incident_id", "?"),
                sev_str,
                "{:.1f}m".format(pm.get("duration_minutes", 0)),
                "{:.0f}%".format(pm.get("impact_score", 0)),
                pm.get("summary", "")[:40],
                str(len(pm.get("action_items", []))))
        console.print(pm_table)
        console.print()
        for pm in self.postmortems:
            rca = pm.get("root_cause_analysis", {})
            pm_lines = [
                pm.get("title", "Post-mortem"),
                "Cause: " + str(rca.get("primary_cause", "unknown")) + " (confidence: " + str(rca.get("confidence", "n/a")) + ")",
            ]
            for idx, step in enumerate(rca.get("causal_chain", []), 1):
                pm_lines.append("  {}. {}".format(idx, step))
            pm_lines.append("Action items:")
            for item in pm.get("action_items", []):
                pm_lines.append("  - [{}] ({}) {}".format(item["id"], item["priority"], item["action"]))
            pm_lines.append("Impact-weighted downtime units: " + "{:.2f}".format(pm.get("impact_weighted_downtime", 0)))
            console.print(Panel("\n".join(pm_lines),
                                title="Post-Mortem " + pm.get("incident_id", ""),
                                border_style="red", box=box.ROUNDED))
            console.print()

    def _display_http_details_rich(self):
        if self.dns_info:
            dns_table = Table(title="DNS Information", box=box.ROUNDED, border_style="cyan")
            dns_table.add_column("Property", style="bold", width=25)
            dns_table.add_column("Value", width=50)
            dns_table.add_row("IPv4 Records", ", ".join(self.dns_info.get("a_records", [])) or "None")
            dns_table.add_row("IPv6 Records", ", ".join(self.dns_info.get("aaaa_records", [])) or "None")
            dns_table.add_row("Nameservers", ", ".join(self.dns_info.get("ns_records", [])) or "None")
            mx_list = [m["priority"] + " " + m["host"] for m in self.dns_info.get("mx_records", [])]
            dns_table.add_row("MX Records", ", ".join(mx_list) or "None")
            dns_table.add_row("CNAME Records", ", ".join(self.dns_info.get("cname_records", [])) or "None")
            spf = self.dns_info.get("spf_record", "")
            dns_table.add_row("SPF Record", spf[:80] if spf else "None")
            dkim = self.dns_info.get("dkim_record", "")
            dns_table.add_row("DKIM Record", dkim[:80] if dkim else "None")
            res_time = "{:.1f}".format(self.dns_info.get("resolution_time", 0))
            dns_table.add_row("Resolution Time", res_time + "ms")
            dns_table.add_row("Round-Robin", "Yes" if self.dns_info.get("round_robin") else "No")
            soa = self.dns_info.get("soa_record", {})
            if soa:
                dns_table.add_row("SOA Serial", soa.get("serial", "N/A"))
                dns_table.add_row("SOA Primary NS", soa.get("primary_ns", "N/A"))
            srv = self.dns_info.get("srv_records", [])
            if srv:
                for s in srv[:3]:
                    dns_table.add_row("SRV", s.get("priority", "") + " " + s.get("target", ""))
            caa = self.dns_info.get("caa_records", [])
            if caa:
                for c in caa[:3]:
                    dns_table.add_row("CAA", c.get("tag", "") + " " + c.get("value", ""))
            console.print(dns_table)
            console.print()
            changes = self.dns_info.get("record_changes", {})
            if changes:
                ch_table = Table(title="DNS Record Changes Detected", box=box.ROUNDED, border_style="yellow")
                ch_table.add_column("Record Type", style="bold", width=12)
                ch_table.add_column("Previous", width=35)
                ch_table.add_column("Current", width=35)
                for rtype, chg in changes.items():
                    prev = ", ".join(chg.get("previous", [])) or "None"
                    curr = ", ".join(chg.get("current", [])) or "None"
                    ch_table.add_row(rtype, prev[:70], curr[:70])
                console.print(ch_table)
                console.print()
            ttl = self.dns_info.get("ttl_analysis", {})
            if ttl and ttl.get("records"):
                ttl_table = Table(title="DNS TTL Analysis", box=box.ROUNDED, border_style="cyan")
                ttl_table.add_column("Record Type", style="bold", width=15)
                ttl_table.add_column("TTL (seconds)", width=15)
                for rtype, val in ttl["records"].items():
                    ttl_table.add_row(rtype, str(val))
                ttl_table.add_row("Average TTL", "{:.0f}".format(ttl.get("avg_ttl", 0)) + "s")
                if ttl.get("warning"):
                    ttl_table.add_row("Warning", "[bold yellow]" + ttl["warning"] + "[/bold yellow]")
                console.print(ttl_table)
                console.print()
            doh = self.dns_info.get("dns_over_https", {})
            if doh:
                doh_table = Table(title="DNS-over-HTTPS", box=box.ROUNDED, border_style="cyan")
                doh_table.add_column("Property", style="bold", width=25)
                doh_table.add_column("Value", width=50)
                doh_table.add_row("Supported", "[bold green]Yes[/bold green]" if doh.get("supported") else "[bold red]No[/bold red]")
                doh_table.add_row("Latency", "{:.1f}".format(doh.get("latency_ms", 0)) + "ms")
                if doh.get("records"):
                    doh_table.add_row("Answers", str(doh["records"].get("answer_count", 0)))
                if doh.get("error"):
                    doh_table.add_row("Error", doh["error"])
                console.print(doh_table)
                console.print()
            multi = self.dns_info.get("multi_provider", {})
            if multi:
                mp_table = Table(title="Multi-Provider DNS Comparison", box=box.ROUNDED, border_style="cyan")
                mp_table.add_column("Provider", style="bold", width=15)
                mp_table.add_column("Server", width=18)
                mp_table.add_column("Records", width=25)
                mp_table.add_column("Matches Primary", width=15)
                for name, info in multi.items():
                    recs = ", ".join(info.get("records", [])[:2]) or "None"
                    match = info.get("matches_primary", False)
                    match_str = "[bold green]Yes[/bold green]" if match else "[bold red]No[/bold red]"
                    mp_table.add_row(name, info.get("server", ""), recs, match_str)
                console.print(mp_table)
                console.print()
            if self.dns_info.get("propagation"):
                prop_table = Table(title="DNS Propagation", box=box.ROUNDED, border_style="cyan")
                prop_table.add_column("DNS Server", style="bold", width=15)
                prop_table.add_column("IP", width=18)
                prop_table.add_column("Resolved", width=20)
                prop_table.add_column("Consistent", width=12)
                for server_name, info in self.dns_info["propagation"].items():
                    records = ", ".join(info.get("records", [])[:2]) or "None"
                    consistent = info.get("consistent", False)
                    if consistent:
                        cons_str = "[bold green]Yes[/bold green]"
                    else:
                        cons_str = "[bold red]No[/bold red]"
                    prop_table.add_row(server_name, info.get("server", ""), records, cons_str)
                console.print(prop_table)
                console.print()
            if self.dns_info.get("dnssec"):
                dnssec = self.dns_info["dnssec"]
                dnssec_table = Table(title="DNSSEC Validation", box=box.ROUNDED, border_style="cyan")
                dnssec_table.add_column("Property", style="bold", width=25)
                dnssec_table.add_column("Value", width=50)
                ds = dnssec.get("status", "UNKNOWN")
                if ds == "SECURED":
                    ds_str = "[bold green]" + ds + "[/bold green]"
                elif ds in ("NOT_SECURED", "CHECK_FAILED"):
                    ds_str = "[bold red]" + ds + "[/bold red]"
                else:
                    ds_str = "[bold yellow]" + ds + "[/bold yellow]"
                dnssec_table.add_row("Status", ds_str)
                dnssec_table.add_row("Details", dnssec.get("details", "N/A"))
                if dnssec.get("chain"):
                    for line in dnssec["chain"][:3]:
                        dnssec_table.add_row("Chain", line[:50])
                console.print(dnssec_table)
                console.print()
        if self.ssl_info:
            self._display_ssl_table()
        if self.redirect_chain and self.redirect_chain.get("hop_count", 0) > 0:
            redir_table = Table(title="Redirect Analysis", box=box.ROUNDED, border_style="cyan")
            redir_table.add_column("Hop", width=6)
            redir_table.add_column("URL", width=50)
            redir_table.add_column("Status", width=10)
            redir_table.add_column("Time", width=12)
            for i, hop in enumerate(self.redirect_chain.get("chain", []), 1):
                redir_table.add_row(str(i), hop["url"], str(hop["status"]),
                                    "{:.0f}".format(hop["time"]) + "ms")
            console.print(redir_table)
            console.print()
            if self.redirect_chain.get("http_to_https"):
                console.print("  [bold green]+[/bold green] HTTP -> HTTPS redirect enabled")
            if self.redirect_chain.get("www_redirect"):
                console.print("  [bold green]+[/bold green] WWW redirect present")
            console.print()
        if self.headers_info:
            headers_table = Table(title="Headers Analysis", box=box.ROUNDED, border_style="cyan")
            headers_table.add_column("Header", style="bold", width=30)
            headers_table.add_column("Value", width=45)
            for k, v in self.headers_info.items():
                headers_table.add_row(k, v)
            console.print(headers_table)
            console.print()
        if self.extended_info:
            self._display_extended_rich()
        if self.content_info:
            content_table = Table(title="Content Check", box=box.ROUNDED, border_style="cyan")
            content_table.add_column("Property", style="bold", width=25)
            content_table.add_column("Value", width=50)
            content_table.add_row("Page Size", self.content_info.get("page_size_human", "N/A"))
            content_table.add_row("Content Type", self.content_info.get("content_type", "N/A"))
            if self.expect:
                exp = self.content_info.get("has_expected_content", False)
                if exp:
                    content_table.add_row("Expected Content", "[bold green]FOUND[/bold green]")
                else:
                    content_table.add_row("Expected Content", "[bold red]NOT FOUND[/bold red]")
            console.print(content_table)
            console.print()

    def _display_ssl_table(self):
        ssl_table = Table(title="SSL Certificate", box=box.ROUNDED, border_style="cyan")
        ssl_table.add_column("Property", style="bold", width=25)
        ssl_table.add_column("Value", width=50)
        status = self.ssl_info.get("status", "UNKNOWN")
        if status == "VALID":
            ssl_status_str = "[bold green]" + status + "[/bold green]"
        elif status == "WARNING":
            ssl_status_str = "[bold yellow]" + status + "[/bold yellow]"
        else:
            ssl_status_str = "[bold red]" + status + "[/bold red]"
        ssl_table.add_row("Status", ssl_status_str)
        ssl_table.add_row("Issuer", self.ssl_info.get("issuer", "N/A"))
        ssl_table.add_row("Subject", self.ssl_info.get("subject", "N/A"))
        ssl_table.add_row("SANs", ", ".join(self.ssl_info.get("sans", [])[:5]) or "None")
        ssl_table.add_row("Expiry Date", self.ssl_info.get("expiry", "N/A"))
        days = self.ssl_info.get("days_until_expiry", 0)
        if days < 7:
            ssl_table.add_row("Days Until Expiry", "[bold red]" + str(days) + "[/bold red]")
        elif days < 30:
            ssl_table.add_row("Days Until Expiry", "[bold yellow]" + str(days) + "[/bold yellow]")
        else:
            ssl_table.add_row("Days Until Expiry", "[bold green]" + str(days) + "[/bold green]")
        if self.ssl_info.get("chain_valid"):
            chain = self.ssl_info["chain_valid"]
            if isinstance(chain, dict):
                if chain.get("valid"):
                    chain_str = "[bold green]Valid[/bold green]"
                else:
                    chain_str = "[bold red]Invalid[/bold red]"
                ssl_table.add_row("Chain Validation", chain_str)
                ssl_table.add_row("Chain Depth", str(chain.get("depth", 0)))
        ocsp = self.ssl_info.get("ocsp_status", "UNKNOWN")
        if ocsp in ("GOOD", "SUCCESSFUL"):
            ocsp_str = "[bold green]" + ocsp + "[/bold green]"
        elif ocsp == "REVOKED":
            ocsp_str = "[bold red]" + ocsp + "[/bold red]"
        else:
            ocsp_str = "[bold yellow]" + ocsp + "[/bold yellow]"
        ssl_table.add_row("OCSP Status", ocsp_str)
        ct = self.ssl_info.get("ct_logs", [])
        ssl_table.add_row("CT Logs", "; ".join(ct) if ct else "None detected")
        cipher = self.ssl_info.get("cipher_suite", "")
        if cipher:
            ssl_table.add_row("Cipher Suite", cipher)
        key_size = self.ssl_info.get("key_size", 0)
        if key_size:
            ssl_table.add_row("Key Size", str(key_size) + " bits")
        console.print(ssl_table)
        console.print()

    def _display_tcp_details_rich(self):
        if self.results and self.results[0].get("tcp"):
            tcp = self.results[0]["tcp"]
            tcp_table = Table(title="TCP Port Check", box=box.ROUNDED, border_style="cyan")
            tcp_table.add_column("Property", style="bold", width=25)
            tcp_table.add_column("Value", width=50)
            avail = tcp.get("available", False)
            tcp_table.add_row("Host", tcp.get("host", "N/A"))
            tcp_table.add_row("Port", str(tcp.get("port", 0)))
            tcp_table.add_row("Available", "[bold green]Yes[/bold green]" if avail else "[bold red]No[/bold red]")
            tcp_table.add_row("Response Time", "{:.1f}".format(tcp.get("response_time_ms", 0)) + "ms")
            banner = tcp.get("banner", "")
            if banner:
                tcp_table.add_row("Banner", banner[:60])
            if tcp.get("error"):
                tcp_table.add_row("Error", tcp["error"])
            console.print(tcp_table)
            console.print()

    def _display_smtp_details_rich(self):
        if self.results and self.results[0].get("smtp"):
            smtp = self.results[0]["smtp"]
            smtp_table = Table(title="SMTP Check", box=box.ROUNDED, border_style="cyan")
            smtp_table.add_column("Property", style="bold", width=25)
            smtp_table.add_column("Value", width=50)
            smtp_table.add_row("Host", smtp.get("host", "N/A"))
            smtp_table.add_row("Port", str(smtp.get("port", 0)))
            avail = smtp.get("available", False)
            smtp_table.add_row("Available", "[bold green]Yes[/bold green]" if avail else "[bold red]No[/bold red]")
            smtp_table.add_row("Banner", smtp.get("banner", "")[:60])
            smtp_table.add_row("STARTTLS", "[bold green]Supported[/bold green]" if smtp.get("starttls") else "[bold red]Not Supported[/bold red]")
            auth = smtp.get("auth_methods", [])
            smtp_table.add_row("Auth Methods", ", ".join(auth) if auth else "None")
            smtp_table.add_row("Response Time", "{:.1f}".format(smtp.get("response_time_ms", 0)) + "ms")
            if smtp.get("error"):
                smtp_table.add_row("Error", smtp["error"])
            console.print(smtp_table)
            console.print()

    def _display_ftp_details_rich(self):
        if self.results and self.results[0].get("ftp"):
            ftp = self.results[0]["ftp"]
            ftp_table = Table(title="FTP Check", box=box.ROUNDED, border_style="cyan")
            ftp_table.add_column("Property", style="bold", width=25)
            ftp_table.add_column("Value", width=50)
            ftp_table.add_row("Host", ftp.get("host", "N/A"))
            ftp_table.add_row("Port", str(ftp.get("port", 21)))
            avail = ftp.get("available", False)
            ftp_table.add_row("Available", "[bold green]Yes[/bold green]" if avail else "[bold red]No[/bold red]")
            ftp_table.add_row("Banner", ftp.get("banner", "")[:60])
            ftp_table.add_row("Anonymous Login", "[bold green]Allowed[/bold green]" if ftp.get("anonymous_login") else "[bold red]Denied[/bold red]")
            ftp_table.add_row("TLS Support", "[bold green]Yes[/bold green]" if ftp.get("tls_support") else "[bold red]No[/bold red]")
            ftp_table.add_row("Response Time", "{:.1f}".format(ftp.get("response_time_ms", 0)) + "ms")
            if ftp.get("error"):
                ftp_table.add_row("Error", ftp["error"])
            console.print(ftp_table)
            console.print()

    def _display_ssh_details_rich(self):
        if self.results and self.results[0].get("ssh"):
            ssh = self.results[0]["ssh"]
            ssh_table = Table(title="SSH Check", box=box.ROUNDED, border_style="cyan")
            ssh_table.add_column("Property", style="bold", width=25)
            ssh_table.add_column("Value", width=50)
            ssh_table.add_row("Host", ssh.get("host", "N/A"))
            ssh_table.add_row("Port", str(ssh.get("port", 22)))
            avail = ssh.get("available", False)
            ssh_table.add_row("Available", "[bold green]Yes[/bold green]" if avail else "[bold red]No[/bold red]")
            ssh_table.add_row("Banner", ssh.get("banner", "")[:60])
            ssh_table.add_row("Protocol", ssh.get("protocol_version", "N/A"))
            kex = ssh.get("key_exchange", [])
            if kex:
                ssh_table.add_row("Key Exchange", ", ".join(kex[:3]))
            ssh_table.add_row("Response Time", "{:.1f}".format(ssh.get("response_time_ms", 0)) + "ms")
            if ssh.get("error"):
                ssh_table.add_row("Error", ssh["error"])
            console.print(ssh_table)
            console.print()

    def _display_ping_details_rich(self):
        if self.results and self.results[0].get("ping"):
            ping = self.results[0]["ping"]
            ping_table = Table(title="ICMP Ping Check", box=box.ROUNDED, border_style="cyan")
            ping_table.add_column("Property", style="bold", width=25)
            ping_table.add_column("Value", width=50)
            ping_table.add_row("Host", ping.get("host", "N/A"))
            avail = ping.get("available", False)
            ping_table.add_row("Available", "[bold green]Yes[/bold green]" if avail else "[bold red]No[/bold red]")
            sent = ping.get("packets_sent", 0)
            recv = ping.get("packets_received", 0)
            ping_table.add_row("Packets Sent", str(sent))
            ping_table.add_row("Packets Received", str(recv))
            loss = ping.get("loss_pct", 100)
            if loss == 0:
                loss_str = "[bold green]{:.1f}%[/bold green]".format(loss)
            elif loss < 20:
                loss_str = "[bold yellow]{:.1f}%[/bold yellow]".format(loss)
            else:
                loss_str = "[bold red]{:.1f}%[/bold red]".format(loss)
            ping_table.add_row("Packet Loss", loss_str)
            ping_table.add_row("Min RTT", "{:.2f}".format(ping.get("min_rtt", 0)) + "ms")
            ping_table.add_row("Avg RTT", "{:.2f}".format(ping.get("avg_rtt", 0)) + "ms")
            ping_table.add_row("Max RTT", "{:.2f}".format(ping.get("max_rtt", 0)) + "ms")
            if ping.get("error"):
                ping_table.add_row("Error", ping["error"])
            console.print(ping_table)
            console.print()

    def _display_dns_details_rich(self):
        if self.results and self.results[0].get("dns"):
            dns = self.results[0]["dns"]
            dns_table = Table(title="DNS Check", box=box.ROUNDED, border_style="cyan")
            dns_table.add_column("Property", style="bold", width=25)
            dns_table.add_column("Value", width=50)
            dns_table.add_row("Hostname", self.hostname)
            dns_table.add_row("IPv4 Records", ", ".join(dns.get("a_records", [])) or "None")
            dns_table.add_row("IPv6 Records", ", ".join(dns.get("aaaa_records", [])) or "None")
            dns_table.add_row("Nameservers", ", ".join(dns.get("ns_records", [])) or "None")
            mx_list = [m["priority"] + " " + m["host"] for m in dns.get("mx_records", [])]
            dns_table.add_row("MX Records", ", ".join(mx_list) or "None")
            dns_table.add_row("TXT Records", str(len(dns.get("txt_records", []))) + " found")
            dns_table.add_row("CNAME Records", ", ".join(dns.get("cname_records", [])) or "None")
            res_time = "{:.1f}".format(dns.get("resolution_time", 0))
            dns_table.add_row("Resolution Time", res_time + "ms")
            dns_table.add_row("Round-Robin", "Yes" if dns.get("round_robin") else "No")
            console.print(dns_table)
            console.print()
            changes = dns.get("record_changes", {})
            if changes:
                ch_table = Table(title="DNS Record Changes Detected", box=box.ROUNDED, border_style="yellow")
                ch_table.add_column("Record Type", style="bold", width=12)
                ch_table.add_column("Previous", width=35)
                ch_table.add_column("Current", width=35)
                for rtype, chg in changes.items():
                    prev = ", ".join(chg.get("previous", [])) or "None"
                    curr = ", ".join(chg.get("current", [])) or "None"
                    ch_table.add_row(rtype, prev[:70], curr[:70])
                console.print(ch_table)
                console.print()
            ttl = dns.get("ttl_analysis", {})
            if ttl and ttl.get("records"):
                ttl_table = Table(title="DNS TTL Analysis", box=box.ROUNDED, border_style="cyan")
                ttl_table.add_column("Record Type", style="bold", width=15)
                ttl_table.add_column("TTL (seconds)", width=15)
                for rtype, val in ttl["records"].items():
                    ttl_table.add_row(rtype, str(val))
                ttl_table.add_row("Average TTL", "{:.0f}".format(ttl.get("avg_ttl", 0)) + "s")
                if ttl.get("warning"):
                    ttl_table.add_row("Warning", "[bold yellow]" + ttl["warning"] + "[/bold yellow]")
                console.print(ttl_table)
                console.print()
            doh = dns.get("dns_over_https", {})
            if doh:
                doh_table = Table(title="DNS-over-HTTPS", box=box.ROUNDED, border_style="cyan")
                doh_table.add_column("Property", style="bold", width=25)
                doh_table.add_column("Value", width=50)
                doh_table.add_row("Supported", "[bold green]Yes[/bold green]" if doh.get("supported") else "[bold red]No[/bold red]")
                doh_table.add_row("Latency", "{:.1f}".format(doh.get("latency_ms", 0)) + "ms")
                if doh.get("records"):
                    doh_table.add_row("Answers", str(doh["records"].get("answer_count", 0)))
                console.print(doh_table)
                console.print()
            multi = dns.get("multi_provider", {})
            if multi:
                mp_table = Table(title="Multi-Provider DNS Comparison", box=box.ROUNDED, border_style="cyan")
                mp_table.add_column("Provider", style="bold", width=15)
                mp_table.add_column("Server", width=18)
                mp_table.add_column("Records", width=25)
                mp_table.add_column("Matches Primary", width=15)
                for name, info in multi.items():
                    recs = ", ".join(info.get("records", [])[:2]) or "None"
                    match = info.get("matches_primary", False)
                    match_str = "[bold green]Yes[/bold green]" if match else "[bold red]No[/bold red]"
                    mp_table.add_row(name, info.get("server", ""), recs, match_str)
                console.print(mp_table)
                console.print()
            if dns.get("propagation"):
                prop_table = Table(title="DNS Propagation", box=box.ROUNDED, border_style="cyan")
                prop_table.add_column("DNS Server", style="bold", width=15)
                prop_table.add_column("IP", width=18)
                prop_table.add_column("Resolved", width=20)
                prop_table.add_column("Consistent", width=12)
                for server_name, info in dns["propagation"].items():
                    records = ", ".join(info.get("records", [])[:2]) or "None"
                    consistent = info.get("consistent", False)
                    cons_str = "[bold green]Yes[/bold green]" if consistent else "[bold red]No[/bold red]"
                    prop_table.add_row(server_name, info.get("server", ""), records, cons_str)
                console.print(prop_table)
                console.print()
            if dns.get("dnssec"):
                dnssec = dns["dnssec"]
                dnssec_table = Table(title="DNSSEC Validation", box=box.ROUNDED, border_style="cyan")
                dnssec_table.add_column("Property", style="bold", width=25)
                dnssec_table.add_column("Value", width=50)
                ds = dnssec.get("status", "UNKNOWN")
                if ds == "SECURED":
                    ds_str = "[bold green]" + ds + "[/bold green]"
                elif ds in ("NOT_SECURED", "CHECK_FAILED"):
                    ds_str = "[bold red]" + ds + "[/bold red]"
                else:
                    ds_str = "[bold yellow]" + ds + "[/bold yellow]"
                dnssec_table.add_row("Status", ds_str)
                dnssec_table.add_row("Details", dnssec.get("details", "N/A"))
                console.print(dnssec_table)
                console.print()

    def _display_extended_rich(self):
        ext = self.extended_info
        cdn_list = ext.get("cdn", [])
        if cdn_list:
            console.print("  [bold cyan]CDN:[/bold cyan] " + ", ".join(cdn_list))
        lb_list = ext.get("load_balancer", [])
        if lb_list:
            console.print("  [bold cyan]Load Balancer:[/bold cyan] " + ", ".join(lb_list))
        tech_list = ext.get("technologies", [])
        if tech_list:
            console.print("  [bold cyan]Technologies:[/bold cyan] " + ", ".join(tech_list))
        http23 = ext.get("http23", {})
        if http23:
            h2_str = "[bold green]Yes[/bold green]" if http23.get("http2") else "[bold red]No[/bold red]"
            h3_str = "[bold green]Yes[/bold green]" if http23.get("http3") else "[bold red]No[/bold red]"
            console.print("  [bold cyan]HTTP/2:[/bold cyan] " + h2_str + "  [bold cyan]HTTP/3:[/bold cyan] " + h3_str)
        mx_health = ext.get("mx_health", {})
        if mx_health.get("records"):
            mx_table = Table(title="MX Record Health", box=box.ROUNDED, border_style="cyan")
            mx_table.add_column("Host", style="bold", width=30)
            mx_table.add_column("Priority", width=10)
            mx_table.add_column("Resolves", width=10)
            for mx in mx_health["records"]:
                resolve_str = "[bold green]Yes[/bold green]" if mx["resolves"] else "[bold red]No[/bold red]"
                mx_table.add_row(mx["host"], mx["priority"], resolve_str)
            console.print(mx_table)
        maint = ext.get("maintenance_window", {})
        if maint.get("detected"):
            console.print("  [bold red]MAINTENANCE WINDOW DETECTED[/bold red]")
            for indicator in maint.get("indicators", []):
                console.print("    - " + indicator)
        hsts = ext.get("hsts_preload", {})
        if hsts:
            hsts_enabled = hsts.get("enabled", False)
            on_list = hsts.get("on_list", False)
            if hsts_enabled:
                preload_val = "Yes" if hsts.get("preload") else "No"
                on_list_val = "Yes" if on_list else "No"
                console.print("  [bold cyan]HSTS:[/bold cyan] Enabled (preload: " + preload_val + ", on preload list: " + on_list_val + ")")
            else:
                console.print("  [bold cyan]HSTS:[/bold cyan] [bold red]Not enabled[/bold red]")
        geo = ext.get("geographic", {})
        if geo:
            geo_table = Table(title="Geographic Response", box=box.ROUNDED, border_style="cyan")
            geo_table.add_column("Region/DNS", style="bold", width=15)
            geo_table.add_column("Server IP", width=18)
            geo_table.add_column("Resolved", width=10)
            geo_table.add_column("Response", width=12)
            for region, info in geo.items():
                resolved_str = "[bold green]Yes[/bold green]" if info.get("resolved") else "[bold red]No[/bold red]"
                rt = info.get("response_time_ms", -1)
                rt_str = "{:.1f}".format(rt) + "ms" if rt >= 0 else "N/A"
                geo_table.add_row(region, info.get("server_ip", ""), resolved_str, rt_str)
            console.print(geo_table)
            self._display_geo_ascii_map(geo)
        deps = ext.get("dependencies", [])
        if deps:
            dep_table = Table(title="External Dependencies", box=box.ROUNDED, border_style="cyan")
            dep_table.add_column("Domain", style="bold", width=40)
            dep_table.add_column("Type", width=15)
            for dep in deps[:15]:
                dep_table.add_row(dep["domain"], dep["type"])
            if len(deps) > 15:
                dep_table.add_row("... and " + str(len(deps) - 15) + " more", "")
            console.print(dep_table)
        console.print()

    def _display_geo_ascii_map(self, geo):
        if not geo:
            return
        lines = ["    Geographic Availability Map", "    " + "-" * 40]
        region_map = {"Google": "  [NA] ", "Cloudflare": "  [EU] ", "Quad9": "  [AS] "}
        for region, info in geo.items():
            prefix = region_map.get(region, "  [?] ")
            resolved = info.get("resolved", False)
            rt = info.get("response_time_ms", -1)
            if resolved and rt >= 0:
                if rt < 100:
                    indicator = "[bold green]*[/bold green]"
                elif rt < 300:
                    indicator = "[yellow]*[/yellow]"
                else:
                    indicator = "[red]*[/red]"
                lines.append(prefix + indicator + " " + region + " (" + "{:.0f}".format(rt) + "ms)")
            else:
                lines.append(prefix + "[red]x[/red] " + region + " (unreachable)")
        lines.append("    " + "-" * 40)
        lines.append("    [green]*[/green] <100ms  [yellow]*[/yellow] <300ms  [red]*[/red] >300ms  [red]x[/red] down")
        console.print(Panel("\n".join(lines), title="Geo Map", border_style="cyan", box=box.ROUNDED))

    def _display_status_page(self, verdict, uptime_pct, stats):
        if verdict == "UP":
            verdict_color = "green"
        elif verdict == "DEGRADED":
            verdict_color = "yellow"
        else:
            verdict_color = "red"
        status_line = "[bold " + verdict_color + "]STATUS: " + verdict + "[/bold " + verdict_color + "]"
        uptime_str = "{:.2f}".format(uptime_pct)
        avg_resp = "{:.0f}".format(stats["avg_time"])
        num_checks = str(len(self.results))
        err_rate = "{:.1f}".format(stats["error_rate"])
        content = (
            status_line + "\n"
            "Uptime: " + uptime_str + "%  |  "
            "Avg Response: " + avg_resp + "ms  |  "
            "Checks: " + num_checks + "  |  "
            "Error Rate: " + err_rate + "%  |  "
            "Protocol: " + self.protocol.upper())
        if self.multi_region and self.multi_region_monitor:
            mr_summary = self.multi_region_monitor.get_summary()
            content += "\nRegions: " + str(mr_summary["available_regions"]) + "/" + str(mr_summary["total_regions"]) + " available  |  "
            content += "Avg Region Latency: " + "{:.0f}".format(mr_summary["avg_latency"]) + "ms"
        if self.analytics_results:
            sla_pred = self.analytics_results.get("sla_prediction", {})
            if sla_pred:
                breach_str = "BREACH RISK" if sla_pred.get("will_breach") else "OK"
                content += "\nSLA Prediction: " + breach_str + "  |  "
                content += "Projected: " + "{:.2f}".format(sla_pred.get("projected_uptime", 0)) + "%"
        console.print(Panel(content, title="Status Page", border_style=verdict_color, box=box.HEAVY))

    def _display_availability_calendar(self, stats):
        if len(self.results) < 2:
            return
        cols = min(40, len(self.results))
        row_chars = []
        for r in self.results[:cols]:
            sc = r["status"].get("status_code", 0)
            if 200 <= sc < 300:
                row_chars.append("[green].[/green]")
            elif 300 <= sc < 400:
                row_chars.append("[yellow]r[/yellow]")
            elif r.get("error"):
                row_chars.append("[red]x[/red]")
            else:
                row_chars.append("[red]x[/red]")
        line = " ".join(row_chars)
        total = str(len(self.results))
        console.print(Panel(
            "Check results (" + total + " total):\n" + line + "\n\n"
            "[green].[/green] = OK  [yellow]r[/yellow] = Redirect  [red]x[/red] = Error",
            title="Availability Calendar", border_style="cyan", box=box.ROUNDED))
        console.print()

    def _display_sla_report(self, uptime_pct, stats):
        sla_compliant, sla_status = EnhancedStats.sla_compliance(uptime_pct, self.sla_target)
        sla_formatted = EnhancedStats.format_sla_uptime(uptime_pct)
        sla_color = "green" if sla_compliant else "red"
        sla_text = "[bold " + sla_color + "]" + sla_status + "[/bold " + sla_color + "]"
        lines = ["Target SLA: " + "{:.3f}".format(self.sla_target) + "%",
                 "Actual Uptime: " + sla_formatted,
                 "Compliance: " + sla_text]
        if stats.get("mtbf") is not None:
            lines.append("MTBF: " + "{:.1f}".format(stats["mtbf"]) + " check intervals")
        if stats.get("mttr") is not None:
            lines.append("MTTR: " + "{:.1f}".format(stats["mttr"]) + " check intervals")
        lines.append("Error Rate: " + "{:.2f}".format(stats["error_rate"]) + "%")
        if self.analytics_results:
            sla_pred = self.analytics_results.get("sla_prediction", {})
            if sla_pred.get("confidence", 0) > 0:
                lines.append("")
                lines.append("--- SLA Breach Prediction ---")
                lines.append("Breach Risk: " + ("YES" if sla_pred.get("will_breach") else "NO"))
                lines.append("Current Uptime: " + "{:.2f}".format(sla_pred.get("current_uptime", 0)) + "%")
                lines.append("Projected Uptime: " + "{:.2f}".format(sla_pred.get("projected_uptime", 0)) + "%")
                lines.append("Trend: " + "{:.4f}%/check".format(sla_pred.get("slope", 0)))
                lines.append("Confidence: " + "{:.0f}%".format(sla_pred.get("confidence", 0)))
                lines.append(sla_pred.get("reason", ""))
        console.print(Panel("\n".join(lines), title="SLA Compliance Report", border_style=sla_color, box=box.ROUNDED))
        console.print()

    def _display_performance_trend(self, stats):
        lines = []
        trend = stats["response_time_trend"]
        if trend > 1:
            lines.append("Response Time: [bold red]+{:.1f} ms/check (degrading)[/bold red]".format(trend))
        elif trend < -1:
            lines.append("Response Time: [bold green]{:.1f} ms/check (improving)[/bold green]".format(trend))
        else:
            lines.append("Response Time: Stable")
        err_trend = stats.get("error_rate_trend", [])
        if err_trend and len(err_trend) >= 2:
            recent = err_trend[-1]
            initial = err_trend[0]
            if recent > initial + 5:
                lines.append("Error Rate: [bold red]Increasing ({:.1f}% -> {:.1f}%)[/bold red]".format(initial, recent))
            elif recent < initial - 5:
                lines.append("Error Rate: [bold green]Decreasing ({:.1f}% -> {:.1f}%)[/bold green]".format(initial, recent))
            else:
                lines.append("Error Rate: Stable ({:.1f}%)".format(recent))
        pcts = stats["percentiles"]
        lines.append("Latency Distribution: P50={:.0f}ms P90={:.0f}ms P95={:.0f}ms P99={:.0f}ms".format(
            pcts["p50"], pcts["p90"], pcts["p95"], pcts["p99"]))
        if self.analytics_results:
            lines.append("")
            lines.append("--- Performance Trend Graph ---")
            times = [r.get("timing", {}).get("total", 0) for r in self.results
                     if r.get("timing", {}).get("total", 0) > 0]
            if times:
                graph = self._build_ascii_graph(times, width=50, height=8)
                lines.append(graph)
        console.print(Panel("\n".join(lines), title="Performance Trend Analysis", border_style="cyan", box=box.ROUNDED))
        console.print()

    def _build_ascii_graph(self, values, width=50, height=8):
        if not values:
            return "No data"
        n = len(values)
        min_val = min(values)
        max_val = max(values)
        val_range = max_val - min_val
        if val_range == 0:
            val_range = 1
        sampled = values
        if n > width:
            step = n / width
            sampled = [values[int(i * step)] for i in range(width)]
        grid = [[" " for _ in range(len(sampled))] for _ in range(height)]
        for col, val in enumerate(sampled):
            row = int(((val - min_val) / val_range) * (height - 1))
            row = max(0, min(height - 1, row))
            for r in range(row + 1):
                if r == row:
                    grid[r][col] = "*"
                elif r > row - 3:
                    grid[r][col] = "."
        lines = []
        lines.append("  Max: {:.0f}ms".format(max_val))
        for row_idx in range(height - 1, -1, -1):
            if row_idx == height - 1:
                prefix = "  "
            elif row_idx == 0:
                prefix = "  "
            else:
                prefix = "  "
            line = prefix + "".join(grid[row_idx])
            lines.append(line)
        lines.append("  Min: {:.0f}ms".format(min_val))
        lines.append("  " + "-" * len(sampled))
        return "\n".join(lines)

    def _build_summary_verdict(self, verdict, uptime_pct, avg_score, stats):
        lines = []
        if verdict == "UP":
            lines.append("[bold green]STATUS: UP[/bold green] \u2014 Target is operational")
        elif verdict == "DEGRADED":
            lines.append("[bold yellow]STATUS: DEGRADED[/bold yellow] \u2014 Target experiencing issues")
        else:
            lines.append("[bold red]STATUS: DOWN[/bold red] \u2014 Target is unreachable")
        lines.append("Protocol: " + self.protocol.upper())
        lines.append("Target: " + self.target_label)
        lines.append("Uptime: " + "{:.2f}".format(uptime_pct) + "%")
        lines.append("Avg Score: " + "{:.0f}".format(avg_score) + "/100")
        if self.results:
            lines.append("Checks: " + str(len(self.results)))
            lines.append("Avg Response: " + "{:.0f}".format(stats["avg_time"]) + "ms")
            lines.append("Error Rate: " + "{:.2f}".format(stats["error_rate"]) + "%")
        sla_compliant, sla_status = EnhancedStats.sla_compliance(uptime_pct, self.sla_target)
        lines.append("SLA (" + "{:.3f}".format(self.sla_target) + "%): " + sla_status)
        if self.analytics_results:
            slo = self.analytics_results.get("slo", {})
            budget = self.analytics_results.get("error_budget", {})
            if slo:
                met_str = "MET" if slo.get("met") else "NOT MET"
                lines.append("SLO (" + "{:.3f}".format(slo.get("slo_target", self.slo_target)) + "%): " + met_str)
                if budget:
                    lines.append("Error Budget: " + budget.get("status", "N/A") +
                                 " (" + "{:.1f}".format(budget.get("remaining_minutes", 0)) + " min remaining)")
            predictive = self.analytics_results.get("predictive", {})
            if predictive:
                lines.append("Failure Risk: " + "{:.1f}".format(predictive.get("failure_probability", 0)) +
                             "% (" + predictive.get("risk_level", "LOW") + ")")
        if self.multi_region and self.multi_region_monitor:
            mr = self.multi_region_monitor.get_summary()
            lines.append("Multi-Region: " + str(mr["available_regions"]) + "/" + str(mr["total_regions"]) + " regions up")
        if self.analytics_results:
            regression = self.analytics_results.get("regression", {})
            if regression.get("regression_detected"):
                lines.append("[bold yellow]PERFORMANCE REGRESSION DETECTED[/bold yellow]")
            anomalies = self.analytics_results.get("anomalies", {})
            if anomalies.get("count", 0) > 0:
                lines.append("Anomalies: " + str(anomalies["count"]) + " detected")
        return "\n".join(lines)

    def _human_size(self, size):
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return "{:.1f}".format(size) + unit
            size /= 1024
        return "{:.1f}".format(size) + "TB"

    def _display_plain(self):
        verdict, uptime_pct, avg_score = self.get_verdict()
        stats = self.get_stats()
        print("\n" + "=" * 70)
        print("  UptimeChecker v" + VERSION + " - " + self.protocol.upper())
        print("=" * 70 + "\n")
        print("Status: " + verdict)
        print("Protocol: " + self.protocol.upper())
        print("Target: " + self.target_label)
        print("Uptime: " + "{:.2f}".format(uptime_pct) + "%")
        print("Avg Score: " + "{:.0f}".format(avg_score) + "/100")
        print("Error Rate: " + "{:.2f}".format(stats["error_rate"]) + "%")
        print()
        header = " {:<4} {:<20} {:<8} {:<10} {:<12} {:<8}".format("#", "Timestamp", "Proto", "Status", "Time", "Score")
        print(header)
        print("  " + "-" * 66)
        for r in self.results:
            sc = r["status"].get("status_code", 0)
            rt = r.get("timing", {}).get("total", 0)
            proto = r.get("protocol", "http")[:4].upper()
            if rt > 0:
                row = "  {:<4} {:<20} {:<8} {:<10} {:<12.0f} {:<8}".format(
                    r["index"], r["timestamp"], proto, sc, rt, r["score"])
            else:
                row = "  {:<4} {:<20} {:<8} {:<10} {:<12} {:<8}".format(
                    r["index"], r["timestamp"], proto, sc, "N/A", r["score"])
            print(row)
        print()
        if self.protocol == "http":
            self._display_http_plain()
        elif self.protocol == "tcp":
            self._display_tcp_plain()
        elif self.protocol == "smtp":
            self._display_smtp_plain()
        elif self.protocol == "ftp":
            self._display_ftp_plain()
        elif self.protocol == "ssh":
            self._display_ssh_plain()
        elif self.protocol == "ping":
            self._display_ping_plain()
        elif self.protocol == "dns":
            self._display_dns_plain()
        print("Timing:")
        print("  Average: " + "{:.1f}".format(stats["avg_time"]) + "ms")
        print("  Min: " + "{:.1f}".format(stats["min_time"]) + "ms")
        print("  Max: " + "{:.1f}".format(stats["max_time"]) + "ms")
        print("  P50: " + "{:.1f}".format(stats["percentiles"]["p50"]) + "ms")
        print("  P90: " + "{:.1f}".format(stats["percentiles"]["p90"]) + "ms")
        print("  P95: " + "{:.1f}".format(stats["percentiles"]["p95"]) + "ms")
        print("  P99: " + "{:.1f}".format(stats["percentiles"]["p99"]) + "ms")
        if stats.get("mtbf") is not None:
            print("  MTBF: " + "{:.1f}".format(stats["mtbf"]) + " intervals")
        if stats.get("mttr") is not None:
            print("  MTTR: " + "{:.1f}".format(stats["mttr"]) + " intervals")
        print()
        sla_compliant, sla_status = EnhancedStats.sla_compliance(uptime_pct, self.sla_target)
        print("SLA Compliance:")
        print("  Target: " + "{:.3f}".format(self.sla_target) + "%")
        print("  Actual: " + EnhancedStats.format_sla_uptime(uptime_pct))
        print("  Status: " + sla_status)
        print()
        incidents = self.incident_tracker.to_list()
        if incidents:
            print("Incidents:")
            for inc in incidents:
                print("  " + inc.get("group_id", "?") + " | " + inc["start"] + " - " + str(inc["end"]) +
                      " | " + inc.get("severity", "?") + " | " + inc["reason"] +
                      " | " + inc.get("root_cause", "Unknown") +
                      " (" + str(inc["failures"]) + " failures)")
            groups = self.incident_tracker.group_by_root_cause()
            if groups:
                print("\n  By Root Cause:")
                for cat, incs in sorted(groups.items(), key=lambda x: -len(x[1])):
                    print("    " + cat + ": " + str(len(incs)) + " incidents")
            res = self.incident_tracker.get_resolution_stats()
            if res["total_resolved"] > 0:
                print("\n  Resolution: Avg {:.1f}s | Resolved: {} | Open: {}".format(
                    res["avg_resolution_time"], res["total_resolved"], res["total_open"]))
            print()
        if self.multi_region and self.multi_region_monitor:
            mr = self.multi_region_monitor.get_summary()
            print("Multi-Region:")
            print("  Regions: {}/{} available | Avg latency: {:.0f}ms | Score: {:.0f}/100".format(
                mr["available_regions"], mr["total_regions"], mr["avg_latency"], mr["score"]))
            for region_id, result in self.multi_region_monitor.region_results.items():
                region_name = REGIONS[region_id]["name"]
                dns_ok = "OK" if result["dns_resolved"] else "FAIL"
                http_ok = "OK" if result["http_available"] else "FAIL"
                http_time = "{:.0f}ms".format(result["http_response_ms"]) if result["http_response_ms"] >= 0 else "N/A"
                print("    " + region_name + ": DNS=" + dns_ok + " HTTP=" + http_ok + " " + http_time)
            print()
        if self.analytics_results:
            print("Advanced Analytics:")
            trend = self.analytics_results.get("uptime_trend", {})
            print("  Uptime Trend: " + trend.get("trend", "unknown"))
            regression = self.analytics_results.get("regression", {})
            print("  Regression: " + ("DETECTED" if regression.get("regression_detected") else "None") +
                  " (slope: {:.2f}ms/check)".format(regression.get("slope", 0)))
            anomalies = self.analytics_results.get("anomalies", {})
            if anomalies.get("count", 0) > 0:
                print("  Anomalies: " + str(anomalies["count"]) + " detected (mean: {:.0f}ms, stdev: {:.0f}ms)".format(
                    anomalies.get("mean", 0), anomalies.get("stdev", 0)))
            capacity = self.analytics_results.get("capacity", {})
            for hint in capacity.get("hints", []):
                print("  Capacity: " + hint)
            sla_pred = self.analytics_results.get("sla_prediction", {})
            if sla_pred.get("confidence", 0) > 0:
                print("  SLA Prediction: " + ("BREACH RISK" if sla_pred.get("will_breach") else "OK") +
                      " (current: {:.2f}%, projected: {:.2f}%)".format(
                          sla_pred.get("current_uptime", 0), sla_pred.get("projected_uptime", 0)))
            print()
        if self.analytics_results:
            slo = self.analytics_results.get("slo", {})
            budget = self.analytics_results.get("error_budget", {})
            if slo:
                print("SLO & Error Budget:")
                print("  Target: " + "{:.3f}".format(slo.get("slo_target", 0)) + "% | Actual: " +
                      "{:.2f}".format(slo.get("actual_uptime", 0)) + "% | " +
                      ("MET" if slo.get("met") else "NOT MET"))
                if budget:
                    print("  Budget: " + budget.get("status", "N/A") +
                          " | Used: " + "{:.1f}".format(budget.get("consumed_minutes", 0)) +
                          "/" + "{:.1f}".format(budget.get("allowed_minutes", 0)) + " min" +
                          " | Remaining: " + "{:.1f}".format(budget.get("remaining_minutes", 0)) + " min")
                print("  Burn rate: " + "{:.2f}".format(slo.get("burn_rate", 0)) + "x")
            predictive = self.analytics_results.get("predictive", {})
            if predictive:
                print("Predictive Failure Analysis:")
                print("  Probability: " + "{:.1f}".format(predictive.get("failure_probability", 0)) +
                      "% | Risk: " + predictive.get("risk_level", "LOW"))
                for factor in predictive.get("factors", []):
                    print("  - " + factor)
            projection = self.analytics_results.get("projection", {})
            if projection and projection.get("direction") != "insufficient_data":
                print("Trend Extrapolation:")
                print("  Direction: " + projection.get("direction", "n/a") +
                      " | Slope: " + "{:.2f}".format(projection.get("latency_slope", 0)) + " ms/check" +
                      " | Confidence: " + "{:.0f}".format(projection.get("confidence", 0)) + "%")
                lat_proj = projection.get("latency_projection", [])
                if lat_proj:
                    print("  Latency projection: [" + ", ".join("{:.0f}".format(v) for v in lat_proj[:8]) + "]")
            seasonality = self.analytics_results.get("seasonality", {})
            if seasonality and seasonality.get("pattern") != "insufficient_data":
                print("Seasonal Patterns: " + str(seasonality.get("pattern", "none")) +
                      " (strength " + "{:.0f}".format(seasonality.get("strength", 0)) + ")")
            cap_forecast = self.analytics_results.get("capacity_forecast", {})
            if cap_forecast and cap_forecast.get("status") != "NO_DATA":
                print("Capacity Forecast: " + "{:.1f}".format(cap_forecast.get("utilization_pct", 0)) +
                      "% utilization (" + cap_forecast.get("status", "N/A") + ")")
                breach = cap_forecast.get("checks_until_breach")
                if breach is not None:
                    print("  Breach projected in " + str(breach) + " checks")
            cost = self.analytics_results.get("cost", {})
            for hint in cost.get("hints", []):
                print("Cost: " + hint)
            correlation = self.analytics_results.get("correlation", {})
            if correlation:
                print("Incident Correlation: " + str(len(correlation.get("clusters", []))) +
                      " clusters | cascade: " + ("YES" if correlation.get("cascade_detected") else "NO"))
            escalation = self.analytics_results.get("escalation", {})
            esc_stats = escalation.get("stats", {})
            if esc_stats:
                print("Escalation Sim: " + str(esc_stats.get("escalated_count", 0)) + "/" +
                      str(esc_stats.get("incidents_evaluated", 0)) + " escalated | exec pages: " +
                      str(esc_stats.get("exec_page_count", 0)))
            ensemble = self.analytics_results.get("predictive_ensemble", {})
            if ensemble and ensemble.get("model_votes"):
                print("Ensemble Forecast: " + "{:.1f}".format(ensemble.get("probability", 0)) +
                      "% (" + ensemble.get("risk_level", "LOW") + ", confidence " +
                      "{:.0f}".format(ensemble.get("confidence", 0)) + "%)")
            rolling = self.analytics_results.get("rolling_stats", {})
            if rolling and rolling.get("available"):
                print("Rolling Stats: avg " + "{:.0f}".format(rolling.get("recent_avg_ms", 0)) +
                      "ms vs overall " + "{:.0f}".format(rolling.get("overall_avg_ms", 0)) +
                      "ms (momentum " + "{:+.1f}".format(rolling.get("momentum_pct", 0)) + "%)")
            scale_rec = self.analytics_results.get("scale_recommendation", {})
            if scale_rec and scale_rec.get("action") not in (None, "insufficient_data"):
                print("Capacity Action: " + scale_rec.get("action", "?") +
                      " - " + scale_rec.get("rationale", ""))
            sla_windows = self.analytics_results.get("sla_windows", {})
            for w in sla_windows.get("windows", []):
                print("SLA Window [" + w.get("label", "?") + "]: " +
                      "{:.3f}".format(w.get("projected_uptime", 0)) + "% vs " +
                      "{:.3f}".format(w.get("target", 0)) + "% -> " +
                      ("COMPLIANT" if w.get("compliant") else "AT RISK"))
            ttb = self.analytics_results.get("time_to_breach", {})
            if ttb and ttb.get("checks_until_sla_breach") is not None:
                print("Time to SLA breach: " + str(ttb.get("checks_until_sla_breach")) +
                      " checks (~" + str(ttb.get("minutes_until_sla_breach")) + " min)")
            ebf = self.analytics_results.get("error_budget_forecast", {})
            if ebf:
                print("Error Budget Forecast: " + ebf.get("status", "N/A") +
                      " (" + "{:.1f}".format(ebf.get("projected_remaining_minutes", 0)) + " min unused)")
            rum = self.analytics_results.get("rum")
            if rum and rum.get("available"):
                vitals = rum.get("vitals", {})
                print("RUM: samples=" + str(rum.get("sample_count", 0)) +
                      " apdex=" + "{:.3f}".format(rum.get("apdex", 0)) +
                      " LCP=" + "{:.0f}".format(vitals.get("lcp_ms", 0)) + "ms")
            ab = self.analytics_results.get("ab_tests")
            if ab and ab.get("detected"):
                print("A/B Tests: " + str(len(ab.get("experiments", []))) + " experiment(s) observed")
            flags = self.analytics_results.get("feature_flags")
            if flags and flags.get("detected"):
                print("Feature Flags: " + str(flags.get("total_flags", 0)) + " tracked, " +
                      str(flags.get("enabled_count", 0)) + " enabled, " +
                      str(len(flags.get("flapping", []))) + " flapping")
            dep_chain = self.analytics_results.get("dependency_chain")
            if dep_chain and dep_chain.get("hops", 0) > 0:
                print("Dependency Chain: " + dep_chain.get("status", "N/A") +
                      " | health " + "{:.1f}".format(dep_chain.get("chain_health_pct", 0)) + "%" +
                      " | path " + "{:.0f}".format(dep_chain.get("critical_path_ms", 0)) + "ms")
            synth = self.analytics_results.get("synthetic")
            if synth and synth.get("journeys_run", 0) > 0:
                print("Synthetic Journeys: " + str(synth.get("journeys_run", 0)) +
                      " | success " + "{:.1f}".format(synth.get("success_rate", 0)) + "%")
            automation = self.analytics_results.get("incident_response", {})
            if automation.get("enabled"):
                print("Incident Automation: " + str(len(automation.get("actions", []))) + " actions executed")
            notes = self.analytics_results.get("notifications", [])
            if notes:
                print("Stakeholder Notifications: " + str(len(notes)) + " sent")
            roi = self.analytics_results.get("roi")
            if roi:
                print("ROI: " + "{:.0f}".format(roi.get("roi_pct", 0)) + "% | net " +
                      "${:,.2f}".format(roi.get("net_benefit_monthly", 0)) + "/month | " +
                      roi.get("verdict", "N/A"))
            service_map = self.analytics_results.get("service_map")
            if service_map and service_map.get("node_count", 0) > 0:
                print("Service Map: " + str(service_map.get("node_count", 0)) + " nodes, " +
                      str(service_map.get("edge_count", 0)) + " edges | status " +
                      service_map.get("status", "N/A") + " | blast radius " +
                      str(service_map.get("blast_radius_count", 0)))
                if service_map.get("critical_at_risk"):
                    print("  Critical at risk: " + ", ".join(service_map["critical_at_risk"]))
            cascade = self.analytics_results.get("cascade")
            if cascade:
                print("Cascade Detection: " + ("YES" if cascade.get("detected") else "no") +
                      " | chains: " + str(cascade.get("chain_count", 0)) +
                      " | max depth: " + str(cascade.get("max_depth", 0)) +
                      " | risk: " + cascade.get("risk", "LOW"))
            maintenance = self.analytics_results.get("maintenance")
            if maintenance and maintenance.get("total_windows", 0) > 0:
                print("Maintenance Windows: " + str(maintenance.get("total_windows", 0)) +
                      " | active: " + ("yes" if maintenance.get("active") else "no") +
                      " | suppressed: " + str(maintenance.get("suppressed_total", 0)))
            fatigue = self.analytics_results.get("alert_fatigue")
            if fatigue and fatigue.get("total_evaluated", 0) > 0:
                print("Alert Fatigue: sent " + str(fatigue.get("alerts_sent", 0)) +
                      " | suppressed " + str(fatigue.get("alerts_suppressed", 0)) +
                      " (" + "{:.1f}".format(fatigue.get("suppression_pct", 0)) + "% removed)")
            oncall = self.analytics_results.get("oncall")
            if oncall and oncall.get("stats", {}).get("incidents_evaluated", 0) > 0:
                oc_stats = oncall.get("stats", {})
                print("On-Call Sim: ack rate " + "{:.1f}".format(oc_stats.get("ack_rate_pct", 0)) +
                      "% | unacked " + str(oc_stats.get("unacked_events", 0)) +
                      " | handoffs " + str(oc_stats.get("handoff_events", 0)))
            pred_refine = self.analytics_results.get("predictive_refined")
            if pred_refine:
                print("Predictive (refined): " + pred_refine.get("risk_band", "STABLE") +
                      " (score " + "{:.1f}".format(pred_refine.get("risk_score", 0)) + "/100)")
            cap_refine = self.analytics_results.get("capacity_refined")
            if cap_refine and cap_refine.get("available"):
                print("Capacity (refined): headroom " +
                      "{:.1f}".format(cap_refine.get("headroom_pct", 0)) + "% -> " +
                      "{:.1f}".format(cap_refine.get("projected_headroom_pct", 0)) + "% [" +
                      cap_refine.get("posture", "n/a") + "]")
            cost_refine = self.analytics_results.get("cost_refined")
            if cost_refine and cost_refine.get("available"):
                rec = cost_refine.get("recommended") or {}
                print("Cost (refined): efficiency " +
                      "{:.1f}".format(cost_refine.get("efficiency_score", 0)) +
                      "/100 | recommended interval " + str(rec.get("interval_seconds", 0)) + "s")
            roi_refine = self.analytics_results.get("roi_refined")
            if roi_refine and roi_refine.get("available"):
                best = roi_refine.get("best_scenario") or {}
                print("ROI (refined): best scenario " + best.get("scenario", "n/a") +
                      " net " + "${:,.2f}".format(best.get("net_benefit_monthly", 0)) +
                      "/month | breakeven capture " +
                      "{:.1f}".format(roi_refine.get("breakeven_capture_rate_pct", 0)) + "%")
            forecast = self.analytics_results.get("sla_forecast_refined")
            if forecast and forecast.get("available"):
                print("SLA Forecast (refined): trend " + forecast.get("trend", "n/a") +
                      " | first breach: " + str(forecast.get("first_breach_horizon") or "none"))
                for horizon in forecast.get("horizons", []):
                    print("  " + horizon.get("label", "?") + ": " +
                          "{:.4f}".format(horizon.get("projected_uptime", 0)) + "% vs " +
                          "{:.3f}".format(horizon.get("target", 0)) + "% -> " +
                          ("COMPLIANT" if horizon.get("compliant") else "AT RISK"))
            digest = self.analytics_results.get("notification_digest")
            if digest and digest.get("total", 0) > 0:
                print("Notification Digest: " + str(digest.get("total", 0)) +
                      " sent | delivery " + "{:.1f}".format(digest.get("delivery_rate_pct", 0)) + "%")
            print()
        if self.postmortems:
            print("Post-Mortems Generated: " + str(len(self.postmortems)))
            for pm in self.postmortems:
                print("  " + pm.get("incident_id", "?") + " | " + pm.get("severity", "?") +
                      " | " + pm.get("summary", "") +
                      " | actions: " + str(len(pm.get("action_items", []))))
            print()
        if (self.exec_summary or self.full_report) and self.analytics_results:
            generator = self._build_report_generator()
            incidents = self.incident_tracker.to_list()
            exec_lines = generator.executive_summary(
                verdict, uptime_pct, avg_score, stats,
                self.analytics_results, incidents,
                self.analytics_results.get("slo", {}), len(self.results))
            print("Executive Summary:")
            for line in exec_lines:
                print("  " + re.sub(r"\[[^\]]+\]", "", line))
            print()
        if (self.deep_dive or self.full_report) and self.analytics_results:
            generator = self._build_report_generator()
            deep_lines = generator.technical_deep_dive(
                stats, self.analytics_results,
                self.analytics_results.get("slo", {}),
                self.incident_tracker.to_list())
            print("Technical Deep Dive:")
            for line in deep_lines:
                print("  " + re.sub(r"\[[^\]]+\]", "", line))
            print()
        print("=" * 70)
        print("  Verdict: " + verdict)
        print("  Protocol: " + self.protocol.upper())
        print("  Uptime: " + "{:.2f}".format(uptime_pct) + "%")
        print("  Avg Score: " + "{:.0f}".format(avg_score) + "/100")
        print("=" * 70 + "\n")

    def _display_http_plain(self):
        if self.dns_info:
            print("DNS Information:")
            a_recs = ", ".join(self.dns_info.get("a_records", [])) or "None"
            aaaa_recs = ", ".join(self.dns_info.get("aaaa_records", [])) or "None"
            ns_recs = ", ".join(self.dns_info.get("ns_records", [])) or "None"
            print("  IPv4: " + a_recs)
            print("  IPv6: " + aaaa_recs)
            print("  NS: " + ns_recs)
            spf_val = self.dns_info.get("spf_record", "")
            print("  SPF: " + (spf_val[:60] if spf_val else "None"))
            dkim_val = self.dns_info.get("dkim_record", "")
            print("  DKIM: " + (dkim_val[:60] if dkim_val else "None"))
            res_time = "{:.1f}".format(self.dns_info.get("resolution_time", 0))
            print("  Resolution: " + res_time + "ms")
            changes = self.dns_info.get("record_changes", {})
            if changes:
                print("  [!] DNS Record Changes Detected:")
                for rtype, chg in changes.items():
                    print("      " + rtype + ": " + ", ".join(chg.get("previous", []))[:30] + " -> " + ", ".join(chg.get("current", []))[:30])
            print()
        if self.ssl_info:
            print("SSL Certificate:")
            print("  Status: " + self.ssl_info.get("status", "N/A"))
            print("  Issuer: " + self.ssl_info.get("issuer", "N/A"))
            print("  Expiry: " + self.ssl_info.get("expiry", "N/A"))
            days = self.ssl_info.get("days_until_expiry", "N/A")
            print("  Days Left: " + str(days))
            print("  OCSP: " + self.ssl_info.get("ocsp_status", "N/A"))
            print()
        if self.headers_info:
            print("Headers:")
            for k, v in self.headers_info.items():
                print("  " + k + ": " + v)
            print()
        if self.extended_info:
            print("Extended Checks:")
            cdn = self.extended_info.get("cdn", [])
            if cdn:
                print("  CDN: " + ", ".join(cdn))
            lb = self.extended_info.get("load_balancer", [])
            if lb:
                print("  Load Balancer: " + ", ".join(lb))
            tech = self.extended_info.get("technologies", [])
            if tech:
                print("  Technologies: " + ", ".join(tech))
            http23 = self.extended_info.get("http23", {})
            if http23:
                print("  HTTP/2: " + ("Yes" if http23.get("http2") else "No"))
                print("  HTTP/3: " + ("Yes" if http23.get("http3") else "No"))
            print()
        if self.content_info:
            print("Content:")
            print("  Size: " + self.content_info.get("page_size_human", "N/A"))
            print("  Type: " + self.content_info.get("content_type", "N/A"))
            print()

    def _display_tcp_plain(self):
        if self.results and self.results[0].get("tcp"):
            tcp = self.results[0]["tcp"]
            print("TCP Port Check:")
            print("  Host: " + str(tcp.get("host", "N/A")))
            print("  Port: " + str(tcp.get("port", 0)))
            print("  Available: " + ("Yes" if tcp.get("available") else "No"))
            print("  Response: " + "{:.1f}".format(tcp.get("response_time_ms", 0)) + "ms")
            if tcp.get("banner"):
                print("  Banner: " + tcp["banner"][:60])
            if tcp.get("error"):
                print("  Error: " + tcp["error"])
            print()

    def _display_smtp_plain(self):
        if self.results and self.results[0].get("smtp"):
            smtp = self.results[0]["smtp"]
            print("SMTP Check:")
            print("  Host: " + str(smtp.get("host", "N/A")))
            print("  Port: " + str(smtp.get("port", 0)))
            print("  Available: " + ("Yes" if smtp.get("available") else "No"))
            print("  STARTTLS: " + ("Yes" if smtp.get("starttls") else "No"))
            auth = smtp.get("auth_methods", [])
            print("  Auth Methods: " + (", ".join(auth) if auth else "None"))
            if smtp.get("error"):
                print("  Error: " + smtp["error"])
            print()

    def _display_ftp_plain(self):
        if self.results and self.results[0].get("ftp"):
            ftp = self.results[0]["ftp"]
            print("FTP Check:")
            print("  Host: " + str(ftp.get("host", "N/A")))
            print("  Available: " + ("Yes" if ftp.get("available") else "No"))
            print("  Anonymous: " + ("Allowed" if ftp.get("anonymous_login") else "Denied"))
            print("  TLS: " + ("Yes" if ftp.get("tls_support") else "No"))
            if ftp.get("error"):
                print("  Error: " + ftp["error"])
            print()

    def _display_ssh_plain(self):
        if self.results and self.results[0].get("ssh"):
            ssh = self.results[0]["ssh"]
            print("SSH Check:")
            print("  Host: " + str(ssh.get("host", "N/A")))
            print("  Port: " + str(ssh.get("port", 22)))
            print("  Available: " + ("Yes" if ssh.get("available") else "No"))
            print("  Protocol: " + ssh.get("protocol_version", "N/A"))
            if ssh.get("error"):
                print("  Error: " + ssh["error"])
            print()

    def _display_ping_plain(self):
        if self.results and self.results[0].get("ping"):
            ping = self.results[0]["ping"]
            print("ICMP Ping Check:")
            print("  Host: " + str(ping.get("host", "N/A")))
            print("  Available: " + ("Yes" if ping.get("available") else "No"))
            print("  Sent: " + str(ping.get("packets_sent", 0)) + "  Received: " + str(ping.get("packets_received", 0)))
            print("  Loss: " + "{:.1f}".format(ping.get("loss_pct", 100)) + "%")
            print("  RTT: min={:.2f} avg={:.2f} max={:.2f}ms".format(
                ping.get("min_rtt", 0), ping.get("avg_rtt", 0), ping.get("max_rtt", 0)))
            if ping.get("error"):
                print("  Error: " + ping["error"])
            print()

    def _display_dns_plain(self):
        if self.results and self.results[0].get("dns"):
            dns = self.results[0]["dns"]
            print("DNS Check:")
            print("  Hostname: " + self.hostname)
            print("  IPv4: " + ", ".join(dns.get("a_records", [])) or "None")
            print("  IPv6: " + ", ".join(dns.get("aaaa_records", [])) or "None")
            print("  NS: " + ", ".join(dns.get("ns_records", [])) or "None")
            res_time = "{:.1f}".format(dns.get("resolution_time", 0))
            print("  Resolution: " + res_time + "ms")
            changes = dns.get("record_changes", {})
            if changes:
                print("  [!] Changes Detected:")
                for rtype, chg in changes.items():
                    print("      " + rtype + ": " + ", ".join(chg.get("previous", []))[:30] + " -> " + ", ".join(chg.get("current", []))[:30])
            print()

    def export_results(self):
        verdict, uptime_pct, avg_score = self.get_verdict()
        stats = self.get_stats()
        output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
        os.makedirs(output_dir, exist_ok=True)
        safe_name = self.hostname.replace(".", "_") if self.hostname else "target"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if self.export in ("json", "all"):
            data = {
                "version": VERSION, "protocol": self.protocol,
                "target": self.target_label, "hostname": self.hostname,
                "verdict": verdict, "uptime_pct": uptime_pct, "avg_score": avg_score,
                "stats": stats, "dns": self.dns_info, "ssl": self.ssl_info,
                "headers": self.headers_info, "redirects": self.redirect_chain,
                "content": self.content_info, "extended": self.extended_info,
                "incidents": self.incident_tracker.to_list(),
                "incident_groups": self.incident_tracker.group_by_root_cause(),
                "incident_severity_groups": self.incident_tracker.group_by_severity(),
                "resolution_stats": self.incident_tracker.get_resolution_stats(),
                "dependencies": self.dependencies,
                "circuit_breaker": {"state": self.circuit_breaker.state,
                                    "failures": self.circuit_breaker.failure_count},
                "checks": self.results,
                "analytics": self.analytics_results,
                "postmortems": self.postmortems,
                "slo": self.analytics_results.get("slo") if self.analytics_results else None,
                "error_budget": self.analytics_results.get("error_budget") if self.analytics_results else None,
                "predictive": self.analytics_results.get("predictive") if self.analytics_results else None,
                "projection": self.analytics_results.get("projection") if self.analytics_results else None,
                "seasonality": self.analytics_results.get("seasonality") if self.analytics_results else None,
                "capacity_forecast": self.analytics_results.get("capacity_forecast") if self.analytics_results else None,
                "correlation": self.analytics_results.get("correlation") if self.analytics_results else None,
                "escalation": self.analytics_results.get("escalation") if self.analytics_results else None,
                "cost": self.analytics_results.get("cost") if self.analytics_results else None,
                "predictive_ensemble": self.analytics_results.get("predictive_ensemble") if self.analytics_results else None,
                "time_to_breach": self.analytics_results.get("time_to_breach") if self.analytics_results else None,
                "scale_recommendation": self.analytics_results.get("scale_recommendation") if self.analytics_results else None,
                "rolling_stats": self.analytics_results.get("rolling_stats") if self.analytics_results else None,
                "sla_windows": self.analytics_results.get("sla_windows") if self.analytics_results else None,
                "error_budget_forecast": self.analytics_results.get("error_budget_forecast") if self.analytics_results else None,
                "roi": self.analytics_results.get("roi") if self.analytics_results else None,
                "rum": self.analytics_results.get("rum") if self.analytics_results else None,
                "ab_tests": self.analytics_results.get("ab_tests") if self.analytics_results else None,
                "feature_flags": self.analytics_results.get("feature_flags") if self.analytics_results else None,
                "dependency_chain": self.analytics_results.get("dependency_chain") if self.analytics_results else None,
                "synthetic_journeys": self.analytics_results.get("synthetic") if self.analytics_results else None,
                "incident_response": self.analytics_results.get("incident_response") if self.analytics_results else None,
                "stakeholder_notifications": self.analytics_results.get("notifications") if self.analytics_results else None,
                "service_map": self.analytics_results.get("service_map") if self.analytics_results else None,
                "cascade": self.analytics_results.get("cascade") if self.analytics_results else None,
                "maintenance": self.analytics_results.get("maintenance") if self.analytics_results else None,
                "alert_fatigue": self.analytics_results.get("alert_fatigue") if self.analytics_results else None,
                "oncall": self.analytics_results.get("oncall") if self.analytics_results else None,
                "predictive_refined": self.analytics_results.get("predictive_refined") if self.analytics_results else None,
                "capacity_refined": self.analytics_results.get("capacity_refined") if self.analytics_results else None,
                "cost_refined": self.analytics_results.get("cost_refined") if self.analytics_results else None,
                "roi_refined": self.analytics_results.get("roi_refined") if self.analytics_results else None,
                "sla_forecast_refined": self.analytics_results.get("sla_forecast_refined") if self.analytics_results else None,
                "notification_digest": self.analytics_results.get("notification_digest") if self.analytics_results else None}
            if self.multi_region and self.multi_region_monitor:
                data["multi_region"] = {
                    "summary": self.multi_region_monitor.get_summary(),
                    "region_results": self.multi_region_monitor.region_results,
                    "availability_scores": self.multi_region_monitor.get_availability_scores(),
                    "latency_comparison": self.multi_region_monitor.get_latency_comparison(),
                    "cdn_edge_comparison": self.multi_region_monitor.get_cdn_edge_comparison()}
            path = os.path.join(output_dir, safe_name + "_" + timestamp + ".json")
            with open(path, "w") as f:
                json.dump(data, f, indent=2, default=str)
            if not self.no_color:
                console.print("[green]+[/green] Exported JSON: " + path)
            else:
                print("Exported JSON: " + path)
        if self.export in ("csv", "all"):
            path = os.path.join(output_dir, safe_name + "_" + timestamp + ".csv")
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["#", "Timestamp", "Protocol", "Status", "ResponseTime(ms)",
                                 "Score", "DNS_Time(ms)", "SSL_Status", "Page_Size",
                                 "Error_Rate(%)", "Circuit_Breaker"])
                for r in self.results:
                    writer.writerow([
                        r["index"], r["timestamp"], r.get("protocol", "http"),
                        r["status"].get("status_code", 0),
                        r.get("timing", {}).get("total", 0),
                        r["score"],
                        r.get("dns", {}).get("resolution_time", 0),
                        r.get("ssl", {}).get("status", "N/A") if r.get("ssl") else "N/A",
                        r.get("content", {}).get("page_size", 0),
                        stats["error_rate"],
                        self.circuit_breaker.state])
            if not self.no_color:
                console.print("[green]+[/green] Exported CSV: " + path)
            else:
                print("Exported CSV: " + path)
        if self.export in ("html", "all"):
            path = os.path.join(output_dir, safe_name + "_" + timestamp + ".html")
            html = self._generate_html(verdict, uptime_pct, avg_score, stats)
            with open(path, "w") as f:
                f.write(html)
            if not self.no_color:
                console.print("[green]+[/green] Exported HTML: " + path)
            else:
                print("Exported HTML: " + path)

    def _generate_html(self, verdict, uptime_pct, avg_score, stats):
        if verdict == "UP":
            verdict_color = "#22c55e"
        elif verdict == "DEGRADED":
            verdict_color = "#eab308"
        else:
            verdict_color = "#ef4444"
        rows = ""
        for r in self.results:
            sc = r["status"].get("status_code", 0)
            rt = r.get("timing", {}).get("total", 0)
            proto = r.get("protocol", "http")
            if 200 <= sc < 300:
                sc_color = "#22c55e"
            elif 300 <= sc < 400:
                sc_color = "#eab308"
            else:
                sc_color = "#ef4444"
            rt_display = "{:.0f}".format(rt) + "ms" if rt > 0 else "N/A"
            rows += ('<tr><td>' + str(r['index']) + '</td>'
                     '<td>' + r['timestamp'] + '</td>'
                     '<td>' + proto.upper() + '</td>'
                     '<td style="color:' + sc_color + ';font-weight:bold">' + str(sc) + '</td>'
                     '<td>' + rt_display + '</td>'
                     '<td>' + str(r['score']) + '</td></tr>\n')
        ssl_section = ""
        if self.ssl_info:
            ssl_color = {"VALID": "#22c55e", "WARNING": "#eab308"}.get(self.ssl_info.get("status"), "#ef4444")
            ssl_section = (
                '<div class="card"><h3>SSL Certificate</h3>\n'
                '<p><b>Status:</b> <span style="color:' + ssl_color + '">' + str(self.ssl_info.get('status')) + '</span></p>\n'
                '<p><b>Issuer:</b> ' + str(self.ssl_info.get('issuer')) + '</p>\n'
                '<p><b>Expiry:</b> ' + str(self.ssl_info.get('expiry')) + '</p>\n'
                '<p><b>Days Left:</b> ' + str(self.ssl_info.get('days_until_expiry')) + '</p>\n'
                '<p><b>OCSP:</b> ' + str(self.ssl_info.get('ocsp_status')) + '</p>\n'
                '</div>\n')
        dns_section = ""
        if self.dns_info:
            a_records = ", ".join(self.dns_info.get("a_records", [])) or "None"
            aaaa_records = ", ".join(self.dns_info.get("aaaa_records", [])) or "None"
            res_time = "{:.1f}".format(self.dns_info.get("resolution_time", 0))
            spf_rec = self.dns_info.get("spf_record", "")[:80] or "None"
            dkim_rec = self.dns_info.get("dkim_record", "")[:80] or "None"
            changes = self.dns_info.get("record_changes", {})
            dns_section = (
                '<div class="card"><h3>DNS</h3>\n'
                '<p><b>IPv4:</b> ' + a_records + '</p>\n'
                '<p><b>IPv6:</b> ' + aaaa_records + '</p>\n'
                '<p><b>Resolution:</b> ' + res_time + 'ms</p>\n'
                '<p><b>SPF:</b> ' + spf_rec + '</p>\n'
                '<p><b>DKIM:</b> ' + dkim_rec + '</p>\n')
            if changes:
                dns_section += '<p><b style="color:#eab308">DNS Changes Detected:</b></p>\n<ul>\n'
                for rtype, chg in changes.items():
                    prev = ", ".join(chg.get("previous", []))[:40] or "None"
                    curr = ", ".join(chg.get("current", []))[:40] or "None"
                    dns_section += '<li>' + rtype + ': ' + prev + ' &rarr; ' + curr + '</li>\n'
                dns_section += '</ul>\n'
            dns_section += '</div>\n'
        extended_section = ""
        if self.extended_info:
            cdn = self.extended_info.get("cdn", [])
            tech = self.extended_info.get("technologies", [])
            http23 = self.extended_info.get("http23", {})
            h2 = "Yes" if http23.get("http2") else "No"
            h3 = "Yes" if http23.get("http3") else "No"
            deps = self.extended_info.get("dependencies", [])
            extended_section = '<div class="card"><h3>Extended Checks</h3>\n'
            if cdn:
                extended_section += '<p><b>CDN:</b> ' + ", ".join(cdn) + '</p>\n'
            if tech:
                extended_section += '<p><b>Technologies:</b> ' + ", ".join(tech) + '</p>\n'
            extended_section += '<p><b>HTTP/2:</b> ' + h2 + ' | <b>HTTP/3:</b> ' + h3 + '</p>\n'
            if deps:
                dep_domains = [d["domain"] for d in deps[:10]]
                extended_section += '<p><b>Dependencies:</b> ' + ", ".join(dep_domains) + '</p>\n'
            extended_section += '</div>\n'
        incidents = self.incident_tracker.to_list()
        incident_section = ""
        if incidents:
            incident_section = (
                '<div class="card"><h3>Incidents</h3>\n'
                '<table><tr><th>ID</th><th>Start</th><th>End</th><th>Severity</th><th>Reason</th>'
                '<th>Root Cause</th><th>Impact</th><th>Status</th></tr>\n')
            for inc in incidents:
                i_color = "#ef4444" if inc["status"] == "OPEN" else "#22c55e"
                sev_color = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308"}.get(inc.get("severity", ""), "#6b7280")
                incident_section += (
                    '<tr><td>' + inc.get("group_id", "?") + '</td>'
                    '<td>' + inc["start"] + '</td>'
                    '<td>' + str(inc["end"]) + '</td>'
                    '<td style="color:' + sev_color + '">' + inc.get("severity", "?") + '</td>'
                    '<td>' + inc["reason"] + '</td>'
                    '<td>' + inc.get("root_cause", "Unknown") + '</td>'
                    '<td>' + str(inc.get("impact_score", 0)) + '%</td>'
                    '<td style="color:' + i_color + '">' + inc["status"] + '</td></tr>\n')
            incident_section += '</table></div>\n'
        sla_compliant, sla_status = EnhancedStats.sla_compliance(uptime_pct, self.sla_target)
        sla_color = "#22c55e" if sla_compliant else "#ef4444"
        sla_section = (
            '<div class="card"><h3>SLA Compliance</h3>\n'
            '<p><b>Target:</b> ' + "{:.3f}".format(self.sla_target) + '%</p>\n'
            '<p><b>Actual:</b> ' + EnhancedStats.format_sla_uptime(uptime_pct) + '</p>\n'
            '<p><b>Status:</b> <span style="color:' + sla_color + '">' + sla_status + '</span></p>\n'
            '<p><b>Error Rate:</b> ' + "{:.2f}".format(stats["error_rate"]) + '%</p>\n')
        if stats.get("mtbf") is not None:
            sla_section += '<p><b>MTBF:</b> ' + "{:.1f}".format(stats["mtbf"]) + ' intervals</p>\n'
        if stats.get("mttr") is not None:
            sla_section += '<p><b>MTTR:</b> ' + "{:.1f}".format(stats["mttr"]) + ' intervals</p>\n'
        sla_section += '</div>\n'
        analytics_section = ""
        if self.analytics_results:
            sla_pred = self.analytics_results.get("sla_prediction", {})
            pred_color = "#ef4444" if sla_pred.get("will_breach") else "#22c55e"
            analytics_section = (
                '<div class="card"><h3>Advanced Analytics</h3>\n'
                '<p><b>Uptime Trend:</b> ' + self.analytics_results.get("uptime_trend", {}).get("trend", "N/A") + '</p>\n'
                '<p><b>Performance Regression:</b> ' + ("DETECTED" if self.analytics_results.get("regression", {}).get("regression_detected") else "None") + '</p>\n'
                '<p><b>Anomalies:</b> ' + str(self.analytics_results.get("anomalies", {}).get("count", 0)) + ' detected</p>\n'
                '<p><b>SLA Breach Risk:</b> <span style="color:' + pred_color + '">' +
                ("YES" if sla_pred.get("will_breach") else "NO") + '</span></p>\n')
            if sla_pred.get("confidence", 0) > 0:
                analytics_section += '<p><b>Projected Uptime:</b> ' + "{:.2f}".format(sla_pred.get("projected_uptime", 0)) + '%</p>\n'
            analytics_section += '</div>\n'
            slo = self.analytics_results.get("slo", {})
            budget = self.analytics_results.get("error_budget", {})
            if slo:
                met_color = "#22c55e" if slo.get("met") else "#ef4444"
                budget_status = budget.get("status", "N/A")
                budget_color = {"OK": "#22c55e", "WARNING": "#eab308", "CRITICAL": "#f97316"}.get(budget_status, "#ef4444")
                analytics_section += (
                    '<div class="card"><h3>SLO &amp; Error Budget</h3>\n'
                    '<p><b>SLO Target:</b> ' + "{:.3f}".format(slo.get("slo_target", 0)) + '%</p>\n'
                    '<p><b>Actual:</b> ' + "{:.2f}".format(slo.get("actual_uptime", 0)) + '% | <b>Status:</b> ' +
                    '<span style="color:' + met_color + '">' + ("MET" if slo.get("met") else "NOT MET") + '</span></p>\n'
                    '<p><b>Error Budget:</b> <span style="color:' + budget_color + '">' + budget_status + '</span></p>\n'
                    '<p><b>Consumed:</b> ' + "{:.1f}".format(budget.get("consumed_minutes", 0)) + ' / ' +
                    "{:.1f}".format(budget.get("allowed_minutes", 0)) + ' min (' +
                    "{:.1f}".format(budget.get("consumed_pct", 0)) + '%)</p>\n'
                    '<p><b>Remaining:</b> ' + "{:.1f}".format(budget.get("remaining_minutes", 0)) + ' min</p>\n'
                    '<p><b>Burn Rate:</b> ' + "{:.2f}".format(slo.get("burn_rate", 0)) + 'x</p>\n'
                    '</div>\n')
            predictive = self.analytics_results.get("predictive", {})
            if predictive:
                risk = predictive.get("risk_level", "LOW")
                risk_color = {"LOW": "#22c55e", "MEDIUM": "#eab308", "HIGH": "#ef4444", "CRITICAL": "#ef4444"}.get(risk, "#60a5fa")
                analytics_section += (
                    '<div class="card"><h3>Predictive Failure Analysis</h3>\n'
                    '<p><b>Failure Probability:</b> <span style="color:' + risk_color + '">' +
                    "{:.1f}".format(predictive.get("failure_probability", 0)) + '% (' + risk + ')</span></p>\n')
                for factor in predictive.get("factors", []):
                    factor_text = str(factor).replace("<", "&lt;").replace(">", "&gt;")
                    analytics_section += '<p>&bull; ' + factor_text + '</p>\n'
                analytics_section += '</div>\n'
            projection = self.analytics_results.get("projection", {})
            if projection and projection.get("latency_projection"):
                analytics_section += (
                    '<div class="card"><h3>Trend Projections</h3>\n'
                    '<p><b>Direction:</b> ' + str(projection.get("direction", "n/a")) +
                    ' | <b>Slope:</b> ' + "{:.2f}".format(projection.get("latency_slope", 0)) + ' ms/check' +
                    ' | <b>Confidence:</b> ' + "{:.0f}".format(projection.get("confidence", 0)) + '%</p>\n'
                    '<p><b>Latency projection:</b> [' +
                    ", ".join("{:.0f}".format(v) for v in projection.get("latency_projection", [])[:10]) + ']</p>\n'
                    '<p><b>Uptime projection:</b> [' +
                    ", ".join("{:.2f}".format(v) + "%" for v in projection.get("uptime_projection", [])[:10]) + ']</p>\n'
                    '</div>\n')
            cost = self.analytics_results.get("cost", {})
            if cost.get("hints"):
                analytics_section += '<div class="card"><h3>Cost Optimization</h3>\n'
                analytics_section += '<p><b>Monthly probe volume:</b> ' + "{:,}".format(cost.get("estimated_monthly_checks", 0)) + '</p>\n'
                for hint in cost.get("hints", []):
                    hint_text = str(hint).replace("<", "&lt;").replace(">", "&gt;")
                    analytics_section += '<p>&bull; ' + hint_text + '</p>\n'
                analytics_section += '</div>\n'
        v7_section = ""
        if self.analytics_results:
            service_map = self.analytics_results.get("service_map")
            if service_map and service_map.get("node_count", 0) > 0:
                map_status = service_map.get("status", "N/A")
                map_color = {"HEALTHY": "#22c55e", "DEGRADED": "#eab308"}.get(map_status, "#ef4444")
                v7_section += (
                    '<div class="card"><h3>Service Dependency Map</h3>\n'
                    '<p><b>Status:</b> <span style="color:' + map_color + '">' + map_status + '</span>'
                    ' | <b>Nodes:</b> ' + str(service_map.get("node_count", 0)) +
                    ' | <b>Edges:</b> ' + str(service_map.get("edge_count", 0)) +
                    ' | <b>Blast radius:</b> ' + str(service_map.get("blast_radius_count", 0)) + '</p>\n')
                if service_map.get("critical_at_risk"):
                    v7_section += '<p><b style="color:#ef4444">Critical at risk:</b> ' + \
                        ", ".join(str(n).replace("<", "&lt;").replace(">", "&gt;") for n in service_map["critical_at_risk"]) + '</p>\n'
                if service_map.get("nodes"):
                    v7_section += '<table><tr><th>Node</th><th>Kind</th><th>Tier</th><th>Critical</th><th>Health</th></tr>\n'
                    for node in service_map.get("nodes", [])[:20]:
                        health = node.get("health", "unknown")
                        h_color = {"up": "#22c55e", "degraded": "#eab308", "down": "#ef4444"}.get(health, "#6b7280")
                        v7_section += (
                            '<tr><td>' + str(node.get("id", "?")) + '</td>'
                            '<td>' + str(node.get("kind", "?")) + '</td>'
                            '<td>' + str(node.get("tier", "?")) + '</td>'
                            '<td>' + ("yes" if node.get("critical") else "no") + '</td>'
                            '<td style="color:' + h_color + '">' + health + '</td></tr>\n')
                    v7_section += '</table>\n'
                v7_section += '</div>\n'
            cascade = self.analytics_results.get("cascade")
            if cascade:
                cascade_risk = cascade.get("risk", "LOW")
                cascade_color = {"LOW": "#22c55e", "MEDIUM": "#eab308", "HIGH": "#ef4444", "CRITICAL": "#ef4444"}.get(cascade_risk, "#6b7280")
                v7_section += (
                    '<div class="card"><h3>Cascading Failure Detection</h3>\n'
                    '<p><b>Detected:</b> <span style="color:' + ('#ef4444' if cascade.get("detected") else '#22c55e') + '">' +
                    ("YES" if cascade.get("detected") else "NO") + '</span>'
                    ' | <b>Chains:</b> ' + str(cascade.get("chain_count", 0)) +
                    ' | <b>Max depth:</b> ' + str(cascade.get("max_depth", 0)) +
                    ' | <b>Risk:</b> <span style="color:' + cascade_color + '">' + cascade_risk + '</span></p>\n')
                if cascade.get("chains"):
                    v7_section += '<table><tr><th>Chain</th><th>Depth</th><th>Origin</th><th>Severity</th><th>Span</th></tr>\n'
                    for chain in cascade.get("chains", [])[:10]:
                        v7_section += (
                            '<tr><td>' + chain.get("chain_id", "?") + '</td>'
                            '<td>' + str(chain.get("depth", 0)) + '</td>'
                            '<td>' + chain.get("origin_incident", "?") + '</td>'
                            '<td>' + chain.get("max_severity", "?") + '</td>'
                            '<td>' + "{:.0f}".format(chain.get("span_seconds", 0)) + 's</td></tr>\n')
                    v7_section += '</table>\n'
                v7_section += '</div>\n'
            maintenance = self.analytics_results.get("maintenance")
            if maintenance and maintenance.get("total_windows", 0) > 0:
                v7_section += (
                    '<div class="card"><h3>Maintenance Window Automation</h3>\n'
                    '<p><b>Windows:</b> ' + str(maintenance.get("total_windows", 0)) +
                    ' | <b>Active now:</b> ' + ("yes" if maintenance.get("active") else "no") +
                    ' | <b>Suppressed alerts:</b> ' + str(maintenance.get("suppressed_total", 0)) + '</p>\n')
                if maintenance.get("windows"):
                    v7_section += '<table><tr><th>ID</th><th>Label</th><th>Start</th><th>End</th><th>Suppressed</th></tr>\n'
                    for window in maintenance.get("windows", []):
                        start_h, start_m = divmod(window.get("start_minutes", 0), 60)
                        end_h, end_m = divmod(window.get("end_minutes", 0), 60)
                        v7_section += (
                            '<tr><td>' + window.get("id", "?") + '</td>'
                            '<td>' + str(window.get("label", "?")) + '</td>'
                            '<td>' + "{:02d}:{:02d}".format(start_h, start_m) + '</td>'
                            '<td>' + "{:02d}:{:02d}".format(end_h, end_m) + '</td>'
                            '<td>' + str(window.get("suppressed_alerts", 0)) + '</td></tr>\n')
                    v7_section += '</table>\n'
                v7_section += '</div>\n'
            fatigue = self.analytics_results.get("alert_fatigue")
            if fatigue and fatigue.get("total_evaluated", 0) > 0:
                v7_section += (
                    '<div class="card"><h3>Alert Fatigue Reduction</h3>\n'
                    '<p><b>Evaluated:</b> ' + str(fatigue.get("total_evaluated", 0)) +
                    ' | <b>Sent:</b> ' + str(fatigue.get("alerts_sent", 0)) +
                    ' | <b>Suppressed:</b> ' + str(fatigue.get("alerts_suppressed", 0)) +
                    ' (' + "{:.1f}".format(fatigue.get("suppression_pct", 0)) + '% removed)' +
                    ' | <b>Noise score:</b> ' + "{:.1f}".format(fatigue.get("noise_score", 0)) + '/100</p>\n')
                reasons = fatigue.get("suppression_reasons", {})
                if reasons:
                    v7_section += '<p><b>Reasons:</b> ' + ", ".join(
                        str(k) + '=' + str(v) for k, v in sorted(reasons.items())) + '</p>\n'
                v7_section += '</div>\n'
            oncall = self.analytics_results.get("oncall")
            if oncall and oncall.get("stats", {}).get("incidents_evaluated", 0) > 0:
                oc_stats = oncall.get("stats", {})
                ack_rate = oc_stats.get("ack_rate_pct", 0)
                ack_color = "#22c55e" if ack_rate >= 90 else ("#eab308" if ack_rate >= 70 else "#ef4444")
                v7_section += (
                    '<div class="card"><h3>On-Call Simulation</h3>\n'
                    '<p><b>Ack rate:</b> <span style="color:' + ack_color + '">' +
                    "{:.1f}".format(ack_rate) + '%</span>'
                    ' | <b>Unacked:</b> ' + str(oc_stats.get("unacked_events", 0)) +
                    ' | <b>Handoffs:</b> ' + str(oc_stats.get("handoff_events", 0)) + '</p>\n')
                if oncall.get("simulations"):
                    v7_section += '<table><tr><th>Incident</th><th>Severity</th><th>Tier</th><th>Role</th><th>On-Call</th><th>Ack</th></tr>\n'
                    for sim in oncall.get("simulations", [])[:10]:
                        for responder in sim.get("responders", []):
                            ack_str = "yes" if responder.get("acked") else "no"
                            ack_cell = "#22c55e" if responder.get("acked") else "#ef4444"
                            v7_section += (
                                '<tr><td>' + sim.get("incident_id", "?") + '</td>'
                                '<td>' + sim.get("severity", "?") + '</td>'
                                '<td>' + str(responder.get("tier", "?")) + '</td>'
                                '<td>' + str(responder.get("role", "?")) + '</td>'
                                '<td>' + str(responder.get("oncall", "?")) + '</td>'
                                '<td style="color:' + ack_cell + '">' + ack_str + '</td></tr>\n')
                    v7_section += '</table>\n'
                v7_section += '</div>\n'
            forecast = self.analytics_results.get("sla_forecast_refined")
            if forecast and forecast.get("available"):
                trend_name = forecast.get("trend", "n/a")
                trend_color = {"improving": "#22c55e", "degrading": "#ef4444"}.get(trend_name, "#60a5fa")
                v7_section += (
                    '<div class="card"><h3>SLA Forecast (Refined)</h3>\n'
                    '<p><b>Current:</b> ' + "{:.4f}".format(forecast.get("current_uptime", 0)) +
                    '% | <b>Trend:</b> <span style="color:' + trend_color + '">' + trend_name + '</span>' +
                    ' | <b>First breach:</b> ' + str(forecast.get("first_breach_horizon") or "none within horizon") + '</p>\n')
                if forecast.get("horizons"):
                    v7_section += '<table><tr><th>Horizon</th><th>Projected</th><th>Target</th><th>Status</th></tr>\n'
                    for horizon in forecast.get("horizons", []):
                        ok = horizon.get("compliant")
                        h_color = "#22c55e" if ok else "#ef4444"
                        v7_section += (
                            '<tr><td>' + horizon.get("label", "?") + '</td>'
                            '<td>' + "{:.4f}".format(horizon.get("projected_uptime", 0)) + '%</td>'
                            '<td>' + "{:.3f}".format(horizon.get("target", 0)) + '%</td>'
                            '<td style="color:' + h_color + '">' +
                            ("COMPLIANT" if ok else "AT RISK") + '</td></tr>\n')
                    v7_section += '</table>\n'
                v7_section += '</div>\n'
            roi_refine = self.analytics_results.get("roi_refined")
            if roi_refine and roi_refine.get("available"):
                best = roi_refine.get("best_scenario") or {}
                v7_section += (
                    '<div class="card"><h3>ROI Analysis (Refined)</h3>\n'
                    '<p><b>Monthly downtime risk:</b> $' + "{:,.2f}".format(roi_refine.get("monthly_downtime_risk", 0)) +
                    ' | <b>Breakeven capture:</b> ' + "{:.1f}".format(roi_refine.get("breakeven_capture_rate_pct", 0)) + '%' +
                    ' | <b>Best:</b> ' + str(best.get("scenario", "n/a")) +
                    ' (net $' + "{:,.2f}".format(best.get("net_benefit_monthly", 0)) + '/mo)</p>\n')
                if roi_refine.get("scenarios"):
                    v7_section += '<table><tr><th>Scenario</th><th>Capture</th><th>Net/mo</th><th>ROI</th></tr>\n'
                    for scenario in roi_refine.get("scenarios", []):
                        v7_section += (
                            '<tr><td>' + str(scenario.get("scenario", "?")) + '</td>'
                            '<td>' + "{:.0f}".format(scenario.get("capture_rate_pct", 0)) + '%</td>'
                            '<td>$' + "{:,.2f}".format(scenario.get("net_benefit_monthly", 0)) + '</td>'
                            '<td>' + "{:.0f}".format(scenario.get("roi_pct", 0)) + '%</td></tr>\n')
                    v7_section += '</table>\n'
                v7_section += '</div>\n'
            pred_refine = self.analytics_results.get("predictive_refined")
            cap_refine = self.analytics_results.get("capacity_refined")
            cost_refine = self.analytics_results.get("cost_refined")
            if pred_refine or (cap_refine and cap_refine.get("available")) or (cost_refine and cost_refine.get("available")):
                v7_section += '<div class="card"><h3>Refined Analytics</h3>\n'
                if pred_refine:
                    band = pred_refine.get("risk_band", "STABLE")
                    band_color = {"STABLE": "#22c55e", "GUARDED": "#eab308", "ELEVATED": "#f97316", "SEVERE": "#ef4444"}.get(band, "#60a5fa")
                    v7_section += '<p><b>Predictive risk band:</b> <span style="color:' + band_color + '">' + band + \
                        '</span> (score ' + "{:.1f}".format(pred_refine.get("risk_score", 0)) + '/100)</p>\n'
                if cap_refine and cap_refine.get("available"):
                    posture = cap_refine.get("posture", "n/a")
                    posture_color = {"COMFORTABLE": "#22c55e", "ADEQUATE": "#eab308"}.get(posture, "#ef4444")
                    v7_section += '<p><b>Capacity:</b> headroom ' + \
                        "{:.1f}".format(cap_refine.get("headroom_pct", 0)) + '% &rarr; ' + \
                        "{:.1f}".format(cap_refine.get("projected_headroom_pct", 0)) + '% projected' + \
                        ' | <span style="color:' + posture_color + '">' + posture + '</span></p>\n'
                if cost_refine and cost_refine.get("available"):
                    rec = cost_refine.get("recommended") or {}
                    v7_section += '<p><b>Cost efficiency:</b> ' + \
                        "{:.1f}".format(cost_refine.get("efficiency_score", 0)) + '/100' + \
                        ' | recommended interval: ' + str(rec.get("interval_seconds", 0)) + 's' + \
                        ' (' + "{:.1f}".format(rec.get("volume_reduction_pct", 0)) + '% volume reduction)</p>\n'
                v7_section += '</div>\n'
        postmortem_section = ""
        if self.postmortems:
            postmortem_section = (
                '<div class="card"><h3>Incident Post-Mortems</h3>\n'
                '<table><tr><th>Incident</th><th>Severity</th><th>Duration</th><th>Root Cause</th><th>Actions</th></tr>\n')
            for pm in self.postmortems:
                pm_cause = str(pm.get("summary", "")).replace("<", "&lt;").replace(">", "&gt;")
                postmortem_section += (
                    '<tr><td>' + pm.get("incident_id", "?") + '</td>'
                    '<td>' + pm.get("severity", "?") + '</td>'
                    '<td>' + "{:.1f}".format(pm.get("duration_minutes", 0)) + 'm</td>'
                    '<td>' + pm_cause + '</td>'
                    '<td>' + str(len(pm.get("action_items", []))) + '</td></tr>\n')
            postmortem_section += '</table></div>\n'
        pcts = stats["percentiles"]
        trend = stats["response_time_trend"]
        if trend > 1:
            trend_text = "+{:.1f} ms/check (degrading)".format(trend)
        elif trend < -1:
            trend_text = "{:.1f} ms/check (improving)".format(trend)
        else:
            trend_text = "Stable"
        pct_section = (
            '<div class="card"><h3>Response Time Percentiles</h3>\n'
            '<p><b>P50:</b> ' + "{:.1f}".format(pcts["p50"]) + 'ms | '
            '<b>P90:</b> ' + "{:.1f}".format(pcts["p90"]) + 'ms | '
            '<b>P95:</b> ' + "{:.1f}".format(pcts["p95"]) + 'ms | '
            '<b>P99:</b> ' + "{:.1f}".format(pcts["p99"]) + 'ms</p>\n'
            '<p><b>Trend:</b> ' + trend_text + '</p>\n'
            '</div>\n')
        generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return (
            '<!DOCTYPE html><html><head>'
            '<title>UptimeChecker v' + VERSION + ' Report - ' + str(self.hostname) + '</title>\n'
            '<style>\n'
            'body{font-family:system-ui,-apple-system,sans-serif;margin:40px;background:#0f172a;color:#e2e8f0}\n'
            'h1,h2,h3{color:#f8fafc}\n'
            '.card{background:#1e293b;border-radius:12px;padding:20px;margin:16px 0;border:1px solid #334155}\n'
            'table{width:100%;border-collapse:collapse;margin:16px 0}\n'
            'th,td{padding:10px;text-align:left;border-bottom:1px solid #334155}\n'
            'th{background:#1e293b;color:#94a3b8}\n'
            '.verdict{font-size:2em;font-weight:bold;color:' + verdict_color + ';text-align:center;padding:20px}\n'
            '.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}\n'
            '.stat-box{background:#1e293b;border-radius:8px;padding:16px;text-align:center;border:1px solid #334155}\n'
            '.stat-value{font-size:1.5em;font-weight:bold;color:#60a5fa}\n'
            '</style></head><body>\n'
            '<h1>UptimeChecker v' + VERSION + ' Report</h1>\n'
            '<p>Protocol: ' + self.protocol.upper() + ' | Target: ' + self.target_label + '</p>\n'
            '<p>Generated: ' + generated + '</p>\n'
            '<div class="verdict">' + verdict + '</div>\n'
            '<div class="stats">\n'
            '<div class="stat-box"><div class="stat-value">' + "{:.2f}".format(uptime_pct) + '%</div><div>Uptime</div></div>\n'
            '<div class="stat-box"><div class="stat-value">' + "{:.0f}".format(avg_score) + '/100</div><div>Score</div></div>\n'
            '<div class="stat-box"><div class="stat-value">' + "{:.0f}".format(stats["avg_time"]) + 'ms</div><div>Avg Response</div></div>\n'
            '<div class="stat-box"><div class="stat-value">' + str(len(self.results)) + '</div><div>Checks</div></div>\n'
            '<div class="stat-box"><div class="stat-value">' + "{:.2f}".format(stats["error_rate"]) + '%</div><div>Error Rate</div></div>\n'
            '</div>\n'
            '<div class="card"><h2>Check Results</h2>\n'
            '<table><tr><th>#</th><th>Timestamp</th><th>Protocol</th><th>Status</th><th>Response</th><th>Score</th></tr>\n'
            + rows + '</table></div>\n'
            + dns_section + ssl_section + extended_section + incident_section + sla_section + analytics_section + v7_section + postmortem_section + pct_section
            + '<div class="card"><h3>Timing</h3>\n'
            '<p>Average: ' + "{:.1f}".format(stats["avg_time"]) + 'ms | '
            'Min: ' + "{:.1f}".format(stats["min_time"]) + 'ms | '
            'Max: ' + "{:.1f}".format(stats["max_time"]) + 'ms | '
            'Median: ' + "{:.1f}".format(stats["median_time"]) + 'ms</p>\n'
            '</div>\n'
            '</body></html>')

def main():
    if len(sys.argv) == 1:
        print(HELP_TEXT)
        sys.exit(0)

    parser = argparse.ArgumentParser(
        description="UptimeChecker v" + VERSION + " -- Multi-protocol uptime, DNS, SSL & network monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=HELP_TEXT)
    parser.add_argument("-u", "--url", help="Target URL to check (HTTP/HTTPS)")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Timeout in seconds (default: 15)")
    parser.add_argument("-c", "--count", type=int, default=1, help="Number of checks (default: 1)")
    parser.add_argument("-i", "--interval", type=int, default=5, help="Seconds between checks (default: 5)")
    parser.add_argument("--export", choices=["all", "json", "csv", "html", "none"],
                        default="none", help="Export format (default: none)")
    parser.add_argument("--no-color", action="store_true", help="Disable colors")
    parser.add_argument("--follow-redirects", action="store_true", default=True,
                        help="Follow redirects (default: true)")
    parser.add_argument("--no-follow-redirects", dest="follow_redirects",
                        action="store_false", help="Do not follow redirects")
    parser.add_argument("--expect", help="Expected string to find on page")
    parser.add_argument("--extended-checks", action="store_true",
                        help="Run extended checks (CDN, load balancer, tech, HTTP/2/3, etc.)")
    parser.add_argument("--circuit-breaker", type=int, default=5,
                        help="Stop after N consecutive failures (default: 5, 0=disabled)")
    parser.add_argument("--exponential-backoff", action="store_true",
                        help="Use exponential backoff for retry intervals")
    parser.add_argument("--jitter", action="store_true",
                        help="Add random jitter to monitoring intervals")
    parser.add_argument("--sla-target", type=float, default=99.9,
                        help="SLA target percentage (default: 99.9)")
    parser.add_argument("--tcp", dest="tcp_target", help="TCP target as host:port")
    parser.add_argument("--smtp", dest="smtp_host", help="SMTP host to check")
    parser.add_argument("--port", dest="smtp_port", type=int, default=587,
                        help="SMTP port (default: 587)")
    parser.add_argument("--ftp", dest="ftp_host", help="FTP host to check")
    parser.add_argument("--ssh", dest="ssh_host", help="SSH host to check")
    parser.add_argument("-p", "--ssh-port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--ping", dest="ping_host", help="Host to ICMP ping")
    parser.add_argument("--dns", dest="dns_host", help="Hostname for DNS checks")
    parser.add_argument("--dns-record", dest="dns_record_type", default="A",
                        choices=DNS_RECORD_TYPES, help="DNS record type (default: A)")
    parser.add_argument("--webhook", help="Webhook URL for notifications")
    parser.add_argument("--health-endpoint", help="Custom health check endpoint path")
    parser.add_argument("--synthetic-method", default="GET",
                        choices=["GET", "POST", "PUT", "DELETE", "HEAD"],
                        help="HTTP method for synthetic checks")
    parser.add_argument("--synthetic-body", help="Request body for synthetic POST/PUT")
    parser.add_argument("--doh-server", default="https://cloudflare-dns.com/dns-query",
                        help="DNS-over-HTTPS server URL")
    parser.add_argument("--multi-region", action="store_true",
                        help="Enable multi-region monitoring (HTTP only)")
    parser.add_argument("--regions", type=str, default=None,
                        help="Comma-separated region IDs (default: all)")
    parser.add_argument("--analytics", action="store_true",
                        help="Enable advanced analytics (trend, regression, anomalies, SLA prediction, SLO, predictive)")
    parser.add_argument("--slo-target", type=float, default=None,
                        help="SLO target percentage for error budget tracking (default: same as --sla-target)")
    parser.add_argument("--slo-period", type=int, default=30, dest="slo_period_days",
                        help="SLO period in days for error budget window (default: 30)")
    parser.add_argument("--exec-summary", action="store_true",
                        help="Show executive summary dashboard")
    parser.add_argument("--deep-dive", action="store_true",
                        help="Show technical deep dive report")
    parser.add_argument("--postmortem", action="store_true",
                        help="Generate incident post-mortem reports with automated RCA")
    parser.add_argument("--full-report", action="store_true",
                        help="Show full enhanced report (exec summary + deep dive + projections + SLA forecast)")
    parser.add_argument("--rum", action="store_true",
                        help="Enable real user monitoring integration (v6.0)")
    parser.add_argument("--rum-file", dest="rum_file", default=None,
                        help="Path to JSON array of RUM samples to ingest")
    parser.add_argument("--ab-test", action="store_true",
                        help="Enable A/B test variant monitoring (v6.0)")
    parser.add_argument("--feature-flags", action="store_true",
                        help="Enable feature flag state monitoring (v6.0)")
    parser.add_argument("--dependency-chain", action="store_true",
                        help="Enable dependency chain monitoring (v6.0)")
    parser.add_argument("--incident-automation", action="store_true",
                        help="Enable incident response automation with runbooks (v6.0)")
    parser.add_argument("--stakeholders", type=str, default=None,
                        help="Comma-separated stakeholders (role or role:address) for notifications")
    parser.add_argument("--roi", action="store_true",
                        help="Enable ROI analysis (v6.0)")
    parser.add_argument("--synthetic-journey", action="store_true",
                        help="Run multi-step synthetic journey monitoring (v6.0)")
    parser.add_argument("--hourly-downtime-cost", type=float, default=500.0,
                        help="Hourly cost of downtime in USD for ROI analysis (default: 500)")
    parser.add_argument("--service-map", action="store_true",
                        help="Enable service dependency mapping with blast-radius analysis (v7.0)")
    parser.add_argument("--cascade-detect", action="store_true",
                        help="Enable cascading failure detection across incidents (v7.0)")
    parser.add_argument("--maintenance-window", action="append", default=None,
                        dest="maintenance_windows", metavar="HH:MM-HH:MM",
                        help="Schedule a maintenance window that suppresses low/medium alerts (repeatable, v7.0)")
    parser.add_argument("--alert-fatigue", action="store_true",
                        help="Enable alert fatigue reduction with dedupe and burst rate limiting (v7.0)")
    parser.add_argument("--oncall-sim", action="store_true",
                        help="Enable on-call rotation simulation with ack/handoff analysis (v7.0)")
    parser.add_argument("-v", "--version", action="version", version="UptimeChecker v" + VERSION)

    args = parser.parse_args()

    if args.no_color:
        global console
        console = Console(no_color=True)

    cb_threshold = args.circuit_breaker if args.circuit_breaker > 0 else 9999

    protocol = "http"
    if args.tcp_target:
        protocol = "tcp"
    elif args.smtp_host:
        protocol = "smtp"
    elif args.ftp_host:
        protocol = "ftp"
    elif args.ssh_host:
        protocol = "ssh"
    elif args.ping_host:
        protocol = "ping"
    elif args.dns_host:
        protocol = "dns"

    regions = None
    if args.regions:
        regions = [r.strip() for r in args.regions.split(",") if r.strip()]

    stakeholders = None
    if args.stakeholders:
        stakeholders = [s.strip() for s in args.stakeholders.split(",") if s.strip()]

    checker = UptimeChecker(
        url=args.url,
        timeout=args.timeout,
        count=args.count,
        interval=args.interval,
        export=args.export,
        no_color=args.no_color,
        follow_redirects=args.follow_redirects,
        expect=args.expect,
        circuit_breaker_threshold=cb_threshold,
        exponential_backoff=args.exponential_backoff,
        jitter=args.jitter,
        extended_checks=args.extended_checks,
        sla_target=args.sla_target,
        protocol=protocol,
        tcp_target=args.tcp_target,
        smtp_host=args.smtp_host,
        smtp_port=args.smtp_port,
        ftp_host=args.ftp_host,
        ssh_host=args.ssh_host,
        ssh_port=args.ssh_port,
        ping_host=args.ping_host,
        dns_host=args.dns_host,
        dns_record_type=args.dns_record_type,
        webhook=args.webhook,
        health_endpoint=args.health_endpoint,
        synthetic_method=args.synthetic_method,
        synthetic_body=args.synthetic_body,
        doh_server=args.doh_server,
        multi_region=args.multi_region,
        regions=regions,
        analytics=args.analytics,
        slo_target=args.slo_target,
        slo_period_days=args.slo_period_days,
        exec_summary=args.exec_summary,
        deep_dive=args.deep_dive,
        postmortem=args.postmortem,
        full_report=args.full_report,
        rum=args.rum,
        rum_file=args.rum_file,
        ab_test=args.ab_test,
        feature_flags=args.feature_flags,
        dependency_chain=args.dependency_chain,
        incident_automation=args.incident_automation,
        stakeholders=stakeholders,
        roi=args.roi,
        synthetic_journey=args.synthetic_journey,
        hourly_downtime_cost=args.hourly_downtime_cost,
        service_map=args.service_map,
        cascade_detect=args.cascade_detect,
        maintenance_windows=args.maintenance_windows,
        alert_fatigue=args.alert_fatigue,
        oncall_sim=args.oncall_sim,
    )
    checker.run()


if __name__ == "__main__":
    main()
