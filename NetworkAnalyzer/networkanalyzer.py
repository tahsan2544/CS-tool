#!/usr/bin/env python3
import sys
import os
import argparse
import socket
import ssl
import time
import json
import csv
import struct
import hashlib
import base64
import re
import subprocess
import warnings
import ipaddress
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

warnings.filterwarnings("ignore", category=DeprecationWarning)

try:
    import requests
except ImportError:
    os.system("pip install requests >/dev/null 2>&1")
    import requests

try:
    import dns.resolver
    import dns.rdatatype
    import dns.flags
    import dns.dnssec
    import dns.name
    import dns.message
    import dns.query
    HAS_DNSPYTHON = True
except ImportError:
    os.system("pip install dnspython >/dev/null 2>&1")
    try:
        import dns.resolver
        import dns.rdatatype
        import dns.flags
        import dns.dnssec
        import dns.name
        import dns.message
        import dns.query
        HAS_DNSPYTHON = True
    except ImportError:
        HAS_DNSPYTHON = False

VERSION = "5.0"

DOH_PROVIDERS = [
    {"name": "Google", "url": "https://dns.google/resolve"},
    {"name": "Cloudflare", "url": "https://cloudflare-dns.com/dns-query"},
    {"name": "Quad9", "url": "https://dns.quad9.net/dns-query"},
]

CATEGORY_NAMES = {
    "dns": "DNS Analysis",
    "tcp": "TCP/Connection",
    "ssl": "SSL/TLS Network",
    "http": "HTTP Protocol",
    "cdn": "CDN Detection",
    "fingerprint": "Server Fingerprinting",
    "latency": "Latency & Routing",
    "bandwidth": "Bandwidth Estimation",
    "netsec": "Network Security",
    "protocols": "Protocol Support",
    "ipv6": "IPv6 Connectivity",
    "routing": "BGP Routing",
    "congestion": "Congestion/Loss/Jitter",
    "pmtu": "Path MTU",
    "audit": "Security Audit",
    "encryption": "Encryption Analysis",
    "certchain": "Certificate Chain",
    "protosec": "Protocol Security",
    "portsec": "Port Security",
    "reliability": "Reliability Analysis",
    "scalability": "Scalability Analysis",
    "resilience": "Resilience Analysis",
    "quic": "QUIC / HTTP3 Deep",
    "tls13": "TLS 1.3 Optimization",
    "tfo": "TCP Fast Open",
    "coalesce": "Connection Coalescing",
    "priority": "Priority Headers",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    GRAY = '\033[90m'
    WHITE = '\033[97m'
    MAGENTA = '\033[35m'


class NoColors:
    HEADER = ''
    BLUE = ''
    CYAN = ''
    GREEN = ''
    YELLOW = ''
    RED = ''
    BOLD = ''
    UNDERLINE = ''
    END = ''
    GRAY = ''
    WHITE = ''
    MAGENTA = ''


def print_banner(colors):
    banner = f"""
{colors.CYAN}{colors.BOLD}
    \u2588\u2588\u2588\u2557   \u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2557    \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2557    \u2588\u2588\u2557  \u2588\u2588\u2557
    \u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2594\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u2550\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2594\u2550\u2550\u2550\u2550\u255d    \u2588\u2588\u2594\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2594\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2594\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2594\u2550\u255d\u2588\u2588\u2594\u2550\u2550\u255d
    \u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557   \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557    \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2594\u2550\u255d   \u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2557
    \u2588\u2588\u2594\u2550\u2550\u2550\u2550\u2550\u2588\u2588\u2588\u2557\u2588\u2588\u2594\u2550\u2550\u2550\u2550\u255d   \u2588\u2588\u2594\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2594\u2550\u2550\u2550\u2550\u255d    \u2588\u2588\u2594\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2594\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2594\u2550\u255d  \u2588\u2588\u2594\u2550\u2550\u2550\u2550\u2550\u2588\u2588\u2557
    \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551 \u255a\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551   \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551    \u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u255a\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2594\u2550\u255d \u255a\u2588\u2588\u2588\u2557 \u2588\u2588\u2557
    \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d   \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d    \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u2550\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u255d
{colors.END}
{colors.YELLOW}    Network Analyzer v{VERSION} - Advanced Network Diagnostics{colors.END}
{colors.GRAY}    DNS \u00b7 CDN \u00b7 SSL/TLS \u00b7 HTTP \u00b7 IPv6 \u00b7 BGP \u00b7 Congestion \u00b7 MTU \u00b7 Encryption{colors.END}
{colors.GRAY}    Certificates \u00b7 Protocol Security \u00b7 Port Security \u00b7 Reliability \u00b7 Scalability{colors.END}
{colors.GRAY}    QUIC/HTTP3 \u00b7 TLS 1.3 \u00b7 TCP Fast Open \u00b7 Coalescing \u00b7 Priority Headers{colors.END}
"""
    print(banner)


class NetworkAnalyzer:
    def __init__(self, url, timeout=15, no_color=False, verbose=False):
        self.url = url if url.startswith(('http://', 'https://')) else f'https://{url}'
        self.timeout = timeout
        self.no_color = no_color
        self.verbose = verbose
        self.colors = NoColors if no_color else Colors
        self.results = {}
        self.scores = {}
        self.refined_scores = {}
        self.refined_analysis = {}
        self.recommendations = []
        self.parsed = urlparse(self.url)
        self.domain = self.parsed.hostname
        self.port = self.parsed.port or (443 if self.parsed.scheme == 'https' else 80)
        self.ip_addresses = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })

    def _log(self, msg, level="info"):
        if self.verbose or level in ("info", "warn", "error", "ok"):
            prefix = {
                "info": f"{self.colors.CYAN}[*]{self.colors.END}",
                "ok": f"{self.colors.GREEN}[+]{self.colors.END}",
                "warn": f"{self.colors.YELLOW}[!]{self.colors.END}",
                "error": f"{self.colors.RED}[-]{self.colors.END}",
            }.get(level, f"{self.colors.CYAN}[*]{self.colors.END}")
            print(f"  {prefix} {msg}")

    def _resolve_dns(self, record_type, resolver=None):
        if not HAS_DNSPYTHON:
            return []
        try:
            r = resolver or dns.resolver.Resolver()
            answers = r.resolve(self.domain, record_type)
            return [str(rdata) for rdata in answers]
        except Exception:
            return []

    def _doh_query(self, provider_url, record_type):
        """Query DNS-over-HTTPS provider for a record type."""
        try:
            rtype_map = {
                "A": 1, "AAAA": 28, "CNAME": 5, "MX": 15,
                "NS": 2, "TXT": 16, "SOA": 6, "SRV": 33, "CAA": 257,
            }
            rtype_val = rtype_map.get(record_type)
            if rtype_val is None:
                return {"ips": [], "time_ms": -1, "error": f"Unsupported type: {record_type}"}
            params = {"name": self.domain, "type": str(rtype_val)}
            headers = {"Accept": "application/dns-json"}
            start = time.time()
            resp = requests.get(provider_url, params=params, headers=headers, timeout=10)
            elapsed = round((time.time() - start) * 1000, 2)
            if resp.status_code == 200:
                data = resp.json()
                answers = [a.get("data", "") for a in data.get("Answer", []) if a.get("data")]
                return {"data": answers, "time_ms": elapsed, "status": data.get("Status", -1)}
            return {"data": [], "time_ms": elapsed, "status": resp.status_code}
        except Exception as e:
            return {"data": [], "time_ms": -1, "error": str(e)}

    def _doh_multi_query(self):
        """Query multiple DoH providers and compare results."""
        results = {}
        record_type = "A"
        for provider in DOH_PROVIDERS:
            query_result = self._doh_query(provider["url"], record_type)
            results[provider["name"]] = query_result
            data = query_result.get("data", [])
            ms = query_result.get("time_ms", -1)
            status = query_result.get("status", -1)
            if data:
                joined = ", ".join(data[:3])
                self._log(f"  DoH {provider['name']}: {joined} ({ms}ms) status={status}", "ok")
            else:
                err = query_result.get("error", "no data")
                self._log(f"  DoH {provider['name']}: Failed - {err}", "warn")
        return results

    def _dns_ttl_analysis(self):
        """Analyze TTL values across A records."""
        ttl_map = {}
        if not HAS_DNSPYTHON:
            return ttl_map
        try:
            answers = dns.resolver.resolve(self.domain, "A")
            for rdata in answers:
                ttl_map[str(rdata)] = answers.ttl
        except Exception:
            pass
        return ttl_map

    def _dns_propagation_check(self):
        """Check DNS propagation consistency across multiple global resolvers."""
        global_resolvers = {
            "Google (8.8.8.8)": "8.8.8.8",
            "Google (8.8.4.4)": "8.8.4.4",
            "Cloudflare (1.1.1.1)": "1.1.1.1",
            "Cloudflare (1.0.0.1)": "1.0.0.1",
            "Quad9 (9.9.9.9)": "9.9.9.9",
            "Quad9 (149.112.112.112)": "149.112.112.112",
            "OpenDNS (208.67.222.222)": "208.67.222.222",
        }
        propagation = {}
        all_ips = set()
        for name, server in global_resolvers.items():
            try:
                r = dns.resolver.Resolver()
                r.nameservers = [server]
                start = time.time()
                answers = r.resolve(self.domain, "A")
                elapsed = round((time.time() - start) * 1000, 2)
                ips = sorted([str(a) for a in answers])
                propagation[name] = {"ips": ips, "time_ms": elapsed, "status": "ok"}
                all_ips.update(ips)
            except Exception as e:
                propagation[name] = {"ips": [], "time_ms": -1, "status": str(e)}
        consistent = len(all_ips) <= 1
        return propagation, consistent, all_ips

    def _dnssec_chain_validation(self):
        """Validate DNSSEC chain of trust."""
        dnssec_info = {
            "enabled": False,
            "ds_records": [],
            "dnskey_records": [],
            "rrsig_valid": False,
            "chain_status": "unknown",
        }
        if not HAS_DNSPYTHON:
            return dnssec_info

        try:
            resolver = dns.resolver.Resolver()
            resolver.use_edns(0, dns.flags.DO, 4096)
            answers = resolver.resolve(self.domain, "A")
            dnssec_info["enabled"] = bool(answers.response.flags & dns.flags.AD)
        except Exception:
            pass

        if dnssec_info["enabled"]:
            dnssec_info["chain_status"] = "validated"

        try:
            ds_answers = dns.resolver.resolve(self.domain, "DS")
            dnssec_info["ds_records"] = [str(r) for r in ds_answers]
        except Exception:
            pass

        try:
            dnskey_answers = dns.resolver.resolve(self.domain, "DNSKEY")
            dnssec_info["dnskey_records"] = [str(r) for r in dnskey_answers]
        except Exception:
            pass

        if dnssec_info["ds_records"] and dnssec_info["enabled"]:
            dnssec_info["chain_status"] = "chain_complete"
        elif dnssec_info["ds_records"] and not dnssec_info["enabled"]:
            dnssec_info["chain_status"] = "chain_broken"
        elif not dnssec_info["ds_records"] and not dnssec_info["enabled"]:
            dnssec_info["chain_status"] = "no_dnssec"

        return dnssec_info

    def _dns_change_detection(self):
        """Detect potential DNS record changes by checking multiple record sets."""
        change_info = {"changes_detected": False, "records": {}}
        if not HAS_DNSPYTHON:
            return change_info
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA"]
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, rtype)
                records = []
                for rdata in answers:
                    records.append({
                        "value": str(rdata),
                        "ttl": answers.ttl,
                        "rdtype": str(rdata.rdtype),
                    })
                change_info["records"][rtype] = records
            except Exception:
                change_info["records"][rtype] = []
        return change_info

    def analyze_dns(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  1. DNS ANALYSIS (DEEP)")
        print(f"{'='*60}{c.END}")
        result = {"category": "dns", "max_score": 20, "score": 0, "details": {}}

        if not HAS_DNSPYTHON:
            self._log("dnspython not available, using socket fallback", "warn")
            try:
                ips = socket.getaddrinfo(self.domain, None)
                a_records = list(set([addr[4][0] for addr in ips]))
                result["details"]["A"] = a_records
                joined = ", ".join(a_records)
                self._log(f"A Records: {joined}", "ok")
                result["score"] = 5
                self.ip_addresses = a_records
            except Exception as e:
                self._log(f"DNS resolution failed: {e}", "error")
                self.scores["dns"] = result
                return result
            self.scores["dns"] = result
            return result

        start = time.time()
        a_records = self._resolve_dns("A")
        dns_time = round((time.time() - start) * 1000, 2)
        result["details"]["A"] = a_records
        result["details"]["dns_response_time_ms"] = dns_time

        if a_records:
            joined = ", ".join(a_records)
            self._log(f"A Records: {joined}", "ok")
            self.ip_addresses = a_records
        else:
            self._log("No A records found", "error")
            self.scores["dns"] = result
            return result

        self._log(f"DNS Response Time: {dns_time}ms", "info")

        aaaa_records = self._resolve_dns("AAAA")
        result["details"]["AAAA"] = aaaa_records
        if aaaa_records:
            joined = ", ".join(aaaa_records)
            self._log(f"AAAA Records: {joined}", "ok")
        else:
            self._log("No AAAA records found", "info")

        ns_records = self._resolve_dns("NS")
        result["details"]["NS"] = ns_records
        if ns_records:
            joined = ", ".join(ns_records)
            self._log(f"NS Records: {joined}", "ok")

        mx_records = self._resolve_dns("MX")
        result["details"]["MX"] = mx_records
        if mx_records:
            joined = ", ".join(str(m) for m in mx_records)
            self._log(f"MX Records: {joined}", "ok")

        txt_records = self._resolve_dns("TXT")
        result["details"]["TXT"] = txt_records
        if txt_records:
            self._log(f"TXT Records: {len(txt_records)} found", "ok")
            for txt in txt_records[:5]:
                self._log(f"  - {txt[:80]}", "info")

        cname_records = self._resolve_dns("CNAME")
        result["details"]["CNAME"] = cname_records
        if cname_records:
            joined = ", ".join(cname_records)
            self._log(f"CNAME: {joined}", "ok")

        soa_records = self._resolve_dns("SOA")
        result["details"]["SOA"] = [str(s) for s in soa_records] if soa_records else []
        if soa_records:
            self._log("SOA: Found", "ok")

        srv_records = self._resolve_dns("SRV")
        result["details"]["SRV"] = srv_records
        if srv_records:
            self._log(f"SRV Records: {len(srv_records)} found", "ok")

        caa_records = self._resolve_dns("CAA")
        result["details"]["CAA"] = caa_records
        if caa_records:
            self._log(f"CAA Records: {len(caa_records)} found", "ok")

        self._log("--- DNS TTL Analysis ---", "info")
        ttl_info = self._dns_ttl_analysis()
        result["details"]["TTL"] = ttl_info
        if ttl_info:
            for ip, ttl in ttl_info.items():
                self._log(f"  TTL for {ip}: {ttl}s", "info")

        self._log("--- DNS-over-HTTPS (DoH) ---", "info")
        doh_results = self._doh_multi_query()
        result["details"]["doh_providers"] = doh_results
        doh_success = sum(1 for v in doh_results.values() if v.get("data"))
        result["details"]["doh_success_count"] = doh_success

        self._log("--- DNS Propagation ---", "info")
        propagation, propagation_consistent, all_resolved_ips = self._dns_propagation_check()
        result["details"]["propagation"] = propagation
        result["details"]["propagation_consistent"] = propagation_consistent
        result["details"]["propagation_ips"] = sorted(list(all_resolved_ips))
        ip_count = len(all_resolved_ips)
        if propagation_consistent:
            self._log(f"Propagation consistent: Yes ({ip_count} unique IPs)", "ok")
        else:
            self._log(f"Propagation consistent: No ({ip_count} unique IPs)", "warn")

        self._log("--- DNSSEC Validation ---", "info")
        dnssec_info = self._dnssec_chain_validation()
        result["details"]["dnssec"] = dnssec_info
        dnssec_enabled = dnssec_info.get("enabled", False)
        chain_status = dnssec_info.get("chain_status", "unknown")
        if dnssec_enabled:
            self._log("DNSSEC: Enabled", "ok")
        else:
            self._log("DNSSEC: Disabled", "warn")
        if chain_status in ("validated", "chain_complete"):
            self._log(f"  Chain Status: {chain_status}", "ok")
        else:
            self._log(f"  Chain Status: {chain_status}", "warn")
        if dnssec_info.get("ds_records"):
            self._log(f"  DS Records: {len(dnssec_info['ds_records'])}", "ok")
        if dnssec_info.get("dnskey_records"):
            self._log(f"  DNSKEY Records: {len(dnssec_info['dnskey_records'])}", "ok")

        self._log("--- DNS Change Detection ---", "info")
        change_info = self._dns_change_detection()
        result["details"]["change_detection"] = change_info
        change_count = sum(1 for records in change_info.get("records", {}).values() if records)
        self._log(f"Record types with data: {change_count}", "info")

        score = 0
        if a_records: score += 3
        if aaaa_records: score += 1
        if ns_records: score += 2
        if mx_records: score += 1
        if txt_records: score += 2
        if cname_records: score += 1
        if soa_records: score += 1
        if dns_time < 50: score += 2
        elif dns_time < 200: score += 1
        if dnssec_enabled: score += 2
        if propagation_consistent: score += 1
        if doh_success >= 2: score += 2
        if ttl_info:
            max_ttl = max(ttl_info.values()) if ttl_info else 0
            if max_ttl > 0: score += 1
        result["score"] = min(score, 20)
        self.scores["dns"] = result
        self._log(f"DNS Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def analyze_tcp(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  2. TCP/CONNECTION ANALYSIS (DEEP)")
        print(f"{'='*60}{c.END}")
        result = {"category": "tcp", "max_score": 15, "score": 0, "details": {}}

        if not self.ip_addresses:
            self._log("No IP addresses resolved, attempting DNS lookup", "warn")
            try:
                ips = socket.getaddrinfo(self.domain, None)
                self.ip_addresses = list(set([addr[4][0] for addr in ips]))
            except Exception as e:
                self._log(f"Failed to resolve: {e}", "error")
                self.scores["tcp"] = result
                return result

        tcp_results = []
        for ip in self.ip_addresses[:3]:
            try:
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((ip, self.port))
                connect_time = round((time.time() - start) * 1000, 2)

                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                try:
                    buf_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                    snd_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
                except Exception:
                    buf_size = 0
                    snd_size = 0

                sock.close()
                tcp_results.append({
                    "ip": ip,
                    "connect_time_ms": connect_time,
                    "recv_buffer": buf_size,
                    "send_buffer": snd_size,
                })
                self._log(f"TCP connect to {ip}:{self.port} - {connect_time}ms", "ok")
                self._log(f"  Recv buffer: {buf_size} bytes, Send buffer: {snd_size} bytes", "info")
            except Exception as e:
                self._log(f"TCP connect to {ip}:{self.port} failed: {e}", "error")

        result["details"]["connections"] = tcp_results

        keep_alive = False
        try:
            r = self.session.head(self.url, timeout=self.timeout, allow_redirects=True)
            keep_alive = 'keep-alive' in r.headers.get('Connection', '').lower()
            result["details"]["keep_alive"] = keep_alive
            self._log(f"Keep-Alive: {'Supported' if keep_alive else 'Not Supported'}", "ok")
        except Exception:
            result["details"]["keep_alive"] = False

        connection_pool = False
        try:
            adapter = self.session.get_adapter(self.url)
            if hasattr(adapter, 'pool_connections') or hasattr(adapter, '_pool'):
                connection_pool = True
        except Exception:
            pass
        result["details"]["connection_pooling"] = connection_pool

        conn_quality = {}
        if tcp_results:
            avg_connect = sum(t["connect_time_ms"] for t in tcp_results) / len(tcp_results)
            min_connect = min(t["connect_time_ms"] for t in tcp_results)
            max_connect = max(t["connect_time_ms"] for t in tcp_results)
            jitter = max_connect - min_connect
            conn_quality = {
                "avg_ms": round(avg_connect, 2),
                "min_ms": round(min_connect, 2),
                "max_ms": round(max_connect, 2),
                "jitter_ms": round(jitter, 2),
                "rating": "excellent" if avg_connect < 50 else "good" if avg_connect < 150 else "fair" if avg_connect < 500 else "poor",
            }
            self._log(f"Connection Quality: {conn_quality['rating']} (avg={avg_connect:.1f}ms, jitter={jitter:.1f}ms)", "ok")
        result["details"]["connection_quality"] = conn_quality

        cc_info = self._detect_tcp_congestion_control()
        result["details"]["congestion_control"] = cc_info

        score = 0
        if tcp_results:
            avg_connect = sum(t["connect_time_ms"] for t in tcp_results) / len(tcp_results)
            if avg_connect < 50: score += 4
            elif avg_connect < 100: score += 3
            elif avg_connect < 300: score += 2
            elif avg_connect < 1000: score += 1
            score += min(len(tcp_results), 3)
        if keep_alive: score += 2
        if connection_pool: score += 1
        if conn_quality and conn_quality.get("jitter_ms", 999) < 10: score += 2
        if cc_info.get("local_cc"): score += 1
        if cc_info.get("remote_rtt_ms", -1) >= 0 and cc_info.get("remote_rtt_ms", 9999) < 100: score += 1
        result["score"] = min(score, 15)
        self.scores["tcp"] = result
        self._log(f"TCP Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def _detect_tcp_congestion_control(self):
        """Detect TCP congestion control: local algorithm + remote RTT/cwnd via TCP_INFO."""
        info = {
            "local_cc": "",
            "available_cc": [],
            "remote_rtt_ms": -1,
            "remote_cwnd": -1,
            "remote_rttvar_ms": -1,
            "tcp_info_supported": False,
        }
        try:
            with open("/proc/sys/net/ipv4/tcp_congestion_control") as f:
                info["local_cc"] = f.read().strip()
        except Exception:
            try:
                proc = subprocess.run(["sysctl", "-n", "net.ipv4.tcp_congestion_control"],
                                      capture_output=True, text=True, timeout=5)
                if proc.returncode == 0:
                    info["local_cc"] = proc.stdout.strip()
            except Exception:
                pass
        try:
            with open("/proc/sys/net/ipv4/tcp_available_congestion_control") as f:
                info["available_cc"] = f.read().strip().split()
        except Exception:
            pass

        target = self.ip_addresses[0] if self.ip_addresses else self.domain
        try:
            sock = socket.create_connection((target, self.port), timeout=self.timeout)
            try:
                tcp_info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 232)
                if len(tcp_info) >= 104:
                    info["tcp_info_supported"] = True
                    info["remote_rtt_ms"] = round(struct.unpack_from("I", tcp_info, 68)[0] / 1000.0, 2)
                    info["remote_rttvar_ms"] = round(struct.unpack_from("I", tcp_info, 72)[0] / 1000.0, 2)
                    info["remote_cwnd"] = struct.unpack_from("I", tcp_info, 80)[0]
                    info["remote_total_retrans"] = struct.unpack_from("I", tcp_info, 100)[0]
            except Exception:
                pass
            sock.close()
        except Exception:
            pass

        if info["local_cc"]:
            avail = ", ".join(info["available_cc"]) if info["available_cc"] else "unknown"
            self._log(f"Local TCP Congestion Control: {info['local_cc']} (available: {avail})", "ok")
        if info["tcp_info_supported"]:
            self._log(f"Remote path RTT: {info['remote_rtt_ms']}ms (+/-{info['remote_rttvar_ms']}ms), cwnd: {info['remote_cwnd']}", "ok")
        return info

    def _ssl_performance_analysis(self, handshake_time_ms):
        """Deep SSL/TLS performance: resumption timing, cert size, cipher strength cost."""
        perf = {
            "full_handshake_ms": handshake_time_ms,
            "resumed_handshake_ms": -1,
            "resumption_gain_pct": 0.0,
            "cert_size_bytes": 0,
            "cert_bits": 0,
            "alpn_set": [],
            "record_overhead_estimate": 0,
            "rating": "unknown",
        }
        if handshake_time_ms <= 0:
            return perf

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((self.domain, self.port), timeout=self.timeout)
            ssock = ctx.wrap_socket(sock, server_hostname=self.domain)
            session = ssock.session
            cert_der = ssock.getpeercert(binary_form=True)
            if cert_der:
                perf["cert_size_bytes"] = len(cert_der)
            perf["cert_bits"] = ssock.cipher()[2] if ssock.cipher() else 0
            try:
                alpn = ssock.selected_alpn_protocol()
                if alpn:
                    perf["alpn_set"] = [alpn]
            except Exception:
                pass
            ssock.close()

            try:
                ctx2 = ssl.create_default_context()
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_NONE
                start = time.time()
                sock2 = socket.create_connection((self.domain, self.port), timeout=self.timeout)
                ssock2 = ctx2.wrap_socket(sock2, server_hostname=self.domain, session=session)
                resumed = round((time.time() - start) * 1000, 2)
                was_resumed = getattr(ssock2, "session_reused", False)
                ssock2.close()
                if was_resumed:
                    perf["resumed_handshake_ms"] = resumed
                    if handshake_time_ms > 0:
                        gain = ((handshake_time_ms - resumed) / handshake_time_ms) * 100
                        perf["resumption_gain_pct"] = round(max(gain, 0.0), 1)
            except Exception:
                pass

            perf["record_overhead_estimate"] = 29
            if handshake_time_ms < 100:
                perf["rating"] = "excellent"
            elif handshake_time_ms < 250:
                perf["rating"] = "good"
            elif handshake_time_ms < 500:
                perf["rating"] = "fair"
            else:
                perf["rating"] = "poor"
        except Exception as e:
            self._log(f"TLS performance probe failed: {e}", "warn")

        self._log(f"TLS Performance: full={perf['full_handshake_ms']}ms, resumed={perf['resumed_handshake_ms']}ms, rating={perf['rating']}", "ok")
        return perf

    def analyze_ssl(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  3. SSL/TLS NETWORK ANALYSIS (DEEP)")
        print(f"{'='*60}{c.END}")
        result = {"category": "ssl", "max_score": 15, "score": 0, "details": {}}

        if self.parsed.scheme != "https":
            self._log("Not HTTPS, skipping SSL analysis", "warn")
            self.scores["ssl"] = result
            return result

        tls_versions = {}
        version_names = {
            ssl.TLSVersion.TLSv1: "TLS 1.0",
            ssl.TLSVersion.TLSv1_1: "TLS 1.1",
            ssl.TLSVersion.TLSv1_2: "TLS 1.2",
            ssl.TLSVersion.TLSv1_3: "TLS 1.3",
        }
        for ver, name in version_names.items():
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    ctx.minimum_version = ver
                    ctx.maximum_version = ver
                except AttributeError:
                    pass
                sock = socket.create_connection((self.domain, self.port), timeout=self.timeout)
                ssock = ctx.wrap_socket(sock, server_hostname=self.domain)
                ssock.close()
                tls_versions[name] = True
                self._log(f"{name}: Supported", "ok")
            except Exception:
                tls_versions[name] = False
                self._log(f"{name}: Not Supported", "info")
        result["details"]["tls_versions"] = tls_versions

        handshake_time = -1
        cipher_info = None
        pfs = False
        session_resumption = False
        alpn_protocols = []
        try:
            start = time.time()
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((self.domain, self.port), timeout=self.timeout)
            ssock = ctx.wrap_socket(sock, server_hostname=self.domain)
            handshake_time = round((time.time() - start) * 1000, 2)
            result["details"]["handshake_time_ms"] = handshake_time
            self._log(f"Handshake Time: {handshake_time}ms", "ok")

            cipher = ssock.cipher()
            if cipher:
                cipher_info = {
                    "name": cipher[0],
                    "protocol": cipher[1],
                    "bits": cipher[2],
                }
                result["details"]["cipher_suite"] = cipher_info
                self._log(f"Cipher: {cipher[0]} ({cipher[2]} bits)", "ok")

                cipher_name = cipher[0].upper()
                pfs_indicators = ['ECDHE', 'DHE']
                pfs = any(ind in cipher_name for ind in pfs_indicators)
                if cipher[1] == "TLSv1.3":
                    pfs = True
            result["details"]["perfect_forward_secrecy"] = pfs
            self._log(f"Perfect Forward Secrecy: {'Yes' if pfs else 'No'}", "ok" if pfs else "warn")

            try:
                alpn = ssock.selected_alpn_protocol()
                if alpn:
                    alpn_protocols.append(alpn)
            except Exception:
                pass
            result["details"]["alpn_protocols"] = alpn_protocols

            ssock.close()

            try:
                ctx2 = ssl.create_default_context()
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_NONE
                sock2 = socket.create_connection((self.domain, self.port), timeout=self.timeout)
                ssock2 = ctx2.wrap_socket(sock2, server_hostname=self.domain)
                session_resumption = (ssock2.session_reused if hasattr(ssock2, 'session_reused') else False)
                ssock2.close()
            except Exception:
                pass
            result["details"]["session_resumption"] = session_resumption
            self._log(f"Session Resumption: {'Supported' if session_resumption else 'Not Supported'}", "ok" if session_resumption else "info")

        except Exception as e:
            self._log(f"SSL connection failed: {e}", "error")
            result["details"]["handshake_time_ms"] = -1

        tls_perf = self._ssl_performance_analysis(handshake_time)
        result["details"]["tls_performance"] = tls_perf

        cert_chain = False
        chain_depth = 0
        try:
            cmd = f"echo | openssl s_client -connect {self.domain}:{self.port} -servername {self.domain} -showcerts 2>/dev/null | grep -c 'BEGIN CERTIFICATE'"
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            chain_depth = int(proc.stdout.strip()) if proc.stdout.strip().isdigit() else 0
            cert_chain = chain_depth > 1
            result["details"]["certificate_chain_complete"] = cert_chain
            result["details"]["chain_depth"] = chain_depth
            self._log(f"Certificate Chain Depth: {chain_depth}", "ok")
        except Exception:
            pass

        ocsp = False
        try:
            cmd = f"echo | openssl s_client -connect {self.domain}:{self.port} -servername {self.domain} -status 2>/dev/null | grep 'OCSP Response Status'"
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            ocsp = "successful" in proc.stdout.lower()
            result["details"]["ocsp_stapling"] = ocsp
            self._log(f"OCSP Stapling: {'Enabled' if ocsp else 'Disabled'}", "ok" if ocsp else "warn")
        except Exception:
            result["details"]["ocsp_stapling"] = False

        cert_details = {}
        try:
            cmd = f"echo | openssl s_client -connect {self.domain}:{self.port} -servername {self.domain} 2>/dev/null | openssl x509 -noout -dates -subject -issuer -serial -fingerprint 2>/dev/null"
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if proc.returncode == 0 and proc.stdout.strip():
                cert_details["raw"] = proc.stdout.strip()
                for line in proc.stdout.strip().split("\n"):
                    if "notBefore" in line:
                        cert_details["not_before"] = line.split("=", 1)[-1].strip()
                    if "notAfter" in line:
                        cert_details["not_after"] = line.split("=", 1)[-1].strip()
                    if "subject" in line.lower():
                        cert_details["subject"] = line.split("=", 1)[-1].strip()
                    if "issuer" in line.lower():
                        cert_details["issuer"] = line.split("=", 1)[-1].strip()
                self._log("Certificate info retrieved via openssl", "ok")
                if cert_details.get("not_after"):
                    self._log(f"  Expires: {cert_details['not_after']}", "info")
                if cert_details.get("issuer"):
                    self._log(f"  Issuer: {cert_details['issuer']}", "info")
        except Exception:
            pass
        result["details"]["certificate"] = cert_details

        hsts = False
        try:
            r = self.session.head(self.url, timeout=self.timeout)
            hsts_header = r.headers.get("Strict-Transport-Security", "")
            hsts = bool(hsts_header)
            result["details"]["hsts"] = hsts
            result["details"]["hsts_header"] = hsts_header
            if hsts:
                self._log(f"HSTS: {hsts_header}", "ok")
            else:
                self._log("HSTS: Not enabled", "warn")
        except Exception:
            result["details"]["hsts"] = False

        score = 0
        if tls_versions.get("TLS 1.3"): score += 3
        elif tls_versions.get("TLS 1.2"): score += 2
        if handshake_time > 0 and handshake_time < 200: score += 2
        elif handshake_time > 0 and handshake_time < 500: score += 1
        if pfs: score += 1
        if cert_chain: score += 1
        if ocsp: score += 1
        if cipher_info and cipher_info.get("bits", 0) >= 256: score += 1
        if session_resumption: score += 1
        if hsts: score += 1
        if not tls_versions.get("TLS 1.0") and not tls_versions.get("TLS 1.1"): score += 1
        if tls_perf.get("resumed_handshake_ms", -1) > 0: score += 1
        result["score"] = min(score, 15)
        self.scores["ssl"] = result
        self._log(f"SSL/TLS Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def _http2_multiplex_analysis(self, http2_supported):
        """Measure HTTP/2 multiplexing benefit: parallel streams vs sequential requests."""
        info = {
            "http2_supported": http2_supported,
            "sequential_ms": -1,
            "parallel_ms": -1,
            "speedup_ratio": 0.0,
            "streams_tested": 6,
            "multiplex_gain_pct": 0.0,
            "rating": "n/a",
        }
        if not http2_supported:
            self._log("HTTP/2 not negotiated, skipping multiplex analysis", "info")
            return info

        n = info["streams_tested"]
        try:
            start = time.time()
            for _ in range(n):
                self.session.get(self.url, timeout=self.timeout)
            info["sequential_ms"] = round((time.time() - start) * 1000, 2)

            start = time.time()
            with ThreadPoolExecutor(max_workers=n) as ex:
                futures = [ex.submit(self.session.get, self.url, timeout=self.timeout) for _ in range(n)]
                for f in as_completed(futures):
                    f.result()
            info["parallel_ms"] = round((time.time() - start) * 1000, 2)

            if info["parallel_ms"] > 0:
                info["speedup_ratio"] = round(info["sequential_ms"] / info["parallel_ms"], 2)
                gain = ((info["sequential_ms"] - info["parallel_ms"]) / info["sequential_ms"]) * 100
                info["multiplex_gain_pct"] = round(max(gain, 0.0), 1)
                if info["speedup_ratio"] >= 3:
                    info["rating"] = "excellent"
                elif info["speedup_ratio"] >= 2:
                    info["rating"] = "good"
                elif info["speedup_ratio"] >= 1.3:
                    info["rating"] = "fair"
                else:
                    info["rating"] = "poor"
            self._log(f"HTTP/2 Multiplex: seq={info['sequential_ms']}ms, par={info['parallel_ms']}ms, speedup={info['speedup_ratio']}x ({info['rating']})", "ok")
        except Exception as e:
            self._log(f"Multiplex analysis failed: {e}", "warn")
        return info

    def _connection_reuse_analysis(self):
        """Measure connection reuse efficiency: first vs subsequent request timing."""
        info = {
            "cold_request_ms": -1,
            "warm_requests_ms": [],
            "warm_avg_ms": -1,
            "reuse_savings_pct": 0.0,
            "keep_alive_hint": "",
            "rating": "unknown",
        }
        try:
            start = time.time()
            self.session.get(self.url, timeout=self.timeout)
            info["cold_request_ms"] = round((time.time() - start) * 1000, 2)

            warm = []
            for _ in range(4):
                start = time.time()
                r = self.session.get(self.url, timeout=self.timeout)
                warm.append(round((time.time() - start) * 1000, 2))
                if not info["keep_alive_hint"]:
                    info["keep_alive_hint"] = r.headers.get("Keep-Alive", "") or r.headers.get("Connection", "")
            info["warm_requests_ms"] = warm
            if warm:
                info["warm_avg_ms"] = round(sum(warm) / len(warm), 2)
            if info["cold_request_ms"] > 0 and info["warm_avg_ms"] >= 0:
                savings = ((info["cold_request_ms"] - info["warm_avg_ms"]) / info["cold_request_ms"]) * 100
                info["reuse_savings_pct"] = round(max(savings, 0.0), 1)
                if info["reuse_savings_pct"] >= 30:
                    info["rating"] = "excellent"
                elif info["reuse_savings_pct"] >= 15:
                    info["rating"] = "good"
                elif info["reuse_savings_pct"] >= 5:
                    info["rating"] = "fair"
                else:
                    info["rating"] = "poor"
            self._log(f"Connection Reuse: cold={info['cold_request_ms']}ms, warm_avg={info['warm_avg_ms']}ms, savings={info['reuse_savings_pct']}% ({info['rating']})", "ok")
        except Exception as e:
            self._log(f"Reuse analysis failed: {e}", "warn")
        return info

    def analyze_http(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  4. HTTP PROTOCOL ANALYSIS (DEEP)")
        print(f"{'='*60}{c.END}")
        result = {"category": "http", "max_score": 15, "score": 0, "details": {}}

        protocols = {}

        if self.parsed.scheme == "https":
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((self.domain, self.port), timeout=self.timeout)
                ssock = ctx.wrap_socket(sock, server_hostname=self.domain)
                proto = ssock.selected_alpn_protocol()
                if proto:
                    protocols["negotiated_protocol"] = proto
                    self._log(f"Negotiated Protocol: {proto}", "ok")
                else:
                    protocols["negotiated_protocol"] = "unknown"
                ssock.close()
            except Exception as e:
                self._log(f"ALPN detection failed: {e}", "error")

        http_version = 0
        server_header = ""
        conn_header = ""
        keep_alive_timeout = ""

        try:
            r = self.session.get(self.url, timeout=self.timeout, allow_redirects=True)
            server_header = r.headers.get("Server", "")
            result["details"]["server_header"] = server_header
            self._log(f"Server: {server_header or 'Not disclosed'}", "ok")

            conn_header = r.headers.get("Connection", "")
            result["details"]["connection_header"] = conn_header

            keep_alive_timeout = r.headers.get("Keep-Alive", "")
            result["details"]["keep_alive_timeout"] = keep_alive_timeout
            if keep_alive_timeout:
                self._log(f"Keep-Alive: {keep_alive_timeout}", "info")

            if hasattr(r.raw, 'version'):
                http_version = r.raw.version
            protocols["http_version"] = http_version
            if http_version:
                ver_str = f"{http_version/10:.1f}"
                self._log(f"HTTP Version: {ver_str}", "ok")
        except Exception as e:
            self._log(f"HTTP request failed: {e}", "error")

        http2_supported = protocols.get("negotiated_protocol") == "h2"
        http3_supported = False

        try:
            r3 = self.session.get(self.url, timeout=self.timeout)
            alt_svc = r3.headers.get("Alt-Svc", "")
            http3_supported = "h3" in alt_svc.lower() or "quic" in alt_svc.lower()
            result["details"]["alt_svc"] = alt_svc
            if http3_supported:
                self._log(f"HTTP/3 (QUIC) Detected via Alt-Svc: {alt_svc}", "ok")
        except Exception:
            pass

        result["details"]["protocols"] = protocols
        result["details"]["http2"] = http2_supported
        result["details"]["http3"] = http3_supported

        upgrade_support = False
        try:
            r = self.session.get(self.url, timeout=self.timeout, headers={"Upgrade": "h2c"})
            upgrade_support = r.status_code in (101, 200)
        except Exception:
            pass
        result["details"]["upgrade_support"] = upgrade_support

        self._log(f"HTTP/2: {'Supported' if http2_supported else 'Not Supported'}", "ok" if http2_supported else "info")
        self._log(f"HTTP/3: {'Supported' if http3_supported else 'Not Supported'}", "ok" if http3_supported else "info")

        multiplex_info = self._http2_multiplex_analysis(http2_supported)
        result["details"]["multiplex_analysis"] = multiplex_info

        reuse_info = self._connection_reuse_analysis()
        result["details"]["connection_reuse"] = reuse_info

        security_headers = {}
        try:
            r = self.session.get(self.url, timeout=self.timeout)
            sec_check = {
                "X-Content-Type-Options": "x_content_type_options",
                "X-Frame-Options": "x_frame_options",
                "X-XSS-Protection": "x_xss_protection",
                "Content-Security-Policy": "content_security_policy",
                "Referrer-Policy": "referrer_policy",
                "Permissions-Policy": "permissions_policy",
                "X-Permitted-Cross-Domain-Policies": "x_permitted_cross_domain",
            }
            for header, key in sec_check.items():
                val = r.headers.get(header, "")
                security_headers[key] = val
                if val:
                    self._log(f"  {header}: {val[:60]}", "ok")
            result["details"]["security_headers"] = security_headers
        except Exception:
            result["details"]["security_headers"] = {}

        score = 0
        if protocols.get("negotiated_protocol") == "h2": score += 3
        elif http_version == 11: score += 2
        elif http_version == 10: score += 1
        if http3_supported: score += 2
        if keep_alive_timeout: score += 1
        if upgrade_support: score += 1
        if protocols.get("negotiated_protocol") in ("h2", "h3"): score += 1
        if conn_header: score += 1
        sec_count = sum(1 for v in security_headers.values() if v)
        if sec_count >= 5: score += 3
        elif sec_count >= 3: score += 2
        elif sec_count >= 1: score += 1
        if multiplex_info.get("speedup_ratio", 0) >= 2: score += 1
        if reuse_info.get("reuse_savings_pct", 0) >= 15: score += 1
        result["score"] = min(score, 15)
        self.scores["http"] = result
        self._log(f"HTTP Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def analyze_cdn(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  5. CDN DETECTION (ENHANCED)")
        print(f"{'='*60}{c.END}")
        result = {"category": "cdn", "max_score": 15, "score": 0, "details": {}}

        cdn_providers = []
        cdn_headers = {}
        cache_status = ""
        edge_location = ""

        try:
            r = self.session.get(self.url, timeout=self.timeout, allow_redirects=True)
            headers = dict(r.headers)

            cdn_headers = {
                "X-CDN": headers.get("X-CDN", ""),
                "X-Cache": headers.get("X-Cache", ""),
                "Via": headers.get("Via", ""),
                "X-Served-By": headers.get("X-Served-By", ""),
                "X-FASTLY-Request-ID": headers.get("X-FASTLY-Request-ID", ""),
                "X-CF-Ray": headers.get("X-CF-Ray", ""),
                "X-Akamai-Transformed": headers.get("X-Akamai-Transformed", ""),
                "X-Edge-Location": headers.get("X-Edge-Location", ""),
                "X-Amz-Cf-Id": headers.get("X-Amz-Cf-Id", ""),
                "X-Cache-Status": headers.get("X-Cache-Status", ""),
                "CF-Cache-Status": headers.get("CF-Cache-Status", ""),
                "X-SH": headers.get("X-SH", ""),
                "X-Varnish": headers.get("X-Varnish", ""),
                "X-CDN-Debug": headers.get("X-CDN-Debug", ""),
                "X-True-Cache-Key": headers.get("X-True-Cache-Key", ""),
                "X-Limelight-Cache-Name": headers.get("X-Limelight-Cache-Name", ""),
                "X-Cache-RS": headers.get("X-Cache-RS", ""),
                "X-Cache-Lookup": headers.get("X-Cache-Lookup", ""),
                "X-Azure-Ref": headers.get("X-Azure-Ref", ""),
                "X-MSEdge-Ref": headers.get("X-MSEdge-Ref", ""),
                "X-Fastly-Debug": headers.get("X-Fastly-Debug", ""),
                "X-HW": headers.get("X-HW", ""),
                "X-Edge-IP": headers.get("X-Edge-IP", ""),
                "X-Orig-Client-IP": headers.get("X-Orig-Client-IP", ""),
            }
            result["details"]["cdn_headers"] = {k: v for k, v in cdn_headers.items() if v}

            for h, v in cdn_headers.items():
                if v:
                    self._log(f"  {h}: {v}", "ok")

            all_headers_str = " ".join(str(v) for v in headers.values()).lower() + " " + " ".join(headers.keys()).lower()
            server_val = headers.get("Server", "").lower()
            all_headers_str += " " + server_val

            provider_checks = [
                ("Cloudflare", ["cloudflare", "cf-ray", "cf-cache"]),
                ("Akamai", ["akamai", "akamaighost"]),
                ("Fastly", ["fastly", "x-fastly"]),
                ("CloudFront", ["cloudfront", "x-amz-cf"]),
                ("StackPath/MaxCDN", ["stackpath", "maxcdn"]),
                ("KeyCDN", ["keycdn"]),
                ("Varnish", ["varnish", "x-varnish"]),
                ("Incapsula/Imperva", ["incapsula", "imperva"]),
                ("Sucuri", ["sucuri"]),
                ("Azure CDN / Front Door", ["azure", "azureedge", "microsoft"]),
                ("Google Cloud CDN", ["google cloud", "gclb"]),
                ("Limelight", ["limelight"]),
                ("Level3/Lumen", ["level3", "lumen"]),
                ("BelugaCDN", ["beluga"]),
                ("Cachefly", ["cachefly"]),
                ("Amazon CloudFront", ["amazons3"]),
                ("Tencent CDN", ["tencent", "tencentcdn"]),
                ("Alibaba CDN", ["alibaba", "alicdn"]),
                ("Bunny CDN", ["bunnycdn", "bunny.net"]),
                ("QUIC.cloud", ["quic.cloud"]),
                ("Netlify", ["netlify"]),
                ("Vercel", ["vercel"]),
                ("GitHub Pages", ["github-pages"]),
                ("Fastly CDN", ["fastly.net"]),
                ("CDN77", ["cdn77"]),
                ("Highwinds", ["highwinds"]),
                ("WordPress.com VIP", ["wpengine", "wordpress"]),
            ]

            for provider, indicators in provider_checks:
                if any(ind in all_headers_str for ind in indicators):
                    cdn_providers.append(provider)

            cdn_providers = list(set(cdn_providers))
            result["details"]["cdn_providers"] = cdn_providers
            if cdn_providers:
                joined = ", ".join(cdn_providers)
                self._log(f"CDN Providers: {joined}", "ok")
            else:
                self._log("No CDN detected", "warn")

            cache_status = headers.get("X-Cache", "") or headers.get("CF-Cache-Status", "") or headers.get("X-Cache-Status", "")
            result["details"]["cache_status"] = cache_status
            if cache_status:
                self._log(f"Cache Status: {cache_status}", "ok")

            edge_location = headers.get("X-Edge-Location", "") or headers.get("X-Azure-Ref", "") or headers.get("X-Served-By", "")
            result["details"]["edge_location"] = edge_location
            if edge_location:
                self._log(f"Edge Location: {edge_location}", "ok")

            origin_ip = ""
            origin_header = headers.get("X-Orig-Client-IP", "") or headers.get("X-Real-IP", "") or headers.get("X-Forwarded-For", "")
            if origin_header:
                origin_ip = origin_header.split(",")[0].strip()
            result["details"]["origin_ip_hint"] = origin_ip
            origin_exposed = not bool(cdn_providers)
            result["details"]["origin_exposed"] = origin_exposed

            cdn_perf = {}
            if cdn_providers:
                perf_start = time.time()
                try:
                    perf_r = self.session.get(self.url, timeout=self.timeout)
                except Exception:
                    pass
                perf_elapsed = round((time.time() - perf_start) * 1000, 2)
                cdn_perf = {
                    "provider": cdn_providers[0] if cdn_providers else "unknown",
                    "cache_hit": cache_status.lower() in ("hit", "true", "yes", "stale") if cache_status else False,
                    "edge_active": bool(edge_location),
                    "response_time_ms": perf_elapsed,
                }
            result["details"]["cdn_performance"] = cdn_perf

        except Exception as e:
            self._log(f"CDN detection failed: {e}", "error")

        score = 0
        if cdn_providers: score += 5
        if cache_status and cache_status.lower() in ("hit", "true", "yes"): score += 3
        elif cache_status: score += 1
        if edge_location: score += 2
        if any(v for v in cdn_headers.values() if v): score += 2
        if not result["details"].get("origin_exposed", True): score += 2
        if len(cdn_providers) >= 2: score += 1
        result["score"] = min(score, 15)
        self.scores["cdn"] = result
        self._log(f"CDN Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def analyze_fingerprint(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  6. SERVER TECHNOLOGY FINGERPRINTING (ENHANCED)")
        print(f"{'='*60}{c.END}")
        result = {"category": "fingerprint", "max_score": 15, "score": 0, "details": {}}

        try:
            r = self.session.get(self.url, timeout=self.timeout, allow_redirects=True)
            headers = dict(r.headers)
            body = r.text[:100000]
            body_lower = body.lower()

            server = headers.get("Server", "")
            result["details"]["server"] = server
            self._log(f"Server: {server or 'Not disclosed'}", "ok")

            powered_by = headers.get("X-Powered-By", "")
            result["details"]["x_powered_by"] = powered_by
            if powered_by:
                self._log(f"X-Powered-By: {powered_by}", "ok")

            os_hints = []
            server_lower = server.lower()
            if "linux" in server_lower or "ubuntu" in server_lower or "debian" in server_lower:
                os_hints.append("Linux")
            if "windows" in server_lower or "iis" in server_lower:
                os_hints.append("Windows")
            if "cloudflare" in server_lower:
                os_hints.append("Cloudflare Edge")
            if "nginx" in server_lower:
                os_hints.append("Nginx")
            if "apache" in server_lower:
                os_hints.append("Apache")
            if "openresty" in server_lower:
                os_hints.append("OpenResty")
            if "litespeed" in server_lower:
                os_hints.append("LiteSpeed")
            if "caddy" in server_lower:
                os_hints.append("Caddy")
            if "gunicorn" in server_lower or "uvicorn" in server_lower or "hypercorn" in server_lower:
                os_hints.append("Python WSGI/ASGI")
            if "node" in server_lower:
                os_hints.append("Node.js")
            if "envoy" in server_lower:
                os_hints.append("Envoy Proxy")
            if "ATS" in server_lower or "trafficserver" in server_lower:
                os_hints.append("Apache Traffic Server")
            result["details"]["os_hints"] = os_hints

            tech_stack = []
            if powered_by:
                pb = powered_by.lower()
                if "php" in pb: tech_stack.append("PHP")
                if "node" in pb: tech_stack.append("Node.js")
                if "python" in pb: tech_stack.append("Python")
                if "asp.net" in pb: tech_stack.append(".NET")
                if "ruby" in pb: tech_stack.append("Ruby")
                if "perl" in pb: tech_stack.append("Perl")
                if "java" in pb: tech_stack.append("Java")

            detections = [
                ("WordPress", ["wp-content", "wp-includes"]),
                ("Drupal", ["drupal", "sites/all/", "sites/default/"]),
                ("Joomla", ["joomla"]),
                ("Shopify", ["shopify", "cdn.shopify.com"]),
                ("Next.js/React", ["react", "_next", "__next"]),
                ("Vue.js/Nuxt", ["vue", "nuxt"]),
                ("Angular", ["angular", "ng-version"]),
                ("Laravel", ["laravel", "csrf-token"]),
                ("Django", ["django", "csrfmiddlewaretoken"]),
                ("Ruby on Rails", ["rails", "csrf-param"]),
                ("Express.js", ["express"]),
                ("Flask", ["flask"]),
                ("FastAPI", ["fastapi"]),
                ("Spring", ["springframework"]),
                ("Gin (Go)", ["gin-gonic"]),
                ("Svelte/SvelteKit", ["svelte"]),
                ("Remix", ["__remix", "remix"]),
                ("Astro", ["astro", "__astro"]),
                ("Hugo", ["hugo", "powered by hugo"]),
                ("Ghost", ["ghost", "ghost-platform"]),
                ("Magento", ["magento"]),
                ("PrestaShop", ["prestashop"]),
                ("WooCommerce", ["woocommerce"]),
                ("Squarespace", ["squarespace"]),
                ("Wix", ["wix", "wixstatic"]),
                ("Webflow", ["webflow"]),
                ("Strapi", ["strapi"]),
                ("Contentful", ["contentful"]),
                ("Sanity", ["sanity.io"]),
                ("Netlify CMS", ["netlify-cms"]),
                ("Craft CMS", ["craftcms"]),
                ("Statamic", ["statamic"]),
                ("October CMS", ["october"]),
                ("Typo3", ["typo3"]),
                ("Blogger", ["blogspot", "blogger"]),
                ("MediaWiki", ["mediawiki"]),
                ("Discourse", ["discourse"]),
                ("phpBB", ["phpbb"]),
                ("Flarum", ["flarum"]),
                ("Laravel Forge", ["forge"]),
                ("cPanel", ["cpanel"]),
                ("Plesk", ["plesk"]),
                ("DirectAdmin", ["directadmin"]),
                ("Vercel", ["vercel", "_vercel"]),
                ("Netlify", ["netlify", "_netlify"]),
                ("Railway", ["railway.app"]),
                ("Render", ["render.com"]),
                ("Fly.io", ["fly.dev"]),
                ("Deno", ["deno"]),
                ("Bun", ["bun.sh"]),
            ]

            for name, indicators in detections:
                if any(ind in body_lower for ind in indicators):
                    tech_stack.append(name)

            js_libs = [
                ("jQuery", ["jquery"]),
                ("Lodash", ["lodash"]),
                ("Moment.js", ["moment"]),
                ("Day.js", ["dayjs"]),
                ("Axios", ["axios"]),
                ("GSAP", ["gsap"]),
                ("Three.js", ["three.js", "three.min"]),
                ("D3.js", ["d3.js", "d3.min"]),
                ("Chart.js", ["chart.js"]),
                ("Socket.io", ["socket.io"]),
                ("Webpack", ["webpack"]),
                ("Vite", ["vite"]),
                ("Bootstrap", ["bootstrap"]),
                ("Tailwind CSS", ["tailwindcss", "tailwind"]),
                ("Material UI", ["material-ui", "@mui"]),
                ("Ant Design", ["antd", "ant-design"]),
                ("Chakra UI", ["chakra-ui"]),
                ("Alpine.js", ["alpine.js", "alpinejs"]),
                ("Stimulus", ["stimulus", "data-controller"]),
                ("htmx", ["htmx.org", "hx-get"]),
            ]
            for name, indicators in js_libs:
                if any(ind in body_lower for ind in indicators):
                    tech_stack.append(name)

            meta_gen = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)', body)
            if meta_gen:
                gen_val = meta_gen.group(1).strip()
                if gen_val and gen_val not in tech_stack:
                    tech_stack.append(f"Generator:{gen_val}")

            tech_stack = list(set(tech_stack))
            result["details"]["tech_stack"] = tech_stack

            cms_words = {"WordPress", "Drupal", "Joomla", "Shopify", "Magento", "PrestaShop", "WooCommerce", "Ghost", "Squarespace", "Wix", "Webflow", "Hugo", "Craft CMS", "Statamic", "October CMS", "Typo3", "Blogger", "MediaWiki"}
            cms = [t for t in tech_stack if t in cms_words]
            result["details"]["cms"] = cms

            framework_words = {"Laravel", "Django", "Ruby on Rails", "Express.js", "Flask", "FastAPI", "Spring", "Gin (Go)", "Next.js/React", "Vue.js/Nuxt", "Angular", "Svelte/SvelteKit", "Remix", "Astro"}
            frameworks = [t for t in tech_stack if t in framework_words]
            result["details"]["frameworks"] = frameworks

            hosting_words = {"Netlify", "Vercel", "Cloudflare", "Railway", "Render", "Fly.io", "GitHub Pages", "WordPress.com VIP"}
            hosting = [t for t in tech_stack if t in hosting_words]
            result["details"]["hosting"] = hosting

            if tech_stack:
                ts_preview = ", ".join(tech_stack[:15])
                self._log(f"Technology Stack ({len(tech_stack)}): {ts_preview}", "ok")
            if cms:
                self._log(f"CMS: {', '.join(cms)}", "ok")
            if frameworks:
                self._log(f"Frameworks: {', '.join(frameworks)}", "ok")
            if hosting:
                self._log(f"Hosting: {', '.join(hosting)}", "ok")
            if os_hints:
                self._log(f"Server/OS Hints: {', '.join(os_hints)}", "ok")

        except Exception as e:
            self._log(f"Fingerprinting failed: {e}", "error")

        score = 0
        if result["details"].get("server"): score += 2
        if result["details"].get("x_powered_by"): score += 1
        if result["details"].get("tech_stack"): score += 4
        if result["details"].get("cms"): score += 2
        if result["details"].get("frameworks"): score += 2
        if result["details"].get("os_hints"): score += 1
        if result["details"].get("hosting"): score += 2
        if len(result["details"].get("tech_stack", [])) >= 5: score += 1
        result["score"] = min(score, 15)
        self.scores["fingerprint"] = result
        self._log(f"Fingerprint Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def analyze_latency(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  7. LATENCY & ROUTING (ENHANCED)")
        print(f"{'='*60}{c.END}")
        result = {"category": "latency", "max_score": 15, "score": 0, "details": {}}

        target_ip = self.ip_addresses[0] if self.ip_addresses else self.domain

        ping_results = []
        try:
            proc = subprocess.run(
                ["ping", "-c", "5", "-W", str(self.timeout), target_ip],
                capture_output=True, text=True, timeout=self.timeout + 5
            )
            if proc.returncode == 0:
                for line in proc.stdout.strip().split("\n"):
                    if "time=" in line:
                        try:
                            time_val = line.split("time=")[1].split(" ")[0]
                            ping_results.append(float(time_val))
                        except (ValueError, IndexError):
                            pass
                if ping_results:
                    avg_ping = sum(ping_results) / len(ping_results)
                    jitter = 0
                    if len(ping_results) > 1:
                        jitter = max(ping_results) - min(ping_results)
                    result["details"]["ping_avg_ms"] = round(avg_ping, 2)
                    result["details"]["ping_min_ms"] = min(ping_results)
                    result["details"]["ping_max_ms"] = max(ping_results)
                    result["details"]["ping_jitter_ms"] = round(jitter, 2)
                    self._log(f"Ping to {target_ip}: avg={avg_ping:.2f}ms, min={min(ping_results):.2f}ms, max={max(ping_results):.2f}ms", "ok")
                    self._log(f"  Jitter: {jitter:.2f}ms", "info")
            else:
                self._log("Ping failed or not available", "warn")
        except Exception as e:
            self._log(f"Ping error: {e}", "error")

        traceroute_results = []
        try:
            proc = subprocess.run(
                ["traceroute", "-m", "15", "-w", "2", target_ip],
                capture_output=True, text=True, timeout=30
            )
            if proc.returncode == 0:
                lines = proc.stdout.strip().split("\n")[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        hop_num = parts[0].strip()
                        hop_ip = parts[1].strip() if len(parts) > 1 else "*"
                        latency = parts[-1].strip() if len(parts) > 2 else "*"
                        traceroute_results.append({
                            "hop": hop_num,
                            "ip": hop_ip,
                            "latency": latency,
                        })
                result["details"]["traceroute_hops"] = len(traceroute_results)
                result["details"]["traceroute"] = traceroute_results[:15]
                self._log(f"Traceroute: {len(traceroute_results)} hops to {target_ip}", "ok")
                for hop in traceroute_results[:5]:
                    self._log(f"  Hop {hop['hop']}: {hop['ip']} ({hop['latency']})", "info")
                if len(traceroute_results) > 5:
                    more = len(traceroute_results) - 5
                    self._log(f"  ... and {more} more hops", "info")
            else:
                self._log("Traceroute failed or not available", "warn")
        except Exception as e:
            self._log(f"Traceroute error: {e}", "error")

        geo_info = {}
        try:
            r = self.session.get(f"https://ipinfo.io/{target_ip}/json", timeout=5)
            if r.status_code == 200:
                geo_info = r.json()
                result["details"]["geolocation"] = {
                    "city": geo_info.get("city", "Unknown"),
                    "region": geo_info.get("region", "Unknown"),
                    "country": geo_info.get("country", "Unknown"),
                    "org": geo_info.get("org", "Unknown"),
                    "loc": geo_info.get("loc", "Unknown"),
                    "timezone": geo_info.get("timezone", "Unknown"),
                    "postal": geo_info.get("postal", "Unknown"),
                }
                self._log(f"Location: {geo_info.get('city', 'Unknown')}, {geo_info.get('region', 'Unknown')}, {geo_info.get('country', 'Unknown')}", "ok")
                self._log(f"Organization: {geo_info.get('org', 'Unknown')}", "ok")
                if geo_info.get("timezone"):
                    self._log(f"Timezone: {geo_info['timezone']}", "info")
        except Exception:
            self._log("Geolocation lookup failed", "warn")

        as_info = geo_info.get("org", "")
        result["details"]["asn"] = as_info
        if as_info:
            self._log(f"ASN: {as_info}", "ok")

        path_analysis = {}
        if traceroute_results:
            private_hops = 0
            timeout_hops = 0
            for hop in traceroute_results:
                hip = hop.get("ip", "*")
                if hip == "*" or "ms" not in str(hop.get("latency", "*")):
                    timeout_hops += 1
                elif hip.startswith("10.") or hip.startswith("172.") or hip.startswith("192.168."):
                    private_hops += 1
            path_analysis = {
                "total_hops": len(traceroute_results),
                "timeout_hops": timeout_hops,
                "private_hops": private_hops,
                "loss_pct": round((timeout_hops / max(len(traceroute_results), 1)) * 100, 1),
            }
            self._log(f"Path Analysis: {path_analysis['total_hops']} hops, {path_analysis['loss_pct']}% loss", "ok")
        result["details"]["path_analysis"] = path_analysis

        score = 0
        if ping_results:
            avg_ping = sum(ping_results) / len(ping_results)
            if avg_ping < 10: score += 3
            elif avg_ping < 30: score += 2
            elif avg_ping < 100: score += 1
        if traceroute_results: score += 2
        if geo_info.get("city"): score += 2
        if geo_info.get("org"): score += 1
        if len(traceroute_results) < 15: score += 1
        if traceroute_results and any("*" not in str(h.get("latency", "*")) for h in traceroute_results[:5]): score += 1
        if ping_results and len(ping_results) > 1:
            jitter = max(ping_results) - min(ping_results)
            if jitter < 5: score += 2
            elif jitter < 20: score += 1
        if path_analysis and path_analysis.get("loss_pct", 100) < 5: score += 1
        if path_analysis and path_analysis.get("total_hops", 30) < 15: score += 1
        result["score"] = min(score, 15)
        self.scores["latency"] = result
        self._log(f"Latency Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def analyze_bandwidth(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  8. BANDWIDTH ESTIMATION")
        print(f"{'='*60}{c.END}")
        result = {"category": "bandwidth", "max_score": 5, "score": 0, "details": {}}

        ttfb = -1
        ttlb = -1

        try:
            start = time.time()
            r = self.session.get(self.url, timeout=self.timeout, stream=True)
            ttfb = round((time.time() - start) * 1000, 2)
            result["details"]["ttfb_ms"] = ttfb
            self._log(f"Time to First Byte (TTFB): {ttfb}ms", "ok")

            start_dl = time.time()
            content = b""
            for chunk in r.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > 512 * 1024:
                    break
            download_time = round((time.time() - start_dl) * 1000, 2)
            download_size = len(content)
            ttlb = round(ttfb + download_time, 2)
            result["details"]["ttlb_ms"] = ttlb
            result["details"]["download_size_bytes"] = download_size

            if download_time > 0:
                speed_bps = (download_size * 8) / (download_time / 1000)
                speed_mbps = speed_bps / 1_000_000
                result["details"]["download_speed_mbps"] = round(speed_mbps, 2)
                self._log(f"Download Speed: {speed_mbps:.2f} Mbps ({download_size} bytes in {download_time}ms)", "ok")
            else:
                self._log("Download speed too fast to measure", "info")

        except Exception as e:
            self._log(f"Bandwidth test failed: {e}", "error")

        ttfb_consistent = False
        try:
            ttfb_times = []
            for _ in range(3):
                start = time.time()
                r = self.session.get(self.url, timeout=self.timeout)
                elapsed = (time.time() - start) * 1000
                ttfb_times.append(elapsed)
            if ttfb_times:
                avg = sum(ttfb_times) / len(ttfb_times)
                std_dev = (sum((t - avg) ** 2 for t in ttfb_times) / len(ttfb_times)) ** 0.5
                ttfb_consistent = std_dev < avg * 0.3
                result["details"]["ttfb_times"] = [round(t, 2) for t in ttfb_times]
                result["details"]["consistency"] = "Consistent" if ttfb_consistent else "Inconsistent"
                self._log(f"TTFB Consistency: {result['details']['consistency']} (std dev: {std_dev:.2f}ms)", "ok")
        except Exception:
            pass

        score = 0
        if ttfb > 0:
            if ttfb < 200: score += 2
            elif ttfb < 500: score += 1
        if result["details"].get("download_speed_mbps", 0) > 10: score += 2
        elif result["details"].get("download_speed_mbps", 0) > 1: score += 1
        if ttfb_consistent: score += 1
        result["score"] = min(score, 5)
        self.scores["bandwidth"] = result
        self._log(f"Bandwidth Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def analyze_netsec(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  9. NETWORK SECURITY (ENHANCED)")
        print(f"{'='*60}{c.END}")
        result = {"category": "netsec", "max_score": 15, "score": 0, "details": {}}

        target_ip = self.ip_addresses[0] if self.ip_addresses else self.domain
        common_ports = {
            80: "HTTP", 443: "HTTPS", 21: "FTP", 22: "SSH", 25: "SMTP",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 3306: "MySQL", 5432: "PostgreSQL",
            6379: "Redis", 27017: "MongoDB", 3389: "RDP", 110: "POP3",
            143: "IMAP", 993: "IMAPS", 995: "POP3S", 53: "DNS", 587: "SMTP-Submission",
            8000: "Dev-Server", 8888: "Jupyter", 9200: "Elasticsearch",
            2375: "Docker", 6443: "Kubernetes", 10250: "Kubelet",
        }

        open_ports = []

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result_code = sock.connect_ex((target_ip, port))
                sock.close()
                return port, result_code == 0
            except Exception:
                return port, False

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(scan_port, port): port for port in common_ports}
            for future in as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)
                    self._log(f"Port {port} ({common_ports.get(port, 'Unknown')}): OPEN", "ok")

        result["details"]["open_ports"] = open_ports
        result["details"]["open_port_count"] = len(open_ports)
        self._log(f"Open Ports: {len(open_ports)} found", "info")

        banners = {}
        for port in open_ports[:5]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((target_ip, port))
                sock.send(b"HEAD / HTTP/1.0\r\nHost: " + self.domain.encode() + b"\r\n\r\n")
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                sock.close()
                if banner:
                    banners[port] = banner[:200]
                    self._log(f"Banner on port {port}: {banner[:80]}", "info")
            except Exception:
                pass
        result["details"]["banners"] = banners

        dns_hijack = False
        try:
            real_ips = socket.getaddrinfo(self.domain, None)
            real_ip = real_ips[0][4][0]
            if HAS_DNSPYTHON:
                try:
                    fake_resolver = dns.resolver.Resolver()
                    fake_resolver.nameservers = ["8.8.8.8"]
                    fake_answers = fake_resolver.resolve(self.domain, "A")
                    google_ip = str(list(fake_answers)[0])
                    if real_ip != google_ip:
                        dns_hijack = True
                except Exception:
                    pass
        except Exception:
            pass
        result["details"]["dns_hijack_detected"] = dns_hijack
        if dns_hijack:
            self._log("Potential DNS hijacking detected!", "warn")
        else:
            self._log("No DNS hijacking detected", "ok")

        reverse_dns = ""
        try:
            reverse_dns = socket.gethostbyaddr(target_ip)[0]
            result["details"]["reverse_dns"] = reverse_dns
            self._log(f"Reverse DNS: {reverse_dns}", "ok")
        except Exception:
            self._log("Reverse DNS: Not available", "info")

        risk_assessment = {}
        dangerous_ports = [21, 25, 3306, 5432, 6379, 27017, 3389, 2375, 8888, 10250]
        open_dangerous = [p for p in open_ports if p in dangerous_ports]
        risk_score = 0
        risk_score += len(open_dangerous) * 2
        if dns_hijack: risk_score += 3
        if not reverse_dns: risk_score += 1
        if 3389 in open_ports: risk_score += 2
        if 2375 in open_ports: risk_score += 3
        if 27017 in open_ports: risk_score += 2
        if 6379 in open_ports: risk_score += 2
        risk_level = "low" if risk_score <= 2 else "medium" if risk_score <= 5 else "high"
        risk_assessment = {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "dangerous_open": open_dangerous,
            "recommendations": [],
        }
        if open_dangerous:
            risk_assessment["recommendations"].append(f"Close or restrict access to ports: {open_dangerous}")
        if dns_hijack:
            risk_assessment["recommendations"].append("Investigate potential DNS hijacking")
        if 3389 in open_ports:
            risk_assessment["recommendations"].append("RDP port 3389 exposed - consider VPN or restricting access")
        if 2375 in open_ports:
            risk_assessment["recommendations"].append("Docker API port 2375 exposed - CRITICAL security risk")
        result["details"]["risk_assessment"] = risk_assessment
        self._log(f"Risk Level: {risk_level.upper()} (score={risk_score})", "ok" if risk_level == "low" else "warn")

        score = 0
        if len(open_ports) <= 3: score += 3
        elif len(open_ports) <= 5: score += 2
        elif len(open_ports) <= 8: score += 1
        if not dns_hijack: score += 2
        if reverse_dns: score += 1
        if 443 in open_ports: score += 1
        if 80 in open_ports: score += 1
        if not any(p in open_ports for p in dangerous_ports): score += 2
        if risk_level == "low": score += 2
        elif risk_level == "medium": score += 1
        if not 2375 in open_ports and not 6379 in open_ports: score += 1
        result["score"] = min(score, 15)
        self.scores["netsec"] = result
        self._log(f"Network Security Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def analyze_protocols(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  10. PROTOCOL SUPPORT")
        print(f"{'='*60}{c.END}")
        result = {"category": "protocols", "max_score": 5, "score": 0, "details": {}}

        protocols = {}

        ws_url = f"wss://{self.domain}" if self.parsed.scheme == "https" else f"ws://{self.domain}"
        try:
            sock = socket.create_connection((self.domain, self.port), timeout=3)
            upgrade_req = (
                "GET / HTTP/1.1\r\n"
                f"Host: {self.domain}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "\r\n"
            )
            sock.send(upgrade_req.encode())
            response = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()
            protocols["websocket"] = "101" in response or "switching" in response.lower()
            if protocols["websocket"]:
                self._log("WebSocket (wss://): Supported", "ok")
            else:
                self._log("WebSocket (wss://): Not Supported", "info")
        except Exception:
            protocols["websocket"] = False
            self._log("WebSocket (wss://): Not Supported", "info")

        ftp_support = False
        try:
            sock = socket.create_connection((self.domain, 21), timeout=3)
            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()
            ftp_support = "ftp" in banner.lower() or "220" in banner
            protocols["ftp"] = ftp_support
            if ftp_support:
                self._log(f"FTP: Supported ({banner.strip()[:50]})", "ok")
        except Exception:
            protocols["ftp"] = False
            self._log("FTP: Not Supported", "info")

        smtp_support = False
        try:
            sock = socket.create_connection((self.domain, 25), timeout=3)
            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()
            smtp_support = "smtp" in banner.lower() or "220" in banner
            protocols["smtp"] = smtp_support
            if smtp_support:
                self._log(f"SMTP: Supported ({banner.strip()[:50]})", "ok")
        except Exception:
            protocols["smtp"] = False
            self._log("SMTP: Not Supported", "info")

        ssh_support = False
        try:
            sock = socket.create_connection((self.domain, 22), timeout=3)
            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()
            ssh_support = "ssh" in banner.lower()
            protocols["ssh"] = ssh_support
            if ssh_support:
                self._log(f"SSH: Supported ({banner.strip()[:50]})", "ok")
        except Exception:
            protocols["ssh"] = False
            self._log("SSH: Not Supported", "info")

        grpc_support = False
        try:
            r = self.session.post(
                f"https://{self.domain}",
                timeout=3,
                headers={"Content-Type": "application/grpc-web+proto", "TE": "trailers"},
            )
            grpc_support = r.status_code in (200, 415, 500)
            protocols["grpc"] = grpc_support
            if grpc_support:
                self._log("gRPC: Likely Supported", "ok")
        except Exception:
            protocols["grpc"] = False
            self._log("gRPC: Not Detected", "info")

        result["details"]["protocols"] = protocols

        score = 0
        if protocols.get("websocket"): score += 1
        if protocols.get("ftp"): score += 1
        if protocols.get("smtp"): score += 1
        if protocols.get("ssh"): score += 1
        if protocols.get("grpc"): score += 1
        result["score"] = min(score, 5)
        self.scores["protocols"] = result
        self._log(f"Protocol Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def analyze_ipv6(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  11. IPV6 CONNECTIVITY ANALYSIS")
        print(f"{'='*60}{c.END}")
        result = {"category": "ipv6", "max_score": 10, "score": 0, "details": {}}
        details = result["details"]

        details["local_ipv6_stack"] = bool(socket.has_ipv6)
        if not socket.has_ipv6:
            self._log("Local host has no IPv6 stack", "warn")
            self.scores["ipv6"] = result
            return result
        self._log("Local IPv6 stack: available", "ok")

        aaaa = self._resolve_dns("AAAA")
        details["aaaa_records"] = aaaa
        if not aaaa:
            self._log("No AAAA records - target does not publish IPv6", "warn")
            self.scores["ipv6"] = result
            return result
        joined = ", ".join(aaaa)
        self._log(f"AAAA records: {joined}", "ok")

        ipv6_addr = aaaa[0].split("%")[0]
        try:
            parsed_ip = ipaddress.ip_address(ipv6_addr)
            details["address_class"] = str(parsed_ip)
            details["is_global"] = parsed_ip.is_global
            details["is_private"] = parsed_ip.is_private
            details["is_reserved"] = parsed_ip.is_reserved
            cls = "global unicast" if parsed_ip.is_global else "non-global"
            self._log(f"Address class: {cls}", "ok")
        except ValueError:
            details["is_global"] = False

        connect_ms = -1
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ipv6_addr, self.port, 0, 0))
            connect_ms = round((time.time() - start) * 1000, 2)
            sock.close()
            details["ipv6_connect_ms"] = connect_ms
            self._log(f"IPv6 TCP connect to {ipv6_addr}:{self.port} - {connect_ms}ms", "ok")
        except Exception as e:
            details["ipv6_connect_ms"] = -1
            self._log(f"IPv6 TCP connect failed: {e}", "error")

        ping6 = []
        try:
            proc = subprocess.run(
                ["ping", "-6", "-c", "5", "-W", str(self.timeout), ipv6_addr],
                capture_output=True, text=True, timeout=self.timeout + 5
            )
            for line in proc.stdout.splitlines():
                if "time=" in line:
                    try:
                        ping6.append(float(line.split("time=")[1].split(" ")[0]))
                    except (ValueError, IndexError):
                        pass
        except Exception:
            pass
        avg6 = round(sum(ping6) / len(ping6), 2) if ping6 else -1
        details["ipv6_ping_avg_ms"] = avg6
        if avg6 >= 0:
            self._log(f"IPv6 ping avg: {avg6}ms", "ok")

        avg4 = None
        try:
            v4_ip = self.ip_addresses[0] if self.ip_addresses else self.domain
            proc = subprocess.run(
                ["ping", "-4", "-c", "5", "-W", str(self.timeout), v4_ip],
                capture_output=True, text=True, timeout=self.timeout + 5
            )
            v4s = []
            for line in proc.stdout.splitlines():
                if "time=" in line:
                    try:
                        v4s.append(float(line.split("time=")[1].split(" ")[0]))
                    except (ValueError, IndexError):
                        pass
            if v4s:
                avg4 = round(sum(v4s) / len(v4s), 2)
                details["ipv4_ping_avg_ms"] = avg4
        except Exception:
            pass

        happy_eyeballs_ok = False
        if avg6 >= 0 and avg4 is not None and avg4 > 0:
            ratio = round(avg6 / avg4, 2)
            details["v6_v4_latency_ratio"] = ratio
            happy_eyeballs_ok = ratio <= 1.5
            self._log(f"IPv6/IPv4 latency ratio: {ratio} ({'IPv6 competitive' if happy_eyeballs_ok else 'IPv6 slower'})", "ok" if happy_eyeballs_ok else "warn")

        dual_stack = bool(aaaa and self.ip_addresses)
        details["dual_stack"] = dual_stack
        if dual_stack:
            self._log("Dual-stack (A + AAAA): yes", "ok")

        score = 0
        if aaaa: score += 2
        if details.get("is_global"): score += 1
        if details.get("ipv6_connect_ms", -1) >= 0: score += 3
        if avg6 >= 0: score += 2
        if dual_stack: score += 1
        if happy_eyeballs_ok: score += 1
        result["score"] = min(score, 10)
        self.scores["ipv6"] = result
        self._log(f"IPv6 Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def _ripe_get(self, endpoint, params):
        try:
            url = f"https://stat.ripe.net/data/{endpoint}/data.json"
            r = self.session.get(url, params=params, timeout=10)
            if r.status_code == 200:
                return r.json().get("data", {})
            return {}
        except Exception:
            return {}

    def analyze_routing(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  12. BGP ROUTING ANALYSIS")
        print(f"{'='*60}{c.END}")
        result = {"category": "routing", "max_score": 10, "score": 0, "details": {}}
        details = result["details"]

        target_ip = self.ip_addresses[0] if self.ip_addresses else ""
        if not target_ip:
            self._log("No target IP for BGP lookup", "warn")
            self.scores["routing"] = result
            return result

        self._log(f"Querying RIPE Stat for {target_ip} ...", "info")

        net_info = self._ripe_get("network-info", {"resource": target_ip})
        asns = [str(a) for a in net_info.get("asns", [])]
        prefix = net_info.get("prefix", "")
        details["origin_asns"] = asns
        details["announced_prefix"] = prefix
        if asns:
            joined = ", ".join("AS" + a for a in asns)
            self._log(f"Origin ASN: {joined}", "ok")
        if prefix:
            self._log(f"Announced prefix: {prefix}", "ok")

        asn_name = ""
        rpki_state = "unknown"
        if asns:
            asnum = asns[0]
            as_overview = self._ripe_get("as-overview", {"resource": "AS" + asnum})
            asn_name = as_overview.get("holder", "")
            details["asn_name"] = asn_name
            if asn_name:
                self._log(f"ASN holder: {asn_name}", "ok")

            rpki_data = self._ripe_get("rpki-validation", {"resource": target_ip, "prefix": prefix})
            rpki_state = str(rpki_data.get("state", "unknown"))
            details["rpki_state"] = rpki_state
            details["rpki_validated"] = rpki_state.lower() in ("valid", "ok")
            self._log(f"RPKI validation: {rpki_state}", "ok" if rpki_state.lower() in ("valid", "ok") else "warn")

            announced = self._ripe_get("announced-prefixes", {"resource": "AS" + asnum})
            prefixes = [p.get("prefix", "") for p in announced.get("prefixes", [])]
            details["asn_prefix_count"] = len(prefixes)
            details["asn_prefixes_sample"] = prefixes[:10]
            self._log(f"Prefixes announced by origin AS: {len(prefixes)}", "ok")

        bgp_state = self._ripe_get("bgp-state", {"resource": target_ip})
        visibility = bgp_state.get("source_id", "")
        details["bgp_state_source"] = visibility
        routes = bgp_state.get("bgp_state", [])
        details["bgp_peer_count"] = len(routes) if isinstance(routes, list) else 0
        if isinstance(routes, list) and routes:
            self._log(f"BGP table entries visible: {len(routes)}", "ok")

        whois_data = self._ripe_get("whois", {"resource": target_ip})
        raw_items = whois_data.get("records", {})
        country = ""
        if isinstance(raw_items, dict):
            for block in raw_items.values():
                if isinstance(block, list):
                    for item in block:
                        if str(item.get("key", "")).lower() == "country":
                            country = str(item.get("value", ""))
                            break
                if country:
                    break
        details["registry_country"] = country
        if country:
            self._log(f"Registry country: {country}", "ok")

        path_hops = self.scores.get("latency", {}).get("details", {}).get("traceroute_hops", 0)
        details["path_hops"] = path_hops

        score = 0
        if asns: score += 3
        if prefix: score += 2
        if details.get("rpki_validated"): score += 2
        elif rpki_state.lower() in ("not-found", "unknown"): score += 1
        if details.get("asn_name"): score += 1
        if details.get("bgp_peer_count", 0) > 0: score += 1
        if path_hops and path_hops < 20: score += 1
        result["score"] = min(score, 10)
        self.scores["routing"] = result
        self._log(f"Routing Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def _collect_ping_samples(self, count=20):
        """Run a ping burst and return RTT samples + loss percentage."""
        target = self.ip_addresses[0] if self.ip_addresses else self.domain
        rtts = []
        loss_pct = 100.0
        try:
            proc = subprocess.run(
                ["ping", "-c", str(count), "-i", "0.2", "-W", "2", target],
                capture_output=True, text=True, timeout=count * 0.5 + 10
            )
            out = proc.stdout
            for line in out.splitlines():
                if "time=" in line:
                    try:
                        rtts.append(float(line.split("time=")[1].split(" ")[0]))
                    except (ValueError, IndexError):
                        pass
            m = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
            if m:
                loss_pct = float(m.group(1))
            elif count > 0:
                loss_pct = round(((count - len(rtts)) / count) * 100, 1)
        except Exception:
            pass
        return rtts, loss_pct

    def analyze_congestion(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  13. CONGESTION, PACKET LOSS & JITTER ANALYSIS")
        print(f"{'='*60}{c.END}")
        result = {"category": "congestion", "max_score": 15, "score": 0, "details": {}}
        details = result["details"]

        self._log("Collecting ping samples for loss/jitter/congestion...", "info")
        rtts, loss_pct = self._collect_ping_samples(20)
        details["ping_samples"] = len(rtts)
        details["packet_loss_pct"] = loss_pct

        if rtts:
            avg_rtt = sum(rtts) / len(rtts)
            min_rtt = min(rtts)
            max_rtt = max(rtts)
            variance = sum((x - avg_rtt) ** 2 for x in rtts) / len(rtts)
            stddev = variance ** 0.5

            # RFC 3550-style smoothed jitter: mean of |RTT[i] - RTT[i-1]|
            diffs = [abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))]
            raw_jitter = sum(diffs) / len(diffs) if diffs else 0.0
            smoothed = 0.0
            if diffs:
                for d in diffs:
                    smoothed += (d - smoothed) / 16.0

            details["rtt_avg_ms"] = round(avg_rtt, 2)
            details["rtt_min_ms"] = round(min_rtt, 2)
            details["rtt_max_ms"] = round(max_rtt, 2)
            details["rtt_stddev_ms"] = round(stddev, 2)
            details["jitter_mean_abs_ms"] = round(raw_jitter, 2)
            details["jitter_smoothed_ms"] = round(smoothed, 2)
            self._log(f"RTT avg={avg_rtt:.2f}ms stddev={stddev:.2f}ms", "ok")
            self._log(f"Jitter (mean-abs)={raw_jitter:.2f}ms, smoothed={smoothed:.2f}ms", "ok")
        else:
            self._log("No RTT samples collected - congestion analysis limited", "warn")

        latency_data = self.scores.get("latency", {}).get("details", {})
        path_analysis = latency_data.get("path_analysis", {})
        hop_loss = path_analysis.get("loss_pct", 0) or 0
        details["path_hop_loss_pct"] = hop_loss

        conn_quality = self.scores.get("tcp", {}).get("details", {}).get("connection_quality", {})
        conn_jitter = conn_quality.get("jitter_ms", 0) or 0
        details["connect_jitter_ms"] = conn_jitter

        tcp_cc = self.scores.get("tcp", {}).get("details", {}).get("congestion_control", {})
        details["rtt_variance_remote_ms"] = tcp_cc.get("remote_rttvar_ms", -1)
        details["remote_retrans"] = tcp_cc.get("remote_total_retrans", -1)

        # Congestion score combining signals 0..100 where 100 = clean
        signals = []
        loss = details.get("packet_loss_pct", 100)
        if loss <= 0:
            signals.append(100)
        elif loss < 1:
            signals.append(80)
        elif loss < 3:
            signals.append(55)
        elif loss < 10:
            signals.append(30)
        else:
            signals.append(10)

        jit = details.get("jitter_mean_abs_ms", 50)
        if jit < 2:
            signals.append(100)
        elif jit < 5:
            signals.append(80)
        elif jit < 15:
            signals.append(55)
        elif jit < 40:
            signals.append(30)
        else:
            signals.append(10)

        if details.get("rtt_avg_ms") is not None and details.get("rtt_stddev_ms") is not None and details.get("rtt_avg_ms") > 0:
            cv = details["rtt_stddev_ms"] / details["rtt_avg_ms"]
            details["rtt_cv"] = round(cv, 3)
            if cv < 0.1:
                signals.append(100)
            elif cv < 0.25:
                signals.append(70)
            elif cv < 0.5:
                signals.append(45)
            else:
                signals.append(15)
        else:
            details["rtt_cv"] = -1

        if hop_loss < 5:
            signals.append(90)
        elif hop_loss < 15:
            signals.append(50)
        else:
            signals.append(20)

        congestion_index = round(sum(signals) / len(signals), 1) if signals else 0
        details["congestion_index"] = congestion_index
        if congestion_index >= 85:
            level = "clear"
        elif congestion_index >= 65:
            level = "light"
        elif congestion_index >= 40:
            level = "moderate"
        else:
            level = "severe"
        details["congestion_level"] = level
        self._log(f"Congestion index: {congestion_index}/100 ({level})", "ok" if level == "clear" else "warn")

        # Packet-loss rating
        if loss_pct <= 0:
            loss_rating = "excellent"
        elif loss_pct < 1:
            loss_rating = "good"
        elif loss_pct < 3:
            loss_rating = "fair"
        else:
            loss_rating = "poor"
        details["loss_rating"] = loss_rating

        # Jitter rating
        jit_val = details.get("jitter_mean_abs_ms", -1)
        if jit_val < 0:
            jitter_rating = "unknown"
        elif jit_val < 2:
            jitter_rating = "excellent"
        elif jit_val < 5:
            jitter_rating = "good"
        elif jit_val < 15:
            jitter_rating = "fair"
        else:
            jitter_rating = "poor"
        details["jitter_rating"] = jitter_rating
        self._log(f"Loss rating: {loss_rating} ({loss_pct}%) | Jitter rating: {jitter_rating}", "ok")

        score = 0
        if loss_pct <= 0: score += 4
        elif loss_pct < 1: score += 3
        elif loss_pct < 3: score += 2
        elif loss_pct < 10: score += 1
        if jit_val >= 0 and jit_val < 2: score += 4
        elif jit_val >= 0 and jit_val < 5: score += 3
        elif jit_val >= 0 and jit_val < 15: score += 2
        elif jit_val >= 0 and jit_val < 40: score += 1
        if congestion_index >= 85: score += 4
        elif congestion_index >= 65: score += 3
        elif congestion_index >= 40: score += 2
        elif congestion_index >= 20: score += 1
        if hop_loss < 5: score += 2
        elif hop_loss < 15: score += 1
        if details.get("rtt_cv", 1) >= 0 and details.get("rtt_cv", 1) < 0.25: score += 1
        result["score"] = min(score, 15)
        self.scores["congestion"] = result
        self._log(f"Congestion/Loss/Jitter Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def _probe_path_mtu(self, ip, ipv6=False):
        """Binary-search the path MTU using DF-flag ping probes."""
        family = socket.AF_INET6 if ipv6 else socket.AF_INET
        header = 48 if ipv6 else 28  # IPv6+ICMPv6 vs IPv4+ICMP headers
        lo = 576 - header
        hi = 1500 - header
        best = lo

        def probe(payload):
            try:
                args = ["ping", "-M", "do", "-s", str(payload), "-c", "1", "-W", "2"]
                if ipv6:
                    args.insert(1, "-6")
                else:
                    args.insert(1, "-4")
                args.append(ip)
                proc = subprocess.run(args, capture_output=True, text=True, timeout=6)
                out = (proc.stdout + proc.stderr).lower()
                if proc.returncode == 0:
                    return True
                if "frag needed" in out or "message too long" in out or "packet too big" in out:
                    return False
                return False
            except Exception:
                return False

        if probe(hi):
            return hi + header
        while lo <= hi and (hi - lo) > 8:
            mid = ((lo + hi) // 2) & ~7  # align to 8 bytes
            if mid < (576 - header):
                break
            if probe(mid):
                best = mid
                lo = mid + 8
            else:
                hi = mid - 8
        return best + header

    def analyze_pmtu(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  14. PATH MTU DETECTION")
        print(f"{'='*60}{c.END}")
        result = {"category": "pmtu", "max_score": 10, "score": 0, "details": {}}
        details = result["details"]

        target_ip = self.ip_addresses[0] if self.ip_addresses else ""
        is_v6 = False
        if target_ip:
            try:
                is_v6 = ipaddress.ip_address(target_ip).version == 6
            except ValueError:
                is_v6 = ":" in target_ip
        details["target_family"] = 6 if is_v6 else 4

        # Method 1: TCP_MAXSEG after connect (local MSS observation)
        mss = -1
        sock_mtu = -1
        try:
            sock = socket.create_connection((self.domain, self.port), timeout=self.timeout)
            try:
                mss = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
            except Exception:
                pass
            try:
                level = socket.IPPROTO_IPV6 if is_v6 else socket.IPPROTO_IP
                opt = getattr(socket, "IPV6_MTU", None) if is_v6 else getattr(socket, "IP_MTU", None)
                if opt is not None:
                    sock_mtu = sock.getsockopt(level, opt)
            except Exception:
                pass
            sock.close()
        except Exception as e:
            self._log(f"Socket MTU probe failed: {e}", "warn")

        details["tcp_mss"] = mss
        details["socket_mtu"] = sock_mtu
        if mss > 0:
            inferred = mss + (60 if is_v6 else 40)
            details["mtu_from_mss"] = inferred
            self._log(f"TCP MSS: {mss} (implies MTU ~{inferred})", "ok")
        if sock_mtu > 0:
            self._log(f"Socket-reported MTU: {sock_mtu}", "ok")

        # Method 2: DF-flag binary search (best-effort, may be blocked)
        pmtu = -1
        if target_ip:
            self._log("Probing path MTU with DF-flag pings...", "info")
            pmtu = self._probe_path_mtu(target_ip, ipv6=is_v6)
            details["pmtu_probe"] = pmtu
            if pmtu > 0:
                self._log(f"Path MTU probe result: {pmtu} bytes", "ok")

        effective = pmtu if pmtu > 0 else (sock_mtu if sock_mtu > 0 else (details.get("mtu_from_mss", -1) if mss > 0 else -1))
        details["effective_mtu"] = effective

        if effective >= 1500:
            mtu_rating = "excellent"
        elif effective >= 1400:
            mtu_rating = "good"
        elif effective >= 1280:
            mtu_rating = "fair"
        elif effective > 0:
            mtu_rating = "poor"
        else:
            mtu_rating = "unknown"
        details["mtu_rating"] = mtu_rating
        if effective > 0:
            self._log(f"Effective MTU: {effective} ({mtu_rating})", "ok" if mtu_rating in ("excellent", "good") else "warn")

        blackhole_risk = 0 < effective < 1280
        details["blackhole_risk"] = blackhole_risk
        if blackhole_risk:
            self._log("WARNING: MTU below 1280 - potential IPv6 blackhole risk", "warn")

        score = 0
        if effective <= 0:
            score = 3
        else:
            if effective >= 1500: score += 5
            elif effective >= 1400: score += 4
            elif effective >= 1280: score += 3
            elif effective >= 1200: score += 1
            if mss > 0: score += 2
            if pmtu > 0: score += 2
            if not blackhole_risk: score += 1
        result["score"] = min(score, 10)
        self.scores["pmtu"] = result
        self._log(f"Path MTU Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def analyze_security_audit(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  15. NETWORK SECURITY AUDIT")
        print(f"{'='*60}{c.END}")
        result = {"category": "audit", "max_score": 15, "score": 0, "details": {}}
        details = result["details"]
        findings = []

        def note(severity, name, detail):
            findings.append({"severity": severity, "name": name, "detail": detail})

        audit_headers = {}
        cookie_issues = []
        method_checks = {}
        try:
            r = self.session.get(self.url, timeout=self.timeout, allow_redirects=True)
            details["final_url"] = r.url
            details["redirect_count"] = len(r.history)
            if self.parsed.scheme == "https" and not r.url.startswith("https://"):
                note("critical", "HTTPS downgrade", f"Redirected to insecure URL: {r.url}")

            sec_header_map = {
                "Strict-Transport-Security": "hsts",
                "Content-Security-Policy": "csp",
                "X-Content-Type-Options": "x_content_type",
                "X-Frame-Options": "x_frame",
                "Referrer-Policy": "referrer",
                "Permissions-Policy": "permissions",
                "Cross-Origin-Opener-Policy": "coop",
                "Cross-Origin-Resource-Policy": "corp",
                "Cross-Origin-Embedder-Policy": "coep",
            }
            present = 0
            for header, key in sec_header_map.items():
                val = r.headers.get(header, "")
                audit_headers[key] = val
                if val:
                    present += 1
                else:
                    sev = "medium" if key in ("hsts", "csp") else "low"
                    note(sev, f"Missing {header}", f"{header} header is not set.")
            details["security_headers"] = audit_headers
            details["security_headers_present"] = present

            server = r.headers.get("Server", "")
            powered = r.headers.get("X-Powered-By", "")
            details["server_disclosure"] = server
            details["powered_by_disclosure"] = powered
            if powered:
                note("low", "Tech disclosure", f"X-Powered-By exposes: {powered}")
            if server and re.search(r"\d+\.\d+", server):
                note("low", "Version disclosure", f"Server header reveals version: {server}")

            raw_set_cookies = r.headers.get("Set-Cookie", "")
            details["cookies_present"] = bool(raw_set_cookies)
            if raw_set_cookies:
                lower = raw_set_cookies.lower()
                if "secure" not in lower:
                    cookie_issues.append("missing Secure")
                if "httponly" not in lower:
                    cookie_issues.append("missing HttpOnly")
                if "samesite" not in lower:
                    cookie_issues.append("missing SameSite")
            details["cookie_issues"] = cookie_issues
            for issue in cookie_issues:
                note("medium", "Cookie flags", f"Set-Cookie {issue}.")
        except Exception as e:
            self._log(f"Security audit request failed: {e}", "error")
            details["security_headers"] = audit_headers
            details["security_headers_present"] = 0
            details["cookie_issues"] = cookie_issues

        try:
            for method in ("OPTIONS", "TRACE", "PUT", "DELETE"):
                try:
                    mr = self.session.request(method, self.url, timeout=5)
                    method_checks[method] = mr.status_code
                except Exception:
                    method_checks[method] = -1
            details["http_methods"] = method_checks
            if method_checks.get("TRACE") == 200:
                note("medium", "TRACE enabled", "HTTP TRACE method is enabled (XST risk).")
        except Exception:
            details["http_methods"] = method_checks

        mixed_content = False
        if self.parsed.scheme == "https":
            try:
                r = self.session.get(self.url, timeout=self.timeout)
                body_sample = r.text[:200000]
                insecure_refs = re.findall(r'(?:src|href)\s*=\s*["\']http://[^"\']+', body_sample, re.IGNORECASE)
                mixed_content = len(insecure_refs) > 0
                details["mixed_content_refs"] = len(insecure_refs)
                if mixed_content:
                    note("medium", "Mixed content", f"{len(insecure_refs)} insecure http:// resource references found.")
            except Exception:
                pass
        details["mixed_content"] = mixed_content

        try:
            r = self.session.get(self.url, timeout=self.timeout)
            rl = {}
            for h in ("X-RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After", "X-RateLimit-Reset"):
                val = r.headers.get(h, "")
                if val:
                    rl[h] = val
            details["rate_limit_headers"] = rl
            if not rl:
                note("info", "No rate limiting", "No rate-limit headers observed on responses.")
        except Exception:
            details["rate_limit_headers"] = {}

        error_disclosure = False
        try:
            r = self.session.get(self.url + "/definitely-not-a-real-path-404-check", timeout=5, allow_redirects=False)
            details["error_probe_status"] = r.status_code
            body = r.text[:5000].lower()
            leak_markers = [
                "traceback (most recent call last)", "stack trace", "exception in",
                "sqlstate", "fatal error", "php warning", "at line ",
            ]
            leaked = [m for m in leak_markers if m in body]
            error_disclosure = bool(leaked)
            details["error_leak_markers"] = leaked
            if leaked:
                note("high", "Error disclosure", f"Error page leaks internals: {', '.join(leaked)}.")
        except Exception:
            pass
        details["error_disclosure"] = error_disclosure

        details["findings"] = findings
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for item in findings:
            sev = item.get("severity", "info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        details["finding_counts"] = sev_counts
        audit_ok = sev_counts["critical"] == 0 and sev_counts["high"] == 0
        self._log(f"Security audit: {len(findings)} findings ({sev_counts['critical']} critical, {sev_counts['high']} high)", "ok" if audit_ok else "warn")

        score = 0
        present = details.get("security_headers_present", 0)
        if present >= 7: score += 5
        elif present >= 5: score += 4
        elif present >= 3: score += 2
        elif present >= 1: score += 1
        if not cookie_issues: score += 2
        if method_checks.get("TRACE") != 200: score += 2
        if not mixed_content: score += 2
        if not error_disclosure: score += 2
        if details.get("final_url", "").startswith("https://"): score += 2
        result["score"] = min(score, 15)
        self.scores["audit"] = result
        self._log(f"Security Audit Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def analyze_encryption(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  16. ENCRYPTION ANALYSIS")
        print(f"{'='*60}{c.END}")
        result = {"category": "encryption", "max_score": 15, "score": 0, "details": {}}
        details = result["details"]

        if self.parsed.scheme != "https":
            self._log("Not HTTPS - no transport encryption in use", "error")
            details["encrypted"] = False
            details["encryption_rating"] = "none"
            details["weak_versions_offered"] = []
            details["weak_ciphers_accepted"] = []
            details["findings"] = ["Site does not use HTTPS encryption"]
            self.scores["encryption"] = result
            return result

        details["encrypted"] = True
        ssl_details = self.scores.get("ssl", {}).get("details", {})
        tls_versions = dict(ssl_details.get("tls_versions", {}))
        cipher_info = dict(ssl_details.get("cipher_suite", {}) or {})
        cipher_name = cipher_info.get("name", "")
        cipher_bits = cipher_info.get("bits", 0)
        pfs = bool(ssl_details.get("perfect_forward_secrecy", False))

        details["negotiated_tls_versions"] = tls_versions
        details["negotiated_cipher"] = cipher_name
        details["negotiated_bits"] = cipher_bits
        if "TLSv1.3" in (cipher_info.get("protocol") or ""):
            pfs = True
        details["perfect_forward_secrecy"] = pfs

        weak_versions = [v for v, supported in tls_versions.items() if supported and v in ("TLS 1.0", "TLS 1.1")]
        details["weak_versions_offered"] = weak_versions
        for v in weak_versions:
            self._log(f"Weak TLS version offered: {v}", "warn")

        cipher_upper = cipher_name.upper()
        aead = any(tag in cipher_upper for tag in ("GCM", "CHACHA20", "POLY1305"))
        details["aead_cipher"] = aead
        self._log(f"Negotiated cipher: {cipher_name or 'unknown'} ({cipher_bits} bits), AEAD={aead}, PFS={pfs}", "ok")

        ephemeral_kx = any(tag in cipher_upper for tag in ("ECDHE", "DHE"))
        if "TLSv1.3" in (cipher_info.get("protocol") or ""):
            ephemeral_kx = True
        details["ephemeral_key_exchange"] = ephemeral_kx

        weak_cipher_probes = [
            ("RC4", "RC4-SHA"),
            ("3DES", "DES-CBC3-SHA"),
            ("NULL", "NULL-SHA"),
            ("EXPORT", "EXP-RC4-MD5:EXP-DES-CBC-SHA"),
            ("Anonymous", "aNULL"),
        ]
        accepted_weak = []
        for label, cipher_expr in weak_cipher_probes:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    ctx.set_ciphers(cipher_expr)
                except ssl.SSLError:
                    continue
                sock = socket.create_connection((self.domain, self.port), timeout=5)
                ssock = ctx.wrap_socket(sock, server_hostname=self.domain)
                accepted_weak.append(label)
                ssock.close()
                self._log(f"Weak cipher family accepted: {label}", "warn")
            except Exception:
                pass
        details["weak_ciphers_accepted"] = accepted_weak

        if accepted_weak or weak_versions:
            rating = "poor"
        elif cipher_bits >= 256 and aead and pfs and tls_versions.get("TLS 1.3"):
            rating = "excellent"
        elif cipher_bits >= 128 and pfs:
            rating = "good"
        else:
            rating = "fair"
        details["encryption_rating"] = rating
        self._log(f"Encryption rating: {rating}", "ok" if rating in ("excellent", "good") else "warn")

        score = 0
        if details.get("encrypted"): score += 2
        if tls_versions.get("TLS 1.3"): score += 3
        elif tls_versions.get("TLS 1.2"): score += 2
        if cipher_bits >= 256: score += 2
        elif cipher_bits >= 128: score += 1
        if aead: score += 2
        if pfs: score += 2
        if not weak_versions: score += 2
        if not accepted_weak: score += 2
        result["score"] = min(score, 15)
        self.scores["encryption"] = result
        self._log(f"Encryption Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def analyze_cert_chain(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  17. CERTIFICATE CHAIN ANALYSIS")
        print(f"{'='*60}{c.END}")
        result = {"category": "certchain", "max_score": 15, "score": 0, "details": {}}
        details = result["details"]

        if self.parsed.scheme != "https":
            self._log("Not HTTPS - no certificate chain to analyze", "warn")
            details["chain_length"] = 0
            details["chain_verified"] = False
            self.scores["certchain"] = result
            return result

        chain_certs = []
        try:
            cmd = f"echo | openssl s_client -connect {self.domain}:{self.port} -servername {self.domain} -showcerts 2>/dev/null"
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            pem_blocks = re.findall(
                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                proc.stdout, re.DOTALL,
            )
            details["chain_length"] = len(pem_blocks)
            for idx, pem in enumerate(pem_blocks):
                try:
                    text_proc = subprocess.run(
                        ["openssl", "x509", "-noout", "-text"],
                        input=pem + "\n", capture_output=True, text=True, timeout=10,
                    )
                    text = text_proc.stdout
                except Exception:
                    continue
                info = {
                    "index": idx,
                    "subject": "",
                    "issuer": "",
                    "not_before": "",
                    "not_after": "",
                    "signature_algorithm": "",
                    "public_key_bits": 0,
                    "subject_alt_name": "",
                }
                for line in text.splitlines():
                    s = line.strip()
                    if s.startswith("Subject:"):
                        info["subject"] = s.split(":", 1)[1].strip()
                    elif s.startswith("Issuer:"):
                        info["issuer"] = s.split(":", 1)[1].strip()
                    elif "Not Before" in s:
                        info["not_before"] = s.split(":", 1)[1].strip()
                    elif "Not After" in s:
                        info["not_after"] = s.split(":", 1)[1].strip()
                    elif s.startswith("Signature Algorithm:") and not info["signature_algorithm"]:
                        info["signature_algorithm"] = s.split(":", 1)[1].strip()
                    elif s.startswith("Public-Key:"):
                        m = re.search(r"\((\d+)\s*bit", s)
                        if m:
                            info["public_key_bits"] = int(m.group(1))
                    elif "DNS:" in s and not info["subject_alt_name"]:
                        info["subject_alt_name"] = s
                chain_certs.append(info)
            details["chain"] = chain_certs
            if chain_certs:
                self._log(f"Certificate chain length: {len(chain_certs)}", "ok")
        except Exception as e:
            self._log(f"Certificate chain retrieval failed: {e}", "error")
            details["chain_length"] = 0
            details["chain"] = []

        leaf = chain_certs[0] if chain_certs else {}
        details["leaf"] = leaf
        if leaf:
            self._log(f"Leaf subject: {leaf.get('subject', 'unknown')}", "info")
            self._log(f"Leaf issuer: {leaf.get('issuer', 'unknown')}", "info")

        self_signed = bool(leaf) and leaf.get("subject") == leaf.get("issuer") and bool(leaf.get("subject"))
        details["self_signed"] = self_signed
        if self_signed:
            self._log("Leaf certificate is self-signed", "warn")

        days_to_expiry = -1
        try:
            raw_expiry = leaf.get("not_after", "")
            if raw_expiry:
                try:
                    expiry = datetime.strptime(raw_expiry, "%b %d %H:%M:%S %Y %Z")
                except ValueError:
                    expiry = datetime.strptime(raw_expiry.replace(" GMT", "").strip(), "%b %d %H:%M:%S %Y")
                days_to_expiry = (expiry - datetime.now()).days
        except Exception:
            pass
        details["days_to_expiry"] = days_to_expiry
        if days_to_expiry >= 0:
            self._log(f"Certificate expires in {days_to_expiry} days", "ok" if days_to_expiry > 30 else "warn")

        sig_alg = (leaf.get("signature_algorithm") or "").lower()
        details["strong_signature"] = any(t in sig_alg for t in ("sha256", "sha384", "sha512", "ecdsa"))
        details["weak_signature"] = any(t in sig_alg for t in ("sha1", "md5"))
        if details["weak_signature"]:
            self._log(f"Weak certificate signature algorithm: {leaf.get('signature_algorithm')}", "warn")

        verify_code = -1
        verify_msg = ""
        try:
            cmd = f"echo | openssl s_client -connect {self.domain}:{self.port} -servername {self.domain} 2>/dev/null"
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            m = re.search(r"Verify return code: (\d+)\s*\((.*?)\)", proc.stdout)
            if m:
                verify_code = int(m.group(1))
                verify_msg = m.group(2)
        except Exception:
            pass
        details["verify_return_code"] = verify_code
        details["verify_return_msg"] = verify_msg
        details["chain_verified"] = verify_code == 0
        self._log(f"Chain verification: code={verify_code} ({verify_msg or 'n/a'})", "ok" if verify_code == 0 else "warn")

        sct_present = False
        try:
            cmd = f"echo | openssl s_client -connect {self.domain}:{self.port} -servername {self.domain} 2>/dev/null | openssl x509 -noout -text 2>/dev/null"
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            leaf_text = proc.stdout.lower()
            sct_present = "signed certificate timestamp" in leaf_text or "ct precert sct" in leaf_text
        except Exception:
            pass
        details["sct_present"] = sct_present

        if details["chain_verified"]:
            self._log("Certificate chain: trusted and verified", "ok")
        elif len(chain_certs) >= 2:
            self._log("Certificate chain: present but not fully verified", "warn")
        elif chain_certs:
            self._log("Certificate chain: incomplete (only leaf served)", "warn")

        score = 0
        if chain_certs: score += 2
        if len(chain_certs) >= 2: score += 3
        if details.get("chain_verified"): score += 3
        if days_to_expiry > 60: score += 2
        elif days_to_expiry > 14: score += 1
        if not self_signed: score += 2
        if details.get("strong_signature"): score += 2
        if sct_present: score += 1
        if details.get("weak_signature"): score = max(0, score - 3)
        result["score"] = min(score, 15)
        self.scores["certchain"] = result
        self._log(f"Certificate Chain Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def analyze_protocol_security(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  18. PROTOCOL SECURITY ANALYSIS")
        print(f"{'='*60}{c.END}")
        result = {"category": "protosec", "max_score": 10, "score": 0, "details": {}}
        details = result["details"]
        findings = []

        ssl_d = self.scores.get("ssl", {}).get("details", {})
        tls_versions = ssl_d.get("tls_versions", {})
        insecure_versions = [v for v, ok in tls_versions.items() if ok and v in ("TLS 1.0", "TLS 1.1")]
        details["insecure_tls_versions"] = insecure_versions
        if insecure_versions:
            findings.append(f"Insecure TLS versions enabled: {', '.join(insecure_versions)}")

        netsec_d = self.scores.get("netsec", {}).get("details", {})
        open_ports = netsec_d.get("open_ports", [])
        cleartext_ports = {
            21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP",
            3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
            27017: "MongoDB", 2375: "Docker API", 9200: "Elasticsearch",
        }
        exposed_cleartext = {p: cleartext_ports[p] for p in open_ports if p in cleartext_ports}
        details["cleartext_services"] = exposed_cleartext
        for p in sorted(exposed_cleartext):
            findings.append(f"Cleartext service exposed: {exposed_cleartext[p]} (port {p})")

        redirect_ok = False
        if self.parsed.scheme == "https":
            try:
                http_url = f"http://{self.domain}/"
                r = self.session.get(http_url, timeout=6, allow_redirects=False)
                location = r.headers.get("Location", "")
                redirect_ok = r.status_code in (301, 302, 307, 308) and location.startswith("https://")
                details["http_to_https_redirect"] = redirect_ok
                details["http_redirect_status"] = r.status_code
                if not redirect_ok:
                    findings.append("HTTP port does not redirect to HTTPS")
                else:
                    self._log(f"HTTP->HTTPS redirect: {r.status_code} -> {location[:60]}", "ok")
            except Exception:
                details["http_to_https_redirect"] = False
                findings.append("HTTP port did not respond with an HTTPS redirect")
        else:
            details["http_to_https_redirect"] = False
            findings.append("Site served over plain HTTP")

        starttls = {}
        target = self.ip_addresses[0] if self.ip_addresses else self.domain
        for port, name in ((25, "SMTP"), (110, "POP3"), (143, "IMAP")):
            if port in open_ports:
                try:
                    sock = socket.create_connection((target, port), timeout=4)
                    banner = sock.recv(1024).decode("utf-8", errors="ignore")
                    sock.close()
                    supports = "starttls" in banner.lower()
                    starttls[name] = {"banner": banner.strip()[:80], "starttls_advertised": supports}
                    if not supports:
                        findings.append(f"{name} on port {port} does not advertise STARTTLS")
                except Exception:
                    pass
        details["starttls"] = starttls

        proto_d = self.scores.get("protocols", {}).get("details", {}).get("protocols", {})
        ws_enabled = bool(proto_d.get("websocket"))
        details["websocket_enabled"] = ws_enabled
        if ws_enabled and self.parsed.scheme != "https":
            findings.append("WebSocket accepted without TLS (ws:// instead of wss://)")

        hsts = bool(ssl_d.get("hsts", False))
        details["hsts"] = hsts
        if not hsts and self.parsed.scheme == "https":
            findings.append("HSTS not enabled; protocol downgrade attacks possible")

        http_d = self.scores.get("http", {}).get("details", {})
        details["http2"] = bool(http_d.get("http2"))
        details["http3"] = bool(http_d.get("http3"))
        if not details["http2"] and not details["http3"]:
            findings.append("Neither HTTP/2 nor HTTP/3 negotiated; falling back to HTTP/1.1")

        details["findings"] = findings
        for msg in findings:
            self._log(f"Protocol issue: {msg}", "warn")
        if not findings:
            self._log("No protocol security issues found", "ok")

        score = 0
        if not insecure_versions: score += 2
        if redirect_ok: score += 2
        if hsts: score += 1
        if not exposed_cleartext: score += 2
        if self.parsed.scheme == "https" or not ws_enabled: score += 1
        if not findings: score += 2
        result["score"] = min(score, 10)
        self.scores["protosec"] = result
        self._log(f"Protocol Security Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def analyze_port_security(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  19. PORT SECURITY ANALYSIS")
        print(f"{'='*60}{c.END}")
        result = {"category": "portsec", "max_score": 10, "score": 0, "details": {}}
        details = result["details"]

        target_ip = self.ip_addresses[0] if self.ip_addresses else self.domain
        extended_ports = {
            20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPCBind",
            135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS",
            445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP-Submission",
            636: "LDAPS", 873: "rsync", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS-Proxy",
            1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2181: "Zookeeper",
            2375: "Docker", 2376: "Docker-TLS", 3000: "Dev-Server", 3128: "HTTP-Proxy",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5601: "Kibana",
            5900: "VNC", 5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes-API",
            8000: "Dev-HTTP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter",
            9000: "PHP-FPM", 9090: "Prometheus", 9200: "Elasticsearch",
            9418: "Git", 10250: "Kubelet", 11211: "Memcached", 27017: "MongoDB",
        }
        risk_tiers = {
            "critical": [2375, 10250, 6379, 27017, 9200, 11211, 5900, 5984],
            "high": [21, 23, 3389, 445, 1433, 1521, 3306, 5432, 5601, 9090, 1080, 3128],
            "medium": [25, 111, 135, 139, 389, 69, 873, 2049, 2181, 3000, 8000, 8888, 9000],
            "low": [53, 80, 443, 587, 465, 993, 995, 636, 8080, 8443, 6443, 2376, 20],
        }

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                code = sock.connect_ex((target_ip, port))
                sock.close()
                return port, code == 0
            except Exception:
                return port, False

        found = []
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(scan_port, port): port for port in extended_ports}
            for future in as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    found.append(port)
        open_ports = sorted(set(found))
        details["scanned_ports"] = len(extended_ports)
        details["open_ports"] = open_ports
        details["open_services"] = {p: extended_ports.get(p, "unknown") for p in open_ports}
        self._log(f"Port security scan: {len(open_ports)} open of {len(extended_ports)} probed", "ok")

        exposure = {"critical": [], "high": [], "medium": [], "low": [], "unknown": []}
        for p in open_ports:
            placed = False
            for tier, ports in risk_tiers.items():
                if p in ports:
                    exposure[tier].append(p)
                    placed = True
                    break
            if not placed:
                exposure["unknown"].append(p)
        details["exposure"] = exposure
        for tier in ("critical", "high"):
            if exposure[tier]:
                names = ", ".join(f"{p}/{extended_ports.get(p, '?')}" for p in exposure[tier])
                self._log(f"{tier.upper()} risk ports open: {names}", "warn")

        banners = {}
        versioned = []
        for p in open_ports[:6]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.5)
                sock.connect((target_ip, p))
                if p not in (80, 443, 8080, 8443):
                    try:
                        sock.send(b"HEAD / HTTP/1.0\r\nHost: " + self.domain.encode() + b"\r\n\r\n")
                    except Exception:
                        pass
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                sock.close()
                if banner:
                    banners[p] = banner[:160]
                    if re.search(r"\d+\.\d+", banner):
                        versioned.append(p)
            except Exception:
                pass
        details["banners"] = banners
        details["version_disclosing_ports"] = versioned
        if versioned:
            self._log(f"Version strings leaked on ports: {versioned}", "warn")

        recommended = ["Allow 443/tcp (HTTPS) from the internet", "Allow 80/tcp (HTTP) only to redirect to HTTPS"]
        for tier in ("critical", "high", "medium"):
            for p in exposure[tier]:
                recommended.append(f"Restrict {p}/tcp ({extended_ports.get(p, 'unknown')}) to trusted source IPs or VPN")
        details["recommended_rules"] = recommended

        score = 0
        if not exposure["critical"]: score += 3
        if not exposure["high"]: score += 2
        if len(open_ports) <= 4: score += 2
        elif len(open_ports) <= 8: score += 1
        if 443 in open_ports: score += 1
        if not versioned: score += 1
        if not exposure["medium"]: score += 1
        result["score"] = min(score, 10)
        self.scores["portsec"] = result
        self._log(f"Port Security Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def analyze_reliability(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  20. NETWORK RELIABILITY ANALYSIS")
        print(f"{'='*60}{c.END}")
        result = {"category": "reliability", "max_score": 10, "score": 0, "details": {}}
        details = result["details"]

        attempts = 8
        successes = 0
        times = []
        status_codes = {}
        for _ in range(attempts):
            try:
                start = time.time()
                r = self.session.get(self.url, timeout=self.timeout)
                elapsed = round((time.time() - start) * 1000, 2)
                times.append(elapsed)
                status_codes[r.status_code] = status_codes.get(r.status_code, 0) + 1
                if 200 <= r.status_code < 400:
                    successes += 1
            except Exception:
                pass
        success_rate = round((successes / attempts) * 100, 1) if attempts else 0.0
        details["attempts"] = attempts
        details["successes"] = successes
        details["success_rate_pct"] = success_rate
        details["status_codes"] = status_codes
        self._log(f"Request reliability: {successes}/{attempts} succeeded ({success_rate}%)", "ok" if success_rate >= 99 else "warn")

        if times:
            avg = sum(times) / len(times)
            variance = sum((t - avg) ** 2 for t in times) / len(times)
            stddev = variance ** 0.5
            details["avg_ms"] = round(avg, 2)
            details["stddev_ms"] = round(stddev, 2)
            details["min_ms"] = min(times)
            details["max_ms"] = max(times)
            details["variance_ms"] = round(variance, 2)
            self._log(f"Response time stability: avg={avg:.1f}ms stddev={stddev:.1f}ms", "ok")

        propagation = self.scores.get("dns", {}).get("details", {}).get("propagation", {})
        resolver_ok = sum(1 for v in propagation.values() if v.get("status") == "ok")
        resolver_total = len(propagation)
        details["resolver_success"] = resolver_ok
        details["resolver_total"] = resolver_total
        if resolver_total:
            resolver_pct = round((resolver_ok / resolver_total) * 100, 1)
            details["resolver_success_pct"] = resolver_pct
            self._log(f"DNS resolver reachability: {resolver_ok}/{resolver_total} ({resolver_pct}%)", "ok")

        cdn_providers = self.scores.get("cdn", {}).get("details", {}).get("cdn_providers", [])
        details["cdn_redundancy"] = bool(cdn_providers)
        keep_alive = bool(self.scores.get("tcp", {}).get("details", {}).get("keep_alive", False))
        details["keep_alive"] = keep_alive

        if success_rate >= 100 and resolver_total and resolver_ok == resolver_total:
            rating = "excellent"
        elif success_rate >= 90:
            rating = "good"
        elif success_rate >= 75:
            rating = "fair"
        else:
            rating = "poor"
        details["reliability_rating"] = rating
        self._log(f"Reliability rating: {rating}", "ok" if rating in ("excellent", "good") else "warn")

        score = 0
        if success_rate >= 100: score += 4
        elif success_rate >= 90: score += 3
        elif success_rate >= 75: score += 2
        elif success_rate >= 50: score += 1
        if resolver_total and resolver_ok == resolver_total: score += 2
        elif resolver_total and resolver_ok >= resolver_total / 2: score += 1
        if details.get("stddev_ms") is not None and details.get("avg_ms"):
            if details["stddev_ms"] < details["avg_ms"] * 0.3: score += 1
        if cdn_providers: score += 1
        if keep_alive: score += 1
        if success_rate == 100: score += 1
        result["score"] = min(score, 10)
        self.scores["reliability"] = result
        self._log(f"Reliability Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def analyze_scalability(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  21. NETWORK SCALABILITY ANALYSIS")
        print(f"{'='*60}{c.END}")
        result = {"category": "scalability", "max_score": 10, "score": 0, "details": {}}
        details = result["details"]

        cache_control = ""
        etag = ""
        expires = ""
        vary = ""
        try:
            r = self.session.get(self.url, timeout=self.timeout, stream=True)
            cache_control = r.headers.get("Cache-Control", "")
            etag = r.headers.get("ETag", "")
            expires = r.headers.get("Expires", "")
            vary = r.headers.get("Vary", "")
            r.close()
        except Exception as e:
            self._log(f"Cache header probe failed: {e}", "warn")
        details["cache_control"] = cache_control
        details["etag"] = etag
        details["expires"] = expires
        details["vary"] = vary
        if cache_control:
            self._log(f"Cache-Control: {cache_control[:70]}", "ok")
        if etag:
            self._log(f"ETag: {etag[:60]}", "ok")

        content_encoding = ""
        try:
            r = self.session.get(
                self.url,
                headers={"Accept-Encoding": "gzip, deflate, br"},
                timeout=self.timeout, stream=True,
            )
            content_encoding = r.headers.get("Content-Encoding", "")
            r.close()
        except Exception:
            pass
        details["content_encoding"] = content_encoding
        details["compression_enabled"] = bool(content_encoding)
        if content_encoding:
            self._log(f"Compression: {content_encoding}", "ok")
        else:
            self._log("Compression: not enabled", "warn")

        http_d = self.scores.get("http", {}).get("details", {})
        audit_d = self.scores.get("audit", {}).get("details", {})
        signals = {
            "http2": bool(http_d.get("http2")),
            "http3": bool(http_d.get("http3")),
            "keep_alive": bool(self.scores.get("tcp", {}).get("details", {}).get("keep_alive", False)),
            "cdn": bool(self.scores.get("cdn", {}).get("details", {}).get("cdn_providers")),
            "cacheable": bool(cache_control or etag or expires),
            "compressed": bool(content_encoding),
            "multi_ip": len(self.ip_addresses) > 1,
            "rate_limited": bool(audit_d.get("rate_limit_headers")),
        }
        details["signals"] = signals
        active = sum(1 for v in signals.values() if v)
        details["signals_active"] = active
        if active >= 7:
            readiness = "excellent"
        elif active >= 5:
            readiness = "good"
        elif active >= 3:
            readiness = "fair"
        else:
            readiness = "poor"
        details["readiness"] = readiness
        self._log(f"Scalability signals: {active}/8 active ({readiness})", "ok" if active >= 5 else "warn")

        score = 0
        if signals["http2"]: score += 2
        if signals["http3"]: score += 1
        if signals["keep_alive"]: score += 1
        if signals["cdn"]: score += 2
        if signals["cacheable"]: score += 1
        if signals["compressed"]: score += 1
        if signals["multi_ip"]: score += 1
        if signals["rate_limited"]: score += 1
        result["score"] = min(score, 10)
        self.scores["scalability"] = result
        self._log(f"Scalability Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def analyze_resilience(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  22. NETWORK RESILIENCE ANALYSIS")
        print(f"{'='*60}{c.END}")
        result = {"category": "resilience", "max_score": 10, "score": 0, "details": {}}
        details = result["details"]

        working_ips = 0
        for ip in self.ip_addresses[:4]:
            try:
                sock = socket.create_connection((ip, self.port), timeout=5)
                sock.close()
                working_ips += 1
            except Exception:
                pass
        details["ips_total"] = len(self.ip_addresses)
        details["ips_reachable"] = working_ips
        if working_ips:
            self._log(f"Endpoint reachability: {working_ips}/{len(self.ip_addresses)} IPs accept connections", "ok")

        ipv6_d = self.scores.get("ipv6", {}).get("details", {})
        dual_stack = bool(ipv6_d.get("dual_stack")) and ipv6_d.get("ipv6_connect_ms", -1) >= 0
        details["dual_stack"] = dual_stack

        http_d = self.scores.get("http", {}).get("details", {})
        http3 = bool(http_d.get("http3"))
        details["http3"] = http3

        cdn_providers = self.scores.get("cdn", {}).get("details", {}).get("cdn_providers", [])
        details["cdn_failover"] = bool(cdn_providers)

        graceful = False
        try:
            r = self.session.get(self.url + "/resilience-probe-nonexistent-xyz", timeout=6, allow_redirects=False)
            details["error_page_status"] = r.status_code
            body = r.text[:5000].lower()
            leaky = any(m in body for m in (
                "traceback (most recent call last)", "stack trace",
                "system.nullreferenceexception", "fatal error:",
            ))
            graceful = not leaky
        except Exception:
            graceful = False
        details["graceful_errors"] = graceful
        self._log(f"Graceful error handling: {'yes' if graceful else 'no'}", "ok" if graceful else "warn")

        rel_d = self.scores.get("reliability", {}).get("details", {})
        status_codes = rel_d.get("status_codes", {})
        throttled = bool(
            status_codes.get(429) or status_codes.get("429")
            or status_codes.get(503) or status_codes.get("503")
        )
        details["rate_limited_under_load"] = throttled

        hsts = bool(self.scores.get("ssl", {}).get("details", {}).get("hsts", False))
        details["hsts"] = hsts

        signals = {
            "ip_failover": working_ips > 1,
            "dual_stack": dual_stack,
            "http3_quic": http3,
            "cdn_layer": bool(cdn_providers),
            "graceful_errors": graceful,
            "no_throttling": not throttled,
            "hsts": hsts,
        }
        details["signals"] = signals
        active = sum(1 for v in signals.values() if v)
        details["signals_active"] = active
        if active >= 6:
            rating = "excellent"
        elif active >= 4:
            rating = "good"
        elif active >= 2:
            rating = "fair"
        else:
            rating = "poor"
        details["resilience_rating"] = rating
        self._log(f"Resilience signals: {active}/7 active ({rating})", "ok" if active >= 4 else "warn")

        score = 0
        if details["ips_reachable"] >= 1: score += 1
        if signals["ip_failover"]: score += 2
        if signals["dual_stack"]: score += 2
        if signals["http3_quic"]: score += 1
        if signals["cdn_layer"]: score += 1
        if signals["graceful_errors"]: score += 1
        if signals["no_throttling"]: score += 1
        if signals["hsts"]: score += 1
        result["score"] = min(score, 10)
        self.scores["resilience"] = result
        self._log(f"Resilience Score: {result['score']}/{result['max_score']}", "ok")
        return result

    def analyze_quic(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  23. QUIC / HTTP3 DEEP ANALYSIS")
        print(f"{'='*60}{c.END}")
        result = {"category": "quic", "max_score": 10, "score": 0, "details": {}}
        details = result["details"]

        http_d = self.scores.get("http", {}).get("details", {})
        ssl_d = self.scores.get("ssl", {}).get("details", {})
        alt_svc = http_d.get("alt_svc", "")
        details["alt_svc"] = alt_svc
        h3_advertised = bool(re.search(r"h3|quic", alt_svc.lower())) if alt_svc else False
        details["h3_advertised"] = h3_advertised
        h3_variants = sorted(set(re.findall(r"h3(?:-\d+)?", alt_svc.lower())))
        details["h3_variants"] = h3_variants
        if h3_variants:
            joined = ", ".join(h3_variants)
            self._log(f"Alt-Svc HTTP/3 variants: {joined}", "ok")

        alpn = ssl_d.get("alpn_protocols", [])
        alpn_h3 = any(str(p).startswith("h3") or str(p).startswith("hq") for p in alpn)
        details["alpn_h3"] = alpn_h3

        udp_reachable = False
        version_negotiation = False
        supported_versions = []
        udp_probe_ms = -1
        target_ip = self.ip_addresses[0] if self.ip_addresses else self.domain

        if self.parsed.scheme == "https":
            self._log("Probing QUIC on UDP/443 (grease version Initial)...", "info")
            try:
                u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                u.settimeout(3)
                dcid = os.urandom(8)
                payload = os.urandom(900)
                plen = len(payload)
                pkt = bytearray()
                pkt.append(0xC0)
                pkt += b"\x0a\x0a\x0a\x0a"
                pkt.append(len(dcid))
                pkt += dcid
                pkt.append(0)
                pkt.append(0x40 | ((plen >> 8) & 0x3F))
                pkt.append(plen & 0xFF)
                pkt += payload
                if len(pkt) < 1200:
                    pkt += os.urandom(1200 - len(pkt))
                start = time.time()
                u.sendto(bytes(pkt), (target_ip, 443))
                data, _addr = u.recvfrom(2048)
                udp_probe_ms = round((time.time() - start) * 1000, 2)
                if data:
                    udp_reachable = True
                    details["quic_response_bytes"] = len(data)
                    if len(data) >= 6 and (data[0] & 0x80) and data[1:5] == b"\x00\x00\x00\x00":
                        version_negotiation = True
                        try:
                            off = 6 + data[5]
                            scid_len = data[off]
                            off += 1 + scid_len
                            while off + 4 <= len(data):
                                supported_versions.append(data[off:off + 4].hex())
                                off += 4
                        except IndexError:
                            pass
                    self._log(f"UDP/443 responded in {udp_probe_ms}ms ({len(data)} bytes)", "ok")
                u.close()
            except Exception as e:
                self._log(f"QUIC/UDP probe failed: {e}", "warn")

        details["udp_reachable"] = udp_reachable
        details["quic_version_negotiation"] = version_negotiation
        details["quic_supported_versions"] = supported_versions
        details["udp_probe_ms"] = udp_probe_ms
        if version_negotiation and supported_versions:
            joined = ", ".join(supported_versions[:8])
            self._log(f"QUIC version negotiation: {joined}", "ok")

        h3_direct = False
        try:
            ver_proc = subprocess.run(["curl", "--version"], capture_output=True, text=True, timeout=5)
            version_text = (ver_proc.stdout + ver_proc.stderr).upper()
            if "HTTP3" in version_text or "HTTP/3" in version_text:
                start = time.time()
                proc = subprocess.run(
                    ["curl", "--http3-only", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     "--max-time", "10", self.url],
                    capture_output=True, text=True, timeout=15,
                )
                elapsed = round((time.time() - start) * 1000, 2)
                code = proc.stdout.strip()
                details["h3_direct_status"] = code
                details["h3_direct_ms"] = elapsed
                h3_direct = code.isdigit() and 200 <= int(code) < 500
                if h3_direct:
                    self._log(f"HTTP/3 direct fetch OK (status {code}) in {elapsed}ms", "ok")
                else:
                    self._log(f"HTTP/3 direct fetch failed (status {code or 'n/a'})", "warn")
        except Exception:
            pass
        details["h3_direct_ok"] = h3_direct

        score = 0
        if h3_advertised: score += 3
        if udp_reachable: score += 2
        if version_negotiation: score += 1
        if h3_direct: score += 2
        if h3_variants: score += 1
        if alpn_h3 or http_d.get("http3"): score += 1
        result["score"] = min(score, 10)
        if score >= 8:
            rating = "excellent"
        elif score >= 6:
            rating = "good"
        elif score >= 3:
            rating = "fair"
        else:
            rating = "poor"
        details["quic_rating"] = rating
        self.scores["quic"] = result
        self._log(f"QUIC/HTTP3 Score: {result['score']}/{result['max_score']} ({rating})", "ok")
        return result

    def analyze_tls13_optimization(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  24. TLS 1.3 OPTIMIZATION")
        print(f"{'='*60}{c.END}")
        result = {"category": "tls13", "max_score": 10, "score": 0, "details": {}}
        details = result["details"]

        if self.parsed.scheme != "https":
            self._log("Not HTTPS, skipping TLS 1.3 optimization", "warn")
            details["tls13_supported"] = False
            self.scores["tls13"] = result
            return result

        ssl_d = self.scores.get("ssl", {}).get("details", {})
        tls_versions = ssl_d.get("tls_versions", {})
        tls13_supported = bool(tls_versions.get("TLS 1.3"))
        details["tls13_supported"] = tls13_supported
        legacy = [v for v, ok in tls_versions.items() if ok and v in ("TLS 1.0", "TLS 1.1")]
        details["legacy_versions"] = legacy

        def timed_handshake(min_ver, max_ver):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = min_ver
                ctx.maximum_version = max_ver
                start = time.time()
                sock = socket.create_connection((self.domain, self.port), timeout=self.timeout)
                ssock = ctx.wrap_socket(sock, server_hostname=self.domain)
                elapsed = round((time.time() - start) * 1000, 2)
                proto = ssock.version() or ""
                ssock.close()
                return elapsed, proto
            except Exception:
                return -1, ""

        hs13, proto13 = timed_handshake(ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)
        hs12, proto12 = timed_handshake(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
        details["handshake_tls13_ms"] = hs13
        details["handshake_tls12_ms"] = hs12
        details["negotiated_tls13"] = proto13 == "TLSv1.3"
        details["negotiated_tls12"] = proto12 == "TLSv1.2"
        if hs13 > 0 and hs12 > 0:
            delta = round(((hs12 - hs13) / hs12) * 100, 1)
            details["tls13_speedup_pct"] = max(delta, 0.0)
        else:
            details["tls13_speedup_pct"] = 0.0
        if hs13 > 0:
            self._log(f"TLS 1.3 handshake: {hs13}ms (TLS 1.2: {hs12}ms, speedup {details['tls13_speedup_pct']}%)", "ok")

        early_data = None
        session_ticket = False
        key_group = ""
        max_early_data = 0
        try:
            cmd = (f"echo | openssl s_client -connect {self.domain}:{self.port} "
                   f"-servername {self.domain} -tls1_3 -tlsextdebug 2>/dev/null")
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            out = proc.stdout
            out_l = out.lower()
            if "tlsv1.3" in out_l:
                details["openssl_tls13"] = True
            if "early data" in out_l:
                if 'extension "early data"' in out_l or '"early data"' in out_l:
                    early_data = True
                elif "tls server extension" in out_l:
                    early_data = False
            elif "tls server extension" in out_l:
                early_data = False
            m = re.search(r"Negotiated TLS1\.3 group:\s*(\S+)", out)
            if m:
                key_group = m.group(1).strip()
            if "session ticket" in out_l or re.search(r"Session-ID:\s+[0-9a-f]{8,}", out):
                session_ticket = True
            m2 = re.search(r"max[ _]early[ _]data:\s*(\d+)", out_l)
            if m2:
                try:
                    max_early_data = int(m2.group(1))
                except ValueError:
                    max_early_data = 0
        except Exception as e:
            self._log(f"TLS 1.3 openssl probe failed: {e}", "warn")

        details["early_data_0rtt"] = early_data
        details["session_tickets"] = session_ticket
        details["key_share_group"] = key_group
        details["max_early_data_bytes"] = max_early_data
        if early_data is True:
            self._log("TLS 1.3 0-RTT early data: advertised", "ok")
        elif early_data is False:
            self._log("TLS 1.3 0-RTT early data: not advertised", "info")
        if key_group:
            self._log(f"TLS 1.3 key share group: {key_group}", "ok")

        modern_groups = ("x25519", "x25519mlkem768", "secp256r1", "secp384r1", "secp521r1")
        modern_group = key_group.lower() in modern_groups
        details["modern_key_group"] = modern_group

        if not tls13_supported:
            rating = "poor"
        elif hs13 > 0 and hs13 < 150 and modern_group:
            rating = "excellent"
        elif hs13 > 0 and hs13 < 300:
            rating = "good"
        elif hs13 > 0:
            rating = "fair"
        else:
            rating = "unknown"
        details["tls13_rating"] = rating

        score = 0
        if tls13_supported: score += 3
        if details.get("negotiated_tls13"): score += 1
        if hs13 > 0 and hs13 < 150: score += 2
        elif hs13 > 0 and hs13 < 300: score += 1
        if details.get("tls13_speedup_pct", 0) > 5: score += 1
        if early_data is True: score += 1
        if session_ticket: score += 1
        if modern_group: score += 1
        result["score"] = min(score, 10)
        self.scores["tls13"] = result
        self._log(f"TLS 1.3 Optimization Score: {result['score']}/{result['max_score']} ({rating})", "ok")
        return result

    def analyze_tcp_fast_open(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  25. TCP FAST OPEN DETECTION")
        print(f"{'='*60}{c.END}")
        result = {"category": "tfo", "max_score": 10, "score": 0, "details": {}}
        details = result["details"]

        sysctl_val = None
        try:
            with open("/proc/sys/net/ipv4/tcp_fastopen") as f:
                sysctl_val = int(f.read().strip())
        except Exception:
            try:
                proc = subprocess.run(["sysctl", "-n", "net.ipv4.tcp_fastopen"],
                                      capture_output=True, text=True, timeout=5)
                if proc.returncode == 0 and proc.stdout.strip().lstrip("-").isdigit():
                    sysctl_val = int(proc.stdout.strip())
            except Exception:
                pass
        details["local_sysctl"] = sysctl_val
        local_client = bool(sysctl_val is not None and (sysctl_val & 1))
        local_server_bit = bool(sysctl_val is not None and (sysctl_val & 2))
        details["local_client_enabled"] = local_client
        details["local_server_bit"] = local_server_bit
        if sysctl_val is not None:
            client_txt = "on" if local_client else "off"
            server_txt = "on" if local_server_bit else "off"
            level = "ok" if local_client else "warn"
            self._log(f"Local tcp_fastopen sysctl: {sysctl_val} (client={client_txt}, server-bit={server_txt})", level)
        else:
            self._log("Local tcp_fastopen sysctl: unavailable", "warn")

        target_ip = self.ip_addresses[0] if self.ip_addresses else self.domain
        msg_fastopen = getattr(socket, "MSG_FASTOPEN", 0x20000000)
        tcp_fastopen_connect = getattr(socket, "TCP_FASTOPEN_CONNECT", None)

        server_tfo = False
        syn_data_sent = False
        syn_data_acked = False
        tfo_ms = -1
        tfo_ms_second = -1
        cookie_cached = False
        baseline_ms = -1

        try:
            probe = b"HEAD / HTTP/1.0\r\nHost: " + self.domain.encode() + b"\r\nConnection: close\r\n\r\n"
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            start = time.time()
            sent = s.sendto(probe, msg_fastopen, (target_ip, self.port))
            if sent and sent > 0:
                syn_data_sent = True
            resp = s.recv(512)
            tfo_ms = round((time.time() - start) * 1000, 2)
            try:
                info_raw = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 232)
                if len(info_raw) > 5:
                    syn_data_acked = bool(info_raw[5] & 32)
            except Exception:
                pass
            s.close()
            if resp:
                server_tfo = syn_data_acked
                self._log(f"TFO SYN-data probe: response in {tfo_ms}ms, syn-data-acked={'yes' if syn_data_acked else 'no'}",
                          "ok" if syn_data_acked else "info")
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.settimeout(self.timeout)
            start = time.time()
            s2.sendto(probe, msg_fastopen, (target_ip, self.port))
            resp2 = s2.recv(512)
            tfo_ms_second = round((time.time() - start) * 1000, 2)
            s2.close()
            if resp2 and syn_data_acked:
                cookie_cached = True
        except Exception as e:
            self._log(f"TFO SYN-data probe failed: {e}", "warn")

        try:
            s3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s3.settimeout(self.timeout)
            start = time.time()
            s3.connect((target_ip, self.port))
            baseline_ms = round((time.time() - start) * 1000, 2)
            s3.close()
        except Exception:
            pass

        tfo_connect_opt = False
        if tcp_fastopen_connect is not None:
            try:
                s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s4.settimeout(self.timeout)
                s4.setsockopt(socket.IPPROTO_TCP, tcp_fastopen_connect, 1)
                s4.connect((target_ip, self.port))
                tfo_connect_opt = True
                s4.close()
            except Exception:
                tfo_connect_opt = False

        details["syn_data_sent"] = syn_data_sent
        details["syn_data_acked"] = syn_data_acked
        details["server_tfo"] = server_tfo
        details["tfo_connect_ms"] = tfo_ms
        details["tfo_second_ms"] = tfo_ms_second
        details["baseline_connect_ms"] = baseline_ms
        details["tfo_cookie_cached"] = cookie_cached
        details["tcp_fastopen_connect_opt"] = tfo_connect_opt

        gain_pct = 0.0
        if tfo_ms > 0 and baseline_ms > 0:
            gain_pct = round(max(((baseline_ms - tfo_ms) / baseline_ms) * 100, 0.0), 1)
        details["tfo_gain_pct"] = gain_pct
        if baseline_ms > 0:
            self._log(f"TFO vs baseline connect: {tfo_ms}ms vs {baseline_ms}ms (gain {gain_pct}%)", "ok")

        score = 0
        if local_client: score += 2
        if server_tfo: score += 4
        elif syn_data_sent: score += 1
        if cookie_cached: score += 2
        if tfo_connect_opt: score += 1
        if tfo_ms > 0 and baseline_ms > 0 and tfo_ms < baseline_ms: score += 1
        result["score"] = min(score, 10)

        if server_tfo and cookie_cached:
            rating = "excellent"
        elif server_tfo:
            rating = "good"
        elif syn_data_sent or local_client:
            rating = "fair"
        else:
            rating = "poor"
        details["tfo_rating"] = rating
        self.scores["tfo"] = result
        self._log(f"TCP Fast Open Score: {result['score']}/{result['max_score']} ({rating})", "ok")
        return result

    def analyze_connection_coalescing(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  26. CONNECTION COALESCING ANALYSIS")
        print(f"{'='*60}{c.END}")
        result = {"category": "coalesce", "max_score": 10, "score": 0, "details": {}}
        details = result["details"]

        http_d = self.scores.get("http", {}).get("details", {})
        ssl_d = self.scores.get("ssl", {}).get("details", {})
        cert_d = self.scores.get("certchain", {}).get("details", {})

        h2 = bool(http_d.get("http2"))
        details["http2"] = h2
        alpn = ssl_d.get("alpn_protocols", [])
        details["alpn"] = alpn

        san_raw = ""
        leaf = cert_d.get("leaf", {}) or {}
        san_raw = leaf.get("subject_alt_name", "") or ""
        if not san_raw and self.parsed.scheme == "https":
            try:
                cmd = (f"echo | openssl s_client -connect {self.domain}:{self.port} "
                       f"-servername {self.domain} 2>/dev/null | openssl x509 -noout -ext subjectAltName 2>/dev/null")
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                san_raw = proc.stdout.strip()
            except Exception:
                san_raw = ""
        san_hosts = sorted(set(re.findall(r"DNS:([\w.\-]+)", san_raw)))
        details["san_hosts"] = san_hosts
        details["san_count"] = len(san_hosts)
        wildcard = any(h.startswith("*.") for h in san_hosts)
        details["wildcard_cert"] = wildcard
        if san_hosts:
            joined = ", ".join(san_hosts[:8])
            self._log(f"Certificate SAN hosts ({len(san_hosts)}): {joined}", "ok")

        own_ips = set(self.ip_addresses)
        shared_hosts = []
        other_hosts = []
        for host in san_hosts[:12]:
            base = host[2:] if host.startswith("*.") else host
            if not base or base == self.domain:
                continue
            try:
                infos = socket.getaddrinfo(base, None)
                host_ips = {i[4][0] for i in infos}
                if host_ips & own_ips:
                    shared_hosts.append(base)
                else:
                    other_hosts.append(base)
            except Exception:
                pass
        details["shared_ip_hosts"] = shared_hosts
        details["other_hosts"] = other_hosts
        if shared_hosts:
            joined = ", ".join(shared_hosts[:6])
            self._log(f"Coalescing candidates (same IP): {joined}", "ok")

        alt_svc = http_d.get("alt_svc", "")
        details["alt_svc_present"] = bool(alt_svc)
        coalescing_ready = bool(h2 and len(san_hosts) >= 2 and (shared_hosts or wildcard))
        details["coalescing_ready"] = coalescing_ready
        self._log(f"Coalescing ready: {'yes' if coalescing_ready else 'no'}", "ok" if coalescing_ready else "info")

        score = 0
        if h2: score += 3
        if len(san_hosts) >= 2: score += 2
        elif san_hosts: score += 1
        if shared_hosts: score += 2
        if wildcard: score += 1
        if alpn and "h2" in alpn: score += 1
        if alt_svc: score += 1
        result["score"] = min(score, 10)

        if score >= 8:
            rating = "excellent"
        elif score >= 6:
            rating = "good"
        elif score >= 3:
            rating = "fair"
        else:
            rating = "poor"
        details["coalesce_rating"] = rating
        self.scores["coalesce"] = result
        self._log(f"Connection Coalescing Score: {result['score']}/{result['max_score']} ({rating})", "ok")
        return result

    def analyze_priority_headers(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  27. PRIORITY HEADER ANALYSIS")
        print(f"{'='*60}{c.END}")
        result = {"category": "priority", "max_score": 10, "score": 0, "details": {}}
        details = result["details"]

        response_priority = ""
        link_header = ""
        deprecate_header = ""
        request_priority_ok = False

        try:
            r = self.session.get(self.url, timeout=self.timeout, headers={"Priority": "u=0, i"})
            request_priority_ok = r.status_code < 400
            response_priority = r.headers.get("Priority", "")
            link_header = r.headers.get("Link", "")
            deprecate_header = r.headers.get("Deprecate", "")
        except Exception as e:
            self._log(f"Priority header request failed: {e}", "warn")

        details["request_priority_accepted"] = request_priority_ok
        details["response_priority"] = response_priority
        details["link_header"] = link_header
        details["deprecate_header"] = deprecate_header

        parsed_priority = {}
        if response_priority:
            for part in response_priority.split(","):
                for tok in part.split(";"):
                    tok = tok.strip()
                    if not tok:
                        continue
                    if "=" in tok:
                        k, v = tok.split("=", 1)
                        parsed_priority[k.strip()] = v.strip()
                    else:
                        flags = parsed_priority.get("flags")
                        if isinstance(flags, list):
                            flags.append(tok)
                        else:
                            parsed_priority["flags"] = [tok]
        details["priority_parsed"] = parsed_priority
        if response_priority:
            self._log(f"Response Priority header: {response_priority}", "ok")

        early_hints = False
        early_links = []
        status_sequence = []
        if self.parsed.scheme == "https":
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((self.domain, self.port), timeout=self.timeout)
                ssock = ctx.wrap_socket(sock, server_hostname=self.domain)
                path = self.parsed.path or "/"
                if self.parsed.query:
                    path += "?" + self.parsed.query
                req = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {self.domain}\r\n"
                    "Priority: u=0, i\r\n"
                    "Accept: */*\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                )
                ssock.sendall(req.encode())
                raw = b""
                try:
                    while len(raw) < 32768:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        raw += chunk
                        statuses_now = re.findall(br"HTTP/\d\.\d (\d{3})", raw)
                        if statuses_now and int(statuses_now[-1]) >= 200:
                            break
                except Exception:
                    pass
                ssock.close()
                text = raw.decode("utf-8", errors="ignore")
                status_sequence = [int(m) for m in re.findall(r"HTTP/\d\.\d (\d{3})", text)]
                details["status_sequence"] = status_sequence
                early_hints = 103 in status_sequence
                if early_hints:
                    for block in re.split(r"\r\n\r\n", text):
                        if re.search(r"HTTP/\d\.\d 103", block):
                            for lm in re.finditer(r"Link:\s*([^\r\n]+)", block, re.I):
                                early_links.append(lm.group(1).strip())
                if not response_priority:
                    pm = re.search(r"Priority:\s*([^\r\n]+)", text, re.I)
                    if pm:
                        response_priority = pm.group(1).strip()
                        details["response_priority"] = response_priority
            except Exception as e:
                self._log(f"Early Hints probe failed: {e}", "warn")

        preload_count = len(re.findall(r"rel=\s*\"?preload\"?", link_header, re.I))
        if not preload_count:
            preload_count = len(re.findall(r"rel=\s*\"?preload\"?", " ".join(early_links), re.I))
        details["early_hints"] = early_hints
        details["early_hint_links"] = early_links
        details["preload_link_count"] = preload_count
        if early_hints:
            joined = "; ".join(early_links[:3]) if early_links else "no Link headers"
            self._log(f"103 Early Hints received: {joined}", "ok")
        else:
            self._log("103 Early Hints: not observed", "info")
        if preload_count:
            self._log(f"Preload links found: {preload_count}", "ok")

        details["priority_support"] = bool(response_priority or early_hints)

        score = 0
        if response_priority: score += 3
        if early_hints: score += 3
        if early_links or preload_count: score += 2
        if request_priority_ok: score += 1
        if deprecate_header: score += 1
        result["score"] = min(score, 10)

        if score >= 8:
            rating = "excellent"
        elif score >= 5:
            rating = "good"
        elif score >= 2:
            rating = "fair"
        else:
            rating = "poor"
        details["priority_rating"] = rating
        self.scores["priority"] = result
        self._log(f"Priority Header Score: {result['score']}/{result['max_score']} ({rating})", "ok")
        return result

    def refine_network_analysis(self):
        """Refinement pass: performance, reliability, security, scalability indices (0-100)."""
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  28. REFINED NETWORK ANALYSIS")
        print(f"{'='*60}{c.END}")

        def rating_of(pct):
            if pct >= 90: return "excellent"
            if pct >= 75: return "good"
            if pct >= 55: return "fair"
            if pct >= 35: return "poor"
            return "critical"

        def combine(components):
            present = {k: v for k, v in components.items() if v is not None}
            score = round(sum(present.values()) / len(present), 1) if present else 0.0
            return score, rating_of(score), present

        bw_d = self.scores.get("bandwidth", {}).get("details", {})
        ssl_d = self.scores.get("ssl", {}).get("details", {})
        tcp_d = self.scores.get("tcp", {}).get("details", {})
        http_d = self.scores.get("http", {}).get("details", {})
        cong_d = self.scores.get("congestion", {}).get("details", {})
        tfo_d = self.scores.get("tfo", {}).get("details", {})
        tls13_d = self.scores.get("tls13", {}).get("details", {})
        quic_d = self.scores.get("quic", {}).get("details", {})
        prio_d = self.scores.get("priority", {}).get("details", {})
        coal_d = self.scores.get("coalesce", {}).get("details", {})
        rel_d = self.scores.get("reliability", {}).get("details", {})
        dns_d = self.scores.get("dns", {}).get("details", {})
        res_d = self.scores.get("resilience", {}).get("details", {})
        cdn_d = self.scores.get("cdn", {}).get("details", {})
        audit_d = self.scores.get("audit", {}).get("details", {})
        enc_d = self.scores.get("encryption", {}).get("details", {})
        cert_d = self.scores.get("certchain", {}).get("details", {})
        portsec_d = self.scores.get("portsec", {}).get("details", {})
        scale_d = self.scores.get("scalability", {}).get("details", {})
        lat_d = self.scores.get("latency", {}).get("details", {})

        perf_c = {}
        ttfb = bw_d.get("ttfb_ms", -1)
        perf_c["ttfb"] = 100 if 0 <= ttfb < 200 else 70 if 0 <= ttfb < 400 else 40 if 0 <= ttfb < 800 else 15 if ttfb > 0 else None
        hs = ssl_d.get("handshake_time_ms", -1)
        perf_c["tls_handshake"] = 100 if 0 <= hs < 150 else 75 if 0 <= hs < 300 else 45 if 0 <= hs < 600 else 15 if hs > 0 else None
        tcp_avg = tcp_d.get("connection_quality", {}).get("avg_ms", -1)
        perf_c["tcp_connect"] = 100 if 0 <= tcp_avg < 50 else 75 if 0 <= tcp_avg < 120 else 45 if 0 <= tcp_avg < 300 else 15 if tcp_avg >= 0 else None
        speed = bw_d.get("download_speed_mbps", -1)
        perf_c["throughput"] = 100 if speed > 25 else 80 if speed > 10 else 55 if speed > 2 else 25 if speed >= 0 else None
        cong_idx = cong_d.get("congestion_index", -1)
        perf_c["congestion"] = cong_idx if cong_idx >= 0 else None
        mux = http_d.get("multiplex_analysis", {}).get("speedup_ratio", 0)
        perf_c["multiplexing"] = 100 if mux >= 3 else 80 if mux >= 2 else 60 if mux >= 1.3 else 35 if mux > 0 else None
        perf_c["tcp_fast_open"] = 100 if tfo_d.get("server_tfo") else 60 if tfo_d.get("syn_data_sent") else 30 if tfo_d.get("local_client_enabled") else None
        if tls13_d.get("tls13_supported"):
            hs13 = tls13_d.get("handshake_tls13_ms", -1)
            perf_c["tls13"] = 100 if 0 <= hs13 < 150 else 75 if hs13 > 0 else 65
        else:
            perf_c["tls13"] = None
        if quic_d:
            perf_c["http3_quic"] = 100 if quic_d.get("quic_rating") in ("excellent", "good") else 60 if quic_d.get("h3_advertised") else 20
        else:
            perf_c["http3_quic"] = None
        ping_avg = lat_d.get("ping_avg_ms", -1)
        perf_c["rtt"] = 100 if 0 <= ping_avg < 20 else 80 if 0 <= ping_avg < 50 else 55 if 0 <= ping_avg < 120 else 25 if ping_avg >= 0 else None
        perf_score, perf_rating, perf_present = combine(perf_c)

        rel_c = {}
        sr = rel_d.get("success_rate_pct", -1)
        rel_c["success_rate"] = sr if sr >= 0 else None
        avg_ms = rel_d.get("avg_ms", 0) or 0
        std_ms = rel_d.get("stddev_ms")
        if avg_ms > 0 and std_ms is not None:
            cv = std_ms / avg_ms
            rel_c["latency_stability"] = 100 if cv < 0.15 else 75 if cv < 0.3 else 45 if cv < 0.6 else 20
        else:
            rel_c["latency_stability"] = None
        resolver_total = rel_d.get("resolver_total", 0)
        resolver_ok = rel_d.get("resolver_success", 0)
        rel_c["resolver_reach"] = round((resolver_ok / resolver_total) * 100, 1) if resolver_total else None
        rel_c["keep_alive"] = 100 if rel_d.get("keep_alive") else 40
        rel_c["cdn_layer"] = 100 if rel_d.get("cdn_redundancy") else 45
        rel_c["dual_stack"] = 100 if res_d.get("dual_stack") else 50
        retrans = tcp_d.get("congestion_control", {}).get("remote_total_retrans", -1)
        rel_c["retransmissions"] = 100 if retrans == 0 else 70 if 0 < retrans <= 5 else 40 if 5 < retrans <= 20 else 15 if retrans > 20 else None
        loss = cong_d.get("packet_loss_pct", -1)
        rel_c["packet_loss"] = 100 if loss >= 0 and loss <= 0 else 75 if 0 < loss < 1 else 45 if 1 <= loss < 3 else 15 if loss >= 3 else None
        rel_c["http3_failover"] = 100 if quic_d.get("h3_advertised") or quic_d.get("h3_direct_ok") else 50 if quic_d else None
        rel_score, rel_rating, rel_present = combine(rel_c)

        sec_c = {}
        sev = audit_d.get("finding_counts", {})
        crit = sev.get("critical", 0)
        high = sev.get("high", 0)
        sec_c["audit_findings"] = 100 if crit == 0 and high == 0 else 70 if crit == 0 and high <= 2 else 40 if crit == 0 else 10
        enc_rating = enc_d.get("encryption_rating", "")
        sec_c["encryption"] = {"excellent": 100, "good": 85, "fair": 55, "poor": 15}.get(enc_rating, 40 if enc_d else None)
        sec_c["cert_chain"] = 100 if cert_d.get("chain_verified") else 60 if cert_d.get("chain_length", 0) > 1 else 30 if cert_d.get("chain_length", 0) else None
        exposure = portsec_d.get("exposure", {})
        sec_c["port_exposure"] = 100 if not exposure.get("critical") and not exposure.get("high") else 60 if not exposure.get("critical") else 20
        sec_c["dnssec"] = 100 if dns_d.get("dnssec", {}).get("enabled") else 45
        sec_c["tls13"] = 100 if tls13_d.get("tls13_supported") else 30 if tls13_d else None
        hsts = ssl_d.get("hsts", False)
        sec_c["hsts"] = 100 if hsts else 40
        sec_c["http_headers"] = min(100, (audit_d.get("security_headers_present", 0) / 7) * 100) if audit_d.get("security_headers_present") is not None else None
        weak_ok = not enc_d.get("weak_ciphers_accepted")
        sec_c["weak_ciphers"] = 100 if weak_ok and enc_d else 20 if enc_d else None
        sec_score, sec_rating, sec_present = combine(sec_c)

        scl_c = {}
        sig = scale_d.get("signals", {})
        scl_c["core_signals"] = round((sum(1 for v in sig.values() if v) / max(len(sig), 1)) * 100, 1) if sig else None
        scl_c["compression"] = 100 if scale_d.get("compression_enabled") else 30
        scl_c["cacheability"] = 100 if scale_d.get("cache_control") or scale_d.get("etag") else 40
        scl_c["http2"] = 100 if http_d.get("http2") else 40
        scl_c["http3"] = 100 if quic_d.get("h3_advertised") or quic_d.get("h3_direct_ok") else 45 if quic_d else None
        scl_c["coalescing"] = 100 if coal_d.get("coalescing_ready") else 55 if coal_d.get("http2") else 25 if coal_d else None
        scl_c["priority"] = 100 if prio_d.get("response_priority") and prio_d.get("early_hints") else 70 if prio_d.get("priority_support") else 35 if prio_d else None
        scl_c["multi_ip"] = 100 if len(self.ip_addresses) > 1 else 50
        scl_c["rate_limiting"] = 100 if audit_d.get("rate_limit_headers") else 45
        scl_score, scl_rating, scl_present = combine(scl_c)

        self.refined_analysis = {
            "performance": {"score": perf_score, "rating": perf_rating, "components": perf_present},
            "reliability": {"score": rel_score, "rating": rel_rating, "components": rel_present},
            "security": {"score": sec_score, "rating": sec_rating, "components": sec_present},
            "scalability": {"score": scl_score, "rating": scl_rating, "components": scl_present},
        }

        self._log("--- Refined Analysis Indices ---", "info")
        labels = {
            "performance": "Performance",
            "reliability": "Reliability",
            "security": "Security",
            "scalability": "Scalability",
        }
        for key, data in self.refined_analysis.items():
            label = labels.get(key, key.title())
            n_comp = len(data["components"])
            self._log(f"  {label}: {data['score']}% ({data['rating']}, {n_comp} signals)", "ok")
        return self.refined_analysis

    def calculate_total_score(self):
        total = sum(s.get("score", 0) for s in self.scores.values())
        max_total = sum(s.get("max_score", 0) for s in self.scores.values())
        return total, max_total

    def get_grade(self, score):
        c = self.colors
        if score >= 90: return "A", c.GREEN
        if score >= 70: return "B", c.CYAN
        if score >= 50: return "C", c.YELLOW
        if score >= 30: return "D", c.RED
        return "F", c.RED

    def _pct(self, category):
        data = self.scores.get(category, {})
        mx = data.get("max_score", 0)
        if mx <= 0:
            return 0.0
        return round((data.get("score", 0) / mx) * 100, 1)

    def calculate_refined_scores(self):
        """Refined multi-axis scoring: quality, security, performance, reliability.

        Each axis is a weighted blend of category percentages; components are
        stored so the breakdown can be shown in reports and exports.
        """
        c = self.colors

        def weighted(components):
            num = 0.0
            den = 0.0
            breakdown = {}
            for cat, weight in components.items():
                if cat in self.scores:
                    pct = self._pct(cat)
                    num += pct * weight
                    den += weight
                    breakdown[cat] = {"pct": pct, "weight": weight}
            if den == 0:
                return 0.0, {}
            return round(num / den, 1), breakdown

        axes = {
            "network_quality": {
                "latency": 18, "bandwidth": 13, "congestion": 16, "pmtu": 7,
                "ipv6": 6, "routing": 6, "scalability": 10, "reliability": 9,
                "quic": 5, "tfo": 4, "coalesce": 3, "priority": 3,
            },
            "security": {
                "ssl": 16, "netsec": 16, "dns": 8, "http": 8,
                "encryption": 12, "certchain": 8, "protosec": 7, "portsec": 6,
                "tls13": 10, "audit": 9,
            },
            "performance": {
                "tcp": 12, "ssl": 8, "http": 12, "bandwidth": 14,
                "congestion": 10, "scalability": 10, "resilience": 6, "latency": 6,
                "tls13": 6, "tfo": 6, "quic": 5, "priority": 3, "coalesce": 3,
            },
            "reliability": {
                "dns": 14, "congestion": 16, "cdn": 8, "tcp": 10,
                "latency": 8, "reliability": 14, "resilience": 10,
                "quic": 5, "tfo": 5, "coalesce": 3, "fingerprint": 2, "pmtu": 5,
            },
        }

        def axis_grade(pct):
            if pct >= 90: return "A"
            if pct >= 75: return "B"
            if pct >= 55: return "C"
            if pct >= 35: return "D"
            return "F"

        def axis_descriptor(pct):
            if pct >= 90: return "Excellent"
            if pct >= 75: return "Very Good"
            if pct >= 55: return "Good"
            if pct >= 40: return "Needs Work"
            if pct >= 25: return "Poor"
            return "Critical"

        total_categories = max(len(self.scores), 1)
        self.refined_scores = {}
        for axis_name, components in axes.items():
            score, breakdown = weighted(components)
            confidence = round(min(99.0, (len(breakdown) / total_categories) * 100), 1)
            self.refined_scores[axis_name] = {
                "score": score,
                "grade": axis_grade(score),
                "descriptor": axis_descriptor(score),
                "confidence": confidence,
                "components": breakdown,
            }

        self._log("--- Refined Scores ---", "info")
        for axis, data in self.refined_scores.items():
            label = axis.replace("_", " ").title()
            self._log(f"  {label}: {data['score']}% (grade {data['grade']}, {data['descriptor']}, confidence {data['confidence']}%)", "ok")
        return self.refined_scores

    def build_recommendations(self):
        """Generate prioritized optimization recommendations from all analyses."""
        recs = []

        def add(severity, category, message):
            recs.append({"severity": severity, "category": category, "message": message})

        ssl_d = self.scores.get("ssl", {}).get("details", {})
        http_d = self.scores.get("http", {}).get("details", {})
        netsec_d = self.scores.get("netsec", {}).get("details", {})
        dns_d = self.scores.get("dns", {}).get("details", {})
        cong_d = self.scores.get("congestion", {}).get("details", {})
        pmtu_d = self.scores.get("pmtu", {}).get("details", {})
        ipv6_d = self.scores.get("ipv6", {}).get("details", {})
        bw_d = self.scores.get("bandwidth", {}).get("details", {})
        cdn_d = self.scores.get("cdn", {}).get("details", {})
        route_d = self.scores.get("routing", {}).get("details", {})
        tcp_d = self.scores.get("tcp", {}).get("details", {})

        if self.parsed.scheme != "https":
            add("critical", "ssl", "Serve the site over HTTPS and redirect all HTTP traffic.")
        if ssl_d and not ssl_d.get("hsts", False):
            add("high", "ssl", "Enable HSTS (Strict-Transport-Security) with a long max-age.")
        tls_versions = ssl_d.get("tls_versions", {})
        if tls_versions.get("TLS 1.0") or tls_versions.get("TLS 1.1"):
            add("high", "ssl", "Disable legacy TLS 1.0/1.1; negotiate TLS 1.2+ only.")
        if tls_versions and not tls_versions.get("TLS 1.3"):
            add("medium", "ssl", "Enable TLS 1.3 for faster handshakes and improved security.")
        if ssl_d and not ssl_d.get("ocsp_stapling", False):
            add("medium", "ssl", "Enable OCSP stapling to avoid client-side revocation checks.")
        if ssl_d and not ssl_d.get("perfect_forward_secrecy", False):
            add("high", "ssl", "Use ECDHE/DHE cipher suites for perfect forward secrecy.")
        tls_perf = ssl_d.get("tls_performance", {})
        if tls_perf.get("resumed_handshake_ms", -1) < 0:
            add("low", "ssl", "Session resumption appears ineffective; check session ticket configuration.")

        sec_headers = http_d.get("security_headers", {})
        missing_headers = [k for k, v in sec_headers.items() if not v]
        if missing_headers:
            pretty = ", ".join(k.replace("_", "-").title() for k in missing_headers)
            add("medium", "http", f"Add missing security headers: {pretty}.")
        if not http_d.get("http2", False):
            add("medium", "http", "Enable HTTP/2 for multiplexed streams and lower latency.")
        if not http_d.get("http3", False):
            add("low", "http", "Consider HTTP/3 (QUIC) via Alt-Svc for lossy-network resilience.")

        multiplex = http_d.get("multiplex_analysis", {})
        if multiplex.get("speedup_ratio", 0) and multiplex.get("speedup_ratio", 0) < 1.5 and http_d.get("http2"):
            add("medium", "http", "HTTP/2 multiplex speedup is low; verify server stream limits and HPACK efficiency.")
        reuse = http_d.get("connection_reuse", {})
        if reuse.get("reuse_savings_pct", 100) < 15:
            add("medium", "http", "Connection reuse savings are low; raise Keep-Alive timeout and enable pooling.")

        if netsec_d.get("dns_hijack_detected"):
            add("critical", "netsec", "Investigate potential DNS hijacking immediately.")
        risk = netsec_d.get("risk_assessment", {})
        if risk.get("dangerous_open"):
            ports_str = ", ".join(str(p) for p in risk["dangerous_open"])
            add("high", "netsec", f"Restrict exposure of dangerous open ports: {ports_str}.")
        if risk.get("risk_level") in ("medium", "high"):
            add("high", "netsec", "Reduce the attack surface: close unused services and place admin ports behind a VPN.")

        if dns_d and not dns_d.get("dnssec", {}).get("enabled", False):
            add("medium", "dns", "Sign the zone with DNSSEC to prevent cache poisoning.")
        if dns_d.get("propagation_consistent") is False:
            add("medium", "dns", "DNS propagation is inconsistent; check resolver cache and TTL settings.")
        if dns_d.get("doh_success_count", 3) < 3:
            add("low", "dns", "Some DNS-over-HTTPS providers failed; verify authoritative NS reachability.")

        if not ipv6_d.get("aaaa_records"):
            add("medium", "ipv6", "Publish AAAA records to enable IPv6 connectivity.")
        elif ipv6_d.get("ipv6_connect_ms", -1) < 0:
            add("high", "ipv6", "AAAA records exist but IPv6 TCP connect failed; verify the v6 routing/firewall path.")

        loss = cong_d.get("packet_loss_pct", 0)
        if loss >= 3:
            add("high", "congestion", f"Packet loss is {loss}%; investigate uplink quality or provider congestion.")
        elif loss >= 1:
            add("medium", "congestion", f"Packet loss is {loss}%; monitor and consider ECMP/QoS tuning.")
        jit = cong_d.get("jitter_mean_abs_ms", -1)
        if jit >= 15:
            add("medium", "congestion", f"Jitter ({jit}ms) may harm VoIP/real-time traffic; apply traffic shaping.")
        if cong_d.get("congestion_level") in ("moderate", "severe"):
            add("high", "congestion", "Significant congestion detected; review bufferbloat (try CAKE/FQ-CoDel qdisc).")

        effective_mtu = pmtu_d.get("effective_mtu", -1)
        if 0 < effective_mtu < 1400:
            add("medium", "pmtu", f"Path MTU is {effective_mtu}; clamp TCP MSS to avoid fragmentation/blackholes.")
        if pmtu_d.get("blackhole_risk"):
            add("high", "pmtu", "MTU below 1280 risks blackholing; fix ICMP filtering or tunnel MTU configuration.")

        ttfb = bw_d.get("ttfb_ms", -1)
        if ttfb > 600:
            add("high", "bandwidth", f"TTFB is {ttfb}ms; optimize server response time or enable edge caching.")
        elif ttfb > 300:
            add("medium", "bandwidth", f"TTFB is {ttfb}ms; profile slow queries/middleware and cache aggressively.")
        if bw_d.get("consistency") == "Inconsistent":
            add("medium", "bandwidth", "TTFB is inconsistent; check backend load variance and connection pooling.")

        if not cdn_d.get("cdn_providers"):
            add("medium", "cdn", "No CDN detected; deploy one to reduce origin load and global latency.")
        elif cdn_d.get("cache_status") and cdn_d.get("cache_status", "").lower() not in ("hit", "true", "yes", "stale"):
            add("low", "cdn", "CDN cache is not hitting; tune cache keys/TTLs for higher hit ratios.")

        rpki = route_d.get("rpki_state", "unknown")
        if rpki.lower() in ("invalid", "not-found"):
            add("medium", "routing", f"RPKI state is '{rpki}'; publish ROAs to prevent route hijacks.")

        cc = tcp_d.get("congestion_control", {})
        if cc.get("local_cc") in ("reno", "cubic") and "bbr" in cc.get("available_cc", []):
            add("low", "tcp", "BBR is available locally; consider enabling it for better throughput on lossy paths.")
        retrans = cc.get("remote_total_retrans", -1)
        if isinstance(retrans, int) and retrans > 10:
            add("medium", "tcp", f"High TCP retransmissions observed ({retrans}); check for loss or middlebox interference.")

        audit_d = self.scores.get("audit", {}).get("details", {})
        enc_d = self.scores.get("encryption", {}).get("details", {})
        cert_d = self.scores.get("certchain", {}).get("details", {})
        protosec_d = self.scores.get("protosec", {}).get("details", {})
        portsec_d = self.scores.get("portsec", {}).get("details", {})
        rel_d = self.scores.get("reliability", {}).get("details", {})
        scale_d = self.scores.get("scalability", {}).get("details", {})
        res_d = self.scores.get("resilience", {}).get("details", {})

        for item in audit_d.get("findings", []):
            sev = item.get("severity", "info")
            if sev in ("critical", "high", "medium"):
                add(sev, "audit", f"{item.get('name', 'Audit finding')}: {item.get('detail', '')}")

        if enc_d.get("weak_ciphers_accepted"):
            weak = ", ".join(enc_d["weak_ciphers_accepted"])
            add("critical", "encryption", f"Server accepts weak cipher families: {weak}. Disable them immediately.")
        if enc_d.get("weak_versions_offered"):
            versions = ", ".join(enc_d["weak_versions_offered"])
            add("high", "encryption", f"Weak TLS versions offered ({versions}); restrict negotiation to TLS 1.2+.")
        if enc_d.get("encrypted") and enc_d.get("encryption_rating") in ("fair", "poor"):
            add("medium", "encryption", "Encryption posture is below modern baselines; prefer AEAD ciphers with ephemeral key exchange.")

        days = cert_d.get("days_to_expiry", -1)
        if 0 <= days <= 14:
            add("critical", "certchain", f"Certificate expires in {days} days; renew immediately.")
        elif 0 <= days <= 60:
            add("medium", "certchain", f"Certificate expires in {days} days; schedule a renewal.")
        if cert_d.get("self_signed"):
            add("high", "certchain", "Leaf certificate is self-signed; obtain a certificate from a trusted CA.")
        if cert_d.get("chain_length", 0) == 1 and self.parsed.scheme == "https":
            add("medium", "certchain", "Incomplete certificate chain (leaf only); serve intermediate certificates.")
        if cert_d.get("weak_signature"):
            add("high", "certchain", "Certificate uses a weak signature algorithm (SHA-1/MD5); reissue with SHA-256+.")
        if cert_d.get("chain_length", 0) > 0 and not cert_d.get("chain_verified"):
            add("medium", "certchain", "Certificate chain failed OpenSSL verification; check intermediates and trust anchors.")

        if protosec_d.get("insecure_tls_versions"):
            add("high", "protosec", "Legacy TLS versions observed on the wire; disable TLS 1.0/1.1 everywhere.")
        if protosec_d.get("http_to_https_redirect") is False and self.parsed.scheme == "https":
            add("medium", "protosec", "Add an HTTP-to-HTTPS redirect on port 80 so clients always upgrade.")
        if protosec_d.get("starttls"):
            for svc, info in protosec_d["starttls"].items():
                if not info.get("starttls_advertised"):
                    add("medium", "protosec", f"{svc} does not advertise STARTTLS; enable it or close the cleartext port.")
        if protosec_d.get("websocket_enabled") and self.parsed.scheme != "https":
            add("high", "protosec", "WebSocket traffic is accepted without TLS; require wss:// only.")

        exposure = portsec_d.get("exposure", {})
        if exposure.get("critical"):
            crit = ", ".join(str(p) for p in exposure["critical"])
            add("critical", "portsec", f"Critical-risk ports are exposed: {crit}. Firewall them now.")
        if exposure.get("high"):
            high = ", ".join(str(p) for p in exposure["high"])
            add("high", "portsec", f"High-risk ports are exposed: {high}. Restrict to trusted sources.")
        if portsec_d.get("version_disclosing_ports"):
            ports = ", ".join(str(p) for p in portsec_d["version_disclosing_ports"])
            add("low", "portsec", f"Service banners leak version strings on ports {ports}; suppress versions.")

        success_rate = rel_d.get("success_rate_pct", 100)
        if success_rate < 100:
            add("high" if success_rate < 90 else "medium", "reliability",
                f"Request success rate is {success_rate}%; investigate upstream errors and timeouts.")
        if rel_d.get("stddev_ms") is not None and rel_d.get("avg_ms"):
            if rel_d["stddev_ms"] > rel_d["avg_ms"] * 0.5:
                add("medium", "reliability", "Response times are highly variable; check backend load and connection pooling.")

        signals = scale_d.get("signals", {})
        if not signals.get("compressed"):
            add("medium", "scalability", "Enable gzip/brotli response compression to reduce transfer sizes.")
        if not signals.get("cacheable"):
            add("medium", "scalability", "Add Cache-Control/ETag/Expires headers so caches and CDNs can scale load.")
        if not signals.get("cdn"):
            add("low", "scalability", "No CDN in front of the origin; add one to absorb traffic spikes.")
        if not signals.get("http2"):
            add("low", "scalability", "HTTP/2 multiplexing is off; enable it to handle more concurrent streams per connection.")

        res_signals = res_d.get("signals", {})
        if not res_signals.get("http3_quic"):
            add("low", "resilience", "Enable HTTP/3 (QUIC) for better loss tolerance and connection migration.")
        if not res_signals.get("dual_stack") and ipv6_d.get("aaaa_records"):
            add("medium", "resilience", "AAAA records exist but the IPv6 path is not healthy; fix v6 routing for dual-stack failover.")
        if not res_signals.get("graceful_errors"):
            add("medium", "resilience", "Error pages leak internals; serve generic error pages to fail gracefully without disclosure.")
        if res_signals.get("cdn_layer") is False and not cdn_d.get("cdn_providers"):
            add("low", "resilience", "No CDN failover layer; consider multi-region origin replication.")
        if res_d.get("rate_limited_under_load"):
            add("info", "resilience", "Server throttled under repeated requests; verify rate limits allow legitimate bursts.")

        quic_d = self.scores.get("quic", {}).get("details", {})
        tls13_d = self.scores.get("tls13", {}).get("details", {})
        tfo_d = self.scores.get("tfo", {}).get("details", {})
        coal_d = self.scores.get("coalesce", {}).get("details", {})
        prio_d = self.scores.get("priority", {}).get("details", {})

        if self.parsed.scheme == "https" and not quic_d.get("h3_advertised") and not quic_d.get("h3_direct_ok"):
            add("medium", "quic", "Advertise HTTP/3 via Alt-Svc and enable QUIC on UDP/443 to avoid head-of-line blocking.")
        if quic_d.get("h3_advertised") and not quic_d.get("udp_reachable"):
            add("high", "quic", "Alt-Svc advertises HTTP/3 but UDP/443 did not respond; open UDP/443 through firewalls and WAF rules.")
        if self.parsed.scheme == "https" and tls13_d and not tls13_d.get("tls13_supported"):
            add("high", "tls13", "TLS 1.3 is unavailable; enable it to remove a handshake round-trip and modernize ciphers.")
        if tls13_d.get("tls13_supported") and tls13_d.get("early_data_0rtt") is not True:
            add("low", "tls13", "Consider TLS 1.3 0-RTT early data for repeat visitors, with anti-replay protection on unsafe methods.")
        if tls13_d.get("handshake_tls13_ms", -1) > 300:
            add("medium", "tls13", f"TLS 1.3 handshake is {tls13_d.get('handshake_tls13_ms')}ms; check session tickets and key-share group selection.")
        if tfo_d and not tfo_d.get("server_tfo"):
            add("low", "tfo", "TCP Fast Open is not confirmed on the server; enable TFO to save one RTT on repeat connections.")
        if tfo_d and tfo_d.get("local_client_enabled") is False:
            add("info", "tfo", "This analyzer host has TCP Fast Open disabled (tcp_fastopen sysctl); enable client TFO for faster connects.")
        if coal_d and not coal_d.get("coalescing_ready") and coal_d.get("http2"):
            add("medium", "coalesce", "HTTP/2 coalescing is not ready; make certificate SANs cover alternate hostnames served from the same IP.")
        if prio_d and not prio_d.get("response_priority"):
            add("low", "priority", "Adopt RFC 9218 Priority response headers so clients can schedule urgent resources first.")
        if prio_d and not prio_d.get("early_hints"):
            add("low", "priority", "Send 103 Early Hints with Link: rel=preload to start subresource fetches before the origin finishes.")

        ra = getattr(self, "refined_analysis", {}) or {}
        perf_idx = ra.get("performance", {})
        if perf_idx.get("score", 100) < 55:
            add("high", "bandwidth",
                f"Refined performance index is {perf_idx.get('score')}% ({perf_idx.get('rating')}); prioritize TTFB, handshake, and throughput fixes.")
        rel_idx = ra.get("reliability", {})
        if rel_idx.get("score", 100) < 70:
            add("medium", "reliability",
                f"Refined reliability index is {rel_idx.get('score')}% ({rel_idx.get('rating')}); improve resolver reachability and request consistency.")
        sec_idx = ra.get("security", {})
        if sec_idx.get("score", 100) < 70:
            add("high", "netsec",
                f"Refined security index is {sec_idx.get('score')}% ({sec_idx.get('rating')}); remediate audit findings and encryption gaps first.")
        scl_idx = ra.get("scalability", {})
        if scl_idx.get("score", 100) < 60:
            add("medium", "scalability",
                f"Refined scalability index is {scl_idx.get('score')}% ({scl_idx.get('rating')}); strengthen caching, compression, and edge layers.")

        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        recs.sort(key=lambda r: order.get(r["severity"], 9))
        self.recommendations = recs
        self._log(f"Generated {len(recs)} optimization recommendations", "ok")
        return recs

    def print_topology(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  NETWORK TOPOLOGY VISUALIZATION")
        print(f"{'='*60}{c.END}")

        lines = []
        geo = self.scores.get("latency", {}).get("details", {}).get("geolocation", {})
        asn = self.scores.get("latency", {}).get("details", {}).get("asn", "Unknown ASN")
        cdn = self.scores.get("cdn", {}).get("details", {}).get("cdn_providers", [])
        hops = self.scores.get("latency", {}).get("details", {}).get("traceroute", [])
        ipv6 = self.scores.get("ipv6", {}).get("details", {})
        route = self.scores.get("routing", {}).get("details", {})
        edge = self.scores.get("cdn", {}).get("details", {}).get("edge_location", "")

        print(f"\n  {c.BOLD}Logical topology:{c.END}\n")
        print(f"    {c.CYAN}[ Client / This Host ]{c.END}")
        print(f"    {c.GRAY}    |{c.END}")
        print(f"    {c.GRAY}    +-- local CC: {self.scores.get('tcp', {}).get('details', {}).get('congestion_control', {}).get('local_cc', 'unknown')}{c.END}")

        if geo:
            loc = f"{geo.get('city', '?')}, {geo.get('country', '?')}"
            print(f"    {c.GRAY}    |{c.END}")
            print(f"    {c.CYAN}[ Origin / Target ] {self.domain}{c.END}")
            print(f"    {c.GRAY}    +-- location: {loc}{c.END}")
            print(f"    {c.GRAY}    +-- network: {asn}{c.END}")
        else:
            print(f"    {c.GRAY}    |{c.END}")
            print(f"    {c.CYAN}[ Origin / Target ] {self.domain}{c.END}")

        if route.get("announced_prefix"):
            print(f"    {c.GRAY}    +-- prefix: {route['announced_prefix']}{c.END}")
        if route.get("origin_asns"):
            asns_joined = ", ".join("AS" + a for a in route["origin_asns"])
            print(f"    {c.GRAY}    +-- origin: {asns_joined} ({route.get('asn_name', 'n/a')}){c.END}")
            print(f"    {c.GRAY}    +-- RPKI: {route.get('rpki_state', 'unknown')}{c.END}")

        if cdn:
            edge_label = edge or "edge"
            print(f"    {c.GRAY}    |{c.END}")
            print(f"    {c.MAGENTA}[ CDN Layer ] {', '.join(cdn)}{c.END}")
            print(f"    {c.GRAY}    +-- edge: {edge_label}{c.END}")

        if ipv6.get("aaaa_records"):
            print(f"    {c.GRAY}    |{c.END}")
            print(f"    {c.CYAN}[ IPv6 Path ]{c.END}")
            v6_joined = ", ".join(ipv6["aaaa_records"][:3])
            print(f"    {c.GRAY}    +-- AAAA: {v6_joined}{c.END}")
            v6_conn = ipv6.get("ipv6_connect_ms", -1)
            print(f"    {c.GRAY}    +-- connect: {v6_conn}ms{c.END}")

        if hops:
            print(f"\n  {c.BOLD}Router-level path (traceroute):{c.END}\n")
            print(f"    {c.CYAN}+- this host{c.END}")
            for i, hop in enumerate(hops):
                is_last = i == len(hops) - 1
                branch = "\\-" if is_last else "+-"
                hip = hop.get("ip", "*")
                hlat = hop.get("latency", "*")
                hnum = hop.get("hop", i + 1)
                try:
                    ip_obj = ipaddress.ip_address(hip)
                    if ip_obj.is_private:
                        hip = f"{hip} (private)"
                except ValueError:
                    pass
                color = c.RED if hip == "*" else c.WHITE
                print(f"    {c.GRAY}{branch}{c.END} hop {hnum}: {color}{hip}{c.END} {c.GRAY}{hlat}{c.END}")
                if not is_last:
                    print(f"    {c.GRAY}   |{c.END}")
        else:
            print(f"\n  {c.GRAY}  (traceroute data unavailable){c.END}")

        path = self.scores.get("latency", {}).get("details", {}).get("path_analysis", {})
        if path:
            print(f"\n  {c.BOLD}Path summary:{c.END}")
            print(f"    hops={path.get('total_hops', '?')}  timeouts={path.get('timeout_hops', '?')}  hop-loss={path.get('loss_pct', '?')}%")

        enc_d = self.scores.get("encryption", {}).get("details", {})
        cert_d = self.scores.get("certchain", {}).get("details", {})
        protosec_d = self.scores.get("protosec", {}).get("details", {})
        portsec_d = self.scores.get("portsec", {}).get("details", {})
        rel_d = self.scores.get("reliability", {}).get("details", {})
        scale_d = self.scores.get("scalability", {}).get("details", {})
        res_d = self.scores.get("resilience", {}).get("details", {})
        quic_d = self.scores.get("quic", {}).get("details", {})
        tls13_d = self.scores.get("tls13", {}).get("details", {})
        tfo_d = self.scores.get("tfo", {}).get("details", {})
        coal_d = self.scores.get("coalesce", {}).get("details", {})
        prio_d = self.scores.get("priority", {}).get("details", {})
        ra = self.refined_analysis or {}

        print(f"\n  {c.BOLD}Transport & protocol layer:{c.END}")
        quic_state = "available" if (quic_d.get("h3_advertised") or quic_d.get("h3_direct_ok")) else "not advertised"
        quic_color = c.GREEN if quic_state == "available" else c.YELLOW
        variants = ", ".join(quic_d.get("h3_variants", [])) or "n/a"
        udp_state = "ok" if quic_d.get("udp_reachable") else "no"
        print(f"    QUIC/HTTP3: {quic_color}{quic_state}{c.END}  variants={variants}  udp443={udp_state}")
        tls13_state = "enabled" if tls13_d.get("tls13_supported") else "disabled"
        tls13_color = c.GREEN if tls13_state == "enabled" else c.RED
        hs13 = tls13_d.get("handshake_tls13_ms", -1)
        hs13_str = f"{hs13}ms" if hs13 >= 0 else "n/a"
        zero_rtt = tls13_d.get("early_data_0rtt")
        zero_str = "yes" if zero_rtt is True else "no" if zero_rtt is False else "unknown"
        group_str = tls13_d.get("key_share_group") or "n/a"
        print(f"    TLS 1.3: {tls13_color}{tls13_state}{c.END}  handshake={hs13_str}  0-RTT={zero_str}  group={group_str}")
        tfo_state = "server confirmed" if tfo_d.get("server_tfo") else "not confirmed"
        tfo_color = c.GREEN if tfo_d.get("server_tfo") else c.YELLOW
        local_tfo = "on" if tfo_d.get("local_client_enabled") else "off"
        print(f"    TCP Fast Open: {tfo_color}{tfo_state}{c.END}  local-client={local_tfo}  gain={tfo_d.get('tfo_gain_pct', 0)}%")
        coal_ready = "ready" if coal_d.get("coalescing_ready") else "not ready"
        coal_color = c.GREEN if coal_d.get("coalescing_ready") else c.YELLOW
        shared_n = len(coal_d.get("shared_ip_hosts", []))
        print(f"    H2 coalescing: {coal_color}{coal_ready}{c.END}  SANs={coal_d.get('san_count', 0)}  shared-hosts={shared_n}")
        prio_state = "RFC 9218" if prio_d.get("response_priority") else "absent"
        prio_color = c.GREEN if prio_d.get("response_priority") else c.YELLOW
        hints_state = "yes" if prio_d.get("early_hints") else "no"
        print(f"    Priority headers: {prio_color}{prio_state}{c.END}  early-hints={hints_state}  preloads={prio_d.get('preload_link_count', 0)}")

        print(f"\n  {c.BOLD}Security layer:{c.END}")
        rating = enc_d.get("encryption_rating", "n/a")
        rating_color = c.GREEN if rating in ("excellent", "good") else c.YELLOW if rating in ("fair",) else c.RED
        print(f"    encryption: {rating_color}{rating}{c.END}  cipher: {enc_d.get('negotiated_cipher', 'n/a')} ({enc_d.get('negotiated_bits', 0)} bits)")
        print(f"    PFS: {'yes' if enc_d.get('perfect_forward_secrecy') else 'no'}  AEAD: {'yes' if enc_d.get('aead_cipher') else 'no'}  weak ciphers accepted: {len(enc_d.get('weak_ciphers_accepted', []))}")
        days = cert_d.get("days_to_expiry", -1)
        days_str = f"{days}d" if days >= 0 else "n/a"
        print(f"    certificate: depth={cert_d.get('chain_length', 0)}  verified={'yes' if cert_d.get('chain_verified') else 'no'}  expires in {days_str}")
        prot_issues = len(protosec_d.get("findings", []))
        print(f"    protocol issues: {prot_issues}  HTTP->HTTPS redirect: {'yes' if protosec_d.get('http_to_https_redirect') else 'no'}")
        exposure = portsec_d.get("exposure", {})
        crit = len(exposure.get("critical", []))
        high = len(exposure.get("high", []))
        exposure_color = c.GREEN if crit == 0 and high == 0 else c.RED
        print(f"    port exposure: {c.END}{exposure_color}{crit} critical / {high} high risk ports open{c.END}  surface: {portsec_d.get('scanned_ports', 0)} probed")
        sec_idx = ra.get("security", {})
        if sec_idx:
            sec_pct = sec_idx.get("score", 0)
            sec_rate = sec_idx.get("rating", "n/a")
            sec_i_color = c.GREEN if sec_rate in ("excellent", "good") else c.YELLOW if sec_rate == "fair" else c.RED
            ssl_hsts = self.scores.get("ssl", {}).get("details", {}).get("hsts", False)
            t13_flag = "yes" if tls13_d.get("tls13_supported") else "no"
            hsts_flag = "yes" if ssl_hsts else "no"
            print(f"    security index: {sec_i_color}{sec_pct}% ({sec_rate}){c.END}  tls13={t13_flag}  hsts={hsts_flag}")

        print(f"\n  {c.BOLD}Operational layer:{c.END}")
        rel_rating = rel_d.get("reliability_rating", "n/a")
        rel_color = c.GREEN if rel_rating in ("excellent", "good") else c.YELLOW
        print(f"    reliability: {rel_color}{rel_rating}{c.END}  success={rel_d.get('success_rate_pct', 'n/a')}%  resolvers={rel_d.get('resolver_success', 0)}/{rel_d.get('resolver_total', 0)}")
        scale_ready = scale_d.get("readiness", "n/a")
        scale_color = c.GREEN if scale_ready in ("excellent", "good") else c.YELLOW
        print(f"    scalability: {scale_color}{scale_ready}{c.END}  signals={scale_d.get('signals_active', 0)}/8  compression={scale_d.get('content_encoding') or 'none'}")
        res_rating = res_d.get("resilience_rating", "n/a")
        res_color = c.GREEN if res_rating in ("excellent", "good") else c.YELLOW
        print(f"    resilience: {res_color}{res_rating}{c.END}  signals={res_d.get('signals_active', 0)}/7  reachable IPs={res_d.get('ips_reachable', 0)}/{res_d.get('ips_total', 0)}")
        perf_idx = ra.get("performance", {})
        rel_idx = ra.get("reliability", {})
        scl_idx = ra.get("scalability", {})
        if perf_idx:
            p_rate = perf_idx.get("rating", "n/a")
            p_color = c.GREEN if p_rate in ("excellent", "good") else c.YELLOW if p_rate == "fair" else c.RED
            print(f"    performance index: {p_color}{perf_idx.get('score', 0)}% ({p_rate}){c.END}")
        if rel_idx:
            r_rate = rel_idx.get("rating", "n/a")
            r_color = c.GREEN if r_rate in ("excellent", "good") else c.YELLOW if r_rate == "fair" else c.RED
            print(f"    reliability index: {r_color}{rel_idx.get('score', 0)}% ({r_rate}){c.END}")
        if scl_idx:
            s_rate = scl_idx.get("rating", "n/a")
            s_color = c.GREEN if s_rate in ("excellent", "good") else c.YELLOW if s_rate == "fair" else c.RED
            print(f"    scalability index: {s_color}{scl_idx.get('score', 0)}% ({s_rate}){c.END}")

        print()

    def print_performance_dashboard(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  PERFORMANCE COMPARISON DASHBOARD")
        print(f"{'='*60}{c.END}")

        rows = []

        def row(name, value, good, warn):
            rows.append((name, value, good, warn))

        dns_ms = self.scores.get("dns", {}).get("details", {}).get("dns_response_time_ms", -1)
        if dns_ms >= 0:
            row("DNS lookup", f"{dns_ms}ms", "<50ms", "<200ms",)

        ping_avg = self.scores.get("latency", {}).get("details", {}).get("ping_avg_ms", -1)
        if ping_avg >= 0:
            row("Ping RTT", f"{ping_avg}ms", "<30ms", "<100ms")

        ttfb = self.scores.get("bandwidth", {}).get("details", {}).get("ttfb_ms", -1)
        if ttfb >= 0:
            row("TTFB", f"{ttfb}ms", "<200ms", "<600ms")

        speed = self.scores.get("bandwidth", {}).get("details", {}).get("download_speed_mbps", -1)
        if speed >= 0:
            row("Download speed", f"{speed}Mbps", ">10Mbps", ">2Mbps")

        hs = self.scores.get("ssl", {}).get("details", {}).get("handshake_time_ms", -1)
        if hs >= 0:
            row("TLS handshake", f"{hs}ms", "<200ms", "<500ms")

        tcp_avg = self.scores.get("tcp", {}).get("details", {}).get("connection_quality", {}).get("avg_ms", -1)
        if tcp_avg >= 0:
            row("TCP connect", f"{tcp_avg}ms", "<50ms", "<150ms")

        jit = self.scores.get("congestion", {}).get("details", {}).get("jitter_mean_abs_ms", -1)
        if jit >= 0:
            row("Jitter", f"{jit}ms", "<2ms", "<10ms")

        loss = self.scores.get("congestion", {}).get("details", {}).get("packet_loss_pct", -1)
        if loss >= 0:
            row("Packet loss", f"{loss}%", "0%", "<1%")

        cong_idx = self.scores.get("congestion", {}).get("details", {}).get("congestion_index", -1)
        if cong_idx >= 0:
            row("Congestion index", f"{cong_idx}/100", ">85", ">65")

        mtu = self.scores.get("pmtu", {}).get("details", {}).get("effective_mtu", -1)
        if mtu >= 0:
            row("Path MTU", f"{mtu}B", "1500B", ">=1400B")

        hops = self.scores.get("latency", {}).get("details", {}).get("traceroute_hops", -1)
        if hops >= 0:
            row("Path hops", str(hops), "<=12", "<=20")

        mux = self.scores.get("http", {}).get("details", {}).get("multiplex_analysis", {})
        if mux.get("speedup_ratio", 0) > 0:
            row("H2 multiplex speedup", f"{mux['speedup_ratio']}x", ">=3x", ">=1.5x")

        reuse = self.scores.get("http", {}).get("details", {}).get("connection_reuse", {})
        if reuse.get("reuse_savings_pct", -1) >= 0:
            row("Conn reuse savings", f"{reuse['reuse_savings_pct']}%", ">=30%", ">=15%")

        v6 = self.scores.get("ipv6", {}).get("details", {}).get("ipv6_ping_avg_ms", -1)
        if v6 >= 0:
            row("IPv6 ping", f"{v6}ms", "compare v4", "ratio<=1.5")

        cert_days = self.scores.get("certchain", {}).get("details", {}).get("days_to_expiry", -1)
        if cert_days >= 0:
            row("Cert expiry", f"{cert_days}d", ">60d", ">14d")

        rel_rate = self.scores.get("reliability", {}).get("details", {}).get("success_rate_pct", -1)
        if rel_rate >= 0:
            row("Reliability", f"{rel_rate}%", "100%", ">=90%")

        rel_stddev = self.scores.get("reliability", {}).get("details", {}).get("stddev_ms", -1)
        if rel_stddev >= 0:
            row("Response stddev", f"{rel_stddev}ms", "<30% avg", "<50% avg")

        scale_active = self.scores.get("scalability", {}).get("details", {}).get("signals_active", -1)
        if scale_active >= 0:
            row("Scalability signals", f"{scale_active}/8", "7-8", "5-6")

        res_active = self.scores.get("resilience", {}).get("details", {}).get("signals_active", -1)
        if res_active >= 0:
            row("Resilience signals", f"{res_active}/7", "6-7", "4-5")

        audit_headers = self.scores.get("audit", {}).get("details", {}).get("security_headers_present", -1)
        if audit_headers >= 0:
            row("Security headers", f"{audit_headers}/9", ">=7", ">=5")

        hs13 = self.scores.get("tls13", {}).get("details", {}).get("handshake_tls13_ms", -1)
        if hs13 >= 0:
            row("TLS 1.3 handshake", f"{hs13}ms", "<150ms", "<300ms")

        tfo_conn = self.scores.get("tfo", {}).get("details", {}).get("tfo_connect_ms", -1)
        if tfo_conn >= 0:
            row("TFO connect", f"{tfo_conn}ms", "<40ms", "<120ms")

        quic_ms = self.scores.get("quic", {}).get("details", {}).get("udp_probe_ms", -1)
        if quic_ms >= 0:
            row("QUIC/UDP probe", f"{quic_ms}ms", "<50ms", "<150ms")

        coal_d = self.scores.get("coalesce", {}).get("details", {})
        if coal_d:
            row("Coalescing SANs", str(coal_d.get("san_count", 0)), ">=2", ">=1")

        prio_d = self.scores.get("priority", {}).get("details", {})
        if prio_d:
            prio_flag = "yes" if prio_d.get("priority_support") else "no"
            row("Priority/EH support", prio_flag, "yes", "priority only")

        if not rows:
            print(f"\n  {c.GRAY}No performance metrics collected.{c.END}")
            return

        print(f"\n  {c.BOLD}{'Metric':<22} {'Measured':>12} {'Excellent':>14} {'Acceptable':>14}{c.END}")
        print(f"  {c.GRAY}{'-'*64}{c.END}")
        for name, value, good, warn in rows:
            print(f"  {name:<22} {value:>12} {c.GREEN}{good:>14}{c.END} {c.YELLOW}{warn:>14}{c.END}")

        # Refined axis comparison
        if self.refined_scores:
            print(f"\n  {c.BOLD}Score axes:{c.END}")
            for axis, data in self.refined_scores.items():
                label = axis.replace("_", " ").title()
                pct = data["score"]
                grade = data["grade"]
                bar_len = 24
                filled = int(bar_len * pct / 100)
                bar = f"{'#' * filled}{'.' * (bar_len - filled)}"
                if pct >= 75:
                    bc = c.GREEN
                elif pct >= 55:
                    bc = c.YELLOW
                else:
                    bc = c.RED
                print(f"  {label:<22} {bc}{bar}{c.END} {pct:>5.1f}%  grade {grade}")

                components = data.get("components", {})
                if components and self.verbose:
                    parts = ", ".join(
                        f"{CATEGORY_NAMES.get(cat, cat)}={comp['pct']}%"
                        for cat, comp in sorted(components.items(), key=lambda kv: -kv[1]["weight"])
                    )
                    print(f"  {c.GRAY}  components: {parts}{c.END}")

        # Refined analysis indices (performance / reliability / security / scalability)
        if self.refined_analysis:
            print(f"\n  {c.BOLD}Refined analysis indices:{c.END}")
            print(f"  {c.BOLD}{'Domain':<16} {'Index':>8} {'Rating':<12} {'Signals':>8}  Bar{c.END}")
            print(f"  {c.GRAY}{'-'*64}{c.END}")
            for name, data in self.refined_analysis.items():
                pct = data.get("score", 0)
                rating = data.get("rating", "n/a")
                n_sig = len(data.get("components", {}))
                bar_len = 20
                filled = int(bar_len * pct / 100)
                bar = f"{'#' * filled}{'.' * (bar_len - filled)}"
                if pct >= 75:
                    bc = c.GREEN
                elif pct >= 55:
                    bc = c.YELLOW
                else:
                    bc = c.RED
                label = name.capitalize()
                print(f"  {label:<16} {pct:>7.1f}% {rating:<12} {n_sig:>8}  {bc}{bar}{c.END}")

        # Operational posture panel (reliability / scalability / resilience / encryption)
        print(f"\n  {c.BOLD}Operational posture:{c.END}")
        posture_rows = []

        def posture_row(name, value, good, warn):
            posture_rows.append((name, value, good, warn))

        rel = self.scores.get("reliability", {}).get("details", {})
        if rel.get("reliability_rating"):
            posture_row("Reliability", rel["reliability_rating"], "excellent/good", "fair")

        scale = self.scores.get("scalability", {}).get("details", {})
        if scale.get("readiness"):
            posture_row("Scalability readiness", scale["readiness"], "excellent/good", "fair")

        res = self.scores.get("resilience", {}).get("details", {})
        if res.get("resilience_rating"):
            posture_row("Resilience", res["resilience_rating"], "excellent/good", "fair")

        enc = self.scores.get("encryption", {}).get("details", {})
        if enc.get("encryption_rating"):
            posture_row("Encryption", enc["encryption_rating"], "excellent/good", "fair")

        cert = self.scores.get("certchain", {}).get("details", {})
        if cert.get("chain_length", 0) > 0:
            verified = "verified" if cert.get("chain_verified") else "unverified"
            posture_row("Certificate chain", verified, "verified", "unverified")

        if posture_rows:
            print(f"  {c.BOLD}{'Aspect':<22} {'Status':>14} {'Excellent':>14} {'Acceptable':>14}{c.END}")
            print(f"  {c.GRAY}{'-'*64}{c.END}")
            for name, value, good, warn in posture_rows:
                print(f"  {name:<22} {value:>14} {c.GREEN}{good:>14}{c.END} {c.YELLOW}{warn:>14}{c.END}")

        # Category vs previous (self-comparison across runs is not persisted; show category deltas vs 100)
        print(f"\n  {c.BOLD}Category performance vs maximum:{c.END}")
        for cat, data in sorted(self.scores.items(), key=lambda kv: -self._pct(kv[0])):
            name = CATEGORY_NAMES.get(cat, cat)
            pct = self._pct(cat)
            if pct >= 75:
                marker = f"{c.GREEN}strong{c.END}"
            elif pct >= 50:
                marker = f"{c.YELLOW}fair{c.END}  "
            else:
                marker = f"{c.RED}weak{c.END}  "
            print(f"    {marker} {name:<26} {pct:>5.1f}%")
        print()

    def print_security_report(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  SECURITY ASSESSMENT REPORT")
        print(f"{'='*60}{c.END}")

        findings = []

        def finding(sev, name, detail):
            findings.append((sev, name, detail))

        if self.parsed.scheme != "https":
            finding("CRITICAL", "No HTTPS", "Site is served over plain HTTP.")

        ssl_d = self.scores.get("ssl", {}).get("details", {})
        tls_versions = ssl_d.get("tls_versions", {})
        if tls_versions.get("TLS 1.0") or tls_versions.get("TLS 1.1"):
            finding("HIGH", "Legacy TLS", "TLS 1.0/1.1 is accepted; disable it.")
        if tls_versions and not tls_versions.get("TLS 1.3"):
            finding("MEDIUM", "No TLS 1.3", "TLS 1.3 is not enabled.")
        if ssl_d and not ssl_d.get("hsts", False):
            finding("MEDIUM", "No HSTS", "Strict-Transport-Security header is missing.")
        if ssl_d and not ssl_d.get("ocsp_stapling", False):
            finding("LOW", "No OCSP Stapling", "Clients must fetch revocation status themselves.")
        if ssl_d and not ssl_d.get("perfect_forward_secrecy", False):
            finding("HIGH", "No PFS", "Negotiated cipher lacks perfect forward secrecy.")
        cipher = ssl_d.get("cipher_suite", {})
        if cipher and cipher.get("bits", 0) < 256:
            finding("LOW", "Cipher strength", f"Negotiated cipher uses {cipher.get('bits', 0)} bits.")

        dns_d = self.scores.get("dns", {}).get("details", {})
        if dns_d and not dns_d.get("dnssec", {}).get("enabled", False):
            finding("MEDIUM", "DNSSEC off", "Zone is not DNSSEC-signed.")
        if dns_d.get("propagation_consistent") is False:
            finding("LOW", "DNS inconsistency", "Resolvers return differing answers.")

        netsec_d = self.scores.get("netsec", {}).get("details", {})
        if netsec_d.get("dns_hijack_detected"):
            finding("CRITICAL", "DNS hijack", "Resolver answers differ from Google DNS.")
        risk = netsec_d.get("risk_assessment", {})
        if risk.get("dangerous_open"):
            ports_str = ", ".join(str(p) for p in risk["dangerous_open"])
            finding("HIGH", "Dangerous ports", f"Open: {ports_str}.")
        if risk.get("risk_level") == "high":
            finding("HIGH", "High risk score", f"Risk score {risk.get('risk_score', 0)}.")
        elif risk.get("risk_level") == "medium":
            finding("MEDIUM", "Medium risk score", f"Risk score {risk.get('risk_score', 0)}.")

        http_d = self.scores.get("http", {}).get("details", {})
        sec_headers = http_d.get("security_headers", {})
        missing = [k.replace("_", "-").title() for k, v in sec_headers.items() if not v]
        if missing:
            missing_str = ", ".join(missing)
            finding("MEDIUM", "Missing headers", f"Not set: {missing_str}.")

        route_d = self.scores.get("routing", {}).get("details", {})
        if route_d.get("rpki_state", "unknown").lower() in ("invalid", "not-found"):
            finding("MEDIUM", "RPKI", f"RPKI state: {route_d.get('rpki_state')}.")

        audit_d = self.scores.get("audit", {}).get("details", {})
        audit_sev_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "LOW"}
        for item in audit_d.get("findings", []):
            sev = audit_sev_map.get(item.get("severity", "info"), "LOW")
            finding(sev, item.get("name", "Audit"), item.get("detail", ""))

        enc_d = self.scores.get("encryption", {}).get("details", {})
        if enc_d and not enc_d.get("encrypted", True):
            finding("CRITICAL", "No encryption", "Transport is not encrypted.")
        if enc_d.get("weak_ciphers_accepted"):
            weak = ", ".join(enc_d["weak_ciphers_accepted"])
            finding("CRITICAL", "Weak ciphers", f"Accepted weak cipher families: {weak}.")
        if enc_d.get("weak_versions_offered"):
            versions = ", ".join(enc_d["weak_versions_offered"])
            finding("HIGH", "Weak TLS versions", f"Offered: {versions}.")
        if enc_d.get("encrypted") and not enc_d.get("aead_cipher", False) and enc_d.get("negotiated_bits", 0) > 0:
            finding("LOW", "Non-AEAD cipher", f"Negotiated cipher is not AEAD ({enc_d.get('negotiated_cipher', 'unknown')}).")

        cert_d = self.scores.get("certchain", {}).get("details", {})
        days = cert_d.get("days_to_expiry", -1)
        if 0 <= days <= 14:
            finding("CRITICAL", "Cert expiring", f"Certificate expires in {days} days.")
        elif 0 <= days <= 60:
            finding("MEDIUM", "Cert expiring", f"Certificate expires in {days} days.")
        if cert_d.get("self_signed"):
            finding("HIGH", "Self-signed cert", "Leaf certificate is self-signed.")
        if cert_d.get("weak_signature"):
            finding("HIGH", "Weak cert signature", f"Signature algorithm: {cert_d.get('leaf', {}).get('signature_algorithm', 'unknown')}.")
        if cert_d.get("chain_length", 0) == 1:
            finding("MEDIUM", "Incomplete chain", "Only the leaf certificate is served.")
        if cert_d.get("chain_length", 0) > 0 and not cert_d.get("chain_verified"):
            finding("MEDIUM", "Chain unverified", f"OpenSSL verify code: {cert_d.get('verify_return_code', 'n/a')}.")

        protosec_d = self.scores.get("protosec", {}).get("details", {})
        if protosec_d.get("insecure_tls_versions"):
            versions = ", ".join(protosec_d["insecure_tls_versions"])
            finding("HIGH", "Legacy protocol", f"Insecure TLS on the wire: {versions}.")
        if protosec_d.get("http_to_https_redirect") is False and self.parsed.scheme == "https":
            finding("MEDIUM", "No HTTP redirect", "Port 80 does not redirect to HTTPS.")
        for p, name in protosec_d.get("cleartext_services", {}).items():
            finding("HIGH", "Cleartext service", f"{name} exposed on port {p} without encryption.")
        if protosec_d.get("websocket_enabled") and self.parsed.scheme != "https":
            finding("MEDIUM", "Insecure WebSocket", "WebSocket accepted without TLS.")

        portsec_d = self.scores.get("portsec", {}).get("details", {})
        exposure = portsec_d.get("exposure", {})
        if exposure.get("critical"):
            crit = ", ".join(str(p) for p in exposure["critical"])
            finding("CRITICAL", "Critical ports", f"Exposed: {crit}.")
        if exposure.get("high"):
            high = ", ".join(str(p) for p in exposure["high"])
            finding("HIGH", "High-risk ports", f"Exposed: {high}.")
        if portsec_d.get("version_disclosing_ports"):
            ports = ", ".join(str(p) for p in portsec_d["version_disclosing_ports"])
            finding("LOW", "Banner versions", f"Version strings leaked on ports {ports}.")

        res_d = self.scores.get("resilience", {}).get("details", {})
        if res_d.get("graceful_errors") is False:
            finding("MEDIUM", "Error disclosure", "Error pages may leak stack traces or internals.")

        tls13_d = self.scores.get("tls13", {}).get("details", {})
        if tls13_d.get("early_data_0rtt") is True:
            finding("LOW", "0-RTT early data", "TLS 1.3 0-RTT is advertised; verify anti-replay protections on state-changing requests.")
        quic_d = self.scores.get("quic", {}).get("details", {})
        if quic_d.get("h3_advertised") and not quic_d.get("udp_reachable"):
            finding("MEDIUM", "HTTP/3 unreachable", "Alt-Svc advertises HTTP/3 but the UDP/443 probe got no response; clients may stall on retry.")
        prio_d = self.scores.get("priority", {}).get("details", {})
        if http_d and http_d.get("http2") and prio_d and not prio_d.get("response_priority"):
            finding("LOW", "No Priority header", "RFC 9218 Priority response header is missing; clients cannot prioritize critical resources.")
        ra = getattr(self, "refined_analysis", {}) or {}
        sec_idx = ra.get("security", {})
        if sec_idx and sec_idx.get("score", 100) < 60:
            finding("HIGH", "Security posture",
                    f"Refined security index is {sec_idx.get('score')}% ({sec_idx.get('rating')}); remediate critical and high findings first.")

        if not findings:
            print(f"\n  {c.GREEN}{c.BOLD}No security issues detected.{c.END}\n")
            return

        sev_colors = {
            "CRITICAL": c.RED,
            "HIGH": c.RED,
            "MEDIUM": c.YELLOW,
            "LOW": c.CYAN,
        }
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for sev, _, _ in findings:
            counts[sev] = counts.get(sev, 0) + 1

        print(f"\n  {c.BOLD}Summary:{c.END} {sev_colors['CRITICAL']}{counts['CRITICAL']} critical{c.END}, "
              f"{sev_colors['HIGH']}{counts['HIGH']} high{c.END}, "
              f"{sev_colors['MEDIUM']}{counts['MEDIUM']} medium{c.END}, "
              f"{sev_colors['LOW']}{counts['LOW']} low{c.END}")
        ra = getattr(self, "refined_analysis", {}) or {}
        sec_idx = ra.get("security", {})
        if sec_idx:
            idx_pct = sec_idx.get("score", 0)
            idx_rate = sec_idx.get("rating", "n/a")
            idx_color = c.GREEN if idx_rate in ("excellent", "good") else c.YELLOW if idx_rate == "fair" else c.RED
            print(f"  {c.BOLD}Refined security index:{c.END} {idx_color}{idx_pct}% ({idx_rate}){c.END}")
        print(f"  {c.GRAY}{'-'*60}{c.END}")
        for sev, name, detail in findings:
            sc = sev_colors.get(sev, c.WHITE)
            print(f"  {sc}[{sev}]{c.END} {c.BOLD}{name}{c.END}")
            print(f"         {c.GRAY}{detail}{c.END}")
        print()

    def print_recommendations(self):
        c = self.colors
        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  OPTIMIZATION RECOMMENDATIONS")
        print(f"{'='*60}{c.END}")

        if not self.recommendations:
            print(f"\n  {c.GREEN}Nothing to improve - all checks look good.{c.END}\n")
            return

        sev_colors = {
            "critical": c.RED,
            "high": c.RED,
            "medium": c.YELLOW,
            "low": c.CYAN,
            "info": c.GRAY,
        }

        sev_counts = {}
        for rec in self.recommendations:
            sev_counts[rec["severity"]] = sev_counts.get(rec["severity"], 0) + 1
        summary_parts = []
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev_counts.get(sev):
                summary_parts.append(f"{sev_colors[sev]}{sev_counts[sev]} {sev}{c.END}")
        if summary_parts:
            print(f"\n  {c.BOLD}Priority summary:{c.END} " + ", ".join(summary_parts))

        current_cat = None
        for i, rec in enumerate(self.recommendations, 1):
            if rec["category"] != current_cat:
                current_cat = rec["category"]
                cat_name = CATEGORY_NAMES.get(current_cat, current_cat)
                print(f"\n  {c.BOLD}{cat_name}{c.END}")
            sc = sev_colors.get(rec["severity"], c.WHITE)
            print(f"  {c.BOLD}{i:>2}.{c.END} {sc}[{rec['severity'].upper()}]{c.END} {rec['message']}")

        action_now = sev_counts.get("critical", 0) + sev_counts.get("high", 0)
        if action_now:
            print(f"\n  {c.BOLD}Action now:{c.END} {action_now} critical/high item(s) to fix before lower-priority optimizations.")
        top_categories = {}
        for rec in self.recommendations:
            top_categories[rec["category"]] = top_categories.get(rec["category"], 0) + 1
        if top_categories:
            focus = sorted(top_categories.items(), key=lambda kv: -kv[1])[:3]
            focus_str = ", ".join(f"{CATEGORY_NAMES.get(cat, cat)} ({n})" for cat, n in focus)
            print(f"  {c.BOLD}Focus areas:{c.END} {focus_str}")
        print()

    def print_summary(self):
        c = self.colors
        total, max_total = self.calculate_total_score()
        percentage = round((total / max_total) * 100) if max_total > 0 else 0
        grade, grade_color = self.get_grade(percentage)

        print(f"\n{c.BOLD}{c.BLUE}{'='*60}")
        print(f"  NETWORK ANALYSIS SUMMARY")
        print(f"{'='*60}{c.END}")
        print(f"  {c.BOLD}Target:{c.END} {self.url}")
        print(f"  {c.BOLD}Domain:{c.END} {self.domain}")
        if self.ip_addresses:
            print(f"  {c.BOLD}IP:{c.END} {', '.join(self.ip_addresses[:3])}")
        print(f"  {c.BOLD}Analyzed:{c.END} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        print(f"  {c.BOLD}{'Category':<30} {'Score':>10} {'Max':>8} {'Pct':>8}{c.END}")
        print(f"  {c.GRAY}{'-'*56}{c.END}")

        for cat, name in CATEGORY_NAMES.items():
            data = self.scores.get(cat, {})
            score = data.get("score", 0)
            max_score = data.get("max_score", 0)
            pct = round((score / max_score) * 100) if max_score > 0 else 0

            if pct >= 70:
                bar_color = c.GREEN
            elif pct >= 40:
                bar_color = c.YELLOW
            else:
                bar_color = c.RED

            bar_len = 20
            filled = int(bar_len * pct / 100)
            bar = f"{'#' * filled}{'.' * (bar_len - filled)}"

            print(f"  {name:<30} {score:>4}/{max_score:<4}  {bar_color}{bar}{c.END} {pct:>3}%")

        print(f"  {c.GRAY}{'-'*56}{c.END}")
        print(f"  {c.BOLD}{'TOTAL':<30} {total:>4}/{max_total:<4}  {grade_color}{grade}{c.END}")
        print()

        if self.refined_scores:
            print(f"  {c.BOLD}Refined Scores:{c.END}")
            for axis, data in self.refined_scores.items():
                label = axis.replace("_", " ").title()
                pct = data["score"]
                gcolor = c.GREEN if data["grade"] in ("A", "B") else c.YELLOW if data["grade"] == "C" else c.RED
                bar_len = 20
                filled = int(bar_len * pct / 100)
                bar = f"{'#' * filled}{'.' * (bar_len - filled)}"
                print(f"    {label:<20} {pct:>5.1f}%  {gcolor}{bar}{c.END} grade {data['grade']}")
            print()

        print(f"  {c.BOLD}Network Topology:{c.END}")
        if self.ip_addresses:
            print(f"    {c.CYAN}Domain:{c.END} {self.domain}")
            for i, ip in enumerate(self.ip_addresses[:5]):
                print(f"    {c.CYAN}IP {i+1}:{c.END} {ip}")
            lat_data = self.scores.get("latency", {}).get("details", {})
            if lat_data.get("geolocation"):
                geo = lat_data["geolocation"]
                print(f"    {c.CYAN}Location:{c.END} {geo.get('city', 'N/A')}, {geo.get('region', 'N/A')}, {geo.get('country', 'N/A')}")
            if lat_data.get("asn"):
                print(f"    {c.CYAN}ASN:{c.END} {lat_data['asn']}")
        print()

        cdn_data = self.scores.get("cdn", {}).get("details", {})
        if cdn_data.get("cdn_providers"):
            print(f"  {c.BOLD}CDN & Technology:{c.END}")
            print(f"    {c.CYAN}CDN:{c.END} {', '.join(cdn_data['cdn_providers'])}")
            if cdn_data.get("edge_location"):
                print(f"    {c.CYAN}Edge:{c.END} {cdn_data['edge_location']}")
            fp_data = self.scores.get("fingerprint", {}).get("details", {})
            if fp_data.get("tech_stack"):
                print(f"    {c.CYAN}Tech:{c.END} {', '.join(fp_data['tech_stack'][:8])}")
            if fp_data.get("frameworks"):
                print(f"    {c.CYAN}Frameworks:{c.END} {', '.join(fp_data['frameworks'][:5])}")
            if fp_data.get("server"):
                print(f"    {c.CYAN}Server:{c.END} {fp_data['server']}")
            print()

        netsec_data = self.scores.get("netsec", {}).get("details", {})
        risk = netsec_data.get("risk_assessment", {})
        if risk:
            risk_color = c.GREEN if risk.get("risk_level") == "low" else c.YELLOW if risk.get("risk_level") == "medium" else c.RED
            print(f"  {c.BOLD}Security Assessment:{c.END}")
            print(f"    {c.CYAN}Risk Level:{c.END} {risk_color}{risk.get('risk_level', 'unknown').upper()}{c.END}")
            print(f"    {c.CYAN}Open Ports:{c.END} {netsec_data.get('open_port_count', 0)}")
            if risk.get("dangerous_open"):
                ports_str = ", ".join(str(p) for p in risk["dangerous_open"])
                print(f"    {c.RED}Dangerous Ports:{c.END} {ports_str}{c.END}")
            if risk.get("recommendations"):
                for rec in risk["recommendations"][:3]:
                    print(f"    {c.YELLOW}Recommendation:{c.END} {rec}")
            print()

        dns_data = self.scores.get("dns", {}).get("details", {})
        dnssec = dns_data.get("dnssec", {})
        if dnssec:
            print(f"  {c.BOLD}DNS Security:{c.END}")
            dnssec_color = c.GREEN if dnssec.get("enabled") else c.YELLOW
            dnssec_text = 'Enabled' if dnssec.get('enabled') else 'Disabled'
            print(f"    {c.CYAN}DNSSEC:{c.END} {dnssec_color}{dnssec_text}{c.END}")
            print(f"    {c.CYAN}Chain:{c.END} {dnssec.get('chain_status', 'unknown')}")
            doh_count = dns_data.get("doh_success_count", 0)
            if doh_count > 0:
                print(f"    {c.CYAN}DoH:{c.END} {doh_count}/{len(DOH_PROVIDERS)} providers responded")
            prop_consistent = dns_data.get("propagation_consistent")
            if prop_consistent is not None:
                prop_color = c.GREEN if prop_consistent else c.YELLOW
                prop_text = 'Consistent' if prop_consistent else 'Inconsistent'
                print(f"    {c.CYAN}Propagation:{c.END} {prop_color}{prop_text}{c.END}")
            print()

    def export_results(self, format_type):
        total, max_total = self.calculate_total_score()
        percentage = round((total / max_total) * 100) if max_total > 0 else 0
        grade, _ = self.get_grade(percentage)

        export_data = {
            "tool": f"NetworkAnalyzer v{VERSION}",
            "url": self.url,
            "domain": self.domain,
            "ip_addresses": self.ip_addresses,
            "analyzed_at": datetime.now().isoformat(),
            "total_score": total,
            "max_score": max_total,
            "percentage": percentage,
            "grade": grade,
            "refined_scores": self.refined_scores,
            "refined_analysis": self.refined_analysis,
            "recommendations": self.recommendations,
            "categories": self.scores,
        }

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if format_type in ("json", "all"):
            filename = f"network_analysis_{timestamp}.json"
            with open(filename, "w") as f:
                json.dump(export_data, f, indent=2, default=str)
            self._log(f"Exported JSON: {filename}", "ok")

        if format_type in ("csv", "all"):
            filename = f"network_analysis_{timestamp}.csv"
            with open(filename, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Category", "Score", "Max Score", "Percentage"])
                for cat, data in self.scores.items():
                    name = CATEGORY_NAMES.get(cat, cat)
                    pct = round((data["score"] / data["max_score"]) * 100) if data["max_score"] > 0 else 0
                    writer.writerow([name, data["score"], data["max_score"], f"{pct}%"])
                writer.writerow([])
                writer.writerow(["Total", total, max_total, f"{percentage}%"])
                writer.writerow(["Grade", grade])
                if self.refined_scores:
                    writer.writerow([])
                    writer.writerow(["Refined Axis", "Score", "Grade", "Descriptor", "Confidence"])
                    for axis, data in self.refined_scores.items():
                        writer.writerow([axis, data["score"], data["grade"],
                                         data.get("descriptor", ""), f"{data.get('confidence', 0)}%"])
                if self.refined_analysis:
                    writer.writerow([])
                    writer.writerow(["Refined Domain", "Index", "Rating", "Signals"])
                    for dom, dd in self.refined_analysis.items():
                        writer.writerow([dom, f"{dd.get('score', 0)}%", dd.get("rating", ""),
                                         len(dd.get("components", {}))])
            self._log(f"Exported CSV: {filename}", "ok")

        if format_type in ("html", "all"):
            filename = f"network_analysis_{timestamp}.html"
            html_content = self._generate_html(export_data)
            with open(filename, "w") as f:
                f.write(html_content)
            self._log(f"Exported HTML: {filename}", "ok")

    def _generate_html(self, data):
        grade = data["grade"]
        grade_colors = {"A": "#22c55e", "B": "#06b6d4", "C": "#eab308", "D": "#f97316", "F": "#ef4444"}
        grade_color = grade_colors.get(grade, "#94a3b8")

        categories_html = ""
        for cat, cat_data in data["categories"].items():
            name = CATEGORY_NAMES.get(cat, cat)
            score = cat_data.get("score", 0)
            max_score = cat_data.get("max_score", 0)
            pct = round((score / max_score) * 100) if max_score > 0 else 0
            bar_color = "#22c55e" if pct >= 70 else "#eab308" if pct >= 40 else "#ef4444"

            details_html = ""
            details = cat_data.get("details", {})
            for key, val in details.items():
                if isinstance(val, (list, dict)):
                    val_str = json.dumps(val, indent=2, default=str)
                else:
                    val_str = str(val)
                if len(val_str) > 500:
                    val_str = val_str[:500] + "..."
                val_escaped = val_str.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                key_escaped = key.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                details_html += f"""
                <div class="detail-item">
                    <span class="detail-key">{key_escaped}:</span>
                    <pre class="detail-val">{val_escaped}</pre>
                </div>"""

            categories_html += f"""
            <div class="category-card">
                <div class="cat-header">
                    <h3>{name}</h3>
                    <span class="cat-score">{score}/{max_score} ({pct}%)</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {pct}%; background: {bar_color};"></div>
                </div>
                <div class="cat-details">{details_html}</div>
            </div>"""

        refined_html = ""
        refined = data.get("refined_scores", {})
        if refined:
            refined_html = '<h2 style="color: #f1f5f9; margin-bottom: 1rem; font-size: 1.3rem;">Refined Scores</h2><div class="refined-grid">'
            for axis, rdata in refined.items():
                label = axis.replace("_", " ").title()
                rpct = rdata.get("score", 0)
                rgrade = rdata.get("grade", "-")
                rcolor = grade_colors.get(rgrade, "#94a3b8")
                refined_html += f"""
            <div class="summary-card">
                <div class="label">{label}</div>
                <div class="value"><span class="grade-badge" style="background: {rcolor};">{rgrade}</span> {rpct}%</div>
            </div>"""
            refined_html += "</div>"

        recs_html = ""
        recommendations = data.get("recommendations", [])
        if recommendations:
            recs_html = '<h2 style="color: #f1f5f9; margin: 1.5rem 0 1rem; font-size: 1.3rem;">Optimization Recommendations</h2><div class="rec-list">'
            sev_colors = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#06b6d4", "info": "#94a3b8"}
            for i, rec in enumerate(recommendations, 1):
                sev = rec.get("severity", "info")
                scolor = sev_colors.get(sev, "#94a3b8")
                cat = CATEGORY_NAMES.get(rec.get("category", ""), rec.get("category", ""))
                msg = rec.get("message", "")
                msg_esc = msg.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                recs_html += f"""
            <div class="rec-item">
                <span class="rec-sev" style="background: {scolor};">{sev.upper()}</span>
                <span class="rec-cat">{cat}</span>
                <span class="rec-msg">{i}. {msg_esc}</span>
            </div>"""
            recs_html += "</div>"

        # Security findings (compact)
        security_html = ""
        ssl_d = data.get("categories", {}).get("ssl", {}).get("details", {})
        netsec_d = data.get("categories", {}).get("netsec", {}).get("details", {})
        findings = []
        if not ssl_d.get("hsts", False) and data.get("url", "").startswith("https"):
            findings.append(("MEDIUM", "HSTS header missing"))
        if ssl_d.get("tls_versions", {}).get("TLS 1.0") or ssl_d.get("tls_versions", {}).get("TLS 1.1"):
            findings.append(("HIGH", "Legacy TLS versions accepted"))
        risk = netsec_d.get("risk_assessment", {})
        if risk.get("dangerous_open"):
            ports_str = ", ".join(str(p) for p in risk["dangerous_open"])
            findings.append(("HIGH", f"Dangerous ports open: {ports_str}"))
        if netsec_d.get("dns_hijack_detected"):
            findings.append(("CRITICAL", "Potential DNS hijacking"))
        if findings:
            sev_colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#06b6d4"}
            security_html = '<h2 style="color: #f1f5f9; margin: 1.5rem 0 1rem; font-size: 1.3rem;">Security Findings</h2>'
            for sev, text in findings:
                scolor = sev_colors.get(sev, "#94a3b8")
                text_esc = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                security_html += f"""
            <div class="rec-item">
                <span class="rec-sev" style="background: {scolor};">{sev}</span>
                <span class="rec-msg">{text_esc}</span>
            </div>"""

        ip_list = ", ".join(data.get("ip_addresses", [])[:5])
        geolocation = data.get("categories", {}).get("latency", {}).get("details", {}).get("geolocation", {})
        location_str = f"{geolocation.get('city', 'N/A')}, {geolocation.get('country', 'N/A')}"

        cdn_providers = data.get("categories", {}).get("cdn", {}).get("details", {}).get("cdn_providers", [])
        cdn_str = ", ".join(cdn_providers) if cdn_providers else "None detected"
        tech_stack = data.get("categories", {}).get("fingerprint", {}).get("details", {}).get("tech_stack", [])
        tech_str = ", ".join(tech_stack[:8]) if tech_stack else "None detected"

        netsec_risk = data.get("categories", {}).get("netsec", {}).get("details", {}).get("risk_assessment", {})
        risk_level = netsec_risk.get("risk_level", "unknown")
        risk_color_map = {"low": "#22c55e", "medium": "#eab308", "high": "#ef4444"}
        risk_color = risk_color_map.get(risk_level, "#94a3b8")

        dnssec_info = data.get("categories", {}).get("dns", {}).get("details", {}).get("dnssec", {})
        dnssec_enabled = dnssec_info.get("enabled", False)
        dnssec_text = "Enabled" if dnssec_enabled else "Disabled"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Analysis Report - v{VERSION}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            min-height: 100vh;
            padding: 2rem;
        }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        .header {{
            text-align: center;
            padding: 2rem 0;
            border-bottom: 1px solid #1e293b;
            margin-bottom: 2rem;
        }}
        .header h1 {{ font-size: 1.8rem; color: #38bdf8; margin-bottom: 0.5rem; }}
        .header .subtitle {{ color: #94a3b8; font-size: 0.95rem; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .refined-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .summary-card {{
            background: #1e293b;
            border-radius: 8px;
            padding: 1.2rem;
            border: 1px solid #334155;
        }}
        .summary-card .label {{ color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .summary-card .value {{ font-size: 1.5rem; font-weight: 700; margin-top: 0.3rem; color: #f1f5f9; }}
        .grade-badge {{
            display: inline-block;
            padding: 0.3rem 1rem;
            border-radius: 6px;
            font-weight: 700;
            font-size: 1.2rem;
            color: #fff;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .info-card {{
            background: #1e293b;
            border-radius: 8px;
            padding: 1.2rem;
            border: 1px solid #334155;
        }}
        .info-card h4 {{
            color: #38bdf8;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.8rem;
            border-bottom: 1px solid #334155;
            padding-bottom: 0.5rem;
        }}
        .info-row {{
            display: flex;
            justify-content: space-between;
            padding: 0.3rem 0;
            font-size: 0.85rem;
        }}
        .info-row .key {{ color: #94a3b8; }}
        .info-row .val {{ color: #f1f5f9; font-weight: 500; }}
        .rec-list {{ margin-bottom: 1rem; }}
        .rec-item {{
            display: flex;
            align-items: center;
            gap: 0.7rem;
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 6px;
            padding: 0.7rem 0.9rem;
            margin-bottom: 0.5rem;
            flex-wrap: wrap;
        }}
        .rec-sev {{
            color: #0f172a;
            font-size: 0.7rem;
            font-weight: 700;
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
        }}
        .rec-cat {{ color: #94a3b8; font-size: 0.75rem; min-width: 110px; }}
        .rec-msg {{ color: #e2e8f0; font-size: 0.85rem; flex: 1; }}
        .category-card {{
            background: #1e293b;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            border: 1px solid #334155;
        }}
        .cat-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.8rem;
        }}
        .cat-header h3 {{ color: #f1f5f9; font-size: 1.1rem; }}
        .cat-score {{ color: #94a3b8; font-size: 0.9rem; }}
        .progress-bar {{
            height: 8px;
            background: #334155;
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 1rem;
        }}
        .progress-fill {{ height: 100%; border-radius: 4px; transition: width 0.5s ease; }}
        .cat-details {{ max-height: 300px; overflow-y: auto; }}
        .detail-item {{ margin-bottom: 0.6rem; }}
        .detail-key {{ color: #38bdf8; font-weight: 600; font-size: 0.85rem; }}
        .detail-val {{
            color: #cbd5e1;
            font-family: 'Fira Code', monospace;
            font-size: 0.8rem;
            background: #0f172a;
            padding: 0.4rem 0.6rem;
            border-radius: 4px;
            margin-top: 0.2rem;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .footer {{
            text-align: center;
            padding: 2rem 0 1rem;
            color: #475569;
            font-size: 0.8rem;
            border-top: 1px solid #1e293b;
            margin-top: 2rem;
        }}
        ::-webkit-scrollbar {{ width: 6px; }}
        ::-webkit-scrollbar-track {{ background: #0f172a; }}
        ::-webkit-scrollbar-thumb {{ background: #475569; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>NetworkAnalyzer v{VERSION}</h1>
            <p class="subtitle">Advanced Network Diagnostics Report</p>
        </div>

        <div class="summary">
            <div class="summary-card">
                <div class="label">Target</div>
                <div class="value" style="font-size: 1rem; word-break: break-all;">{data["url"]}</div>
            </div>
            <div class="summary-card">
                <div class="label">IP Address</div>
                <div class="value" style="font-size: 1rem;">{ip_list or "N/A"}</div>
            </div>
            <div class="summary-card">
                <div class="label">Location</div>
                <div class="value" style="font-size: 1rem;">{location_str}</div>
            </div>
            <div class="summary-card">
                <div class="label">Score</div>
                <div class="value"><span class="grade-badge" style="background: {grade_color};">{grade}</span> {data["total_score"]}/{data["max_score"]} ({data["percentage"]}%)</div>
            </div>
        </div>

{refined_html}

        <div class="info-grid">
            <div class="info-card">
                <h4>CDN &amp; Technology</h4>
                <div class="info-row"><span class="key">CDN</span><span class="val">{cdn_str}</span></div>
                <div class="info-row"><span class="key">Tech Stack</span><span class="val">{tech_str}</span></div>
            </div>
            <div class="info-card">
                <h4>Security</h4>
                <div class="info-row"><span class="key">Risk Level</span><span class="val" style="color: {risk_color};">{risk_level.upper()}</span></div>
                <div class="info-row"><span class="key">Open Ports</span><span class="val">{data.get("categories", {}).get("netsec", {}).get("details", {}).get("open_port_count", 0)}</span></div>
                <div class="info-row"><span class="key">DNSSEC</span><span class="val">{dnssec_text}</span></div>
            </div>
        </div>

{security_html}

{recs_html}

        <h2 style="color: #f1f5f9; margin-bottom: 1rem; font-size: 1.3rem;">Category Breakdown</h2>
{categories_html}

        <div class="footer">
            NetworkAnalyzer v{VERSION} - Generated {data["analyzed_at"]}
        </div>
    </div>
</body>
</html>"""

        return html

    def run(self, max_seconds=100):
        print_banner(self.colors)

        self._log(f"Starting analysis of {self.url}", "info")
        self._log(f"Domain: {self.domain}, Port: {self.port}", "info")

        class _BudgetExceeded(BaseException):
            """BaseException so analyzer `except Exception` blocks cannot swallow it."""

        def _on_alarm(signum, frame):
            raise _BudgetExceeded()

        deadline = time.time() + max_seconds
        prev_handler = None
        try:
            import signal
            prev_handler = signal.signal(signal.SIGALRM, _on_alarm)
            signal.setitimer(signal.ITIMER_REAL, max_seconds)
        except (ValueError, OSError, AttributeError):
            prev_handler = None

        phases = (
            ("dns", self.analyze_dns),
            ("tcp", self.analyze_tcp),
            ("ssl", self.analyze_ssl),
            ("http", self.analyze_http),
            ("cdn", self.analyze_cdn),
            ("fingerprint", self.analyze_fingerprint),
            ("latency", self.analyze_latency),
            ("bandwidth", self.analyze_bandwidth),
            ("netsec", self.analyze_netsec),
            ("protocols", self.analyze_protocols),
            ("ipv6", self.analyze_ipv6),
            ("routing", self.analyze_routing),
            ("congestion", self.analyze_congestion),
            ("pmtu", self.analyze_pmtu),
            ("audit", self.analyze_security_audit),
            ("encryption", self.analyze_encryption),
            ("certchain", self.analyze_cert_chain),
            ("protosec", self.analyze_protocol_security),
            ("portsec", self.analyze_port_security),
            ("reliability", self.analyze_reliability),
            ("scalability", self.analyze_scalability),
            ("resilience", self.analyze_resilience),
            ("quic", self.analyze_quic),
            ("tls13", self.analyze_tls13_optimization),
            ("tfo", self.analyze_tcp_fast_open),
            ("coalesce", self.analyze_connection_coalescing),
            ("priority", self.analyze_priority_headers),
        )
        skipped = 0
        stopped = False
        try:
            for name, fn in phases:
                if stopped or time.time() >= deadline:
                    skipped += 1
                    continue
                try:
                    fn()
                except _BudgetExceeded:
                    stopped = True
                    skipped += 1
                    self._log(f"Time budget hit during {name}; stopping remaining phases.", "warn")
                except Exception as exc:
                    self._log(f"{name} failed: {exc}", "warn")
        finally:
            try:
                signal.setitimer(signal.ITIMER_REAL, 0)
                if prev_handler is not None:
                    signal.signal(signal.SIGALRM, prev_handler)
            except (ValueError, OSError, AttributeError, NameError):
                pass

        if skipped:
            self._log(
                f"Time budget ({max_seconds}s) reached; skipped {skipped} phase(s). "
                "Summary uses completed phases only.",
                "warn",
            )

        try:
            self.refine_network_analysis()
        except Exception as exc:
            self._log(f"refine failed: {exc}", "warn")

        try:
            self.calculate_refined_scores()
            self.build_recommendations()
        except Exception as exc:
            self._log(f"scoring failed: {exc}", "warn")

        try:
            self.print_summary()
        except Exception as exc:
            self._log(f"summary failed: {exc}", "error")
            # Still emit a machine-readable TOTAL so scan can extract a score.
            try:
                total, max_total = self.calculate_total_score()
                pct = round((total / max_total) * 100) if max_total else 0
                grade, _ = self.get_grade(pct)
                print(f"  TOTAL                            {total}/{max_total}  {grade}")
            except Exception:
                pass

        try:
            self.print_topology()
            self.print_performance_dashboard()
            self.print_security_report()
            self.print_recommendations()
        except Exception as exc:
            self._log(f"report section failed: {exc}", "warn")

        return self.scores


def main():
    parser = argparse.ArgumentParser(
        description=f"NetworkAnalyzer v{VERSION} - Advanced Network Diagnostics Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com
  %(prog)s -u example.com -t 30 --export json
  %(prog)s -u https://google.com --export all --verbose
  %(prog)s -u example.com --no-color -t 10
        """,
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL to analyze")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--export", choices=["all", "json", "csv", "html", "none"], default="none", help="Export format (default: none)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    analyzer = NetworkAnalyzer(
        url=args.url,
        timeout=args.timeout,
        no_color=args.no_color,
        verbose=args.verbose,
    )

    analyzer.run()

    if args.export != "none":
        print(f"\n  Exporting results...")
        analyzer.export_results(args.export)


if __name__ == "__main__":
    main()
