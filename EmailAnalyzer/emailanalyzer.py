#!/usr/bin/env python3
import argparse
import base64
import csv
import datetime
import json
import os
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
from html import escape as html_escape
from urllib.parse import urlparse


def ensure_dependency(package, module=None):
    module = module or package
    try:
        __import__(module)
        return True
    except ImportError:
        pass
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", package],
            capture_output=True,
            timeout=120,
            check=False,
        )
        __import__(module)
        return True
    except Exception:
        return False


HAS_REQUESTS = ensure_dependency("requests")
if HAS_REQUESTS:
    import requests

TOOL_NAME = "EmailAnalyzer"
TOOL_VERSION = "2.0"

QTYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "DNSKEY": 48,
    "RRSIG": 46,
    "CAA": 257,
    "TLSA": 52,
}

COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "s1", "s2"]

SPF_TERM_RE = re.compile(
    r"^(?:[-+~?])?(?:all|include:\S+|a(?:[:/]\S+)?|mx(?:[:/]\S+)?|"
    r"ptr(?:[:/]\S+)?|ip4:[0-9./]+|ip6:[0-9a-fA-F:./]+|exists:\S+)$"
)
SPF_MOD_RE = re.compile(r"^(?:redirect|exp)=\S+$")

DNSBL_SERVERS = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org"]


class Palette:
    def __init__(self, enabled=True):
        self.enabled = enabled

    def c(self, code, text):
        if not self.enabled:
            return str(text)
        return "\033[" + str(code) + "m" + str(text) + "\033[0m"

    def red(self, t):
        return self.c("31", t)

    def green(self, t):
        return self.c("32", t)

    def yellow(self, t):
        return self.c("33", t)

    def blue(self, t):
        return self.c("34", t)

    def magenta(self, t):
        return self.c("35", t)

    def cyan(self, t):
        return self.c("36", t)

    def white(self, t):
        return self.c("37", t)

    def gray(self, t):
        return self.c("2", t)

    def bold(self, t):
        return self.c("1", t)

    def bright_red(self, t):
        return self.c("91", t)

    def bright_green(self, t):
        return self.c("92", t)

    def bright_yellow(self, t):
        return self.c("93", t)

    def bright_blue(self, t):
        return self.c("94", t)

    def bright_magenta(self, t):
        return self.c("95", t)

    def bright_cyan(self, t):
        return self.c("96", t)


GLYPHS = {
    "E": ["#####", "#    ", "#### ", "#    ", "#####"],
    "M": ["##  ##", "######", "##  ##", "##  ##", "##  ##"],
    "A": [" ### ", "#   #", "#####", "#   #", "#   #"],
    "I": ["#####", "  #  ", "  #  ", "  #  ", "#####"],
    "L": ["#    ", "#    ", "#    ", "#    ", "#####"],
    "N": ["#   #", "##  #", "# # #", "#  ##", "#   #"],
    "Y": ["#   #", " # # ", "  #  ", "  #  ", "  #  "],
    "Z": ["#####", "   # ", "  #  ", " #   ", "#####"],
    "R": ["#### ", "#   #", "#### ", "#  # ", "#   #"],
}

BANNER_COLORS = ["96", "94", "95", "93", "92"]


def render_word(word):
    rows = []
    for i in range(5):
        rows.append(" ".join(GLYPHS[ch][i] for ch in word if ch in GLYPHS))
    return rows


def print_banner(pal):
    rows = render_word("EMAIL") + render_word("ANALYZER")
    print()
    for idx, row in enumerate(rows):
        code = BANNER_COLORS[idx % len(BANNER_COLORS)]
        print("   " + pal.c(code, row))
    print("   " + pal.bold(pal.bright_yellow("EmailAnalyzer v" + TOOL_VERSION)))
    print("   " + pal.gray("SPF  DKIM  DMARC  MX  DNSSEC  MTA-STS  BIMI"))
    print()


def decode_name(data, offset):
    labels = []
    jumped = False
    orig = offset
    for _ in range(64):
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                orig = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(data[offset : offset + length])
        offset += length
    if not jumped:
        orig = offset
    name = b".".join(labels).decode("utf-8", "replace")
    return name, orig


def parse_txt_rdata(rdata):
    out = b""
    i = 0
    while i < len(rdata):
        length = rdata[i]
        i += 1
        out += rdata[i : i + length]
        i += length
    return out.decode("utf-8", "replace")


def build_dns_query(name, qtype):
    tid = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b""
    clean = name.strip(".")
    if clean:
        for label in clean.split("."):
            raw = label.encode() if label.isascii() else label.encode("idna", "ignore")
            qname += bytes([len(raw)]) + raw
    qname += b"\x00"
    question = qname + struct.pack("!HH", qtype, 1)
    return tid, header + question


def parse_dns_response(data, expected_tid):
    if len(data) < 12:
        raise ValueError("short DNS response")
    tid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if tid != expected_tid:
        raise ValueError("DNS transaction id mismatch")
    truncated = bool(flags & 0x0200)
    rcode = flags & 0x000F
    pos = 12
    for _ in range(qd):
        _, pos = decode_name(data, pos)
        pos += 4
    answers = []
    for _ in range(an):
        _, pos = decode_name(data, pos)
        if pos + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[pos : pos + 10])
        pos += 10
        if pos + rdlen > len(data):
            break
        answers.append((rtype, pos, rdlen, data[pos : pos + rdlen]))
        pos += rdlen
    return answers, truncated, rcode


def format_answer(rtype, offset, rdlen, rdata, full):
    if rtype == 1 and rdlen == 4:
        return socket.inet_ntoa(rdata)
    if rtype == 28 and rdlen == 16:
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if rtype == 16:
        return parse_txt_rdata(rdata)
    if rtype == 15 and rdlen >= 3:
        pref = struct.unpack("!H", rdata[:2])[0]
        host, _ = decode_name(full, offset + 2)
        return str(pref) + " " + host
    if rtype in (2, 5, 12):
        host, _ = decode_name(full, offset)
        return host
    if rtype == 257 and rdlen >= 2:
        flags = rdata[0]
        taglen = rdata[1]
        tag = rdata[2 : 2 + taglen].decode("utf-8", "replace")
        value = rdata[2 + taglen :].decode("utf-8", "replace")
        return str(flags) + " " + tag + ' "' + value + '"'
    if rtype == 48:
        return "DNSKEY " + base64.b64encode(rdata).decode()[:48]
    return rdata.hex()


class DNSResolver:
    def __init__(self, timeout=5, vlog=None):
        self.timeout = timeout
        self.vlog = vlog or (lambda msg: None)

    def _dig(self, name, rtype):
        try:
            proc = subprocess.run(
                [
                    "dig",
                    "+short",
                    "+time=" + str(max(1, int(self.timeout))),
                    "+tries=1",
                    name,
                    rtype,
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout + 3,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None
        if proc.returncode != 0:
            return None
        lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        return lines

    def _merge_txt(self, lines):
        records = []
        for line in lines:
            parts = re.findall(r'"([^"]*)"', line)
            if parts:
                records.append("".join(parts))
            else:
                records.append(line.strip('"'))
        return records

    def ad_flag(self, name):
        try:
            proc = subprocess.run(
                [
                    "dig",
                    "+time=" + str(max(1, int(self.timeout))),
                    "+tries=1",
                    name,
                    "SOA",
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout + 3,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None
        match = re.search(r"flags:\s*([^;]+);", proc.stdout)
        if not match:
            return None
        return bool(re.search(r"\bad\b", match.group(1)))

    def _recv_exact(self, sock, size):
        buf = b""
        while len(buf) < size:
            chunk = sock.recv(size - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def _tcp_query(self, name, qtype, server):
        tid, packet = build_dns_query(name, qtype)
        sock = socket.create_connection((server, 53), timeout=self.timeout)
        try:
            sock.settimeout(self.timeout)
            sock.sendall(struct.pack("!H", len(packet)) + packet)
            header = self._recv_exact(sock, 2)
            if len(header) < 2:
                return []
            length = struct.unpack("!H", header)[0]
            data = self._recv_exact(sock, length)
        finally:
            sock.close()
        answers, _truncated, _rcode = parse_dns_response(data, tid)
        return answers

    def _socket_query(self, name, rtype):
        qtype = QTYPES.get(rtype.upper())
        if qtype is None:
            return None
        last_err = None
        for server in ("8.8.8.8", "1.1.1.1"):
            try:
                tid, packet = build_dns_query(name, qtype)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                try:
                    sock.sendto(packet, (server, 53))
                    data, _ = sock.recvfrom(4096)
                finally:
                    sock.close()
                answers, truncated, _rcode = parse_dns_response(data, tid)
                if truncated:
                    answers = self._tcp_query(name, qtype, server)
                return [
                    format_answer(rt, off, ln, rd, data)
                    for (rt, off, ln, rd) in answers
                ]
            except Exception as exc:
                last_err = exc
                continue
        if last_err is not None:
            self.vlog("socket DNS failed for " + name + " " + rtype + ": " + str(last_err))
            return None
        return None

    def query(self, name, rtype):
        self.vlog("DNS " + rtype + " " + name)
        lines = self._dig(name, rtype)
        if lines is None:
            return self._socket_query(name, rtype)
        if rtype.upper() == "TXT":
            return self._merge_txt(lines)
        return lines

    def txt(self, name):
        records = self.query(name, "TXT")
        if records is None:
            return None
        return records


def resolve_host(host):
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError, UnicodeError):
        return []
    ips = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


def parse_mx_lines(lines):
    records = []
    if not lines:
        return records
    for line in lines:
        text = line.strip().rstrip(".")
        match = re.match(r"^(\d+)\s+(\S+)$", text)
        if match:
            records.append((int(match.group(1)), match.group(2).rstrip(".")))
            continue
        if re.match(r"^\d+$", text):
            continue
        if text:
            records.append((10, text))
    records.sort(key=lambda item: item[0])
    return records


def read_smtp_reply(sock_file):
    lines = []
    for _ in range(60):
        raw = sock_file.readline()
        if not raw:
            break
        text = raw.decode("utf-8", "replace").rstrip("\r\n")
        lines.append(text)
        if len(text) >= 4 and text[3] == " ":
            break
        if len(text) >= 3 and not text[:3].isdigit():
            break
    return lines


def smtp_probe(host, timeout):
    result = {
        "ok": False,
        "banner": None,
        "starttls": False,
        "tls_version": None,
        "auth": False,
        "error": None,
    }
    sock = None
    sock_file = None
    try:
        sock = socket.create_connection((host, 25), timeout=timeout)
        sock.settimeout(timeout)
        sock_file = sock.makefile("rb")
        banner = sock_file.readline()
        result["banner"] = banner.decode("utf-8", "replace").strip()

        def send_cmd(command):
            sock.sendall(command.encode("ascii") + b"\r\n")
            return read_smtp_reply(sock_file)

        ehlo_lines = send_cmd("EHLO analyzer.local")
        ehlo_text = "\n".join(ehlo_lines)
        if "STARTTLS" in ehlo_text.upper():
            result["starttls"] = True
            reply = send_cmd("STARTTLS")
            if reply and reply[0].startswith("220"):
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ssock = ctx.wrap_socket(sock, server_hostname=host)
                sock = ssock
                sock_file = ssock.makefile("rb")
                result["tls_version"] = ssock.version()
                ehlo2 = send_cmd("EHLO analyzer.local")
                if "AUTH " in "\n".join(ehlo2).upper():
                    result["auth"] = True
        else:
            if "AUTH " in ehlo_text.upper():
                result["auth"] = True
        result["ok"] = True
    except Exception as exc:
        result["error"] = str(exc)
    finally:
        try:
            if sock_file is not None:
                sock_file.close()
        except Exception:
            pass
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass
    return result


def parse_dkim_tags(record):
    tags = {}
    problems = []
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            problems.append(part)
            continue
        key, value = part.split("=", 1)
        tags[key.strip()] = value.strip()
    return tags, problems


def rsa_key_bits(der):
    def read_tlv(data, i):
        tag = data[i]
        i += 1
        first = data[i]
        i += 1
        if first & 0x80:
            count = first & 0x7F
            length = int.from_bytes(data[i : i + count], "big")
            i += count
        else:
            length = first
        return tag, data[i : i + length], i + length

    try:
        _tag, body, _ = read_tlv(der, 0)
        _t2, _alg, j = read_tlv(body, 0)
        _t3, bits, _k = read_tlv(body, j)
        inner = bits[1:]
        _t4, rsa_body, _ = read_tlv(inner, 0)
        _t5, modulus, _ = read_tlv(rsa_body, 0)
        return int.from_bytes(modulus, "big").bit_length()
    except Exception:
        pass
    size = len(der)
    if size >= 290:
        return 2048
    if size >= 140:
        return 1024
    return 512


def dkim_key_bits(tags):
    p_value = tags.get("p", "")
    if not p_value:
        return None
    key_type = tags.get("k", "rsa").lower()
    try:
        der = base64.b64decode(re.sub(r"\s+", "", p_value))
    except Exception:
        return None
    if key_type == "ed25519":
        return 256
    return rsa_key_bits(der)


def normalize_target(raw):
    text = (raw or "").strip()
    if not text:
        return ""
    if "://" in text:
        parsed = urlparse(text)
        text = parsed.hostname or text
    text = text.split("/")[0]
    if text.count(":") == 1:
        text = text.split(":")[0]
    text = text.strip().lower().rstrip(".")
    if text.startswith("www."):
        text = text[4:]
    return text


def load_headers_text():
    candidates = [
        os.path.join(os.getcwd(), "headers.txt"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "headers.txt"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    return handle.read(), path
            except OSError:
                continue
    return None, None


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


GRADE_LABELS = {
    "A+": "Excellent deliverability posture",
    "A": "Strong deliverability posture",
    "B": "Good, minor gaps remain",
    "C": "Average, fixes recommended",
    "D": "Weak, significant issues",
    "F": "Poor, critical misconfiguration",
}


class EmailAnalyzer:
    def __init__(self, domain, timeout=15, verbose=False, selector=None, pal=None):
        self.domain = domain
        self.timeout = timeout
        self.verbose = verbose
        self.pal = pal or Palette(False)
        self.selectors = None
        if selector:
            self.selectors = [s.strip() for s in selector.split(",") if s.strip()]
        self.dns = DNSResolver(timeout=min(timeout, 8), vlog=self.vlog)
        self.primary_mx_host = None
        self.primary_mx_ip = None
        self.mx_records = []
        self.spf_records = []
        self.dmarc_record = None
        self.start_time = time.time()

    def vlog(self, msg):
        if self.verbose:
            print(self.pal.gray("  [.] " + str(msg)))

    def _new_cat(self, cid, name, max_points):
        return {"id": cid, "name": name, "max": max_points, "checks": [], "score": 0}

    def _add(self, cat, name, points, maximum, detail, advice=""):
        points = int(max(0, min(int(points), maximum)))
        entry = {
            "name": name,
            "points": points,
            "max": int(maximum),
            "detail": str(detail),
            "passed": points >= maximum,
            "advice": advice if points < maximum else "",
        }
        cat["checks"].append(entry)
        cat["score"] = sum(item["points"] for item in cat["checks"])
        return entry

    def check_mx(self):
        cat = self._new_cat("mx", "MX Records", 15)
        lines = self.dns.query(self.domain, "MX")
        if lines is None:
            lines = []
        records = parse_mx_lines(lines)
        self.mx_records = records

        if records:
            self._add(cat, "MX record existence", 5, 5, str(len(records)) + " MX record(s) found")
        else:
            self._add(
                cat,
                "MX record existence",
                0,
                5,
                "no MX record published",
                "Publish at least one MX record for " + self.domain,
            )

        if records:
            valid = all(pref >= 0 and host for pref, host in records)
            summary = ", ".join(str(p) + ":" + h for p, h in records[:6])
            if valid:
                self._add(cat, "MX record priority analysis", 3, 3, summary)
            else:
                self._add(cat, "MX record priority analysis", 1, 3, "invalid priorities: " + summary,
                          "Fix MX preference values to integers 0-65535")
        else:
            self._add(cat, "MX record priority analysis", 0, 3, "no MX records to analyze",
                      "Add MX records with sensible priorities")

        count = len(records)
        if count >= 2:
            self._add(cat, "MX record count (redundancy)", 2, 2, str(count) + " servers (redundant)")
        elif count == 1:
            self._add(cat, "MX record count (redundancy)", 1, 2, "single MX server (no redundancy)",
                      "Add a backup MX record for redundancy")
        else:
            self._add(cat, "MX record count (redundancy)", 0, 2, "no MX servers",
                      "Add at least one MX record")

        resolved = 0
        ips_seen = []
        for _pref, host in records:
            ip_literal = re.match(r"^\d+\.\d+\.\d+\.\d+$", host)
            if ip_literal:
                resolved += 1
                if host not in ips_seen:
                    ips_seen.append(host)
                continue
            ips = resolve_host(host)
            if ips:
                resolved += 1
            for ip in ips:
                if ip not in ips_seen:
                    ips_seen.append(ip)

        if records and resolved == len(records):
            self._add(cat, "MX host resolution", 3, 3,
                      "all hosts resolve (" + ", ".join(ips_seen[:4]) + ")")
        elif resolved:
            self._add(cat, "MX host resolution", 1, 3,
                      str(resolved) + "/" + str(len(records)) + " hosts resolve",
                      "Fix broken MX hostnames that fail DNS resolution")
        else:
            self._add(cat, "MX host resolution", 0, 3, "no MX host resolved",
                      "Ensure MX hostnames have valid A/AAAA records")

        if count >= 2:
            prefs = [p for p, _ in records]
            unique = sorted(set(prefs))
            detail = "priorities " + ", ".join(str(p) for p in unique) + " across " + str(count) + " hosts"
            self._add(cat, "MX record weight distribution", 2, 2, detail)
        elif count == 1:
            self._add(cat, "MX record weight distribution", 1, 2,
                      "single host, no distribution",
                      "Add another MX at the same or lower priority for load sharing")
        else:
            self._add(cat, "MX record weight distribution", 0, 2, "no hosts",
                      "Publish MX records with priority-based distribution")

        if ips_seen:
            self.primary_mx_ip = ips_seen[0]
        for _pref, host in records:
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", host) and resolve_host(host):
                self.primary_mx_host = host
                break
        if self.primary_mx_host is None and records:
            self.primary_mx_host = records[0][1]
        return cat

    def check_spf(self):
        cat = self._new_cat("spf", "SPF Record", 15)
        records = self.dns.txt(self.domain) or []
        spf = [r for r in records if r.lower().startswith("v=spf1")]
        self.spf_records = spf

        if len(spf) == 1:
            self._add(cat, "SPF record existence", 3, 3, "one SPF record found")
        elif len(spf) > 1:
            self._add(cat, "SPF record existence", 1, 3,
                      str(len(spf)) + " SPF records found (RFC 7208 allows one)",
                      "Merge all SPF records into a single v=spf1 record")
        else:
            self._add(cat, "SPF record existence", 0, 3, "no SPF record",
                      "Publish a v=spf1 TXT record on " + self.domain)

        if not spf:
            self._add(cat, "SPF record syntax validation", 0, 2, "no record",
                      "Add a valid SPF record")
            self._add(cat, "SPF record version (v=spf1)", 0, 1, "no record",
                      "Start the record with v=spf1")
            self._add(cat, "SPF mechanisms (+all/~all/-all/?all)", 0, 3, "no record",
                      "End your SPF record with -all")
            self._add(cat, "SPF include chain analysis", 0, 2, "no record",
                      "Define include: or ip4: mechanisms")
            self._add(cat, "SPF lookup count (limit: 10)", 0, 2, "no record",
                      "Keep DNS-lookup mechanisms at or below 10")
            self._add(cat, "SPF record length", 0, 2, "no record",
                      "Keep the SPF record under 450 characters")
            return cat

        record = spf[0]
        terms = record.split()[1:]
        bad_terms = []
        for term in terms:
            if SPF_TERM_RE.match(term) or SPF_MOD_RE.match(term):
                continue
            bad_terms.append(term)
        multi = len(spf) > 1
        if not bad_terms and not multi:
            self._add(cat, "SPF record syntax validation", 2, 2, "all terms valid")
        elif not bad_terms and multi:
            self._add(cat, "SPF record syntax validation", 1, 2, "valid terms but multiple records",
                      "Consolidate into one SPF record")
        else:
            self._add(cat, "SPF record syntax validation", 0, 2,
                      "invalid terms: " + ", ".join(bad_terms[:5]),
                      "Remove or fix unknown SPF mechanisms")

        version_ok = record.lower().startswith("v=spf1")
        if version_ok:
            self._add(cat, "SPF record version (v=spf1)", 1, 1, "v=spf1 present")
        else:
            self._add(cat, "SPF record version (v=spf1)", 0, 1,
                      "record does not start with v=spf1",
                      "Prefix the record with v=spf1")

        all_term = None
        for term in terms:
            bare = term[1:] if term[:1] in "+-~?" else term
            if bare.lower() == "all":
                all_term = term
                break
        if all_term is None:
            self._add(cat, "SPF mechanisms (+all/~all/-all/?all)", 1, 3, "no all mechanism",
                      "Add -all to explicitly fail unlisted senders")
        else:
            bare = all_term[1:] if all_term[:1] in "+-~?" else all_term
            qualifier = all_term[0] if all_term[0] in "+-~?" else "+"
            if bare.lower() == "all" and qualifier == "-":
                self._add(cat, "SPF mechanisms (+all/~all/-all/?all)", 3, 3, "-all (fail) - strictest")
            elif bare.lower() == "all" and qualifier == "~":
                self._add(cat, "SPF mechanisms (+all/~all/-all/?all)", 2, 3, "~all (softfail)",
                          "Tighten ~all to -all once all legitimate senders are listed")
            elif bare.lower() == "all" and qualifier == "?":
                self._add(cat, "SPF mechanisms (+all/~all/-all/?all)", 1, 3, "?all (neutral)",
                          "Replace ?all with -all")
            else:
                self._add(cat, "SPF mechanisms (+all/~all/-all/?all)", 0, 3, "+all (pass everything) - dangerous",
                          "Never use +all; switch to -all immediately")

        lookups, failures = self._spf_walk(self.domain, record, set(), 0, [])
        if lookups <= 10:
            self._add(cat, "SPF lookup count (limit: 10)", 2, 2, str(lookups) + " DNS lookups (limit 10)")
        elif lookups <= 13:
            self._add(cat, "SPF lookup count (limit: 10)", 1, 2,
                      str(lookups) + " DNS lookups (over limit 10)",
                      "Flatten or remove includes to get back under 10 lookups")
        else:
            self._add(cat, "SPF lookup count (limit: 10)", 0, 2,
                      str(lookups) + " DNS lookups (severely over limit)",
                      "Reduce SPF includes/redirects below the 10-lookup limit")

        includes = [t.split(":", 1)[1] for t in terms if t.lower().startswith("include:")]
        redirects = [t.split("=", 1)[1] for t in terms if t.lower().startswith("redirect=")]
        if failures:
            self._add(cat, "SPF include chain analysis", 1, 2,
                      "broken includes: " + ", ".join(failures[:5]),
                      "Fix or remove SPF includes that have no SPF record: " + ", ".join(failures[:3]))
        elif includes or redirects:
            count = len(includes) + len(redirects)
            self._add(cat, "SPF include chain analysis", 2, 2, str(count) + " include/redirect target(s) resolve")
        else:
            self._add(cat, "SPF include chain analysis", 1, 2, "no include/redirect chain",
                      "Consider include: mechanisms for ESP providers")

        length = len(record)
        if length <= 450:
            self._add(cat, "SPF record length", 2, 2, str(length) + " chars (within 450)")
        elif length <= 1000:
            self._add(cat, "SPF record length", 1, 2,
                      str(length) + " chars (long)",
                      "Shorten the SPF record below 450 characters")
        else:
            self._add(cat, "SPF record length", 0, 2,
                      str(length) + " chars (too long)",
                      "Flatten the SPF record to stay near 450 characters")
        return cat

    def _spf_walk(self, domain, record, seen, depth, failures):
        if depth > 4 or domain in seen:
            return 0, failures
        seen.add(domain)
        lookups = 0
        terms = record.split()[1:] if record.lower().startswith("v=spf1") else record.split()
        for term in terms:
            name = term[1:] if term[:1] in "+-~?" else term
            lowered = name.lower()
            if lowered.startswith("include:"):
                lookups += 1
                target = name.split(":", 1)[1]
                if target not in seen:
                    child = self._load_spf(target)
                    if child:
                        extra, failures = self._spf_walk(target, child, seen, depth + 1, failures)
                        lookups += extra
                    else:
                        failures.append(target)
            elif lowered.startswith("redirect="):
                lookups += 1
                target = name.split("=", 1)[1]
                if target not in seen:
                    child = self._load_spf(target)
                    if child:
                        extra, failures = self._spf_walk(target, child, seen, depth + 1, failures)
                        lookups += extra
                    else:
                        failures.append(target)
            elif lowered in ("a", "mx", "ptr") or lowered.startswith(
                ("a:", "a/", "mx:", "mx/", "ptr:", "exists:")
            ):
                lookups += 1
        return lookups, failures

    def _load_spf(self, domain):
        records = self.dns.txt(domain) or []
        for record in records:
            if record.lower().startswith("v=spf1"):
                return record
        return None

    def check_dkim(self):
        cat = self._new_cat("dkim", "DKIM Record", 15)
        selectors = self.selectors or COMMON_DKIM_SELECTORS
        found = None
        found_selector = None
        tried = []
        for selector in selectors:
            name = selector + "._domainkey." + self.domain
            tried.append(selector)
            records = self.dns.txt(name) or []
            for record in records:
                if "p=" in record:
                    found = record
                    found_selector = selector
                    break
            if found:
                break

        if found:
            self._add(cat, "DKIM record detection", 5, 5,
                      "selector '" + found_selector + "' with public key")
        else:
            self._add(cat, "DKIM record detection", 0, 5,
                      "no key on selectors: " + ", ".join(tried),
                      "Publish a DKIM TXT record (e.g. default._domainkey." + self.domain + ")")

        if not found:
            self._add(cat, "DKIM key type (RSA, Ed25519)", 0, 2, "no key", "Add an RSA or Ed25519 DKIM key")
            self._add(cat, "DKIM key length (2048, 1024, 512)", 0, 3, "no key", "Use a 2048-bit RSA key")
            self._add(cat, "DKIM record syntax validation", 0, 3, "no key", "Publish a valid DKIM record")
            self._add(cat, "DKIM flags (t=y, t=s)", 0, 2, "no key", "Do not set t=y in production keys")
            return cat

        tags, problems = parse_dkim_tags(found)
        key_type = tags.get("k", "rsa").lower()
        if key_type in ("rsa", "ed25519"):
            self._add(cat, "DKIM key type (RSA, Ed25519)", 2, 2, "k=" + key_type)
        else:
            self._add(cat, "DKIM key type (RSA, Ed25519)", 0, 2, "unsupported k=" + key_type,
                      "Use k=rsa or k=ed25519")

        bits = dkim_key_bits(tags)
        if key_type == "ed25519":
            self._add(cat, "DKIM key length (2048, 1024, 512)", 3, 3, "Ed25519 (256-bit equivalent)")
        elif bits is None:
            self._add(cat, "DKIM key length (2048, 1024, 512)", 0, 3, "no usable public key",
                      "Publish a complete base64 p= value")
        elif bits >= 2048:
            self._add(cat, "DKIM key length (2048, 1024, 512)", 3, 3, str(bits) + "-bit RSA key")
        elif bits >= 1024:
            self._add(cat, "DKIM key length (2048, 1024, 512)", 1, 3,
                      str(bits) + "-bit RSA key (weak)",
                      "Rotate to a 2048-bit DKIM key")
        else:
            self._add(cat, "DKIM key length (2048, 1024, 512)", 0, 3,
                      str(bits) + "-bit RSA key (too short)",
                      "Replace with a 2048-bit DKIM key")

        p_ok = bool(tags.get("p"))
        bad_keys = [k for k in tags if k not in ("v", "k", "s", "t", "h", "n", "q", "o", "x", "d", "c", "a", "i", "l", "r", "b", "p", "g", "z")]
        if p_ok and not problems and not bad_keys:
            self._add(cat, "DKIM record syntax validation", 3, 3, "well-formed tag list")
        elif p_ok:
            self._add(cat, "DKIM record syntax validation", 1, 3,
                      "minor issues: " + ", ".join((problems + bad_keys)[:4]),
                      "Remove unknown or malformed DKIM tags")
        else:
            self._add(cat, "DKIM record syntax validation", 0, 3, "missing p= public key",
                      "Include the base64 public key in p=")

        flags = tags.get("t", "")
        flag_list = [f.strip() for f in flags.split(",") if f.strip()] if flags else []
        if "y" in flag_list:
            self._add(cat, "DKIM flags (t=y, t=s)", 0, 2, "t=y test key flag set",
                      "Remove t=y; it marks the key as a test key")
        elif "s" in flag_list:
            self._add(cat, "DKIM flags (t=y, t=s)", 2, 2, "t=s (strict domain matching)")
        else:
            self._add(cat, "DKIM flags (t=y, t=s)", 2, 2, "no test flags (production key)")
        return cat

    def check_dmarc(self):
        cat = self._new_cat("dmarc", "DMARC Record", 15)
        name = "_dmarc." + self.domain
        records = self.dns.txt(name) or []
        dmarc = [r for r in records if r.lower().startswith("v=dmarc1")]
        record = dmarc[0] if dmarc else None
        self.dmarc_record = record

        if record:
            self._add(cat, "DMARC record existence", 3, 3, "found at " + name)
        else:
            self._add(cat, "DMARC record existence", 0, 3, "not found at " + name,
                      "Create a DMARC TXT record at _dmarc." + self.domain)
            self._add(cat, "DMARC policy (none, quarantine, reject)", 0, 4, "no record",
                      "Set p=reject (or start with p=none and rua=)")
            self._add(cat, "DMARC subdomain policy", 0, 2, "no record",
                      "Set sp=reject for subdomains")
            self._add(cat, "DMARC percentage (pct)", 0, 1, "no record", "Set pct=100")
            self._add(cat, "DMARC aggregate report URI (rua)", 0, 2, "no record",
                      "Add rua=mailto:dmarc-reports@" + self.domain)
            self._add(cat, "DMARC forensic report URI (ruf)", 0, 1, "no record",
                      "Add ruf=mailto:dmarc-forensics@" + self.domain)
            self._add(cat, "DMARC alignment mode (adkim, aspf)", 0, 2, "no record",
                      "Add adkim=s and aspf=s for strict alignment")
            return cat

        tags = parse_dmarc_tags(record)
        policy = tags.get("p", "").lower()
        if policy == "reject":
            self._add(cat, "DMARC policy (none, quarantine, reject)", 4, 4, "p=reject")
        elif policy == "quarantine":
            self._add(cat, "DMARC policy (none, quarantine, reject)", 2, 4, "p=quarantine",
                      "Move from p=quarantine to p=reject when reports look clean")
        elif policy == "none":
            self._add(cat, "DMARC policy (none, quarantine, reject)", 1, 4, "p=none (monitor only)",
                      "Upgrade p=none to p=quarantine or p=reject")
        else:
            self._add(cat, "DMARC policy (none, quarantine, reject)", 0, 4, "missing p= tag",
                      "Add an explicit p= tag to the DMARC record")

        sp = tags.get("sp", "").lower()
        if sp in ("reject", "quarantine"):
            self._add(cat, "DMARC subdomain policy", 2, 2, "sp=" + sp)
        elif sp == "none":
            self._add(cat, "DMARC subdomain policy", 0, 2, "sp=none",
                      "Set sp=reject so subdomains inherit protection")
        else:
            self._add(cat, "DMARC subdomain policy", 1, 2, "sp not set (inherits p=" + policy + ")",
                      "Consider an explicit sp= tag for subdomain control")

        pct_raw = tags.get("pct", "100")
        try:
            pct = int(pct_raw)
        except ValueError:
            pct = -1
        if pct == 100:
            self._add(cat, "DMARC percentage (pct)", 1, 1, "pct=100 (full enforcement)")
        elif pct > 0:
            self._add(cat, "DMARC percentage (pct)", 0, 1, "pct=" + str(pct) + " (partial)",
                      "Raise pct to 100 for full DMARC enforcement")
        else:
            self._add(cat, "DMARC percentage (pct)", 0, 1, "invalid pct value",
                      "Use pct=100")

        rua = tags.get("rua", "")
        if rua:
            self._add(cat, "DMARC aggregate report URI (rua)", 2, 2, rua)
        else:
            self._add(cat, "DMARC aggregate report URI (rua)", 0, 2, "rua not set",
                      "Add rua=mailto:dmarc-reports@" + self.domain)

        ruf = tags.get("ruf", "")
        if ruf:
            self._add(cat, "DMARC forensic report URI (ruf)", 1, 1, ruf)
        else:
            self._add(cat, "DMARC forensic report URI (ruf)", 0, 1, "ruf not set",
                      "Add ruf=mailto:dmarc-forensics@" + self.domain)

        adkim = tags.get("adkim", "r").lower()
        aspf = tags.get("aspf", "r").lower()
        strict_count = (1 if adkim == "s" else 0) + (1 if aspf == "s" else 0)
        detail = "adkim=" + adkim + "; aspf=" + aspf
        if strict_count == 2:
            self._add(cat, "DMARC alignment mode (adkim, aspf)", 2, 2, detail + " (both strict)")
        else:
            self._add(cat, "DMARC alignment mode (adkim, aspf)", 1, 2, detail,
                      "Set adkim=s and aspf=s for strict alignment")
        return cat


def parse_dmarc_tags(record):
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        tags[key.strip().lower()] = value.strip()
    return tags


def check_dnssec(self):
    cat = self._new_cat("dnssec", "DNS Security", 10)
    ad = self.dns.ad_flag(self.domain)
    dnskey = self.dns.query(self.domain, "DNSKEY")
    signed = (ad is True) or bool(dnskey)
    if signed:
        source = "DNSSEC-signed (AD flag)" if ad else "DNSKEY record present"
        self._add(cat, "DNSSEC validation", 4, 4, source)
    elif ad is False:
        self._add(cat, "DNSSEC validation", 0, 4, "resolver reports no AD flag",
                  "Sign the zone with DNSSEC at your registrar")
    else:
        self._add(cat, "DNSSEC validation", 0, 4, "no DNSKEY/AD indicator",
                  "Enable DNSSEC signing for " + self.domain)

    caa = self.dns.query(self.domain, "CAA")
    if caa:
        issues = [line for line in caa if "issue" in line]
        sample = issues[0] if issues else caa[0]
        self._add(cat, "CAA record (Certificate Authority Authorization)", 3, 3, sample)
    else:
        self._add(cat, "CAA record (Certificate Authority Authorization)", 0, 3,
                  "no CAA record",
                  "Publish a CAA record to restrict certificate issuance")

    tlsrpt = self.dns.txt("_smtp._tls." + self.domain) or []
    tlsrpt_ok = [r for r in tlsrpt if "v=TLSRPT" in r or "rua=" in r]
    if tlsrpt_ok:
        self._add(cat, "TLSRPT record (TLS reporting)", 2, 2, tlsrpt_ok[0][:100])
    else:
        self._add(cat, "TLSRPT record (TLS reporting)", 0, 2, "not found at _smtp._tls." + self.domain,
                  "Add a TLSRPT TXT record with rua= for TLS failure reports")

    rua = ""
    if self.dmarc_record:
        rua = parse_dmarc_tags(self.dmarc_record).get("rua", "")
    if rua:
        self._add(cat, "RUA record (Aggregate reporting)", 1, 1, rua[:100])
    else:
        self._add(cat, "RUA record (Aggregate reporting)", 0, 1, "no rua= endpoint",
                  "Add rua= to your DMARC record for aggregate reporting")
    return cat


def check_mailsec(self):
    cat = self._new_cat("mailsec", "Mail Server Security", 10)
    host = self.primary_mx_host
    if not host:
        self._add(cat, "SMTP STARTTLS support", 0, 4, "no MX host to probe",
                  "Fix MX records before mail security probing")
        self._add(cat, "SMTP TLS version", 0, 3, "no MX host to probe", "Fix MX records")
        self._add(cat, "SMTP authentication support", 0, 2, "no MX host to probe", "Fix MX records")
        self._add(cat, "Mail server banner analysis", 0, 1, "no MX host to probe", "Fix MX records")
        return cat

    self.vlog("SMTP probe " + host + ":25")
    probe = smtp_probe(host, self.timeout)
    error = probe.get("error")

    if probe.get("starttls"):
        self._add(cat, "SMTP STARTTLS support", 4, 4, "STARTTLS advertised by " + host)
    elif error:
        self._add(cat, "SMTP STARTTLS support", 0, 4, "probe failed: " + error,
                  "Ensure port 25 is reachable and STARTTLS is offered on " + host)
    else:
        self._add(cat, "SMTP STARTTLS support", 0, 4, "STARTTLS not offered",
                  "Enable STARTTLS on the receiving MTA")

    version = probe.get("tls_version")
    if version in ("TLSv1.3", "TLSv1.2"):
        self._add(cat, "SMTP TLS version", 3, 3, version)
    elif version in ("TLSv1.1", "TLSv1.0"):
        self._add(cat, "SMTP TLS version", 1, 3, version + " (deprecated)",
                  "Disable TLS 1.0/1.1; require TLS 1.2+")
    elif error:
        self._add(cat, "SMTP TLS version", 0, 3, "not determined: " + error, "Enable STARTTLS")
    else:
        self._add(cat, "SMTP TLS version", 0, 3, "no TLS session",
                  "Enable STARTTLS to negotiate modern TLS")

    if probe.get("auth"):
        self._add(cat, "SMTP authentication support", 2, 2, "AUTH advertised after EHLO")
    elif error:
        self._add(cat, "SMTP authentication support", 0, 2, "not determined: " + error,
                  "Probe failed; verify SMTP services on " + host)
    else:
        self._add(cat, "SMTP authentication support", 0, 2, "AUTH not advertised on port 25",
                  "Offer AUTH on submission; port 25 AUTH is optional")

    banner = probe.get("banner") or ""
    if banner.startswith("220"):
        lowered = banner.lower()
        software = any(token in lowered for token in
                       ("postfix", "exim", "sendmail", "exchange", "hmail", "gmail", "google", "microsoft", "mailenable", "opensmtpd", "dovecot"))
        domainish = self.domain in lowered or "smtp" in lowered or "esmtp" in lowered
        if software or domainish:
            self._add(cat, "Mail server banner analysis", 1, 1, banner[:90])
        else:
            self._add(cat, "Mail server banner analysis", 1, 1, "generic banner: " + banner[:70],
                      "Consider a banner that identifies the MTA/hostname")
    elif error:
        self._add(cat, "Mail server banner analysis", 0, 1, "no banner: " + error,
                  "Check that " + host + " listens on port 25")
    else:
        self._add(cat, "Mail server banner analysis", 0, 1, "missing or invalid banner",
                  "Return a 220 greeting banner from the MTA")
    return cat


def check_reputation(self):
    cat = self._new_cat("reputation", "IP Reputation Hints", 5)
    ip = self.primary_mx_ip
    if not ip:
        self._add(cat, "IP blacklist check (DNS-based)", 0, 2, "no MX IP resolved",
                  "Resolve MX hosts before reputation checks")
        self._add(cat, "Reverse DNS (PTR) record", 0, 2, "no IP to reverse lookup",
                  "Resolve MX hosts first")
        self._add(cat, "IP geolocation", 0, 1, "no IP available", "Resolve MX hosts first")
        return cat

    is_v4 = re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) is not None
    listed = []
    unknown = []
    if is_v4:
        reversed_ip = ".".join(reversed(ip.split(".")))
        for bl in DNSBL_SERVERS:
            query = reversed_ip + "." + bl
            answers = self.dns.query(query, "A")
            if answers is None:
                unknown.append(bl)
                continue
            for answer in answers:
                if answer.startswith("127.255.255"):
                    unknown.append(bl)
                elif answer.startswith("127."):
                    listed.append(bl + " -> " + answer)
        if listed:
            self._add(cat, "IP blacklist check (DNS-based)", 0, 2,
                      "listed on " + ", ".join(listed),
                      "Delist " + ip + " and remediate the listing")
        elif unknown and len(unknown) == len(DNSBL_SERVERS):
            self._add(cat, "IP blacklist check (DNS-based)", 1, 2,
                      "blacklist queries inconclusive (" + ", ".join(unknown[:3]) + ")")
        else:
            self._add(cat, "IP blacklist check (DNS-based)", 2, 2,
                      "clean on " + str(len(DNSBL_SERVERS)) + " DNSBLs (" + ip + ")")
    else:
        self._add(cat, "IP blacklist check (DNS-based)", 1, 2,
                  "IPv6 " + ip + " (most DNSBLs are IPv4-only)")

    ptr_host = None
    try:
        ptr_host, _aliases, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, OSError):
        ptr_host = None

    if ptr_host:
        forward_ok = False
        try:
            forward_ok = socket.gethostbyname(ptr_host) == ip
        except (socket.gaierror, OSError):
            forward_ok = False
        if forward_ok:
            self._add(cat, "Reverse DNS (PTR) record", 2, 2,
                      "FCrDNS confirmed: " + ptr_host + " -> " + ip)
        else:
            self._add(cat, "Reverse DNS (PTR) record", 1, 2,
                      "PTR exists but forward lookup differs: " + ptr_host,
                      "Align PTR and A records (forward-confirmed reverse DNS)")
    else:
        self._add(cat, "Reverse DNS (PTR) record", 0, 2, "no PTR for " + ip,
                  "Set a PTR record for " + ip + " matching your mail hostname")

    if not HAS_REQUESTS:
        self._add(cat, "IP geolocation", 0, 1, "requests library unavailable",
                  "Install requests to enable geolocation lookup")
    else:
        try:
            geo = requests.get(
                "http://ip-api.com/json/" + ip,
                params={"fields": "status,message,country,regionName,city,isp,org,as"},
                timeout=min(self.timeout, 8),
            )
            data = geo.json()
            if data.get("status") == "success":
                place = ", ".join(filter(None, [
                    data.get("city"), data.get("country")
                ]))
                org = data.get("org") or data.get("isp") or ""
                detail = (place + " | " + org).strip(" |")
                self._add(cat, "IP geolocation", 1, 1, detail[:100])
            else:
                self._add(cat, "IP geolocation", 0, 1, data.get("message", "lookup failed"))
        except Exception as exc:
            self._add(cat, "IP geolocation", 0, 1, "lookup failed: " + str(exc))
    return cat


def check_headers(self):
    cat = self._new_cat("headers", "Email Headers Analysis", 5)
    text, path = load_headers_text()
    if not text:
        detail = "headers.txt not found (add full headers for analysis)"
        self._add(cat, "Mailer detection", 0, 2, detail,
                  "Create headers.txt with a pasted Received/Message-ID header block")
        self._add(cat, "Message-ID format", 0, 1, detail,
                  "Create headers.txt to validate Message-ID format")
        self._add(cat, "Received header chain", 0, 2, detail,
                  "Create headers.txt to inspect the Received chain")
        return cat

    mailer_tokens = [
        "x-mailer", "user-agent", "x-mimeole", "microsoft outlook", "postfix",
        "sendmail", "exim", "gmail.com", "amazon ses", "mailgun", "sendgrid",
        "sparkpost", "roundcube", "apple mail", "mozilla", "opensmtpd",
        "lotus notes", "zimbra", "phpmailer",
    ]
    lowered = text.lower()
    detected = [token for token in mailer_tokens if token in lowered]
    if detected:
        self._add(cat, "Mailer detection", 2, 2, "detected: " + ", ".join(detected[:4]) +
                  (" via " + os.path.basename(path) if path else ""))
    else:
        self._add(cat, "Mailer detection", 0, 2, "no mailer identification headers",
                  "Add/keep X-Mailer or identifiable Received MTA strings")

    msgid_match = re.search(r"(?im)^Message-ID:\s*<([^<>\s]+)@([^<>\s]+)>", text)
    if msgid_match:
        local = msgid_match.group(1)
        host = msgid_match.group(2)
        if len(local) >= 4 and "." in host:
            self._add(cat, "Message-ID format", 1, 1, "<" + local + "@" + host + ">")
        else:
            self._add(cat, "Message-ID format", 0, 1, "weak Message-ID <" + local + "@" + host + ">",
                      "Generate unique Message-IDs like <unique@yourdomain>")
    elif re.search(r"(?im)^Message-ID:", text):
        self._add(cat, "Message-ID format", 0, 1, "Message-ID present but malformed",
                  "Use <id@domain> format for Message-ID")
    else:
        self._add(cat, "Message-ID format", 0, 1, "Message-ID header missing",
                  "Always set a unique Message-ID header")

    received_lines = re.findall(r"(?im)^Received:.*$", text)
    count = len(received_lines)
    if count >= 2:
        self._add(cat, "Received header chain", 2, 2, str(count) + " Received hops traced")
    elif count == 1:
        self._add(cat, "Received header chain", 1, 2, "only 1 Received hop",
                  "Full delivery paths usually show 2+ Received headers")
    else:
        self._add(cat, "Received header chain", 0, 2, "no Received headers",
                  "Include full Received headers for chain analysis")
    return cat


def check_mta_sts(self):
    cat = self._new_cat("mta_sts", "MTA-STS", 5)
    name = "_mta-sts." + self.domain
    records = self.dns.txt(name) or []
    sts = [r for r in records if "v=STSv1" in r or "STSv" in r]

    if sts and sts[0].startswith("v=STSv1"):
        self._add(cat, "MTA-STS record existence", 2, 2, "found at " + name + ": " + sts[0][:60])
    elif sts:
        self._add(cat, "MTA-STS record existence", 1, 2, "record present but wrong version",
                  "Use v=STSv1 in the _mta-sts TXT record")
    else:
        self._add(cat, "MTA-STS record existence", 0, 2, "not found at " + name,
                  "Publish a TXT record at _mta-sts." + self.domain + " (v=STSv1; id=...)")
        self._add(cat, "MTA-STS policy mode", 0, 2, "no policy", "Deploy an MTA-STS policy file")
        self._add(cat, "MTA-STS policy validation", 0, 1, "no policy", "Deploy an MTA-STS policy file")
        return cat

    policy_url = "https://mta-sts." + self.domain + "/.well-known/mta-sts.txt"
    mode = None
    mx_patterns = []
    version_ok = False
    fetch_error = None
    if not HAS_REQUESTS:
        fetch_error = "requests library unavailable"
    else:
        try:
            resp = requests.get(
                policy_url,
                timeout=min(self.timeout, 10),
                headers={"User-Agent": TOOL_NAME + "/" + TOOL_VERSION},
            )
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" not in line:
                        continue
                    key, value = line.split(":", 1)
                    key = key.strip().lower()
                    value = value.strip()
                    if key == "version" and value.upper() == "STSV1":
                        version_ok = True
                    if key == "mode":
                        mode = value.lower()
                    if key == "mx":
                        mx_patterns.append(value)
            else:
                fetch_error = "HTTP " + str(resp.status_code)
        except Exception as exc:
            fetch_error = str(exc)

    if mode == "enforce":
        self._add(cat, "MTA-STS policy mode", 2, 2, "mode: enforce")
    elif mode == "testing":
        self._add(cat, "MTA-STS policy mode", 1, 2, "mode: testing",
                  "Move MTA-STS mode from testing to enforce")
    elif mode == "none":
        self._add(cat, "MTA-STS policy mode", 0, 2, "mode: none",
                  "Set mode: enforce in the MTA-STS policy")
    else:
        self._add(cat, "MTA-STS policy mode", 0, 2,
                  "policy fetch failed: " + (fetch_error or "no mode line"),
                  "Serve a valid policy at " + policy_url)

    if version_ok and mx_patterns:
        self._add(cat, "MTA-STS policy validation", 1, 1,
                  "STSv1 with " + str(len(mx_patterns)) + " mx pattern(s)")
    elif version_ok:
        self._add(cat, "MTA-STS policy validation", 0, 1, "version ok but no mx: entries",
                  "List expected MX hosts with mx: lines in the policy")
    else:
        self._add(cat, "MTA-STS policy validation", 0, 1,
                  "invalid policy: " + (fetch_error or "missing version: STSv1"),
                  "Include version: STSv1 and mx: entries in the policy file")
    return cat


def check_bimi(self):
    cat = self._new_cat("bimi", "BIMI", 5)
    name = "default._bimi." + self.domain
    records = self.dns.txt(name) or []
    bimi = [r for r in records if "v=BIMI1" in r or "BIMI" in r]

    if bimi and bimi[0].startswith("v=BIMI1"):
        self._add(cat, "BIMI record existence", 2, 2, "found at " + name)
    elif bimi:
        self._add(cat, "BIMI record existence", 1, 2, "record present but version tag wrong",
                  "Use v=BIMI1 in the BIMI record")
    else:
        self._add(cat, "BIMI record existence", 0, 2, "not found at " + name,
                  "Publish a BIMI record at default._bimi." + self.domain)
        self._add(cat, "BIMI SVG certificate", 0, 1, "no record", "Add l= with your SVG logo URL")
        self._add(cat, "VMC (Verified Mark Certificate)", 0, 2, "no record",
                  "Obtain a VMC and reference it in the a= tag")
        return cat

    tags, _problems = parse_dkim_tags(bimi[0])
    logo = tags.get("l", "")
    if logo:
        self._add(cat, "BIMI SVG certificate", 1, 1, logo[:90])
    else:
        self._add(cat, "BIMI SVG certificate", 0, 1, "l= SVG URL missing",
                  "Add l=https://.../logo.svg pointing to a valid BIMI SVG")

    cert = tags.get("a") or tags.get("vc") or ""
    if cert:
        kind = "VMC" if tags.get("a") else "certificate reference"
        self._add(cat, "VMC (Verified Mark Certificate)", 2, 2, kind + ": " + cert[:80])
    else:
        self._add(cat, "VMC (Verified Mark Certificate)", 0, 2, "no a=/vc= certificate tag",
                  "Add a= with your VMC/SMC certificate URL for verified marks")
    return cat


EmailAnalyzer.check_dnssec = check_dnssec
EmailAnalyzer.check_mailsec = check_mailsec
EmailAnalyzer.check_reputation = check_reputation
EmailAnalyzer.check_headers = check_headers
EmailAnalyzer.check_mta_sts = check_mta_sts
EmailAnalyzer.check_bimi = check_bimi


def check_dane(self):
    cat = self._new_cat("dane", "DANE TLSA", 5)
    hosts = []
    for _pref, host in self.mx_records:
        if host and host not in hosts and not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
            hosts.append(host)
    if not hosts:
        self._add(cat, "TLSA record existence", 0, 3, "no MX host to query",
                  "Fix MX records before DANE checks")
        self._add(cat, "DANE usage mode", 0, 1, "no MX host", "Fix MX records first")
        self._add(cat, "TLSA selector/matching type", 0, 1, "no MX host", "Fix MX records first")
        return cat

    query_host = hosts[0]
    name = "_25._tcp." + query_host
    records = self.dns.query(name, "TLSA") or []
    tlsa = []
    for record in records:
        parts = str(record).split()
        if len(parts) >= 4 and parts[0].isdigit():
            tlsa.append(parts)

    if tlsa:
        self._add(cat, "TLSA record existence", 3, 3,
                  str(len(tlsa)) + " TLSA record(s) at " + name)
    else:
        self._add(cat, "TLSA record existence", 0, 3, "not found at " + name,
                  "Publish DANE TLSA records for " + query_host +
                  " (openssl s_client -showcerts | openssl x509 ... then dig TLSA)")

    if not tlsa:
        self._add(cat, "DANE usage mode", 0, 1, "no record",
                  "Use usage=3 (DANE-EE) to bind the MX certificate via DNS")
        self._add(cat, "TLSA selector/matching type", 0, 1, "no record",
                  "Publish selector=1 matching=1 TLSA data")
        return cat

    usage = tlsa[0][0]
    if usage == "3":
        self._add(cat, "DANE usage mode", 1, 1, "usage=3 (DANE-EE)")
    elif usage == "2":
        self._add(cat, "DANE usage mode", 1, 1, "usage=2 (DANE-TA)",
                  "Prefer usage=3 for end-entity MX certificates")
    else:
        self._add(cat, "DANE usage mode", 0, 1, "usage=" + usage + " (not recommended for SMTP)",
                  "Prefer usage=3 (DANE-EE) for mail certificate association")

    selector = tlsa[0][1]
    matching = tlsa[0][2]
    cert_hex = tlsa[0][3]
    if selector in ("0", "1") and matching in ("0", "1", "2") and len(cert_hex) >= 32:
        self._add(cat, "TLSA selector/matching type", 1, 1,
                  "selector=" + selector + " matching=" + matching +
                  " (" + str(len(cert_hex)) + " hex chars)")
    else:
        self._add(cat, "TLSA selector/matching type", 0, 1,
                  "malformed: selector=" + selector + " matching=" + matching,
                  "Use selector 0/1 and matching 0/1/2 with full certificate data")
    return cat


EmailAnalyzer.check_dane = check_dane


def run_analysis(self):
    self.vlog("starting analysis for " + self.domain)
    steps = [
        ("mx", self.check_mx),
        ("spf", self.check_spf),
        ("dkim", self.check_dkim),
        ("dmarc", self.check_dmarc),
        ("dnssec", self.check_dnssec),
        ("mailsec", self.check_mailsec),
        ("reputation", self.check_reputation),
        ("headers", self.check_headers),
        ("mta_sts", self.check_mta_sts),
        ("bimi", self.check_bimi),
        ("dane", self.check_dane),
    ]
    categories = []
    for cid, fn in steps:
        try:
            cat = fn()
        except Exception as exc:
            cat = self._new_cat(cid, cid, 0)
            self.vlog("category " + cid + " failed: " + str(exc))
            print(self.pal.yellow("  [!] ") + "check '" + cid + "' failed: " + str(exc))
        categories.append(cat)

    total = int(round(sum(c["score"] for c in categories)))
    total = max(0, min(100, total))
    grade = grade_for(total)
    recommendations = []
    for cat in categories:
        for check in cat["checks"]:
            advice = check.get("advice") or ""
            if advice and advice not in recommendations:
                recommendations.append(advice)
    duration = round(time.time() - self.start_time, 2)
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "domain": self.domain,
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "timeout": self.timeout,
        "duration_seconds": duration,
        "score": total,
        "grade": grade,
        "grade_label": GRADE_LABELS.get(grade, ""),
        "categories": categories,
        "recommendations": recommendations,
        "summary": {
            c["id"]: {"name": c["name"], "score": c["score"], "max": c["max"]}
            for c in categories
        },
    }


EmailAnalyzer.run = run_analysis


def grade_color(pal, grade):
    if grade in ("A+", "A"):
        return pal.bright_green(grade)
    if grade == "B":
        return pal.bright_cyan(grade)
    if grade == "C":
        return pal.bright_yellow(grade)
    if grade == "D":
        return pal.bright_magenta(grade)
    return pal.bright_red(grade)


def progress_bar(pal, score, max_points, width=12):
    if max_points <= 0:
        return pal.gray("[" + " " * width + "]")
    filled = int(round(score * width / float(max_points)))
    filled = max(0, min(width, filled))
    bar = "#" * filled + "-" * (width - filled)
    ratio = score / float(max_points)
    if ratio >= 0.99:
        color = pal.green
    elif ratio >= 0.6:
        color = pal.yellow
    else:
        color = pal.red
    return color("[" + bar + "]")


def print_report(results, pal, verbose=False):
    print(pal.bold("  Analysis Report"))
    print(pal.gray("  Target: " + results["domain"] +
                   "   Timeout: " + str(results["timeout"]) + "s" +
                   "   Generated: " + results["generated"]))
    print()

    for cat in results["categories"]:
        header = "  " + pal.bold(pal.white(cat["name"])) + "  " + \
            progress_bar(pal, cat["score"], cat["max"]) + "  " + \
            pal.bold(str(cat["score"]) + "/" + str(cat["max"]))
        print(header)
        for check in cat["checks"]:
            if check["points"] >= check["max"]:
                symbol = pal.green("PASS")
            elif check["points"] > 0:
                symbol = pal.yellow("WARN")
            else:
                symbol = pal.red("FAIL")
            name = check["name"]
            if len(name) > 40:
                name = name[:37] + "..."
            detail = check["detail"]
            if not verbose and len(detail) > 70:
                detail = detail[:67] + "..."
            line = "    " + symbol + "  " + name.ljust(42) + \
                str(check["points"]).rjust(2) + "/" + str(check["max"]) + "  " + \
                pal.gray(detail)
            print(line)
            if verbose and check.get("advice"):
                print(pal.gray("           -> " + check["advice"]))
        print()

    total = results["score"]
    grade = results["grade"]
    label = results.get("grade_label", "")
    width = 54
    top = "  +" + "-" * width + "+"

    def boxed(prefix_plain, value_colored, suffix_plain):
        plain_value = re.sub(r"\033\[[0-9;]*m", "", value_colored)
        visible = len(prefix_plain) + len(plain_value) + len(suffix_plain)
        inner = width - visible
        return "  |" + prefix_plain + value_colored + suffix_plain + " " * max(0, inner) + "|"

    print(top)
    print(boxed("  DELIVERABILITY SCORE : ",
                pal.bold(pal.bright_cyan(str(total))),
                " / 100"))
    print(boxed("  GRADE                : ", grade_color(pal, grade), ""))
    print(pal.gray("  |  " + label.ljust(width - 2) + "|"))
    print(top)
    print()

    recs = results.get("recommendations") or []
    if recs:
        print(pal.bold("  Recommendations"))
        for index, item in enumerate(recs[:14], 1):
            print("   " + pal.yellow(str(index) + ".") + " " + item)
        if len(recs) > 14:
            print(pal.gray("   ... " + str(len(recs) - 14) + " more"))
        print()
    else:
        print(pal.green("  No configuration issues detected."))
        print()

    print(pal.gray("  Completed in " + str(results.get("duration_seconds", "?")) + "s"))
    print()


def export_json(results, path):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2, ensure_ascii=False)
    return path


def export_csv(results, path):
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "category_id", "category", "check", "status",
            "points", "max_points", "detail", "advice",
        ])
        for cat in results["categories"]:
            for check in cat["checks"]:
                if check["points"] >= check["max"]:
                    status = "pass"
                elif check["points"] > 0:
                    status = "warn"
                else:
                    status = "fail"
                writer.writerow([
                    cat["id"], cat["name"], check["name"], status,
                    check["points"], check["max"], check["detail"],
                    check.get("advice", ""),
                ])
        writer.writerow([])
        writer.writerow(["summary", "total", "score", results["grade"],
                         results["score"], 100, results.get("grade_label", ""), ""])
    return path


HTML_CSS = """
:root {
  --bg: #0a1020;
  --panel: #111a2e;
  --border: #1e2a44;
  --text: #e6edf7;
  --muted: #8b9bb4;
  --accent: #2dd4bf;
  --good: #34d399;
  --warn: #f59e0b;
  --bad: #f87171;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: "Segoe UI", Helvetica, Arial, sans-serif;
  line-height: 1.5;
}
.wrap { max-width: 960px; margin: 0 auto; padding: 40px 24px 72px; }
header { border-bottom: 1px solid var(--border); padding-bottom: 28px; margin-bottom: 32px; }
h1 {
  font-family: Georgia, "Times New Roman", serif;
  font-size: 2rem;
  font-weight: 600;
  margin: 0 0 6px;
  letter-spacing: 0.02em;
}
.meta { color: var(--muted); font-size: 0.9rem; }
.score-row { display: flex; align-items: center; gap: 32px; margin: 8px 0 36px; flex-wrap: wrap; }
.ring {
  --p: 0;
  width: 148px;
  height: 148px;
  border-radius: 50%;
  background: conic-gradient(var(--accent) calc(var(--p) * 1%), var(--border) 0);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.ring-inner {
  width: 118px;
  height: 118px;
  border-radius: 50%;
  background: var(--bg);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}
.ring-inner strong { font-size: 2.4rem; font-family: Georgia, serif; }
.ring-inner span { color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; }
.grade-box .grade {
  font-family: Georgia, serif;
  font-size: 3.4rem;
  line-height: 1;
  margin: 0;
}
.grade-box p { margin: 8px 0 0; color: var(--muted); max-width: 26ch; }
section { margin-bottom: 36px; }
h2 {
  font-family: Georgia, serif;
  font-size: 1.15rem;
  font-weight: 600;
  margin: 0 0 14px;
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 12px;
}
h2 .pts { color: var(--accent); font-size: 0.95rem; font-family: "Segoe UI", sans-serif; }
.bar { height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; margin-bottom: 12px; }
.bar > i { display: block; height: 100%; background: var(--accent); }
table { width: 100%; border-collapse: collapse; font-size: 0.92rem; }
th {
  text-align: left;
  color: var(--muted);
  font-weight: 500;
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  padding: 8px 10px;
  border-bottom: 1px solid var(--border);
}
td { padding: 9px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
td.pts { white-space: nowrap; font-variant-numeric: tabular-nums; }
tr.pass td.pts { color: var(--good); }
tr.warn td.pts { color: var(--warn); }
tr.fail td.pts { color: var(--bad); }
td.detail { color: var(--muted); }
ol.recs { margin: 0; padding-left: 22px; }
ol.recs li { margin-bottom: 8px; }
footer { color: var(--muted); font-size: 0.82rem; border-top: 1px solid var(--border); padding-top: 18px; }
@media (max-width: 640px) {
  .score-row { gap: 18px; }
  td.detail { display: none; }
}
"""


def export_html(results, path):
    parts = []
    parts.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
    parts.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
    parts.append("<title>EmailAnalyzer report - " + html_escape(results["domain"]) + "</title>\n")
    parts.append("<style>" + HTML_CSS + "</style>\n</head>\n<body>\n<div class=\"wrap\">\n")
    parts.append("<header><h1>EmailAnalyzer <span style=\"color:var(--accent)\">v" +
                 html_escape(results["version"]) + "</span></h1>")
    parts.append("<p class=\"meta\">" + html_escape(results["domain"]) +
                 " &mdash; generated " + html_escape(results["generated"]) +
                 " &mdash; timeout " + str(results["timeout"]) + "s</p></header>\n")

    pct = results["score"]
    parts.append("<div class=\"score-row\">")
    parts.append("<div class=\"ring\" style=\"--p:" + str(pct) + "\"><div class=\"ring-inner\">" +
                 "<strong>" + str(results["score"]) + "</strong><span>of 100</span></div></div>")
    parts.append("<div class=\"grade-box\"><p class=\"grade\" style=\"color:" +
                 ("var(--good)" if results["score"] >= 90 else
                  "var(--accent)" if results["score"] >= 75 else
                  "var(--warn)" if results["score"] >= 60 else
                  "var(--bad)") + "\">" + html_escape(results["grade"]) + "</p>" +
                 "<p>" + html_escape(results.get("grade_label", "")) + "</p></div>")
    parts.append("</div>\n")

    for cat in results["categories"]:
        cat_pct = 0
        if cat["max"]:
            cat_pct = int(round(cat["score"] * 100 / float(cat["max"])))
        parts.append("<section><h2>" + html_escape(cat["name"]) +
                     "<span class=\"pts\">" + str(cat["score"]) + "/" + str(cat["max"]) +
                     "</span></h2>")
        parts.append("<div class=\"bar\"><i style=\"width:" + str(cat_pct) + "%\"></i></div>")
        parts.append("<table><thead><tr><th>Check</th><th>Points</th><th>Detail</th></tr></thead><tbody>")
        for check in cat["checks"]:
            if check["points"] >= check["max"]:
                status = "pass"
            elif check["points"] > 0:
                status = "warn"
            else:
                status = "fail"
            parts.append(
                "<tr class=\"" + status + "\"><td>" + html_escape(check["name"]) +
                "</td><td class=\"pts\">" + str(check["points"]) + "/" + str(check["max"]) +
                "</td><td class=\"detail\">" + html_escape(check["detail"]) + "</td></tr>"
            )
        parts.append("</tbody></table></section>\n")

    recs = results.get("recommendations") or []
    if recs:
        parts.append("<section><h2>Recommendations</h2><ol class=\"recs\">")
        for item in recs:
            parts.append("<li>" + html_escape(item) + "</li>")
        parts.append("</ol></section>\n")

    parts.append("<footer>Score " + str(results["score"]) + "/100 &middot; grade " +
                 html_escape(results["grade"]) + " &middot; " + html_escape(results["tool"]) +
                 " v" + html_escape(results["version"]) + "</footer>\n")
    parts.append("</div>\n</body>\n</html>\n")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("".join(parts))
    return path


def safe_filename(domain):
    return re.sub(r"[^A-Za-z0-9._-]", "_", domain) or "report"


def run_exports(results, export, pal):
    if not export or export == "none":
        return []
    base = "emailanalyzer_" + safe_filename(results["domain"])
    written = []
    formats = ["json", "csv", "html"] if export == "all" else [export]
    for fmt in formats:
        path = base + "." + fmt
        try:
            if fmt == "json":
                export_json(results, path)
            elif fmt == "csv":
                export_csv(results, path)
            elif fmt == "html":
                export_html(results, path)
            else:
                continue
            written.append(path)
            print(pal.green("  [+] ") + "Exported " + fmt.upper() + " -> " + path)
        except OSError as exc:
            print(pal.red("  [!] ") + "Failed to write " + path + ": " + str(exc))
    return written


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="emailanalyzer",
        description="EmailAnalyzer v2.0 - email deliverability configuration analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  python emailanalyzer.py -u example.com\n"
               "  python emailanalyzer.py -u https://example.com -v --export all\n"
               "  python emailanalyzer.py -u example.com --selector google,selector1 --no-color\n",
    )
    parser.add_argument("-u", "--url", required=True,
                        help="target URL/domain (e.g. example.com)")
    parser.add_argument("-t", "--timeout", type=float, default=15,
                        help="network timeout in seconds (default: 15)")
    parser.add_argument("--export", default="none",
                        choices=["all", "json", "csv", "html", "none"],
                        help="export format (default: none)")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    parser.add_argument("--selector", default=None,
                        help="DKIM selector(s) to test, comma-separated (default: common selectors)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    color_enabled = (not args.no_color) and sys.stdout.isatty()
    pal = Palette(color_enabled)
    print_banner(pal)

    domain = normalize_target(args.url)
    if not domain or not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", domain):
        print(pal.red("  [!] ") + "Invalid target: " + str(args.url))
        print(pal.gray("      Provide a domain like example.com or https://example.com/path"))
        return 2

    if args.timeout <= 0:
        args.timeout = 15

    print(pal.cyan("  [*] ") + "Analyzing " + pal.bold(domain) +
          " (timeout " + str(args.timeout) + "s)")
    if args.selector:
        print(pal.cyan("  [*] ") + "DKIM selectors: " + args.selector)
    if not HAS_REQUESTS:
        print(pal.yellow("  [!] ") + "requests library unavailable - HTTP checks will be skipped")
    print()

    analyzer = EmailAnalyzer(
        domain,
        timeout=args.timeout,
        verbose=args.verbose,
        selector=args.selector,
        pal=pal,
    )
    results = analyzer.run()
    print_report(results, pal, verbose=args.verbose)
    run_exports(results, args.export, pal)
    if args.export != "none":
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
