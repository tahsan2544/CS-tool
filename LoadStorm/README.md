# LoadStorm v4.0

### Ultimate Website Load & Stress Testing Tool for Cybersecurity Professionals

> Test how much concurrent traffic your infrastructure can handle — up to **10 million virtual users** — before it degrades or crashes.

```
     ██╗      ██████╗ ███╗   ██╗██████╗ ███████╗██████╗ ████████╗
     ██║     ██╔═══██╗████╗  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
     ██║     ██║   ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝   ██║
     ██║     ██║   ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗   ██║
     ███████╗╚██████╔╝██║ ╚████║██████╔╝███████╗██║  ██║   ██║
     ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝
```

---

## What is LoadStorm?

LoadStorm is a **powerful, lightweight, cross-platform** load testing tool built for cybersecurity professionals who need to verify infrastructure resilience under massive concurrent traffic. It uses an **async Python engine** capable of simulating **10 million+ virtual users** with realistic browser behavior.

---

## Features

### Core Capabilities
- **10M+ Virtual Users** — Scale beyond anything your server can handle
- **Async Engine** — Built on `aiohttp` with connection pooling for maximum performance
- **10 Attack Patterns** — Constant, Ramp, Spike, Wave, Stepped, Pulse, Targeted, Staircase, Elastic, Random Chaos
- **Multi-URL Testing** — Test multiple endpoints simultaneously
- **WebSocket Support** — Test WebSocket connections at scale
- **Scenario Chains** — Chain multiple requests in sequence (login -> dashboard -> action)
- **Real-time Dashboard** — Live stats with latency distribution, sparkline trends, progress bars
- **Cross-Platform** — Works on Linux, macOS, Windows, and Termux

### Advanced Features
- **DNS Pre-resolution** — Warm DNS cache before test starts
- **Cache Busting** — Bypass CDN/proxy caching for real server load
- **Random Paths** — Each request hits different URL paths (simulates real browsing)
- **Random Referers** — Realistic Referer header rotation
- **Request Jitter** — Add random delays between requests
- **Browser Fingerprinting** — Realistic User-Agent, Sec-Ch-Ua, Sec-Fetch headers
- **P99.9 Percentile** — Ultra-precise tail latency tracking
- **Latency Buckets** — Visual distribution from <50ms to >5s
- **Response Validation** — Verify response status, content, and timing
- **Geographic Simulation** — Simulate users from different global regions
- **Adaptive Rate Control** — Automatically adjust load based on error rates
- **Per-URL Metrics** — Track performance per endpoint in multi-URL tests

### Reports
- **JSON** — Machine-readable for API integration
- **CSV** — Spreadsheet analysis with RPS timeline
- **HTML** — Beautiful browser-viewable reports with interactive Chart.js charts
- **Auto-saved** — Every test generates reports automatically

---

## Installation

### Quick Install
```bash
git clone https://github.com/tahsan2544/LoadStorm.git
cd LoadStorm
pip install -r requirements.txt
python loadstorm.py --help
```

### Install via pip
```bash
pip install .
loadstorm --help
```

### Termux (Android)
```bash
pkg install python git
git clone https://github.com/tahsan2544/LoadStorm.git
cd LoadStorm
pip install -r requirements.txt
python loadstorm.py --help
```

### Requirements
| Package | Version | Purpose |
|---------|---------|---------|
| Python | 3.8+ | Runtime |
| aiohttp | >=3.9.0 | Async HTTP engine |
| colorama | >=0.4.6 | Terminal colors |
| websockets | >=12.0 | WebSocket testing |

---

## Usage Examples

### Basic Test (1000 Users)
```bash
python loadstorm.py -u https://example.com -c 1000
```

### 1 Million Users — Spike Attack
```bash
python loadstorm.py -u https://target.com -c 1000000 -d 60 -C 50000 -p spike -y
```

### Multi-URL Testing
```bash
# Create urls.txt with one URL per line
python loadstorm.py -u https://target.com -c 10000 --urls urls.txt
```

### WebSocket Testing
```bash
python loadstorm.py -u wss://echo.websocket.org -c 100 --websocket -y
```

### Response Validation
```bash
python loadstorm.py -u https://api.target.com -c 5000 --validate-status 200
python loadstorm.py -u https://api.target.com -c 5000 --validate-contains "success"
```

### Geographic Simulation
```bash
python loadstorm.py -u https://target.com -c 100000 --geo-sim -y
```

### Adaptive Rate Control
```bash
python loadstorm.py -u https://target.com -c 50000 --adaptive -y
```

### Scenario Chain
```bash
python loadstorm.py -u https://target.com -c 10000 --scenario scenario.json -y
```

### Wave Pattern Test
```bash
python loadstorm.py -u https://target.com -c 500000 -d 120 -p wave -C 20000
```

### Random Path + Cache Busting + Jitter
```bash
python loadstorm.py -u https://target.com -c 100000 --random-path --cache-bust --jitter 50
```

---

## Attack Patterns

| Pattern | Description | Use Case |
|---------|-------------|----------|
| `constant` | All users hit simultaneously | Maximum stress test |
| `ramp` | Gradual increase over duration | Find breaking point (default) |
| `spike` | Sudden burst, rest, burst again | DDoS resilience testing |
| `wave` | Sinusoidal wave pattern | Sustained oscillating load |
| `stepped` | Increase in discrete steps | Capacity threshold testing |
| `pulse` | Periodic bursts at intervals | Connection pool testing |
| `targeted` | Ramp up, hold, ramp down | Production-like testing |
| `staircase` | Incremental steps with holds | Step-wise capacity testing |
| `elastic` | Expand and contract dynamically | Elastic scaling testing |
| `random_chaos` | Unpredictable fluctuations | Chaos engineering |

---

## Command Line Options

### Core Options
| Flag | Description | Default |
|------|-------------|---------|
| `-u, --url` | Target URL | Required |
| `-c, --count` | Virtual users | 100 |
| `-d, --duration` | Duration (seconds) | 30 |
| `-C, --concurrency` | Max concurrent connections | 500 |
| `-p, --pattern` | Attack pattern | ramp |
| `-m, --method` | HTTP method | GET |
| `-t, --timeout` | Request timeout (seconds) | 10 |
| `-B, --batch-size` | Users per launch batch | 500 |

### Request Options
| Flag | Description | Default |
|------|-------------|---------|
| `-H, --header` | Custom headers (repeatable) | — |
| `-b, --body` | Request body | — |
| `--payload-file` | File with payloads (1/line) | — |
| `--rate-limit` | Requests/sec per user | 0 (unlimited) |
| `--no-keep-alive` | Disable keep-alive | false |

### Advanced Options
| Flag | Description | Default |
|------|-------------|---------|
| `--urls` | File with multiple URLs | — |
| `--websocket` | Enable WebSocket mode | false |
| `--validate-status` | Validate response status | — |
| `--validate-contains` | Validate response contains text | — |
| `--validate-max-time` | Validate max response time (ms) | — |
| `--geo-sim` | Geographic distribution simulation | false |
| `--adaptive` | Adaptive rate control | false |
| `--scenario` | JSON file with scenario chain | — |
| `--random-path` | Random URL paths per request | false |
| `--random-referer` | Random Referer headers | false |
| `--jitter` | Random delay per request (ms) | 0 (none) |
| `--cache-bust` | Bypass CDN/proxy caching | false |
| `--proxy` | Proxy URL | — |
| `--no-follow` | No redirect following | false |

### Output Options
| Flag | Description | Default |
|------|-------------|---------|
| `--export` | Report format | all |
| `--no-color` | Disable colors | false |
| `-y, --yes` | Skip confirmation | false |

---

## Scenario Chain Format

Create a JSON file with request sequences:

```json
{
  "steps": [
    {
      "url": "https://api.example.com/login",
      "method": "POST",
      "body": "{\"user\":\"test\",\"pass\":\"test\"}",
      "validation": {"status": 200}
    },
    {
      "url": "https://api.example.com/dashboard",
      "method": "GET",
      "validation": {"status": 200, "contains": "dashboard"}
    },
    {
      "url": "https://api.example.com/data",
      "method": "GET",
      "validation": {"status": 200, "max_time": 500}
    }
  ]
}
```

---

## Auto-Generated Reports

Every test automatically saves three report files:

| File | Format | Use Case |
|------|--------|----------|
| `loadstorm_YYYYMMDD_HHMMSS.json` | JSON | API integration, data analysis |
| `loadstorm_YYYYMMDD_HHMMSS.csv` | CSV | Spreadsheet analysis with RPS timeline |
| `loadstorm_YYYYMMDD_HHMMSS.html` | HTML | Interactive report with Chart.js charts |

---

## Verdict Guide

| Success Rate | Verdict | Description |
|-------------|---------|-------------|
| >= 99% | EXCELLENT | Site handled load perfectly |
| >= 90% | GOOD | Minor issues under load |
| >= 70% | FAIR | Noticeable degradation |
| < 70% | CRITICAL | Site struggling under load |

---

## Scaling Guide

| Users | Concurrency | Duration | System Needed |
|-------|-------------|----------|---------------|
| 1,000 | 500 | 30s | Any laptop |
| 10,000 | 2,000 | 30s | Desktop/server |
| 100,000 | 10,000 | 60s | Server (8+ cores) |
| 500,000 | 30,000 | 60s | Server (16+ cores) |
| 1,000,000 | 50,000 | 60s | High-end server |
| 10,000,000 | 100,000 | 120s | Cluster/distributed |

---

## Disclaimer

**This tool is for authorized security testing only.**

Only test websites you own or have explicit written permission to test. Unauthorized stress testing may violate laws and terms of service.

**The authors are not responsible for any misuse of this tool.**

---

## License

MIT License — see [LICENSE](LICENSE) for details.
