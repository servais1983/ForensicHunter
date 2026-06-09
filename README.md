# ForensicHunter

Professional digital forensics platform for Windows artifact collection, threat analysis, and investigation reporting.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage — CLI](#usage--cli)
- [Usage — REST API](#usage--rest-api)
- [Docker Deployment](#docker-deployment)
- [YARA Rules](#yara-rules)
- [Configuration Reference](#configuration-reference)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

---

## Overview

ForensicHunter is an open-source forensic platform designed for incident responders, digital forensic analysts, and SOC teams. It automates the acquisition of Windows artifacts, applies YARA-based threat detection and behavioral analysis, and produces structured reports in HTML, JSON, and CSV formats.

**Core capabilities**

- Artifact collection: event logs, registry hives, file system metadata, browser history, running processes, network connections, USB device history, memory dumps, and user profile data
- Threat detection: 500+ YARA rules covering APT groups, ransomware, RATs, exploit kits, malicious documents, web shells, packers, and CVE signatures
- Behavioral analysis: anomaly detection using scikit-learn, memory forensics via Volatility 3, VirusTotal integration
- Reporting: self-contained HTML reports with interactive tables, raw JSON output, CSV exports, and chain-of-custody metadata
- Enterprise API: FastAPI REST interface with WebSocket progress streaming, bearer-token authentication, and Prometheus metrics
- Disk image support: VMDK, VHD, and raw image analysis

---

## Architecture

```
ForensicHunter/
├── src/
│   ├── forensichunter.py       # CLI entry point
│   ├── api/main.py             # FastAPI REST server
│   ├── collectors/             # Artifact collectors (event logs, registry, etc.)
│   ├── analyzers/              # Analysis engines (YARA, malware, phishing, etc.)
│   ├── reporters/              # Report generators (HTML, JSON, CSV)
│   ├── core/                   # Enterprise collection targets and modules
│   ├── utils/                  # Config, logging, hashing, encoding helpers
│   ├── behavioral/             # ML-based behavioral analyzer
│   ├── ai/                     # AI-assisted analysis module
│   ├── cloud/                  # Cloud artifact analysis
│   ├── remote/                 # Remote host analysis
│   ├── siem/                   # SIEM connector
│   └── gui/                    # PyQt5 desktop interface (Windows)
├── rules/                      # YARA rule sets (malware, APT, ransomware, etc.)
├── static/                     # CSS and JS for HTML reports
├── tests/                      # Unit and integration tests
├── Dockerfile                  # Multi-stage container build
├── requirements.txt            # Core Python dependencies
├── requirements-prod.txt       # API / production dependencies
└── setup.py                    # Package installation
```

The pipeline follows three sequential phases:

1. **Collection** — each collector runs in a dedicated thread, writing raw artifacts to the output directory with a SHA-256 chain-of-custody hash.
2. **Analysis** — registered analyzers process the collected artifacts concurrently. YARA scanning, entropy checks, and behavioral heuristics produce structured `Finding` objects.
3. **Reporting** — findings and artifacts are serialized into one or more report formats. HTML reports include sortable tables, severity badges, and executive summary statistics.

---

## Requirements

| Component | Minimum version |
|-----------|----------------|
| Python | 3.10 |
| Operating system | Windows 10/11, Windows Server 2016+ (for live collection); Linux for API/container deployment |
| RAM | 4 GB (8 GB recommended for memory forensics) |
| Disk space | 10 GB free for evidence and reports |

**Optional system tools** (extend analysis capabilities when available on PATH):

- `yara` CLI — used as fallback when `yara-python` is unavailable
- `volatility3` — memory dump analysis
- `strings` / `binutils` — binary string extraction

---

## Installation

### From source (recommended)

```bash
git clone https://github.com/servais1983/ForensicHunter.git
cd ForensicHunter
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

For the REST API:

```bash
pip install -r requirements-prod.txt
```

### Verify installation

```bash
python src/forensichunter.py --version
# ForensicHunter v2.0.0
```

---

## Usage — CLI

> **Note:** Full artifact collection requires administrator / root privileges.

### Full system scan

```bash
# Windows (run as Administrator)
python src/forensichunter.py --full-scan --output C:\Evidence\case-001

# Linux (for non-Windows artifacts / API mode)
sudo python src/forensichunter.py --full-scan --output /evidence/case-001
```

### Selective collection

```bash
python src/forensichunter.py \
    --collect eventlogs,registry,filesystem \
    --output ./results
```

### Disk image analysis

```bash
python src/forensichunter.py \
    --image-path /path/to/disk.vmdk \
    --full-scan \
    --output ./results
```

### Report format selection

```bash
# HTML only (default)
python src/forensichunter.py --full-scan

# All formats
python src/forensichunter.py --full-scan --format all

# JSON only
python src/forensichunter.py --full-scan --format json
```

### Custom YARA rules

```bash
python src/forensichunter.py --full-scan --yara-rules /path/to/custom.yar
```

### All CLI options

```
positional arguments:
  (none)

options:
  -h, --help            show this help message and exit
  -v, --version         show version and exit
  --debug               enable debug logging
  -o, --output DIR      output directory (default: forensichunter_report)
  --gui                 launch the PyQt5 desktop interface (Windows only)

collection:
  --full-scan           collect all artifact types
  --collect COLLECTORS  comma-separated list: eventlogs,registry,filesystem,
                        browser,process,network,usb,memory,userdata
  --image-path PATH     path to a disk image (VMDK, VHD, raw)
  --no-memory           skip RAM acquisition

analysis:
  --no-analysis         skip all analysis phases
  --threat-intel        enrich findings with VirusTotal threat intelligence
  --yara-rules PATH     path to additional YARA rule file or directory

reporting:
  --format FORMAT       html | json | csv | all  (default: html)
  --no-report           skip report generation
```

---

## Usage — REST API

### Start the server

```bash
# Copy and fill in the environment template
cp .env.example .env

# Generate a strong API key
python -c "import secrets; print(secrets.token_hex(32))"
# Paste the output into API_SECRET_KEY in .env

source .env   # or: set -a && . .env && set +a (bash)
uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```

Interactive documentation is available at `http://localhost:8000/api/docs`.

### Authentication

All endpoints (except `/api/health` and `/api/status`) require a Bearer token:

```bash
curl -H "Authorization: Bearer <API_SECRET_KEY>" http://localhost:8000/api/targets
```

### Start a collection

```bash
curl -X POST http://localhost:8000/api/collections \
  -H "Authorization: Bearer <API_SECRET_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["eventlogs", "registry"],
    "destination": "/evidence/case-001",
    "case_name": "IR-2024-001",
    "investigator": "j.smith"
  }'
```

Response:

```json
{
  "collection_id": "abc123...",
  "status": "started"
}
```

### Monitor progress via WebSocket

```javascript
const ws = new WebSocket("ws://localhost:8000/api/ws/collections/abc123...");
ws.onmessage = (event) => console.log(JSON.parse(event.data));
// { "status": "collecting", "progress": 42.5, "timestamp": "..." }
```

### Key endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Liveness check |
| GET | `/api/status` | System status and dependency check |
| GET | `/api/targets` | List available forensic targets |
| GET | `/api/modules` | List available analysis modules |
| POST | `/api/collections` | Start a new collection |
| GET | `/api/collections` | List all collections |
| GET | `/api/collections/{id}` | Collection status |
| DELETE | `/api/collections/{id}` | Cancel a running collection |
| WS | `/api/ws/collections/{id}` | Real-time progress stream |
| GET | `/api/metrics` | Operational metrics |

---

## Docker Deployment

### Build and run (production)

```bash
# Build
docker build --target production -t forensichunter:latest .

# Run
docker run -d \
  --name forensichunter \
  -p 8000:8000 \
  -e API_SECRET_KEY=<strong-secret> \
  -e FORENSICHUNTER_ENV=production \
  -e ALLOWED_ORIGINS=https://your-dashboard.example.com \
  -v /host/evidence:/opt/forensichunter/evidence \
  -v /host/reports:/opt/forensichunter/reports \
  forensichunter:latest
```

### Development mode

```bash
docker build --target development -t forensichunter:dev .

docker run -d \
  --name forensichunter-dev \
  -p 8000:8000 \
  -e FORENSICHUNTER_ENV=development \
  -v $(pwd):/opt/forensichunter \
  forensichunter:dev
```

### Health check

```bash
curl http://localhost:8000/api/health
# {"status": "healthy", "timestamp": "..."}
```

---

## YARA Rules

Rules are organized under `rules/` by category:

| Directory | Coverage |
|-----------|----------|
| `rules/malware/` | APT groups (APT1, APT10, Sofacy, Turla…), ransomware, RATs, banking trojans, botnets, cryptominers |
| `rules/cve_rules/` | Weaponized CVE signatures (CVE-2017-11882, EternalBlue, etc.) |
| `rules/maldocs/` | Malicious Office documents, PDF exploits, VBA macro detection |
| `rules/exploit_kits/` | Angler, Blackhole, RIG, and similar exploit kit traffic patterns |
| `rules/webshells/` | ChinaChopper, ASPXSpy, PHP webshells |
| `rules/email/` | Phishing, extortion, malicious attachment patterns |
| `rules/packers/` | Packer/obfuscation signatures, polyglot files |
| `rules/capabilities/` | Anti-debug, anti-VM, lateral movement, credential theft |
| `rules/crypto/` | Cryptographic constant signatures |

All rules are aggregated in `rules/all_rules.yar`. Add custom rules by:

1. Placing `.yar` files in the appropriate subdirectory
2. Passing the path via `--yara-rules /path/to/custom.yar` or `--yara-rules /path/to/dir/`

---

## Configuration Reference

ForensicHunter reads configuration from environment variables (see `.env.example`) and CLI arguments. There is no mandatory configuration file for basic usage.

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `FORENSICHUNTER_ENV` | No | `development` or `production` (default: `production`) |
| `API_SECRET_KEY` | Yes (API) | Bearer token for API authentication — min 32 chars |
| `ALLOWED_ORIGINS` | No | Comma-separated CORS origins. Empty = deny all (production), `*` allowed in development |
| `VIRUSTOTAL_API_KEY` | No | VirusTotal API key for threat intelligence enrichment |
| `SIEM_ENDPOINT` | No | SIEM webhook URL for automated event forwarding |
| `SENTRY_DSN` | No | Sentry DSN for error tracking |
| `DATABASE_URL` | No | PostgreSQL connection string for persistent collection history |
| `REDIS_URL` | No | Redis URL for task queue and caching |

---

## Project Structure

```
src/
├── forensichunter.py               # Main CLI entry point
├── api/
│   └── main.py                     # FastAPI application
├── collectors/
│   ├── base_collector.py           # Abstract base class and Artifact model
│   ├── collector_manager.py        # Parallel collection orchestrator
│   ├── event_logs.py               # Windows event log collection
│   ├── registry.py                 # Registry hive collection
│   ├── filesystem.py               # File system metadata collection
│   ├── browser.py                  # Browser history extraction
│   ├── process.py                  # Process and network connection collection
│   ├── memory.py                   # RAM acquisition
│   ├── usb.py                      # USB device history
│   ├── user_data.py                # User profile artifacts
│   └── vmdk_collector.py           # Disk image support
├── analyzers/
│   ├── base_analyzer.py            # Abstract base class and Finding model
│   ├── analyzer_manager.py         # Analysis orchestrator
│   ├── yara_analyzer.py            # YARA rule engine
│   ├── malware_analyzer.py         # PE-based malware heuristics
│   ├── phishing_analyzer.py        # Phishing indicator detection
│   ├── whitelist_manager.py        # False-positive suppression
│   ├── log_analyzer/               # Event log and CSV analyzers
│   ├── virustotal/                 # VirusTotal API integration
│   └── memory/                     # Volatility 3 memory analysis
├── reporters/
│   ├── reporter_manager.py         # Report generation orchestrator
│   ├── html_reporter.py            # HTML report with interactive tables
│   ├── json_reporter.py            # Structured JSON output
│   └── csv_reporter.py             # Flat CSV export
├── core/
│   ├── enterprise_config.py        # Target and module definitions
│   └── enterprise_collector.py     # Enterprise collection engine
└── utils/
    ├── config.py                   # Configuration management
    ├── logger.py                   # Rotating file + console logger
    ├── helpers.py                  # Admin check, output dir, file hashing
    ├── encoding_utils.py           # UTF-8 / CP1252 / Latin-1 fallback decoder
    ├── banner.py                   # CLI banner
    ├── integrity/                  # Chain-of-custody, audit logging
    └── security/                   # Privilege and security management
```

---

## Contributing

Contributions are welcome. Please follow these guidelines:

1. Fork the repository and create a feature branch from `main`.
2. Write tests for any new collector, analyzer, or reporter.
3. Run the test suite before opening a pull request: `pytest tests/ -v --cov=src`
4. Format code with `black src/ tests/` and lint with `ruff src/`.
5. Document public classes and methods with Google-style docstrings.
6. Do not commit `.env` files, API keys, evidence data, or generated reports.

### Adding a collector

Subclass `BaseCollector` from `src/collectors/base_collector.py`, implement `collect() -> List[Artifact]`, and register the class in `CollectorManager._register_collectors()`.

### Adding a YARA rule set

Place `.yar` files under the relevant `rules/` subdirectory and add an `include` statement to `rules/all_rules.yar`.

### Running tests

```bash
pytest tests/ -v --cov=src --cov-report=term-missing
```

---

## Security

**Responsible disclosure:** if you discover a security vulnerability in ForensicHunter, please report it privately by opening a GitHub Security Advisory rather than a public issue.

**Production hardening checklist:**

- Set `API_SECRET_KEY` to a randomly generated secret of at least 32 characters.
- Set `ALLOWED_ORIGINS` to explicit domain names; do not use `*` in production.
- Run the container as the non-root `forensichunter` user (enforced by default in the Dockerfile).
- Mount evidence and report volumes on encrypted storage.
- Restrict network access to the API port (8000) using a reverse proxy or firewall; do not expose it directly to the internet.
- Rotate `API_SECRET_KEY` periodically and immediately after any suspected compromise.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for the full text.

YARA rules in `rules/` are sourced from various open-source threat intelligence repositories. Each rule file retains its original author attribution and license.

---

*ForensicHunter is a tool for authorized forensic investigation only. Use it only on systems and data for which you have explicit written authorization. Unauthorized use may violate computer crime laws.*
