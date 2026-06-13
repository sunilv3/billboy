# INFOSEC — Attack Surface Intelligence Platform

A comprehensive offensive security assessment platform built with Flask. Integrates **39+ real security tools** with **103+ scanning modules** across 4 categories (Web, Code, Network, VM/Cloud), **5 custom discovery engines** (mutation, anomaly, logic, OOB, parser stress), production-grade detection logic, MITMProxy traffic analysis, Playwright DOM-verified XSS, algorithm-aware JWT attacks, source-to-sink SAST, enterprise-grade risk management, a confirmation protocol with Welch's T-test statistical validation, vulnerability chain mapping via BFS attack graphs, a 15-rule universal false-positive elimination engine, a **Wazuh-style detection engine** (FIM, rootkit detection, vulnerability detection, log analysis, compliance checks), an **Enterprise Cross-Layer Risk Correlation Engine** (4-layer telemetry analysis with MITRE ATT&CK mapping), and an **AI-powered autonomous recon agent** that uses Ollama for intelligent finding triage, attack path identification, and prioritized remediation.

---

## Table of Contents

- [Architecture](#architecture)
- [Integrated Security Tools (39+)](#integrated-security-tools-39)
- [Scanning Modules (103+)](#scanning-modules-103)
- [Discovery Engines (5)](#discovery-engines-5)
- [Detection Intelligence](#detection-intelligence)
- [False Positive Elimination Engine](#false-positive-elimination-engine)
- [Confirmation Protocol](#confirmation-protocol)
- [Vulnerability Chain Mapping](#vulnerability-chain-mapping)
- [Risk Assessment Engine](#risk-assessment-engine)
- [Wazuh-Style Detection Engine](#wazuh-style-detection-engine)
- [Enterprise Risk Correlation Engine](#enterprise-risk-correlation-engine)
- [AI-Powered Recon Agent](#ai-powered-recon-agent)
- [Platform Features](#platform-features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [API Endpoints](#api-endpoints)
- [Project Structure](#project-structure)
- [Security Features](#security-features)
- [Troubleshooting](#troubleshooting)

---

## Architecture

The platform uses a **modular Flask blueprint architecture**. Each domain is a self-contained sub-package; `app_new.py` is a thin factory that wires them together. The legacy `app.py` remains the entry point for `wsgi.py` in production until migration is complete.

```
app_new.py  ← Flask application factory (create_app)
│
├── core/               Infrastructure & shared routes
│   ├── auth.py         Session-based authentication, login_required decorator
│   ├── database.py     SQLite init, schema migrations
│   ├── extensions.py   Shared Flask-Limiter instance, _rate_limit() decorator
│   ├── logger.py       Structured logging + per-client SSE queue
│   ├── main_routes.py  Index route (/) + /api/health liveness probe
│   ├── misc_routes.py  SSE stream, CI/CD webhook, scan history
│   ├── proxy.py        MITMProxy start/stop/traffic analysis
│   ├── tool_routes.py  Tools, schedule, SIEM, notify, replay, page-type
│   └── utils.py        _find_tool, _run_tool, SSRF guards, NVD lookup, req_lib
│
├── scanner/            Full-scan engine
│   ├── constants.py    SCAN_PROFILES, SCAN_HARD_LIMIT, ATTACK_MODULE_NAMES,
│   │                   ADAPTIVE_ROUTING, DYNAMIC_ONLY_MODULES
│   ├── routing.py      PageTypeDetector, classify_target, apply_adaptive_routing
│   ├── validation.py   15-Rule FP gate, CVSS scoring, classify_vuln,
│   │                   fingerprint, _extract_tool_output, context risk scoring
│   ├── suppression.py  Self-learning FP suppression (persisted fingerprints)
│   ├── orchestrator.py Multi-phase scan orchestrator (Phase 1 → 2 → 3 → 8)
│   ├── confirmation.py Confirmation protocol with Welch's T-test validation
│   ├── chains.py       Vulnerability chain mapping, BFS attack graph paths
│   ├── report.py       Full report generation with CVSS 3.1 vectors
│   ├── limits.py       Hard limits: rate limiter, semaphores, kill switch
│   ├── health.py       Health monitoring: error rate, time trend, auto-pause
│   ├── routes.py       /api/start_scan, /api/stop_scan, /api/status, findings API
│   ├── state.py        scan_state dict, LOCK, SCAN_JOBS
│   ├── findings.py     add_finding, op_log, set_progress, auto-verify pool
│   ├── verify.py       verify_findings, build_attack_chains, calculate_risk_score
│   ├── tools/
│   │   ├── detection.py   check_tool_availability
│   │   └── wrappers.py    Tool subprocess helpers
│   ├── engines/            5 custom discovery engines
│   │   ├── __init__.py     Engine registry
│   │   ├── mutation.py     Engine 1: Coverage-guided input mutation
│   │   ├── anomaly.py      Engine 2: Differential/anomaly detection
│   │   ├── logic.py        Engine 3: State-aware logic-flaw hunting
│   │   ├── oob.py          Engine 4: Blind OOB (local HTTP+DNS server)
│   │   └── parser_stress.py Engine 5: Memory/parser edge cases
│   └── modules/
│       ├── web/        headers, injection, auth, discovery, advanced, api, pentest
│       ├── code/       sast.py
│       ├── network/    recon.py, vuln.py
│       └── vm/         container.py
│
├── reports/            Export engine
│   ├── routes.py       /api/export/* (JSON, CSV, SARIF, Markdown, PDF)
│   ├── pdf.py          FPDF-based PDF report generator
│   └── json_export.py  JSON/SARIF export helpers
│
├── risk/               Risk management
│   ├── routes.py       /api/assets, /api/risks, /api/kris, /api/controls
│   └── engine.py       NIST/ISO/FAIR risk scoring, ALE calculation
│
├── recon/              Intelligent recon agent (AI-powered)
│   ├── routes.py       /api/recon/start, /status, /report, /stream, /stop, /ai-analyze
│   └── agent.py        Multi-phase adaptive recon with AI triage (Phase 3.5: Ollama)
│
├── ai/                 AI-assisted analysis (Ollama LLM)
│   ├── routes.py       /api/ai/status, /api/ai/analyze, /api/ai/triage
│   └── ollama.py       Ollama LLM integration (dolphin3:8b, configurable)
│
├── scripts/            Utility scripts (not part of the Flask app)
│   └── setup_ai.sh     Ollama + dolphin3:8b installation helper
│
├── wsgi.py             Production WSGI entry point (gunicorn wsgi:app)
└── templates/
    ├── login.html
    └── infosec_platform.html   Main UI (7,000+ lines)
```

### Scan Flow

```
Phase 1: FAST PASSIVE RECON (7 modules, parallel)
  DNS → Subdomains → Ports → Tech Detection → WAF Fingerprint → Subdomain Enum
      ↓ (feeds into)
      [Adaptive Routing] — PageTypeDetector classifies target as static/dynamic/SPA
      ↓ (prunes modules for static sites when ADAPTIVE_ROUTING=1)
Phase 2: BASELINE ESTABLISHMENT (30 samples/endpoint)
  30 normal requests per discovered endpoint → feeds Health Monitor
      ↓
Phase 2A: DISCOVERY (4 modules, parallel)
  SSL/TLS → Web Crawler → JS Analysis → Wayback
      ↓ (feeds into)
Phase 2B: TECH-SPECIFIC TESTING (sequential)
  WordPress → Laravel → API → GraphQL (based on Phase 1 tech detection)
      ↓ (feeds into)
Phase 2C: SECURITY TESTING (55+ modules, batched)
  Headers → CORS → SQLi → XSS → SSRF → SSTI → JWT → OAuth → File → Logic → ...
      ↓
Phase 3: DISCOVERY ENGINES (5 custom engines, sequential)
  Engine 1: Coverage-Guided Input Mutation (JSON/GraphQL/XML/headers/params/multipart)
  Engine 2: Differential/Anomaly Detection (30-sample baseline + Z-score analysis)
  Engine 3: State-Aware Logic-Flaw Hunting (auto-discovers workflows, tests bypass/replay)
  Engine 4: Blind OOB Discovery (local HTTP+DNS server, 5 payload categories)
  Engine 5: Memory/Parser Edge Cases (oversized/nested/encoding/smuggling/cash detection)
      ↓ (all engines enforce hard limits: 10 req/s, 10K max requests, kill switch)
Phase 3.5: AI ANALYSIS (optional — requires Ollama)
  Triage findings → TRUE / FALSE_POSITIVE / UNCERTAIN classification
  Identify attack paths → chains of findings for privilege escalation
  Apply FP verdicts → auto-mark false positives
      ↓
Phase 8: CHAIN ANALYSIS
  Attack Graph (BFS) → Chain Narrative → Loot Extraction → Report
      ↓ (final)
  Confirmation Protocol (T-test) → CVSS 3.1 Scoring → PDF Report
```

---

## Integrated Security Tools (39+)

### Core Scanning Tools

| Tool | Purpose | Integration | Detection Value |
|------|---------|-------------|-----------------|
| **nmap** | Port scanning, service detection | Subprocess | Network reconnaissance |
| **sqlmap** | SQL injection confirmation | Subprocess | Automated exploitation testing |
| **ffuf** | Directory bruteforcing | Subprocess | Hidden path discovery |
| **nuclei** | Template-based vuln scanning | Subprocess | 6,000+ vulnerability templates |
| **httpx** | HTTP probing, tech detection | Subprocess | Technology fingerprinting |
| **nikto** | Server misconfiguration scanning | Subprocess | Web server vulnerabilities |
| **rustscan** | Ultra-fast port scanning | Subprocess | 3-second full port scan |
| **naabu** | SYN port scanning | Subprocess | Fast port discovery |

### Subdomain & DNS Tools

| Tool | Purpose | Integration | Detection Value |
|------|---------|-------------|-----------------|
| **subfinder** | Passive subdomain enumeration | Subprocess | Attack surface mapping |
| **amass** | Active subdomain enumeration | Subprocess | OSINT-based discovery |
| **assetfinder** | Additional subdomain enumeration | Subprocess | Complementary discovery |
| **dnsx** | Bulk DNS validation + DNSSEC/CAA | Subprocess | DNS security analysis |
| **puredns** | DNS resolution and brute-forcing | Subprocess | DNS enumeration |
| **theHarvester** | OSINT email and subdomain gathering | Subprocess | Intelligence gathering |

### Web Security Tools

| Tool | Purpose | Integration | Detection Value |
|------|---------|-------------|-----------------|
| **dalfox** | XSS detection and confirmation | Subprocess | Automated XSS testing |
| **wafw00f** | WAF detection and fingerprinting | Subprocess | WAF type identification |
| **hakrawler** | Deep crawl with secret endpoint detection | Subprocess | .env, .git, config discovery |
| **katana** | JS-aware web crawling | Subprocess | Deep endpoint discovery |
| **gau** | Wayback Machine URL recovery | Subprocess | Historical URL discovery |
| **gospider** | Recursive web crawling | Subprocess | Full site mapping |
| **arjun** | Hidden parameter discovery | Subprocess | Parameter enumeration |
| **crlfuzz** | CRLF injection testing | Subprocess | Header injection |
| **ssrfmap** | SSRF exploitation | Subprocess | Server-side request forgery |

### SSL/TLS Tools

| Tool | Purpose | Integration | Detection Value |
|------|---------|-------------|-----------------|
| **testssl.sh** | SSL/TLS protocol testing | Subprocess | Protocol vulnerability detection |
| **sslyze** | SSL/TLS cipher & config analysis | Python library | Certificate security |

### Secret Detection Tools

| Tool | Purpose | Integration | Detection Value |
|------|---------|-------------|-----------------|
| **gitleaks** | Git history secret scanning | Subprocess | Hardcoded credential detection |
| **trufflehog** | High-entropy secret detection | Subprocess | Deep secret scanning |
| **semgrep** | Custom rule-based SAST | Subprocess | Static analysis |
| **bearer** | Source-to-sink SAST | Subprocess | Data-flow vulnerability detection |

### Supply Chain & Dependency Tools

| Tool | Purpose | Integration | Detection Value |
|------|---------|-------------|-----------------|
| **osv-scanner** | Open Source Vulnerabilities database | Subprocess | Dependency vulnerabilities |
| **grype** | Container CVE scanning | Subprocess | Exploitability scoring |

### Container & Cloud Tools

| Tool | Purpose | Integration | Detection Value |
|------|---------|-------------|-----------------|
| **trivy** | Container image CVE scanning | Subprocess | Container security |
| **checkov** | IaC misconfiguration scanning | Subprocess | Dockerfile, K8s, Terraform security |

### Traffic Analysis Tools

| Tool | Purpose | Integration | Detection Value |
|------|---------|-------------|-----------------|
| **mitmproxy** | Traffic capture and security analysis | Subprocess | Sensitive data leak detection |
| **playwright** | Headless Chromium DOM verification | Python library | XSS execution confirmation |

### OSINT Tools

| Tool | Purpose | Integration | Detection Value |
|------|---------|-------------|-----------------|
| **whois** | Domain registration data | Python library | Ownership information |

---

## Scanning Modules (103+)

### Web Scan (85 modules)

#### Injection Testing
- **SQL Injection** — Error-based, boolean, time-based, UNION (sqlmap confirmed)
- **XSS** — Reflected, stored, DOM-based, Playwright dialog/DOM-mutation verification
- **SSRF** — Internal service discovery, cloud metadata, pivot scanning
- **SSTI** — Template injection across 15+ engines (Jinja2, Twig, Freemarker, etc.)
- **Command Injection** — Blind, out-of-band, time-based
- **XXE** — XML external entity injection, file read, SSRF
- **NoSQL Injection** — MongoDB, CouchDB, Redis injection
- **LDAP Injection** — Directory service attacks
- **CRLF Injection** — Header injection, response splitting
- **SQLi Deep / Manual** — Advanced and manual SQL injection verification
- **XSS Manual / SSRF Manual** — Manual exploitation verification
- **Advanced XXE** — Out-of-band XXE testing

#### Authentication & Authorization
- **JWT Attacks** — Algorithm confusion (RS256→HS256), weak secret brute-force, expired token acceptance, `none` algorithm bypass
- **JWT Advanced** — JWT attack chains
- **OAuth Testing** — JS bundle client_id discovery, redirect URI bypasses, token endpoint abuse
- **Session Fixation** — Session token predictability, fixation attacks
- **IDOR / IDOR Deep** — Insecure direct object reference across APIs
- **2FA Bypass** — Brute-force, response manipulation, backup code abuse
- **Auth Testing** — 8-step flowchart-based authentication bypass detection

#### Business Logic
- **Race Conditions** — TOCTOU vulnerabilities, double-spending
- **Mass Assignment** — Privilege escalation via parameter pollution
- **Business Logic** — Workflow bypass, pricing manipulation

#### Web Security
- **CORS Misconfiguration / CORS with Credentials** — Credential reflection, origin validation
- **CSRF** — Token absence, SameSite cookie analysis
- **Clickjacking / Deep** — X-Frame-Options analysis
- **Security Headers** — CSP, HSTS, X-Content-Type-Options, 15+ header checks
- **Advanced Headers** — Deep header security analysis
- **Open Redirect** — Domain validation bypasses
- **Cache Poisoning** — Web cache deception, poisoning
- **Host Header Injection** — Host header manipulation

#### Advanced
- **HTTP Smuggling** — CL.TE, TE.CL, TE.TE attacks
- **WebSocket Security** — Authentication, origin validation
- **DNS Rebinding** — Internal service access
- **Prototype Pollution** — JavaScript prototype poisoning
- **File Inclusion** — LFI/RFI with wrapper detection
- **File Upload** — Unrestricted upload, webshell detection
- **Insecure Deserialization** — Java, PHP, Python deserialization
- **Header Injection** — HTTP header manipulation

#### WAF Detection & Bypass
- **WAF Fingerprinting** — 12+ WAF vendors (Cloudflare, Akamai, AWS WAF, ModSecurity, Imperva, etc.)
- **Known Bypass Payloads** — 200+ real bypass payloads per WAF type × vulnerability class
- **Encoding Mutations** — Double encoding, Unicode, chunked transfer, null bytes

#### Crawl & Discovery
- **Web Crawling** — katana + hakrawler deep crawl with secret endpoint detection
- **JavaScript Analysis** — Endpoint extraction from JS bundles
- **Parameter Discovery** — Hidden parameter enumeration from HTML + JS
- **Enhanced Subdomain Enum** — Multi-tool subdomain discovery

#### Proxy Layer
- **MITMProxy Traffic Capture** — Full HAR recording of all HTTP traffic
- **9-Category Traffic Analysis**: auth tokens in URLs, sensitive POST bodies, missing cookie flags, CORS reflection, Cache-Control gaps, CSP absence, HSTS missing, verbose errors, mixed content
- **Request Replay** — Replay any captured request with modifications

### Code Scan (11 modules)
- **Bearer SAST** — Source-to-sink data flow analysis
- **Semgrep SAST** — Custom rule-based static analysis
- **Gitleaks / TruffleHog** — Git history and high-entropy secret scanning
- **Enhanced Secrets** — 30+ secret patterns (AWS, Azure, GCP, GitHub, Stripe, etc.)
- **OSV Dependencies** — Open Source Vulnerabilities database
- **Supply Chain** — Third-party dependency mapping
- **Credential Stuffing / 2FA Bypass / Crypto Miner Detection**

### Network Scan (9 modules)
- **DNS Enumeration** — A/AAAA/MX/NS/TXT/CNAME/SOA record discovery
- **SSL/TLS Analysis** — testssl.sh + sslyze for certificate, cipher, protocol analysis
- **Port Scanning** — nmap-based TCP port scanning with service detection
- **Subdomain Enumeration** — subfinder + amass + assetfinder + DNSX bulk validation
- **DNS Security** — DNSSEC, CAA record analysis, zone transfer testing
- **WHOIS / Email Security / OOB Detection / theHarvester OSINT**

### VM / Cloud Scan (8 modules)
- **Cloud Storage** — S3, GCS, Azure Blob misconfiguration detection
- **Cloud VM** — Cloud metadata, IAM, service vulnerabilities
- **Container Security** — Docker API exposure, Trivy + Grype CVE scanning
- **Checkov IaC** — Dockerfile, K8s YAML, Terraform, CloudFormation misconfigurations
- **Kubernetes** — API server, etcd, kubelet, RBAC, dashboard exposure
- **Compliance / Monitoring / Takeover**

### Wazuh-Style Detection Engine (5 sub-modules)
- **File Integrity Monitoring (FIM)** — 25+ critical file paths (SSH keys, shadow, sudoers, Docker configs, cloud credentials); SHA-256 hashing with baseline comparison
- **Rootkit Detection** — 18 shell backdoor signatures (BIND shell, REVERSE shell, encoded payloads, hidden processes, kernel modules, LD_PRELOAD, etc.)
- **Vulnerability Detection** — 12 software categories × 25+ CVE patterns (Apache, Nginx, OpenSSL, PHP, Python, Node.js, Java, Docker, MySQL, PostgreSQL, Redis, WordPress)
- **Log Analysis** — 17 log paths × 10 marker patterns (Failed password, Segfault, Out of memory, Kernel panic, segfault, authentication failure, root login, sudo failures, service crashes)
- **Compliance Checks** — PCI-DSS (6 rules), HIPAA (5 rules), GDPR (4 rules), OWASP Top 10 (10 rules) — 25 compliance rules checking security headers, TLS, auth, logging, access controls

---

## Discovery Engines (5)

Five custom fuzzing engines that run during Phase 3, each operating within the hard limits framework (10 req/s rate limiter, 5 concurrent connections, 10,000 max requests, kill switch checked per-request).

### Engine 1: Coverage-Guided Input Mutation (`scanner/engines/mutation.py`)
Generates mutation payloads based on the target's content-type and response structure.

| Payload Category | Count | Description |
|-----------------|-------|-------------|
| **JSON mutations** | 5 types | Deep nesting (10/20/50), type confusion, dup keys, large numerics |
| **GraphQL mutations** | 5 types | Introspection, alias overload (10/50/100), depth amplification (10/20/50), batched queries (50), fragment circular refs |
| **XML/SOAP** | 5 types | XXE, billion laughs, quadratic bomb, deep nesting (100/500), UTF-16/UTF-7, CDATA |
| **Headers** | 4 types | CRLF injection, null byte, tab smuggle, line fold |
| **URL params** | 5 types | SQLi (6 payloads), XSS (5), CMDi (5), SSRF (4), path traversal (3), type confusion (12) |
| **Multipart** | 3 types | Boundary confusion, nested multipart, binary filename, long fieldname |

Includes response fingerprinting with structure hash (MD5 of response skeleton) for deduplication.

### Engine 2: Differential/Anomaly Detection (`scanner/engines/anomaly.py`)
Establishes a 30-sample baseline per endpoint and detects deviations.

- **Baseline phase**: 30 normal requests per endpoint, recording time, length, status, error count
- **Statistical analysis**: Z-score > 3.0 flags anomalies in response time, length, status code, or error patterns
- **Targeted follow-up**: 5 normal + 5 trigger requests to confirm anomalies
- **Deterministic difference check**: Content comparison to rule out false positives from dynamic content

### Engine 3: State-Aware Logic-Flaw Hunting (`scanner/engines/logic.py`)
Automatically discovers multi-step workflows and tests for authorization and workflow bypass.

- **Flow discovery**: Auto-detects login, register, checkout, password reset flows
- **Step skipping**: Execute step N+1 without completing step N
- **Step repetition**: Execute the same step twice to trigger idempotency issues
- **Step reversal**: Execute steps in reverse order
- **Parameter tampering**: Modify parameters between steps (prices, quantities, user IDs)
- **Cross-step injection**: Inject parameters from step A into step B
- **Race conditions**: 5 concurrent requests to trigger TOCTOU vulnerabilities
- **Replay attacks**: 10 replay attempts to test for replay protection

### Engine 4: Blind OOB Discovery (`scanner/engines/oob.py`)
Full out-of-band vulnerability discovery using a local HTTP+DNS server.

- **Local HTTP server**: Listens on `127.0.0.1` for HTTP callbacks
- **Local DNS server**: Listens on port `15353` for DNS callbacks
- **5 payload categories** (25 total payloads):
  - Command injection (10 payloads)
  - SSRF (5 payloads)
  - XXE (3 payloads)
  - SQLi DNS exfiltration (3 payloads)
  - XSS OOB (4 payloads)
- **Per-injection-point unique tokens** for correlation
- **Callback monitoring**: Collects and correlates all incoming callbacks

### Engine 5: Memory/Parser Edge Cases (`scanner/engines/parser_stress.py`)
Tests for crashes, timeouts, and parser edge cases.

- **Oversized inputs**: 64KB and 1MB payloads
- **Deep nesting**: 50, 100, and 500 levels
- **Encoding confusion**: 8 encoding types (UTF-8, UTF-16, UTF-7, ASCII, Latin-1, etc.)
- **Path traversal**: 8 variants (`../`, `%2e%2e%2f`, `..%00/`, etc.)
- **Request smuggling**: CL.TE, TE.CL, TE.TE, duplicate Content-Length
- **XML stress**: Billion laughs, quadratic bomb, 1000-level nesting
- **Crash/timeout detection**: Monitors for connection resets, 500s, empty responses

---

## Detection Intelligence

### Adaptive Routing (`ADAPTIVE_ROUTING=1`)
Before Phase 2C, `PageTypeDetector` fetches the target and classifies it as **static**, **dynamic**, **SPA**, or **hybrid** using 5 HTTP signal groups (server headers, session cookies, forms, JS frameworks, robots.txt). Modules in `DYNAMIC_ONLY_MODULES` are skipped automatically for static sites — eliminating false runs on CDN-hosted pages.

### Tech-Aware Payload Selection
- PHP targets: `php://filter`, `expect://`, `data://` wrappers
- Node.js targets: `require()`, `child_process`, event loop abuse
- Python targets: `os.popen()`, `subprocess`, pickle deserialization
- Java targets: JNDI injection, deserialization gadgets

### CVSS 3.1 Auto-Scoring (`scanner/validation.py`)
Automatic CVSS 3.1 vector computation using the `cvss` Python library:
- 30+ vulnerability class vectors (SQLi=9.8, XSS=6.1, SSRF=8.6, etc.)
- Auth-required and user-interaction adjustment
- Fallback scoring table when library is unavailable

### Attack Chain Patterns (31)
Multi-step exploitation chains that combine individual findings:
- SQLi → Database Dump → Credential Extraction → Lateral Movement
- XSS → Cookie Stealing → Session Hijacking → Admin Access
- SSRF → Internal Service Discovery → Cloud Metadata → IAM Keys
- Subdomain Takeover → DNS Rebinding → Internal Network Access

### Context-Aware Risk Scoring (`calculate_finding_context_risk`)
- Exploit availability (+20%), corroboration by multiple tools (+15%), internet-facing (+10%)
- Sensitive data keywords (+15%), unverified penalty (−20%), speculative confidence (−10%)

### CVE Ingestion Pipeline
15-source live CVE fetching — CISA KEV, NVD, GitHub Security Advisories, and 12+ more.

---

## False Positive Elimination Engine

### Universal FP Gate — 15-Rule Verification (`scanner/validation.py`)

Every finding passes through `_validate_finding()` before being stored. All 15 rules run in order; the first failure short-circuits and rejects the finding.

| # | Rule | Description |
|---|------|-------------|
| 1 | **Info-pattern removal** | Filters tool status messages ("scan completed", "WAF detected", etc.) |
| 2 | **Simulation mode** | Removes findings from modules that require an API key and returned simulation data |
| 3 | **HTML error page** | Rejects high/critical findings where the response is an HTML page with no exploitation evidence |
| 4 | **Redirect rejection** | Rejects 30x redirects to auth/home endpoints for high/critical findings |
| 5 | **Error indicator saturation** | Rejects if ≥2 generic error keywords and no evidence markers (`confirmed:`, `payload`, `evidence:`) |
| 6 | **Baseline similarity** | Rejects findings where response ≥85% similar to baseline (Levenshtein/token overlap) |
| 7 | **SSRF callback proof** | SSRF (non-blind) requires OOB callback URLs, cloud metadata content, or `confirmed:` |
| 8 | **XSS execution proof** | XSS (non-DOM) requires execution evidence for Likely/Confirmed tier |
| 9 | **Auth/2FA bypass proof** | Bypass findings require both an auth-required baseline AND session/access proof |
| 10 | **Secret entropy gate** | Secrets require `_SECRET_MIN_ENTROPY` (3.5 bits/char); placeholder markers, a known-example-token denylist (AWS docs keys, all-same-char strings) and low-variety values auto-reject |
| 11 | **GraphQL schema proof** | Introspection findings require `__schema` data and HTTP 200 |
| 12 | **Sensitive file content** | `.env`, `wp-config`, etc. require HTTP 200 + actual key-value content in response |
| 13 | **Public endpoint sensitivity** | "Unauthenticated access" findings require sensitive data signals (admin flags, credentials) |
| 14 | **Type-specific evidence** | 35+ vuln types mapped to mandatory evidence keywords (e.g. SQLi needs `confirmed:` or `error pattern`) |
| 15 | **Dependency CVE identifier** | Dependency findings require CVE-/GHSA-/PYSEC- identifier; secret findings reject placeholders |

### Confidence-Severity Coupling (Rule 3 pre-pass)
Before validation, `_apply_severity_confidence_coupling()` downgrades severity to match the confidence tier:
- Speculative (0–39) → `info`
- Potential (40–69) → cap high/critical to `medium`
- Likely (70–89) → severity preserved
- Confirmed (90–100) → severity preserved

### Semantic Deduplication (`fingerprint`)
`fingerprint(title, asset, details)` returns `vuln_class|normalized_asset|param` — identical fingerprints merge findings; same-type/same-asset findings merge parameters instead of creating duplicates.

### Evidence-Aware Validation
`add_finding()` forwards `raw_response`, `baseline_text` and `response_status` into the gate, so the HTML-error-page (Rule 3), redirect (Rule 4) and baseline-similarity (Rule 6) checks fire whenever a module supplies response evidence — not just the details-string rules.

### Self-Learning FP Suppression (`scanner/suppression.py`)
When an analyst marks a finding as a **false positive** (via `/api/findings/<id>/verify` or `/api/findings/<id>/status`), its semantic fingerprint is persisted to the `fp_suppressions` SQLite table. On every subsequent scan, `add_finding()` auto-rejects any finding matching a suppressed fingerprint — so a dismissed false positive never resurfaces. Reversing the decision (any non-FP status) removes the suppression.

- `GET /api/fp_suppressions` — list all suppressed fingerprints
- `DELETE /api/fp_suppressions` — remove a suppression (body: `{"fingerprint": "..."}`)

---

## Confirmation Protocol

Every candidate finding from the 5 discovery engines passes through the **confirmation protocol** (`scanner/confirmation.py`) before being stored. This protocol combines deterministic reproduction, oracle verification, payload minimization, and statistical validation.

### Confirmation Pipeline

1. **Deterministic Reproduction** — 3 attempts at 0.5s intervals; only 3/3 is considered reproducible
2. **Oracle Verification** — Verifies the finding using the appropriate oracle:
   - OOB: Checks for callback URLs, DNS lookups, HTTP callbacks
   - Error-based: Looks for SQL error patterns, stack traces, debug output
   - Reflected: Confirms payload reflection in response
   - Command output: Validates command execution output
   - File content: Confirms file read/write
   - Metadata: Cloud metadata response validation
3. **Payload Minimization** — Binary search to find the smallest triggering payload
4. **Known Pattern Check** — Validates against known vulnerability patterns and signatures
5. **Statistical Validation (Welch's T-test)** — For time-based blind vulnerabilities:
   - Collects 5 normal + 5 trigger timing samples
   - Performs Welch's t-test (unequal variance)
   - Requires p < 0.05 for statistical significance
   - Reports t-statistic and p-value in evidence bundle
6. **Confidence Scoring** — Final score 0–100 based on:
   - Deterministic reproduction success
   - Oracle verification results
   - Statistical test results
   - Known pattern matches
   - Minimization success

### Evidence Bundle

Each confirmed finding includes a complete evidence bundle:
- Raw HTTP request/response
- Reproduction steps (timestamped)
- Oracle verification results
- T-test statistics (mean/median/p-value) for time-based findings
- Minimized payload
- Classification (CONFIRMED / LIKELY / SPECULATIVE / INCONCLUSIVE)
- False Positive Classification (FP_CERTAIN / FP_LIKELY / NOT_FP / UNKNOWN)

---

## Vulnerability Chain Mapping

The chain mapping engine (`scanner/chains.py`) builds attack graphs from confirmed findings using BFS (Breadth-First Search) to discover multi-step exploitation paths.

### How It Works

1. **Finding → State Transition Mapping** — Each finding type maps to a state transition:
   - SQLi → `unauth` → `auth` (credential extraction)
   - XSS → `unauth` → `auth` (session hijacking)
   - SSRF → `unauth` → `internal` (service discovery)
   - Auth bypass → `unauth` → `auth` (direct access)
   - Privilege escalation → `auth` → `admin`
   - RCE → `auth` → `rce` (command execution)
   - File read → `auth` → `internal` (file access)
   - And 10+ more patterns

2. **Attack Graph Construction** — Nodes represent access states; edges represent findings that enable transitions

3. **Path Discovery (BFS)** — Finds all paths from `unauth` to each objective (`rce`, `admin`, `internal`, `data_exfil`, `persistence`)

4. **Chain Narrative Generation** — Each chain produces a step-by-step attack report with:
   - Entry point and prerequisites
   - Required findings in sequence
   - Combined risk score
   - Loot extracted at each step

5. **Loot Extraction** — Extracts credentials, tokens, keys, and sensitive data from findings

---

## Risk Assessment Engine

### Capabilities
- **Asset Management** — Track criticality, data classification, ownership
- **Risk Register** — NIST/ISO-based risk identification and scoring (5×5 matrix)
- **Risk Treatment** — Mitigation, transfer, acceptance, avoidance workflows
- **Key Risk Indicators (KRIs)** — Automated threshold monitoring
- **Controls Library** — Pre-loaded NIST baseline controls
- **Risk Acceptance** — Formal approval workflow with expiry tracking
- **Compliance Mapping** — NIST CSF, ISO 27001, SOC 2 alignment
- **FAIR Quantitative Analysis** — Annual Loss Expectancy (ALE) calculation
- **Risk Predictions** — 30/60/90-day risk trajectory modeling

### Operator Timeline
Full audit log of scan operations with timestamps, module progress, finding additions, and verification events. Exportable as PDF appendix.

---

## Enterprise Risk Correlation Engine

The **Cross-Layer Risk Correlation Engine** (`scanner/modules/web/risk_engine.py`) analyzes telemetry from 4 infrastructure layers (WEB, NETWORK, VM, CLOUD) to identify coordinated attacks. HIGH risk only fires when 3+ layers corroborate with a coherent attack chain — eliminating single-source false positives.

### 4-Layer Signal Detection

| Layer | Signal Types | What It Catches |
|-------|-------------|-----------------|
| **WEB** | SQLi, path traversal, XSS, SSRF, auth bypass, WAF blocks, brute force, sensitive file access | Web application attacks |
| **NETWORK** | Port scans, lateral movement, C2 traffic, exfiltration, privilege escalation, SMB/RDP activity | Network-based attacks |
| **VM** | Privilege escalation, process injection, rootkit indicators, credential dumping, persistence | Endpoint compromise |
| **CLOUD** | Policy mutation, data access, resource creation, credential use, unusual API activity | Cloud infrastructure attacks |

### Attack Chain Patterns (6)

| Chain | Description |
|-------|-------------|
| **Web Exploit → RCE** | Web vulnerability exploitation leading to remote code execution |
| **Recon → Exfiltration** | Reconnaissance phase leading to data exfiltration |
| **Lateral → Ransomware** | Lateral movement leading to ransomware deployment |
| **PrivEsc → Domain** | Privilege escalation leading to domain compromise |
| **Cloud → Data Theft** | Cloud misconfiguration leading to data theft |
| **C2 → Pivot** | Command and control leading to network pivot |

### Risk Classification Logic

- **CRITICAL**: HIGH + CONFIRMED + 3+ layers + attack chain detected
- **HIGH**: 3+ layers with coherent chain and confidence ≥ 75
- **MEDIUM**: 2 layers with confidence ≥ 55
- **LOW**: Single layer or insufficient correlation
- **INFO**: No telemetry or no signals detected

### MITRE ATT&CK Mapping

Automatically maps detected signals to 30+ MITRE techniques (T1190, T1059, T1068, T1021, T1078, T1530, etc.) with false-positive likelihood assessment per detection.

### API Endpoint

```bash
POST /api/risk-engine/analyze
Content-Type: application/json

{
  "web": "POST /admin/../etc/passwd HTTP/1.1\nStatus: 403 x40",
  "network": "TCP SYN scan 10.0.0.0/24\nPort 445 open on 12 hosts",
  "vm": "cmd.exe spawned by iis worker\nwhoami /priv -> SeImpersonatePrivilege",
  "cloud": "iam:CreatePolicyVersion by user dev01\nS3 GetObject on billing-data bucket"
}
```

Response:
```json
{
  "status": "ok",
  "result": {
    "risk_level": "HIGH",
    "confidence": 100,
    "attack_pattern": "Web Exploit → Remote Code Execution",
    "layers_involved": ["WEB", "NETWORK", "VM", "CLOUD"],
    "corroborating_signals": ["[WEB] sql_injection", "[NETWORK] lateral_movement", "[VM] privesc", "[CLOUD] data_access"],
    "mitre_techniques": ["T1190", "T1059", "T1068", "T1021", "T1530"],
    "recommended_action": "IMMEDIATE: Isolate affected systems and initiate incident response",
    "false_positive_likelihood": "LOW",
    "analyst_notes": "Cross-layer correlation detected across WEB, NETWORK, VM, CLOUD. Attack chain: Web Exploit → Remote Code Execution."
  }
}
```

---

## AI-Powered Recon Agent

The **Intelligent Recon Agent** (`recon/agent.py`) is a multi-phase autonomous reconnaissance workflow that adapts its strategy based on the target's detected site type and technology stack. When Ollama is available, it adds an **AI Analysis phase** that uses an LLM to triage findings and identify attack paths.

### Recon Workflow (5 Phases)

```
Phase 0: INITIAL ANALYSIS
  Fetch root page → classify site type (static/dynamic/SPA/API)
  Multi-signal PageTypeDetector (5 HTTP signal groups)
  Tech fingerprinting (server, framework, CMS, CDN/WAF, JS frameworks)
      ↓
Phase 1: SURFACE MAPPING
  crt.sh subdomain enumeration
  robots.txt + sitemap.xml parsing
  Active directory probing (40+ common paths)
  Root page crawl (forms, inputs, links, JS files)
  JS-based API endpoint extraction
      ↓
Phase 2: STRATEGY SELECTION
  Tool matrix selection based on site type:
    static  → Katana, Gau, Waybackurls, Httpx, LinkFinder
    dynamic → Katana, Nuclei, Dalfox, ParamSpider, SQLMap, Feroxbuster, FFUF
    spa     → Katana (headless), JSFinder, SecretFinder, LinkFinder, Nuclei
    api     → Kiterunner, Nuclei, FFUF
  Adaptive recommendations (login, upload, search, GraphQL, API detected)
      ↓
Phase 3: ADAPTIVE RECON (10 security checks)
  1. Security headers check (CSP, HSTS, X-Frame-Options, etc.)
  2. Sensitive file exposure (.env, .git, config, wp-config, etc.)
  3. CORS misconfiguration (reflected origin + credentials)
  4. Information disclosure (stack traces, debug mode)
  5. Dynamic-only tests (CSRF, autocomplete, rate limiting)
  6. Open redirect detection
  7. API endpoint sensitive data exposure
  8. Upload functionality bypass
  9. Search/XSS reflection check
  10. SSL/TLS certificate expiry check
      ↓
Phase 3.5: AI ANALYSIS (optional — requires Ollama)
  Uses dolphin3:8b LLM for:
  • Finding triage: TRUE / FALSE_POSITIVE / UNCERTAIN classification
  • Attack path identification: chains of findings for privilege escalation
  • Executive summary: 2-3 sentence risk assessment
  • Prioritized remediation: grouped fixes by effort/impact
  Auto-applies FALSE_POSITIVE verdicts to findings
      ↓
Phase 4: REPORT COMPILATION
  Technology stack summary
  Website classification (type, confidence, strategy)
  Attack surface map (subdomains, dirs, params, APIs, JS, forms)
  Tool matrix with availability status
  Findings with severity breakdown and risk level
  AI analysis results (triage, attack paths, remediation)
  Recommended next actions
```

### Tool Matrix by Site Type

| Site Type | Primary Tools | Rationale |
|-----------|--------------|-----------|
| **Static** | Katana, Gau, Waybackurls, Httpx, LinkFinder | No server-side attack surface; focus on URL enumeration, header hardening, CDN config |
| **Dynamic** | Katana, Nuclei, Dalfox, ParamSpider, SQLMap, Feroxbuster, FFUF | Full attack surface; prioritize injection vectors, auth tests, directory bruteforce |
| **SPA** | Katana (headless), JSFinder, SecretFinder, LinkFinder, Nuclei | JS bundles contain API endpoints and route maps; headless crawl for client-side routes |
| **API** | Kiterunner, Nuclei, FFUF | No HTML surface; API-specific endpoint bruteforce, auth bypass, BOLA testing |

### AI Triage Example Output

```json
{
  "triage": [
    {"id": "Missing Security Headers", "verdict": "TRUE", "confidence": 0.95, "reason": "CSP, HSTS, X-Frame-Options all absent in HTTP response"},
    {"id": "Sensitive File Exposed: .env", "verdict": "TRUE", "confidence": 0.99, "reason": "GET /.env returned HTTP 200 with DB_PASSWORD content"},
    {"id": "Reflected XSS via ?q=", "verdict": "UNCERTAIN", "confidence": 0.6, "reason": "Payload reflected but CSP may block execution"}
  ],
  "false_positive_count": 2,
  "true_positive_count": 5,
  "executive_summary": "Critical exposure of .env file with database credentials. Missing security headers across all pages. 3 injection vectors confirmed."
}
```

---

## Platform Features

### Scan Configuration
- **Scan Profiles** — Quick (batch=15), Balanced (batch=6), Aggressive (batch=10), Stealth (batch=1, passive-only)
- **Advanced Options UI** — Nmap flags, Nuclei severity filter, SQLMap level/risk, FFuf threads, tool timeout, skip modules
- **Per-Module Progress** — Real-time module status (running/completed/failed/timed_out)
- **Module Count Tracking** — `modules_done` / `modules_total` with percentage display

### UI Features
- **Real-time Progress** — SSE-based live scan updates with 81+ progress keys
- **4 Scan Type Tabs** — Web, Code, Network, VM/Cloud with dedicated stats and findings
- **Dark/Light Theme** — Full theme support with system preference detection
- **Collapsible Sidebar Navigation** — 30 investigation tabs organised into 5 expandable groups (Network Details, Security Analysis, Threat Analysis, Recon Agent, Risk Management) with icons, item-count badges, smooth CSS animation, and localStorage-persisted state
- **Proxy Traffic Viewer** — Browse, filter, and replay captured HTTP traffic
- **Finding Details Modal** — Full finding details with verification controls (Verified True / Needs Review / False Positive)
- **FP Suppressions Manager** — Dedicated panel (Threat Analysis → FP Suppressions) listing every analyst-dismissed false positive, with one-click Restore to let a fingerprint surface again
- **Attack Graph** — Visual attack chain representation
- **Scan Diff** — Compare findings between scans (new, resolved, persisting)
- **AI-Powered Recon Agent** — Multi-phase autonomous recon with live SSE log streaming, 6-phase progress bar, tech fingerprinting, attack surface mapping, tool matrix recommendations, and AI triage results display (triage cards, executive summary, attack paths, prioritized remediation)
- **Standalone AI Analysis** — Run AI triage on existing recon findings without re-running recon

### Data & Reporting
- **SQLite Persistence** — Findings, scan history, risk data, operator log
- **PDF Report Generation** — Executive summary, detailed findings, compliance mapping
- **JSON / CSV / SARIF 2.1.0 Export** — GitHub Code Scanning / Azure DevOps integration
- **CVE Ingestion** — 15-source live CVE feeds

### Security
- **Authentication** — Session-based auth with rate limiting
- **Security Headers** — CSP, HSTS, X-Frame-Options enforcement
- **SSRF Protection** — Cloud metadata endpoint blocking, private IP guard
- **Rate Limiting** — Per-endpoint via `core.extensions._rate_limit()`
- **Concurrent Safety** — Proper locking on all shared scan state

---

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git
- Go (for installing Go-based tools)

### Required Security Tools

```bash
# Python packages (install in requirements.txt)
pip install --break-system-packages -r requirements.txt

# Core tools (Ubuntu/Debian)
sudo apt install nmap sqlmap ffuf nuclei httpx subfinder amass assetfinder \
    dnsx hakrawler gau katana dalfox wafw00f sslyze mitmproxy playwright \
    gitleaks crlfuzz naabu testssl.sh

# Go tools (install Go first: https://go.dev/dl/)
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/lc/gau/v2/cmd/gau/latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/dalfox/v2/cmd/dalfox@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/osv-scanner/cmd/osv-scanner@latest
go install github.com/zricethezav/gitleaks/v8@latest
go install github.com/edoardoc/crlfuzz@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu/latest

# Additional Python tools (install in requirements.txt)
pip install --break-system-packages semgrep trivy checkov bearer

# Optional: testssl.sh
git clone https://github.com/drwetter/testssl.sh.git ~/testssl.sh
ln -s ~/testssl.sh/testssl.sh ~/.local/bin/testssl.sh

# Optional: jwt_tool
git clone https://github.com/ticarpi/jwt_tool.git ~/jwt_tool
pip install --break-system-packages PyJWT
```

### AI Analysis (optional)

```bash
# Installs Ollama and pulls the dolphin3:8b model
bash scripts/setup_ai.sh

# Or manually:
curl -fsSL https://ollama.com/install.sh | sh
ollama pull dolphin3:8b
```

---

## Quick Start

### 1. Clone and Install

```bash
git clone https://github.com/your-username/Risk-assesment.git
cd Risk-assesment
python3 -m venv venv
source venv/bin/activate
pip install --break-system-packages -r requirements.txt
```

### 2. Run (Development)

```bash
python3 app_new.py
# → http://localhost:8080
```

### 3. Login

| Field | Value |
|-------|-------|
| URL | `http://localhost:8080` |
| Username | `admin` |
| Password | `admin@123456` |

### 4. Start Scanning

1. Enter a target URL (e.g., `https://example.com`)
2. Select scan type: **Web**, **Code**, **Network**, or **VM/Cloud**
3. Click **Start Scan**
4. Monitor real-time progress in the **Terminal** tab
5. View findings in the **Findings** tab
6. Use **Risk Engine** tab for cross-layer telemetry analysis

---

## Installation

```bash
git clone https://github.com/your-username/Risk-assesment.git
cd Risk-assesment
python3 -m venv venv
source venv/bin/activate
pip install --break-system-packages -r requirements.txt
```

### Run Commands

```bash
# Development server (auto-reload)
python3 app_new.py

# Production (gunicorn)
gunicorn 'app_new:create_app()' --workers 1 --bind 0.0.0.0:8080

# Background with logs
python3 app_new.py > /tmp/infosec.log 2>&1 &
```

The application starts on `http://localhost:8080`.

### Default Credentials

| Username | Password |
|----------|----------|
| admin    | `admin@123456` |

```bash
# Set custom password
export ADMIN_PASSWORD="your-secure-password"
python app_new.py
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | auto-generated | Flask session secret (persisted to `.secret_key`) |
| `ADMIN_PASSWORD` | `admin@123456` | Dashboard login password |
| `ADAPTIVE_ROUTING` | `0` | Set to `1` to enable static-site module pruning |
| `ALLOW_PRIVATE_TARGETS` | `0` | Set to `1` to allow scanning private IP ranges |
| `ALLOW_INSECURE_COOKIE` | `0` | Set to `1` to disable `Secure` cookie flag (HTTP dev only) |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API endpoint for AI analysis |
| `OLLAMA_MODEL` | `dolphin3:8b` | LLM model for AI-assisted findings triage |
| `CORS_ALLOWED_ORIGINS` | _(empty — same-origin only)_ | Comma-separated allowed CORS origins |
| `PORT` | `8080` | Port for the dev server (`python app_new.py`) |

---

## API Endpoints

### System
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Liveness probe — returns `{status, scanning, findings, ts}` for Docker/K8s |

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/login` | Authenticate user |
| GET | `/logout` | Destroy session |
| GET | `/api/auth/check` | Verify authentication status |

### Scanning
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/start_scan` | Initiate scan (params: `target`, `scan_type`, `scan_profile`, `advanced`) |
| GET | `/api/status` | Current scan status, progress, module progress, logs |
| POST | `/api/stop_scan` | Abort running scan |
| GET | `/api/stream` | SSE stream for real-time updates |

### Findings
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/findings/<id>/verify` | Verify / unverify / mark false positive (auto-syncs FP suppressions) |
| POST | `/api/findings/<id>/status` | Set lifecycle status (open / in_progress / mitigated / accepted / false_positive) |
| GET | `/api/fp_suppressions` | List all analyst-dismissed false-positive fingerprints |
| DELETE | `/api/fp_suppressions` | Remove a suppression (body: `{"fingerprint": "..."}`) |
| GET | `/api/risk/finding_context` | Context-aware risk score for a finding |

### Proxy Traffic
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/proxy/traffic` | Read HAR file, return simplified traffic entries |
| POST | `/api/replay` | Replay HTTP request with optional modifications |

### Risk Assessment
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/POST | `/api/assets` | Manage assets |
| GET/POST | `/api/risks` | Manage risks |
| POST | `/api/risks/:id/treatment` | Add risk treatment |
| GET | `/api/kris` | Key Risk Indicators |
| GET | `/api/controls` | Security controls |

### Reports & Analytics
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/export/pdf` | Generate PDF report |
| GET | `/api/export/json` | Export findings as JSON |
| GET | `/api/export/csv` | Export findings as CSV |
| GET | `/api/export/sarif` | Export as SARIF 2.1.0 (GitHub Code Scanning) |
| GET | `/api/history` | Historical scan data |
| GET | `/api/cve/ingest` | Fetch CVEs from 15 sources |

### Tools & Utilities
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/tools` | List all 39+ integrated tools with availability status |
| POST | `/api/tools/jwt-decode` | Decode a JWT token (header + payload) |
| POST | `/api/tools/nvd-lookup` | Look up CVEs for a technology via NVD API |
| POST | `/api/notify/test` | Test Slack/Discord notification webhook |
| GET | `/api/page_type` | Page type result for current/last scan target |
| POST | `/api/page_type/detect` | On-demand page type detection for any target |
| POST | `/api/scan/trigger` | CI/CD webhook — trigger scan via `X-API-Key` |
| GET | `/api/scan/<id>/status` | CI/CD job status |
| GET | `/api/scan/<id>/findings` | CI/CD job findings |

### AI Analysis
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/ai/status` | Check Ollama + model availability |
| POST | `/api/ai/analyze` | AI-assisted triage: FP filter, attack paths, executive summary, remediation |
| POST | `/api/ai/triage` | Apply AI FP verdicts to findings (mark false positives) |

### Recon Agent
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/recon/start` | Start autonomous recon agent (param: `target`) |
| GET | `/api/recon/status` | Recon agent phase, progress, log count |
| GET | `/api/recon/report` | Full structured recon report (tech stack, surface, findings, AI analysis) |
| GET | `/api/recon/stream` | SSE stream — real-time log lines during recon |
| POST | `/api/recon/stop` | Stop running recon agent gracefully |
| POST | `/api/recon/ai-analyze` | Run AI analysis on existing recon findings (standalone, no recon needed) |

### Enterprise Risk Correlation Engine
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/risk-engine/analyze` | Analyze 4-layer telemetry (web/network/vm/cloud) for cross-layer attack correlation |

### Discovery Engines
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/engines/status` | Status of all 5 discovery engines (mutation, anomaly, logic, OOB, parser) |
| POST | `/api/engines/confirm` | Run confirmation protocol on a single finding (T-test, oracle verification) |
| POST | `/api/engines/kill_switch` | Emergency kill switch: check or trigger scan abort |
| GET | `/api/engines/limits` | Current hard limits status (rate limiter, semaphores, request counter) |
| GET | `/api/engines/health` | Target health status (error rate, time trend, auto-pause state) |

### Chain Analysis & Reports
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/chains` | List all attack chains found |
| GET | `/api/chains/full` | Full attack chain analysis with BFS graph and exploitation paths |
| POST | `/api/report/generate` | Generate full scan report (CVSS 3.1 vectors, findings, chains) |
| GET | `/api/report/finding/<id>` | Generate report for a single finding |
| POST | `/api/confirm/batch` | Run confirmation protocol on all unconfirmed findings |

---

## Project Structure

```
Risk-assesment/
├── app.py                          # Legacy monolith (wsgi.py entry point)
├── app_new.py                      # Modular Flask application factory
├── wsgi.py                         # Production WSGI entry point (gunicorn)
│
├── core/
│   ├── auth.py                     # Session auth, login_required
│   ├── database.py                 # SQLite init + schema
│   ├── extensions.py               # Shared limiter, _rate_limit()
│   ├── logger.py                   # log(), push_sse(), sse_stream()
│   ├── main_routes.py              # / index + /api/health
│   ├── misc_routes.py              # SSE stream, CI/CD webhook, history
│   ├── proxy.py                    # MITMProxy integration
│   ├── tool_routes.py              # Tools, schedule, SIEM, notify, replay
│   └── utils.py                    # _find_tool, _run_tool, SSRF guards,
│                                   # validate_webhook_url, run_nvd_lookup
│
├── scanner/
│   ├── constants.py                # SCAN_PROFILES, ATTACK_MODULE_NAMES,
│   │                               # ADAPTIVE_ROUTING, DYNAMIC_ONLY_MODULES
│   ├── routing.py                  # PageTypeDetector, classify_target,
│   │                               # apply_adaptive_routing
│   ├── validation.py               # 15-Rule FP gate (_validate_finding),
│   │                               # CVSS scoring, classify_vuln, fingerprint,
│   │                               # _extract_tool_output, context risk
│   ├── suppression.py              # Self-learning FP suppression
│   ├── orchestrator.py             # Multi-phase scan orchestrator
│   │                               # (Phase 1 → 2 → 3 → 8)
│   ├── confirmation.py             # Confirmation protocol: deterministic
│   │                               # reproduction, oracle verification,
│   │                               # T-test, payload minimization
│   ├── chains.py                   # Vulnerability chain mapping,
│   │                               # BFS attack graph, chain narratives
│   ├── report.py                   # Full report generation with CVSS 3.1
│   ├── limits.py                   # Hard limits: rate limiter (10 req/s),
│   │                               # semaphores, kill switch, request counter
│   ├── health.py                   # Health monitoring: error rate, time
│   │                               # trend, auto-pause/resume
│   ├── routes.py                   # Scan API endpoints + engine APIs
│   ├── state.py                    # scan_state, LOCK, SCAN_JOBS
│   ├── findings.py                 # add_finding, op_log, set_progress,
│   │                               # auto-verify pool
│   ├── verify.py                   # verify_findings, attack chains, risk score
│   ├── tools/
│   │   ├── detection.py            # check_tool_availability
│   │   └── wrappers.py             # Tool subprocess helpers
│   ├── engines/                    # 5 custom discovery engines
│   │   ├── __init__.py             # Engine registry
│   │   ├── mutation.py             # Engine 1: Coverage-guided input mutation
│   │   │                           # (JSON/GraphQL/XML/headers/params/multipart)
│   │   ├── anomaly.py              # Engine 2: Differential/anomaly detection
│   │   │                           # (30-sample baseline, Z-score analysis)
│   │   ├── logic.py                # Engine 3: State-aware logic-flaw hunting
│   │   │                           # (workflow bypass, replay, race conditions)
│   │   ├── oob.py                  # Engine 4: Blind OOB discovery
│   │   │                           # (local HTTP+DNS server, 5 payload types)
│   │   └── parser_stress.py        # Engine 5: Memory/parser edge cases
│   │                               # (oversized/nested/encoding/smuggling)
│   └── modules/
│       ├── web/                    # headers, injection, auth, discovery,
│       │                           # advanced, api, pentest, wazuh,
│       │                           # risk_engine (9 files)
│       ├── code/                   # sast.py
│       ├── network/                # recon.py, vuln.py
│       └── vm/                     # container.py
│
├── reports/
│   ├── routes.py                   # /api/export/* endpoints
│   ├── pdf.py                      # FPDF-based PDF report generator
│   └── json_export.py              # JSON / SARIF helpers
│
├── risk/
│   ├── routes.py                   # /api/assets, /api/risks, /api/kris
│   └── engine.py                   # NIST/ISO/FAIR scoring, ALE calculation
│
├── recon/
│   ├── routes.py                   # /api/recon/start, /status, /report, /stream, /stop, /ai-analyze
│   └── agent.py                    # Multi-phase adaptive recon agent
│                                   # (5 phases: analysis → fingerprint → surface → adaptive scan → AI → report)
│
├── ai/
│   ├── routes.py                   # /api/ai/* endpoints
│   └── ollama.py                   # Ollama integration (dolphin3:8b)
│
├── templates/
│   ├── login.html                  # Login page
│   └── infosec_platform.html       # Main UI (7,000+ lines)
│
├── tests/
│   ├── test_fp_validation.py       # 41 pytest tests — 15-rule FP gate + secret hardening
│   ├── test_fp_suppression.py      # 6 pytest tests — suppression store round-trip
│   ├── test_suppression_api.py     # 3 pytest tests — suppression lifecycle via API
│   ├── test_page_type_detector.py  # 22 pytest tests — PageTypeDetector
│   ├── test_wazuh.py              # 32 pytest tests — Wazuh-style detection engine
│   ├── test_bizlogic_oracles.py    # Business logic oracle tests
│   ├── test_dedup_recall.py        # Deduplication and recall tests
│   └── test_scope.py               # Scope validation tests
│
├── scripts/
│   └── setup_ai.sh                 # Ollama + dolphin3:8b install helper
│
├── SCAN_METHODOLOGY.md             # Per-module scan methodology docs
├── requirements.txt                # Python dependencies
├── infosec.db                      # SQLite database (auto-created, git-ignored)
└── .secret_key                     # Session secret (auto-generated, git-ignored)
```

---

## Security Features

### Built-in Protections
- **Rate Limiting** — 10 login attempts/minute, 5 scans/hour (via `core.extensions`)
- **Session Security** — HttpOnly, SameSite=Strict cookies
- **CSRF Protection** — Origin/Referer header validation on all state-changing requests
- **SSRF Prevention** — `_check_target_for_ssrf()` blocks cloud metadata (`169.254.169.254`, `fd00:ec2::254`) and private RFC-1918 ranges; `validate_webhook_url()` enforces the same rules for outbound webhooks
- **CSP Headers** — Strict Content-Security-Policy (no unsafe-eval, no external scripts except pinned CDNs)
- **Input Validation** — 10 MB request size limit, `_safe_str()` / `_safe_int()` boundary sanitization
- **Password Hashing** — Werkzeug secure password storage
- **Concurrent Safety** — `threading.Lock` on all shared scan state
- **Scan Hard Limit** — 3600-second timeout with auto-reset for stuck scans
- **Thread Safety** — `ThreadPoolExecutor` with `cancel_futures` for stuck modules

### Discovery Engine Protections
- **Rate Limiter** — Token bucket at 10 requests/second per target
- **Connection Limiter** — Semaphore allowing max 5 concurrent connections
- **Kill Switch** — Checks `/tmp/stop_scan_{scan_id}` before every request; POST to `/api/engines/kill_switch` to trigger
- **Request Counter** — Hard cap at 10,000 requests per scan; engines abort when exceeded
- **Payload Truncation** — Request body capped at 10KB to prevent resource exhaustion
- **Health Monitoring** — Sliding 60-second window tracking error rate, response time trend, connection resets; auto-pauses at >10% error rate or degraded time trend; auto-resumes when recovered

---

## Troubleshooting

**Port already in use:**
```bash
fuser -k 8080/tcp
# or
lsof -i :8080
kill -9 <PID>
```

**Tool not found:**
```bash
# Check which tools are installed
which nmap sqlmap ffuf nuclei httpx subfinder gau katana wafw00f mitmdump
# Reinstall missing tools per Prerequisites section
```

**Playwright browser issues:**
```bash
python3 -m playwright install chromium
python3 -m playwright install-deps
```

**Scan stuck or not starting:**
- The scan auto-resets after `SCAN_HARD_LIMIT + 300` seconds (≈ 1 h 5 min)
- Check logs for `NameError` or `TimeoutError` messages
- Ensure all required tools are installed

**Import errors after refactor:**
- All routes live in sub-packages; `wsgi.py` and `app_new.py` are the only valid entry points
- Do not import from `app.py` in new code — use the module paths shown in the architecture diagram

**Login fails (HTTP mode):**
- `SESSION_COOKIE_SECURE` defaults to `0` for HTTP access — this is expected
- If login still fails, clear browser cookies and retry

**Admin password reset:**
```bash
python3 -c "
import sqlite3, os
db = sqlite3.connect('infosec.db')
db.execute('DELETE FROM users WHERE username = \"admin\"')
db.commit()
db.close()
print('Admin deleted. Restart app to recreate with ADMIN_PASSWORD env var.')
"
export ADMIN_PASSWORD='your-new-password'
python app_new.py
```

**Tests:**
```bash
# Run full test suite (150+ tests)
python -m pytest tests/ -v

# Run specific test
python -m pytest tests/test_wazuh.py -v
```

---

## Disclaimer

This tool is designed for legitimate security assessments and authorized penetration testing only. Users are responsible for obtaining proper authorization before scanning any systems. Unauthorized scanning is illegal.

## License

This project is for authorized security testing and educational purposes only.
