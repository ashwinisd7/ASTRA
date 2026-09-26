# Python AI-Driven WordPress User Enumeration & Recon Tool

[![Python Version](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-19%20passed-brightgreen.svg)]()

An autonomous AI-driven reconnaissance and vulnerability detection tool engineered to map WordPress attack surfaces, dynamically discover user accounts across 6 enumeration vectors, perform targeted administrative credential verification, and synthesize actionable executive reports.


---

## Table of Contents
1. [Approach and Reasoning](#1-approach-and-reasoning)
2. [Architecture (Modules, Flow, Agent Design)](#2-architecture-modules-flow-agent-design)
3. [How to Configure and Run the Tool](#3-how-to-configure-and-run-the-tool)
4. [CLI Options Reference](#4-cli-options-reference)
5. [How to Test the Tool](#5-how-to-test-the-tool)
6. [Limitations and Trade-offs](#6-limitations-and-trade-offs)

---

## 1. Approach and Reasoning

### Autonomous ReAct Agent Loop
Rather than executing a rigid, linear script, the tool models WordPress reconnaissance as an **autonomous ReAct (Reasoning + Action) agent**:
* **Thought:** At each cycle, the AI evaluates the current state of reconnaissance (target URL, users already discovered, techniques attempted, and previous observations).
* **Action:** The agent selects the highest-probability next vector from an active registry (or decides to `STOP` if sufficient intelligence is gathered).
* **Observation:** The selected module probes the target, captures HTTP responses, extracts user identities, deduplicates usernames, and records evidentiary endpoints.

### Defense-in-Depth Vector Coverage (6 Enumeration Modules)
WordPress instances frequently disable one vector while leaving others exposed. To ensure high discovery yield, 6 distinct vectors are supported:
1. **REST API Exposure (`/wp-json/wp/v2/users`):** Directly queries the core WordPress REST API endpoint to extract complete user profiles, slugs, and numeric IDs.
2. **Author Archive Routing (`/?author=N`):** Probes sequential user IDs (`?author=1..N`). WordPress automatically redirects valid IDs (HTTP 301/302) to `/author/<slug>/`, leaking the username in the `Location` header.
3. **Login Error Leakage (`/wp-login.php`):** Sends probe requests with candidate usernames. Default WordPress authentication returns distinct error strings (*"The password you entered for the username admin is incorrect"* vs. *"Unknown username"*), allowing unauthenticated user confirmation.
4. **RSS / Atom Feed Sniffing (`/feed/`, `/?feed=rss2`):** Parses published feed XML for `<dc:creator>` and `<author>` tags containing author usernames.
5. **XML Sitemap Sniffing (`/wp-sitemap-users-1.xml`, `/author-sitemap.xml`):** Inspects WordPress 5.5+ core sitemaps and popular SEO plugins (Yoast, RankMath) that index author profile URLs.
6. **oEmbed API Sniffing (`/wp-json/oembed/1.0/embed`):** Queries post embed metadata which embeds public author display names and URLs.

### Resilient Dual-Engine AI Architecture
* **Cloud AI Engine:** Uses Google Gemini (`gemini-3.1-flash-lite`) via native REST APIs with enforced JSON mode (`responseMimeType: application/json`) for structured planning, login error disambiguation, and executive report synthesis.
* **Offline Deterministic Fallback:** If no API key is configured, or if rate limits / network errors occur, the agent seamlessly falls back to a built-in heuristic engine without interrupting the scan.

### Targeted Administrative Credential Verification
Reconnaissance does not stop at username discovery. The orchestrator identifies high-privilege administrative accounts (`admin`, `administrator`, `root`, or `user_id=1`) and conducts a rate-limited password audit against common default WordPress credentials or a custom wordlist.

### Auxiliary Exploit & Attack Surface Detection
Identifies additional high-severity misconfigurations including core version disclosure (`readme.html`, meta tags), active XML-RPC endpoints (`/xmlrpc.php`), and exposed sensitive files (`debug.log`, `wp-config.php.bak`).

---

## 2. Architecture (Modules, Flow, Agent Design)

### Project Directory Structure

```
python_agent/
├── astra_recon/
│   ├── cli.py                  # CLI entrypoint with Click & Rich console
│   ├── config.py               # Hierarchical config loader (.env, CLI, file)
│   ├── models.py               # Pydantic schemas (Section 6.2 spec)
│   ├── mock_server.py          # Flask vulnerable WordPress testbed
│   ├── agent/
│   │   ├── orchestrator.py     # ReAct agent execution coordinator
│   │   ├── llm_client.py       # Gemini client & Heuristic engine
│   │   ├── prompts.py          # System and task prompts for LLM
│   │   └── reporter.py         # Markdown and JSON report generator
│   ├── enumerators/            # 6 user enumeration modules
│   │   ├── base.py             # Abstract BaseEnumerator interface
│   │   ├── rest_api.py         # REST API enumerator
│   │   ├── author_archive.py   # Author redirect enumerator
│   │   ├── login_leak.py       # Login error message enumerator
│   │   ├── feed_sniffer.py     # RSS/Atom feed parser
│   │   ├── sitemap_sniffer.py  # XML sitemap parser
│   │   └── oembed_sniffer.py   # oEmbed API consumer
│   ├── attacks/
│   │   ├── bruteforce.py       # Admin credential brute-force engine
│   │   └── wordlists.py        # Wordlist loader & curated defaults
│   ├── scanners/
│   │   └── exploit_detector.py # Version, XML-RPC & sensitive file scanner
│   └── utils/
│       ├── http_client.py      # Resilient HTTP client with timeouts
│       └── console.py          # Rich terminal formatter & table generator
├── tests/                      # 19 automated unit and integration tests
├── reports/                    # Auto-generated scan reports (JSON + Markdown)
├── requirements.txt            # Python dependencies
├── setup.py                    # Package installer (astra-wp-recon command)
├── docker-compose.yml          # Containerized WordPress environment
└── sample_scan_results.json    # Sample JSON results
```

### Execution Flow Diagram

```
+-------------------------------------------------------------+
|                       CLI (cli.py)                          |
|         Parses flags, reads .env, loads ScanConfig          |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|           ReconAgentOrchestrator (orchestrator.py)          |
+------------------------------+------------------------------+
                               |
         +---------------------+---------------------+
         |                                           |
         v                                           v
+-------------------------------+   +-------------------------------+
|     ReAct Enumeration Loop    |   |     Credential Brute-Force    |
|  1. llm.plan_next_technique() |   |  - Target: admin accounts     |
|  2. enumerator.run()          |   |  - Tests: wp-login & XML-RPC  |
|  3. Deduplicate & Observe     |   |  - Custom or top-15 wordlist  |
+---------------+---------------+   +---------------+---------------+
                |                                   |
                +-----------------+-----------------+
                                  |
                                  v
+-------------------------------------------------------------+
|             Exploit Detector (exploit_detector.py)          |
|    Probes version, XML-RPC, debug.log, backup files         |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|         AI Summary Synthesis (llm.generate_summary)         |
|         Executive overview, findings, risk assessment       |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|               Report Generator (reporter.py)                |
|      Outputs results.json (Sec 6.2) & report.md (Audit)     |
+-------------------------------------------------------------+
```

---

## 3. How to Configure and Run the Tool

### Installation

```powershell
# 1. Clone/navigate to the project directory
cd C:\Users\HP\OneDrive\Desktop\TEST\ASTRA

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install in editable mode
pip install -e .
```

### Starting the Vulnerable Mock Server
A dedicated mock server is included to safely simulate vulnerable WordPress endpoints:
```powershell
python -m astra_recon.mock_server --port 8081
```

### Basic Reconnaissance Scan
```powershell
astra-wp-recon --url http://localhost:8081
# or
python -m astra_recon.cli -u http://localhost:8081
```

### Custom Password Wordlist
Supply a custom wordlist and configure maximum attempts per administrator:
```powershell
astra-wp-recon -u http://localhost:8081 -w passwords.txt --max-bruteforce 50
```

### Disabling Brute-Force Testing
Run user enumeration and exploit detection without attempting credential logins:
```powershell
astra-wp-recon -u http://localhost:8081 --no-bruteforce
```

### Selective Technique Execution
Target specific attack vectors (`rest_api`, `author_archive`, `login_leak`, `feed_sniffer`, `sitemap_sniffer`, `oembed_sniffer`):
```powershell
astra-wp-recon -u http://localhost:8081 -t rest_api,author_archive
```

### Machine / CI-CD Output (Strict JSON Mode)
Outputs only pure, machine-readable JSON matching the Section 6.2 schema to `stdout`:
```powershell
astra-wp-recon -u http://localhost:8081 --json
```

### Configuring AI Keys
Set your key in `.env`:
```env
API_KEY=Your_Gemini_Api_Key_Here
MODEL=gemini-3.1-flash-lite
```
Or pass it directly on the command line:
```powershell
astra-wp-recon -u http://localhost:8081 --gemini-key "AIzaSy..."
```
*(If no API key is supplied, the tool automatically uses its built-in offline Heuristic AI engine).*

---

## 4. CLI Options Reference

| Flag / Option | Short | Default | Description |
|---|---|---|---|
| `--url <URL>` | `-u` | *None* | Target WordPress URL (e.g. `http://localhost:8081`). Can also be set via `TARGET_URL` env var. |
| `--config <PATH>` | `-c` | *None* | Path to YAML or JSON configuration file. |
| `--techniques <LIST>` | `-t` | All 6 | Comma-separated list: `rest_api`, `author_archive`, `login_leak`, `feed_sniffer`, `sitemap_sniffer`, `oembed_sniffer`. |
| `--wordlist <PATH>` | `-w` | Top 15 Built-in | Path to custom text file with passwords for admin brute-forcing (one password per line). |
| `--max-bruteforce <N>` | | `15` | Maximum number of passwords to test per admin user. |
| `--no-bruteforce` | | `False` | Disable credential brute-force testing entirely. |
| `--max-authors <N>` | | `10` | Maximum author IDs to probe during author archive enumeration (`?author=1..N`). |
| `--no-exploit-checks` | | `False` | Skip WordPress version, XML-RPC, and sensitive file checks. |
| `--timeout <SEC>` | | `10` | HTTP request timeout in seconds. |
| `--gemini-key <KEY>` | | *None* | Google Gemini API key (or set `GOOGLE_GENERATIVE_AI_API_KEY` / `GEMINI_API_KEY` in `.env`). |
| `--gemini-model <MODEL>` | | `gemini-3.1-flash-lite` | Gemini model identifier. |
| `--api-key <KEY>` | | *None* | Google Gemini API key (alias for `--gemini-key`). |
| `--model <MODEL>` | | *None* | AI model identifier (default: `gemini-3.1-flash-lite`). |
| `--output <PATH>` | `-o` | *None* | Custom destination path for structured JSON results. |
| `--report <PATH>` | `-r` | *None* | Custom destination path for Markdown audit report. |
| `--json` | | `False` | Output strictly JSON to `stdout` (Section 6.2 spec). |
| `--verbose` | `-v` | `False` | Enable detailed debug logs, HTTP responses, and rich tables. |
| `--quiet` | `-q` | `False` | Suppress banner and progress status lines. |
| `--help` | `-h` | | Show full help message and options list. |

---

## 5. How to Test the Tool

### Step 1: Environment Variables Configuration (Gemini API Key)
The AI agent uses **Google Gemini** for intelligent ReAct loop planning and executive security summary synthesis.

Copy the provided example environment configuration:
```powershell
cp .env.example .env
```

Set your Google Gemini API key in `.env`:
```env
# Astra WordPress Security Tool Configuration
TARGET_URL=http://localhost:8081
REQUEST_TIMEOUT=10
MAX_AUTHOR_ID=10
BRUTEFORCE_ENABLED=true
MAX_BRUTEFORCE_ATTEMPTS=15

# AI Agent Configuration (Google Gemini)
API_KEY=Your_Gemini_Api_Key_Here
MODEL=gemini-3.1-flash-lite
```

> **Note on Zero-Dependency Testing (Offline Mode):** If no API key is provided, or during network failure, the tool automatically engages its built-in deterministic heuristic reasoning engine (`is_offline = True`), allowing full execution without requiring any cloud API key.

### Step 2: Testing with the Local Mock Server
A dedicated mock WordPress server is bundled with the project to safely test the complete reconnaissance lifecycle against realistic vulnerabilities:

1. **Launch the mock WordPress environment in Terminal 1:**
   ```powershell
   python -m astra_recon.mock_server --port 8081
   ```

2. **Execute the autonomous reconnaissance scan in Terminal 2:**
   ```powershell
   # With Gemini AI reasoning active (using .env API_KEY):
   python -m astra_recon.cli -u http://localhost:8081

   # Or testing the offline heuristic fallback mode:
   python -m astra_recon.cli -u http://localhost:8081 --no-bruteforce
   ```

### Step 3: Running the Automated Test Suite (19 Tests)
The tool is comprehensively verified using an automated `unittest` test suite covering unit functionality, edge cases, fault tolerance, and full end-to-end integration:

```powershell
# Run the complete test suite
python -m unittest discover -s tests -v
```

### Test Catalog & Technical Rationale

| Module / Test File | Test Method | Technical Rationale & Purpose |
|---|---|---|
| **AI Agent**<br>[`test_agent.py`](tests/test_agent.py) | `test_plan_next_technique_initial` | **Initial Attack Strategy:** Verifies that the agent begins reconnaissance by prioritizing the most reliable high-yield vector (`rest_api`). |
| | `test_plan_next_technique_fallback` | **Adaptive Vector Switching:** Verifies that when a vector yields no new users or has already executed, the agent dynamically pivots to alternate vectors like `author_archive`. |
| | `test_analyze_login_response` | **Error Message Disambiguation:** Verifies that login response parsing correctly distinguishes between existing accounts (*"password incorrect"*) and invalid usernames (*"unknown username"*). |
| | `test_generate_summary_format` | **Executive Report Synthesis:** Ensures the generated security summary correctly incorporates discovered accounts, evidence endpoints, and critical risk findings. |
| | `test_heuristic_is_offline` | **Engine Status Transparency:** Verifies that the offline deterministic heuristic engine explicitly reports its offline status (`is_offline = True`) for clear console logging. |
| | `test_gemini_fallback_notifies_offline` | **Resilient Fault Tolerance:** Simulates a Gemini API error (e.g., invalid key or network timeout) and verifies that the agent automatically falls back to the heuristic engine without crashing or terminating the scan. |
| **Credential Brute-Force**<br>[`test_bruteforce.py`](tests/test_bruteforce.py) | `test_identify_admin_targets` | **Privileged Account Targeting:** Verifies that discovered users named `admin`, `administrator`, `root`, or user ID 1 are prioritized for password auditing. |
| | `test_bruteforce_success_wp_login` | **Authentication Detection:** Verifies that receiving an HTTP 302 redirect to `/wp-admin/` correctly flags the account as compromised and logs the cracked password. |
| | `test_wordlist_fallback` | **Default Password Fallback:** Ensures that if no custom wordlist is supplied, the tool loads built-in common WordPress passwords up to the configured limit. |
| **Enumerators**<br>[`test_enumerators.py`](tests/test_enumerators.py) | `test_rest_api_enumerator_standard` | **REST API (`/wp-json/wp/v2/users`):** Verifies parsing of WordPress core user objects, extracting usernames, slugs, IDs, and admin flags. |
| | `test_author_archive_redirect` | **Author Redirects (`/?author=N`):** Verifies detection of HTTP 301/302 redirects containing `/author/<username>/` in the `Location` header. |
| | `test_login_leak_enumerator` | **Login Information Disclosure:** Verifies user existence detection via differentiated error messages at `/wp-login.php`. |
| | `test_feed_sniffer` | **RSS/Atom Feed Sniffing:** Verifies extraction of author identities from `<dc:creator>` XML tags in `/feed/` and `/?feed=rss2`. |
| | `test_sitemap_sniffer` | **XML Sitemap Sniffing:** Verifies detection of author URLs in user sitemaps (`/wp-sitemap-users-1.xml`, `/author-sitemap.xml`). |
| | `test_oembed_sniffer` | **oEmbed Metadata Sniffing:** Verifies that public author names exposed via the oEmbed endpoint (`/wp-json/oembed/1.0/embed`) are captured. |
| **Exploit Detector**<br>[`test_exploit_detector.py`](tests/test_exploit_detector.py) | `test_version_disclosure_readme` | **Version Leak Detection:** Verifies detection of exposed WordPress core versions through static files like `readme.html` or generator headers. |
| | `test_xmlrpc_enabled` | **XML-RPC Attack Surface:** Verifies detection of active `/xmlrpc.php` endpoints (which can enable brute-force amplification and DDoS). |
| | `test_sensitive_files` | **Exposed Sensitive Files:** Verifies detection of sensitive logs/backups (e.g., `debug.log`, `wp-config.php.bak`) and sets appropriate severity ratings (CRITICAL). |
| **End-to-End**<br>[`test_e2e.py`](tests/test_e2e.py) | `test_full_recon_cycle` | **Full Lifecycle Integration:** Spins up a live mock WordPress server on an ephemeral port in a background thread, executes the complete autonomous ReAct agent loop (multi-vector discovery, credential brute-forcing, and vulnerability detection), and validates that the output matches the required JSON specification. |

---

## 6. Limitations and Trade-offs

| Design Area | Limitation / Trade-off | Rationale & Mitigation |
|---|---|---|
| **Rate Limiting & WAFs** | Aggressive probing can trigger Cloudflare, Wordfence, or Fail2ban IP bans. | A default inter-request delay (`bruteforce_delay: 0.2s`) and request timeouts (`timeout: 10s`) are enforced. For stealth testing, delay and wordlist length can be tuned via CLI flags. |
| **LLM Latency vs. Heuristics** | Cloud LLM network round-trips add ~1-2 seconds per reasoning step. | Native JSON mode (`responseMimeType: application/json`) ensures deterministic schema compliance. When offline or during quota limits, the zero-latency Heuristic engine takes over instantly. |
| **Sequential vs. Concurrent Probing** | Techniques are executed sequentially rather than simultaneously. | Sequential execution maintains a predictable ReAct agent trace, avoids overwhelming the target server, and allows observations from vector $N$ to inform vector $N+1$. |
| **Brute-Force Safeguards** | Default brute-force attempts are intentionally capped at 15 passwords per admin. | Real-world penetration testing prioritizes low-volume, high-probability passwords to avoid account lockouts or alarm generation. Can be overridden via `--max-bruteforce`. |
| **Complex Custom Setups** | Headless WordPress setups (e.g. Next.js/Gatsby frontends) may not redirect `?author=N` or expose `/wp-login.php`. | By deploying 6 complementary vectors (such as REST API and oEmbed), the tool maintains high discovery probability even when traditional frontend routing is modified. |
