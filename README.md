# NetSecureX — In-Transit Email MTA & Milter Threat Scanner

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](#running-tests)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://python.org)
[![MTA](https://img.shields.io/badge/MTA-Postfix%20%7C%20Milter%20%7C%20SMTP%20Proxy-orange.svg)](#mail-flow-architecture)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](#license)

**NetSecureX** is a high-performance Mail Transfer Agent (MTA) scanning gateway and milter filter designed to intercept emails in transit — before they reach recipient inboxes — and inspect them for phishing, executive spoofing, malware attachments, and domain impersonation.

---

## Key Features

- **In-Transit Header Validation (Pre-DATA & DATA)**:
  - **SPF Validation (`pyspf`)**: Evaluates sending IP against envelope sender and HELO name.
  - **DKIM Cryptographic Verification (`dkimpy`)**: Verifies cryptographic signatures against public DNS keys with timeout-bound DNS lookups.
  - **DMARC Alignment**: Evaluates strict/relaxed SPF and DKIM alignment against Header From domains, enforcing published `reject`/`quarantine`/`none` policies.
  - **RFC 8601 `Authentication-Results` Injection**: Appends standardized verification headers to accepted messages.

- **Content & Payload Scanning Hook**:
  - **URL Extraction & Google Safe Browsing API v4**: Detects credential phishing, malware links, and social engineering URLs with batch query support and LRU caching.
  - **Attachment Hash Extraction & VirusTotal v3**: Extracts MIME parts, calculates SHA-256 hashes, queries VirusTotal AV engines, and detects dangerous double extensions (`.pdf.exe`) or macro documents (`.docm`, `.xlsm`).
  - **Advanced Threat Heuristics**:
    - **Urgency / Coercion Detection**: NLP-like regex scoring for wire transfers, gift cards, and password reset extortion.
    - **Display Name Spoofing**: Detects executive/VIP impersonation (e.g. `CEO John Doe <attacker@gmail.com>`) and cousin reply-to baiting.
    - **Lookalike & Homoglyph Domains**: Levenshtein edit-distance calculation and Unicode/Cyrillic character substitution matrices.

- **Decision Engine**:
  - **High Risk (Score &ge; 70)**: Immediate SMTP-layer **550 rejection** (`5.7.1 Message rejected by NetSecureX policy`) or silent reroute to security quarantine mailbox.
  - **Medium Risk (30 &le; Score < 70)**: Modifies Subject (e.g. `[SUSPECTED PHISHING]`), injects `X-NetSecureX-*` audit headers, and relays to destination.
  - **Low Risk (Score < 30)**: Injects audit headers and delivers cleanly.

- **Performance & Graceful Degradation**:
  - Thread-safe in-memory LRU cache with configurable TTL.
  - Asynchronous timeouts on external API calls (Safe Browsing, VirusTotal) with graceful fail-open fallbacks.

- **Persistence & Telemetry**:
  - Stores comprehensive audit trails (sender, recipient, IP, scores, breakdown, URL list, attachment SHA256 hashes, processing latency) in SQLite or PostgreSQL via SQLAlchemy.

---

## Mail Flow Architecture

```
                                  INCOMING EMAIL (Internet)
                                              │
                                              ▼
                             ┌─────────────────────────────────┐
                             │  Postfix Mail Gateway (Port 25) │
                             └────────────────┬────────────────┘
                                              │
                        ┌─────────────────────┴─────────────────────┐
                        │                                           │
         Pre-DATA Validation (CONNECT / HELO / MAIL FROM)     DATA Scanning Hook
                        │                                           │
                        └───────────────► NetSecureX ◄──────────────┘
                                        Milter / Proxy
                                   • SPF / DKIM / DMARC
                                   • Safe Browsing API
                                   • VirusTotal API
                                   • Heuristic Engine
                                              │
                      ┌───────────────────────┼───────────────────────┐
                      ▼                       ▼                       ▼
                [ HIGH RISK ]           [ MEDIUM RISK ]          [ LOW RISK ]
               Score >= 70.0            30.0 <= Score < 70.0     Score < 30.0
                      │                       │                       │
           ┌──────────┴──────────┐     ┌──────┴───────┐        ┌──────┴───────┐
           ▼                     ▼     ▼              ▼        ▼              ▼
       550 Reject            Divert to   Prepend Tag    Inject   Deliver        Inject
       at SMTP Level        Quarantine   to Subject     Headers  Normally       Headers
                                 │            │            │        │              │
                                 └────────────┴────────────┴────────┴──────────────┘
                                                          │
                                                          ▼
                                            [ Internal Mailbox / Exchange ]
```

---

## Quickstart: 1-Command College Demo (Web UI + Live MTA Gateway)

Run both the **In-Transit SMTP Scanning Gateway** and the **Interactive Live Dashboard** in a single command:

```bash
# 1. Activate virtual environment
# Windows:
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
# source .venv/bin/activate

# 2. Start the unified application
python app.py
```

Open your browser at **`http://127.0.0.1:5000`**:
- **🚀 1-Click Attack Simulator**: Test CEO Impersonation, Malware `.pdf.exe` attachments, Urgency Phishing, or Clean emails.
- **✉️ Custom Email Injector**: Compose any custom email and test SPF spoofing live.
- **📡 Real-Time Telemetry Log**: Watch the gateway intercept, score, and decide on emails in real time with detailed breakdown modals!

---

## Technical Architecture & Viva Guide

For project presentation and oral examination materials, see:
- 🎓 **[COLLEGE_PROJECT_REPORT.md](COLLEGE_PROJECT_REPORT.md)** — Project Abstract, Block Diagram, Module Breakdown, and **Top 10 Viva Q&A**.
- 🌐 **[DNS_MX_PREREQUISITES.md](docs/DNS_MX_PREREQUISITES.md)** — MX, SPF, DKIM, and DMARC DNS configuration guide.
- ⚙️ **[POSTFIX_DEPLOYMENT.md](docs/POSTFIX_DEPLOYMENT.md)** — Postfix milter & systemd deployment.

### 3. Run Test Vectors

In a separate terminal, inject built-in threat scenarios:

```bash
# 1. Clean email (Allowed)
python scripts/send_test_email.py --vector clean

# 2. Urgency & extortion threat (Tagged with [SUSPECTED PHISHING])
python scripts/send_test_email.py --vector urgency

# 3. VIP / Executive impersonation (Scored & Tagged/Quarantined)
python scripts/send_test_email.py --vector vip_spoof

# 4. Dangerous executable attachment (550 Rejected / Quarantined)
python scripts/send_test_email.py --vector attachment

# 5. Lookalike typosquatted domain
python scripts/send_test_email.py --vector lookalike

# Or test all vectors at once:
python scripts/send_test_email.py --vector all
```

---

## Running with Docker Compose (with MailHog UI)

To test end-to-end delivery with a visual webmail inbox:

```bash
docker-compose -f docker/docker-compose.yml up --build
```

- **NetSecureX Inbound SMTP**: `localhost:10025`
- **MailHog Web UI**: Open [http://localhost:8025](http://localhost:8025) to view tagged/accepted emails and injected security headers.

---

## Running Tests

Run the full automated test suite with pytest:

```bash
pytest -v
```

Output:
```
============================= test session starts =============================
tests/test_auth.py::test_auth_validator_spf_logic PASSED                 [  5%]
tests/test_auth.py::test_auth_validator_dmarc_alignment_strict_relaxed PASSED [ 11%]
tests/test_auth.py::test_auth_validator_scoring PASSED                   [ 16%]
tests/test_engine.py::test_scan_clean_email PASSED                       [ 22%]
tests/test_engine.py::test_scan_vip_spoofing PASSED                      [ 27%]
tests/test_engine.py::test_scan_attachment_threat PASSED                 [ 33%]
tests/test_engine.py::test_persistence_audit_log PASSED                  [ 38%]
tests/test_heuristics.py::test_levenshtein_distance PASSED               [ 44%]
tests/test_heuristics.py::test_normalize_homoglyphs PASSED               [ 50%]
tests/test_heuristics.py::test_heuristic_urgency_detection PASSED        [ 55%]
tests/test_heuristics.py::test_heuristic_display_name_spoofing PASSED    [ 61%]
tests/test_heuristics.py::test_heuristic_lookalike_domain PASSED         [ 66%]
tests/test_proxy.py::test_proxy_clean_email_acceptance PASSED            [ 72%]
tests/test_proxy.py::test_proxy_high_risk_smtp_rejection PASSED          [ 77%]
tests/test_scanners.py::test_mime_parser_basic_text PASSED               [ 83%]
tests/test_scanners.py::test_mime_parser_html_and_attachments PASSED     [ 88%]
tests/test_scanners.py::test_url_scanner_patterns_and_caching PASSED     [ 94%]
tests/test_scanners.py::test_attachment_scanner_dangerous_extension PASSED [100%]
======================= 18 passed in 4.69s ========================
```

---

## Production Deployment & DNS Documentation

For complete step-by-step production guides:

- [DNS & MX Prerequisites Guide](docs/DNS_MX_PREREQUISITES.md) — MX, SPF `include:`, DKIM key generation, and DMARC policies.
- [Postfix Gateway & Systemd Deployment](docs/POSTFIX_DEPLOYMENT.md) — Production `main.cf`, `master.cf`, transport tables, and systemd service setup.

---

## Configuration Reference (`config/config.yaml.example`)

```yaml
server:
  mode: "proxy"             # "proxy" (aiosmtpd) or "milter" (pymilter)
  host: "0.0.0.0"
  port: 10025
  milter_socket: "inet:127.0.0.1:8899"
  downstream_host: "127.0.0.1"
  downstream_port: 1025

database:
  url: "sqlite:///netsecurex.db"

decision_engine:
  medium_risk_threshold: 30
  high_risk_threshold: 70
  high_risk_action: "quarantine"    # "reject" (550 SMTP code) or "quarantine"
  medium_risk_action: "tag"
  subject_tag_prefix: "[SUSPECTED PHISHING]"
  quarantine_recipient: "quarantine@security.local"

api_keys:
  google_safe_browsing: ""          # Optional API key for Google Safe Browsing v4
  virustotal: ""                    # Optional API key for VirusTotal v3

performance:
  api_timeout_seconds: 2.5
  cache_ttl_seconds: 86400

heuristics:
  protected_vip_names:
    - "CEO"
    - "Chief Executive Officer"
    - "Finance Director"
  protected_domains:
    - "company.com"
```

---

## License

This project is licensed under the MIT License.
