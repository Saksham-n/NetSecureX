# NetSecureX — Academic Project Report & Viva Guide

**Project Title:** In-Transit MTA Email Threat Interception & Anti-Phishing Gateway  
**Domain:** Network Security / Cybersecurity & Applied Cryptography  
**Technology Stack:** Python 3, SMTP / Milter Protocol (`aiosmtpd`), Cryptographic Verification (`pyspf`, `dkimpy`, `dnspython`), Threat Feeds (Google Safe Browsing, VirusTotal), SQLite, Flask.

---

## 1. Abstract

Email remains the primary initial attack vector for enterprise breaches, ransomware deployments, and Business Email Compromise (BEC) attacks. Conventional email filters operate at the endpoint (e.g., client plugins or mailbox post-delivery sorting), which introduces latency and allows malicious messages into users' local stores.

**NetSecureX** is a network-level Mail Transfer Agent (MTA) scanning gateway. Operating between the public Internet and internal mailbox servers, it intercepts SMTP traffic in real time during the `HELO`, `MAIL FROM`, `RCPT TO`, and `DATA` transaction phases. It enforces sender authentication (SPF, DKIM, DMARC), inspects URLs and attachments against threat intelligence feeds, evaluates social engineering heuristics (display-name spoofing and lookalike domains), and dynamically issues **550 SMTP-level rejections**, **quarantine diversions**, or **subject-line tagging** prior to final delivery.

---

## 2. Block Diagram (For Presentation & Slides)

```
                       [ INCOMING EMAIL (INTERNET) ]
                                    │
                                    ▼
                 ┌──────────────────────────────────────┐
                 │    NetSecureX SMTP Gateway (10025)   │
                 └──────────────────┬───────────────────┘
                                    │
    ┌───────────────────────────────┴───────────────────────────────┐
    │                     IN-TRANSIT INSPECTION                     │
    │                                                               │
    │  1. Protocol Authentication (SPF + DKIM + DMARC Alignment)    │
    │  2. URL Threat Scanner (Google Safe Browsing + Patterns)      │
    │  3. Attachment Threat Scanner (SHA-256 + VirusTotal AV)       │
    │  4. Threat Heuristics (CEO Spoofing, Urgency, Lookalikes)     │
    └───────────────────────────────┬───────────────────────────────┘
                                    │
                                    ▼
                 ┌──────────────────────────────────────┐
                 │     Multi-Vector Decision Engine     │
                 │      (Calculates Score: 0 - 100)     │
                 └──────────────────┬───────────────────┘
                                    │
           ┌────────────────────────┼────────────────────────┐
           ▼                        ▼                        ▼
     [ HIGH RISK ]           [ MEDIUM RISK ]           [ LOW RISK ]
     Score >= 70             30 <= Score < 70          Score < 30
           │                        │                        │
     550 SMTP Reject         Prepend Tag:             Deliver Cleanly
   or Quarantine Divert   "[SUSPECTED PHISHING]"     with Audit Headers
           │                        │                        │
           └────────────────────────┴────────────────────────┘
                                    │
                                    ▼
                 ┌──────────────────────────────────────┐
                 │     SQLite Audit Trail & Logging     │
                 └──────────────────┬───────────────────┘
                                    │
                                    ▼
                 ┌──────────────────────────────────────┐
                 │   Live Web Dashboard (Port 5000)     │
                 └──────────────────────────────────────┘
```

---

## 3. Key Modules Explained

| Module | File | Purpose |
| :--- | :--- | :--- |
| **Gateway Proxy** | `netsecurex/proxy/smtp_proxy.py` | Intercepts SMTP commands (`aiosmtpd`), runs scanning hooks, and modifies or rejects packets in transit. |
| **Auth Validator** | `netsecurex/scanners/auth_validator.py` | Verifies SPF IP authorization, verifies DKIM cryptographic signatures, and validates DMARC alignment. |
| **URL Scanner** | `netsecurex/scanners/url_scanner.py` | Extracts URLs, detects raw IP hosts/excessive subdomains, and queries Google Safe Browsing API. |
| **Attachment Scanner** | `netsecurex/scanners/attachment_scanner.py` | Computes SHA-256 hashes, detects double extensions (`.pdf.exe`), and checks VirusTotal detections. |
| **Heuristics** | `netsecurex/scanners/heuristics.py` | Detects VIP/CEO display name spoofing, urgency/coercion language, and Levenshtein lookalike domains (`c0mpany.com`). |
| **Decision Engine** | `netsecurex/scanners/engine.py` | Aggregates all scores into a unified 0–100 risk score and triggers the appropriate routing policy. |
| **Audit Storage** | `netsecurex/db/storage.py` | Logs every transaction to SQLite with timestamp and threat findings. |
| **Live Web App** | `app.py` | Turnkey single-file launcher providing a real-time web dashboard for project demonstration. |

---

## 4. Experimental Demonstration & Test Vectors

| Test Scenario | Attack Technique | Gateway Response | Final Action |
| :--- | :--- | :--- | :--- |
| **1. Clean Email** | Normal sprint planning communication | Score: 0.0 | 🟢 **ALLOW** (Delivered cleanly) |
| **2. Urgency Extortion** | Overdue invoice, cryptocurrency demand | Score: 35.0 | 🟡 **TAG** (Subject modified to `[SUSPECTED PHISHING]`) |
| **3. VIP CEO Spoofing** | Display Name `"CEO <ceo@company.com>"` from external Gmail | Score: 80.5 | 🔴 **QUARANTINE / 550 REJECT** |
| **4. Malware Attachment** | Double extension executable `invoice.pdf.exe` | Score: 75.0 | 🔴 **QUARANTINE / 550 REJECT** |
| **5. Typosquatted Domain** | Link to `c0mpany.com` (1 edit distance from `company.com`) | Score: 50.0 | 🟡 **TAG** (Audit header added) |

---

## 5. Top 10 Viva / Oral Examination Questions & Answers

### Q1: What is an MTA and why perform email scanning at the MTA layer?
**Answer:** A Mail Transfer Agent (MTA) is software that routes and transfers emails across networks using the SMTP protocol. Scanning at the MTA layer intercepts threats *in transit* before they reach users' inboxes, preventing user error, credential harvesting, and zero-day execution without relying on client-side plugins.

### Q2: What is the difference between SPF, DKIM, and DMARC?
**Answer:**
- **SPF (Sender Policy Framework):** DNS record listing which server IP addresses are allowed to send mail for a domain.
- **DKIM (DomainKeys Identified Mail):** Uses public-key cryptography to digitally sign message headers and body, ensuring message integrity and proving sender identity.
- **DMARC (Domain-based Message Authentication):** Enforces alignment between the visible `From:` header domain and SPF/DKIM domains, defining policies (`reject`, `quarantine`, `none`) for unaligned emails.

### Q3: What is a Milter?
**Answer:** A Milter (Mail Filter) is a standard API originally developed by Sendmail and adopted by Postfix (`smtpd_milters`) that allows third-party programs to inspect and modify emails during the live SMTP transaction lifecycle.

### Q4: How does NetSecureX detect Display Name Spoofing?
**Answer:** Attackers often use friendly display names like `"CEO John Doe <ceo@company.com>"` while sending from an unrelated freemail address like `attacker@gmail.com`. NetSecureX extracts both parts, compares the display name against protected VIP keywords and corporate domain names, and flags the mismatch as high risk.

### Q5: How does the Lookalike / Typosquatting detection work?
**Answer:** It uses the **Levenshtein edit-distance algorithm** and **Homoglyph character substitution** (e.g., mapping Cyrillic characters or numeric `0`/`1` to Latin `o`/`l`) to detect lookalike domains like `c0mpany.com` mimicking protected corporate domains (`company.com`).

### Q6: How does NetSecureX handle external API timeouts?
**Answer:** It uses non-blocking asynchronous requests with strict timeout limits (default 2.5s) and thread-safe in-memory caching (TTL 24h). If an external API (like VirusTotal) times out, the scanner fails gracefully with a warning flag rather than blocking email delivery indefinitely.

### Q7: What is the meaning of SMTP error code 550?
**Answer:** `550` is a permanent SMTP error code indicating that the requested action was not taken because the mailbox is unavailable or the message was rejected due to security policy violations (e.g., `550 5.7.1 Security threat detected`).

### Q8: What database is used for auditing?
**Answer:** It uses SQLite (or PostgreSQL) via SQLAlchemy ORM to persist every transaction ID, sender, recipient, SPF/DKIM status, threat score, action taken, and latency in milliseconds.

### Q9: Can this system be deployed on Windows and Linux?
**Answer:** Yes. On Linux, it supports both native Postfix Milter (`pymilter`) and the async SMTP Proxy (`aiosmtpd`). On Windows or macOS development environments, it runs seamlessly via the async SMTP Proxy.

### Q10: How do you demonstrate this project in a lab without real DNS changes?
**Answer:** NetSecureX provides a standalone launcher (`python app.py`) that binds a local SMTP gateway on port `10025` and an interactive web dashboard on port `5000`. You can inject pre-built attack vectors with 1-click buttons or test custom emails directly from the browser.
