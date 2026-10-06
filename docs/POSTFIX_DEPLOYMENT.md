# Postfix Gateway & Milter Deployment Guide

This guide walks through configuring Postfix on Linux (Ubuntu, Debian, RHEL) to route in-transit email through the **NetSecureX Scanning Engine** via the Milter protocol or Transparent SMTP Proxy.

---

## Architecture Overview

```
                        INCOMING INTERNET TRAFFIC
                                    │
                                    ▼
                         [ Postfix Gateway (Port 25) ]
                                    │
                  ┌─────────────────┴─────────────────┐
                  ▼                                   ▼
          (CONNECT / HELO / MAIL)             (DATA / EOM)
                  │                                   │
                  └──────────────► [ NetSecureX ] ◄───┘
                                   • SPF / DKIM / DMARC
                                   • Safe Browsing URLs
                                   • VirusTotal Hashes
                                   • Heuristics & Spoofing
                                          │
                  ┌───────────────────────┼───────────────────────┐
                  ▼                       ▼                       ▼
            [ HIGH RISK ]           [ MEDIUM RISK ]          [ LOW RISK ]
            550 Reject or           Tag Subject line &       Clean Pass-Through
            Divert Quarantine       Inject Scan Headers      with Audit Headers
                  │                       │                       │
                  └───────────────────────┴───────────────────────┘
                                          │
                                          ▼
                             [ Internal Mailbox / Exchange ]
```

---

## 1. System Requirements & Package Installation

```bash
# Ubuntu / Debian
sudo apt-get update
sudo apt-get install -y postfix postfix-pcre libmilter-dev python3 python3-pip python3-venv

# RHEL / Rocky Linux
sudo dnf install -y postfix sendmail-milter sendmail-milter-devel python3 python3-pip
```

---

## 2. Deploying NetSecureX Scanner

### 2.1 Create Dedicated Service User
```bash
sudo useradd -r -s /bin/false -d /var/lib/netsecurex netsecurex
sudo mkdir -p /opt/netsecurex /var/log/netsecurex /var/lib/netsecurex /etc/netsecurex
sudo chown -R netsecurex:netsecurex /var/log/netsecurex /var/lib/netsecurex /etc/netsecurex
```

### 2.2 Clone Codebase & Install Python Environment
```bash
sudo git clone https://github.com/netsecurex/netsecurex.git /opt/netsecurex
cd /opt/netsecurex
sudo python3 -m venv .venv
sudo .venv/bin/pip install --upgrade pip
sudo .venv/bin/pip install -r requirements.txt pymilter

# Configure permissions
sudo chown -R netsecurex:netsecurex /opt/netsecurex
```

### 2.3 Configuration Setup
Copy the configuration template:
```bash
sudo cp /opt/netsecurex/config/config.yaml.example /etc/netsecurex/config.yaml
sudo chmod 640 /etc/netsecurex/config.yaml
sudo chown netsecurex:netsecurex /etc/netsecurex/config.yaml
```

Set your API keys and protected domains in `/etc/netsecurex/config.yaml`:
```yaml
server:
  mode: "milter"
  milter_socket: "inet:127.0.0.1:8899"

database:
  url: "sqlite:////var/lib/netsecurex/netsecurex.db"

decision_engine:
  medium_risk_threshold: 30
  high_risk_threshold: 70
  high_risk_action: "quarantine"
  quarantine_recipient: "quarantine@yourdomain.com"

api_keys:
  google_safe_browsing: "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"
  virustotal: "YOUR_VIRUSTOTAL_API_KEY"

heuristics:
  protected_domains:
    - "yourdomain.com"
```

---

## 3. Postfix Milter Integration

### 3.1 Edit `/etc/postfix/main.cf`
Append the milter hooks to your Postfix configuration:

```ini
# NetSecureX In-Transit Milter Hook
smtpd_milters = inet:127.0.0.1:8899
non_smtpd_milters = inet:127.0.0.1:8899
milter_default_action = accept
milter_connect_macros = j {daemon_name} v {client_ptr} _
milter_command_timeout = 30s
milter_content_timeout = 60s
```

### 3.2 Configure Relay Routing in `/etc/postfix/transport`
Map your corporate domains to internal Exchange / Dovecot mailboxes:
```ini
yourdomain.com    smtp:[mail-internal.yourdomain.com]:25
*                 smtp:[downstream-relay.internal]:25
```
Compile the transport database:
```bash
sudo postmap /etc/postfix/transport
sudo systemctl reload postfix
```

---

## 4. Systemd Service Activation

Install and enable the NetSecureX systemd unit:
```bash
sudo cp /opt/netsecurex/config/systemd/netsecurex.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netsecurex.service
```

Verify service status:
```bash
sudo systemctl status netsecurex.service
sudo journalctl -u netsecurex.service -f
```

---

## 5. Operations & Diagnostics

### Check Mail Queue
```bash
mailq
# or
postqueue -p
```

### Flush Mail Queue
```bash
sudo postqueue -f
```

### Live Postfix + NetSecureX Log Monitoring
```bash
sudo tail -f /var/log/mail.log | grep -E "(postfix|netsecurex)"
```
