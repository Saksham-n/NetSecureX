# DNS & MX Prerequisites Guide for NetSecureX Gateway

When deploying NetSecureX as an intermediary scanning mail gateway, specific DNS records must be established for the domain to ensure valid inbound routing, outbound reputation, and strict cryptographic authentication (SPF, DKIM, DMARC).

---

## 1. Mail Exchange (MX) Records

All public Internet MTAs query the `MX` records of the recipient domain to identify the destination mail servers. When NetSecureX acts as the frontline gateway, your primary MX record must resolve to the public IP address of the NetSecureX server.

### Example Configuration:
| Record Type | Host / Name | Priority | Value / Destination | TTL |
| :--- | :--- | :--- | :--- | :--- |
| **A** | `gateway.yourdomain.com` | — | `203.0.113.10` (Public IP) | 3600 |
| **MX** | `@` (or `yourdomain.com`) | `10` | `gateway.yourdomain.com` | 3600 |
| **MX** | `@` (or `yourdomain.com`) | `20` | `backup-gateway.yourdomain.com` | 3600 |

> **Note:** Lower numerical priority indicates higher preference. The gateway receives all initial connections.

---

## 2. Sender Policy Framework (SPF)

The SPF record (`TXT` record at apex domain) designates which IP addresses and servers are authorized to send email on behalf of your domain. 

If NetSecureX **also relays outbound emails** or generates system notifications / quarantine alerts, its outbound public IP address **must be included** in the SPF record.

### SPF Record Syntax:
```dns
yourdomain.com.  IN  TXT  "v=spf1 ip4:203.0.113.10 include:_spf.google.com ~all"
```

### Breakdown of SPF Directives:
- `v=spf1`: Declares the SPF version.
- `ip4:203.0.113.10`: Explicitly authorizes the NetSecureX gateway IP.
- `include:_spf.google.com`: Authorizes secondary relays (e.g. Google Workspace or Office 365).
- `~all` (Softfail) or `-all` (Hardfail): Dictates how receiving MTAs treat unauthorized IP senders.

---

## 3. DomainKeys Identified Mail (DKIM)

DKIM attaches a cryptographic signature to outbound messages via the `DKIM-Signature` header. Receiving servers verify this signature against a public key published in DNS under a specific selector subdomain: `<selector>._domainkey.yourdomain.com`.

### 3.1 Generating 2048-bit Key Pair (OpenDKIM / OpenSSL)
```bash
# Generate private RSA key
openssl genrsa -out /etc/netsecurex/dkim/mail.private 2048

# Extract DNS public key
openssl rsa -in /etc/netsecurex/dkim/mail.private -pubout -outform PEM -out /etc/netsecurex/dkim/mail.public

# Set strict permissions
chmod 600 /etc/netsecurex/dkim/mail.private
chown -R netsecurex:postfix /etc/netsecurex/dkim/
```

### 3.2 Publishing the DKIM DNS TXT Record
| Record Type | Name / Subdomain | Value |
| :--- | :--- | :--- |
| **TXT** | `mail._domainkey.yourdomain.com` | `v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...` |

> Replace `MIIBIjAN...` with the base64 public key extracted from `mail.public` (without the `-----BEGIN PUBLIC KEY-----` lines).

---

## 4. Domain-based Message Authentication, Reporting & Conformance (DMARC)

DMARC leverages both SPF and DKIM to protect your domain against spoofing and phishing. It specifies how receivers should handle unauthenticated emails claiming to originate from your domain and where to send telemetry reports.

### DMARC DNS TXT Record:
| Record Type | Name / Host | Value |
| :--- | :--- | :--- |
| **TXT** | `_dmarc.yourdomain.com` | `v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:dmarc-aggregate@yourdomain.com; ruf=mailto:dmarc-forensics@yourdomain.com; aspf=r; adkim=r` |

### Key DMARC Parameters:
- `p=reject`: Instructs destination MTAs to reject unaligned emails immediately.
- `p=quarantine`: Instructs destination MTAs to route unaligned emails to spam/quarantine.
- `rua=mailto:...`: Aggregate reporting destination for daily authentication statistics.
- `ruf=mailto:...`: Real-time forensic failure reports.
- `aspf=r` & `adkim=r`: Relaxed alignment mode (allows organizational domain subdomains to align).

---

## 5. Reverse DNS (rDNS / PTR Record)

For outbound reputation and deliverability, the public IP address of your gateway **must** have a valid Pointer (PTR) record configured with your ISP or Cloud provider matching your MTA hostname:

```dns
203.0.113.10 -> gateway.yourdomain.com
```

---

## Verification Commands

Validate your published records from any terminal:
```bash
# 1. Verify MX records
dig MX yourdomain.com +short

# 2. Verify SPF record
dig TXT yourdomain.com +short

# 3. Verify DKIM record
dig TXT mail._domainkey.yourdomain.com +short

# 4. Verify DMARC record
dig TXT _dmarc.yourdomain.com +short

# 5. Verify Reverse DNS (PTR)
dig -x 203.0.113.10 +short
```
