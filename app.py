"""
NetSecureX — Turnkey College Project & Lab Demo Runner.
Starts the MTA Scanning Gateway (port 10025) and Interactive Live Dashboard (port 5000) in 1 command!
"""

from __future__ import annotations

import email.utils
from email.message import EmailMessage
import logging
import smtplib
import threading
from typing import Dict, Any

from flask import Flask, render_template, jsonify, request, make_response

from netsecurex.config import load_config
from netsecurex.db.storage import DatabaseStorage
from netsecurex.proxy.smtp_proxy import create_smtp_proxy_controller
from netsecurex.scanners.engine import ScanEngine
from scripts.test_vectors import (
    make_clean_email,
    make_urgency_email,
    make_vip_spoof_email,
    make_lookalike_email,
    make_attachment_threat_email,
)

# Initialize Flask app
app = Flask(__name__, template_folder="web/templates")
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")
logger = logging.getLogger("netsecurex.app")

# Shared Engine & Storage instances
config = load_config()
config.server.host = "127.0.0.1"
config.server.port = 10025
config.database.url = "sqlite:///netsecurex.db"
config.heuristics.protected_domains = ["company.com", "corp.internal"]
config.heuristics.protected_vip_names = ["CEO", "Chief Executive Officer", "Finance Director", "Payroll Dept"]

storage = DatabaseStorage(db_url=config.database.url)
engine = ScanEngine(config=config, storage=storage)


@app.route("/")
def index():
    """Serves the main interactive dashboard."""
    return render_template("index.html")


@app.route("/api/logs", methods=["GET"])
def api_get_logs():
    """Returns the latest scan logs and aggregated threat metrics."""
    logs = storage.get_recent_scans(limit=30)
    
    logs_data = []
    total = len(logs)
    allow_cnt = 0
    tagged_cnt = 0
    blocked_cnt = 0

    for l in logs:
        if l.action_taken == "ALLOW":
            allow_cnt += 1
        elif l.action_taken == "TAG":
            tagged_cnt += 1
        elif l.action_taken in ("REJECT", "QUARANTINE"):
            blocked_cnt += 1

        logs_data.append({
            "id": l.id,
            "sender": l.sender,
            "recipient": l.recipient,
            "subject": l.subject,
            "spf_status": l.spf_status,
            "dkim_status": l.dkim_status,
            "dmarc_status": l.dmarc_status,
            "total_score": l.total_score,
            "risk_level": l.risk_level,
            "action_taken": l.action_taken,
            "summary_report": l.summary_report,
            "duration_ms": round(l.processing_time_ms, 2),
            "created_at": l.created_at.strftime("%H:%M:%S") if l.created_at else "",
        })

    return jsonify({
        "logs": logs_data,
        "stats": {
            "total": total,
            "allow": allow_cnt,
            "tagged": tagged_cnt,
            "blocked": blocked_cnt,
        }
    })


@app.route("/api/simulate", methods=["POST"])
def api_simulate_attack():
    """Injects a chosen test attack vector through the live MTA gateway port."""
    data = request.get_json() or {}
    vector = data.get("vector", "clean")

    generators = {
        "clean": (make_clean_email, "alice@company.com", "bob@company.com"),
        "urgency": (make_urgency_email, "billing@vendor-notice.net", "accounting@company.com"),
        "vip_spoof": (make_vip_spoof_email, "external-scammer@gmail.com", "finance@company.com"),
        "lookalike": (make_lookalike_email, "support@c0mpany.com", "victim@company.com"),
        "attachment": (make_attachment_threat_email, "billing@external-drop.org", "ap@company.com"),
    }

    if vector not in generators:
        return jsonify({"error": "Unknown vector"}), 400

    gen_func, mail_from, rcpt_to = generators[vector]
    msg = gen_func()

    result_status = _send_smtp(mail_from, rcpt_to, msg.as_bytes())
    return jsonify({"status": "ok", "vector": vector, "smtp_result": result_status})


@app.route("/api/send_custom", methods=["POST"])
def api_send_custom():
    """Injects a custom user-crafted email through the live MTA gateway."""
    data = request.get_json() or {}
    mail_from = data.get("mail_from", "test@external.com")
    mail_to = data.get("mail_to", "user@company.com")
    header_from = data.get("header_from", mail_from)
    subject = data.get("subject", "Test Email")
    body = data.get("body", "Test body")

    msg = EmailMessage()
    msg["Message-ID"] = email.utils.make_msgid(domain="external.com")
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["From"] = header_from
    msg["To"] = mail_to
    msg["Subject"] = subject
    msg.set_content(body)

    result_status = _send_smtp(mail_from, mail_to, msg.as_bytes())
    return jsonify({"status": "ok", "smtp_result": result_status})


def _cors_response(data: dict, status: int = 200):
    """Wraps jsonify response with CORS headers for the browser extension."""
    resp = make_response(jsonify(data), status)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


@app.route("/api/scan_url", methods=["POST", "OPTIONS"])
def api_scan_url():
    """Extension endpoint: scans a single URL via Safe Browsing + heuristics."""
    if request.method == "OPTIONS":
        return _cors_response({})

    data = request.get_json() or {}
    url = data.get("url", "").strip()
    if not url:
        return _cors_response({"error": "No URL provided"}, 400)

    try:
        results = engine.url_scanner.scan_urls([url])
        if results:
            r = results[0]
            risk = "HIGH" if r.is_malicious else ("MEDIUM" if r.suspicious_patterns else "LOW")
            return _cors_response({
                "url": r.url,
                "domain": r.domain,
                "is_malicious": r.is_malicious,
                "threat_type": r.threat_type,
                "suspicious_patterns": r.suspicious_patterns,
                "details": r.details,
                "source": r.source,
                "cached": r.cached,
                "risk_level": risk,
            })
        return _cors_response({"url": url, "is_malicious": False, "risk_level": "LOW", "details": "No result"})
    except Exception as ex:
        logger.error(f"Extension URL scan error: {ex}")
        return _cors_response({"error": str(ex)}, 500)


@app.route("/api/scan_email", methods=["POST", "OPTIONS"])
def api_scan_email():
    """Extension endpoint: heuristic-only analysis of pasted email fields."""
    if request.method == "OPTIONS":
        return _cors_response({})

    data = request.get_json() or {}
    display_name    = data.get("display_name", "")
    from_address    = data.get("from_address", "")
    from_domain     = from_address.split("@")[-1].lower().strip() if "@" in from_address else ""
    reply_to        = data.get("reply_to", "")
    subject         = data.get("subject", "")
    body_text       = data.get("body", "")
    extracted_urls  = data.get("urls", [])

    # Heuristic analysis
    try:
        from urllib.parse import urlparse
        extracted_domains = []
        for u in extracted_urls:
            try:
                d = urlparse(u).netloc.split(":")[0].lower()
                if d:
                    extracted_domains.append(d)
            except Exception:
                pass

        heuristic_res = engine.heuristic_scanner.analyze(
            display_name=display_name,
            from_address=from_address,
            from_domain=from_domain,
            reply_to_address=reply_to,
            subject=subject,
            body_text=body_text,
            extracted_domains=extracted_domains,
        )

        # URL scan if any URLs were provided
        url_results = []
        if extracted_urls:
            for scan_res in engine.url_scanner.scan_urls(extracted_urls[:20]):
                url_results.append({
                    "url": scan_res.url,
                    "domain": scan_res.domain,
                    "is_malicious": scan_res.is_malicious,
                    "threat_type": scan_res.threat_type,
                    "suspicious_patterns": scan_res.suspicious_patterns,
                    "risk": "HIGH" if scan_res.is_malicious else ("MEDIUM" if scan_res.suspicious_patterns else "LOW"),
                })

        # Compute composite score
        score = min(heuristic_res.total_heuristic_score, 100.0)
        has_malicious_url = any(u["is_malicious"] for u in url_results)
        has_suspicious_url = any(u["suspicious_patterns"] for u in url_results)

        if has_malicious_url:
            score = min(score + 80.0, 100.0)
        elif has_suspicious_url:
            score = min(score + 20.0, 100.0)

        if score >= 70:
            risk_level = "HIGH"
        elif score >= 30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return _cors_response({
            "risk_level": risk_level,
            "total_score": round(score, 1),
            "urgency_detected": heuristic_res.urgency_detected,
            "urgency_matches": heuristic_res.urgency_matches,
            "display_name_spoofed": heuristic_res.display_name_spoofed,
            "display_name_reason": heuristic_res.display_name_reason,
            "lookalike_detected": heuristic_res.lookalike_detected,
            "lookalike_matches": heuristic_res.lookalike_matches,
            "reasons": heuristic_res.reasons,
            "url_results": url_results,
        })
    except Exception as ex:
        logger.error(f"Extension email scan error: {ex}")
        return _cors_response({"error": str(ex)}, 500)



def _send_smtp(mail_from: str, rcpt_to: str, raw_bytes: bytes) -> str:
    """Helper to transmit email via local SMTP gateway."""
    try:
        with smtplib.SMTP(host="127.0.0.1", port=10025, timeout=5.0) as client:
            client.ehlo("demo-client.local")
            client.sendmail(
                from_addr=mail_from,
                to_addrs=[rcpt_to],
                msg=raw_bytes,
            )
        return "Accepted by Gateway (250 OK)"
    except smtplib.SMTPResponseException as e:
        return f"SMTP Blocked ({e.smtp_code}): {e.smtp_error.decode('utf-8', errors='replace')}"
    except Exception as ex:
        return f"Processed: {ex}"


def start_smtp_gateway_controller():
    """Starts the MTA proxy listener on port 10025."""
    controller = create_smtp_proxy_controller(engine=engine, config=config)
    controller.start()
    logger.info("=" * 65)
    logger.info(" [1/2] NetSecureX MTA Gateway listening on 127.0.0.1:10025")
    logger.info(" [2/2] Web Demo Dashboard starting on http://127.0.0.1:5000")
    logger.info("=" * 65)
    return controller


if __name__ == "__main__":
    # Start SMTP Gateway in background thread controller
    smtp_ctrl = start_smtp_gateway_controller()
    try:
        # Start Flask Dashboard
        app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
    finally:
        logger.info("Stopping SMTP Controller...")
        smtp_ctrl.stop()
