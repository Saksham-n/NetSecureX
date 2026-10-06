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

from flask import Flask, render_template, jsonify, request

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
