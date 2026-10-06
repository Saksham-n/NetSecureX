import os
import pytest
from netsecurex.config import AppConfig
from netsecurex.db.storage import DatabaseStorage
from netsecurex.scanners.engine import ScanEngine
from scripts.test_vectors import (
    make_clean_email,
    make_urgency_email,
    make_vip_spoof_email,
    make_lookalike_email,
    make_attachment_threat_email,
)


@pytest.fixture
def test_engine(tmp_path):
    db_file = tmp_path / "test_netsecurex.db"
    config = AppConfig()
    config.database.url = f"sqlite:///{db_file}"
    config.heuristics.protected_domains = ["company.com"]
    config.heuristics.protected_vip_names = ["CEO", "Chief Executive Officer"]
    config.decision_engine.medium_risk_threshold = 25
    config.decision_engine.high_risk_threshold = 65

    storage = DatabaseStorage(db_url=config.database.url)
    engine = ScanEngine(config=config, storage=storage)
    return engine


def test_scan_clean_email(test_engine):
    msg = make_clean_email()
    decision = test_engine.scan_message(
        client_ip="127.0.0.1",
        envelope_from="alice@company.com",
        envelope_rcpt="bob@company.com",
        helo_name="mail.company.com",
        raw_message_bytes=msg.as_bytes(),
    )

    assert decision.risk_level == "LOW"
    assert decision.action == "ALLOW"
    assert decision.total_score < 25


def test_scan_vip_spoofing(test_engine):
    msg = make_vip_spoof_email()
    decision = test_engine.scan_message(
        client_ip="198.51.100.25",
        envelope_from="external-scammer@gmail.com",
        envelope_rcpt="finance@company.com",
        helo_name="smtp.gmail.com",
        raw_message_bytes=msg.as_bytes(),
    )

    assert decision.total_score >= 25
    assert decision.risk_level in ["MEDIUM", "HIGH"]
    assert any("Display Name Spoofing" in r or "VIP" in r for r in decision.reasons)


def test_scan_attachment_threat(test_engine):
    msg = make_attachment_threat_email()
    decision = test_engine.scan_message(
        client_ip="198.51.100.50",
        envelope_from="billing@external-drop.org",
        envelope_rcpt="ap@company.com",
        helo_name="drop.org",
        raw_message_bytes=msg.as_bytes(),
    )

    assert decision.total_score >= 25
    assert any("attachment" in r.lower() or "extension" in r.lower() for r in decision.reasons)


def test_persistence_audit_log(test_engine):
    msg = make_urgency_email()
    decision = test_engine.scan_message(
        client_ip="192.0.2.1",
        envelope_from="billing@vendor-notice.net",
        envelope_rcpt="accounting@company.com",
        helo_name="vendor-notice.net",
        raw_message_bytes=msg.as_bytes(),
    )

    logs = test_engine.storage.get_recent_scans(limit=10)
    assert len(logs) >= 1
    latest = logs[0]
    assert latest.sender == "billing@vendor-notice.net"
    assert latest.recipient == "accounting@company.com"
    assert latest.total_score == decision.total_score
