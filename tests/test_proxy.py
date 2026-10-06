import asyncio
import smtplib
import socket
import time
import pytest
from netsecurex.config import AppConfig
from netsecurex.db.storage import DatabaseStorage
from netsecurex.proxy.smtp_proxy import create_smtp_proxy_controller
from netsecurex.scanners.engine import ScanEngine
from scripts.test_vectors import make_clean_email, make_vip_spoof_email, make_attachment_threat_email


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def running_proxy_server(tmp_path):
    proxy_port = get_free_port()
    db_file = tmp_path / "proxy_test.db"

    config = AppConfig()
    config.server.host = "127.0.0.1"
    config.server.port = proxy_port
    config.server.downstream_host = "127.0.0.1"
    config.server.downstream_port = 65534  # Non-existent port to test mock downstream resilience
    config.database.url = f"sqlite:///{db_file}"
    config.heuristics.protected_vip_names = ["CEO"]
    config.heuristics.protected_domains = ["company.com"]
    config.decision_engine.medium_risk_threshold = 20
    config.decision_engine.high_risk_threshold = 35
    config.decision_engine.high_risk_action = "reject"

    storage = DatabaseStorage(db_url=config.database.url)
    engine = ScanEngine(config=config, storage=storage)

    controller = create_smtp_proxy_controller(engine=engine, config=config)
    controller.start()
    time.sleep(0.3)

    yield {
        "host": "127.0.0.1",
        "port": proxy_port,
        "engine": engine,
        "storage": storage,
    }

    controller.stop()


def test_proxy_clean_email_acceptance(running_proxy_server):
    host = running_proxy_server["host"]
    port = running_proxy_server["port"]
    storage = running_proxy_server["storage"]

    msg = make_clean_email()

    with smtplib.SMTP(host=host, port=port, timeout=5.0) as client:
        client.ehlo("tester.local")
        refused = client.sendmail(
            from_addr="alice@company.com",
            to_addrs=["bob@company.com"],
            msg=msg.as_bytes(),
        )
        assert refused == {}

    logs = storage.get_recent_scans(limit=1)
    assert len(logs) == 1
    assert logs[0].action_taken == "ALLOW"
    assert logs[0].risk_level == "LOW"


def test_proxy_high_risk_smtp_rejection(running_proxy_server):
    host = running_proxy_server["host"]
    port = running_proxy_server["port"]
    storage = running_proxy_server["storage"]

    # Spoofed VIP email with dangerous attachment
    msg = make_attachment_threat_email()

    with smtplib.SMTP(host=host, port=port, timeout=5.0) as client:
        client.ehlo("tester.local")
        with pytest.raises(smtplib.SMTPResponseException) as exc_info:
            client.sendmail(
                from_addr="billing@external-drop.org",
                to_addrs=["finance@company.com"],
                msg=msg.as_bytes(),
            )
        assert exc_info.value.smtp_code == 550
        assert b"5.7.1" in exc_info.value.smtp_error

    logs = storage.get_recent_scans(limit=1)
    assert len(logs) == 1
    assert logs[0].action_taken == "REJECT"
    assert logs[0].risk_level == "HIGH"
