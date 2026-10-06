"""
Configuration loader for NetSecureX Gateway Scanner.
Loads YAML configuration files with sane defaults and environment variable overrides.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml


@dataclass
class ServerConfig:
    mode: str = "proxy"  # "proxy" or "milter"
    host: str = "0.0.0.0"
    port: int = 10025
    milter_socket: str = "inet:8899@127.0.0.1"
    downstream_host: str = "127.0.0.1"
    downstream_port: int = 1025
    max_message_size_bytes: int = 25 * 1024 * 1024  # 25 MB


@dataclass
class DatabaseConfig:
    url: str = "sqlite:///netsecurex.db"
    echo: bool = False


@dataclass
class DecisionEngineConfig:
    medium_risk_threshold: int = 30
    high_risk_threshold: int = 70
    high_risk_action: str = "quarantine"  # "reject" or "quarantine"
    medium_risk_action: str = "tag"
    subject_tag_prefix: str = "[SUSPECTED PHISHING]"
    quarantine_recipient: str = "quarantine@security.local"


@dataclass
class ApiKeysConfig:
    google_safe_browsing: str = ""
    virustotal: str = ""


@dataclass
class PerformanceConfig:
    api_timeout_seconds: float = 2.5
    cache_ttl_seconds: int = 86400
    cache_max_entries: int = 10000


@dataclass
class HeuristicsConfig:
    protected_vip_names: List[str] = field(default_factory=lambda: [
        "CEO", "Chief Executive Officer", "Finance Director", 
        "Payroll Dept", "HR Department", "IT Helpdesk", "Security Administrator"
    ])
    protected_domains: List[str] = field(default_factory=lambda: [
        "company.com", "corp.internal"
    ])
    urgency_keywords: List[str] = field(default_factory=lambda: [
        "urgent action required", "immediate response needed", "account suspended",
        "wire transfer", "gift card", "verify your password", "payroll direct deposit",
        "unauthorized sign-in attempt", "final warning", "overdue invoice", "crypto payment"
    ])


@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "json"
    log_file: str = "netsecurex.log"


@dataclass
class AppConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    decision_engine: DecisionEngineConfig = field(default_factory=DecisionEngineConfig)
    api_keys: ApiKeysConfig = field(default_factory=ApiKeysConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    heuristics: HeuristicsConfig = field(default_factory=HeuristicsConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


def load_config(config_path: Optional[str] = None) -> AppConfig:
    """Load configuration from YAML file or environment variables."""
    cfg_data: Dict[str, Any] = {}

    paths_to_check = []
    if config_path:
        paths_to_check.append(Path(config_path))
    if os.getenv("NETSECUREX_CONFIG"):
        paths_to_check.append(Path(os.getenv("NETSECUREX_CONFIG", "")))
    paths_to_check.extend([
        Path("config.yaml"),
        Path("config/config.yaml"),
        Path("config/config.yaml.example"),
        Path("/etc/netsecurex/config.yaml"),
    ])

    for p in paths_to_check:
        if p.exists() and p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    cfg_data = yaml.safe_load(f) or {}
                break
            except Exception as e:
                print(f"Warning: Failed to parse config file {p}: {e}")

    app_cfg = AppConfig()

    if "server" in cfg_data:
        srv = cfg_data["server"]
        app_cfg.server.mode = srv.get("mode", app_cfg.server.mode)
        app_cfg.server.host = srv.get("host", app_cfg.server.host)
        app_cfg.server.port = int(srv.get("port", app_cfg.server.port))
        app_cfg.server.milter_socket = srv.get("milter_socket", app_cfg.server.milter_socket)
        app_cfg.server.downstream_host = srv.get("downstream_host", app_cfg.server.downstream_host)
        app_cfg.server.downstream_port = int(srv.get("downstream_port", app_cfg.server.downstream_port))
        app_cfg.server.max_message_size_bytes = int(srv.get("max_message_size_bytes", app_cfg.server.max_message_size_bytes))

    if "database" in cfg_data:
        db = cfg_data["database"]
        app_cfg.database.url = db.get("url", app_cfg.database.url)
        app_cfg.database.echo = bool(db.get("echo", app_cfg.database.echo))

    if "decision_engine" in cfg_data:
        de = cfg_data["decision_engine"]
        app_cfg.decision_engine.medium_risk_threshold = int(de.get("medium_risk_threshold", app_cfg.decision_engine.medium_risk_threshold))
        app_cfg.decision_engine.high_risk_threshold = int(de.get("high_risk_threshold", app_cfg.decision_engine.high_risk_threshold))
        app_cfg.decision_engine.high_risk_action = de.get("high_risk_action", app_cfg.decision_engine.high_risk_action)
        app_cfg.decision_engine.medium_risk_action = de.get("medium_risk_action", app_cfg.decision_engine.medium_risk_action)
        app_cfg.decision_engine.subject_tag_prefix = de.get("subject_tag_prefix", app_cfg.decision_engine.subject_tag_prefix)
        app_cfg.decision_engine.quarantine_recipient = de.get("quarantine_recipient", app_cfg.decision_engine.quarantine_recipient)

    if "api_keys" in cfg_data:
        ak = cfg_data["api_keys"]
        app_cfg.api_keys.google_safe_browsing = os.getenv("SAFE_BROWSING_API_KEY", ak.get("google_safe_browsing", ""))
        app_cfg.api_keys.virustotal = os.getenv("VIRUSTOTAL_API_KEY", ak.get("virustotal", ""))

    if "performance" in cfg_data:
        pf = cfg_data["performance"]
        app_cfg.performance.api_timeout_seconds = float(pf.get("api_timeout_seconds", app_cfg.performance.api_timeout_seconds))
        app_cfg.performance.cache_ttl_seconds = int(pf.get("cache_ttl_seconds", app_cfg.performance.cache_ttl_seconds))
        app_cfg.performance.cache_max_entries = int(pf.get("cache_max_entries", app_cfg.performance.cache_max_entries))

    if "heuristics" in cfg_data:
        hr = cfg_data["heuristics"]
        if "protected_vip_names" in hr:
            app_cfg.heuristics.protected_vip_names = hr["protected_vip_names"]
        if "protected_domains" in hr:
            app_cfg.heuristics.protected_domains = hr["protected_domains"]
        if "urgency_keywords" in hr:
            app_cfg.heuristics.urgency_keywords = hr["urgency_keywords"]

    if "logging" in cfg_data:
        lg = cfg_data["logging"]
        app_cfg.logging.level = lg.get("level", app_cfg.logging.level)
        app_cfg.logging.format = lg.get("format", app_cfg.logging.format)
        app_cfg.logging.log_file = lg.get("log_file", app_cfg.logging.log_file)

    # Environment variable overrides
    if os.getenv("NETSECUREX_DB_URL"):
        app_cfg.database.url = os.environ["NETSECUREX_DB_URL"]
    if os.getenv("NETSECUREX_SERVER_MODE"):
        app_cfg.server.mode = os.environ["NETSECUREX_SERVER_MODE"]
    if os.getenv("NETSECUREX_PORT"):
        app_cfg.server.port = int(os.environ["NETSECUREX_PORT"])
    if os.getenv("SAFE_BROWSING_API_KEY"):
        app_cfg.api_keys.google_safe_browsing = os.environ["SAFE_BROWSING_API_KEY"]
    if os.getenv("VIRUSTOTAL_API_KEY"):
        app_cfg.api_keys.virustotal = os.environ["VIRUSTOTAL_API_KEY"]

    return app_cfg
