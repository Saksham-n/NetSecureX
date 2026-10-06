"""
Database storage and session management for NetSecureX.
Supports SQLite, PostgreSQL, and connection pooling.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from netsecurex.db.models import Base, EmailScanLog, UrlScanLog, AttachmentScanLog


class DatabaseStorage:
    _instance: Optional[DatabaseStorage] = None
    _lock = threading.Lock()

    def __init__(self, db_url: str = "sqlite:///netsecurex.db", echo: bool = False):
        self.db_url = db_url
        connect_args = {}
        if db_url.startswith("sqlite"):
            connect_args = {"check_same_thread": False}

        self.engine = create_engine(
            db_url,
            echo=echo,
            connect_args=connect_args,
            pool_pre_ping=True
        )
        self.SessionFactory = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.init_schema()

    def init_schema(self) -> None:
        """Create tables if they do not exist."""
        Base.metadata.create_all(self.engine)

    def get_session(self) -> Session:
        """Return a new database session."""
        return self.SessionFactory()

    def log_scan_transaction(
        self,
        message_id: Optional[str],
        queue_id: Optional[str],
        client_ip: str,
        helo_name: Optional[str],
        sender: str,
        recipient: str,
        subject: Optional[str],
        spf_status: Optional[str],
        spf_explanation: Optional[str],
        dkim_status: Optional[str],
        dkim_domain: Optional[str],
        dmarc_status: Optional[str],
        dmarc_policy: Optional[str],
        total_score: float,
        risk_level: str,
        action_taken: str,
        urgency_detected: bool,
        display_name_spoofed: bool,
        lookalike_domain_detected: bool,
        summary_report: str,
        processing_time_ms: float,
        urls: Optional[List[Dict[str, Any]]] = None,
        attachments: Optional[List[Dict[str, Any]]] = None,
    ) -> EmailScanLog:
        """Persist a full scan audit log with associated URLs and attachments."""
        session = self.get_session()
        try:
            email_log = EmailScanLog(
                message_id=message_id,
                queue_id=queue_id,
                client_ip=client_ip,
                helo_name=helo_name,
                sender=sender,
                recipient=recipient,
                subject=subject,
                spf_status=spf_status,
                spf_explanation=spf_explanation,
                dkim_status=dkim_status,
                dkim_domain=dkim_domain,
                dmarc_status=dmarc_status,
                dmarc_policy=dmarc_policy,
                total_score=total_score,
                risk_level=risk_level,
                action_taken=action_taken,
                urgency_detected=urgency_detected,
                display_name_spoofed=display_name_spoofed,
                lookalike_domain_detected=lookalike_domain_detected,
                summary_report=summary_report,
                processing_time_ms=processing_time_ms,
            )
            session.add(email_log)
            session.flush()

            if urls:
                for u in urls:
                    url_entry = UrlScanLog(
                        email_scan_id=email_log.id,
                        url=u.get("url", ""),
                        domain=u.get("domain", ""),
                        is_malicious=u.get("is_malicious", False),
                        threat_type=u.get("threat_type"),
                        source=u.get("source", "google_safe_browsing"),
                        cached=u.get("cached", False),
                    )
                    session.add(url_entry)

            if attachments:
                for att in attachments:
                    att_entry = AttachmentScanLog(
                        email_scan_id=email_log.id,
                        filename=att.get("filename"),
                        content_type=att.get("content_type"),
                        sha256=att.get("sha256", ""),
                        file_size_bytes=att.get("file_size_bytes", 0),
                        is_malicious=att.get("is_malicious", False),
                        positives=att.get("positives", 0),
                        total_engines=att.get("total_engines", 0),
                        suspicious_extension=att.get("suspicious_extension", False),
                        source=att.get("source", "virustotal"),
                        cached=att.get("cached", False),
                    )
                    session.add(att_entry)

            session.commit()
            return email_log
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_recent_scans(self, limit: int = 50) -> List[EmailScanLog]:
        """Fetch the most recent scan logs for monitoring/auditing."""
        session = self.get_session()
        try:
            return (
                session.query(EmailScanLog)
                .order_by(EmailScanLog.id.desc())
                .limit(limit)
                .all()
            )
        finally:
            session.close()
