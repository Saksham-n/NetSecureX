"""
SQLAlchemy ORM models for NetSecureX email audit logs and security telemetry.
"""

from __future__ import annotations

import datetime
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    DateTime,
    Text,
    ForeignKey,
    Boolean,
    Index,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class EmailScanLog(Base):
    """Stores full audit record for every email intercepted and scanned."""
    __tablename__ = "email_scan_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    message_id = Column(String(255), index=True, nullable=True)
    queue_id = Column(String(64), index=True, nullable=True)
    client_ip = Column(String(64), nullable=False, index=True)
    helo_name = Column(String(255), nullable=True)
    
    sender = Column(String(255), nullable=False, index=True)
    recipient = Column(String(255), nullable=False, index=True)
    subject = Column(String(500), nullable=True)
    
    # Auth verification results
    spf_status = Column(String(32), nullable=True)  # pass, fail, softfail, neutral, none, temperror, permerror
    spf_explanation = Column(String(255), nullable=True)
    dkim_status = Column(String(32), nullable=True)  # pass, fail, invalid, none
    dkim_domain = Column(String(255), nullable=True)
    dmarc_status = Column(String(32), nullable=True) # pass, fail, none
    dmarc_policy = Column(String(32), nullable=True) # none, quarantine, reject
    
    # Risk Scoring & Breakdown
    total_score = Column(Float, nullable=False, index=True)
    risk_level = Column(String(32), nullable=False, index=True) # LOW, MEDIUM, HIGH
    action_taken = Column(String(32), nullable=False, index=True) # ALLOW, TAG, QUARANTINE, REJECT
    
    # Detailed heuristics findings
    urgency_detected = Column(Boolean, default=False)
    display_name_spoofed = Column(Boolean, default=False)
    lookalike_domain_detected = Column(Boolean, default=False)
    summary_report = Column(Text, nullable=True)
    
    # Metadata
    processing_time_ms = Column(Float, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), index=True)
    
    # Relationships
    scanned_urls = relationship("UrlScanLog", back_populates="email_log", cascade="all, delete-orphan")
    scanned_attachments = relationship("AttachmentScanLog", back_populates="email_log", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return (
            f"<EmailScanLog(id={self.id}, sender='{self.sender}', "
            f"recipient='{self.recipient}', score={self.total_score}, action='{self.action_taken}')>"
        )


class UrlScanLog(Base):
    """Stores URL reputation results extracted from message body."""
    __tablename__ = "url_scan_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email_scan_id = Column(Integer, ForeignKey("email_scan_logs.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(Text, nullable=False)
    domain = Column(String(255), nullable=True, index=True)
    is_malicious = Column(Boolean, default=False, index=True)
    threat_type = Column(String(64), nullable=True) # MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, etc.
    source = Column(String(64), default="google_safe_browsing")
    cached = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    email_log = relationship("EmailScanLog", back_populates="scanned_urls")


class AttachmentScanLog(Base):
    """Stores attachment hashes and threat analysis results."""
    __tablename__ = "attachment_scan_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email_scan_id = Column(Integer, ForeignKey("email_scan_logs.id", ondelete="CASCADE"), nullable=False, index=True)
    filename = Column(String(255), nullable=True)
    content_type = Column(String(128), nullable=True)
    sha256 = Column(String(64), nullable=False, index=True)
    file_size_bytes = Column(Integer, nullable=False)
    is_malicious = Column(Boolean, default=False, index=True)
    positives = Column(Integer, default=0)
    total_engines = Column(Integer, default=0)
    suspicious_extension = Column(Boolean, default=False)
    source = Column(String(64), default="virustotal")
    cached = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    email_log = relationship("EmailScanLog", back_populates="scanned_attachments")
