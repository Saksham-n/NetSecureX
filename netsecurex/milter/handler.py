"""
Postfix Milter (Mail Filter) interface for NetSecureX.
Implements the Sendmail / Postfix Milter protocol using pymilter.
Hooks directly into the Postfix SMTP transaction lifecycle (CONNECT, HELO, ENVFROM, ENVRCPT, HEADER, EOM).
"""

from __future__ import annotations

import io
import logging
from typing import List, Optional

from netsecurex.config import AppConfig
from netsecurex.scanners.engine import ScanEngine, ScanDecision

logger = logging.getLogger("netsecurex.milter")

# Handle environments where pymilter / libmilter-dev is not compiled
try:
    import Milter
except ImportError:
    Milter = None


if Milter is not None:
    class NetSecureXMilter(Milter.Base):
        """Milter implementation hooked into Postfix smtpd_milters pipeline."""

        # Class-level engine instance injected at startup
        engine: Optional[ScanEngine] = None
        config: Optional[AppConfig] = None

        def __init__(self):
            self.id = Milter.unique_id()
            self.client_ip = "127.0.0.1"
            self.helo_name = ""
            self.mail_from = ""
            self.rcpt_tos: List[str] = []
            self.headers: List[tuple[str, str]] = []
            self.fp = io.BytesIO()
            self.subject = ""

        @Milter.nocallback
        def connect(self, hostname: str, family: int, hostaddr: tuple) -> int:
            """Called when MTA accepts TCP connection from sending client."""
            if hostaddr and len(hostaddr) > 0:
                self.client_ip = str(hostaddr[0])
            logger.debug(f"[{self.id}] Milter connect from {hostname} [{self.client_ip}]")
            return Milter.CONTINUE

        def helo(self, helo_name: str) -> int:
            """Called on HELO/EHLO command."""
            self.helo_name = helo_name
            return Milter.CONTINUE

        def envfrom(self, mailfrom: str, *args) -> int:
            """Called on MAIL FROM command."""
            # pymilter wraps address in <...>; strip them
            self.mail_from = mailfrom.strip("<> ")
            self.fp = io.BytesIO()
            self.headers = []
            self.rcpt_tos = []
            return Milter.CONTINUE

        def envrcpt(self, rcptto: str, *args) -> int:
            """Called on RCPT TO command."""
            clean_rcpt = rcptto.strip("<> ")
            self.rcpt_tos.append(clean_rcpt)
            return Milter.CONTINUE

        def header(self, name: str, val: str) -> int:
            """Called for each RFC 5322 header."""
            self.headers.append((name, val))
            if name.lower() == "subject":
                self.subject = val
            # Write raw header line to internal buffer
            self.fp.write(f"{name}: {val}\r\n".encode("utf-8", errors="replace"))
            return Milter.CONTINUE

        def eoh(self) -> int:
            """Called at end of message headers."""
            self.fp.write(b"\r\n")
            return Milter.CONTINUE

        def body(self, chunk: bytes) -> int:
            """Called for each chunk of message body."""
            self.fp.write(chunk)
            return Milter.CONTINUE

        def eom(self) -> int:
            """Called at End of Message (DATA command completion). Runs scanning hook."""
            if not self.engine or not self.config:
                logger.error("Milter engine not initialized! Passing through message.")
                return Milter.ACCEPT

            raw_bytes = self.fp.getvalue()
            primary_rcpt = self.rcpt_tos[0] if self.rcpt_tos else ""

            try:
                decision: ScanDecision = self.engine.scan_message(
                    client_ip=self.client_ip,
                    envelope_from=self.mail_from,
                    envelope_rcpt=primary_rcpt,
                    helo_name=self.helo_name,
                    raw_message_bytes=raw_bytes,
                )
            except Exception as e:
                logger.error(f"[{self.id}] Milter scan error: {e}", exc_info=True)
                self.addheader("X-NetSecureX-Error", f"Milter scanner error: {str(e)}")
                return Milter.ACCEPT

            # High Risk Action: Reject (550 SMTP code at MTA level)
            if decision.action == "REJECT":
                logger.warning(f"[{self.id}] Milter REJECTING message from {self.mail_from} (Score: {decision.total_score})")
                self.setreply("550", "5.7.1", decision.smtp_response_message)
                return Milter.REJECT

            # High Risk Action: Quarantine
            if decision.action == "QUARANTINE":
                logger.warning(f"[{self.id}] Milter QUARANTINING message from {self.mail_from}")
                # Redirect recipients to quarantine mailbox
                quarantine_target = self.config.decision_engine.quarantine_recipient
                for orig_rcpt in self.rcpt_tos:
                    try:
                        self.delrcpt(f"<{orig_rcpt}>")
                    except Exception as ex:
                        logger.warning(f"Failed to delete rcpt {orig_rcpt}: {ex}")
                self.addrcpt(f"<{quarantine_target}>")
                
                # Tag subject for quarantine visibility
                self.chgheader("Subject", 1, f"[QUARANTINE - RISK {decision.total_score}] {self.subject}")
                for hdr_name, hdr_val in decision.headers_to_add:
                    self.addheader(hdr_name, hdr_val)
                return Milter.ACCEPT

            # Medium Risk: Tag subject and deliver
            if decision.action == "TAG":
                logger.info(f"[{self.id}] Milter TAGGING message from {self.mail_from} with '{decision.modified_subject}'")
                if decision.modified_subject:
                    # Update Subject in place
                    self.chgheader("Subject", 1, decision.modified_subject)
                for hdr_name, hdr_val in decision.headers_to_add:
                    self.addheader(hdr_name, hdr_val)
                return Milter.ACCEPT

            # Low Risk: Allow and inject audit headers
            for hdr_name, hdr_val in decision.headers_to_add:
                self.addheader(hdr_name, hdr_val)

            return Milter.ACCEPT

        def close(self) -> int:
            """Clean up resources on connection teardown."""
            self.fp.close()
            return Milter.CONTINUE

else:
    class NetSecureXMilter:  # type: ignore
        """Placeholder class when pymilter is not installed."""
        engine = None
        config = None


def run_milter_service(engine: ScanEngine, config: AppConfig) -> None:
    """Starts the Milter daemon listening on configured UNIX or TCP socket."""
    if Milter is None:
        raise RuntimeError(
            "pymilter is not installed or libmilter C-libraries are missing. "
            "To use Milter mode on Linux: apt-get install libmilter-dev && pip install pymilter. "
            "Alternatively, use proxy mode (mode: 'proxy') which runs natively anywhere."
        )

    NetSecureXMilter.engine = engine
    NetSecureXMilter.config = config

    socket_str = config.server.milter_socket
    logger.info(f"Starting NetSecureX Milter listening on {socket_str}")

    # Set milter flags to allow header/recipient mutation
    Milter.set_flags(Milter.ADDHDRS | Milter.CHGHDRS | Milter.ADDRCPT | Milter.DELRCPT)
    Milter.factory = NetSecureXMilter
    Milter.runmilter("netsecurex", socket_str, timeout=30)
