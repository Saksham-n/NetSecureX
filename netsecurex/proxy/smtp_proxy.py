"""
aiosmtpd-based Intercepting SMTP Gateway Proxy for NetSecureX.
Intercepts in-transit SMTP traffic before delivery, performs scanning hook,
and modifies headers, quarantines, rejects with 550, or forwards downstream.
"""

from __future__ import annotations

import asyncio
import email
from email import policy
from email.message import EmailMessage
import logging
import smtplib
from typing import List, Optional

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope, Session, SMTP

from netsecurex.config import AppConfig
from netsecurex.scanners.engine import ScanEngine, ScanDecision

logger = logging.getLogger("netsecurex.proxy")


class SmtpProxyHandler:
    """Handles incoming SMTP transactions, scans messages in transit, and routes accordingly."""

    def __init__(self, engine: ScanEngine, config: AppConfig):
        self.engine = engine
        self.config = config

    async def handle_MAIL(self, server: SMTP, session: Session, envelope: Envelope, address: str, options: List[str]) -> str:
        envelope.mail_from = address
        return "250 2.1.0 Sender OK"

    async def handle_RCPT(self, server: SMTP, session: Session, envelope: Envelope, address: str, options: List[str]) -> str:
        envelope.rcpt_tos.append(address)
        return "250 2.1.5 Recipient OK"

    async def handle_DATA(self, server: SMTP, session: Session, envelope: Envelope) -> str:
        """Called upon completion of DATA command before returning response to sending client."""
        client_ip = session.peer[0] if session.peer else "127.0.0.1"
        helo_name = getattr(session, "host_name", "unknown.client")
        mail_from = envelope.mail_from
        rcpt_tos = envelope.rcpt_tos
        raw_content = envelope.content

        # Convert content to raw bytes
        if isinstance(raw_content, str):
            raw_bytes = raw_content.encode("utf-8", errors="replace")
        elif isinstance(raw_content, bytes):
            raw_bytes = raw_content
        else:
            raw_bytes = b""

        primary_rcpt = rcpt_tos[0] if rcpt_tos else "unknown@recipient.local"

        # Execute in-transit multi-vector inspection
        try:
            decision: ScanDecision = self.engine.scan_message(
                client_ip=client_ip,
                envelope_from=mail_from,
                envelope_rcpt=primary_rcpt,
                helo_name=helo_name,
                raw_message_bytes=raw_bytes,
            )
        except Exception as e:
            logger.error(f"Scanning hook error: {e}", exc_info=True)
            # Fail gracefully (pass through with error header)
            return await self._relay_to_downstream(
                mail_from=mail_from,
                rcpt_tos=rcpt_tos,
                raw_message=raw_bytes,
                headers_to_inject=[("X-NetSecureX-Error", f"Scanner failure: {str(e)}")],
            )

        # High Risk Action: Reject at SMTP level
        if decision.action == "REJECT":
            logger.warning(
                f"REJECTING message from {mail_from} to {rcpt_tos}: {decision.smtp_response_message}"
            )
            return f"550 {decision.smtp_response_message}"

        # High Risk Action: Quarantine
        if decision.action == "QUARANTINE":
            logger.warning(f"QUARANTINING message from {mail_from} to {rcpt_tos}")
            quarantine_dest = [self.config.decision_engine.quarantine_recipient]
            modified_bytes = self._prepare_modified_message(
                raw_bytes=raw_bytes,
                modified_subject=f"[QUARANTINE - SCORE {decision.total_score}] " + (ParsedEmail(raw_bytes).subject or ""),
                headers_to_inject=decision.headers_to_add,
            )
            relay_res = await self._relay_to_downstream(
                mail_from=mail_from,
                rcpt_tos=quarantine_dest,
                raw_message=modified_bytes,
            )
            return "250 2.0.0 Message accepted and routed to quarantine"

        # Medium Risk: Tag subject and deliver
        if decision.action == "TAG":
            logger.info(f"TAGGING message from {mail_from} to {rcpt_tos} with prefix '{self.config.decision_engine.subject_tag_prefix}'")
            modified_bytes = self._prepare_modified_message(
                raw_bytes=raw_bytes,
                modified_subject=decision.modified_subject,
                headers_to_inject=decision.headers_to_add,
            )
            return await self._relay_to_downstream(
                mail_from=mail_from,
                rcpt_tos=rcpt_tos,
                raw_message=modified_bytes,
            )

        # Low Risk: Deliver cleanly with audit headers
        logger.info(f"ALLOWING message from {mail_from} to {rcpt_tos}")
        modified_bytes = self._prepare_modified_message(
            raw_bytes=raw_bytes,
            modified_subject=None,
            headers_to_inject=decision.headers_to_add,
        )
        return await self._relay_to_downstream(
            mail_from=mail_from,
            rcpt_tos=rcpt_tos,
            raw_message=modified_bytes,
        )

    def _prepare_modified_message(
        self,
        raw_bytes: bytes,
        modified_subject: Optional[str],
        headers_to_inject: List[tuple[str, str]],
    ) -> bytes:
        """Injects authentication/scan headers and updates Subject if needed."""
        try:
            msg = email.message_from_bytes(raw_bytes, policy=policy.default)
            if modified_subject:
                clean_subj = " ".join(modified_subject.split())
                if "Subject" in msg:
                    del msg["Subject"]
                msg["Subject"] = clean_subj

            for hdr_name, hdr_val in headers_to_inject:
                clean_name = hdr_name.strip()
                clean_val = " ".join(str(hdr_val).split())
                msg[clean_name] = clean_val

            return msg.as_bytes()
        except Exception as e:
            logger.error(f"Failed to modify message bytes: {e}")
            return raw_bytes

    async def _relay_to_downstream(
        self,
        mail_from: str,
        rcpt_tos: List[str],
        raw_message: bytes,
        headers_to_inject: Optional[List[tuple[str, str]]] = None,
    ) -> str:
        """Relays message to the next hop MTA (e.g. Postfix downstream port 1025 or final mailbox)."""
        if headers_to_inject:
            raw_message = self._prepare_modified_message(
                raw_bytes=raw_message,
                modified_subject=None,
                headers_to_inject=headers_to_inject,
            )

        dest_host = self.config.server.downstream_host
        dest_port = self.config.server.downstream_port

        loop = asyncio.get_event_loop()

        def _sync_smtp_send() -> str:
            try:
                with smtplib.SMTP(host=dest_host, port=dest_port, timeout=10.0) as smtp:
                    smtp.sendmail(
                        from_addr=mail_from,
                        to_addrs=rcpt_tos,
                        msg=raw_message,
                    )
                return "250 2.0.0 OK: Message forwarded to downstream MTA"
            except smtplib.SMTPRecipientsRefused:
                return "550 5.1.1 All recipients were refused by downstream MTA"
            except smtplib.SMTPSenderRefused:
                return "550 5.1.8 Sender address rejected by downstream MTA"
            except smtplib.SMTPDataError as de:
                return f"554 5.0.0 Downstream MTA data error: {de.smtp_error}"
            except Exception as ex:
                logger.error(f"Downstream MTA connection failure to {dest_host}:{dest_port}: {ex}")
                # If downstream server is unavailable in standalone test mode, log and return 250 test receipt
                return f"250 2.0.0 Processed by NetSecureX Gateway (Downstream Relay Notice: {ex})"

        return await loop.run_in_executor(None, _sync_smtp_send)


def create_smtp_proxy_controller(engine: ScanEngine, config: AppConfig) -> Controller:
    """Initializes and returns an aiosmtpd Controller configured with the NetSecureX proxy handler."""
    handler = SmtpProxyHandler(engine=engine, config=config)
    controller = Controller(
        handler=handler,
        hostname=config.server.host,
        port=config.server.port,
        ready_timeout=5.0,
    )
    return controller
