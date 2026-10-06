"""
Core Scanning and Decision Engine for NetSecureX.
Coordinates SPF/DKIM/DMARC auth, Safe Browsing URL lookup, VirusTotal attachment scanning,
and heuristics to output composite threat scores, actions, and audit headers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from netsecurex.config import AppConfig
from netsecurex.db.storage import DatabaseStorage
from netsecurex.scanners.auth_validator import AuthValidator, AuthValidationReport
from netsecurex.scanners.url_scanner import UrlScanner, UrlScanResult
from netsecurex.scanners.attachment_scanner import AttachmentScanner, AttachmentScanResult
from netsecurex.scanners.heuristics import HeuristicScanner, HeuristicResult
from netsecurex.utils.mime_parser import ParsedEmail

logger = logging.getLogger("netsecurex.engine")


@dataclass
class ScanDecision:
    total_score: float
    risk_level: str  # LOW, MEDIUM, HIGH
    action: str      # ALLOW, TAG, QUARANTINE, REJECT
    reasons: List[str] = field(default_factory=list)
    modified_subject: Optional[str] = None
    headers_to_add: List[tuple[str, str]] = field(default_factory=list)
    smtp_response_code: int = 250
    smtp_response_message: str = "OK - Queued for delivery"
    auth_report: Optional[AuthValidationReport] = None
    url_results: List[UrlScanResult] = field(default_factory=list)
    attachment_results: List[AttachmentScanResult] = field(default_factory=list)
    heuristic_result: Optional[HeuristicResult] = None
    processing_time_ms: float = 0.0


class ScanEngine:
    """Master threat detection engine coordinating all scanners."""

    def __init__(self, config: AppConfig, storage: Optional[DatabaseStorage] = None):
        self.config = config
        self.storage = storage or DatabaseStorage(
            db_url=config.database.url,
            echo=config.database.echo
        )

        self.auth_validator = AuthValidator(
            authserv_id="gateway.netsecurex.local",
            dns_timeout=config.performance.api_timeout_seconds,
        )

        self.url_scanner = UrlScanner(
            api_key=config.api_keys.google_safe_browsing,
            timeout_seconds=config.performance.api_timeout_seconds,
            cache_ttl_seconds=config.performance.cache_ttl_seconds,
            max_cache_entries=config.performance.cache_max_entries,
        )

        self.attachment_scanner = AttachmentScanner(
            api_key=config.api_keys.virustotal,
            timeout_seconds=config.performance.api_timeout_seconds,
            cache_ttl_seconds=config.performance.cache_ttl_seconds,
            max_cache_entries=config.performance.cache_max_entries,
        )

        self.heuristic_scanner = HeuristicScanner(
            protected_vip_names=config.heuristics.protected_vip_names,
            protected_domains=config.heuristics.protected_domains,
            urgency_keywords=config.heuristics.urgency_keywords,
        )

    def scan_message(
        self,
        client_ip: str,
        envelope_from: str,
        envelope_rcpt: str,
        helo_name: Optional[str],
        raw_message_bytes: bytes,
        queue_id: Optional[str] = None,
    ) -> ScanDecision:
        """Executes full multi-vector inspection on an email message."""
        start_time = time.perf_counter()
        
        # 1. Parse MIME message structure
        parsed = ParsedEmail(raw_message_bytes)

        # 2. In-Transit Header / Protocol Authentication Validation
        auth_report = self.auth_validator.evaluate_all(
            client_ip=client_ip,
            envelope_from=envelope_from,
            helo_name=helo_name,
            header_from_domain=parsed.from_domain,
            raw_message=raw_message_bytes,
        )

        # 3. Content Scanning - URL Extraction & Google Safe Browsing
        url_results = self.url_scanner.scan_urls(parsed.extracted_urls)

        # 4. Content Scanning - Attachment Hashes & VirusTotal
        attachment_results = self.attachment_scanner.scan_attachments(parsed.attachments)

        # 5. Heuristic Analysis (Urgency, Display Name Spoofing, Lookalike Domains)
        extracted_domains = []
        for u in parsed.extracted_urls:
            try:
                d = urlparse(u).netloc.split(":")[0].lower()
                if d:
                    extracted_domains.append(d)
            except Exception:
                pass

        heuristic_res = self.heuristic_scanner.analyze(
            display_name=parsed.display_name,
            from_address=parsed.from_address,
            from_domain=parsed.from_domain,
            reply_to_address=parsed.reply_to_address,
            subject=parsed.subject,
            body_text=parsed.text_body,
            extracted_domains=extracted_domains,
        )

        # 6. Aggregate Scoring & Decision Logic
        score, reasons = self._calculate_composite_score(
            auth_report=auth_report,
            url_results=url_results,
            attachment_results=attachment_results,
            heuristic_res=heuristic_res,
        )

        # Decision threshold evaluation
        cfg_engine = self.config.decision_engine
        med_thresh = cfg_engine.medium_risk_threshold
        high_thresh = cfg_engine.high_risk_threshold

        headers_to_add: List[tuple[str, str]] = []
        modified_subject = None

        if score >= high_thresh:
            risk_level = "HIGH"
            if cfg_engine.high_risk_action == "reject":
                action = "REJECT"
                smtp_code = 550
                smtp_msg = f"5.7.1 Message rejected by NetSecureX policy: Security threat detected (Score: {score})"
            else:
                action = "QUARANTINE"
                smtp_code = 250
                smtp_msg = "2.0.0 Message accepted and routed to quarantine"
        elif score >= med_thresh:
            risk_level = "MEDIUM"
            action = "TAG"
            smtp_code = 250
            smtp_msg = "2.0.0 OK - Message tagged for inspection"
            tag = cfg_engine.subject_tag_prefix
            if not parsed.subject.startswith(tag):
                modified_subject = f"{tag} {parsed.subject}".strip()
        else:
            risk_level = "LOW"
            action = "ALLOW"
            smtp_code = 250
            smtp_msg = "2.0.0 OK - Message verified clean"

        # Construct security headers
        headers_to_add.append(("Authentication-Results", auth_report.auth_results_header.replace("Authentication-Results: ", "")))
        headers_to_add.append(("X-NetSecureX-Scan", "Evaluated"))
        headers_to_add.append(("X-NetSecureX-Score", f"{score:.1f}/100"))
        headers_to_add.append(("X-NetSecureX-Risk", risk_level))
        headers_to_add.append(("X-NetSecureX-Action", action))
        if reasons:
            headers_to_add.append(("X-NetSecureX-Threats", "; ".join(reasons[:5])))

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        decision = ScanDecision(
            total_score=score,
            risk_level=risk_level,
            action=action,
            reasons=reasons,
            modified_subject=modified_subject,
            headers_to_add=headers_to_add,
            smtp_response_code=smtp_code,
            smtp_response_message=smtp_msg,
            auth_report=auth_report,
            url_results=url_results,
            attachment_results=attachment_results,
            heuristic_result=heuristic_res,
            processing_time_ms=elapsed_ms,
        )

        # 7. Persistence & Auditing
        self._persist_log(
            parsed=parsed,
            client_ip=client_ip,
            envelope_from=envelope_from,
            envelope_rcpt=envelope_rcpt,
            helo_name=helo_name,
            queue_id=queue_id,
            decision=decision,
        )

        logger.info(
            f"Scanned email: From={envelope_from} To={envelope_rcpt} "
            f"Score={score:.1f} Risk={risk_level} Action={action} Duration={elapsed_ms:.2f}ms"
        )

        return decision

    def _calculate_composite_score(
        self,
        auth_report: AuthValidationReport,
        url_results: List[UrlScanResult],
        attachment_results: List[AttachmentScanResult],
        heuristic_res: HeuristicResult,
    ) -> tuple[float, List[str]]:
        score = 0.0
        reasons: List[str] = []

        # 1. Auth contributions
        if auth_report.auth_risk_score > 0:
            score += auth_report.auth_risk_score * 0.7  # Weighted
            reasons.extend(auth_report.reasons)

        # 2. URL threats
        for ur in url_results:
            if ur.is_malicious:
                score += 80.0
                reasons.append(f"Malicious URL detected ({ur.threat_type or 'Safe Browsing'}): {ur.url}")
            elif ur.suspicious_patterns:
                score += 15.0
                reasons.append(f"Suspicious URL patterns in {ur.url}: {', '.join(ur.suspicious_patterns)}")

        # 3. Attachment threats
        for att in attachment_results:
            if att.is_malicious:
                score += 85.0
                reasons.append(f"Malware attachment detected by VirusTotal ({att.positives}/{att.total_engines}): {att.filename}")
            elif att.suspicious_extension:
                score += 40.0
                reasons.append(f"High-risk attachment file type: {att.filename}")

        # 4. Heuristics (Urgency, Display Name Spoofing, Lookalike Domains)
        if heuristic_res.total_heuristic_score > 0:
            score += heuristic_res.total_heuristic_score * 0.8
            reasons.extend(heuristic_res.reasons)

        final_score = min(max(round(score, 1), 0.0), 100.0)
        return final_score, reasons

    def _persist_log(
        self,
        parsed: ParsedEmail,
        client_ip: str,
        envelope_from: str,
        envelope_rcpt: str,
        helo_name: Optional[str],
        queue_id: Optional[str],
        decision: ScanDecision,
    ) -> None:
        try:
            urls_payload = [
                {
                    "url": u.url,
                    "domain": u.domain,
                    "is_malicious": u.is_malicious,
                    "threat_type": u.threat_type,
                    "source": u.source,
                    "cached": u.cached,
                }
                for u in decision.url_results
            ]
            attachments_payload = [
                {
                    "filename": a.filename,
                    "content_type": a.content_type,
                    "sha256": a.sha256,
                    "file_size_bytes": a.file_size_bytes,
                    "is_malicious": a.is_malicious,
                    "positives": a.positives,
                    "total_engines": a.total_engines,
                    "suspicious_extension": a.suspicious_extension,
                    "source": a.source,
                    "cached": a.cached,
                }
                for a in decision.attachment_results
            ]

            summary = "; ".join(decision.reasons) if decision.reasons else "Clean - No threats detected"

            self.storage.log_scan_transaction(
                message_id=parsed.message_id or None,
                queue_id=queue_id,
                client_ip=client_ip,
                helo_name=helo_name,
                sender=envelope_from or parsed.from_address,
                recipient=envelope_rcpt or parsed.to_header,
                subject=parsed.subject,
                spf_status=decision.auth_report.spf.result if decision.auth_report else None,
                spf_explanation=decision.auth_report.spf.explanation if decision.auth_report else None,
                dkim_status=decision.auth_report.dkim.result if decision.auth_report else None,
                dkim_domain=decision.auth_report.dkim.domain if decision.auth_report else None,
                dmarc_status=decision.auth_report.dmarc.result if decision.auth_report else None,
                dmarc_policy=decision.auth_report.dmarc.policy if decision.auth_report else None,
                total_score=decision.total_score,
                risk_level=decision.risk_level,
                action_taken=decision.action,
                urgency_detected=decision.heuristic_result.urgency_detected if decision.heuristic_result else False,
                display_name_spoofed=decision.heuristic_result.display_name_spoofed if decision.heuristic_result else False,
                lookalike_domain_detected=decision.heuristic_result.lookalike_detected if decision.heuristic_result else False,
                summary_report=summary,
                processing_time_ms=decision.processing_time_ms,
                urls=urls_payload,
                attachments=attachments_payload,
            )
        except Exception as e:
            logger.error(f"Failed to persist scan transaction to database: {e}")
