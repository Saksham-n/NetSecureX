"""
SMTP Layer Authentication Validator for NetSecureX.
Performs in-transit SPF, DKIM, and DMARC alignment validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
from typing import Optional, Tuple
import dns.resolver

try:
    import spf
except ImportError:
    import pyspf as spf  # type: ignore

try:
    import dkim
except ImportError:
    dkim = None  # type: ignore

logger = logging.getLogger("netsecurex.auth")


@dataclass
class SpfResult:
    result: str  # pass, fail, softfail, neutral, none, temperror, permerror
    code: int
    explanation: str


@dataclass
class DkimResult:
    result: str  # pass, fail, invalid, none
    domain: Optional[str] = None
    selector: Optional[str] = None
    explanation: Optional[str] = None


@dataclass
class DmarcResult:
    result: str  # pass, fail, none, temperror, permerror
    policy: str = "none"  # none, quarantine, reject
    spf_aligned: bool = False
    dkim_aligned: bool = False
    domain: Optional[str] = None
    explanation: Optional[str] = None


@dataclass
class AuthValidationReport:
    spf: SpfResult
    dkim: DkimResult
    dmarc: DmarcResult
    auth_results_header: str = ""
    auth_risk_score: float = 0.0
    reasons: list[str] = field(default_factory=list)


class AuthValidator:
    """Validates SPF, DKIM, and DMARC for an incoming SMTP email."""

    def __init__(self, authserv_id: str = "mailgateway.netsecurex.local", dns_timeout: float = 2.0):
        self.authserv_id = authserv_id
        self.dns_timeout = dns_timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = dns_timeout

    def validate_spf(self, client_ip: str, envelope_from: str, helo_name: Optional[str] = None) -> SpfResult:
        """Evaluates SPF against client IP, envelope-from, and HELO name."""
        if not client_ip:
            return SpfResult("none", 250, "Client IP not provided")

        sender = envelope_from.strip() if envelope_from else ""
        helo = helo_name or "unknown.helo"

        # If envelope from is empty (e.g. bounce NDR), use HELO
        if not sender:
            sender = f"postmaster@{helo}"

        # Treat localhost / test relay loops as neutral/pass if internal
        if client_ip in ("127.0.0.1", "::1", "localhost"):
            return SpfResult("pass", 250, "Local loopback trusted relay")

        try:
            res_tuple = spf.check(i=client_ip, s=sender, h=helo)
            if len(res_tuple) == 3:
                res, code, exp = res_tuple
            elif len(res_tuple) == 2:
                res, exp = res_tuple
                code = 250 if res in ("pass", "none", "neutral") else 550
            else:
                res, code, exp = res_tuple[0], 250, "Evaluated"
            return SpfResult(result=res.lower(), code=code, explanation=str(exp))
        except Exception as e:
            logger.warning(f"SPF validation exception for IP={client_ip}, sender={sender}: {e}")
            return SpfResult(result="temperror", code=451, explanation=str(e))

    def validate_dkim(self, raw_message: bytes) -> DkimResult:
        """Verifies DKIM cryptographic signatures in raw MIME message bytes."""
        if dkim is None:
            return DkimResult(result="none", explanation="dkimpy not installed")

        try:
            # Check if DKIM-Signature header exists
            if b"dkim-signature:" not in raw_message.lower():
                return DkimResult(result="none", explanation="No DKIM-Signature header found")

            # Verify with dkimpy
            valid = dkim.verify(raw_message, dnsfunc=self._dns_txt_lookup)
            if valid:
                # Extract domain and selector from headers
                domain, selector = self._extract_dkim_meta(raw_message)
                return DkimResult(result="pass", domain=domain, selector=selector, explanation="Signature verified")
            else:
                domain, selector = self._extract_dkim_meta(raw_message)
                return DkimResult(result="fail", domain=domain, selector=selector, explanation="Signature verification failed")
        except Exception as e:
            logger.warning(f"DKIM verification exception: {e}")
            return DkimResult(result="invalid", explanation=str(e))

    def _dns_txt_lookup(self, name: bytes | str) -> bytes | None:
        """Custom DNS resolver function for dkimpy with timeout enforcement."""
        domain = name.decode("utf-8") if isinstance(name, bytes) else name
        try:
            answers = self.resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt_str = "".join([part.decode("utf-8", errors="replace") for part in rdata.strings])
                return txt_str.encode("utf-8")
        except Exception:
            pass
        return None

    @staticmethod
    def _extract_dkim_meta(raw_message: bytes) -> Tuple[Optional[str], Optional[str]]:
        domain = None
        selector = None
        for line in raw_message.splitlines():
            lower = line.lower()
            if lower.startswith(b"dkim-signature:"):
                # Parse tags
                for part in line.split(b";"):
                    part = part.strip()
                    if part.startswith(b"d="):
                        domain = part[2:].decode("utf-8", errors="replace").strip()
                    elif part.startswith(b"s="):
                        selector = part[2:].decode("utf-8", errors="replace").strip()
                break
        return domain, selector

    def validate_dmarc(
        self,
        header_from_domain: str,
        spf_result: SpfResult,
        envelope_from: str,
        dkim_result: DkimResult,
        mock_dmarc_txt: Optional[str] = None,
    ) -> DmarcResult:
        """Checks DMARC alignment between Header From domain vs SPF domain and DKIM domain."""
        from_dom = header_from_domain.lower().strip()
        if not from_dom:
            return DmarcResult(result="none", explanation="Missing Header From domain")

        # Fetch DMARC TXT record: _dmarc.<from_dom>
        dmarc_txt = mock_dmarc_txt
        dmarc_target_domain = from_dom
        if not dmarc_txt:
            try:
                answers = self.resolver.resolve(f"_dmarc.{from_dom}", "TXT")
                for rdata in answers:
                    rec = "".join([p.decode("utf-8", errors="replace") for p in rdata.strings])
                    if rec.startswith("v=DMARC1"):
                        dmarc_txt = rec
                        break
            except Exception:
                # Try organizational domain fallback (e.g., sub.domain.com -> domain.com)
                parts = from_dom.split(".")
                if len(parts) > 2:
                    org_dom = ".".join(parts[-2:])
                    dmarc_target_domain = org_dom
                    try:
                        answers = self.resolver.resolve(f"_dmarc.{org_dom}", "TXT")
                        for rdata in answers:
                            rec = "".join([p.decode("utf-8", errors="replace") for p in rdata.strings])
                            if rec.startswith("v=DMARC1"):
                                dmarc_txt = rec
                                break
                    except Exception:
                        pass

        if not dmarc_txt:
            return DmarcResult(result="none", domain=from_dom, explanation="No DMARC record found")

        # Parse DMARC policy tags
        policy = "none"
        aspf = "r"  # 'r' (relaxed) or 's' (strict)
        adkim = "r"
        for tag in dmarc_txt.split(";"):
            tag = tag.strip()
            if tag.startswith("p="):
                policy = tag[2:].strip().lower()
            elif tag.startswith("aspf="):
                aspf = tag[5:].strip().lower()
            elif tag.startswith("adkim="):
                adkim = tag[6:].strip().lower()

        # Check SPF Alignment
        spf_aligned = False
        if spf_result.result == "pass":
            env_dom = envelope_from.split("@")[-1].lower().strip() if "@" in envelope_from else ""
            if aspf == "s":
                spf_aligned = (env_dom == from_dom)
            else:
                spf_aligned = (
                    env_dom == from_dom or 
                    env_dom.endswith(f".{from_dom}") or 
                    from_dom.endswith(f".{env_dom}")
                )

        # Check DKIM Alignment
        dkim_aligned = False
        if dkim_result.result == "pass" and dkim_result.domain:
            dkim_dom = dkim_result.domain.lower().strip()
            if adkim == "s":
                dkim_aligned = (dkim_dom == from_dom)
            else:
                dkim_aligned = (
                    dkim_dom == from_dom or 
                    dkim_dom.endswith(f".{from_dom}") or 
                    from_dom.endswith(f".{dkim_dom}")
                )

        dmarc_pass = spf_aligned or dkim_aligned
        result_status = "pass" if dmarc_pass else "fail"

        return DmarcResult(
            result=result_status,
            policy=policy,
            spf_aligned=spf_aligned,
            dkim_aligned=dkim_aligned,
            domain=dmarc_target_domain,
            explanation=f"DMARC {result_status} (SPF aligned: {spf_aligned}, DKIM aligned: {dkim_aligned}, Policy: {policy})"
        )

    def evaluate_all(
        self,
        client_ip: str,
        envelope_from: str,
        helo_name: Optional[str],
        header_from_domain: str,
        raw_message: bytes,
    ) -> AuthValidationReport:
        """Evaluates SPF, DKIM, DMARC and generates RFC 8601 Authentication-Results header and risk score."""
        spf_res = self.validate_spf(client_ip, envelope_from, helo_name)
        dkim_res = self.validate_dkim(raw_message)
        dmarc_res = self.validate_dmarc(header_from_domain, spf_res, envelope_from, dkim_res)

        score = 0.0
        reasons = []

        # SPF scoring
        if spf_res.result == "fail":
            score += 35.0
            reasons.append(f"SPF permanent failure from IP {client_ip}")
        elif spf_res.result == "softfail":
            score += 15.0
            reasons.append(f"SPF softfail from IP {client_ip}")
        elif spf_res.result == "temperror":
            score += 5.0
            reasons.append("SPF temporary DNS error")

        # DKIM scoring
        if dkim_res.result == "fail":
            score += 25.0
            reasons.append(f"DKIM signature verification failed for domain {dkim_res.domain}")
        elif dkim_res.result == "invalid":
            score += 15.0
            reasons.append("DKIM signature header invalid or malformed")

        # DMARC scoring
        if dmarc_res.result == "fail":
            if dmarc_res.policy == "reject":
                score += 45.0
                reasons.append(f"DMARC failure with strict reject policy for domain {dmarc_res.domain}")
            elif dmarc_res.policy == "quarantine":
                score += 35.0
                reasons.append(f"DMARC failure with quarantine policy for domain {dmarc_res.domain}")
            else:
                score += 20.0
                reasons.append(f"DMARC failure with policy=none for domain {dmarc_res.domain}")

        # Construct RFC 8601 Authentication-Results header string (single-line space-separated)
        auth_hdr = (
            f"Authentication-Results: {self.authserv_id}; "
            f"spf={spf_res.result} smtp.mailfrom={envelope_from or 'none'}; "
            f"dkim={dkim_res.result} header.d={dkim_res.domain or 'none'}; "
            f"dmarc={dmarc_res.result} (p={dmarc_res.policy} dis=none) header.from={header_from_domain or 'none'}"
        )

        return AuthValidationReport(
            spf=spf_res,
            dkim=dkim_res,
            dmarc=dmarc_res,
            auth_results_header=auth_hdr,
            auth_risk_score=min(score, 100.0),
            reasons=reasons,
        )
