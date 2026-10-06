"""
Heuristic Analysis Engine for NetSecureX.
Detects:
1. Urgency & Coercion language patterns
2. Display Name Spoofing / Executive & VIP Impersonation
3. Lookalike / Typosquatting / Homoglyph domains (Levenshtein & character substitution)
"""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
import re
import unicodedata
from typing import List, Set, Tuple

logger = logging.getLogger("netsecurex.heuristics")

# Common Homoglyph / Confusable map (ASCII <-> Cyrillic/Greek/Numbers)
HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b',
    # Cyrillic small letters that look identical to Latin
    '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043e': 'o',
    '\u0440': 'p', '\u0455': 's', '\u0445': 'x', '\u0443': 'y',
    '\u0456': 'i', '\u0458': 'j',
}

# Regex for finding email addresses inside display names (e.g. "admin@company.com" <spammer@evil.com>)
EMBEDDED_EMAIL_REGEX = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+', re.IGNORECASE)


@dataclass
class HeuristicResult:
    urgency_detected: bool = False
    urgency_score: float = 0.0
    urgency_matches: List[str] = field(default_factory=list)

    display_name_spoofed: bool = False
    display_name_score: float = 0.0
    display_name_reason: str = ""

    lookalike_detected: bool = False
    lookalike_score: float = 0.0
    lookalike_matches: List[str] = field(default_factory=list)

    total_heuristic_score: float = 0.0
    reasons: List[str] = field(default_factory=list)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def normalize_homoglyphs(text: str) -> str:
    """Replaces confusable homoglyphs and Cyrillic lookalikes with Latin equivalents."""
    # First normalize NFKD unicode
    norm = unicodedata.normalize('NFKD', text)
    result = []
    for ch in norm:
        lower_ch = ch.lower()
        if lower_ch in HOMOGLYPH_MAP:
            result.append(HOMOGLYPH_MAP[lower_ch])
        else:
            result.append(lower_ch)
    return "".join(result)


class HeuristicScanner:
    """Evaluates message components against advanced threat heuristics."""

    def __init__(
        self,
        protected_vip_names: List[str],
        protected_domains: List[str],
        urgency_keywords: List[str],
    ):
        self.protected_vip_names = [name.strip().lower() for name in protected_vip_names if name.strip()]
        self.protected_domains = [dom.strip().lower() for dom in protected_domains if dom.strip()]
        self.urgency_keywords = [kw.strip().lower() for kw in urgency_keywords if kw.strip()]

    def analyze(
        self,
        display_name: str,
        from_address: str,
        from_domain: str,
        reply_to_address: str,
        subject: str,
        body_text: str,
        extracted_domains: List[str],
    ) -> HeuristicResult:
        result = HeuristicResult()
        reasons = []

        # 1. Urgency & Coercion Language Detection
        urg_score, urg_matches = self._check_urgency(subject, body_text)
        if urg_matches:
            result.urgency_detected = True
            result.urgency_score = urg_score
            result.urgency_matches = urg_matches
            reasons.append(f"Urgency / social engineering triggers found: {', '.join(urg_matches)}")

        # 2. Display Name Spoofing & VIP Impersonation
        spoofed, disp_score, disp_reason = self._check_display_name_spoofing(
            display_name=display_name,
            from_address=from_address,
            from_domain=from_domain,
            reply_to_address=reply_to_address,
        )
        if spoofed:
            result.display_name_spoofed = True
            result.display_name_score = disp_score
            result.display_name_reason = disp_reason
            reasons.append(f"Display Name Spoofing: {disp_reason}")

        # 3. Lookalike / Typosquatting / Homoglyph Domain Detection
        lookalike, look_score, look_matches = self._check_lookalike_domains(
            from_domain=from_domain,
            extracted_domains=extracted_domains,
        )
        if lookalike:
            result.lookalike_detected = True
            result.lookalike_score = look_score
            result.lookalike_matches = look_matches
            reasons.append(f"Lookalike / Typosquatted domain detected: {', '.join(look_matches)}")

        # Aggregate heuristic score (capped at 100)
        total_score = min(result.urgency_score + result.display_name_score + result.lookalike_score, 100.0)
        result.total_heuristic_score = total_score
        result.reasons = reasons

        return result

    def _check_urgency(self, subject: str, body_text: str) -> Tuple[float, List[str]]:
        combined = f"{subject}\n{body_text}".lower()
        matches: Set[str] = set()

        for kw in self.urgency_keywords:
            if kw in combined:
                matches.add(kw)

        if not matches:
            return 0.0, []

        # Calculate score: base 15 + 5 for each additional match (max 30)
        score = min(15.0 + (len(matches) - 1) * 5.0, 30.0)
        return score, sorted(list(matches))

    def _check_display_name_spoofing(
        self,
        display_name: str,
        from_address: str,
        from_domain: str,
        reply_to_address: str,
    ) -> Tuple[bool, float, str]:
        if not display_name:
            return False, 0.0, ""

        disp_lower = display_name.lower().strip()
        disp_norm = normalize_homoglyphs(disp_lower)

        # Check A: Display name contains an embedded email address from a protected domain, but sender is different
        embedded_emails = EMBEDDED_EMAIL_REGEX.findall(disp_lower)
        for emb in embedded_emails:
            emb_dom = emb.split("@")[-1]
            if emb_dom in self.protected_domains and from_domain not in self.protected_domains:
                return True, 50.0, f"Display name contains internal address '{emb}' while sender is external '{from_address}'"

        # Check B: Display name contains protected VIP or executive titles, but sender domain is not protected
        for vip in self.protected_vip_names:
            if vip in disp_norm or vip in disp_lower:
                if from_domain not in self.protected_domains:
                    return True, 45.0, f"Display name matches VIP/executive title '{vip}' from external sender '{from_address}'"

        # Check C: Display name contains protected company domain name (e.g. "Acme Corp Helpdesk") from freemail or external
        for prot_dom in self.protected_domains:
            brand_token = prot_dom.split(".")[0]
            if len(brand_token) >= 4 and (brand_token in disp_norm or brand_token in disp_lower):
                if from_domain not in self.protected_domains:
                    return True, 40.0, f"Display name invokes protected brand '{brand_token}' from external domain '{from_domain}'"

        # Check D: Reply-To domain mismatch with sender (Cousin Domain or freemail bait-and-switch)
        if reply_to_address:
            reply_dom = reply_to_address.split("@")[-1].lower().strip() if "@" in reply_to_address else ""
            if reply_dom and reply_dom != from_domain:
                if from_domain in self.protected_domains and reply_dom not in self.protected_domains:
                    return True, 45.0, f"Sender claims internal domain '{from_domain}' but Reply-To points to external '{reply_to_address}'"

        return False, 0.0, ""

    def _check_lookalike_domains(
        self,
        from_domain: str,
        extracted_domains: List[str],
    ) -> Tuple[bool, float, List[str]]:
        if not self.protected_domains:
            return False, 0.0, []

        all_candidate_domains = set()
        if from_domain:
            all_candidate_domains.add(from_domain.lower().strip())
        for d in extracted_domains:
            if d:
                all_candidate_domains.add(d.lower().strip())

        matched_findings: List[str] = []
        max_score = 0.0

        for candidate in all_candidate_domains:
            # Skip if exact match to protected domain
            if candidate in self.protected_domains:
                continue

            cand_norm = normalize_homoglyphs(candidate)

            for prot in self.protected_domains:
                # 1. Homoglyph check: normalized candidate equals protected domain
                if cand_norm == prot and candidate != prot:
                    matched_findings.append(f"Homoglyph/Confusable domain '{candidate}' masquerading as '{prot}'")
                    max_score = max(max_score, 60.0)
                    continue

                # 2. Levenshtein edit distance check on domain base names
                cand_base = candidate.split(".")[0]
                prot_base = prot.split(".")[0]

                if len(prot_base) >= 4:
                    dist = levenshtein_distance(cand_base, prot_base)
                    # 1 edit distance on strings length 4-7, or <=2 on longer strings
                    if (len(prot_base) <= 7 and dist == 1) or (len(prot_base) > 7 and dist <= 2):
                        matched_findings.append(f"Typosquatted domain '{candidate}' is {dist} edit(s) away from '{prot}'")
                        max_score = max(max_score, 50.0)
                        continue

                # 3. Subdomain / Prefix spoofing (e.g. company.com.attacker.com or company-portal.com)
                if candidate.startswith(f"{prot}.") or candidate.startswith(f"{prot_base}-") or candidate.endswith(f"-{prot}"):
                    matched_findings.append(f"Deceptive subdomain/prefix spoofing '{candidate}' mimicking '{prot}'")
                    max_score = max(max_score, 45.0)

        if matched_findings:
            return True, max_score, matched_findings

        return False, 0.0, []
