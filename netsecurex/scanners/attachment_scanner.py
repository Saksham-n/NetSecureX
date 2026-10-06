"""
Attachment threat analyzer and VirusTotal v3 integration for NetSecureX.
Calculates SHA256 hashes, detects dangerous extensions / double extensions / macros,
and queries VirusTotal API with timeout protection and LRU caching.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
import threading
import time
from typing import Dict, List, Optional, Tuple
import requests
from netsecurex.utils.mime_parser import ParsedAttachment

logger = logging.getLogger("netsecurex.attachment")

# High-risk extensions that should trigger scrutiny / quarantine
DANGEROUS_EXTENSIONS = {
    # Executables & Binaries
    ".exe", ".scr", ".pif", ".com", ".cpl", ".msi", ".msp", ".bin",
    # Scripts
    ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".sh",
    # Office Macro-enabled
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam", ".ppsm",
    # Disk Images & Archives commonly abused for payload hiding
    ".iso", ".img", ".vhd", ".vhdx", ".hta", ".lnk", ".chm", ".jar"
}

# Archive extensions that might contain hidden threats
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab"}


@dataclass
class AttachmentScanResult:
    filename: str
    content_type: str
    file_size_bytes: int
    sha256: str
    md5: str
    is_malicious: bool
    positives: int = 0
    total_engines: int = 0
    suspicious_extension: bool = False
    source: str = "virustotal"
    cached: bool = False
    details: str = ""
    reasons: List[str] = None

    def __post_init__(self):
        if self.reasons is None:
            self.reasons = []

    def to_dict(self) -> Dict[str, any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "file_size_bytes": self.file_size_bytes,
            "sha256": self.sha256,
            "md5": self.md5,
            "is_malicious": self.is_malicious,
            "positives": self.positives,
            "total_engines": self.total_engines,
            "suspicious_extension": self.suspicious_extension,
            "source": self.source,
            "cached": self.cached,
            "details": self.details,
            "reasons": self.reasons,
        }


class AttachmentCacheEntry:
    def __init__(self, is_malicious: bool, positives: int, total_engines: int, details: str, ttl_seconds: int = 86400):
        self.is_malicious = is_malicious
        self.positives = positives
        self.total_engines = total_engines
        self.details = details
        self.expires_at = time.time() + ttl_seconds

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class AttachmentScanner:
    """Scans attachments for known malware hashes via VirusTotal v3 and dangerous file formats."""

    VT_FILE_ENDPOINT = "https://www.virustotal.com/api/v3/files/{sha256}"

    def __init__(
        self,
        api_key: str = "",
        timeout_seconds: float = 2.5,
        cache_ttl_seconds: int = 86400,
        max_cache_entries: int = 10000,
    ):
        self.api_key = api_key.strip() if api_key else ""
        self.timeout_seconds = timeout_seconds
        self.cache_ttl_seconds = cache_ttl_seconds
        self.max_cache_entries = max_cache_entries
        self._cache: Dict[str, AttachmentCacheEntry] = {}
        self._lock = threading.Lock()
        self.session = requests.Session()

    def _get_from_cache(self, sha256: str) -> Optional[Tuple[bool, int, int, str]]:
        with self._lock:
            entry = self._cache.get(sha256)
            if entry:
                if entry.is_expired():
                    del self._cache[sha256]
                    return None
                return entry.is_malicious, entry.positives, entry.total_engines, entry.details
        return None

    def _save_to_cache(self, sha256: str, is_malicious: bool, positives: int, total_engines: int, details: str) -> None:
        with self._lock:
            if len(self._cache) >= self.max_cache_entries:
                now = time.time()
                expired = [k for k, v in self._cache.items() if v.expires_at < now]
                for k in expired:
                    self._cache.pop(k, None)
                if len(self._cache) >= self.max_cache_entries:
                    for k in list(self._cache.keys())[:100]:
                        self._cache.pop(k, None)
            self._cache[sha256] = AttachmentCacheEntry(is_malicious, positives, total_engines, details, self.cache_ttl_seconds)

    def scan_attachments(self, attachments: List[ParsedAttachment]) -> List[AttachmentScanResult]:
        """Analyzes all extracted email attachments."""
        if not attachments:
            return []

        results: List[AttachmentScanResult] = []

        for att in attachments:
            reasons: List[str] = []
            filename_lower = att.filename.lower()
            ext = att.extension

            # Check 1: Dangerous executable/macro extension
            suspicious_ext = False
            if ext in DANGEROUS_EXTENSIONS:
                suspicious_ext = True
                reasons.append(f"Dangerous attachment extension: {ext}")

            # Check 2: Double extension spoofing (e.g. invoice.pdf.exe)
            parts = filename_lower.split(".")
            if len(parts) > 2:
                second_last_ext = f".{parts[-2]}"
                if second_last_ext in {".pdf", ".docx", ".xlsx", ".png", ".jpg", ".txt"} and ext in DANGEROUS_EXTENSIONS:
                    suspicious_ext = True
                    reasons.append(f"Double extension deception detected: {att.filename}")

            # Check 3: Check cache for SHA-256
            cached_val = self._get_from_cache(att.sha256)
            if cached_val is not None:
                is_mal, pos, total, det = cached_val
                if is_mal:
                    reasons.append(f"VirusTotal detected malware: {pos}/{total} engines")
                results.append(
                    AttachmentScanResult(
                        filename=att.filename,
                        content_type=att.content_type,
                        file_size_bytes=att.size_bytes,
                        sha256=att.sha256,
                        md5=att.md5,
                        is_malicious=is_mal,
                        positives=pos,
                        total_engines=total,
                        suspicious_extension=suspicious_ext,
                        source="virustotal (cached)",
                        cached=True,
                        details=det,
                        reasons=reasons,
                    )
                )
                continue

            # Check 4: Remote VirusTotal lookup
            is_mal, pos, total, det = self._query_virustotal(att.sha256)
            if is_mal:
                reasons.append(f"VirusTotal detected malware: {pos}/{total} engines")

            self._save_to_cache(att.sha256, is_mal, pos, total, det)
            results.append(
                AttachmentScanResult(
                    filename=att.filename,
                    content_type=att.content_type,
                    file_size_bytes=att.size_bytes,
                    sha256=att.sha256,
                    md5=att.md5,
                    is_malicious=is_mal,
                    positives=pos,
                    total_engines=total,
                    suspicious_extension=suspicious_ext,
                    source="virustotal",
                    cached=False,
                    details=det,
                    reasons=reasons,
                )
            )

        return results

    def _query_virustotal(self, sha256: str) -> Tuple[bool, int, int, str]:
        """Queries VirusTotal v3 for existing SHA-256 analysis report."""
        if not self.api_key:
            return False, 0, 0, "VirusTotal API key not configured; local heuristics only"

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

        try:
            url = self.VT_FILE_ENDPOINT.format(sha256=sha256)
            resp = self.session.get(url, headers=headers, timeout=self.timeout_seconds)

            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                undetected = stats.get("undetected", 0)
                harmless = stats.get("harmless", 0)
                total = malicious + suspicious + undetected + harmless

                positives = malicious + suspicious
                is_flagged = positives >= 2  # At least 2 AV vendor detections

                details = f"VT Stats: {malicious} malicious, {suspicious} suspicious out of {total} engines"
                return is_flagged, positives, total, details

            elif resp.status_code == 404:
                # File unknown to VirusTotal (not inherently malicious, but uncataloged)
                return False, 0, 0, "File hash not found in VirusTotal catalog"
            else:
                logger.warning(f"VirusTotal API HTTP {resp.status_code} for hash {sha256}")
                return False, 0, 0, f"VT API returned HTTP {resp.status_code}"

        except requests.Timeout:
            logger.warning(f"VirusTotal API timed out after {self.timeout_seconds}s; continuing.")
            return False, 0, 0, "VirusTotal API request timed out"
        except Exception as e:
            logger.error(f"VirusTotal API query failed: {e}")
            return False, 0, 0, f"Error: {str(e)}"
