"""
URL reputation and phishing/malware scanner for NetSecureX.
Features Google Safe Browsing API v4 integration, local cache with TTL, and fast timeout handling.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
import re
import threading
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import requests

logger = logging.getLogger("netsecurex.url")


@dataclass
class UrlScanResult:
    url: str
    domain: str
    is_malicious: bool
    threat_type: Optional[str] = None
    source: str = "google_safe_browsing"
    cached: bool = False
    details: str = ""
    suspicious_patterns: List[str] = None

    def __post_init__(self):
        if self.suspicious_patterns is None:
            self.suspicious_patterns = []

    def to_dict(self) -> Dict[str, any]:
        return {
            "url": self.url,
            "domain": self.domain,
            "is_malicious": self.is_malicious,
            "threat_type": self.threat_type,
            "source": self.source,
            "cached": self.cached,
            "details": self.details,
            "suspicious_patterns": self.suspicious_patterns,
        }


class CacheEntry:
    def __init__(self, is_malicious: bool, threat_type: Optional[str], details: str, ttl_seconds: int = 86400):
        self.is_malicious = is_malicious
        self.threat_type = threat_type
        self.details = details
        self.expires_at = time.time() + ttl_seconds

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class UrlScanner:
    """Scans URLs using Google Safe Browsing v4 and local heuristic pattern checks."""

    SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

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
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = threading.Lock()
        self.session = requests.Session()

    def _get_from_cache(self, url: str) -> Optional[Tuple[bool, Optional[str], str]]:
        with self._lock:
            entry = self._cache.get(url)
            if entry:
                if entry.is_expired():
                    del self._cache[url]
                    return None
                return entry.is_malicious, entry.threat_type, entry.details
        return None

    def _save_to_cache(self, url: str, is_malicious: bool, threat_type: Optional[str], details: str) -> None:
        with self._lock:
            if len(self._cache) >= self.max_cache_entries:
                # Remove expired or first 100 entries
                now = time.time()
                expired_keys = [k for k, v in self._cache.items() if v.expires_at < now]
                for k in expired_keys:
                    self._cache.pop(k, None)
                if len(self._cache) >= self.max_cache_entries:
                    keys_to_pop = list(self._cache.keys())[:100]
                    for k in keys_to_pop:
                        self._cache.pop(k, None)
            self._cache[url] = CacheEntry(is_malicious, threat_type, details, self.cache_ttl_seconds)

    def scan_urls(self, urls: List[str]) -> List[UrlScanResult]:
        """Scans a list of URLs against local heuristics, cache, and Safe Browsing API."""
        if not urls:
            return []

        results: List[UrlScanResult] = []
        uncached_urls: List[str] = []

        for url in urls:
            domain = ""
            try:
                domain = urlparse(url).netloc.lower()
            except Exception:
                pass

            patterns = self._check_suspicious_url_patterns(url, domain)
            cached_val = self._get_from_cache(url)
            if cached_val is not None:
                is_mal, threat, det = cached_val
                results.append(
                    UrlScanResult(
                        url=url,
                        domain=domain,
                        is_malicious=is_mal,
                        threat_type=threat,
                        source="google_safe_browsing (cached)",
                        cached=True,
                        details=det,
                        suspicious_patterns=patterns,
                    )
                )
            else:
                uncached_urls.append(url)

        # Batch query Google Safe Browsing if API key present
        if uncached_urls:
            api_results = self._query_safe_browsing(uncached_urls)
            for url in uncached_urls:
                domain = ""
                try:
                    domain = urlparse(url).netloc.lower()
                except Exception:
                    pass
                patterns = self._check_suspicious_url_patterns(url, domain)
                is_mal, threat, det = api_results.get(url, (False, None, "Clean / Unflagged"))
                
                # If patterns show blatant IP address with login/password or suspicious brand path, flag details
                if patterns and not is_mal:
                    det = f"Heuristic warning: {', '.join(patterns)}"

                self._save_to_cache(url, is_mal, threat, det)
                results.append(
                    UrlScanResult(
                        url=url,
                        domain=domain,
                        is_malicious=is_mal,
                        threat_type=threat,
                        source="google_safe_browsing",
                        cached=False,
                        details=det,
                        suspicious_patterns=patterns,
                    )
                )

        return results

    def _query_safe_browsing(self, urls: List[str]) -> Dict[str, Tuple[bool, Optional[str], str]]:
        """Queries Google Safe Browsing v4 ThreatMatches API with strict timeout."""
        res_map: Dict[str, Tuple[bool, Optional[str], str]] = {}
        for u in urls:
            res_map[u] = (False, None, "Clean")

        if not self.api_key:
            logger.debug("Google Safe Browsing API key not configured; skipping remote lookup.")
            return res_map

        payload = {
            "client": {
                "clientId": "netsecurex-gateway",
                "clientVersion": "1.0.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls[:500]],  # API max is 500 per batch
            },
        }

        try:
            resp = self.session.post(
                f"{self.SAFE_BROWSING_ENDPOINT}?key={self.api_key}",
                json=payload,
                timeout=self.timeout_seconds,
            )
            if resp.status_code == 200:
                data = resp.json()
                matches = data.get("matches", [])
                for match in matches:
                    threat_url = match.get("threat", {}).get("url")
                    threat_type = match.get("threatType")
                    if threat_url and threat_url in res_map:
                        res_map[threat_url] = (True, threat_type, f"Flagged as {threat_type} by Safe Browsing")
            else:
                logger.warning(f"Safe Browsing API returned HTTP {resp.status_code}: {resp.text[:200]}")
        except requests.Timeout:
            logger.warning(f"Safe Browsing API timed out after {self.timeout_seconds}s; failing gracefully.")
        except Exception as e:
            logger.error(f"Safe Browsing API query failed: {e}")

        return res_map

    @staticmethod
    def _check_suspicious_url_patterns(url: str, domain: str) -> List[str]:
        """Detects high-risk URL patterns (raw IP host, punycode/IDN, multiple subdomains, suspicious TLDs)."""
        findings = []
        dom = domain.split(":")[0].strip()

        # Check raw IP address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", dom):
            findings.append("URL uses raw IP address instead of hostname")

        # Punycode / IDN
        if "xn--" in dom:
            findings.append("URL uses punycode / internationalized domain")

        # Excessive subdomains (e.g. login.microsoft.com.account-update.xyz)
        parts = dom.split(".")
        if len(parts) >= 4 and not parts[-1].isdigit():
            findings.append("Excessive subdomain depth (possible brand masquerading)")

        # Suspicious free/abused TLDs commonly used in bulk phishing
        suspicious_tlds = {".top", ".xyz", ".work", ".click", ".link", ".buzz", ".cam", ".rest"}
        for tld in suspicious_tlds:
            if dom.endswith(tld):
                findings.append(f"High-abuse top level domain ({tld})")
                break

        # Password / token harvesting query parameters
        lower_url = url.lower()
        if any(tok in lower_url for tok in ["/login?redirect=", "verify-account", "reset-password-now", "update-bank"]):
            findings.append("Suspicious credential harvesting path/query pattern")

        return findings
