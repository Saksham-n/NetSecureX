"""
MIME Email Parser for NetSecureX.
Extracts headers, plain text, HTML bodies, embedded/plain URLs, and attachments with cryptographic hashes.
"""

from __future__ import annotations

import email
from email import policy
from email.header import decode_header, make_header
from email.message import EmailMessage
import hashlib
import html
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


URL_REGEX = re.compile(
    r'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’]))',
    re.IGNORECASE
)

HTML_HREF_REGEX = re.compile(r'''(?i)<a\s+(?:[^>]*?\s+)?href=["']([^"'>]+)["']''')
HTML_SRC_REGEX = re.compile(r'''(?i)<(?:img|iframe|script|source)\s+(?:[^>]*?\s+)?src=["']([^"'>]+)["']''')


class ParsedAttachment:
    def __init__(self, filename: str, content_type: str, payload: bytes):
        self.filename = filename or "unnamed_attachment"
        self.content_type = content_type or "application/octet-stream"
        self.payload = payload
        self.size_bytes = len(payload)
        self.sha256 = hashlib.sha256(payload).hexdigest()
        self.md5 = hashlib.md5(payload).hexdigest()
        self.extension = self._extract_extension(self.filename)

    @staticmethod
    def _extract_extension(filename: str) -> str:
        parts = filename.lower().rsplit(".", 1)
        return f".{parts[1]}" if len(parts) > 1 else ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "md5": self.md5,
            "extension": self.extension,
        }


class ParsedEmail:
    def __init__(self, raw_bytes: bytes):
        self.raw_bytes = raw_bytes
        self.msg: EmailMessage = email.message_from_bytes(raw_bytes, policy=policy.default)
        
        # Headers
        self.message_id = self._clean_header(self.msg.get("Message-ID", ""))
        self.subject = self._decode_header_str(self.msg.get("Subject", ""))
        self.from_header = self._decode_header_str(self.msg.get("From", ""))
        self.to_header = self._decode_header_str(self.msg.get("To", ""))
        self.reply_to = self._decode_header_str(self.msg.get("Reply-To", ""))
        self.date_str = self._clean_header(self.msg.get("Date", ""))
        
        # Parsed identity components
        self.display_name, self.from_address, self.from_domain = self._parse_address(self.from_header)
        self.reply_to_name, self.reply_to_address, self.reply_to_domain = self._parse_address(self.reply_to)
        
        # Body extraction
        self.text_body: str = ""
        self.html_body: str = ""
        self.attachments: List[ParsedAttachment] = []
        self._parse_body_and_attachments()
        
        # URL extraction
        self.extracted_urls: List[str] = self._extract_all_urls()

    @staticmethod
    def _clean_header(val: str) -> str:
        return val.strip() if val else ""

    @staticmethod
    def _decode_header_str(header_val: str) -> str:
        if not header_val:
            return ""
        try:
            return str(make_header(decode_header(header_val)))
        except Exception:
            return header_val

    @staticmethod
    def _parse_address(addr_str: str) -> Tuple[str, str, str]:
        """Extracts display name, full email address, and domain."""
        if not addr_str:
            return "", "", ""
        name, addr = email.utils.parseaddr(addr_str)
        domain = addr.split("@")[1].lower() if "@" in addr else ""
        return name.strip(), addr.strip().lower(), domain

    def _parse_body_and_attachments(self) -> None:
        """Walks MIME tree to gather text, HTML, and attachments."""
        text_parts = []
        html_parts = []

        if not self.msg.is_multipart():
            content_type = self.msg.get_content_type()
            payload = self.msg.get_payload(decode=True)
            if payload is None:
                payload = self.msg.get_payload()
                if isinstance(payload, str):
                    payload = payload.encode("utf-8", errors="replace")

            if content_type == "text/html":
                html_parts.append(self._decode_payload(payload, self.msg.get_content_charset() or "utf-8"))
            elif content_type == "text/plain":
                text_parts.append(self._decode_payload(payload, self.msg.get_content_charset() or "utf-8"))
            else:
                filename = self.msg.get_filename() or "unnamed_attachment"
                if payload and isinstance(payload, bytes):
                    self.attachments.append(ParsedAttachment(filename, content_type, payload))
        else:
            for part in self.msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", "")).lower()
                filename = part.get_filename()

                # If it's an attachment
                if filename or "attachment" in content_disposition:
                    payload = part.get_payload(decode=True)
                    if payload and isinstance(payload, bytes):
                        self.attachments.append(
                            ParsedAttachment(
                                filename=self._decode_header_str(filename) if filename else "unnamed",
                                content_type=content_type,
                                payload=payload
                            )
                        )
                    continue

                # Body part
                if content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        text_parts.append(self._decode_payload(payload, charset))
                elif content_type == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        html_parts.append(self._decode_payload(payload, charset))

        self.text_body = "\n".join(text_parts)
        self.html_body = "\n".join(html_parts)

    @staticmethod
    def _decode_payload(payload: bytes, charset: str) -> str:
        try:
            return payload.decode(charset, errors="replace")
        except (LookupError, UnicodeDecodeError):
            return payload.decode("latin1", errors="replace")

    def _extract_all_urls(self) -> List[str]:
        """Extract and normalize all unique URLs from plain text and HTML components."""
        found: Set[str] = set()

        # URLs in text body
        if self.text_body:
            for match in URL_REGEX.findall(self.text_body):
                url = match[0] if isinstance(match, tuple) else match
                norm = self._normalize_url(url)
                if norm:
                    found.add(norm)

        # URLs in HTML body
        if self.html_body:
            # Check href attributes
            for href in HTML_HREF_REGEX.findall(self.html_body):
                decoded_href = html.unescape(href).strip()
                norm = self._normalize_url(decoded_href)
                if norm:
                    found.add(norm)

            # Check src attributes
            for src in HTML_SRC_REGEX.findall(self.html_body):
                decoded_src = html.unescape(src).strip()
                norm = self._normalize_url(decoded_src)
                if norm:
                    found.add(norm)

            # Also scan raw HTML text
            for match in URL_REGEX.findall(self.html_body):
                url = match[0] if isinstance(match, tuple) else match
                norm = self._normalize_url(url)
                if norm:
                    found.add(norm)

        return sorted(list(found))

    @staticmethod
    def _normalize_url(raw_url: str) -> Optional[str]:
        """Validates and formats URL into absolute HTTP/HTTPS format."""
        u = raw_url.strip().strip("'\"<>[](){}")
        if not u:
            return None
        # Ignore mailto, tel, javascript, data URIs
        if u.startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
            return None

        # Add scheme if missing
        if u.startswith("//"):
            u = "http:" + u
        elif not (u.startswith("http://") or u.startswith("https://")):
            # Check if looks like domain/path
            if "." in u.split("/")[0]:
                u = "http://" + u
            else:
                return None

        try:
            parsed = urlparse(u)
            if not parsed.netloc or "." not in parsed.netloc:
                return None
            return u
        except Exception:
            return None
