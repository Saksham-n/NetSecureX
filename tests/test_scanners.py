import pytest
from netsecurex.utils.mime_parser import ParsedEmail, ParsedAttachment
from netsecurex.scanners.url_scanner import UrlScanner
from netsecurex.scanners.attachment_scanner import AttachmentScanner


def test_mime_parser_basic_text():
    raw_email = (
        b"From: Alice <alice@example.com>\r\n"
        b"To: Bob <bob@example.com>\r\n"
        b"Subject: Test Subject\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Please check out https://example.com/test and http://192.168.1.1/admin"
    )

    parsed = ParsedEmail(raw_email)
    assert parsed.from_address == "alice@example.com"
    assert parsed.display_name == "Alice"
    assert parsed.from_domain == "example.com"
    assert parsed.subject == "Test Subject"
    assert "https://example.com/test" in parsed.extracted_urls
    assert "http://192.168.1.1/admin" in parsed.extracted_urls


def test_mime_parser_html_and_attachments():
    raw_multipart = (
        b"From: Billing <billing@service.com>\r\n"
        b"To: Client <client@target.com>\r\n"
        b"Subject: Invoice\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n"
        b"\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n"
        b"<p>Please click <a href=\"https://secure-login.xyz/auth\">here</a></p>\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: application/octet-stream; name=\"invoice.pdf.exe\"\r\n"
        b"Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n"
        b"\r\n"
        b"MZ-fake-binary-content\r\n"
        b"--BOUNDARY--"
    )

    parsed = ParsedEmail(raw_multipart)
    assert "https://secure-login.xyz/auth" in parsed.extracted_urls
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename == "invoice.pdf.exe"
    assert att.extension == ".exe"
    assert len(att.sha256) == 64


def test_url_scanner_patterns_and_caching():
    scanner = UrlScanner(api_key="", timeout_seconds=1.0)
    urls = [
        "http://192.168.1.50/login",
        "https://login.company.com.account-verification.xyz/reset-password-now",
        "https://legitimate.org/about",
    ]

    results = scanner.scan_urls(urls)
    assert len(results) == 3
    # First URL has IP address pattern
    ip_result = next(r for r in results if "192.168.1.50" in r.url)
    assert len(ip_result.suspicious_patterns) > 0

    # Second URL has excessive subdomains + suspicious TLD
    phish_result = next(r for r in results if "account-verification" in r.url)
    assert len(phish_result.suspicious_patterns) > 0

    # Test caching
    cached_results = scanner.scan_urls(["http://192.168.1.50/login"])
    assert cached_results[0].cached is True


def test_attachment_scanner_dangerous_extension():
    scanner = AttachmentScanner(api_key="", timeout_seconds=1.0)
    att = ParsedAttachment(
        filename="payroll_update.docm",
        content_type="application/vnd.ms-word.document.macroEnabled.12",
        payload=b"fake-docm-macro-bytes",
    )

    results = scanner.scan_attachments([att])
    assert len(results) == 1
    res = results[0]
    assert res.suspicious_extension is True
    assert len(res.reasons) > 0
