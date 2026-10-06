import pytest
from netsecurex.scanners.auth_validator import AuthValidator, SpfResult, DkimResult, DmarcResult


def test_auth_validator_spf_logic():
    validator = AuthValidator(dns_timeout=1.0)
    # Testing fallback/empty values
    res = validator.validate_spf(client_ip="", envelope_from="")
    assert res.result == "none"


def test_auth_validator_dmarc_alignment_strict_relaxed():
    validator = AuthValidator(dns_timeout=1.0)

    # 1. Relaxed SPF Match (subdomain)
    spf_pass = SpfResult("pass", 250, "SPF pass")
    dkim_none = DkimResult("none")

    # Manually testing evaluate_all or dmarc alignment logic
    # Subdomain mail.company.com matches company.com in relaxed mode
    dmarc_res = validator.validate_dmarc(
        header_from_domain="company.com",
        spf_result=spf_pass,
        envelope_from="sender@mail.company.com",
        dkim_result=dkim_none,
        mock_dmarc_txt="v=DMARC1; p=quarantine; aspf=r; adkim=r",
    )
    assert dmarc_res.spf_aligned is True
    assert dmarc_res.result == "pass"

    # Mismatched domain
    dmarc_res_fail = validator.validate_dmarc(
        header_from_domain="company.com",
        spf_result=spf_pass,
        envelope_from="sender@evil.com",
        dkim_result=dkim_none,
        mock_dmarc_txt="v=DMARC1; p=quarantine; aspf=r; adkim=r",
    )
    assert dmarc_res_fail.spf_aligned is False
    assert dmarc_res_fail.result == "fail"


def test_auth_validator_scoring():
    validator = AuthValidator(dns_timeout=1.0)
    raw_msg = (
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Subject: Test\r\n\r\n"
        b"Hello world"
    )

    report = validator.evaluate_all(
        client_ip="127.0.0.1",
        envelope_from="sender@example.com",
        helo_name="mail.example.com",
        header_from_domain="example.com",
        raw_message=raw_msg,
    )

    assert report.auth_results_header.startswith("Authentication-Results:")
    assert isinstance(report.auth_risk_score, float)
