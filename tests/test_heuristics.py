import pytest
from netsecurex.scanners.heuristics import (
    HeuristicScanner,
    levenshtein_distance,
    normalize_homoglyphs,
)


def test_levenshtein_distance():
    assert levenshtein_distance("apple", "apple") == 0
    assert levenshtein_distance("company", "c0mpany") == 1
    assert levenshtein_distance("microsoft", "micros0ft") == 1
    assert levenshtein_distance("paypal", "paypa1") == 1
    assert levenshtein_distance("google", "gooogle") == 1


def test_normalize_homoglyphs():
    # Cyrillic 'а' (\u0430) -> Latin 'a'
    cyrillic_a = "\u0430pple"
    assert normalize_homoglyphs(cyrillic_a) == "apple"

    # Number substitutions '0' -> 'o'
    assert normalize_homoglyphs("c0mpany") == "company"


def test_heuristic_urgency_detection():
    scanner = HeuristicScanner(
        protected_vip_names=["CEO"],
        protected_domains=["company.com"],
        urgency_keywords=["urgent action required", "wire transfer", "gift card"],
    )

    result = scanner.analyze(
        display_name="Normal User",
        from_address="user@company.com",
        from_domain="company.com",
        reply_to_address="",
        subject="URGENT ACTION REQUIRED: Please process wire transfer",
        body_text="Need you to buy gift card immediately",
        extracted_domains=["company.com"],
    )

    assert result.urgency_detected is True
    assert result.urgency_score > 0
    assert len(result.urgency_matches) >= 2


def test_heuristic_display_name_spoofing():
    scanner = HeuristicScanner(
        protected_vip_names=["CEO", "Chief Executive Officer", "Finance Director"],
        protected_domains=["company.com"],
        urgency_keywords=[],
    )

    # Impersonating CEO with external address
    result = scanner.analyze(
        display_name="CEO John Doe",
        from_address="attacker@gmail.com",
        from_domain="gmail.com",
        reply_to_address="",
        subject="Hello",
        body_text="Test",
        extracted_domains=[],
    )

    assert result.display_name_spoofed is True
    assert result.display_name_score >= 40.0

    # Embedded email in display name
    result_embedded = scanner.analyze(
        display_name='"admin@company.com" <spammer@evil.com>',
        from_address="spammer@evil.com",
        from_domain="evil.com",
        reply_to_address="",
        subject="Update",
        body_text="Body",
        extracted_domains=[],
    )
    assert result_embedded.display_name_spoofed is True


def test_heuristic_lookalike_domain():
    scanner = HeuristicScanner(
        protected_vip_names=[],
        protected_domains=["company.com"],
        urgency_keywords=[],
    )

    # 1 edit distance
    result = scanner.analyze(
        display_name="Support",
        from_address="support@c0mpany.com",
        from_domain="c0mpany.com",
        reply_to_address="",
        subject="Support",
        body_text="Body",
        extracted_domains=[],
    )

    assert result.lookalike_detected is True
    assert result.lookalike_score >= 50.0
