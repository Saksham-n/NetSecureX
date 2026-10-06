"""
Automated Gmail Threat Scenario Test Suite for NetSecureX.
Simulates real Gmail sender infrastructure, IP headers, and attack vectors.
"""

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import email.utils
from email.message import EmailMessage
from netsecurex.config import load_config
from netsecurex.db.storage import DatabaseStorage
from netsecurex.scanners.engine import ScanEngine


def run_gmail_tests():
    print("=" * 70)
    print(" [*] RUNNING GMAIL EMAIL INTERCEPTION & THREAT TESTS")
    print("=" * 70)

    # Initialize Engine & Database
    cfg = load_config()
    cfg.heuristics.protected_domains = ["company.com"]
    cfg.heuristics.protected_vip_names = ["CEO", "Chief Executive Officer", "Finance Director"]
    storage = DatabaseStorage(db_url="sqlite:///netsecurex.db")
    engine = ScanEngine(config=cfg, storage=storage)

    # Real Google MTA IP range
    GMAIL_MTA_IP = "209.85.220.41"
    GMAIL_HELO = "mail-sor-f41.google.com"

    # -------------------------------------------------------------
    # Test 1: VIP CEO Display Name Spoofing from Gmail
    # -------------------------------------------------------------
    print("\n[TEST 1] CEO Impersonation Attack via Gmail:")
    msg1 = EmailMessage()
    msg1["Message-ID"] = email.utils.make_msgid(domain="gmail.com")
    msg1["Date"] = email.utils.formatdate(localtime=True)
    msg1["From"] = '"CEO John Doe <ceo@company.com>" <attacker987@gmail.com>'
    msg1["To"] = "finance@company.com"
    msg1["Reply-To"] = "attacker-secret@mail.ru"
    msg1["Subject"] = "URGENT: Process emergency wire transfer for board meeting"
    msg1.set_content(
        "Hi Finance Team,\n\n"
        "I am currently in an urgent board meeting and need you to immediately execute "
        "a wire transfer and update payroll direct deposit right away.\n\n"
        "Thanks,\nCEO John Doe"
    )

    d1 = engine.scan_message(
        client_ip=GMAIL_MTA_IP,
        envelope_from="attacker987@gmail.com",
        envelope_rcpt="finance@company.com",
        helo_name=GMAIL_HELO,
        raw_message_bytes=msg1.as_bytes(),
    )

    print(f"  -> Sender:         {msg1['From']}")
    print(f"  -> Risk Score:     {d1.total_score} / 100")
    print(f"  -> Risk Level:     {d1.risk_level}")
    print(f"  -> Gateway Action: {d1.action}")
    print("  -> Detected Threats:")
    for r in d1.reasons:
        print(f"     * {r}")

    # -------------------------------------------------------------
    # Test 2: Phishing Link & Credential Harvester via Gmail
    # -------------------------------------------------------------
    print("\n[TEST 2] Credential Phishing Link via Gmail:")
    msg2 = EmailMessage()
    msg2["Message-ID"] = email.utils.make_msgid(domain="gmail.com")
    msg2["Date"] = email.utils.formatdate(localtime=True)
    msg2["From"] = "Google Account Alert <alert-service@gmail.com>"
    msg2["To"] = "employee@company.com"
    msg2["Subject"] = "Security Alert: Unauthorized sign-in attempt detected"
    msg2.set_content(
        "An unauthorized sign-in was detected on your corporate account.\n\n"
        "Please verify your password immediately to prevent account suspension:\n"
        "http://192.168.1.100/login?redirect=company.com\n\n"
        "Google Security Team"
    )

    d2 = engine.scan_message(
        client_ip=GMAIL_MTA_IP,
        envelope_from="alert-service@gmail.com",
        envelope_rcpt="employee@company.com",
        helo_name=GMAIL_HELO,
        raw_message_bytes=msg2.as_bytes(),
    )

    print(f"  -> Sender:         {msg2['From']}")
    print(f"  -> Risk Score:     {d2.total_score} / 100")
    print(f"  -> Risk Level:     {d2.risk_level}")
    print(f"  -> Gateway Action: {d2.action}")
    print("  -> Detected Threats:")
    for r in d2.reasons:
        print(f"     * {r}")

    # -------------------------------------------------------------
    # Test 3: Dangerous Double-Extension Attachment via Gmail
    # -------------------------------------------------------------
    print("\n[TEST 3] Malware Attachment (.pdf.exe) via Gmail:")
    msg3 = EmailMessage()
    msg3["Message-ID"] = email.utils.make_msgid(domain="gmail.com")
    msg3["Date"] = email.utils.formatdate(localtime=True)
    msg3["From"] = "Invoice Delivery <billing-dispatch@gmail.com>"
    msg3["To"] = "ap@company.com"
    msg3["Subject"] = "Attached: March 2026 Overdue Remittance"
    msg3.set_content("Please find attached the latest invoice statement.")
    msg3.add_attachment(
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00Fake-Malware-Executable-Bytes",
        maintype="application",
        subtype="octet-stream",
        filename="overdue_invoice.pdf.exe",
    )

    d3 = engine.scan_message(
        client_ip=GMAIL_MTA_IP,
        envelope_from="billing-dispatch@gmail.com",
        envelope_rcpt="ap@company.com",
        helo_name=GMAIL_HELO,
        raw_message_bytes=msg3.as_bytes(),
    )

    print(f"  -> Sender:         {msg3['From']}")
    print(f"  -> Risk Score:     {d3.total_score} / 100")
    print(f"  -> Risk Level:     {d3.risk_level}")
    print(f"  -> Gateway Action: {d3.action}")
    print("  -> Detected Threats:")
    for r in d3.reasons:
        print(f"     * {r}")

    # -------------------------------------------------------------
    # Test 4: Legitimate Clean Email from a Friend via Gmail
    # -------------------------------------------------------------
    print("\n[TEST 4] Legitimate Clean Email via Gmail:")
    msg4 = EmailMessage()
    msg4["Message-ID"] = email.utils.make_msgid(domain="gmail.com")
    msg4["Date"] = email.utils.formatdate(localtime=True)
    msg4["From"] = "Sarah Jenkins <sarah.jenkins@gmail.com>"
    msg4["To"] = "employee@company.com"
    msg4["Subject"] = "Weekend Lunch Catchup"
    msg4.set_content("Hey! Are you free for lunch this Saturday around 1 PM? Let me know!")

    d4 = engine.scan_message(
        client_ip=GMAIL_MTA_IP,
        envelope_from="sarah.jenkins@gmail.com",
        envelope_rcpt="employee@company.com",
        helo_name=GMAIL_HELO,
        raw_message_bytes=msg4.as_bytes(),
    )

    print(f"  -> Sender:         {msg4['From']}")
    print(f"  -> Risk Score:     {d4.total_score} / 100")
    print(f"  -> Risk Level:     {d4.risk_level}")
    print(f"  -> Gateway Action: {d4.action}")
    if d4.reasons:
        print("  -> Detected Threats:")
        for r in d4.reasons:
            print(f"     * {r}")
    else:
        print("  -> Detected Threats: None (Clean)")

    print("\n" + "=" * 70)
    print(" [SUCCESS] ALL GMAIL THREAT TESTS COMPLETED AND LOGGED TO DATABASE!")
    print("=" * 70)


if __name__ == "__main__":
    run_gmail_tests()
