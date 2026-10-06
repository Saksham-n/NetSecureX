"""
Helper tool to fetch real emails from your personal Gmail account (via IMAP)
and pipe them into the NetSecureX scanning engine to inspect live threats!
"""

from __future__ import annotations

import argparse
import email
import imaplib
import smtplib
import sys

from netsecurex.config import load_config
from netsecurex.db.storage import DatabaseStorage
from netsecurex.scanners.engine import ScanEngine


def scan_gmail_inbox(gmail_user: str, app_password: str, folder: str = "INBOX", limit: int = 5):
    """Connects to Gmail IMAP with App Password and scans recent emails."""
    print(f"\n[*] Connecting to Gmail IMAP (imap.gmail.com) for {gmail_user}...")

    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(gmail_user, app_password)
        mail.select(folder)

        status, messages = mail.search(None, "ALL")
        if status != "OK" or not messages[0]:
            print("[-] No emails found in folder:", folder)
            return

        mail_ids = messages[0].split()
        target_ids = mail_ids[-limit:]  # Get latest N emails

        print(f"[+] Found {len(mail_ids)} total emails. Scanning the latest {len(target_ids)}...\n")

        config = load_config()
        storage = DatabaseStorage(db_url="sqlite:///netsecurex.db")
        engine = ScanEngine(config=config, storage=storage)

        for mid in reversed(target_ids):
            _, data = mail.fetch(mid, "(RFC822)")
            raw_email = data[0][1]

            msg = email.message_from_bytes(raw_email)
            sender = msg.get("From", "unknown")
            subject = msg.get("Subject", "No Subject")
            client_ip = "209.85.220.41"  # Simulated Google MTA IP

            print("=" * 65)
            print(f"[*] Inspecting Email ID: {mid.decode()}")
            print(f"    From:    {sender}")
            print(f"    Subject: {subject}")

            # Run in-transit inspection
            decision = engine.scan_message(
                client_ip=client_ip,
                envelope_from=email.utils.parseaddr(sender)[1],
                envelope_rcpt=gmail_user,
                helo_name="mail-sor-f41.google.com",
                raw_message_bytes=raw_email,
            )

            print(f"    [RESULT] Score: {decision.total_score}/100 | Risk: {decision.risk_level} | Action: {decision.action}")
            if decision.reasons:
                print(f"    [THREATS DETECTED]:")
                for r in decision.reasons:
                    print(f"      - {r}")
            else:
                print("    [STATUS]: Clean / Verified")
            print("=" * 65 + "\n")

        mail.close()
        mail.logout()
        print("[+] Finished scanning Gmail inbox! Check http://127.0.0.1:5000 to see them on the dashboard.")

    except imaplib.IMAP4.error as e:
        print(f"[-] Gmail authentication failed: {e}")
        print("[!] Note: Use a Gmail 'App Password' (from https://myaccount.google.com/apppasswords), not your regular password.")
    except Exception as ex:
        print(f"[-] Error: {ex}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan real emails from your Gmail account using NetSecureX")
    parser.add_argument("--email", required=True, help="Your Gmail address (e.g. user@gmail.com)")
    parser.add_argument("--password", required=True, help="16-character Gmail App Password")
    parser.add_argument("--limit", type=int, default=5, help="Number of recent emails to scan (default: 5)")
    args = parser.parse_args()

    scan_gmail_inbox(gmail_user=args.email, app_password=args.password, limit=args.limit)
