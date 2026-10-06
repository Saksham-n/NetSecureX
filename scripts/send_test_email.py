"""
CLI tool for sending test email vectors to the NetSecureX scanning gateway.
"""

from __future__ import annotations

import argparse
import smtplib
import sys

from scripts.test_vectors import (
    make_clean_email,
    make_urgency_email,
    make_vip_spoof_email,
    make_lookalike_email,
    make_attachment_threat_email,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Inject test email vectors into NetSecureX Gateway")
    parser.add_argument("--host", default="127.0.0.1", help="Gateway host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=10025, help="Gateway port (default: 10025)")
    parser.add_argument(
        "--vector",
        choices=["clean", "urgency", "vip_spoof", "lookalike", "attachment", "all"],
        default="clean",
        help="Test vector to inject",
    )
    parser.add_argument("--from-addr", help="Override envelope sender")
    parser.add_argument("--to-addr", help="Override envelope recipient")
    args = parser.parse_args()

    vector_map = {
        "clean": ("Clean Email", make_clean_email, "alice@company.com", "bob@company.com"),
        "urgency": ("Urgency & Extortion Phish", make_urgency_email, "billing@vendor-notice.net", "accounting@company.com"),
        "vip_spoof": ("VIP Executive Impersonation", make_vip_spoof_email, "external-scammer@gmail.com", "finance@company.com"),
        "lookalike": ("Lookalike Domain Phish", make_lookalike_email, "support@c0mpany.com", "victim@company.com"),
        "attachment": ("Dangerous Binary Attachment", make_attachment_threat_email, "billing@external-drop.org", "ap@company.com"),
    }

    targets = list(vector_map.keys()) if args.vector == "all" else [args.vector]

    print(f"\n[NetSecureX Test Harness] Connecting to SMTP Gateway at {args.host}:{args.port}...\n")

    for key in targets:
        name, generator, def_from, def_to = vector_map[key]
        mail_from = args.from_addr or def_from
        rcpt_to = args.to_addr or def_to
        msg = generator()

        print(f"--> Sending Vector: [{key.upper()}] - {name}")
        print(f"    MAIL FROM: <{mail_from}>")
        print(f"    RCPT TO:   <{rcpt_to}>")
        print(f"    Subject:   {msg['Subject']}")

        try:
            with smtplib.SMTP(host=args.host, port=args.port, timeout=10.0) as client:
                client.set_debuglevel(0)
                client.ehlo("tester.local")
                code, resp = client.sendmail(
                    from_addr=mail_from,
                    to_addrs=[rcpt_to],
                    msg=msg.as_bytes(),
                )
                print(f"    [RESULT] SMTP Response: Code 250 Accepted (Downstream queued/tagged)\n")
        except smtplib.SMTPResponseException as e:
            print(f"    [RESULT] SMTP Response: Code {e.smtp_code} {e.smtp_error.decode('utf-8', errors='replace')}\n")
        except Exception as ex:
            print(f"    [ERROR] Connection error: {ex}\n")


if __name__ == "__main__":
    main()
