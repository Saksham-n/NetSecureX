"""
Test email vectors representing various email threat scenarios for NetSecureX validation.
"""

from __future__ import annotations

from email.message import EmailMessage
import email.utils


def make_clean_email() -> EmailMessage:
    msg = EmailMessage()
    msg["Message-ID"] = email.utils.make_msgid(domain="company.com")
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["From"] = "Alice Engineer <alice@company.com>"
    msg["To"] = "Bob Developer <bob@company.com>"
    msg["Subject"] = "Weekly Sprint Planning Notes"
    msg.set_content(
        "Hi Bob,\n\nHere are the notes from today's sprint planning session. Let's touch base on Thursday.\n\nBest,\nAlice"
    )
    return msg


def make_urgency_email() -> EmailMessage:
    msg = EmailMessage()
    msg["Message-ID"] = email.utils.make_msgid(domain="vendor-notice.net")
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["From"] = "Accounts Department <billing@vendor-notice.net>"
    msg["To"] = "accounting@company.com"
    msg["Subject"] = "URGENT ACTION REQUIRED: Overdue invoice wire transfer"
    msg.set_content(
        "Dear Customer,\n\n"
        "This is a final warning. Immediate response needed regarding your overdue invoice. "
        "Your account suspended status will take effect unless immediate wire transfer or crypto payment is made.\n\n"
        "Regards,\nBilling"
    )
    return msg


def make_vip_spoof_email() -> EmailMessage:
    msg = EmailMessage()
    msg["Message-ID"] = email.utils.make_msgid(domain="gmail.com")
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["From"] = '"CEO John Doe <ceo@company.com>" <external-scammer@gmail.com>'
    msg["To"] = "finance@company.com"
    msg["Reply-To"] = "exec-reply-direct@mail.ru"
    msg["Subject"] = "Urgent confidential task for payroll direct deposit"
    msg.set_content(
        "Hello,\n\n"
        "I am currently in an executive board meeting and cannot take phone calls. "
        "I need you to process an emergency gift card purchase and update payroll direct deposit for our contractor right away.\n\n"
        "Send confirmation as soon as completed.\n\n"
        "Thanks,\nCEO John Doe"
    )
    return msg


def make_lookalike_email() -> EmailMessage:
    msg = EmailMessage()
    msg["Message-ID"] = email.utils.make_msgid(domain="c0mpany.com")
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["From"] = "IT Helpdesk <support@c0mpany.com>"
    msg["To"] = "victim@company.com"
    msg["Subject"] = "IT Notice: Verify your password now"
    msg.set_content(
        "Hello User,\n\n"
        "An unauthorized sign-in attempt was detected on your account. "
        "Please visit http://login.company.com.account-verification.xyz/reset-password-now to keep your account active.\n\n"
        "IT Support Team"
    )
    return msg


def make_attachment_threat_email() -> EmailMessage:
    msg = EmailMessage()
    msg["Message-ID"] = email.utils.make_msgid(domain="external-drop.org")
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["From"] = "Invoice Delivery <billing@external-drop.org>"
    msg["To"] = "ap@company.com"
    msg["Subject"] = "Attached Overdue Invoice - Payment Remittance"
    msg.set_content("Please find attached the latest statement for payment.")

    # Attach fake executable disguised as PDF
    fake_exe_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00This is a simulated malware binary payload for testing."
    msg.add_attachment(
        fake_exe_payload,
        maintype="application",
        subtype="octet-stream",
        filename="invoice_march_2026.pdf.exe",
    )
    return msg
