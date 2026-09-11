"""
eml_parser.py

Parses a raw .eml file into a clean, structured dictionary that the rest
of the forensic pipeline (header forensics, indicator extraction,
correlation) can work with.

No Streamlit here. Pure Python stdlib (email package) so it can be
tested and reused independently of the UI.
"""

from __future__ import annotations
import email
from email import policy
from email.utils import parseaddr, getaddresses
from dataclasses import dataclass, field
from typing import List, Optional
import hashlib


@dataclass
class Attachment:
    filename: str
    content_type: str
    size_bytes: int
    sha256: str


@dataclass
class ParsedEmail:
    subject: str
    from_display_name: str
    from_address: str
    reply_to: Optional[str]
    return_path: Optional[str]
    to_addresses: List[str]
    date: Optional[str]
    message_id: Optional[str]
    received_chain: List[str]          # raw "Received:" header lines, top to bottom
    body_text: str
    body_html: str
    attachments: List[Attachment] = field(default_factory=list)
    raw_headers: dict = field(default_factory=dict)


def parse_eml_file(path: str) -> ParsedEmail:
    with open(path, "rb") as f:
        raw_bytes = f.read()
    return parse_eml_bytes(raw_bytes)


def parse_eml_bytes(raw_bytes: bytes) -> ParsedEmail:
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    # --- Sender / identity fields ---
    from_display_name, from_address = parseaddr(msg.get("From", ""))
    reply_to = msg.get("Reply-To")
    return_path = msg.get("Return-Path")
    to_addresses = [addr for _, addr in getaddresses([msg.get("To", "")])]
    date = msg.get("Date")
    message_id = msg.get("Message-ID")

    # --- Received chain (order = top to bottom = most recent hop first) ---
    received_chain = msg.get_all("Received", [])

    # --- Body extraction (plain + html separately) ---
    body_text = ""
    body_html = ""
    attachments: List[Attachment] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in content_disposition or part.get_filename():
                payload = part.get_payload(decode=True) or b""
                filename = part.get_filename() or "unnamed_attachment"
                attachments.append(Attachment(
                    filename=filename,
                    content_type=content_type,
                    size_bytes=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                ))
                continue

            if content_type == "text/plain" and not body_text:
                payload = part.get_payload(decode=True) or b""
                body_text = _decode_payload(payload, part)
            elif content_type == "text/html" and not body_html:
                payload = part.get_payload(decode=True) or b""
                body_html = _decode_payload(payload, part)
    else:
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True) or b""
        decoded = _decode_payload(payload, msg)
        if content_type == "text/html":
            body_html = decoded
        else:
            body_text = decoded

    raw_headers = {k: v for k, v in msg.items()}

    return ParsedEmail(
        subject=msg.get("Subject", "(no subject)"),
        from_display_name=from_display_name,
        from_address=from_address,
        reply_to=reply_to,
        return_path=return_path,
        to_addresses=to_addresses,
        date=date,
        message_id=message_id,
        received_chain=list(received_chain),
        body_text=body_text,
        body_html=body_html,
        attachments=attachments,
        raw_headers=raw_headers,
    )


def _decode_payload(payload: bytes, part) -> str:
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, TypeError):
        return payload.decode("utf-8", errors="replace")


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) != 2:
        print("Usage: python eml_parser.py <path_to.eml>")
        sys.exit(1)

    parsed = parse_eml_file(sys.argv[1])
    out = {
        "subject": parsed.subject,
        "from_display_name": parsed.from_display_name,
        "from_address": parsed.from_address,
        "reply_to": parsed.reply_to,
        "return_path": parsed.return_path,
        "to_addresses": parsed.to_addresses,
        "date": parsed.date,
        "message_id": parsed.message_id,
        "received_chain_count": len(parsed.received_chain),
        "body_text_preview": parsed.body_text[:200],
        "attachments": [a.filename for a in parsed.attachments],
    }
    print(json.dumps(out, indent=2))
