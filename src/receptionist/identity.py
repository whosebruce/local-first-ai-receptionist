"""Contact identity: keyed fingerprints, masking, lead IDs, log redaction.

Raw phone numbers and email addresses are never persisted or logged by this
service. Contacts are tracked by (a) an 8-character lead ID derived from the
conversation, and (b) a keyed HMAC fingerprint of the normalized address.
Trust decisions always bind lead ID + fingerprint together, so a changed
number or handle never inherits a previous grant.
"""
from __future__ import annotations

import hashlib
import hmac
import re

PHONE_RE = re.compile(r"\+?\d{7,15}")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
URL_RE = re.compile(r"https?://\S+", re.I)


def normalize_address(sender: str, default_country_code: str = "1") -> str:
    """Normalize a phone/email handle so fingerprints are stable across
    formatting differences. Never returns raw digits ungrouped to callers that
    persist data — this is an input to the keyed fingerprint only."""
    raw = (sender or "").strip().lower()
    digits = re.sub(r"\D", "", raw)
    if "@" in raw:
        return raw
    if len(digits) == 10 and default_country_code:
        return "+" + default_country_code + digits
    if len(digits) >= 7:
        return "+" + digits
    return raw


def contact_fingerprint(key: str, sender: str, default_country_code: str = "1") -> str:
    """Keyed fingerprint of the normalized address. Empty key OR a blank/
    unknown address -> empty result, so callers fail closed: an address-less
    inbound never shares a fingerprint bucket and can never match an enrolled
    owner or a fingerprint-based block."""
    if not key:
        return ""
    normalized = normalize_address(sender, default_country_code)
    if not normalized or normalized == "unknown":
        return ""
    return hmac.new(key.encode(), normalized.encode(), hashlib.sha256).hexdigest()


def lead_id(chat_id: str, sender: str) -> str:
    """Stable, non-identifying 8-char ID for a (conversation, sender) pair."""
    return hashlib.sha256(f"{chat_id}|{sender}".encode()).hexdigest()[:8].upper()


def mask_sender(sender: str) -> str:
    """Human-readable mask that never reveals the full address."""
    sender = (sender or "unknown").strip()
    if PHONE_RE.fullmatch(sender) or re.fullmatch(r"[+\d* ().-]{7,}", sender):
        digits = re.sub(r"\D", "", sender)
        return f"phone ending {digits[-4:]}" if len(digits) >= 4 else "phone ending unknown"
    if "@" in sender:
        local, _, domain = sender.partition("@")
        return f"{local[:1]}***@{domain}"
    return sender[:40] or "unknown"


_DIGIT_RUN_RE = re.compile(r"\d[\d\s().-]{4,}\d")
_TOKEN_RE = re.compile(r"\b[0-9a-fA-F]{16,}\b")


def redact(text: str) -> str:
    """Strip phone numbers and email addresses before anything is logged."""
    text = PHONE_RE.sub("[REDACTED_PHONE]", text or "")
    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    return text


def redact_audit(text: str) -> str:
    """Stronger redaction for anything derived from contact content before it is
    written to the local audit trail: phones, emails, long digit runs
    (SSNs/cards/account/codes), and long hex tokens are all masked so no raw
    PII or secret ever persists at rest."""
    text = redact(text or "")
    text = _TOKEN_RE.sub("[REDACTED_TOKEN]", text)
    text = _DIGIT_RUN_RE.sub("[REDACTED_DIGITS]", text)
    return text
