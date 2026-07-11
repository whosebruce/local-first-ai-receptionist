"""Tier 1: deterministic, no-LLM front desk.

Every unknown contact lands here. Classification is a fixed allowlist of FAQ
categories answered from operator-supplied response text; anything sensitive,
escalatory, or unclassifiable gets a bounded acknowledgment and is relayed to
the owner. No model is ever invoked on Tier-1 traffic.
"""
from __future__ import annotations

import re
from typing import Any

from .identity import URL_RE

# Generic FAQ response templates. Operators replace these with their own text
# via config `faq_responses`; `{business_name}` and `{assistant_name}` are
# substituted at load time. None of this text may contain private data.
DEFAULT_FAQ_RESPONSES = {
    "greeting": (
        "Hi, this is {assistant_name}, the digital assistant for {business_name}. "
        "How can I help you today?"
    ),
    "services": (
        "{business_name} offers the services listed on our public site. Tell me a "
        "little about what you need and I can point you to the best starting place."
    ),
    "pricing": (
        "Pricing depends on scope, and the owner reviews every quote before it is "
        "offered. Tell me what you're looking for and I'll relay it for review."
    ),
    "booking": (
        "The best first step is a short intake: 1) what you do, 2) what you need "
        "help with, and 3) any timing constraints. I'll relay it to the owner for "
        "review before anything is scheduled or paid."
    ),
    "privacy": (
        "{business_name} takes privacy seriously. Please do not send passwords, "
        "verification codes, account numbers, or sensitive records by text."
    ),
    "location": (
        "Location and availability details are on our public site; the owner "
        "confirms scheduling directly. I've relayed your question."
    ),
    "ack": (
        "Thanks for reaching out. I've relayed your message to the owner. Anything "
        "involving a commitment, schedule, or quote gets a human review first."
    ),
}

ESCALATION_TERMS = re.compile(
    r"\b(lawyer|legal|lawsuit|contract|refund|complaint|angry|fraud|scam|"
    r"emergency|urgent|911|police|medical|injur(?:y|ed)|suicide|threat|"
    r"password|passcode|verification code|2fa|account number|social security|"
    r"credit card|bank|routing|wire|crypto|invoice|payment link|discount|"
    r"guarantee|promise|deadline)\b",
    re.I,
)
INVOICE_REQUEST_RE = re.compile(r"\b(invoice|payment link|pay(?:ment)?|credit card|bank|wire)\b", re.I)
THANKS_RE = re.compile(r"^\s*(thanks|thank you|thx|ty|ok|okay|got it|sounds good)[!. ]*$", re.I)


def build_faq(config: dict[str, Any]) -> dict[str, str]:
    responses = dict(DEFAULT_FAQ_RESPONSES)
    responses.update(config.get("faq_responses") or {})
    subs = {
        "business_name": str(config.get("business_name") or "this business"),
        "assistant_name": str(config.get("assistant_name") or "the assistant"),
    }
    return {key: text.format(**subs) for key, text in responses.items()}


def classify(text: str) -> str | None:
    """Return an allowlisted FAQ key, 'ack', or None for intentional silence."""
    clean = " ".join((text or "").strip().split())
    low = clean.lower()
    if not clean or THANKS_RE.match(clean):
        return None
    if len(clean) > 2000 or URL_RE.search(clean) or ESCALATION_TERMS.search(clean):
        return "ack"
    if re.search(r"\b(price|pricing|cost|how much|rate|rates|charge|budget)\b", low):
        return "pricing"
    if re.search(r"\b(book|booking|schedule|appointment|consult|consultation|start|get started|next step)\b", low):
        return "booking"
    if re.search(r"\b(private|privacy|secure|security|data)\b", low):
        return "privacy"
    if re.search(r"\b(where|location|located|remote|virtual|in person)\b", low):
        return "location"
    if re.search(r"\b(service|services|offer|offers|what do you do|help with)\b", low):
        return "services"
    if re.search(r"^(hi|hello|hey|good morning|good afternoon|good evening|yo)\b", low):
        return "greeting"
    return "ack"


def is_invoice_request(text: str) -> bool:
    """Invoice/payment interest is owner-alert-only; nothing is ever
    auto-invoiced, auto-quoted, or auto-charged by this service."""
    return bool(INVOICE_REQUEST_RE.search(text or ""))
