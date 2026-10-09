"""Data-leak prevention: finds secrets and personal data with fast regex rules.

Rules only - no model calls - so a scan takes microseconds.
"""
import re

PATTERNS = {
    "api_key":     re.compile(r"\b(?:sk-(?:live|test|proj)?-?[A-Za-z0-9]{16,}|gsk_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,})\b"),
    "password":    re.compile(r"(?i)\w*(?:password|passwd|pwd)\s*[=:]\s*\S+"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    # 12 digits, not part of a longer number (so card numbers don't match)
    "aadhaar":     re.compile(r"(?<!\d)(?<!\d[ -])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![ -]?\d)"),
    "pan":         re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
    "card_number": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
}


def _luhn_ok(digits: str) -> bool:
    nums = [int(d) for d in digits][::-1]
    total = sum(n if i % 2 == 0 else (n * 2 - 9 if n * 2 > 9 else n * 2) for i, n in enumerate(nums))
    return total % 10 == 0


def find(text: str):
    """Return a list of (kind, matched_text) found in text."""
    hits = []
    for kind, pattern in PATTERNS.items():
        for m in pattern.finditer(text or ""):
            if kind == "card_number" and not _luhn_ok(re.sub(r"\D", "", m.group())):
                continue
            hits.append((kind, m.group()))
    return hits


def redact(text: str):
    """Mask secrets so they never reach the LLM. Returns (clean_text, kinds_found)."""
    kinds = []
    for kind, matched in find(text):
        text = text.replace(matched, f"[REDACTED:{kind}]")
        kinds.append(kind)
    return text, kinds
