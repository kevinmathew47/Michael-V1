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


# Verhoeff checksum - the algorithm UIDAI uses for the last digit of every Aadhaar.
# Validating it means random 12-digit numbers (order IDs, phone+code) aren't flagged.
_V_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
        [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
        [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
_V_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
        [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]


def _verhoeff_ok(digits: str) -> bool:
    c = 0
    for i, d in enumerate(reversed(digits)):
        c = _V_D[c][_V_P[i % 8][int(d)]]
    return c == 0


_VALIDATORS = {
    "card_number": _luhn_ok,
    "aadhaar": _verhoeff_ok,
}


def find(text: str):
    """Return a list of (kind, matched_text) found in text."""
    hits = []
    for kind, pattern in PATTERNS.items():
        for m in pattern.finditer(text or ""):
            check = _VALIDATORS.get(kind)
            if check and not check(re.sub(r"\D", "", m.group())):
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
