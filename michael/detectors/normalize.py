"""Undo common obfuscation before detection, so detectors see what the AI sees.

Attackers hide instructions from classifiers with tricks the LLM itself
can still read: base64 / hex blobs, zero-width characters between letters,
and look-alike Unicode. This runs in microseconds.
"""
import base64
import binascii
import re
import unicodedata

ZERO_WIDTH = re.compile(r"[​-‏⁠-⁤﻿­]")
B64_BLOB = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
HEX_BLOB = re.compile(r"\b(?:[0-9a-fA-F]{2}){12,}\b")


def _printable(raw: bytes):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if text and sum(c.isprintable() or c.isspace() for c in text) / len(text) > 0.9 else None


INSTRUCTION_WORDS = re.compile(
    r"\b(ignore|disregard|forget|bypass|override|send|email|forward|transfer|pay|wire|delete|"
    r"password|api[_ ]?key|secret|rules|instructions|system prompt)\b", re.IGNORECASE)


def decoded_parts(text: str):
    """Hidden text recovered from base64 / hex blobs - only if it reads like instructions,
    so harmless codes (coupons, IDs) aren't treated as attacks."""
    found = []
    for blob in B64_BLOB.findall(text):
        try:
            out = _printable(base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True))
        except (binascii.Error, ValueError):
            out = None
        if out and re.search(r"[A-Za-z]{3,}\s+[A-Za-z]{2,}", out):
            found.append(out)
    for blob in HEX_BLOB.findall(text):
        out = _printable(bytes.fromhex(blob))
        if out:
            found.append(out)
    return [f for f in found if INSTRUCTION_WORDS.search(f)]


MANIPULATION_RULES = {
    # pieces stored in variables, then joined and executed: a='Send x' b='to y' ... do a+b
    "instruction splitting": re.compile(
        r"(?is)(\b\w+\s*=\s*['\"].+?['\"].*?){2,}.*?\b(perform|execute|run|do|follow|carry out)\b.*?\w+\s*\+\s*\w+"),
    # claimed authority + pressure to skip the normal checks
    "authority + skip checks": re.compile(
        r"(?is)(?=.*\b(i am|i'm|this is)\s+(the|your)?\s*(ceo|cfo|cto|md|director|admin|administrator|boss|manager|it head)\b)"
        r"(?=.*\b(no time|skip|bypass|without (the )?(usual )?(check|checks|verification|approval)|"
        r"usual checks|i authori[sz]e you|don'?t verify|no need to verify)\b)"),
}


def manipulation_rules(text: str):
    """Deterministic, microsecond checks for well-known social-engineering patterns."""
    return [name for name, rule in MANIPULATION_RULES.items() if rule.search(text)]


def normalize(text: str):
    """Return (clean_text, list_of_tricks_found)."""
    tricks = []
    clean = unicodedata.normalize("NFKC", text)
    if clean != text:
        tricks.append("look-alike unicode")
    stripped = ZERO_WIDTH.sub("", clean)
    if stripped != clean:
        tricks.append("hidden zero-width characters")
    hidden = decoded_parts(stripped)
    if hidden:
        tricks.append("encoded instructions")
        stripped += "\n[decoded hidden text]: " + " | ".join(hidden)
    return stripped, tricks
