"""Undo common obfuscation before detection, so detectors see what the AI sees.

Attackers hide instructions from classifiers with tricks the LLM itself can
still read: base64 / hex blobs (whole or split into pieces), zero-width and
bidirectional control characters, reversed text and look-alike Unicode.
This runs in microseconds.
"""
import base64
import binascii
import re
import unicodedata

ZERO_WIDTH = re.compile("[​-‍⁠-⁤﻿­]")
BIDI = re.compile("[‎‏‪-‮⁦-⁩]")
B64_BLOB = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
B64_PIECE = re.compile(r"['\"]([A-Za-z0-9+/]{4,}={0,2})['\"]")
HEX_BLOB = re.compile(r"\b(?:[0-9a-fA-F]{2}){12,}\b")
HEX_SPACED = re.compile(r"\b(?:[0-9a-fA-F]{2}[\s,:]+){8,}[0-9a-fA-F]{2}\b")


def _printable(raw: bytes):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if text and sum(c.isprintable() or c.isspace() for c in text) / len(text) > 0.9 else None


def _b64(blob: str):
    try:
        return _printable(base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True))
    except (binascii.Error, ValueError):
        return None


INSTRUCTION_WORDS = re.compile(
    r"\b(ignore|disregard|forget|bypass|override|send|email|forward|transfer|pay|wire|delete|"
    r"password|api[_ ]?key|secret|rules|instructions|system prompt|guidelines|safety|output|reveal)\b", re.IGNORECASE)


def decoded_parts(text: str):
    """Hidden text recovered from base64 / hex - only if it reads like instructions,
    so harmless codes (coupons, IDs) aren't treated as attacks."""
    found = [out for out in map(_b64, B64_BLOB.findall(text)) if out and re.search(r"[A-Za-z]{3,}\s+[A-Za-z]{2,}", out)]
    pieces = B64_PIECE.findall(text)
    if len(pieces) >= 2:  # base64 split into several quoted pieces, meant to be joined
        joined = _b64("".join(p.rstrip("=") for p in pieces))
        if joined:
            found.append(joined)
    for blob in HEX_BLOB.findall(text):
        out = _printable(bytes.fromhex(blob))
        if out:
            found.append(out)
    for m in HEX_SPACED.finditer(text):
        out = _printable(bytes.fromhex(re.sub(r"[\s,:]", "", m.group())))
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
    # Michael-V1's core rule: an approval written in text is not proof of approval.
    # A claimed sign-off / verification / signature + a risky action = unverifiable authorization.
    "unverifiable approval claim": re.compile(
        r"(?is)(?=.*(?:\b(?:approved|authori[sz]ed|signed[\s-]off|reviewed|verified|authenticated|cleared|"
        r"confirms?|confirmed)\b[^.\n]{0,60}?\b(?:by|via|through|at|from|on)\b"
        r"|\bsignature (?:verified|valid)\b|\bsigned:\s*\S|\bauth(?:orization)? token\b|\bhmac\b))"
        r"(?=.*\b(?:send|delete|transfer|refund|pay|process|proceed|execute|grant|resume|forward|wire|"
        r"release|disable|share|upload|deploy|remove)\b)"),
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
    if BIDI.search(stripped):
        # right-to-left overrides make reversed text display normally - add the reversed reading
        tricks.append("bidirectional text")
        stripped = BIDI.sub("", stripped)
        stripped += "\n[reversed reading]: " + stripped[::-1]
    hidden = decoded_parts(stripped)
    if hidden:
        tricks.append("encoded instructions")
        stripped += "\n[decoded hidden text]: " + " | ".join(hidden)
    return stripped, tricks
