"""UPI Guard: UPI IDs and upi:// payment links, the way money moves in India.

  refund-desk@okaxis           a UPI ID (VPA): name@bank-handle
  upi://pay?pa=x@ybl&am=5000   a payment link / QR code: pay x@ybl ₹5,000
  sbi-kyc@okaxls               "okaxls" imitates the real handle "okaxis"

Rules only (microseconds). The shield traces UPI IDs like bank accounts: one that
came from a WhatsApp message or email instead of the user is blocked.
"""
import re
from urllib.parse import parse_qs, unquote, urlparse

from michael.detectors.lookalike import _distance

# Bank / app handles in common use (NPCI-registered PSP handles).
KNOWN_HANDLES = {
    "okaxis", "okhdfcbank", "okicici", "oksbi", "ybl", "ibl", "axl", "paytm", "ptyes", "ptaxis", "pthdfc", "ptsbi",
    "upi", "apl", "yapl", "rapl", "axisbank", "icici", "sbi", "hdfcbank", "kotak", "kmbl", "yesbank", "yesbankltd",
    "idfcbank", "idfcfirst", "indus", "federal", "fbl", "pnb", "barodampay", "unionbank", "cnrb", "boi", "aubank",
    "rbl", "dbs", "hsbc", "sc", "citi", "freecharge", "jupiteraxis", "naviaxis", "superyes", "waicici", "wahdfcbank",
    "waaxis", "wasbi", "ikwik", "abfspay", "airtel", "jio", "postbank", "mahb", "uco", "indianbank", "iob",
    "okbizaxis", "timecosmos", "slice", "fam", "amazonpay", "gpay",
}

# A UPI ID's handle has no dot (that is what separates it from an email address).
UPI_ID = re.compile(r"(?<![\w.@-])([a-zA-Z0-9][a-zA-Z0-9._-]{1,255})@([a-zA-Z][a-zA-Z0-9]{1,63})(?![\w.@-])")
UPI_LINK = re.compile(r"upi://pay\?[^\s\"'<>)]+", re.IGNORECASE)

# Payee names that pretend to be a bank, the government or support: classic UPI scam bait.
BAIT = re.compile(r"(?i)(refund|cashback|kyc|reward|prize|lottery|helpdesk|help-desk|customer-?care|support|"
                  r"income-?tax|rbi|npci|govt|sbi-|hdfc-|icici-|axis-|electricity|bill-?update)")


def find_ids(text):
    """UPI IDs in text (lower-cased, unique, in order)."""
    seen = []
    for m in UPI_ID.finditer(text or ""):
        vpa = f"{m.group(1)}@{m.group(2)}".lower()
        if vpa not in seen:
            seen.append(vpa)
    return seen


def parse_link(link):
    """upi://pay?pa=...&pn=...&am=... -> {payee, name, amount, note}."""
    q = parse_qs(urlparse(link).query)
    get = lambda k: unquote(q.get(k, [""])[0]).strip()
    return {"payee": get("pa").lower(), "name": get("pn"), "amount": get("am"), "note": get("tn"), "link": link}


def find_links(text):
    return [parse_link(m.group().rstrip(".,;:!?")) for m in UPI_LINK.finditer(text or "")]


def _shape(s):
    """Letters that look alike in small print: rn~m, vv~w, 0~o, 1~l."""
    return s.replace("rn", "m").replace("vv", "w").replace("0", "o").replace("1", "l")


def check(vpa, trusted=()):
    """Reasons a UPI ID looks deceptive (empty list = nothing suspicious)."""
    vpa = str(vpa).strip().lower()
    if "@" not in vpa:
        return ["not a UPI ID"]
    name, handle = vpa.rsplit("@", 1)
    reasons = []
    if any(ord(ch) > 127 for ch in vpa):
        reasons.append("contains non-ASCII look-alike characters")
    if handle not in KNOWN_HANDLES:
        near = sorted(h for h in KNOWN_HANDLES if _distance(handle, h) <= 1 or _shape(handle) == h)
        reasons.append(f"handle '@{handle}' imitates the real '@{near[0]}'" if near else f"unknown bank handle '@{handle}'")
    if BAIT.search(name) and vpa not in {t.lower() for t in trusted}:
        reasons.append(f"payee name '{name}' poses as a bank, refund or support desk")
    return reasons
