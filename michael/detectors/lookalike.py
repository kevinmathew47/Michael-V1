"""Look-alike domain guard: catches recipients that imitate a trusted domain.

  priya@acme-c0rp.example     (0 instead of o)       -> look-alike of acme-corp.example
  priya@acme-corp.еxample     (Cyrillic "е")         -> non-ASCII domain
  priya@xn--acme-corp-xyz.ex  (punycode)             -> encoded domain
"""
import unicodedata


def _distance(a: str, b: str) -> int:
    """Levenshtein edit distance (small strings, so the simple DP is fine)."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def check(address: str, trusted_domains):
    """Return a reason string if the address's domain looks deceptive, else None."""
    domain = str(address).rsplit("@", 1)[-1].strip().lower()
    if not domain:
        return None
    if any(ord(ch) > 127 for ch in domain):
        scripts = {unicodedata.name(ch, "?").split()[0] for ch in domain if ord(ch) > 127}
        return f"domain '{domain}' contains non-ASCII look-alike characters ({', '.join(sorted(scripts))})"
    if any(part.startswith("xn--") for part in domain.split(".")):
        return f"domain '{domain}' is punycode-encoded (can hide look-alike characters)"
    for trusted in trusted_domains:
        if domain != trusted and _distance(domain, trusted) <= 2:
            return f"domain '{domain}' imitates trusted domain '{trusted}'"
    return None
