"""Self-protection for the shield itself.

1. Policy pinning: policy.yaml is pinned by its SHA-256 in policy.lock. If the
   policy is edited (e.g. an attacker adds themselves to trusted_contacts), the
   hash no longer matches and the shield refuses all risky actions (fail closed)
   until a human re-pins it on purpose:

       python -m michael.shield.integrity --pin

2. Tamper-evident audit log: every trace event carries the hash of the event
   before it (a hash chain). Editing, deleting or reordering any event breaks
   the chain, which verify_chain() detects.
"""
import hashlib
import json
import sys
from pathlib import Path

POLICY_PATH = Path(__file__).with_name("policy.yaml")
LOCK_PATH = Path(__file__).with_name("policy.lock")
GENESIS = "0" * 64


def policy_hash(path=POLICY_PATH) -> str:
    # Line endings are normalized so a Windows checkout (CRLF) hashes the same as LF.
    return hashlib.sha256(Path(path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def policy_ok(path=POLICY_PATH, lock=LOCK_PATH):
    """(ok, reason). Missing or mismatching lock = not ok."""
    lock = Path(lock)
    if not lock.exists():
        return False, "policy.lock missing - policy integrity cannot be verified"
    pinned = lock.read_text(encoding="utf-8").strip()
    actual = policy_hash(path)
    if pinned != actual:
        return False, f"policy.yaml was modified (hash {actual[:12]}… != pinned {pinned[:12]}…)"
    return True, "policy hash verified"


def pin(path=POLICY_PATH, lock=LOCK_PATH):
    Path(lock).write_text(policy_hash(path) + "\n", encoding="utf-8")


# --- audit hash chain --------------------------------------------------------

def event_hash(prev: str, event: dict) -> str:
    body = {k: v for k, v in event.items() if k != "h"}
    data = prev + json.dumps(body, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def verify_chain(trace):
    """(ok, index_of_first_bad_event or None)."""
    prev = GENESIS
    for i, ev in enumerate(trace):
        if ev.get("h") != event_hash(prev, ev):
            return False, i
        prev = ev["h"]
    return True, None


if __name__ == "__main__":
    if "--pin" in sys.argv:
        pin()
        print(f"Pinned policy.yaml: {policy_hash()}")
    else:
        ok, why = policy_ok()
        print(("OK: " if ok else "FAIL: ") + why)
