"""The owner's private channel: approvals and system lockdown.

The agent's dashboard is not a safe place to ask "should I run this?": a page can be
injected, clicked by a script, or shown to the wrong person. So Michael-V1 asks the
owner somewhere else:

  * The Approver (python -m michael.approver) is a separate app on 127.0.0.1:8765,
    behind an owner PIN. The agent can't reach it (its web tool blocks localhost).
  * Approvals are signed with an Ed25519 private key kept in the owner's home folder
    (~/.michael), outside the project. The shield only has the PUBLIC key, so even a
    fully compromised agent or dashboard can verify approvals but never forge one.
  * A signature covers the exact action (tool + every argument), expires after
    10 minutes and works once.

Lockdown: when the shield itself is attacked (policy edited, tool swapped, forged
approval, kill switch), every tool call of every task is frozen until the owner
unlocks it in the Approver.
"""
import base64
import hashlib
import json
import os
import secrets
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

HERE = Path(__file__).parent
OWNER_HOME = Path(os.getenv("MICHAEL_OWNER_HOME") or Path.home() / ".michael")  # private: never in the repo
PRIVATE_KEY = OWNER_HOME / "owner_ed25519.pem"
PIN_FILE = OWNER_HOME / "owner_pin"
PUBLIC_KEY = HERE / "owner.pub"
STORE = HERE / ".approvals"
LOCKDOWN_FILE = HERE / "LOCKDOWN"
TTL = 600  # seconds an approval stays valid


def _action(tool, args):
    return json.dumps({"tool": tool, "args": args}, sort_keys=True, ensure_ascii=False, default=str)


def action_hash(tool, args):
    return hashlib.sha256(_action(tool, args).encode()).hexdigest()


# --- keys and PIN (Approver side) -------------------------------------------------

def ensure_owner_keys():
    """Create the owner's key pair on first run. Private key stays in OWNER_HOME."""
    OWNER_HOME.mkdir(parents=True, exist_ok=True)
    if not PRIVATE_KEY.exists():
        key = Ed25519PrivateKey.generate()
        PRIVATE_KEY.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
        try:
            os.chmod(PRIVATE_KEY, 0o600)
        except OSError:
            pass
    key = serialization.load_pem_private_key(PRIVATE_KEY.read_bytes(), password=None)
    PUBLIC_KEY.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                         serialization.PublicFormat.SubjectPublicKeyInfo))
    return key


def _pin_hash(pin, salt):
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, 200_000).hex()


def set_owner(user, password):
    """Create or replace the owner account (username + salted PBKDF2 password hash)."""
    OWNER_HOME.mkdir(parents=True, exist_ok=True)
    salt = secrets.token_bytes(16)
    PIN_FILE.write_text(json.dumps({"user": str(user).strip().lower(), "salt": salt.hex(),
                                    "hash": _pin_hash(str(password), salt)}), encoding="utf-8")


def has_owner():
    return PIN_FILE.exists()


def owner_user():
    if not PIN_FILE.exists():
        return None
    return json.loads(PIN_FILE.read_text(encoding="utf-8")).get("user") or "admin"


def set_pin(pin):  # older name: password only, username "admin"
    set_owner(owner_user() or "admin", pin)


def check_pin(pin):
    """Password check (used by the terminal commands)."""
    if not PIN_FILE.exists():
        return False
    rec = json.loads(PIN_FILE.read_text(encoding="utf-8"))
    return secrets.compare_digest(rec["hash"], _pin_hash(str(pin), bytes.fromhex(rec["salt"])))


def check_login(user, password):
    ok_user = secrets.compare_digest(str(user or "").strip().lower(), owner_user() or "\0")
    return check_pin(password) and ok_user


def _public_key():
    if not PUBLIC_KEY.exists():
        return None
    return serialization.load_pem_public_key(PUBLIC_KEY.read_bytes())


def approver_ready():
    return PUBLIC_KEY.exists()


# --- approval requests --------------------------------------------------------

def _path(req_id):
    return STORE / f"{req_id}.json"


def _save(rec):
    STORE.mkdir(exist_ok=True)
    _path(rec["id"]).write_text(json.dumps(rec, ensure_ascii=False, indent=1), encoding="utf-8")


def get(req_id):
    p = _path(str(req_id))
    if not req_id or not str(req_id).isalnum() or not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def all_requests():
    if not STORE.exists():
        return []
    recs = [json.loads(p.read_text(encoding="utf-8")) for p in STORE.glob("*.json")]
    now = time.time()
    for r in recs:
        if r["status"] == "pending" and now > r["expires"]:
            r["status"] = "expired"
    return sorted(recs, key=lambda r: -r["created"])


def request(tool, args, reason):
    """Filed by the shield. Returns the request (with a 2-digit matching code)."""
    now = time.time()
    rec = {"id": secrets.token_hex(5), "code": f"{secrets.randbelow(90) + 10}", "tool": tool, "args": args,
           "reason": reason, "hash": action_hash(tool, args), "status": "pending",
           "created": now, "expires": now + TTL, "signature": None, "used": False}
    _save(rec)
    return rec


def _message(rec):
    return json.dumps({"id": rec["id"], "hash": rec["hash"], "expires": rec["expires"]}, sort_keys=True).encode()


def decide(req_id, approve, code, private_key):
    """Approver side: the owner typed the code shown next to the request and decided."""
    rec = get(req_id)
    if not rec or rec["status"] != "pending" or time.time() > rec["expires"]:
        return None, "request is not pending (expired or already decided)"
    if str(code).strip() != rec["code"]:
        return None, "the code does not match the one shown with the request"
    if approve:
        rec["status"] = "approved"
        rec["signature"] = base64.b64encode(private_key.sign(_message(rec))).decode()
    else:
        rec["status"] = "denied"
    rec["decided"] = time.time()
    _save(rec)
    return rec, None


def verify(rec, tool, args):
    """Shield side: exact action, not expired, not used, valid owner signature."""
    if not rec or rec.get("status") != "approved" or rec.get("used") or time.time() > rec["expires"]:
        return False
    if rec["hash"] != action_hash(tool, args):
        return False
    key = _public_key()
    if key is None or not rec.get("signature"):
        return False
    try:
        key.verify(base64.b64decode(rec["signature"]), _message(rec))
        return True
    except (InvalidSignature, ValueError):
        return False


def consume(tool, args):
    """If the owner signed this exact action, use the approval (once) and return it."""
    h = action_hash(tool, args)
    for rec in all_requests():
        if rec["hash"] == h and verify(rec, tool, args):
            rec["used"], rec["status"] = True, "used"
            _save(rec)
            return rec
    return None


# --- system lockdown ---------------------------------------------------------------

def lockdown_state():
    if not LOCKDOWN_FILE.exists():
        return None
    try:
        return json.loads(LOCKDOWN_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"reason": "lockdown file present", "since": None}


def trip(reason, source="shield"):
    """Freeze every task. Keeps the first reason (the original attack)."""
    if not LOCKDOWN_FILE.exists():
        LOCKDOWN_FILE.write_text(json.dumps({"reason": reason, "source": source, "since": time.time()},
                                            ensure_ascii=False), encoding="utf-8")


def release():
    """Approver only (after the owner's PIN)."""
    LOCKDOWN_FILE.unlink(missing_ok=True)
