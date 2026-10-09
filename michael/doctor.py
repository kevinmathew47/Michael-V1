"""Check that Michael-V1 is installed and set up correctly on this computer.

    python -m michael.doctor
"""
import importlib
import os

os.environ.setdefault("USE_TF", "0")  # same as the shield: PyTorch only
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OK, WARN, BAD = "OK  ", "WARN", "FAIL"


def _check(results, status, what, fix=""):
    results.append(status)
    print(f"  [{status}] {what}" + (f"\n         -> {fix}" if fix else ""))


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    r = []
    print("Michael-V1 doctor\n")

    v = sys.version_info
    _check(r, OK if v >= (3, 10) else BAD, f"Python {v.major}.{v.minor}", "" if v >= (3, 10) else "install Python 3.10 or newer")

    for mod, why in [("groq", "Groq API client"), ("fastapi", "dashboard"), ("uvicorn", "dashboard"), ("yaml", "policy file"),
                     ("numpy", "local model"), ("cryptography", "signed owner approvals"), ("dotenv", ".env loading")]:
        try:
            importlib.import_module(mod)
            _check(r, OK, f"{mod} ({why})")
        except ImportError:
            _check(r, BAD, f"{mod} missing ({why})", "pip install -r requirements.txt")
    try:
        importlib.import_module("sentence_transformers")
        _check(r, OK, "sentence-transformers (embedding stage of the local model)")
    except Exception:
        _check(r, WARN, "sentence-transformers missing: the local model runs its n-gram stage only",
               "pip install torch sentence-transformers  (CPU wheels are enough)")

    from michael import config
    _check(r, OK if config.GROQ_API_KEY and "your_groq" not in config.GROQ_API_KEY else BAD, "GROQ_API_KEY in .env",
           "" if config.GROQ_API_KEY and "your_groq" not in config.GROQ_API_KEY else "copy .env.example to .env and add a free key from console.groq.com")

    from michael.shield import guards, integrity, owner
    ok, why = integrity.policy_ok()
    _check(r, OK if ok else BAD, f"policy.yaml pinned ({why})", "" if ok else "after editing policy.yaml on purpose: python -m michael.shield.integrity --pin")
    from michael.agent.tools import TOOL_SCHEMAS
    reg = guards.ToolRegistry(TOOL_SCHEMAS)
    _check(r, OK if reg.ok else BAD, "tool definitions pinned", "" if reg.ok else "; ".join(reg.problems) + "  (re-pin on purpose: python -m michael.shield.guards)")

    from michael.detectors import finetune, local_model
    _check(r, OK if local_model.get() else BAD, "local model (results/local_model.npz)", "" if local_model.get() else "git pull the repo again: the file is part of it")
    ft = finetune.available()
    _check(r, OK if ft else WARN, "fine-tuned MiniLM (results/local_ft/)" + ("" if ft else ": not present, the local model uses its two smaller stages"),
           "" if ft else "optional, for full accuracy: python -m michael.detectors.finetune --download")

    _check(r, OK if owner.has_owner() else WARN, "owner account for the Owner Vault",
           "" if owner.has_owner() else "start the dashboard and open http://127.0.0.1:8765 to create it")
    try:
        with urllib.request.urlopen("http://127.0.0.1:8765/health", timeout=0.5):
            _check(r, OK, "Owner Vault running on 127.0.0.1:8765")
    except OSError:
        _check(r, WARN, "Owner Vault not running", "python -m michael.server starts it (or python -m michael.approver)")
    lock = owner.lockdown_state()
    _check(r, BAD if lock else OK, "shield " + (f"FROZEN: {lock['reason']}" if lock else "not frozen"),
           "release it in the Owner Vault after fixing the cause" if lock else "")
    if guards.kill_switch_on():
        _check(r, BAD, "kill switch is ON", "delete michael/shield/KILL or unset MICHAEL_KILL")

    bad, warn = r.count(BAD), r.count(WARN)
    print(f"\n{'Ready.' if not bad else 'Not ready yet.'} {bad} problem(s), {warn} warning(s).")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
