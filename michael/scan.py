"""Posture scan: audit a Michael-V1 deployment BEFORE it runs (graded A-F).

The runtime shield stops attacks while the agent works; this scan catches
configuration mistakes that would weaken it - similar in spirit to static
agent-config scanners such as affaan-m/agentshield.

    python -m michael.scan            # text report
    python -m michael.scan --json     # also writes results/posture.json
"""
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

from michael.agent.tools import TOOL_SCHEMAS
from michael.detectors import dlp
from michael.shield import guards, integrity

ROOT = Path(__file__).resolve().parents[1]
DEDUCT = {"critical": 25, "high": 15, "medium": 5, "low": 2, "info": 0}
SKIP_DIRS = {".git", "external", "results", "__pycache__", "node_modules", ".claude", "docs"}
TEXT_EXT = {".py", ".yaml", ".yml", ".json", ".md", ".txt", ".html", ".js", ".toml", ".cfg", ".ini", ".env"}


def _tracked(path):
    try:
        out = subprocess.run(["git", "ls-files", "--error-unmatch", path], cwd=ROOT, capture_output=True)
        return out.returncode == 0
    except OSError:
        return False


def scan():
    findings, defenses = [], []
    add = lambda sev, area, what, fix: findings.append({"severity": sev, "area": area, "finding": what, "fix": fix})

    # 1. secrets ---------------------------------------------------------------
    for f in ROOT.rglob("*"):
        if f.is_dir() or any(p in SKIP_DIRS for p in f.relative_to(ROOT).parts) or f.suffix not in TEXT_EXT:
            continue
        if f.name == ".env":
            continue  # local secrets file: checked separately below
        text = f.read_text(encoding="utf-8", errors="ignore")
        for kind, hit in dlp.find(text):
            if kind in ("api_key", "private_key") and "DEMOFAKE" not in hit and "workspace.json" not in f.name:
                add("critical", "secrets", f"{kind} hardcoded in {f.relative_to(ROOT)} ({hit[:8]}…)",
                    "Move it to .env / an environment variable and rotate the key")
    for secret in (".env", "michael/shield/.approval_key"):
        if _tracked(secret):
            add("critical", "secrets", f"{secret} is committed to git", "git rm --cached it, add to .gitignore, rotate")
        elif (ROOT / secret).exists():
            defenses.append(f"{secret} present locally and not committed")

    # 2. policy ------------------------------------------------------------------
    ok, why = integrity.policy_ok()
    (defenses.append("policy.yaml pinned by SHA-256") if ok else
     add("critical", "policy", why, "Review the change, then: python -m michael.shield.integrity --pin"))
    policy = yaml.safe_load((ROOT / "michael/shield/policy.yaml").read_text(encoding="utf-8"))
    tools = policy.get("tools", {})
    for s in TOOL_SCHEMAS:
        name = s["function"]["name"]
        rule = tools.get(name)
        if not rule:
            add("high", "policy", f"tool '{name}' has no policy rule (treated as high risk by default)",
                "Add it to policy.yaml with a risk level and sinks")
        elif rule.get("risk") == "high" and not rule.get("sinks"):
            add("high", "policy", f"high-risk tool '{name}' has no sink checks", "List the arguments that pick a target")
        elif rule.get("risk") == "low" and re.search(r"(?i)send|pay|delete|write|transfer|execute", s["function"].get("description", "")):
            add("medium", "policy", f"tool '{name}' looks like it acts but is marked low risk", "Mark it high risk")
    limits = policy.get("limits", {})
    for key in ("max_risky_actions_per_task", "max_payment_per_task", "max_tool_calls_per_task"):
        (defenses.append(f"limit {key} = {limits[key]}") if key in limits else
         add("medium", "policy", f"no {key}", f"Set limits.{key} in policy.yaml"))
    if policy.get("injection_threshold", 0.5) > 0.6:
        add("medium", "policy", "injection_threshold above 0.6 lets more injections through", "Use 0.5")
    internal = set(policy.get("internal_domains", []))
    for c in policy.get("trusted_contacts", []):
        if c.rsplit("@", 1)[-1] not in internal:
            add("low", "policy", f"trusted contact '{c}' is outside the company domains", "Confirm it is intended")

    # 3. tools: poisoning, rug pull, shadowing --------------------------------------
    reg = guards.ToolRegistry(TOOL_SCHEMAS)
    for p in reg.problems:
        add("critical" if ("poisoning" in p or "rug pull" in p) else "high", "tools", p,
            "Inspect the tool definition; if the change is intended: python -m michael.shield.guards")
    if reg.ok:
        defenses.append(f"{len(TOOL_SCHEMAS)} tool definitions pinned and clean")

    # 4. exposure ------------------------------------------------------------------
    server = (ROOT / "michael/server.py").read_text(encoding="utf-8")
    if re.search(r'host\s*=\s*"0\.0\.0\.0"', server):
        add("high", "exposure", "console binds to 0.0.0.0 (reachable from the network)", 'Bind to "127.0.0.1"')
    else:
        defenses.append("console bound to localhost")
    if guards.kill_switch_on():
        add("info", "runtime", "kill switch is ON: all risky actions are frozen", "Remove michael/shield/KILL to resume")

    # 5. supply chain --------------------------------------------------------------
    reqs = (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    loose = [r for r in reqs if r.strip() and "==" not in r]
    if loose:
        add("medium", "supply chain", f"{len(loose)} dependencies not pinned to exact versions ({', '.join(r.split('>')[0] for r in loose[:4])}…)",
            "Pin exact versions (==) and review updates before upgrading")

    # 6. audit -----------------------------------------------------------------------
    agent = (ROOT / "michael/agent/agent.py").read_text(encoding="utf-8")
    (defenses.append("hash-chained audit log enabled") if "event_hash" in agent else
     add("high", "audit", "audit log is not hash-chained", "Enable integrity.event_hash in AgentRun.log"))

    score = max(0, 100 - sum(DEDUCT[f["severity"]] for f in findings))
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    order = list(DEDUCT)
    return {"score": score, "grade": grade, "findings": sorted(findings, key=lambda f: order.index(f["severity"])),
            "defenses": defenses}


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    r = scan()
    print(f"\nMichael-V1 posture scan   Grade {r['grade']}  ({r['score']}/100)\n")
    for f in r["findings"]:
        print(f"  [{f['severity'].upper():8}] {f['area']:12} {f['finding']}\n  {'':10} fix: {f['fix']}")
    print("\n  Recognized defenses:")
    for d in r["defenses"]:
        print(f"    + {d}")
    if "--json" in sys.argv:
        (ROOT / "results" / "posture.json").write_text(json.dumps(r, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
