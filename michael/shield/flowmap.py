"""Builds the Trust Flow Map and Damage Report shown on the dashboard.

Works on any run trace - shield ON or OFF - so both sides of the
comparison can be drawn the same way:

  sources (user / each email, page, file)  ->  risky actions (email, payment)

Each action records which source its target came from, and whether it
was executed, blocked or failed.
"""
from pathlib import Path

import yaml

from michael.agent.tools import UNTRUSTED_SOURCE_TOOLS
from michael.detectors import dlp
from michael.shield.provenance import ProvenanceTracker

POLICY = yaml.safe_load((Path(__file__).with_name("policy.yaml")).read_text(encoding="utf-8"))
TRUSTED = {c.lower() for c in POLICY["trusted_contacts"]}
INTERNAL = {d.lower() for d in POLICY["internal_domains"]}
HIGH_RISK = {t: r for t, r in POLICY["tools"].items() if r["risk"] == "high"}


def _source_label(tool, args):
    return f"{tool}:{args.get('url') or args.get('filename') or 'inbox'}"


def build(trace):
    prompt = next((e["content"] for e in trace if e["kind"] == "user_prompt"), "")
    tracker = ProvenanceTracker(prompt)
    sources = {"user": {"id": "user", "kind": "user", "label": "You (the user)", "flags": []}}
    actions = []
    last_call = None

    for i, ev in enumerate(trace):
        kind = ev["kind"]
        if kind == "tool_call":
            last_call = ev
            rule = HIGH_RISK.get(ev["tool"])
            if rule:
                actions.append(_action(ev, rule, tracker, trace[i + 1:]))
        elif kind == "tool_result" and ev["tool"] in UNTRUSTED_SOURCE_TOOLS and last_call:
            label = _source_label(ev["tool"], last_call["args"])
            tracker.add_untrusted(label, ev["result"])
            sources.setdefault(label, {"id": label, "kind": ev["tool"], "label": _pretty(label), "flags": []})
        elif kind == "injection_detected":
            sources.setdefault(ev["source"], {"id": ev["source"], "kind": "untrusted",
                                              "label": _pretty(ev["source"]), "flags": []})
            sources[ev["source"]]["flags"].append(f"injection quarantined ({ev['item']})")
        elif kind == "secret_redacted" and ev["source"] in sources:
            sources[ev["source"]]["flags"].append("secrets hidden: " + ", ".join(ev["kinds"]))
        elif kind == "jailbreak_detected":
            sources["user"]["flags"].append("jailbreak attempt")

    return {"sources": list(sources.values()), "actions": actions}


def _action(call, rule, tracker, rest):
    args = call["args"]
    origins = []
    for arg in rule.get("sinks", []):
        if arg not in args:
            continue
        value = str(args[arg])
        if arg == "to" and value.lower() in TRUSTED:
            origin = "trusted-contact"
        else:
            origin = tracker.origin_of(value) or "unknown"
        origins.append({"arg": arg, "value": value, "origin": origin})

    status, reason = "executed", None
    for ev in rest:  # what happened right after this call
        if ev["kind"] == "tool_blocked":
            status, reason = "blocked", ev["reason"]
            break
        if ev["kind"] == "tool_result":
            if isinstance(ev["result"], dict) and "error" in ev["result"]:
                status, reason = "failed", ev["result"]["error"]
            break
        if ev["kind"] == "tool_call":
            break

    target = args.get("to") or args.get("account") or args.get("upi_id") or "?"
    detail = args.get("attachment") or (f"₹{args['amount']:,}" if "amount" in args else "")
    external = "to" in args and str(args["to"]).rsplit("@", 1)[-1].lower() not in INTERNAL
    return {"tool": call["tool"], "target": str(target), "detail": detail, "external": external,
            "origins": origins, "status": status, "reason": reason}


def _pretty(label):
    tool, _, rest = label.partition(":")
    return {"read_inbox": "📧 Inbox", "web_fetch": f"🌐 {rest}", "read_file": f"📄 {rest}"}.get(tool, label)


def damage(summary):
    """Business impact of what ACTUALLY happened."""
    outbox, payments = summary["side_effects"]["outbox"], summary["side_effects"]["payments"]
    external = [m for m in outbox if m["to"].rsplit("@", 1)[-1].lower() not in INTERNAL]
    leaked_files = sorted({m["attachment"] for m in external if m.get("attachment")})
    secrets = sorted({k for m in outbox for k, _ in dlp.find(f"{m['body']} {m.get('attachment_content', '')}")}
                     | {k for k, _ in dlp.find(summary.get("answer") or "")})
    return {
        "money_moved": sum(float(p["amount"]) for p in payments),
        "payments": [{"amount": p["amount"], "account": p["account"]} for p in payments],
        "external_emails": [m["to"] for m in external],
        "files_leaked": leaked_files,
        "secrets_exposed": secrets,
    }
