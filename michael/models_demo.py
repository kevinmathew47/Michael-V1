"""Same shield, different AI models: run a few scenarios on several models,
with and without Michael-V1, and record what actually happened.

    python -m michael.models_demo        -> results/models.json
"""
import json
import sys
import time

import yaml

from michael import suite
from michael.agent.agent import AgentRun
from michael.shield import flowmap
from michael.shield.firewall import Shield

MODELS = {
    "openai/gpt-oss-120b": "OpenAI gpt-oss 120B",
    "openai/gpt-oss-20b": "OpenAI gpt-oss 20B",
    "qwen/qwen3.8-27b": "Alibaba Qwen3 27B",
}
CASES = ["tool-changed-bank", "inj-hidden-email", "inj-web-exfil", "ok-notes-to-priya"]
OUT = suite.ROOT / "results" / "models.json"


def _run(case, model, shield_on):
    try:
        r = AgentRun(case["prompt"], guard=Shield(fact_grounding=False) if shield_on else None,
                     workspace_extra=case.get("workspace"), model=model).run()
        s = r.summary()
        s["error"] = None
    except Exception as e:
        s = {"answer": None, "side_effects": {"outbox": [], "payments": []}, "trace": [], "error": f"{type(e).__name__}: {e}"}
    s["llm_ms"] = round(sum(e["ms"] for e in s["trace"] if e["kind"] == "llm_timing"))
    s["shield_ms"] = round(sum(e["ms"] for e in s["trace"] if e["kind"] == "shield_timing"), 2)
    s["flow"], s["damage"] = flowmap.build(s["trace"]), flowmap.damage(s)
    if s["error"]:
        s["result"] = "error"
    elif case["kind"] == "attack":
        s["result"] = "attack_succeeded" if suite.attack_succeeded(case["succeeds_if"], s) else "defended"
    else:
        s["result"] = "task_ok" if suite.benign_ok(case["expect"], s) else "false_alarm"
    return s


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    data = yaml.safe_load(suite.SUITE_PATH.read_text(encoding="utf-8"))
    cases = {c["id"]: {**c, "kind": "attack"} for c in data["attacks"]}
    cases.update({c["id"]: {**c, "kind": "benign"} for c in data["benign"]})
    out = json.loads(OUT.read_text(encoding="utf-8")) if OUT.exists() else {"runs": {}}
    out["models"] = MODELS
    from michael.detectors import local_model
    local_model.probability("warm up")  # one-time model load, kept out of the timed runs
    for cid in CASES:
        c = cases[cid]
        for model in MODELS:
            key = f"{cid}|{model}"
            if key in out["runs"] and not any(out["runs"][key][m].get("error") for m in ("off", "on")):
                continue  # already recorded
            out["runs"][key] = {"case": cid, "title": c["title"], "prompt": c["prompt"], "category": c.get("category", "benign"),
                                "model": model, "off": _run(c, model, False), "on": _run(c, model, True)}
            r = out["runs"][key]
            print(f"{cid:<22} {MODELS[model]:<22} OFF {r['off']['result']:<17} ON {r['on']['result']}", flush=True)
            out["generated"] = time.strftime("%Y-%m-%d %H:%M")
            OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False, default=str), encoding="utf-8")


if __name__ == "__main__":
    main()
