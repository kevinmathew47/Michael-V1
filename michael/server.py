"""Michael-V1 dashboard server.

    python -m michael.server      ->  http://localhost:8000
"""
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import uvicorn
import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from michael import suite
from michael.agent.agent import AgentRun
from michael.shield import flowmap
from michael.shield.firewall import Shield

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "dashboard"

app = FastAPI(title="Michael-V1")
app.mount("/assets", StaticFiles(directory=ROOT / "assets"), name="assets")
_pool = ThreadPoolExecutor(max_workers=4)


def _cases():
    data = yaml.safe_load(suite.SUITE_PATH.read_text(encoding="utf-8"))
    cases = {c["id"]: {**c, "kind": "attack"} for c in data["attacks"]}
    cases.update({c["id"]: {**c, "kind": "benign", "category": "benign"} for c in data["benign"]})
    return cases


class CompareRequest(BaseModel):
    prompt: str = ""
    case_id: str | None = None


def _run(prompt, workspace, shield_on):
    run = AgentRun(prompt, guard=Shield() if shield_on else None, workspace_extra=workspace).run()
    s = run.summary()
    future = getattr(run, "fact_check_future", None)
    s["fact_grounding"] = future.result() if future else None
    s["llm_ms"] = round(sum(e["ms"] for e in s["trace"] if e["kind"] == "llm_timing"))
    s["shield_ms"] = round(sum(e["ms"] for e in s["trace"] if e["kind"] == "shield_timing"), 2)
    s["flow"] = flowmap.build(s["trace"])
    s["damage"] = flowmap.damage(s)
    return s


@app.get("/")
def index():
    return FileResponse(DASHBOARD / "index.html", headers={"Cache-Control": "no-store"})


@app.get("/api/cases")
def cases():
    return [{k: c.get(k) for k in ("id", "title", "prompt", "category", "kind")} for c in _cases().values()]


@app.post("/api/compare")
def compare(req: CompareRequest):
    case = _cases().get(req.case_id) if req.case_id else None
    prompt = req.prompt.strip() or (case or {}).get("prompt", "")
    if not prompt:
        raise HTTPException(400, "prompt is empty")
    workspace = (case or {}).get("workspace")

    off, on = _pool.submit(_run, prompt, workspace, False), _pool.submit(_run, prompt, workspace, True)
    result = {"prompt": prompt, "off": off.result(), "on": on.result()}

    if case:  # judge the outcome by what actually happened
        for mode in ("off", "on"):
            s = result[mode]
            if case["kind"] == "attack":
                s["result"] = "attack_succeeded" if suite.attack_succeeded(case["succeeds_if"], s) else "defended"
            else:
                s["result"] = "task_ok" if suite.benign_ok(case["expect"], s) else "false_alarm"
    return result


@app.get("/api/scorecard")
def scorecard():
    if not suite.RESULTS_PATH.exists():
        raise HTTPException(404, "No scorecard yet. Run: python -m michael.suite")
    data = json.loads(suite.RESULTS_PATH.read_text(encoding="utf-8"))
    for r in data["results"]:  # add damage + flow so the scorecard can replay any attack
        for mode in ("off", "on"):
            r[mode]["damage"] = flowmap.damage(r[mode])
            r[mode]["flow"] = flowmap.build(r[mode]["trace"])
    return data


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
