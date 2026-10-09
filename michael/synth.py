"""Generate synthetic training examples for the local classifier.

Uses only public category / subcategory NAMES (corpus/categories.json),
never the benchmark's test cases. Output: results/synthetic.jsonl

    python -m michael.synth
"""
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor

from michael import llm
from michael.benchmark import CORPUS, ROOT

OUT = ROOT / "results" / "synthetic.jsonl"
MODEL = "qwen/qwen3.8-27b"
PER_SUB = 8

PROMPT = """You create training data for a security classifier that protects an AI agent with tools (email, files, payments, web, code, other agents).
Write {n} DIFFERENT, realistic inputs for EACH of these {kind} types:
{subs}
{guide}
Vary length (1-4 sentences), tone, wording, and fictional names/domains/numbers. Include some in Hindi or Hinglish. Do not copy famous examples word for word.
Return ONLY JSON: {{"items": [{{"type": "<type>", "text": "<input>"}}, ...]}}"""

ATTACK_GUIDE = "Each input must be an ATTACK of that type (something a security gate should block)."
BENIGN_GUIDE = ("Each input must be a LEGITIMATE request that merely LOOKS sensitive (security education, fiction with conflict, "
                "medical/legal, chemistry, pentest discussion, controversial but legitimate topics, normal coding, normal business "
                "tasks like paying a named invoice or emailing a colleague). A security gate must ALLOW all of them.")


def _batches():
    cats = json.loads((CORPUS / "categories.json").read_text(encoding="utf-8"))
    cats = cats["categories"] if isinstance(cats, dict) else cats
    attack, benign = [], []
    for c in cats:
        subs = [s["id"] if isinstance(s, dict) else s for s in c.get("subcategories", [])]
        if c["id"] in ("latency-overhead", "cost-overhead"):
            continue
        (benign if c["id"] == "over-refusal" else attack).extend(f"{c['id']}/{s}" for s in subs)
    for kind, subs, guide, label in (("attack", attack, ATTACK_GUIDE, 1), ("legitimate", benign, BENIGN_GUIDE, 0)):
        for i in range(0, len(subs), 2):
            yield kind, subs[i:i + 2], guide, label


ITEM = re.compile(r'"type"\s*:\s*"([^"]*)"\s*,\s*"text"\s*:\s*"((?:[^"\\]|\\.)*)"')


def _parse(raw):
    """Read items even from slightly malformed JSON (long generations often are)."""
    try:
        return [(it.get("type", ""), it["text"]) for it in json.loads(raw)["items"] if it.get("text")]
    except Exception:
        return [(t, json.loads(f'"{x}"')) for t, x in ITEM.findall(raw)]


def _gen(batch):
    kind, subs, guide, label = batch
    try:
        resp = llm.create(model=MODEL, temperature=0.9, reasoning_effort="none",
                          messages=[{"role": "user", "content": PROMPT.format(n=PER_SUB, kind=kind, guide=guide,
                                                                               subs="\n".join("- " + s for s in subs))}])
        raw = resp.choices[0].message.content or ""
    except Exception as e:  # keep whatever the model produced before failing
        raw = str(e)
    return [{"type": t, "text": x, "label": label} for t, x in _parse(raw)]


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    batches = list(_batches())
    with ThreadPoolExecutor(3) as pool:
        rows = [r for part in pool.map(_gen, batches) for r in part]
    OUT.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows), encoding="utf-8")
    print(f"{len(rows)} examples from {len(batches)} requests -> {OUT} "
          f"({sum(r['label'] for r in rows)} attacks, {sum(1 - r['label'] for r in rows)} legitimate)")


if __name__ == "__main__":
    main()
