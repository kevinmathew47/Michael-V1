"""Fact-check layer: catches the agent claiming things it didn't do or read.

Two parts, split for speed:

1. Action check (sync, rules only, <1 ms) - runs before the answer is shown.
   Finds sentences like "I've sent / replied / paid ..." and checks them
   against the tool calls that REALLY ran (blocked calls don't count).

2. Fact grounding (async, small LLM) - runs in the background after the
   answer is shown, so it never delays the user. A fast model extracts
   factual claims plus a supporting quote; code then verifies the quote
   really exists in the data the tools returned.
"""
import json
import re
from concurrent.futures import ThreadPoolExecutor

from michael import llm

MODEL = "openai/gpt-oss-20b"

_pool = ThreadPoolExecutor(max_workers=2)

# "I've sent", "I have replied", "I also forwarded", "I paid" ...
ACTION_CLAIM = re.compile(
    r"\bI(?:['’]ve| have)?\s+(?:already\s+|also\s+|just\s+|now\s+)?"
    r"(sent|emailed|replied|responded|forwarded|paid|transferred|made (?:a|the) payment)\b",
    re.IGNORECASE,
)
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
GENERIC_TOKENS = {"example", "com", "org", "net", "mail", "team", "corp"}


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", str(text)).strip().lower()


def _tokens(address: str):
    return {t for t in re.split(r"[@._\-]+", address.lower()) if len(t) >= 4 and t not in GENERIC_TOKENS}


def _executed_actions(trace):
    """Tool calls that really ran (not blocked, no error)."""
    done, last_call = [], None
    for ev in trace:
        if ev["kind"] == "tool_call":
            last_call = ev
        elif ev["kind"] == "tool_result" and last_call and last_call["tool"] == ev["tool"]:
            result = ev["result"]
            if not (isinstance(result, dict) and "error" in result):
                done.append(last_call)
    return done


def _flatten(value):
    """All string values inside a tool result, as plain text."""
    if isinstance(value, dict):
        return "\n".join(_flatten(v) for v in value.values())
    if isinstance(value, list):
        return "\n".join(_flatten(v) for v in value)
    return str(value)


def _sources(trace):
    return "\n".join(_flatten(ev["result"]) for ev in trace if ev["kind"] == "tool_result")


def _sentences(text):
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", text) if s.strip()]


# --- 1. action check (sync) -------------------------------------------------

def check_actions(answer, trace):
    executed = _executed_actions(trace)
    known_people = set()  # name-like tokens of every address the agent has seen
    for addr in EMAIL.findall(_sources(trace) + json.dumps([a["args"] for a in executed])):
        known_people |= _tokens(addr)

    claims = []
    for sentence in _sentences(answer):
        m = ACTION_CLAIM.search(sentence)
        if not m:
            continue
        verb = m.group(1).lower()
        tool = "make_payment" if verb in ("paid", "transferred") or "payment" in verb else "send_email"
        candidates = [a for a in executed if a["tool"] == tool]
        words = set(re.findall(r"\w+", sentence.lower()))
        explicit = EMAIL.findall(sentence)

        if explicit:
            ok = any(any(e.lower() in _norm(json.dumps(a["args"])) for e in explicit) for a in candidates)
        elif words & known_people:
            # sentence names someone - an action to THAT person must have happened
            ok = any(words & _tokens(str(a["args"].get("to") or a["args"].get("account") or ""))
                     for a in candidates)
        else:
            ok = bool(candidates)
        claims.append({"text": sentence, "type": "action", "verdict": "verified" if ok else "false"})
    return claims


# --- 2. fact grounding (async) ----------------------------------------------

EXTRACT_PROMPT = """Extract factual claims the ASSISTANT ANSWER makes about the user's emails, files or web pages.
For each, give the shortest EXACT substring of SOURCES that supports it, or null if none does.
Skip offers, questions, greetings and statements about the assistant itself. At most 6 claims.
Return JSON: {"claims": [{"text": str, "quote": str | null}]}

SOURCES:
{sources}

ASSISTANT ANSWER:
{answer}"""


def _quote_found(quote, sources_norm):
    q = _norm(quote or "")
    if not q:
        return False
    if q in sources_norm:
        return True
    words = re.findall(r"\w+", q)  # tolerate tiny paraphrases
    return bool(words) and sum(w in sources_norm for w in words) / len(words) >= 0.8


def check_facts(answer, trace):
    sources = _sources(trace)
    if not sources:
        return []
    try:
        resp = llm.create(
            model=MODEL,
            messages=[{"role": "user", "content": EXTRACT_PROMPT.replace("{sources}", sources[:12000])
                       .replace("{answer}", answer)}],
            response_format={"type": "json_object"},
            temperature=0,
            reasoning_effort="low",
        )
        raw = json.loads(resp.choices[0].message.content).get("claims", [])
    except Exception:  # background check must never break the agent
        return []
    sources_norm = _norm(sources)
    return [{"text": c.get("text", ""), "type": "fact",
             "verdict": "supported" if (_quote_found(c.get("quote"), sources_norm)
                                        or _claim_grounded(c.get("text", ""), sources_norm))
             else "unsupported"}
            for c in raw]


def _claim_grounded(claim, sources_norm):
    """Fallback for paraphrases: every number/email must appear exactly,
    and most of the claim's key words must appear in the sources."""
    claim = _norm(claim)
    exact = (EMAIL.findall(claim)
             + re.findall(r"\b\d{1,2}(?::\d{2})?\s?[ap]m\b", claim)  # times: "1 pm"
             + re.findall(r"\d[\d,.:]*\d|\d", claim))
    if any(e.strip(".,") not in sources_norm for e in exact):
        return False  # invented amount, date or address
    words = [w for w in re.findall(r"[a-z]{4,}", claim)]
    return bool(words) and sum(w in sources_norm for w in words) / len(words) >= 0.6


def check_facts_async(answer, trace):
    return _pool.submit(check_facts, answer, list(trace))


def score(claims):
    if not claims:
        return 1.0
    return round(sum(c["verdict"] in ("verified", "supported") for c in claims) / len(claims), 2)
