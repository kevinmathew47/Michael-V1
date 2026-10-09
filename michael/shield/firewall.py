"""Michael-V1 shield: the guard the agent calls before and after every step.

Design for speed (risk-tiered):
  - low-risk tools take the fast path: no checks beyond tagging their output
  - high-risk tools get provenance + data-leak checks on their arguments
  - the jailbreak scan runs in parallel with the agent's first LLM call
  - every check is timed, so the overhead can be measured and shown
"""
import copy
import time
from pathlib import Path

import yaml

from michael.agent.tools import UNTRUSTED_SOURCE_TOOLS
from michael.detectors import dlp, fact_check, prompt_guard
from michael.shield.provenance import ProvenanceTracker

POLICY_PATH = Path(__file__).with_name("policy.yaml")


def _timed(fn):
    """Record how long each shield check takes in the run's trace."""
    def wrapper(self, run, *args, **kwargs):
        start = time.perf_counter()
        result = fn(self, run, *args, **kwargs)
        ms = (time.perf_counter() - start) * 1000
        run.log("shield_timing", check=fn.__name__, ms=round(ms, 3))
        return result
    return wrapper


class Shield:
    def __init__(self, policy_path=POLICY_PATH, fact_grounding=True):
        self.fact_grounding = fact_grounding
        self.policy = yaml.safe_load(Path(policy_path).read_text(encoding="utf-8"))
        self.trusted_contacts = {c.lower() for c in self.policy.get("trusted_contacts", [])}
        self.internal_domains = {d.lower() for d in self.policy.get("internal_domains", [])}
        self.sensitive_files = set(self.policy.get("sensitive_files", []))
        self.threshold = self.policy.get("injection_threshold", 0.5)
        self.tracker = None
        self._jailbreak_future = None
        self._jailbreak = None  # None = not checked yet, False = clean, dict = attack

    # --- hooks called by the agent ---------------------------------------

    @_timed
    def check_user_prompt(self, run):
        self.tracker = ProvenanceTracker(run.user_prompt)
        # Start the jailbreak scan in the background; the agent keeps thinking.
        self._jailbreak_future = prompt_guard.score_async(run.user_prompt)
        return None

    @_timed
    def check_tool_call(self, run, tool, args):
        jb = self._jailbreak_verdict(run)
        if jb:
            return {"action": "block", "reason": jb["reason"]}

        rule = self.policy["tools"].get(tool, {"risk": "high", "sinks": list(args)})
        if rule["risk"] == "low":
            return None  # fast path

        return self._check_provenance(tool, rule, args) or self._check_data_leak(run, tool, args)

    @_timed
    def process_tool_result(self, run, tool, args, result):
        if tool not in UNTRUSTED_SOURCE_TOOLS:
            return result
        label = f"{tool}:{args.get('url') or args.get('filename') or 'inbox'}"
        self.tracker.add_untrusted(label, result)

        result = copy.deepcopy(result)
        if tool == "read_inbox":
            self._quarantine_injections(run, label, result, field="body")
        elif isinstance(result, dict) and "content" in result:
            self._quarantine_injections(run, label, [result], field="content")
            result["content"], kinds = dlp.redact(result["content"])
            if kinds:
                run.log("secret_redacted", source=label, kinds=kinds)
        return result

    @_timed
    def check_final_answer(self, run, answer):
        jb = self._jailbreak_verdict(run)
        if jb:
            return jb["message"]
        clean, kinds = dlp.redact(answer or "")
        if kinds:
            run.log("secret_redacted", source="final_answer", kinds=kinds)

        # Sync, rules only: did the agent claim actions it never performed?
        actions = fact_check.check_actions(clean, run.trace)
        run.log("action_check", claims=actions)
        false = [c["text"] for c in actions if c["verdict"] == "false"]
        if false:
            clean += "\n\n---\n⚠️ Michael-V1: these claims are NOT backed by any action the assistant took:\n" + \
                     "\n".join(f'- "{t}"' for t in false)

        # Async, small LLM: are the facts grounded in the data? Doesn't delay the answer.
        if self.fact_grounding:
            run.fact_check_future = fact_check.check_facts_async(clean, run.trace)
        return clean

    # --- checks ------------------------------------------------------------

    def _jailbreak_verdict(self, run):
        if self._jailbreak is None:
            score = self._jailbreak_future.result()
            self._jailbreak = False
            if score >= self.threshold:
                self._jailbreak = {
                    "reason": f"user prompt flagged as a jailbreak attempt (score {score:.2f})",
                    "message": "Michael-V1 blocked this request: it looks like a jailbreak attempt.",
                }
                run.log("jailbreak_detected", score=round(score, 4))
        return self._jailbreak

    def _check_provenance(self, tool, rule, args):
        for arg in rule.get("sinks", []):
            if arg not in args:
                continue
            value = args[arg]
            if self._allowlisted(arg, value):
                continue
            origin = self.tracker.origin_of(value)
            if origin and origin != "user":
                return {"action": "block",
                        "reason": f"{tool}.{arg}='{value}' was taken from untrusted content "
                                  f"({origin}), not from the user"}
            if origin is None and arg == "to":
                return {"action": "block",
                        "reason": f"recipient '{value}' is not a trusted contact and the user never named it"}
        return None

    def _check_data_leak(self, run, tool, args):
        outgoing = " ".join(str(v) for v in args.values())
        attachment = args.get("attachment")
        if attachment:
            outgoing += " " + run.ws.data["files"].get(attachment, "")

        secrets = sorted({kind for kind, _ in dlp.find(outgoing)})
        if secrets:
            return {"action": "block", "reason": f"outgoing data contains secrets: {', '.join(secrets)}"}

        if attachment in self.sensitive_files and "to" in args:
            domain = str(args["to"]).rsplit("@", 1)[-1].lower()
            if domain not in self.internal_domains:
                return {"action": "block",
                        "reason": f"sensitive file '{attachment}' cannot be sent outside the company ({domain})"}
        return None

    def _quarantine_injections(self, run, source, items, field):
        texts = [str(item.get(field, "")) for item in items]
        for item, score in zip(items, prompt_guard.score_many(texts)):
            if score >= self.threshold:
                item[field] = (f"[QUARANTINED by Michael-V1: prompt injection detected "
                               f"(score {score:.2f}). Content hidden from the agent.]")
                run.log("injection_detected", source=source, score=round(score, 4),
                        item=item.get("id") or item.get("url") or item.get("filename"))

    # --- helpers -----------------------------------------------------------

    def _allowlisted(self, arg, value):
        if self.policy.get("allowlisted_sinks", {}).get(arg) == "trusted_contacts":
            return str(value).lower() in self.trusted_contacts
        return False
