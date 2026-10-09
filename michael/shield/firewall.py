"""Michael-V1 shield: the guard the agent calls before and after every step.

Design for speed (risk-tiered):
  - low-risk tools take the fast path: no checks beyond tagging their output
  - high-risk tools get provenance checks on their "sink" arguments
  - every check is timed, so the overhead can be measured and shown
"""
import time
from pathlib import Path

import yaml

from michael.agent.tools import UNTRUSTED_SOURCE_TOOLS
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
    def __init__(self, policy_path=POLICY_PATH):
        self.policy = yaml.safe_load(Path(policy_path).read_text(encoding="utf-8"))
        self.trusted_contacts = {c.lower() for c in self.policy.get("trusted_contacts", [])}
        self.tracker = None

    # --- hooks called by the agent ---------------------------------------

    @_timed
    def check_user_prompt(self, run):
        self.tracker = ProvenanceTracker(run.user_prompt)
        return None  # jailbreak guard plugs in here (next checkpoint)

    @_timed
    def check_tool_call(self, run, tool, args):
        rule = self.policy["tools"].get(tool, {"risk": "high", "sinks": list(args)})
        if rule["risk"] == "low":
            return None  # fast path

        for arg in rule.get("sinks", []):
            if arg not in args:
                continue
            value = args[arg]
            if self._allowlisted(arg, value):
                continue
            origin = self.tracker.origin_of(value)
            if origin and origin != "user":
                reason = (f"{tool}.{arg}='{value}' was taken from untrusted content "
                          f"({origin}), not from the user")
                return {"action": "block", "reason": reason}
            if origin is None and arg == "to":
                return {"action": "block",
                        "reason": f"recipient '{value}' is not a trusted contact and the user never named it"}
        return None

    @_timed
    def process_tool_result(self, run, tool, args, result):
        if tool in UNTRUSTED_SOURCE_TOOLS:
            label = f"{tool}:{args.get('url') or args.get('filename') or 'inbox'}"
            self.tracker.add_untrusted(label, result)
        return result

    @_timed
    def check_final_answer(self, run, answer):
        return answer  # fact-check layer plugs in here (next checkpoint)

    # --- helpers -----------------------------------------------------------

    def _allowlisted(self, arg, value):
        if self.policy.get("allowlisted_sinks", {}).get(arg) == "trusted_contacts":
            return str(value).lower() in self.trusted_contacts
        return False
