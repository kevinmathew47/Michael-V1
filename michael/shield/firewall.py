"""Michael-V1 shield: the guard the agent calls before and after every step.

Design for speed (risk-tiered):
  - low-risk tools take the fast path: no checks beyond tagging their output
  - high-risk tools get provenance + data-leak checks on their arguments
  - the jailbreak scan runs in parallel with the agent's first LLM call
  - every check is timed, so the overhead can be measured and shown
"""
import copy
import re
import time
from pathlib import Path

import yaml

from michael.agent.tools import TOOL_SCHEMAS, UNTRUSTED_SOURCE_TOOLS
from michael.detectors import dlp, fact_check, jailbreak, lookalike, prompt_guard, upi
from michael.shield import guards, integrity, owner
from michael.shield.provenance import ProvenanceTracker

POLICY_PATH = Path(__file__).with_name("policy.yaml")
PAYMENT_TOOLS = {"make_payment", "upi_pay"}

# Text in untrusted content that pretends to speak for the shield or claims approval.
IMPERSONATION = re.compile(
    r"(?i)\[?\s*(?:michael[\s-]*v1|blocked_by_michael|agentshield|security (?:gate|team|check)s?)\s*[:\]-][^\n\]]*\]?"
    r"|\b(?:pre-?approved|already approved|verified) by (?:security|michael[\s-]*v1|the shield|it)\b")


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
    def __init__(self, policy_path=POLICY_PATH, fact_grounding=True, ask_owner=False):
        self.fact_grounding = fact_grounding
        self.policy_path = policy_path
        self.ask_owner = ask_owner  # unknown targets go to the owner's private Approver
        self.frozen = None  # reason this task is frozen (attack on the shield seen in this task)
        # Self-protection: refuse risky actions if the policy file was tampered with.
        self.policy_ok, self.policy_reason = integrity.policy_ok(
            policy_path, Path(policy_path).with_name("policy.lock"))
        self.policy = yaml.safe_load(Path(policy_path).read_text(encoding="utf-8"))
        self.trusted_contacts = {c.lower() for c in self.policy.get("trusted_contacts", [])}
        self.internal_domains = {d.lower() for d in self.policy.get("internal_domains", [])}
        self.sensitive_files = set(self.policy.get("sensitive_files", []))
        self.threshold = self.policy.get("injection_threshold", 0.5)
        self.limits = self.policy.get("limits", {})
        self.max_untrusted = self.policy.get("max_untrusted_chars", 20000)
        self.trusted_domains = self.internal_domains | {c.rsplit("@", 1)[-1] for c in self.trusted_contacts}
        self.risky_actions = 0
        self.paid = 0.0
        # Tool definitions pinned by hash: catches tool poisoning, rug pulls and shadowing.
        self.tools = guards.ToolRegistry(TOOL_SCHEMAS)
        # An attack on the shield's own files freezes the whole system, not just one action.
        if not self.policy_ok:
            owner.trip(f"shield integrity check failed: {self.policy_reason}", "policy file")
        if not self.tools.ok:
            owner.trip("tool registry check failed: " + "; ".join(self.tools.problems), "tool definitions")
        self.loop = guards.LoopGuard(max_calls=self.limits.get("max_tool_calls_per_task", 12))
        self.approved = set()  # actions approved with a valid signature (see approve())
        self.untrusted_tools = set(UNTRUSTED_SOURCE_TOOLS)  # tools whose output comes from outside
        self.tracker = None
        self._jailbreak_check = None
        self._jailbreak = None  # None = not checked yet, False = clean, dict = attack

    # --- hooks called by the agent ---------------------------------------

    @_timed
    def check_user_prompt(self, run):
        self.self_check()
        run.log("integrity", policy_ok=self.policy_ok, reason=self.policy_reason,
                tools_ok=self.tools.ok, tool_problems=self.tools.problems, kill_switch=guards.kill_switch_on())
        frozen = self.frozen_reason()
        if frozen:
            run.log("shield_lockdown", scope="system", reason=frozen)
        self.tracker = ProvenanceTracker(run.user_prompt)
        # Start the jailbreak scan in the background; the agent keeps thinking.
        self._jailbreak_check = jailbreak.JailbreakCheck(run.user_prompt)
        # Scan on arrival: inbox and files are scanned now, while the agent thinks,
        # so reading them later costs ~0 ms instead of a fresh scan.
        data = run.ws.data
        prompt_guard.prefetch([m.get("body", "") for m in data.get("inbox", [])] +
                              list(data.get("files", {}).values()))
        return None

    @_timed
    def check_tool_call(self, run, tool, args):
        frozen = self.frozen_reason()
        if frozen:  # lockdown: every tool call stops, reads included
            return {"action": "block", "reason": f"FROZEN by Michael-V1: {frozen}", "frozen": True}
        rule = self.policy["tools"].get(tool, {"risk": "high", "sinks": list(args)})
        loop = self.loop.check(tool, args)
        if loop:
            return {"action": "block", "reason": loop}
        if tool == "web_fetch" and guards.url_guard(args.get("url", "")):
            return {"action": "block", "reason": "unsafe URL: " + guards.url_guard(args.get("url", ""))}
        if tool == "read_file" and guards.path_guard(args.get("filename", "")):
            return {"action": "block", "reason": "unsafe path: " + guards.path_guard(args.get("filename", ""))}
        if rule["risk"] == "low":
            # Fast path: a read can't cause harm, so never wait for the jailbreak
            # verdict here - only use it if it has already arrived.
            if self._jailbreak or (self._jailbreak is None and self._jailbreak_check.ready()):
                jb = self._jailbreak_verdict(run)
                if jb:
                    return {"action": "block", "reason": jb["reason"]}
            return None

        if guards.kill_switch_on():  # rogue-agent response: freeze every risky action
            return {"action": "block", "reason": "kill switch is on: all risky actions are frozen"}
        if not self.policy_ok:  # fail closed: never act on a tampered policy
            return {"action": "block", "reason": f"shield integrity check failed: {self.policy_reason}"}
        if not self.tools.ok:  # poisoned, changed or shadowed tool definitions
            return {"action": "block", "reason": "tool registry check failed: " + "; ".join(self.tools.problems)}
        if self._approval_key(tool, args) in self.approved:  # a human signed this exact action
            self.risky_actions += 1
            return None
        signed = owner.consume(tool, args)  # the owner approved this exact action in the Approver
        if signed:
            run.log("owner_approved", id=signed["id"], tool=tool)
            self.risky_actions += 1
            return None

        jb = self._jailbreak_verdict(run, high_risk=True)
        if jb:
            return {"action": "block", "reason": jb["reason"]}

        verdict = (self._check_limits(tool, args) or self._check_lookalike(args) or self._check_upi(tool, args)
                   or self._check_provenance(tool, rule, args) or self._check_data_leak(run, tool, args))
        if not verdict:
            self.risky_actions += 1
            if tool in PAYMENT_TOOLS:
                self.paid += float(args.get("amount") or 0)
        elif self.ask_owner and ("could not be traced" in verdict["reason"] or verdict["reason"].startswith("payment limit")):
            # Not proven bad, not proven safe: the owner decides, in a private place.
            if owner.approver_ready():
                req = owner.request(tool, args, verdict["reason"])
                verdict["approval"] = {"id": req["id"], "code": req["code"]}
                verdict["reason"] += f" - waiting for the owner in the private Approver (code {req['code']})"
                run.log("approval_requested", id=req["id"], code=req["code"], tool=tool)
            else:
                verdict["reason"] += " - no private Approver is set up (run: python -m michael.approver)"
        return verdict

    @_timed
    def process_tool_result(self, run, tool, args, result):
        if tool not in self.untrusted_tools:
            return result
        label = f"{tool}:{args.get('url') or args.get('filename') or 'inbox'}"
        self.tracker.add_untrusted(label, result)

        result = copy.deepcopy(result)
        self._sanitize(run, label, result)
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
        frozen = self.frozen_reason()
        if frozen:
            return (f"⛔ Michael-V1 froze this task: {frozen}. Nothing will run until the owner "
                    "reviews it in the private Approver.")
        jb = self._jailbreak_verdict(run)
        if jb:
            return jb["message"]
        clean, kinds = dlp.redact(answer or "")
        if kinds:
            run.log("secret_redacted", source="final_answer", kinds=kinds)
        # Zero-click exfiltration: external images / data-carrying links in the answer.
        clean, removed = guards.strip_exfil_links(clean, self.internal_domains)
        if removed:
            run.log("exfil_link_stripped", count=len(removed), urls=[u[:120] for u in removed])

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

    # --- verifiable approvals -------------------------------------------------

    @staticmethod
    def _approval_key(tool, args):
        return integrity.sign_approval(tool, args)

    def approve(self, tool, args, signature):
        """Called by the approval UI. Only a valid HMAC signature over this exact action
        counts; "approved by admin" written in any text never does."""
        if integrity.verify_approval(tool, args, signature):
            self.approved.add(self._approval_key(tool, args))
            return True
        # A forged approval is an attack on the shield itself: freeze everything.
        self.frozen = f"forged approval presented for {tool} (signature does not verify)"
        owner.trip(self.frozen, "approval")
        return False

    def self_check(self):
        """Re-verify the shield's own policy file and tool definitions; trip on tampering."""
        self.policy_ok, self.policy_reason = integrity.policy_ok(self.policy_path, Path(self.policy_path).with_name("policy.lock"))
        if not self.policy_ok:
            owner.trip(f"shield integrity check failed: {self.policy_reason}", "policy file")
        if not self.tools.ok:
            owner.trip("tool registry check failed: " + "; ".join(self.tools.problems), "tool definitions")

    def frozen_reason(self):
        if guards.kill_switch_on():
            return "kill switch is on: every action is frozen"
        if self.frozen:
            return self.frozen
        lock = owner.lockdown_state()
        return f"system lockdown: {lock['reason']}" if lock else None

    # --- checks ------------------------------------------------------------

    def _jailbreak_verdict(self, run, high_risk=False):
        if self._jailbreak is not None:
            return self._jailbreak  # already decided

        v = self._jailbreak_check.verdict(high_risk=high_risk)
        run.log("jailbreak_check", **v)
        if v["flagged_by"]:
            self._jailbreak = {
                "reason": f"user prompt flagged as a jailbreak attempt by {' + '.join(v['flagged_by'])}",
                "message": "Michael-V1 blocked this request: it looks like a jailbreak attempt.",
            }
            run.log("jailbreak_detected", **v)
            return self._jailbreak
        if v["status"] == "ok":
            self._jailbreak = False  # both checks done and clean
            return False
        if high_risk:
            # Fail closed: never run a risky action without the full safety check.
            return {"reason": f"jailbreak safety check unavailable ({v['status']}); risky action held",
                    "message": "Michael-V1 could not finish its safety check, so no risky action was taken."}
        return False  # low-risk step: continue, re-check before the next one

    def _check_provenance(self, tool, rule, args):
        sinks = rule.get("sinks", {})
        modes = sinks if isinstance(sinks, dict) else {a: "strict" for a in sinks}
        for arg, mode in modes.items():
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
            if origin is None and mode == "strict":
                # Fail closed: a target we can't trace to the user is not trusted,
                # even if it was reworded or re-spelled to dodge matching.
                return {"action": "block",
                        "reason": f"{tool}.{arg}='{value}' could not be traced to the user "
                                  f"(not named by the user, not a trusted contact)"}
        return None

    def _check_limits(self, tool, args):
        max_actions = self.limits.get("max_risky_actions_per_task")
        if max_actions and self.risky_actions >= max_actions:
            return {"action": "block", "reason": f"limit reached: max {max_actions} risky actions per task"}
        max_pay = self.limits.get("max_payment_per_task")
        if tool in PAYMENT_TOOLS and max_pay and self.paid + float(args.get("amount") or 0) > max_pay:
            return {"action": "block", "reason": f"payment limit: more than {max_pay:,} in one task"}
        return None

    def _check_upi(self, tool, args):
        """UPI Guard: a spoofed bank handle (okaxls, paytrn, Cyrillic letters) is never paid."""
        if tool != "upi_pay":
            return None
        bad = [r for r in upi.check(args.get("upi_id", ""), self.policy.get("trusted_upi", []))
               if "imitates" in r or "non-ASCII" in r or "not a UPI ID" in r]
        return {"action": "block", "reason": f"suspicious UPI ID '{args.get('upi_id')}': " + "; ".join(bad)} if bad else None

    def _check_lookalike(self, args):
        if "to" in args and str(args["to"]).lower() not in self.trusted_contacts:
            reason = lookalike.check(args["to"], self.trusted_domains)
            if reason:
                return {"action": "block", "reason": f"look-alike recipient: {reason}"}
        return None

    def _sanitize(self, run, source, result):
        """Cut oversized untrusted text and strip text impersonating the shield."""
        items = result if isinstance(result, list) else [result]
        for item in items:
            if not isinstance(item, dict):
                continue
            for field in ("body", "content"):
                text = item.get(field)
                if not isinstance(text, str):
                    continue
                if len(text) > self.max_untrusted:
                    text = text[:self.max_untrusted] + "\n[TRUNCATED by Michael-V1: content too long]"
                    run.log("content_truncated", source=source, limit=self.max_untrusted)
                cleaned, n = IMPERSONATION.subn("[removed by Michael-V1: fake approval/impersonation]", text)
                if n:
                    run.log("impersonation_stripped", source=source, count=n)
                    # Content pretending to be the shield is an attack on the shield: freeze this task.
                    self.frozen = f"text impersonating Michael-V1 / a fake approval was found in {source}"
                    run.log("shield_lockdown", scope="task", reason=self.frozen)
                item[field] = cleaned

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
        listed = self.policy.get("allowlisted_sinks", {}).get(arg)
        if listed == "trusted_contacts":
            return str(value).lower() in self.trusted_contacts
        if listed == "trusted_upi":
            return str(value).strip().lower() in {u.lower() for u in self.policy.get("trusted_upi", [])}
        return False
