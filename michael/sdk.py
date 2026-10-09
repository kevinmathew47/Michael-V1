"""Michael-V1 SDK: protect ANY AI agent, whatever model it uses.

Michael-V1 guards the agent's tools and data, not the model, so the same shield
works with OpenAI, Anthropic Claude, Google Gemini, Meta Llama, Qwen, Mistral,
Groq or a local Ollama model. You keep your agent loop; you wrap your tools.

    from michael.sdk import Michael

    guard = Michael()                                   # loads michael/shield/policy.yaml

    @guard.tool(reads_untrusted=True)                   # content from outside: scanned + tracked
    def read_inbox(): ...

    @guard.tool(risk="high", sinks={"to": "strict", "attachment": "taint"})
    def send_email(to, subject, body, attachment=""): ...

    with guard.session(user_prompt) as s:               # one user request
        ...your agent loop calls read_inbox() / send_email(...) as usual...
        answer = s.check_answer(model_reply)            # fact-check + redaction

A blocked call raises nothing: it returns {"error": "BLOCKED_BY_MICHAEL", "reason": ...},
which you hand back to the model like any tool result, so every model handles it.
"""
import functools
import time
from contextlib import contextmanager
from contextvars import ContextVar

from michael.shield import integrity
from michael.shield.firewall import Shield

_current = ContextVar("michael_session", default=None)


class Session:
    """One user request. Plays the role of the agent run for the shield hooks."""

    def __init__(self, user_prompt, guard, files=None):
        self.user_prompt = user_prompt
        self.trace = []
        self.ws = type("Workspace", (), {"data": {"files": dict(files or {}), "inbox": []}})()
        self.shield = Shield(policy_path=guard.policy_path, fact_grounding=guard.fact_grounding)
        self.blocked = []

    def log(self, kind, **data):
        event = {"t": round(time.time(), 3), "kind": kind, **data}
        prev = self.trace[-1]["h"] if self.trace else integrity.GENESIS
        event["h"] = integrity.event_hash(prev, event)
        self.trace.append(event)

    # explicit API (for frameworks that don't use the decorator) -----------------
    def start(self):
        self.log("user_prompt", content=self.user_prompt)
        self.shield.check_user_prompt(self)

    def check_action(self, tool, args):
        """None if allowed, else {"action": "block", "reason": ...}."""
        self.log("tool_call", tool=tool, args=args)
        verdict = self.shield.check_tool_call(self, tool, args)
        if verdict:
            self.log("tool_blocked", tool=tool, args=args, reason=verdict["reason"])
            self.blocked.append(verdict["reason"])
        return verdict

    def record_read(self, tool, args, result):
        """Pass untrusted content through the shield; returns the cleaned version."""
        clean = self.shield.process_tool_result(self, tool, args, result)
        self.log("tool_result", tool=tool, result=clean)
        return clean

    def check_answer(self, text):
        clean = self.shield.check_final_answer(self, text)
        self.log("final_answer", content=clean)
        return clean

    def audit_ok(self):
        return integrity.verify_chain(self.trace)[0]


class Michael:
    def __init__(self, policy_path=None, fact_grounding=False):
        from michael.shield.firewall import POLICY_PATH
        self.policy_path = policy_path or POLICY_PATH
        self.fact_grounding = fact_grounding

    @contextmanager
    def session(self, user_prompt, files=None):
        s = Session(user_prompt, self, files)
        s.start()
        token = _current.set(s)
        try:
            yield s
        finally:
            _current.reset(token)

    def tool(self, risk="low", sinks=None, reads_untrusted=False):
        """Decorator: route a tool through the shield. Policy for the tool comes from
        policy.yaml; risk/sinks here document intent and are used if it isn't listed."""
        def wrap(fn):
            @functools.wraps(fn)
            def inner(*args, **kwargs):
                s = _current.get()
                if s is None:
                    raise RuntimeError("call tools inside `with guard.session(prompt):`")
                if args:  # map positional args to names for provenance checks
                    names = fn.__code__.co_varnames[:fn.__code__.co_argcount]
                    kwargs = {**dict(zip(names, args)), **kwargs}
                rule = s.shield.policy["tools"].setdefault(fn.__name__, {"risk": risk, "sinks": sinks or {}})
                if reads_untrusted:
                    s.shield.untrusted_tools.add(fn.__name__)
                verdict = s.check_action(fn.__name__, kwargs)
                if verdict:
                    return {"error": "BLOCKED_BY_MICHAEL", "reason": verdict["reason"]}
                result = fn(**kwargs)
                if reads_untrusted or rule.get("risk") == "low":
                    return s.record_read(fn.__name__, kwargs, result)
                s.log("tool_result", tool=fn.__name__, result=result)
                return result
            return inner
        return wrap
