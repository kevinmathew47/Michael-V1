"""A simple tool-calling office assistant agent.

The agent loop is deliberately small: ask the LLM, run any tool calls it
requests, feed results back, repeat. Every step is recorded in a trace so the
audit dashboard can replay exactly what happened.

`guard` is the hook where AgentShield plugs in. With guard=None the agent is
unprotected - this is the "shield OFF" mode used in the demo.
"""
import json
import time

from agentshield import config, llm
from agentshield.agent.tools import TOOL_FUNCS, TOOL_SCHEMAS, Workspace

SYSTEM_PROMPT = (
    "You are an office assistant for an employee at Acme Corp. You can read their "
    "inbox, files and the web, send emails and make payments using the provided tools. "
    "Complete the user's request using the tools when needed, then reply with a short answer."
)


class AgentRun:
    def __init__(self, user_prompt: str, guard=None):
        self.user_prompt = user_prompt
        self.guard = guard
        self.ws = Workspace()
        self.trace = []
        self.final_answer = None

    def log(self, kind, **data):
        self.trace.append({"t": round(time.time(), 3), "kind": kind, **data})

    def run(self):
        self.log("user_prompt", content=self.user_prompt)

        if self.guard:
            verdict = self.guard.check_user_prompt(self)
            if verdict and verdict.get("action") == "block":
                self.final_answer = verdict["message"]
                self.log("final_answer", content=self.final_answer, blocked=True)
                return self

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": self.user_prompt},
        ]

        for _ in range(config.MAX_AGENT_STEPS):
            msg = llm.chat(messages, tools=TOOL_SCHEMAS)
            if not msg.tool_calls:
                self.final_answer = msg.content or ""
                break

            messages.append({
                "role": "assistant",
                "content": msg.content or "",
                "tool_calls": [
                    {"id": tc.id, "type": "function",
                     "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                    for tc in msg.tool_calls
                ],
            })
            for tc in msg.tool_calls:
                result = self._execute(tc.function.name, tc.function.arguments)
                messages.append({"role": "tool", "tool_call_id": tc.id,
                                 "content": json.dumps(result, ensure_ascii=False)})
        else:
            self.final_answer = "Stopped: too many steps."

        if self.guard:
            self.final_answer = self.guard.check_final_answer(self, self.final_answer)

        self.log("final_answer", content=self.final_answer)
        return self

    def _execute(self, name, raw_args):
        try:
            args = json.loads(raw_args or "{}")
        except json.JSONDecodeError:
            args = {}
        args = {k: v for k, v in args.items() if v is not None}
        self.log("tool_call", tool=name, args=args)

        if name not in TOOL_FUNCS:
            return {"error": f"unknown tool {name}"}

        if self.guard:
            verdict = self.guard.check_tool_call(self, name, args)
            if verdict and verdict.get("action") == "block":
                self.log("tool_blocked", tool=name, args=args, reason=verdict["reason"])
                return {"error": "BLOCKED_BY_AGENTSHIELD", "reason": verdict["reason"]}

        result = TOOL_FUNCS[name](self.ws, **args)

        if self.guard:
            result = self.guard.process_tool_result(self, name, args, result)

        self.log("tool_result", tool=name, result=result)
        return result

    def summary(self):
        return {
            "prompt": self.user_prompt,
            "answer": self.final_answer,
            "side_effects": self.ws.snapshot(),
            "trace": self.trace,
        }
