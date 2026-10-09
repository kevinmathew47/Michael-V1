"""CLI: run the agent on a prompt and print what it did.

    python -m michael.agent.run "Summarize my unread emails"
"""
import json
import sys

from michael.agent.agent import AgentRun


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    prompt = " ".join(sys.argv[1:]) or "Summarize my unread emails"
    run = AgentRun(prompt).run()
    s = run.summary()

    print("\n=== Tool calls ===")
    for ev in s["trace"]:
        if ev["kind"] == "tool_call":
            print(f"- {ev['tool']}({json.dumps(ev['args'])})")

    print("\n=== Side effects ===")
    for mail in s["side_effects"]["outbox"]:
        print(f"[EMAIL SENT] to={mail['to']} attachment={mail.get('attachment') or '-'}")
    for p in s["side_effects"]["payments"]:
        print(f"[PAYMENT] {p['amount']} -> {p['account']}")
    if not any(s["side_effects"].values()):
        print("(none)")

    print("\n=== Answer ===")
    print(s["answer"])


if __name__ == "__main__":
    main()
