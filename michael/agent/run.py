"""CLI: run the agent on a prompt and print what it did.

    python -m michael.agent.run "Summarize my unread emails"            # shield OFF
    python -m michael.agent.run --shield "Summarize my unread emails"   # shield ON
"""
import json
import sys
import time

from michael.agent.agent import AgentRun
from michael.detectors import fact_check
from michael.shield.firewall import Shield


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    argv = sys.argv[1:]
    use_shield = "--shield" in argv
    prompt = " ".join(a for a in argv if a != "--shield") or "Summarize my unread emails"

    run = AgentRun(prompt, guard=Shield() if use_shield else None).run()
    s = run.summary()

    print(f"\nMichael-V1 shield: {'ON' if use_shield else 'OFF'}")
    print("\n=== Tool calls ===")
    for ev in s["trace"]:
        if ev["kind"] == "tool_call":
            print(f"- {ev['tool']}({json.dumps(ev['args'])})")
        elif ev["kind"] == "tool_blocked":
            print(f"  BLOCKED: {ev['reason']}")
        elif ev["kind"] == "injection_detected":
            print(f"  INJECTION QUARANTINED: {ev['item']} from {ev['source']} (score {ev['score']})")
        elif ev["kind"] == "jailbreak_detected":
            print(f"  JAILBREAK DETECTED (score {ev['score']})")
        elif ev["kind"] == "secret_redacted":
            print(f"  SECRETS REDACTED from {ev['source']}: {', '.join(ev['kinds'])}")
        elif ev["kind"] == "action_check":
            for c in ev["claims"]:
                print(f"  ACTION CLAIM [{c['verdict'].upper()}]: {c['text']}")

    print("\n=== Side effects ===")
    for mail in s["side_effects"]["outbox"]:
        print(f"[EMAIL SENT] to={mail['to']} attachment={mail.get('attachment') or '-'}")
    for p in s["side_effects"]["payments"]:
        print(f"[PAYMENT] {p['amount']} -> {p['account']}")
    if not any(s["side_effects"].values()):
        print("(none)")

    print("\n=== Answer ===")
    print(s["answer"])

    llm_ms = sum(e["ms"] for e in s["trace"] if e["kind"] == "llm_timing")
    shield = [e["ms"] for e in s["trace"] if e["kind"] == "shield_timing"]
    print("\n=== Latency ===")
    print(f"LLM time:    {llm_ms:,.0f} ms")
    if shield:
        total = sum(shield)
        print(f"Shield time: {total:.2f} ms across {len(shield)} checks "
              f"({total / (llm_ms + total) * 100:.3f}% of total)")

    future = getattr(run, "fact_check_future", None)
    if future:
        start = time.perf_counter()
        facts = future.result()
        waited = (time.perf_counter() - start) * 1000
        print(f"\n=== Fact grounding (background, after answer; extra wait {waited:,.0f} ms) ===")
        for c in facts:
            print(f"  [{c['verdict'].upper()}] {c['text']}")
        print(f"  Trust score: {fact_check.score(facts):.0%}")


if __name__ == "__main__":
    main()
