"""Universal X-Ray: every example gets the right verdict, normal messages stay safe. Offline.

    python -m tests.test_xray
"""
import sys

from michael import xray

EXPECT = {"bank_change": "attack", "hidden_html": "attack", "resume": "attack", "web": "attack",
          "whatsapp": "attack", "readme": "attack", "safe": "safe"}
NORMAL = [
    "Hi team, the assistant manager role is open. Please apply by Friday.",
    "Agent: Ravi Kumar, Policy No 4471. Premium due on 5th.",
    "Bot: your order has shipped and will arrive on Monday.",
    "Reminder: the quarterly review is on Thursday at 3 pm in room 4B.",
    "Kal office band rahega, Diwali ki chutti hai. Happy Diwali sabko!",
]


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    failed = 0
    for sid, title, kind, fname in xray.SAMPLES:
        s = xray.sample(sid)
        r = xray.scan(s["kind"], text=s.get("text"), data_b64=s.get("data_b64"), filename=s["filename"])
        ok = r["level"] == EXPECT[sid]
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {title:42} {r['level']:10} {r['score']}")
    r = xray.scan("pdf", **{k: v for k, v in xray.sample("resume").items() if k in ("data_b64", "filename")})
    ok = any("white text" in h["where"] for h in r["hidden"]) and any(t["value"] == "talent@hire-fast.example" for t in r["targets"])
    failed += not ok
    print(f"{'PASS' if ok else 'FAIL'}  resume: white text found, leak address listed")
    r = xray.scan("chat", **{k: v for k, v in xray.sample("whatsapp").items() if k in ("text", "filename")})
    ok = any(t["value"] == "sbi-kyc@okaxls" and any("imitates" in f for f in t["flags"]) for t in r["targets"]) and r["secrets"]
    failed += not ok
    print(f"{'PASS' if ok else 'FAIL'}  whatsapp: spoofed UPI handle and Aadhaar found")
    for text in NORMAL:
        r = xray.scan("text", text=text)
        ok = r["level"] == "safe"
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  normal text stays safe: {text[:50]} ({r['level']} {r['score']})")
    total = len(xray.SAMPLES) + 2 + len(NORMAL)
    print(f"\n{total - failed}/{total} X-Ray tests passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
