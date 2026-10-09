<p align="center">
  <img src="assets/banner.svg" alt="Michael-V1" width="100%">
</p>

<p align="center">
  <b>A runtime firewall for AI agents. It stops them from being tricked into leaking data, moving money or lying about what they did.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Track-Safe%20%26%20Trustworthy%20AI-6366f1?style=flat-square">
  <img src="https://img.shields.io/badge/AgentShield%20Benchmark-92.2%20(held--out)-22d3ee?style=flat-square">
  <img src="https://img.shields.io/badge/self--defense%20tests-13%2F13-34d399?style=flat-square">
  <img src="https://img.shields.io/badge/Python-3.12-3776ab?style=flat-square&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/LLM-Groq-f55036?style=flat-square">
</p>

---

## 🚨 The problem

AI agents now read emails, web pages and files, then **act**: they send email, pay invoices, share files. One planted message can hijack them. In our tests an unprotected agent:

- **paid ₹12,000 to a scammer** because an email said "we changed banks, pay this new account";
- **emailed the company's finance file** to a look-alike domain (`acme-corp-audit.example`);
- **told the user "I've replied to the vendor"** when it never did.

## 🛡️ The idea

Before any risky action runs, Michael-V1 asks one question:

> **Who chose this target: the user, or something the agent read?**

The recipient, account or file of every action is traced back to its source. If it came from an email, web page or file rather than from the user, the action is blocked, even when the text looks harmless and every AI detector scores it as safe.

<p align="center"><img src="docs/screenshots/overview.png" width="100%" alt="Michael-V1 console overview"></p>

## 📊 Results

### 1. Public benchmark: AgentShield Benchmark (537 open test cases)

Self-run on the open [AgentShield Benchmark](https://github.com/doronp/agentshield-benchmark) corpus with a Python port of its scoring formula. We **tuned only on one half** of the corpus and report the **held-out half (265 cases)**.

| | **Michael-V1** | Lakera Guard | Deepset DeBERTa | LLM Guard |
|---|---|---|---|---|
| **Final score** | **92.2** | 79.4 | 87.6 | 38.7 |
| Prompt injection | **100.0%** | 97.6% | 99.5% | 77.1% |
| Data exfiltration | **97.4%** | 96.6% | 95.4% | 30.8% |
| Tool abuse | 93.5% | 86.3% | 98.8% | 8.9% |
| Jailbreak | 90.5% | 95.6% | 97.8% | n/a |
| Multi-agent | **100.0%** | 94.3% | 100.0% | n/a |
| Provenance & audit | **100.0%** | 95.0% | 100.0% | n/a |
| **Legitimate requests allowed** | **97.0%** | 58.5% | 63.1% | n/a |
| p50 latency per check | 155 ms | 133 ms | 19 ms | 111 ms |

<sub>Other shields' numbers are from the benchmark README (top published entry: AgentGuard, 98.4). Ours is a self-run estimate on half of the corpus, **not an official leaderboard entry**. Prompt Guard 2 alone scores 22.1 on the same cases; our layers take it to 92.2. Details: [docs/REPORT.md](docs/REPORT.md).</sub>

### 2. Our attack suite: real side effects

The same AI model runs each scenario **with and without** Michael-V1, and is judged by **what actually happened** (money moved, emails sent, secrets leaked), not by what it said.

| | Without shield | With Michael-V1 |
|---|---|---|
| 💥 Attacks that caused damage | **12 / 20** | **0 / 20** |
| ✅ Normal tasks still working | 6 / 6 | **6 / 6** (0 false alarms) |

Newer cases (Hindi / Hinglish / base64 / split-instruction / fake-CFO jailbreaks, Hindi and Hinglish normal requests) are verified at the input gate: **8/8 normal prompts allowed, all hard jailbreaks flagged** (`python -m tests.jailbreak_eval`).

### 3. Self-defense: attacks on the shield itself: 13 / 13

Value laundering, spelled-out account numbers, look-alike domains, fake "Michael-V1 approved" notes, hiding past the scan, policy tampering, audit-log editing, exfiltration loops, obfuscated and split commands. Each has an offline test (`python -m tests.test_self_defense`).

## ⚡ Latency: built to stay out of the way

| Change | Before | After |
|---|---|---|
| Inbox read (scan on arrival) | ~255 ms | **0.2 ms** |
| Phishing scenario, total shield time | 252 ms | **5.3 ms** |
| "Summarize inbox" (reads never wait) | 260 ms | **4.9 ms** |
| Benchmark p50 per check (faster judge) | 478 ms | **155 ms** |

How: read-only steps take a fast path · rules before models · AI checks run **in parallel while the agent thinks** · inbox and files are scanned when they arrive, then cached · risky actions **fail closed** if a check is slow.

## 🧱 How it works

```
User ─▶ 1 Input gate ─▶ AI agent ─▶ 3 Answer check ─▶ Reply
        rules · de-obfuscation       │  "I did X" vs action log
        Prompt Guard ‖ judge         ▼  tool call
                            2 Action gate ─▶ Tools (email · pay · files · web)
                            provenance · look-alike ·       │
                            data-leak · limits · fail closed │
        0 Scan on arrival ◀──── emails / files / web pages ──┘
        quarantine · redact · strip fake approvals
every event ─▶ hash-chained audit log · policy pinned by SHA-256
```

| What Michael-V1 adds | Why it matters |
|---|---|
| **Value-level provenance, no agent rewrite** | Stops believable phishing that text detectors miss, while letting user-named recipients through |
| **Hallucinated-action check** | "I've sent it" is verified against the real action log by code: an AI never grades itself |
| **Input gate** | De-obfuscation (base64, hex, reversed, zero-width), instant rules (split instructions, fake authority, "approved by…" claims), Prompt Guard 2 and a policy judge in parallel |
| **India-ready leak guard** | Aadhaar with UIDAI's Verhoeff checksum, PAN, cards (Luhn); Hindi / Hinglish jailbreaks |
| **Self-defense** | Normalized tracing, fail-closed sinks, pinned policy, hash-chained audit log, per-task limits |

## 🖥️ The console

`python -m michael.server` → http://localhost:8000

- **Overview:** what Michael-V1 is for, a 30-second story, how a request flows, a plain-language glossary.
- **Attack Lab:** replay any recorded attack with and without the shield: what happened, damage, trust-flow graph, latency waterfall, decision log.
- **Benchmark:** our score next to published shields, what each layer adds, run history.
- **Self-Defense:** every attack on the shield and its passing test.
- **Changelog:** every improvement with before/after numbers.

<p align="center"><img src="docs/screenshots/lab.png" width="49%" alt="Attack Lab"> <img src="docs/screenshots/benchmark.png" width="49%" alt="Benchmark"></p>

## 🚀 Quick start

```bash
pip install -r requirements.txt
cp .env.example .env                      # add your Groq API key

python -m michael.server                  # console at http://localhost:8000
python -m tests.test_self_defense         # offline self-defense tests (no API calls)
python -m michael.suite                   # attack suite -> results/scorecard.json
python -m michael.agent.run --shield "Go through my unread emails and handle whatever they ask for"
```

Benchmark (optional): `git clone --depth 1 https://github.com/doronp/agentshield-benchmark external/agentshield-benchmark` then `python -m michael.benchmark --split test`.

> All tools are **mocked** (`data/workspace.json`): no real email or payment is ever sent.
> Groq's free tier allows ~200k tokens/day per model; the agent falls back to `gpt-oss-20b`, then `qwen3`, when one runs out.

## 📁 Project structure

```
michael/
├── agent/         office-assistant agent + mock tools
├── shield/        firewall, provenance, flow map, integrity (policy pin + audit chain), policy.yaml
├── detectors/     Prompt Guard, input-gate judge, de-obfuscation + rules, data-leak, look-alike, fact-check
├── server.py      console API
├── suite.py       attack suite runner (judged by side effects)
├── benchmark.py   AgentShield Benchmark adapter + scoring port
└── llm.py         Groq client: per-model rate + token limiter, daily-limit fallback
attacks/suite.yaml   25 attacks + 8 normal tasks
tests/               self-defense tests, jailbreak eval
dashboard/           console
docs/REPORT.md       full technical report
results/             scorecard, benchmark, self-defense results
```

## 📈 Progress

See [PROGRESS.md](PROGRESS.md) and the full [technical report](docs/REPORT.md).

## 🙏 Acknowledgements

- [Groq](https://groq.com): `openai/gpt-oss-120b`, `openai/gpt-oss-20b`, `qwen/qwen3.8-27b`, `meta-llama/llama-prompt-guard-2-86m`
- [AgentShield Benchmark](https://github.com/doronp/agentshield-benchmark) (Apache-2.0): test corpus and scoring method, used for evaluation only
- Ideas we build on: Google DeepMind's CaMeL (provenance), Meta's LlamaFirewall (Prompt Guard 2), Invariant Labs (data-flow rules)
- Libraries: `groq`, `fastapi`, `uvicorn`, `python-dotenv`, `pyyaml`
- AI coding assistants were used during development; all code is reviewed and understood by the team.
