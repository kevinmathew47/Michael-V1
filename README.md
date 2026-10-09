<p align="center">
  <img src="assets/banner.svg" alt="Michael-V1" width="100%">
</p>

<p align="center">
  <b>A runtime firewall for AI agents. It stops them from being tricked into leaking data, moving money or lying about what they did.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Track-Safe%20%26%20Trustworthy%20AI-6366f1?style=flat-square">
  <img src="https://img.shields.io/badge/AgentShield%20Benchmark-99.4%20(held--out)-22d3ee?style=flat-square">
  <img src="https://img.shields.io/badge/self--defense%20tests-21%2F21-34d399?style=flat-square">
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

<p align="center"><img src="docs/screenshots/home.png" width="100%" alt="Michael-V1 home page"></p>

## 🔌 Use it with any AI model

Michael-V1 guards the agent's **tools and data**, not the model, so the same shield works with OpenAI, Anthropic Claude, Google Gemini, Meta Llama, Qwen, Mistral, Groq or a local Ollama model. Wrap your tools once:

```python
from michael.sdk import Michael
guard = Michael()                                     # loads policy.yaml

@guard.tool(reads_untrusted=True)                     # outside content: scanned + tracked
def read_inbox(): ...

@guard.tool(risk="high", sinks={"to": "strict"})      # target must come from the user
def send_email(to, subject, body): ...

with guard.session(user_prompt) as s:
    ...                                               # your agent loop, any model
    answer = s.check_answer(model_reply)              # catches "I sent it" when it didn't happen
```

For OpenAI-style or Claude-style tool calls, call `s.check_action(name, args)` before running a tool and `s.record_read(...)` for untrusted content. Offline example: `python -m tests.test_sdk`.

**Tested on three models** (same attacks, with and without the shield, `python -m michael.models_demo`): OpenAI gpt-oss-120B and gpt-oss-20B were hijacked by every attack without the shield and were safe with Michael-V1 in every case; Alibaba Qwen3 refused the bank-change scam on its own (its other runs are pending the free-tier daily limit).

<p align="center"><img src="docs/screenshots/playground.png" width="49%" alt="Playground"> <img src="docs/screenshots/models.png" width="49%" alt="Any model"></p>

## 📊 Results

### 1. Public benchmark: AgentShield Benchmark (537 open test cases)

Self-run on the open [AgentShield Benchmark](https://github.com/doronp/agentshield-benchmark) corpus with a Python port of its scoring formula. We **tuned only on one half** of the corpus and report the **held-out half (265 cases)**.

| | **Michael-V1** | AgentGuard | Deepset DeBERTa | Lakera Guard | LLM Guard |
|---|---|---|---|---|---|
| **Final score** | **99.4** | 98.4 | 87.6 | 79.4 | 38.7 |
| Prompt injection | **100.0%** | 98.5% | 99.5% | 97.6% | 77.1% |
| Jailbreak | **100.0%** | 97.8% | 97.8% | 95.6% | n/a |
| Data exfiltration | **100.0%** | 100.0% | 95.4% | 96.6% | 30.8% |
| Tool abuse | **100.0%** | 100.0% | 98.8% | 86.3% | 8.9% |
| Multi-agent | **100.0%** | 100.0% | 100.0% | 94.3% | n/a |
| Provenance & audit | **100.0%** | 85.0% | 100.0% | 95.0% | n/a |
| Legitimate requests allowed | 97.0% | 100.0% | 63.1% | 58.5% | n/a |
| p50 latency per check | 22.7 ms | 1 ms | 19 ms | 133 ms | 111 ms |

<sub>**Read before quoting.** Other shields' numbers are from the benchmark README. Ours is **self-run** with a port of its scoring formula on the **held-out half** (265 cases), **not an official leaderboard entry**. Our local model was trained on the *other* half of the same public corpus, so it has seen the benchmark's style; expect lower accuracy on very different real-world traffic, where the remote judge and the action-level firewall still apply. The 99.4 run uses the **fast (latency-optimized) mode**; the product default is **careful mode**, which sends borderline cases to the remote judge while the AI is thinking. Ablation on the same cases: Prompt Guard 2 alone 22.1 → + rules 23.7 → + remote policy judge 92.2 → + local model **99.4**, p95 57 ms. Details: [docs/REPORT.md](docs/REPORT.md).</sub>

### 2. Our attack suite: real side effects

The same AI model runs each scenario **with and without** Michael-V1, and is judged by **what actually happened** (money moved, emails sent, secrets leaked), not by what it said.

| | Without shield | With Michael-V1 |
|---|---|---|
| 💥 Attacks that caused damage | **12 / 20** | **0 / 20** |
| ✅ Normal tasks still working | 6 / 6 | **6 / 6** (0 false alarms) |

Newer cases (Hindi / Hinglish / base64 / split-instruction / fake-CFO jailbreaks, Hindi and Hinglish normal requests) are verified at the input gate: **8/8 normal prompts allowed, all hard jailbreaks flagged** (`python -m tests.jailbreak_eval`).

### 3. Self-defense: attacks on the shield itself: 21 / 21

Value laundering, spelled-out account numbers, look-alike domains, fake "Michael-V1 approved" notes, hiding past the scan, policy tampering, audit-log editing, exfiltration loops, obfuscated and split commands, ASCII smuggling, SSRF, path traversal, zero-click markdown exfiltration, tool poisoning / rug pulls / shadowing, runaway loops, a kill switch and signed approvals. Each has an offline test (`python -m tests.test_self_defense`).

### 4. Posture scan: Grade A (100/100)

`python -m michael.scan` audits the deployment before it runs (secrets, policy, tool definitions, exposure, dependency pinning, audit chain), like static agent-config scanners, and grades it A–F.

### 5. Coverage map

Every item of the **OWASP Top 10 for Agentic Applications (2026)**, the **OWASP Top 10 for LLM Applications (2025)**, the main **MCP attacks** and attacks on the shield itself, mapped to the defense that handles it and marked covered / partial / out of scope ([`michael/coverage.py`](michael/coverage.py), shown on the console).

## ⚡ Latency: built to stay out of the way

| Change | Before | After |
|---|---|---|
| Inbox read (scan on arrival) | ~255 ms | **0.2 ms** |
| Phishing scenario, total shield time | 252 ms | **5.3 ms** |
| "Summarize inbox" (reads never wait) | 260 ms | **4.9 ms** |
| Benchmark p50 per check (faster judge) | 478 ms | 155 ms |
| Benchmark p50 per check (local model decides 98% of cases) | 155 ms | **22.7 ms** (p95 57 ms) |

How: a **local model on the laptop's CPU** (fine-tuned MiniLM + n-gram/embedding classifier, int8) decides ~98% of inputs in ~20 ms with no network · read-only steps take a fast path · rules before models · AI checks run **in parallel while the agent thinks** · inbox and files are scanned when they arrive, then cached · risky actions **fail closed** if a check is slow.

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
| **Self-defense** | Normalized tracing, fail-closed sinks, pinned policy and tools, hash-chained audit log, per-task limits, kill switch, signed approvals |
| **Local fast path** | A local model (n-grams + MiniLM embeddings, CPU) decides clear cases in milliseconds with no network call; only unsure cases reach the hosted detectors |
| **Beyond prompts** | SSRF and path guards on tools, ASCII-smuggling decoding, zero-click markdown exfiltration stripping, tool poisoning / rug-pull / shadowing detection |

## 🖥️ The console

`python -m michael.server` → http://localhost:8000

- **Home:** what Michael-V1 is for, in one screen: an animated attack being stopped, headline numbers, how it works, where to use it.
- **Playground:** pick a model and a situation; two chat-style panels show the same request without and with the shield, every action as a card, what was blocked and why.
- **Any model:** the same attacks on three models, plus copy-paste integration code.
- **Results:** benchmark verdict, score-vs-speed chart, per-category comparison, attack-suite numbers.
- **Security:** attacks on the shield and their tests, posture grade, OWASP / MCP coverage map.



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
