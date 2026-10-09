<p align="center">
  <img src="assets/banner.svg" alt="Michael-V1" width="100%">
</p>

<h3 align="center">A firewall for AI agents. One email can hijack an agent; Michael-V1 stops it.</h3>

<p align="center">
  <a href="https://github.com/kevinmathew47/Michael-V1/releases/tag/v1.0.0"><img src="https://img.shields.io/badge/release-v1.0.0-b8ff3c?style=flat-square"></a>
  <img src="https://img.shields.io/badge/AgentShield%20Benchmark-99.4%20held--out-3dd9ff?style=flat-square">
  <img src="https://img.shields.io/badge/attacks%20through-0%20of%2020-34d399?style=flat-square">
  <img src="https://img.shields.io/badge/self--defense%20tests-24%2F24-34d399?style=flat-square">
  <img src="https://img.shields.io/badge/works%20with-any%20AI%20model-6366f1?style=flat-square">
  <img src="https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square">
</p>

<p align="center">
  <a href="#-get-started">Get started</a> ·
  <a href="docs/INSTALL.md">Install guide</a> ·
  <a href="#-use-it-with-any-ai-model">Use it in your agent</a> ·
  <a href="#-results">Results</a> ·
  <a href="docs/REPORT.md">Technical report</a>
</p>

<p align="center"><img src="docs/screenshots/arena.png" width="100%" alt="Agent Arena: the same request on the same AI, without and with Michael-V1"></p>

## The problem

AI agents read your emails, web pages and files, and then **act**: they send email, pay invoices and share files. One planted message is enough to turn them against you. In our tests an unprotected agent:

- 💸 **paid ₹12,000 to a scammer**, because an email said *"we changed banks, pay this new account"*
- 📤 **emailed the company's finance file** to a look-alike domain
- 🤥 **said "I've replied to the vendor"** when it never did

## The idea

Before any risky action runs, Michael-V1 asks one question:

> ### Who chose this target: **you**, or something the AI **read**?

Every recipient, account and file is traced back to where it came from. If it was copied out of an email or a web page instead of your own request, the action is blocked, even when the text looks perfectly polite and every AI detector calls it safe.

## ✨ What you get

| | |
|---|---|
| 🛡️ **Action firewall** | Traces every target to its source. Disguised values (`3333 9999`, full-width digits, invisible characters) are traced too. |
| 🔍 **Input gate** | Catches jailbreaks and hidden instructions, including encoded, split and Hindi/Hinglish ones. A local model decides most inputs in ~20 ms. |
| ✅ **Truth check** | "I've sent it" or "payment done" is checked against what actually happened. |
| 🔒 **Data-leak guard** | Hides passwords, API keys, Aadhaar, PAN and card numbers before the AI sees them. |
| 🧊 **Freezes when attacked** | If someone edits its policy, swaps a tool or forges an approval, every action stops until the owner releases it. |
| 🔑 **Owner Vault** | A private page where only the owner approves held actions (signed, once, for that exact action) and releases a freeze. |
| 🤖 **Any AI model** | Guards the tools, not the model: OpenAI, Claude, Gemini, Llama, Qwen, Mistral, Groq, Ollama. |

## 📊 Results

| | Without a shield | With Michael-V1 |
|---|---|---|
| Real attacks that caused damage | **12 of 20** | **0 of 20** |
| Normal tasks still working | 6 of 6 | **6 of 6** |
| Public AgentShield Benchmark (held-out half) | | **99.4 / 100**, every attack category 100% |
| Time added per check | | **~23 ms** (the AI itself takes seconds) |

Tested live on **OpenAI gpt-oss-120B and gpt-oss-20B**: both were hijacked by every attack without the shield and were safe with it.

<details>
<summary><b>Benchmark details and comparison</b></summary>

Self-run on the open [AgentShield Benchmark](https://github.com/doronp/agentshield-benchmark) (537 cases) with a Python port of its scoring formula. We tuned on one half and report the **held-out half (265 cases)**.

| | **Michael-V1** | AgentGuard | Deepset DeBERTa | Lakera Guard | LLM Guard |
|---|---|---|---|---|---|
| **Final score** | **99.4** | 98.4 | 87.6 | 79.4 | 38.7 |
| Prompt injection | **100%** | 98.5% | 99.5% | 97.6% | 77.1% |
| Jailbreak | **100%** | 97.8% | 97.8% | 95.6% | n/a |
| Data exfiltration | **100%** | 100% | 95.4% | 96.6% | 30.8% |
| Tool abuse | **100%** | 100% | 98.8% | 86.3% | 8.9% |
| Multi-agent | **100%** | 100% | 100% | 94.3% | n/a |
| Provenance & audit | **100%** | 85.0% | 100% | 95.0% | n/a |
| Legitimate requests allowed | 97.0% | 100% | 63.1% | 58.5% | n/a |
| p50 latency | 22.7 ms | 1 ms | 19 ms | 133 ms | 111 ms |

<sub>Other shields' numbers are copied from the benchmark's README. Ours is **self-run, not an official leaderboard entry**. Our local model learned from the other half of the same public corpus, so expect lower accuracy on very different real-world traffic, where the remote judge and the action firewall still apply. Measured in fast mode; the product default (careful mode) sends borderline cases to the remote judge. Full method: [docs/REPORT.md](docs/REPORT.md).</sub>
</details>

<details>
<summary><b>Self-defense: 24 attacks on the shield itself</b></summary>

Disguised and spelled-out account numbers, look-alike domains, fake "Michael-V1 approved" notes, forged approvals, an edited policy file, rewritten logs, poisoned or swapped tools, invisible text (ASCII smuggling), encoded and split commands, internal-server requests (SSRF), system-file reads, data hidden in image links, oversized content, runaway loops, mass sending, a rogue agent (kill switch), a system-wide freeze, and private one-time approvals. Every one has an offline test: `python -m tests.test_self_defense`. A posture scan grades the setup **A (100/100)**: `python -m michael.scan`.
</details>

## 🚀 Get started

```bash
git clone https://github.com/kevinmathew47/Michael-V1.git
cd Michael-V1
pip install -e ".[local]"
cp .env.example .env                          # add a free Groq key from console.groq.com
python -m michael.detectors.finetune --download   # recommended: the fine-tuned local model (79 MB)
michael-doctor                                # checks everything and says what to fix
michael-server                                # dashboard at http://localhost:8000
```

Open the **Owner Vault** at http://127.0.0.1:8765 once and create the owner account. Full guide for other computers: **[docs/INSTALL.md](docs/INSTALL.md)**.

## 🔌 Use it with any AI model

Wrap your agent's tools once. Your model, prompts and agent loop stay the same.

```python
from michael.sdk import Michael
guard = Michael()

@guard.tool(reads_untrusted=True)                    # outside content: scanned and tracked
def read_inbox(): ...

@guard.tool(risk="high", sinks={"to": "strict"})     # the recipient must come from the user
def send_email(to, subject, body): ...

with guard.session(user_prompt) as s:
    ...                                              # your agent loop, any model
    answer = s.check_answer(model_reply)             # flags "I sent it" when it didn't happen
```

A blocked call returns `{"error": "BLOCKED_BY_MICHAEL", "reason": ...}`, which the model handles like any tool result. For OpenAI-style or Claude-style tool calls, use `s.check_action(name, args)` and `s.record_read(...)`.

## 🖥️ The dashboard

| | |
|---|---|
| **Arena** | The same request on the same AI twice, without and with the shield, stage by stage. |
| **Inside the shield** | The five checkpoints, and where the time goes. |
| **Trust check** | Type any account or email address and watch how the shield decides: allow, block or ask the owner. |
| **Freeze & approve** | Attack the shield and watch everything freeze; then an approval in the private Owner Vault. |
| **Any AI model · Proof** | Results on several models, plug-in code, benchmark, self-tests and OWASP coverage. |

<p align="center"><img src="docs/screenshots/trust.png" width="49%" alt="Trust check"> <img src="docs/screenshots/control.png" width="49%" alt="Freeze and approve"></p>

## 🧱 How it works

```
 you ──▶ ① request check ──▶ AI agent (any model) ──▶ ⑤ answer check ──▶ reply
                                 │ wants to act
                                 ▼
         ③ trace the target ─▶ ④ limits & look-alikes ─▶ tools (email · pay · files · web)
                                 ▲
 emails · web pages · files ──▶ ② scan on arrival (quarantine hidden orders, hide secrets)

 attack on the shield ──▶ 🧊 freeze everything ──▶ owner releases it in the Owner Vault
```

<details>
<summary><b>Project structure</b></summary>

```
michael/
├── sdk.py         protect any agent: @guard.tool, guard.session
├── shield/        firewall, provenance tracing, integrity, freeze + owner channel, policy.yaml
├── detectors/     input gate, local model, Prompt Guard, data-leak, look-alike, fact check
├── approver.py    Owner Vault (private page)
├── server.py      dashboard API
├── doctor.py      setup check
├── agent/         demo office-assistant agent with mocked tools
├── suite.py       attack suite, judged by real side effects
└── benchmark.py   AgentShield Benchmark adapter
dashboard/  tests/  attacks/  docs/  results/
```
</details>

> The demo's email, payment and file tools are **mocked**: no real email or payment is ever sent.

## 📄 License and credits

MIT, see [LICENSE](LICENSE).

- [Groq](https://groq.com) for the models (`gpt-oss-120b`, `gpt-oss-20b`, `qwen3`, `llama-prompt-guard-2-86m`)
- [AgentShield Benchmark](https://github.com/doronp/agentshield-benchmark) (Apache-2.0): test corpus and scoring method, used for evaluation only
- Ideas we build on: Google DeepMind's CaMeL (provenance), Meta's LlamaFirewall (Prompt Guard 2), Invariant Labs (data-flow rules)
- AI coding assistants were used during development; all code is reviewed and understood by the team.

<sub>Built for Track 2: Safe & Trustworthy AI.</sub>
