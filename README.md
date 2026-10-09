<p align="center">
  <img src="assets/banner.svg" alt="Michael-V1" width="100%">
</p>

<h3 align="center">A firewall for AI agents. One email can hijack an agent; Michael-V1 stops it.</h3>

<p align="center">
  <a href="https://github.com/kevinmathew47/Michael-V1/releases/tag/v1.0.0"><img src="https://img.shields.io/badge/release-v1.0.0-b8ff3c?style=flat-square"></a>
  <img src="https://img.shields.io/badge/AgentShield%20Benchmark-99.4%20held--out-3dd9ff?style=flat-square">
  <img src="https://img.shields.io/badge/attacks%20through-0%20of%2020-34d399?style=flat-square">
  <img src="https://img.shields.io/badge/self--defense%20tests-26%2F26-34d399?style=flat-square">
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
| 🩻 **Universal X-Ray** | Scan an email, PDF or resume, web page, WhatsApp message or README: see the text a person can't see, the orders hidden for the AI, and every account, UPI ID, address and link it pushes. Runs offline. |
| 💸 **UPI Guard** | Traces UPI IDs and `upi://` payment links like bank accounts, and catches spoofed bank handles (`@okaxls`, `@paytrn`) and fake "refund / KYC" payees. |
| 🧠 **Memory Firewall** | Only your own words get into the AI's long-term memory. A rule planted by an email ("always CC reports to x") is blocked, unknown rules go to the owner, and old poisoned memories are quarantined. |
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
<summary><b>Self-defense: 26 attacks on the shield itself</b></summary>

Disguised and spelled-out account numbers, look-alike domains, fake "Michael-V1 approved" notes, forged approvals, an edited policy file, rewritten logs, poisoned or swapped tools, invisible text (ASCII smuggling), encoded and split commands, internal-server requests (SSRF), system-file reads, data hidden in image links, oversized content, runaway loops, mass sending, a rogue agent (kill switch), a system-wide freeze, private one-time approvals, UPI scams and memory poisoning. Every one has an offline test: `python -m tests.test_self_defense`. A posture scan grades the setup **A (100/100)**: `python -m michael.scan`.
</details>

## 🌐 Online demo

The dashboard also runs as a static demo website (recorded results, no server, no secrets): `python -m michael.export_static` then `npx vercel --prod`. Details: [docs/DEPLOY.md](docs/DEPLOY.md).

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

Open the **Owner Vault** at http://127.0.0.1:8765 once and create the owner account. Step-by-step for Windows, macOS and Linux: the dashboard's **Install** page, or **[docs/INSTALL.md](docs/INSTALL.md)**.

<p align="center"><img src="docs/screenshots/install.png" width="80%" alt="Install page"></p>

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
| **Universal X-Ray** | Drop in an email (.eml), PDF / resume, web page, chat or README and see what it would make your AI do. 7 ready examples, including a resume with white text for AI screeners. |
| **Memory firewall** | The same poisoned email on two assistants over two days: one leaks every report, the other never saves the rule. Plus a checker for any memory note. |
| **Trust check** | Type any account or email address and watch how the shield decides: allow, block or ask the owner. |
| **Freeze & approve** | Attack the shield and watch everything freeze; then an approval in the private Owner Vault. |
| **Install** | Step-by-step setup for your own PC (Windows, macOS, Linux) with copy buttons and fixes for common problems. |
| **Any AI model · Proof** | Results on several models, plug-in code, benchmark, self-tests and OWASP coverage. |

<p align="center"><img src="docs/screenshots/xray.png" width="80%" alt="Universal X-Ray on a resume with hidden white text"></p>
<p align="center"><img src="docs/screenshots/memory.png" width="80%" alt="Memory firewall: a poisoned memory rule blocked"></p>
<p align="center"><img src="docs/screenshots/trust.png" width="49%" alt="Trust check"> <img src="docs/screenshots/control.png" width="49%" alt="Freeze and approve"></p>

## 🧱 How it works

**1. Every request, step by step.** Michael-V1 sits between the AI agent and its tools, so everything coming in and everything going out passes a checkpoint.

```mermaid
flowchart TD
    U([👤 You]) -->|request| C1{"① Request check<br/>tricks, jailbreaks,<br/>hidden text"}
    C1 -->|clean| A["🤖 AI agent<br/>(any model)"]
    C1 -->|attack| X1[["⛔ Blocked<br/>nothing risky runs"]]

    W[/"📧 Emails · 🌐 web pages · 📄 files"/] --> C2{"② Scan on arrival<br/>hidden orders,<br/>secrets"}
    C2 -->|cleaned| A

    A -->|wants to send / pay| C3{"③ Who chose<br/>the target?"}
    C3 -->|you named it| C4{"④ Limits &<br/>look-alikes"}
    C3 -->|copied from an email<br/>or web page| X2[["⛔ Blocked"]]
    C3 -->|nobody named it| V[["🔑 Ask the owner<br/>in the Owner Vault"]]
    C4 -->|ok| T[("✅ Tools run<br/>email · pay · files")]
    C4 -->|too much / fake domain| X2

    A -->|reply| C5{"⑤ Answer check<br/>did it really<br/>do that?"}
    C5 --> R([💬 Honest reply to you])

    classDef stop fill:#3b0d16,stroke:#ff4d6d,color:#ffd6dd
    classDef ok fill:#1d2b07,stroke:#b8ff3c,color:#e9ffc2
    classDef ask fill:#33240a,stroke:#ffb547,color:#ffe7c2
    class X1,X2 stop
    class T,R ok
    class V ask
```

**2. How the shield decides if a target is safe** (step ③ in detail):

```mermaid
flowchart TD
    S["AI wants to pay account<br/><b>3333-9999</b>"] --> N["Clean up the value<br/>remove invisible characters,<br/>turn ３３３３ into 3333"]
    N --> Q1{"On your trusted<br/>contact list?"}
    Q1 -->|yes| OK[["✅ Allow"]]
    Q1 -->|no| Q2{"Looks like a trusted<br/>domain? acme-c0rp"}
    Q2 -->|yes| NO[["⛔ Block"]]
    Q2 -->|no| Q3{"Did YOU write it<br/>in your request?"}
    Q3 -->|yes| OK
    Q3 -->|no| Q4{"Copied from an email,<br/>web page or file?"}
    Q4 -->|yes| NO
    Q4 -->|no| ASK[["🔑 Ask the owner"]]

    classDef stop fill:#3b0d16,stroke:#ff4d6d,color:#ffd6dd
    classDef ok fill:#1d2b07,stroke:#b8ff3c,color:#e9ffc2
    classDef ask fill:#33240a,stroke:#ffb547,color:#ffe7c2
    class NO stop
    class OK ok
    class ASK ask
```

**3. When the shield itself is attacked, and how the owner takes over:**

```mermaid
flowchart LR
    ATK(["😈 Someone edits the policy,<br/>swaps a tool or<br/>forges an approval"]) --> DET{"Shield checks<br/>its own files and<br/>signatures"}
    DET -->|tampering found| FZ[["🧊 FREEZE<br/>every action of every task stops"]]
    FZ --> OV["🔑 Owner Vault<br/>127.0.0.1 only · owner password"]
    OV -->|owner fixes the cause<br/>and unlocks| RUN(["✅ Shield running again"])

    HOLD(["Held action:<br/>nobody named the target"]) --> OV2["🔑 Owner Vault<br/>owner checks the exact action<br/>and types its 2-digit code"]
    OV2 -->|approve| SIG[["✍️ Signed with the owner's private key<br/>this exact action · once · 10 min"]]
    OV2 -->|deny| NO2[["⛔ Never runs"]]
    SIG --> RUN2(["✅ Runs once"])

    classDef stop fill:#3b0d16,stroke:#ff4d6d,color:#ffd6dd
    classDef ok fill:#1d2b07,stroke:#b8ff3c,color:#e9ffc2
    classDef ask fill:#33240a,stroke:#ffb547,color:#ffe7c2
    class FZ,NO2 stop
    class RUN,RUN2,SIG ok
    class OV,OV2 ask
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
