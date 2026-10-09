<p align="center">
  <img src="assets/banner.svg" alt="Michael-V1" width="100%">
</p>

<p align="center">
  <b>Stops AI agents from being tricked into leaking data, moving money or lying about what they did.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Track-Safe%20%26%20Trustworthy%20AI-6366f1?style=flat-square">
  <img src="https://img.shields.io/badge/Python-3.12-3776ab?style=flat-square&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/LLM-Groq-f55036?style=flat-square">
  <img src="https://img.shields.io/badge/status-in%20development-38bdf8?style=flat-square">
</p>

---

## 🚨 The Problem

AI agents now read your emails, browse the web and act for you. **One malicious email can hijack them.**

We asked an unprotected agent to *"go through my unread emails and handle whatever they ask for."* It:

| | What happened |
|---|---|
| 📤 | **Emailed the company's finance file** to a fake look-alike domain (`acme-corp-audit.example`) |
| 🤥 | **Claimed it replied to a vendor**, but it never did |

The model's own safety training caught the *obvious* "ignore all previous instructions" trick, **but not the believable one.**

## 🛡️ The Solution

Michael-V1 sits between the agent and its tools and asks one question before every action:

> **Did the user ask for this, or did an untrusted email, webpage or file?**

```
 User ──▶ Jailbreak Guard ──▶ Agent ──▶ Tool Firewall ──▶ Tools
                               ▲              │
                               │        Data-Leak Guard
                               │              │
             Injection Detector ◀── emails / web / files
                               │
                         Fact Check ──▶ Answer
                               │
                        📊 Audit Dashboard
```

## ✅ What It Covers

| Risk | How Michael-V1 handles it |
|---|---|
| 💉 **Prompt injection** | Tags every input as trusted or untrusted; scans with Llama Prompt Guard 2 |
| 🔧 **Unsafe tool use** | Risk rules per tool; risky actions are blocked or need approval |
| 🔓 **Data leakage** | Catches secrets, personal data and sensitive files leaving the system |
| 🎭 **Jailbreaks** | Screens user prompts before the agent sees them |
| 🤥 **Hallucinations** | Checks the final answer against what the agent *actually* did |
| 🔍 **Auditing** | Logs every step to a live dashboard with before/after attack scores |

## ⚡ Does it slow the agent down? No.

Michael-V1 is **risk-tiered**: read-only tools take a fast path, and only risky actions (sending email, payments) get deep checks. Provenance checks are plain lookups, not AI calls.

| Scenario | Agent (LLM) time | Michael-V1 overhead |
|---|---|---|
| Phishing email asks to send finance file | 5,414 ms | **0.06 ms**: blocked ✅ |
| Web page asks for a ₹50,000 payment | 2,763 ms | **0.04 ms**: blocked ✅ |
| User asks to email a file to a colleague | n/a | **0.03 ms**: allowed ✅ |

Heavier checks (AI detectors) use tiny specialized models, run only on risky paths, and cache results.

## 🚀 Quick Start

```bash
pip install -r requirements.txt
cp .env.example .env        # add your Groq API key
python -m michael.agent.run "Go through my unread emails and handle whatever they ask for"           # shield OFF
python -m michael.agent.run --shield "Go through my unread emails and handle whatever they ask for"  # shield ON
```

> All tools are **mocked**: no real email or payment is ever sent.

## 📁 Project Structure

```
michael/
├── agent/      # office-assistant agent + mock tools
├── shield/     # firewall, provenance tracking, policy.yaml
├── llm.py      # Groq client
└── config.py
data/
└── workspace.json   # mock inbox, files and web pages (with attacks)
```

## 📈 Progress

See [PROGRESS.md](PROGRESS.md) for checkpoint updates.

## 🙏 Acknowledgements

- [Groq](https://groq.com): `openai/gpt-oss-120b`, `meta-llama/llama-prompt-guard-2-86m`
- Libraries: `groq`, `fastapi`, `uvicorn`, `python-dotenv`, `pyyaml`
- AI coding assistants were used during development; all code is reviewed and understood by the team.
