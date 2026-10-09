# Installing Michael-V1 on another computer

Michael-V1 is a runtime firewall that sits between an AI agent and its tools. It works with any AI model (OpenAI, Claude, Gemini, Llama, Qwen, Mistral, Groq, Ollama…) because it guards the **tool calls**, not the model.

## Is it ready to give to other people?

**Yes, as a beta (v1.0.0, hackathon release).** What that means in practice:

| Ready | Not yet |
|---|---|
| Python SDK: wrap your agent's tools in a few lines, any model | No `pip install michael-v1` from PyPI yet: install from GitHub (below) |
| Dashboard + Owner Vault run on Windows, macOS and Linux (tested on Windows 11) | Only tested end to end on Windows 11 with Python 3.12 |
| 24/24 self-defense tests, posture scan grade A | Not independently security-audited |
| Works offline for its main check (tracing targets); the request check uses a free Groq key | Python only (no JavaScript / TypeScript SDK) |
| Owner Vault: freeze release and signed one-time approvals | Owner Vault is single-owner and local (127.0.0.1) only |

Benchmark numbers in the README are self-run, not an official leaderboard entry.

## 1. Requirements

- Python **3.10 or newer** (3.12 recommended), Git
- A free Groq API key from https://console.groq.com (used for the online request check; the target tracing works without it)
- About 1.5 GB of disk for the optional local AI stages (PyTorch, CPU only)

## 2. Install

```bash
git clone https://github.com/kevinmathew47/Michael-V1.git
cd Michael-V1
python -m venv .venv
```

Activate the environment: Windows `.venv\Scripts\activate` · macOS / Linux `source .venv/bin/activate`

```bash
pip install -e ".[local]"
```

(`pip install -e .` without `[local]` is a lighter install: the shield still works, and its local model uses only the n-gram stage.)
On a machine without a GPU, install the smaller CPU build of PyTorch first: `pip install torch==2.4.1 --index-url https://download.pytorch.org/whl/cpu`.

Then add your key:

```bash
cp .env.example .env        # Windows: copy .env.example .env
```

Open `.env` and set `GROQ_API_KEY=...`.

## 3. Check the setup

```bash
michael-doctor              # or: python -m michael.doctor
```

It checks Python, packages, the API key, the pinned policy and tools, the local model, the owner account and the Owner Vault, and says exactly what to fix.

## 4. Run the dashboard and create the owner account

```bash
michael-server              # or: python -m michael.server  -> http://localhost:8000
```

The dashboard also starts the **Owner Vault** in the background at http://127.0.0.1:8765.
Open it once and **create the owner account** (username + password). Only this account can release a frozen shield or approve held actions. It is stored only as a salted hash in `~/.michael` on that computer.

## 5. Protect your own agent (any AI model)

From your own project, with the same Python environment active:

```python
from michael.sdk import Michael
guard = Michael()

@guard.tool(reads_untrusted=True)                       # outside content: scanned + tracked
def read_inbox(): ...

@guard.tool(risk="high", sinks={"to": "strict"})        # target must come from the user
def send_email(to, subject, body): ...

with guard.session(user_prompt) as s:
    ...                                                 # your agent loop, any model
    answer = s.check_answer(model_reply)
```

A blocked call returns `{"error": "BLOCKED_BY_MICHAEL", "reason": ...}`, which you hand back to the model like any tool result.

**Other frameworks** (OpenAI-style or Claude-style tool calls): call `s.check_action(name, args)` before running a tool (`None` = allowed) and `s.record_read(name, args, content)` for any outside content (emails, web pages, RAG chunks, other agents' messages). See the dashboard's *Any AI model* page for copy-paste code.

## 6. Configure the policy for your tools

Edit `michael/shield/policy.yaml`:

- `tools`: each tool's risk (`low` = read-only, `high` = can send, pay, delete or share) and its **sinks**, meaning the arguments that decide where data or money goes (`strict` = must come from the user; `taint` = blocked if copied from outside content)
- `trusted_contacts`, `internal_domains`, `sensitive_files`, `limits`

Then pin it on purpose (otherwise the shield treats the edit as tampering and freezes):

```bash
python -m michael.shield.integrity --pin
```

## 7. Everyday operation

- **Frozen?** The shield freezes every action when it is attacked. Open the Owner Vault → sign in → **Unlock the shield** (after fixing the cause).
- **Held action?** When nobody named a target, the shield asks the owner: approve or deny it in the Owner Vault by typing the 2-digit code shown on the dashboard.
- **Optional terminal:** `michael-vault --status | --list | --approve <id> | --deny <id> | --unlock`
- **Forgot the owner password:** `michael-vault --reset-owner` (asks the current password), or delete `~/.michael/owner_pin` on that computer and create the account again.
- **Emergency stop:** create the file `michael/shield/KILL` (or set `MICHAEL_KILL=1`) to freeze every action.

## 8. Optional: the fine-tuned local model

The repo ships the n-gram and embedding stages. The 88 MB fine-tuned MiniLM stage is not in Git. To rebuild it:

```bash
git clone --depth 1 https://github.com/doronp/agentshield-benchmark external/agentshield-benchmark
python -m michael.detectors.finetune
```

## Security notes

- The Owner Vault only answers on 127.0.0.1, and the agent's web tool blocks localhost, so the agent can't reach it. Anyone who already controls the computer's files can still edit or delete Michael-V1's files: the shield protects against the AI agent and injected content, not against someone who owns the machine.
- Keep `.env` and `~/.michael` private. Never commit them.
- Tools in the demo are mocked: no real email or payment is ever sent by the demo.
