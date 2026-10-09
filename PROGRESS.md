# Progress Log

## Checkpoint 1: agent and threat reproduction
- [x] Project setup, Groq client
- [x] Office-assistant agent with tool-calling loop and full step trace
- [x] Mock tools: inbox, files, web, send_email, make_payment
- [x] Attack scenarios in the mock workspace (hidden injection, phishing look-alike domain, poisoned web page, secrets file)
- [x] Reproduced: unprotected agent leaks the finance file to a phishing domain and hallucinates actions it never took

## Checkpoint 2: shield core
- [x] Provenance tracker: tags all inbox / file / web content as untrusted
- [x] Tool firewall with YAML risk policy (low-risk fast path, high-risk sink checks)
- [x] Blocks phishing email exfiltration and web-page payment injection
- [x] Legitimate user-directed actions still allowed (no false positive)
- [x] Latency measured per check: ~0.05 ms shield overhead vs ~3-5 s LLM time

## Checkpoint 3: detectors
- [x] Injection detector (Llama Prompt Guard 2, 86M): malicious emails/pages/files quarantined before the agent reads them
- [x] Jailbreak guard on user prompts, running in parallel with the agent's first LLM call
- [x] Data-leak guard: API keys, passwords, private keys, Aadhaar, PAN, card numbers (Luhn-checked)
- [x] Secrets redacted from files before they reach the LLM
- [x] Sensitive files can't be emailed outside company domains
- [x] Parallel scanning + content-hash cache to keep latency low
- [x] Finding: Prompt Guard misses believable phishing and some web injections; provenance layer covers them

## Checkpoint 4: fact-check
- [x] Action fact-check: "I've sent/replied/paid" claims verified against the real tool log (<1 ms, rules only)
- [x] Blocked actions correctly count as "not done"
- [x] Fact grounding in the background (gpt-oss-20b extracts claims, code checks numbers/dates/emails exist in sources)
- [x] First version took ~2.3 s (35% of response time); redesigned to sync rules + async LLM, now ~0 ms visible
- [ ] Known limit: fact grounding sometimes extracts the assistant's own statements; treated as a soft trust score

## Checkpoint 5: attack suite + dashboard
- [x] Attack suite: 20 attacks across all 6 risks + 6 normal tasks, judged by real side effects
- [x] Result: 12/20 attacks succeed without shield, 0/20 with Michael-V1; 6/6 normal tasks still work
- [x] Live dashboard: same prompt runs side by side (shield off vs on), full timeline, block reasons, latency
- [x] Scorecard tab reading results/scorecard.json
- [x] Suite found a gap: Prompt Guard missed fake "developer mode" (0.35) and "grandma" (0.0005) jailbreaks
- [x] Fix: policy judge (gpt-oss-20b) runs in parallel; fails closed before risky actions
- [x] gpt-oss-safeguard-20b tried first: free tier allows only 3 req/min (~20 s waits), so switched
- [x] Shared rate limiter for Groq's 30 req/min free tier

## Checkpoint 6: differentiation + new console
- [x] Researched existing open-source tools (CaMeL, Invariant, LlamaFirewall, LLM Guard, NeMo); honest comparison in README
- [x] New console: Trust Flow Map, SHIELD OFF/ON switch on the same run, damage meter
- [x] Attack Wall: 26 tiles, flip shield to see breaches vs held, click to replay recorded runs (no API call)
- [x] Aadhaar detection now validates the Verhoeff checksum (no false alarms on random 12-digit numbers)
- [x] Flow map + damage report computed for any run, shield on or off (michael/shield/flowmap.py)

## Checkpoint 7: self-defense, public benchmark, latency, console
- [x] Reviewed 416 "AgentShield" repos on GitHub + CaMeL, Invariant, LlamaFirewall, LLM Guard: positioning in docs/REPORT.md
- [x] AgentShield Benchmark adapter (537 public cases, Python port of its scoring); 50/50 dev/test split
- [x] Benchmark: dev 78.7 → 93.7 after improvements; **held-out test 92.2** (Lakera 79.4, Deepset 87.6, LLM Guard 38.7)
- [x] Input gate v2: broader judge policy, input wrapped as data, Qwen3 judge (p50 ~170 ms), 2 parallel votes
- [x] De-obfuscation: base64 (whole + split), spaced hex, reversed / bidi text, zero-width, look-alike Unicode
- [x] Rules: instruction splitting, authority + skip checks, unverifiable approval claims (0 false alarms on normal requests)
- [x] Hindi / Hinglish jailbreak + normal cases
- [x] Self-defense: normalized provenance, strict fail-closed sinks, look-alike domains, impersonation stripping, content cap, limits, pinned policy, hash-chained audit log (13/13 tests)
- [x] Latency: scan on arrival (inbox 255 ms → 0.2 ms), reads never wait, token-aware limiter
- [x] Daily-limit fallback for the agent model (gpt-oss-120b → gpt-oss-20b → qwen3)
- [x] Console redesign: Overview story, Attack Lab, Benchmark, Self-Defense, Changelog with plain-language explanations
- [ ] Known: Groq free-tier daily token cap (200k/model) reached today; remaining shield-ON suite reruns deferred to tomorrow

## Next
- [ ] Demo video, slides, final polish
