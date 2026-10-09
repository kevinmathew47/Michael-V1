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

## Next
- [ ] Dashboard + attack suite scoring
