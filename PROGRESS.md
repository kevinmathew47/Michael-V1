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

## Next
- [ ] Injection and jailbreak detectors (Prompt Guard 2)
- [ ] DLP guard
- [ ] Fact-check layer
- [ ] Dashboard + attack suite scoring
