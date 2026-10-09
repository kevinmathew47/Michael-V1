# Progress Log

## Checkpoint 1: agent and threat reproduction
- [x] Project setup, Groq client
- [x] Office-assistant agent with tool-calling loop and full step trace
- [x] Mock tools: inbox, files, web, send_email, make_payment
- [x] Attack scenarios in the mock workspace (hidden injection, phishing look-alike domain, poisoned web page, secrets file)
- [x] Reproduced: unprotected agent leaks the finance file to a phishing domain and hallucinates actions it never took

## Next
- [ ] Shield core: provenance tagging + tool firewall policy
- [ ] Injection and jailbreak detectors (Prompt Guard 2)
- [ ] DLP guard
- [ ] Fact-check layer
- [ ] Dashboard + attack suite scoring
