"""Attack coverage map: public threat lists -> Michael-V1 defenses.

Status: "covered" (dedicated defense + test), "partial" (helps, but not complete),
"out of scope" (needs something outside a runtime shield).
Sources: OWASP Top 10 for Agentic Applications (2026), OWASP Top 10 for LLM
Applications (2025), and published MCP attack research (tool poisoning, rug
pulls, shadowing, ASCII smuggling, markdown exfiltration).
"""

COVERAGE = [
    # --- OWASP Agentic Top 10 (2026) ---
    ("OWASP Agentic", "ASI01 Agent goal hijack", "covered",
     "Provenance firewall (targets traced to the user), Prompt Guard quarantine of emails/pages/files, input gate",
     "attack suite: 7 injection cases; benchmark prompt injection 100%"),
    ("OWASP Agentic", "ASI02 Tool misuse & exploitation", "covered",
     "Risk-tiered tool policy, strict sinks, URL guard (SSRF), path guard, loop guard, per-task limits",
     "tests: ssrf_urls_blocked, path_traversal_blocked, loops_blocked, action_and_payment_limits"),
    ("OWASP Agentic", "ASI03 Identity & privilege abuse", "covered",
     "Only HMAC-signed approvals count; text claims of approval/authority blocked by rules",
     "tests: only_signed_approvals_count, manipulation_rules; benchmark provenance 100%"),
    ("OWASP Agentic", "ASI04 Agentic supply chain", "covered",
     "Tool definitions pinned by hash (rug pull), poisoning scan, shadowing check, posture scan, pinned dependencies",
     "tests: tool_poisoning_rugpull_shadowing; python -m michael.scan"),
    ("OWASP Agentic", "ASI05 Unexpected code execution", "partial",
     "No code-execution tool is exposed; command/argument injection flagged by the input gate. Real sandboxing is out of scope",
     "benchmark tool abuse 93.5%"),
    ("OWASP Agentic", "ASI06 Memory & context poisoning", "covered",
     "Memory Firewall: a memory write is checked like an action (only the user's own words are saved; rules copied from "
     "emails or pages are blocked, unknown standing rules go to the owner); planted memories are quarantined on recall; "
     "untrusted content is tagged, scanned and quarantined before it enters context",
     "tests/test_self_defense.py::memory_firewall"),
    ("OWASP Agentic", "ASI07 Insecure inter-agent communication", "covered",
     "Messages from other agents treated as untrusted; fake 'approved by agent X' claims blocked; signed approvals only",
     "benchmark multi-agent 100%"),
    ("OWASP Agentic", "ASI08 Cascading failures", "partial",
     "Fail-closed on risky actions, loop guard, per-task caps, model fallback chains (agent + judge)",
     "tests: loops_blocked; judge/agent fallback"),
    ("OWASP Agentic", "ASI09 Human-agent trust exploitation", "covered",
     "Action fact-check: 'I sent / paid' verified against the real action log; fact grounding in the background",
     "attack suite hallucination cases"),
    ("OWASP Agentic", "ASI10 Rogue agents", "covered",
     "Kill switch, hash-chained audit log, every action must trace to the user",
     "tests: kill_switch_freezes_risky_actions, audit_log_tampering_detected"),
    # --- OWASP LLM Top 10 (2025) ---
    ("OWASP LLM", "LLM01 Prompt injection", "covered", "Input gate + scan on arrival + provenance", "benchmark PI 100%"),
    ("OWASP LLM", "LLM02 Sensitive information disclosure", "covered",
     "DLP (API keys, passwords, Aadhaar Verhoeff, PAN, cards Luhn), redaction before the AI reads, markdown-exfil stripping",
     "tests: aadhaar_checksum, markdown_exfiltration_stripped; benchmark exfil 97.4%"),
    ("OWASP LLM", "LLM03 Supply chain", "partial", "Pinned tools + dependencies, posture scan; no model-weight verification",
     "python -m michael.scan"),
    ("OWASP LLM", "LLM04 Data & model poisoning", "out of scope",
     "Training-time attack; Michael-V1 guards runtime. Local model trained only on public, reviewed data", "-"),
    ("OWASP LLM", "LLM05 Improper output handling", "partial",
     "External images / data-carrying links stripped from answers; secrets redacted. HTML/SQL escaping is the app's job",
     "tests: markdown_exfiltration_stripped"),
    ("OWASP LLM", "LLM06 Excessive agency", "covered", "Risk tiers, strict sinks, limits, fail closed, signed approvals",
     "attack suite: 0/20 got through"),
    ("OWASP LLM", "LLM07 System prompt leakage", "covered", "Input gate policy covers extraction in any format",
     "benchmark data exfiltration 97.4%"),
    ("OWASP LLM", "LLM08 Vector & embedding weaknesses", "partial",
     "Retrieved documents are untrusted content: scanned, quarantined, provenance-tracked", "-"),
    ("OWASP LLM", "LLM09 Misinformation", "partial", "Fact grounding of answers against the data the tools returned",
     "background fact check"),
    ("OWASP LLM", "LLM10 Unbounded consumption", "covered",
     "Tool-call cap, loop guard, content size cap, token-aware rate limiter", "tests: loops_blocked, oversized_content_is_truncated"),
    # --- MCP / tool-ecosystem attacks ---
    ("MCP & tools", "Tool poisoning (hidden instructions in tool descriptions)", "covered",
     "Description scan for hidden instructions and obfuscation", "tests: tool_poisoning_rugpull_shadowing"),
    ("MCP & tools", "Rug pull (tool changes after approval)", "covered", "Tool definitions pinned by SHA-256 in tools.lock",
     "tests: tool_poisoning_rugpull_shadowing"),
    ("MCP & tools", "Tool shadowing (duplicate tool names)", "covered", "Duplicate names rejected", "tests: tool_poisoning_rugpull_shadowing"),
    ("MCP & tools", "ASCII smuggling (Unicode tag characters)", "covered", "Tag characters decoded and flagged before detection",
     "tests: ascii_smuggling_decoded"),
    ("MCP & tools", "Markdown image exfiltration (zero-click)", "covered", "External images and data links stripped from answers",
     "tests: markdown_exfiltration_stripped"),
    ("MCP & tools", "SSRF through fetch tools", "covered", "URL guard: internal IPs, metadata, localhost, file://", "tests: ssrf_urls_blocked"),
    # --- attacks on the shield itself ---
    ("Shield itself", "Value laundering / spelled-out targets", "covered", "Normalized provenance + strict fail-closed sinks",
     "tests: laundering_* "),
    ("Shield itself", "Look-alike domains", "covered", "Edit distance + non-ASCII + punycode checks", "tests: lookalike_domains_blocked"),
    ("Shield itself", "Shield impersonation / fake approvals", "covered", "Markers stripped; only signed approvals", "tests: shield_impersonation_is_stripped"),
    ("Shield itself", "Policy tampering", "covered", "policy.yaml pinned by SHA-256, fail closed", "tests: tampered_policy_fails_closed"),
    ("Shield itself", "Audit log editing", "covered", "Hash-chained audit trail", "tests: audit_log_tampering_detected"),
    ("Shield itself", "Instructing the AI judge", "covered", "Input wrapped as data; 'answer 0' counts as an attack", "judge policy v2"),
    ("Shield itself", "Hiding past the scan / flooding detectors", "covered", "Content cap; fail closed when a check times out",
     "tests: oversized_content_is_truncated"),
    ("Shield itself", "Exhausting the detector's quota", "covered", "Judge fallback chain -> local model, no network needed", "judge fallback"),
]


def as_dicts():
    return [{"list": a, "risk": b, "status": c, "defense": d, "evidence": e} for a, b, c, d, e in COVERAGE]
