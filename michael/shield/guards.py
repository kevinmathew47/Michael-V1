"""Extra runtime guards covering attack classes beyond prompt text.

  url_guard        SSRF: internal IPs, cloud metadata, localhost, file:// and other schemes  (OWASP LLM06/ASI02)
  path_guard       path traversal and credential files (../, /etc/passwd, .ssh, .pem, .env)     (ASI02)
  strip_exfil_links  markdown image / link exfiltration in the agent's answer (EchoLeak-style)  (LLM02/ASI01)
  ToolRegistry     tool poisoning, rug pulls and tool shadowing (MCP03): pinned hash of every
                   tool definition, hidden-instruction scan, duplicate names                   (ASI04)
  LoopGuard        repeated identical calls and runaway tool use (unbounded consumption)       (LLM10/ASI08)
  kill_switch      one switch that freezes every risky action                                  (ASI10)

All checks are plain code: microseconds, no model calls.
"""
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from michael.detectors import normalize

KILL_FILE = Path(__file__).with_name("KILL")
TOOLS_LOCK = Path(__file__).with_name("tools.lock")


# --- SSRF -------------------------------------------------------------------------

BLOCKED_HOSTS = {"localhost", "metadata.google.internal", "metadata", "169.254.169.254", "100.100.100.200"}


def url_guard(url: str):
    """Reason string if fetching this URL is unsafe, else None."""
    try:
        u = urlparse(str(url).strip())
    except ValueError:
        return "malformed URL"
    if u.scheme not in ("http", "https"):
        return f"scheme '{u.scheme or 'none'}' is not allowed (only http/https)"
    host = (u.hostname or "").lower().rstrip(".")
    if not host:
        return "URL has no host"
    if host in BLOCKED_HOSTS or host.endswith((".internal", ".local", ".localhost")):
        return f"host '{host}' is internal (SSRF)"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return f"address {ip} is private/internal (SSRF)"
    except ValueError:
        if re.fullmatch(r"[0-9.]+|0x[0-9a-f]+|\d+", host):  # odd numeric forms like 2130706433
            return f"numeric host '{host}' (possible SSRF obfuscation)"
    return None


# --- path traversal ------------------------------------------------------------

SENSITIVE_PATH = re.compile(r"(?i)(^|/)(etc/(passwd|shadow|sudoers)|\.ssh|\.aws|\.gnupg|\.env\b|id_rsa|"
                            r".*\.(pem|key|p12|pfx|kdbx)$|proc/self|windows/system32)")


def path_guard(path: str):
    p = str(path).replace("\\", "/").strip()
    if not p:
        return None
    if ".." in p.split("/"):
        return "path traversal ('..') is not allowed"
    if p.startswith(("/", "~")) or re.match(r"^[a-zA-Z]:/", p):
        return "absolute paths outside the workspace are not allowed"
    if SENSITIVE_PATH.search(p):
        return f"'{p}' looks like a credential or system file"
    return None


# --- output exfiltration ------------------------------------------------------------

MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*<?(https?://[^)\s>]+)>?[^)]*\)")
MD_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(\s*<?(https?://[^)\s>]+)>?[^)]*\)")
RAW_URL = re.compile(r"https?://[^\s)\"'<>]+")


def _carries_data(url: str):
    u = urlparse(url)
    return bool(u.query) or len(u.path) > 60 or re.search(r"[A-Za-z0-9+/=_-]{24,}", u.path or "")


def strip_exfil_links(answer: str, internal_domains):
    """Remove external images (auto-loaded = zero-click leak) and external links/URLs that carry data."""
    removed = []

    def external(url):
        host = (urlparse(url).hostname or "").lower()
        return not any(host == d or host.endswith("." + d) for d in internal_domains)

    def drop_image(m):
        if external(m.group(1)):
            removed.append(m.group(1))
            return "[image removed by Michael-V1]"
        return m.group(0)

    def drop_link(m):
        if external(m.group(1)) and _carries_data(m.group(1)):
            removed.append(m.group(1))
            return "[link removed by Michael-V1]"
        return m.group(0)

    def drop_raw(m):
        url = m.group(0)
        if external(url) and _carries_data(url):
            removed.append(url)
            return "[link removed by Michael-V1]"
        return url

    out = MD_IMAGE.sub(drop_image, answer)
    out = MD_LINK.sub(drop_link, out)
    out = RAW_URL.sub(drop_raw, out)
    return out, removed


# --- tool registry: poisoning, rug pull, shadowing ---------------------------------------

# Wording that has no business in a tool description (seen in real MCP tool-poisoning attacks).
POISON = re.compile(r"(?i)(ignore (all |any )?(previous|prior|other) (instructions|rules)|<\s*/?\s*(important|system|secret)\s*>|"
                    r"(do not|don't|never) (tell|mention|inform|show) (the )?user|secretly|without (the )?user knowing|"
                    r"before (using|calling) this tool,? (first )?(read|send|call)|"
                    r"(read|include|pass|attach) [^.]{0,40}(\.ssh|id_rsa|\.env\b|mcp\.json|credentials|api[_ ]?key))")


def _tool_hash(schema):
    return hashlib.sha256(json.dumps(schema, sort_keys=True).encode()).hexdigest()


class ToolRegistry:
    """Pins every tool definition the agent is given. A changed description (rug pull),
    a hidden instruction in a description (tool poisoning) or two tools with the same
    name (shadowing) are reported and make the shield refuse risky actions."""

    def __init__(self, schemas, lock=TOOLS_LOCK):
        self.problems = []
        names = [s["function"]["name"] for s in schemas]
        for n in {n for n in names if names.count(n) > 1}:
            self.problems.append(f"tool shadowing: two tools named '{n}'")
        pinned = json.loads(Path(lock).read_text(encoding="utf-8")) if Path(lock).exists() else None
        for s in schemas:
            f = s["function"]
            text = f"{f.get('description', '')} " + json.dumps(f.get("parameters", {}))
            clean, tricks = normalize.normalize(text)
            if tricks or POISON.search(clean):
                self.problems.append(f"tool poisoning: hidden instructions in '{f['name']}' description")
            if pinned is None:
                self.problems.append("tools.lock missing - tool definitions cannot be verified")
                break
            if f["name"] not in pinned:
                self.problems.append(f"unknown tool '{f['name']}' (not pinned)")
            elif pinned[f["name"]] != _tool_hash(s):
                self.problems.append(f"rug pull: definition of '{f['name']}' changed since it was approved")
        self.ok = not self.problems


def pin_tools(schemas, lock=TOOLS_LOCK):
    Path(lock).write_text(json.dumps({s["function"]["name"]: _tool_hash(s) for s in schemas}, indent=2), encoding="utf-8")


# --- loops / unbounded consumption ----------------------------------------------------

class LoopGuard:
    def __init__(self, max_calls=12, max_repeats=3):
        self.max_calls, self.max_repeats, self.seen, self.calls = max_calls, max_repeats, {}, 0

    def check(self, tool, args):
        self.calls += 1
        key = tool + json.dumps(args, sort_keys=True)
        self.seen[key] = self.seen.get(key, 0) + 1
        if self.seen[key] > self.max_repeats:
            return f"loop: '{tool}' called with the same arguments {self.seen[key]} times"
        if self.calls > self.max_calls:
            return f"runaway: more than {self.max_calls} tool calls in one task"
        return None


# --- kill switch --------------------------------------------------------------------------

def kill_switch_on():
    return os.getenv("MICHAEL_KILL") == "1" or KILL_FILE.exists()


if __name__ == "__main__":
    from michael.agent.tools import TOOL_SCHEMAS
    pin_tools(TOOL_SCHEMAS)
    print(f"pinned {len(TOOL_SCHEMAS)} tool definitions -> {TOOLS_LOCK}")
