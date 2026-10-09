"""Universal X-Ray: what would this content make your AI agent do?

Scan anything an AI agent reads (email, PDF / resume, web page, chat message,
README) and report, in plain language:

  hidden    text a person can't see but the AI reads (white or tiny text in PDFs,
            hidden HTML, comments, invisible characters, encoded commands)
  orders    sentences that give the AI instructions
  targets   accounts, UPI IDs, email addresses and links it pushes; used as an
            action target, each would be blocked by Michael-V1 (it came from this
            content, not from you), plus look-alike and spoofing checks
  sender    look-alike domains, mismatched Reply-To, fake bank / brand names
  secrets   passwords, keys, Aadhaar, PAN, cards inside the content

Offline: rules + the shield's local model. No content leaves the computer.
"""
import base64
import io
import re
from email import policy as email_policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path

import yaml

from michael.detectors import dlp, lookalike, normalize, upi
from michael.shield import guards
from michael.shield.firewall import IMPERSONATION, POLICY_PATH

MAX_BYTES = 2_000_000
KINDS = {"email": "Email", "pdf": "PDF / resume", "web": "Web page", "chat": "Chat / WhatsApp", "code": "Code / README", "text": "Any text"}
SAMPLES_DIR = Path(__file__).resolve().parent / "xray_samples"


# --- reading each kind of content ------------------------------------------------------

HIDDEN_STYLE = re.compile(r"(?i)display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:\.\d+)?(?:px|pt|em)?\b|"
                          r"opacity\s*:\s*0(?:\.0+)?\b|(?<![-\w])color\s*:\s*(?:#fff(?:fff)?\b|white\b|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))|"
                          r"height\s*:\s*0(?:px)?\b|max-height\s*:\s*0|left\s*:\s*-\d{3,}")
VOID = {"br", "img", "hr", "meta", "link", "input", "area", "base", "col", "embed", "source", "track", "wbr"}


class _HTML(HTMLParser):
    """Splits HTML into what a person sees and what is hidden from them."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.visible, self.hidden, self.links, self.stack, self.skip = [], [], [], [], 0

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag in ("script", "style", "head", "title"):
            self.skip += 1
        why = None
        if "hidden" in a or a.get("aria-hidden") == "true":
            why = "hidden HTML element"
        elif HIDDEN_STYLE.search(a.get("style", "")):
            why = f"hidden by style ({HIDDEN_STYLE.search(a['style']).group().strip()})"
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        if tag == "img" and a.get("src", "").startswith("http"):
            self.links.append(a["src"])
        if tag not in VOID:
            self.stack.append((tag, why))

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head", "title"):
            self.skip = max(0, self.skip - 1)
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        if self.skip or not data.strip():
            return
        why = next((w for _, w in reversed(self.stack) if w), None)
        if why:
            self.hidden.append({"where": why, "text": data.strip()})
        else:
            self.visible.append(data.strip())

    def handle_comment(self, data):
        if data.strip():
            self.hidden.append({"where": "HTML comment (never shown)", "text": data.strip()})


def _html(markup):
    p = _HTML()
    p.feed(markup)
    return {"visible": "\n".join(p.visible), "hidden": p.hidden, "links": p.links}


def _email(raw: bytes):
    msg = BytesParser(policy=email_policy.default).parsebytes(raw)
    meta = {"from": str(msg.get("From", "")), "reply_to": str(msg.get("Reply-To", "")), "subject": str(msg.get("Subject", "")),
            "to": str(msg.get("To", "")), "attachments": []}
    visible, hidden, links = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        name = part.get_filename()
        if name:
            meta["attachments"].append(name)
            continue
        ctype = part.get_content_type()
        try:
            body = part.get_content()
        except (LookupError, ValueError):
            body = part.get_payload(decode=True).decode("utf-8", "replace")
        if ctype == "text/html":
            h = _html(body)
            visible.append(h["visible"]); hidden += h["hidden"]; links += h["links"]
        elif ctype.startswith("text/"):
            visible.append(body)
    return {"visible": "\n".join(v for v in visible if v), "hidden": hidden, "links": links, "meta": meta}


def _pdf(raw: bytes):
    """Visible text plus text a reader can't see: white, near-white or microscopic."""
    from pdfminer.high_level import extract_pages
    from pdfminer.layout import LTChar, LTTextContainer

    def invisible(ch):
        color = getattr(ch.graphicstate, "ncolor", None)
        if isinstance(color, (int, float)):
            color = (color,)
        white = color is not None and ((len(color) in (1, 3) and min(color) >= 0.92) or (len(color) == 4 and max(color) <= 0.08))
        return "white text" if white else "microscopic text" if ch.size < 2 else None

    visible, hidden = [], []
    for page_no, page in enumerate(extract_pages(io.BytesIO(raw)), 1):
        for box in page:
            if not isinstance(box, LTTextContainer):
                continue
            for line in box:
                chars = [c for c in line if isinstance(c, LTChar)] if hasattr(line, "__iter__") else []
                if not chars:
                    continue
                run, kind, vis = "", None, ""
                for c in chars:
                    k = invisible(c)
                    if k:
                        run, kind = run + c.get_text(), k
                    else:
                        if run.strip():
                            hidden.append({"where": f"{kind} on page {page_no}", "text": run.strip()})
                        run = ""
                        vis += c.get_text()
                if run.strip():
                    hidden.append({"where": f"{kind} on page {page_no}", "text": run.strip()})
                if vis.strip():
                    visible.append(vis.strip())
    merged = []  # join neighbouring hidden runs from the same page
    for h in hidden:
        if merged and merged[-1]["where"] == h["where"]:
            merged[-1]["text"] += " " + h["text"]
        else:
            merged.append(dict(h))
    return {"visible": "\n".join(visible), "hidden": merged, "links": []}


def _text(text, markdown=False):
    hidden = [{"where": "HTML comment in Markdown (not shown when rendered)", "text": m.strip()}
              for m in re.findall(r"<!--(.*?)-->", text, re.S) if m.strip()] if markdown else []
    visible = re.sub(r"<!--.*?-->", "", text, flags=re.S) if markdown else text
    return {"visible": visible, "hidden": hidden, "links": []}


def read(kind, text=None, data=None, filename=""):
    """Turn whatever was given into {visible, hidden, links, meta}."""
    name = (filename or "").lower()
    if data is not None and len(data) > MAX_BYTES:
        raise ValueError("file too large (max 2 MB)")
    if kind == "pdf" or name.endswith(".pdf") or (data or b"").startswith(b"%PDF"):
        out, kind = _pdf(data or b""), "pdf"
    elif kind == "email" or name.endswith(".eml") or re.match(r"(?im)^(from|subject|to|received|return-path):", (text or "")[:400]):
        out, kind = _email(data if data is not None else (text or "").encode("utf-8")), "email"
    else:
        body = text if text is not None else (data or b"").decode("utf-8", "replace")
        if kind == "web" or name.endswith((".html", ".htm")) or re.search(r"(?i)<(html|body|div|span|p)\b", body[:2000]):
            out, kind = _html(body), "web" if kind in ("web", "text", None, "") else kind
        else:
            out = _text(body, markdown=kind == "code" or name.endswith(".md"))
    out.setdefault("meta", {})
    out["kind"] = kind
    return out


# --- what the content tries to do ---------------------------------------------------------

AI_ORDER = re.compile(
    r"(?i)\b(ignore (all |any |the )?(previous|prior|above|earlier) (instructions|rules|criteria)|disregard|"
    r"(dear |note to (the )?)?(ai|assistant|agent|chatbot|copilot|llm|language model|screening system|bot)\b[^.\n]{0,40}\b(must|should|please|you are|instructions?)|"
    r"(note|instructions?|message|reminder) (to|for) (the )?(ai|assistants?|agents?|ai [a-z]+ agents?|bots?|chatbots?|llms?|copilots?|screening system)\b|"
    r"^\W*(?:\[[^\]]*\]\s*)?(?:[^:\n]{0,30}:\s*)?(?:assistant|ai|ai agent|chatbot|copilot)\s*:|"
    r"\b(ai|assistants?|agents?|ai agents|llms?|bots?) (reading|processing|summari[sz]ing) this\b|"
    r"system prompt|you are now|new instructions|do not (tell|mention|inform|reveal|show)|without (telling|asking|notifying)|"
    r"rank (this|me) .{0,30}(top|first|highest)|override|jailbreak)")
ACTION = re.compile(r"(?i)\b(pay|transfer|wire|send|forward|email|share|upload|post|submit|reply with|click|log ?in|"
                    r"sign ?in|verify|update (your )?kyc|download|install|run|execute|delete|cat)\b")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>)\]]+", re.I)
ACCOUNT_RE = re.compile(r"(?<![\w-])(\d{4}[- ]\d{4}(?:[- ]\d{2,8})?|\d{9,18})(?![\w-])")
PHONE_RE = re.compile(r"(?:\+91[- ]?)?(?<!\d)[6-9]\d{9}(?!\d)")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc"}
BRANDS = re.compile(r"(?i)\b(sbi|state bank|hdfc|icici|axis bank|kotak|paytm|phonepe|google pay|amazon|flipkart|microsoft|"
                    r"apple|income tax|uidai|rbi|npci|it (department|desk|support)|security team|hr department)\b")
FREEMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me", "protonmail.com", "rediffmail.com", "yandex.com"}


def _sentences(text):
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    return [p.strip() for p in parts if len(p.strip()) > 3][:120]


def _policy():
    return yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))


def _local_scores(sentences):
    try:
        from michael.detectors import local_model
        return [local_model.probability(s) or 0.0 for s in sentences]
    except Exception:
        return [0.0] * len(sentences)


def analyze(content):
    pol = _policy()
    trusted = {c.lower() for c in pol.get("trusted_contacts", [])}
    internal = {d.lower() for d in pol.get("internal_domains", [])}
    trusted_domains = internal | {c.rsplit("@", 1)[-1] for c in trusted}
    trusted_upi = {u.lower() for u in pol.get("trusted_upi", [])}

    hidden = list(content["hidden"])
    full = content["visible"] + ("\n" + "\n".join(h["text"] for h in hidden) if hidden else "")
    clean, tricks = normalize.normalize(full)
    for t in tricks:
        hidden.append({"where": t, "text": "(decoded) " + clean.split("\n[", 1)[-1][:300] if t in ("encoded instructions", "unicode tag smuggling") else "characters a person can't see"})

    # orders aimed at the AI
    sents = _sentences(clean)
    scores = _local_scores(sents)
    hidden_texts = " ".join(h["text"] for h in hidden).lower()
    orders = []
    for s, p in zip(sents, scores):
        rule = AI_ORDER.search(s)
        # the local model alone is not enough for a sentence: it must also carry an instruction word
        if rule or (p >= 0.93 and len(s) > 20 and normalize.INSTRUCTION_WORDS.search(s)):
            orders.append({"text": s[:300], "why": ("speaks to the AI: “" + rule.group()[:40] + "”") if rule else f"local model: {p:.0%} likely an injected order",
                           "hidden": s.lower()[:60] in hidden_texts, "score": round(max(p, 0.9 if rule else 0), 2)})
    rules = normalize.manipulation_rules(clean)
    fake_approval = [m.group()[:120] for m in IMPERSONATION.finditer(clean)]

    # targets it pushes
    asks = [s for s in sents if ACTION.search(s)]
    targets = []

    def add(kind, value, flags, trusted_flag=False):
        if any(t["value"].lower() == value.lower() for t in targets):
            return
        asked = next((a for a in asks if value.lower() in a.lower()), None)
        verdict = "trusted" if trusted_flag else "blocked"
        targets.append({"kind": kind, "value": value, "flags": flags, "verdict": verdict, "asked": asked[:200] if asked else None})

    for link in upi.find_links(clean):
        flags = [f"payment link: {link['name'] or '?'} · ₹{link['amount'] or '?'}"] + upi.check(link["payee"], trusted_upi)
        add("UPI payment link", link["payee"], flags, link["payee"] in trusted_upi)
    for vpa in upi.find_ids(clean):
        if vpa.rsplit("@", 1)[-1] in upi.KNOWN_HANDLES or any("imitates" in r for r in upi.check(vpa)):
            add("UPI ID", vpa, upi.check(vpa, trusted_upi), vpa in trusted_upi)
    for addr in EMAIL_RE.findall(clean):
        a = addr.lower().rstrip(".")
        if "@" in a and a.rsplit("@", 1)[-1] in upi.KNOWN_HANDLES:
            continue
        look = lookalike.check(a, trusted_domains)
        dom = a.rsplit("@", 1)[-1]
        add("email address", a, [look] if look else [], (a in trusted or dom in internal) and not look)
    for url in set(URL_RE.findall(full)) | set(content.get("links", [])):
        if not url.lower().startswith("http"):
            continue
        u = url.rstrip(".,;")
        host = (re.sub(r"^https?://", "", u, flags=re.I).split("/")[0].split(":")[0]).lower()
        flags = []
        bad = guards.url_guard(u)
        if bad:
            flags.append(bad)
        look = lookalike.check("x@" + host, trusted_domains)
        if look:
            flags.append(look)
        if host in SHORTENERS:
            flags.append("link shortener hides the real address")
        if guards._carries_data(u):
            flags.append("link carries data in it (a way to leak information)")
        add("link", u, flags, host in internal or any(host.endswith("." + d) for d in internal))
    for m in ACCOUNT_RE.finditer(clean):
        v = m.group()
        digits = re.sub(r"\D", "", v)
        if PHONE_RE.fullmatch(v) or re.fullmatch(r"(19|20)\d{2}[01]\d[0-3]\d", digits) or any(v in s for _, s in dlp.find(clean)):
            continue
        add("account number", v, [], False)
    for m in PHONE_RE.finditer(clean):
        add("phone number", m.group(), [], False)

    # sender (emails)
    meta, sender = content.get("meta", {}), []
    if meta.get("from"):
        frm = meta["from"]
        addr = (EMAIL_RE.findall(frm) or [""])[0].lower()
        dom = addr.rsplit("@", 1)[-1]
        look = lookalike.check(addr, trusted_domains) if addr else None
        if look:
            sender.append(f"sender {look}")
        name = frm.split("<")[0].strip(' "')
        if BRANDS.search(name) and (dom in FREEMAIL or not any(b in dom for b in BRANDS.search(name).group().lower().split())):
            sender.append(f"display name “{name}” claims to be {BRANDS.search(name).group()} but the address is {addr}")
        rt = (EMAIL_RE.findall(meta.get("reply_to", "")) or [""])[0].lower()
        if rt and rt.rsplit("@", 1)[-1] != dom:
            sender.append(f"replies go to a different domain: {rt}")
        for att in meta.get("attachments", []):
            if re.search(r"(?i)\.(exe|scr|js|vbs|bat|cmd|ps1|iso|lnk|html?)$", att) or re.search(r"(?i)\.\w+\.(exe|scr|js)$", att):
                sender.append(f"risky attachment: {att}")

    secrets = [{"kind": k, "value": (v[:4] + "…" + v[-2:]) if len(v) > 8 else "…"} for k, v in dlp.find(clean)]

    # score + verdict
    hidden_orders = [o for o in orders if o["hidden"]]
    pushed = [t for t in targets if t["verdict"] == "blocked" and t["asked"]]
    spoofed = [t for t in targets if any("imitates" in f or "non-ASCII" in f or "punycode" in f for f in t["flags"])]
    risky_links = [t for t in targets if t["kind"] == "link" and t["flags"]]
    score = (35 * bool(hidden_orders) + 25 * bool(orders) + 15 * bool(hidden) + 20 * bool(rules) + 25 * bool(fake_approval)
             + min(30, 15 * len(pushed)) + 25 * bool(spoofed) + 15 * bool(risky_links) + 20 * bool(sender) + 10 * bool(secrets)
             + 15 * any("poses as" in f for t in targets for f in t["flags"]))
    score = min(100, score)
    level = "attack" if score >= 55 else "suspicious" if score >= 25 else "safe"
    return {"kind": content["kind"], "score": score, "level": level, "summary": _summary(level, orders, hidden_orders, pushed, spoofed, sender, secrets, hidden),
            "orders": orders[:12], "hidden": hidden[:20], "targets": targets[:30], "sender": sender, "secrets": secrets,
            "rules": rules, "fake_approval": fake_approval, "meta": meta,
            "visible": content["visible"][:20000]}


def _summary(level, orders, hidden_orders, pushed, spoofed, sender, secrets, hidden):
    if level == "safe":
        return "Looks safe: no hidden orders, no tricks and nothing it tries to make your AI do."
    bits = []
    if pushed:
        t = pushed[0]
        verb = "pay" if t["kind"] in ("UPI ID", "UPI payment link", "account number") else "send data to" if t["kind"] == "email address" else "open"
        bits.append(f"tries to make your AI agent {verb} {t['value']}, which came from this content, not from you (Michael-V1 would block it)")
    if hidden_orders:
        bits.append(f"hides {len(hidden_orders)} order(s) for the AI where a person can't see them")
    elif orders:
        bits.append(f"gives the AI {len(orders)} instruction(s)")
    elif hidden:
        bits.append("contains text a person can't see")
    if spoofed:
        bits.append(f"uses a look-alike: {spoofed[0]['value']}")
    if sender:
        bits.append(sender[0])
    if secrets and not bits:
        bits.append(f"contains {len(secrets)} secret(s) the AI should not see")
    text = "; ".join(bits[:3]) or "has some warning signs"
    return text[0].upper() + text[1:] + "."


def scan(kind="text", text=None, data_b64=None, filename=""):
    data = base64.b64decode(data_b64) if data_b64 else None
    return analyze(read(kind, text=text, data=data, filename=filename))


# --- built-in examples ---------------------------------------------------------------------

SAMPLES = [
    ("bank_change", "Bank-change invoice email", "email", "bank_change.eml"),
    ("hidden_html", "Newsletter with a hidden order", "email", "newsletter_hidden.eml"),
    ("resume", "Resume with white text for AI screeners", "pdf", "resume_hidden.pdf"),
    ("web", "Vendor web page with hidden text", "web", "vendor_page.html"),
    ("whatsapp", "WhatsApp UPI / KYC scam", "chat", "whatsapp_upi.txt"),
    ("readme", "README that asks for your .env", "code", "readme_env.md"),
    ("safe", "Normal team message (Hinglish)", "chat", "team_hinglish.txt"),
]


def sample(sample_id):
    for sid, title, kind, fname in SAMPLES:
        if sid == sample_id:
            path = SAMPLES_DIR / fname
            if kind == "pdf":
                return {"kind": kind, "filename": fname, "data_b64": base64.b64encode(path.read_bytes()).decode(), "title": title}
            return {"kind": kind, "filename": fname, "text": path.read_text(encoding="utf-8"), "title": title}
    return None
