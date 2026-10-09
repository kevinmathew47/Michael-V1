"""Mock workplace tools the agent can call.

Nothing here touches the real world: emails, payments and file reads all
operate on data/workspace.json and an in-memory outbox, so attacks can be
demonstrated safely.
"""
import json
import copy
from pathlib import Path

WORKSPACE_PATH = Path(__file__).resolve().parents[2] / "data" / "workspace.json"


class Workspace:
    """Holds the mock state for one agent run."""

    def __init__(self, extra=None):
        self.data = json.loads(WORKSPACE_PATH.read_text(encoding="utf-8"))
        # Test cases can add emails / files / web pages, or simulate outages.
        for key, value in (extra or {}).items():
            if isinstance(value, list):
                self.data[key] = value + self.data.get(key, [])
            elif isinstance(value, dict):
                self.data.setdefault(key, {}).update(value)
            else:
                self.data[key] = value
        self.outbox = []     # emails the agent "sent"
        self.payments = []   # payments the agent "made"

    def snapshot(self):
        return {"outbox": copy.deepcopy(self.outbox), "payments": copy.deepcopy(self.payments)}


# --- tool implementations -------------------------------------------------

def read_inbox(ws: Workspace, unread_only: bool = False):
    mails = ws.data["inbox"]
    if unread_only:
        mails = [m for m in mails if m["unread"]]
    return mails


def read_file(ws: Workspace, filename: str):
    files = ws.data["files"]
    if filename not in files:
        return {"error": f"file not found: {filename}", "available": list(files)}
    return {"filename": filename, "content": files[filename]}


def list_files(ws: Workspace):
    return list(ws.data["files"])


def web_fetch(ws: Workspace, url: str):
    page = ws.data["web"].get(url)
    if page is None:
        return {"error": f"could not fetch {url}"}
    return {"url": url, "content": page}


def send_email(ws: Workspace, to: str, subject: str, body: str, attachment: str = ""):
    if ws.data.get("smtp_down"):
        return {"error": "SMTP server unavailable - email was NOT sent"}
    mail = {"to": to, "subject": subject, "body": body, "attachment": attachment}
    if attachment and attachment in ws.data["files"]:
        mail["attachment_content"] = ws.data["files"][attachment]
    ws.outbox.append(mail)
    return {"status": "sent", "to": to}


def make_payment(ws: Workspace, amount: float, account: str, note: str = ""):
    ws.payments.append({"amount": amount, "account": account, "note": note})
    return {"status": "paid", "amount": amount, "account": account}


TOOL_FUNCS = {
    "read_inbox": read_inbox,
    "read_file": read_file,
    "list_files": list_files,
    "web_fetch": web_fetch,
    "send_email": send_email,
    "make_payment": make_payment,
}

# Which tools bring *external, untrusted* content into the agent's context.
# The shield uses this to tag provenance of tool outputs.
UNTRUSTED_SOURCE_TOOLS = {"read_inbox", "read_file", "web_fetch"}


def _fn(name, desc, props, required=()):
    # Optional params also accept null - some models emit null instead of omitting them.
    for key, spec in props.items():
        if key not in required:
            spec["type"] = [spec["type"], "null"]
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": desc,
            "parameters": {"type": "object", "properties": props, "required": list(required)},
        },
    }


TOOL_SCHEMAS = [
    _fn("read_inbox", "Read emails from the user's inbox.",
        {"unread_only": {"type": "boolean", "description": "Only return unread emails"}}),
    _fn("read_file", "Read a file from the user's workspace.",
        {"filename": {"type": "string"}}, ["filename"]),
    _fn("list_files", "List files in the user's workspace.", {}),
    _fn("web_fetch", "Fetch the text content of a web page.",
        {"url": {"type": "string"}}, ["url"]),
    _fn("send_email", "Send an email on the user's behalf, optionally attaching a workspace file.",
        {"to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"},
         "attachment": {"type": "string", "description": "Workspace filename to attach"}},
        ["to", "subject", "body"]),
    _fn("make_payment", "Transfer money from the user's account.",
        {"amount": {"type": "number"}, "account": {"type": "string"}, "note": {"type": "string"}},
        ["amount", "account"]),
]
