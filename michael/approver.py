"""Michael-V1 Approver: the owner's private place to approve actions and unlock the shield.

    python -m michael.approver             ->  http://127.0.0.1:8765  (prints your PIN on first run)
    python -m michael.approver --new-pin   ->  choose a new PIN
    python -m michael.approver --status    ->  terminal: is the shield frozen? anything waiting?
    python -m michael.approver --list      ->  terminal: list approval requests
    python -m michael.approver --approve <id> / --deny <id>   ->  terminal: decide (PIN + request code)
    python -m michael.approver --unlock    ->  terminal: unlock a frozen shield

Why this is separate from the dashboard:
  * different process and port, bound to 127.0.0.1 only; the agent's web tool blocks localhost
  * owner PIN (stored as a salted PBKDF2 hash in ~/.michael), 5 wrong tries = 60 s lock
  * session cookie is HttpOnly + SameSite=Strict; Host and Origin are checked (no CSRF,
    no DNS rebinding); the page can't be framed (no clickjacking)
  * approvals are signed with the owner's Ed25519 private key in ~/.michael; the shield
    only holds the public key, so nothing on the agent side can forge an approval
  * the owner must type the 2-digit code shown with the request (approves the right one)
"""
import getpass
import secrets
import sys
import time

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from michael.shield import owner

HOST, PORT = "127.0.0.1", 8765
ALLOWED_HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
SESSION_TTL = 30 * 60

app = FastAPI(title="Michael-V1 Approver", docs_url=None, redoc_url=None, openapi_url=None)
_sessions = {}          # token -> expiry
_fails = {"n": 0, "until": 0.0}
_key = None


@app.middleware("http")
async def lock_down(request: Request, call_next):
    if request.headers.get("host") not in ALLOWED_HOSTS:  # DNS rebinding / other hosts
        return JSONResponse({"error": "forbidden host"}, status_code=403)
    if request.method != "GET":
        origin = request.headers.get("origin") or ""
        if origin.split("//")[-1] not in ALLOWED_HOSTS:  # cross-site requests (CSRF)
            return JSONResponse({"error": "forbidden origin"}, status_code=403)
    resp = await call_next(request)
    resp.headers.update({"X-Frame-Options": "DENY", "Content-Security-Policy":
                         "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                         "font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
                         "Referrer-Policy": "no-referrer", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
    return resp


def _authed(request: Request):
    tok = request.cookies.get("owner")
    if not tok or _sessions.get(tok, 0) < time.time():
        raise HTTPException(401, "PIN required")


class Pin(BaseModel):
    pin: str


class Decision(BaseModel):
    id: str
    approve: bool
    code: str


def _check_pin(pin):
    if time.time() < _fails["until"]:
        raise HTTPException(429, f"too many wrong PINs, wait {int(_fails['until'] - time.time())} s")
    if not owner.check_pin(pin):
        _fails["n"] += 1
        if _fails["n"] >= 5:
            _fails.update(n=0, until=time.time() + 60)
        raise HTTPException(403, "wrong PIN")
    _fails["n"] = 0


@app.get("/health")
def health():
    return {"ok": True, "pin_set": owner.PIN_FILE.exists()}


@app.post("/api/login")
def login(body: Pin):
    _check_pin(body.pin)
    tok = secrets.token_urlsafe(32)
    _sessions[tok] = time.time() + SESSION_TTL
    resp = JSONResponse({"ok": True})
    resp.set_cookie("owner", tok, httponly=True, samesite="strict", max_age=SESSION_TTL)
    return resp


@app.post("/api/logout")
def logout(request: Request):
    _sessions.pop(request.cookies.get("owner"), None)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("owner")
    return resp


@app.get("/api/state")
def state(request: Request):
    _authed(request)
    reqs = [{k: v for k, v in r.items() if k != "signature"} for r in owner.all_requests()[:30]]
    return {"lockdown": owner.lockdown_state(), "requests": reqs, "now": time.time()}


@app.post("/api/decide")
def decide(body: Decision, request: Request):
    _authed(request)
    rec, err = owner.decide(body.id, body.approve, body.code, _key)
    if err:
        raise HTTPException(400, err)
    return {"ok": True, "status": rec["status"]}


@app.post("/api/unlock")
def unlock(body: Pin, request: Request):
    _authed(request)
    _check_pin(body.pin)  # unlocking needs the PIN again
    owner.release()
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def page():
    return PAGE


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Michael-V1 Approver</title>
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@600;700;800&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#07060a;--panel:#100e15;--panel2:#17141e;--line:#262130;--ink:#f1eef7;--ink2:#c4bdd3;--muted:#867d98;--amber:#ffb547;--amber-d:rgba(255,181,71,.13);--lime:#b8ff3c;--lime-d:rgba(184,255,60,.12);--coral:#ff4d6d;--coral-d:rgba(255,77,109,.14)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14.5px/1.55 Inter,system-ui,sans-serif;min-height:100vh}
button,input{font:inherit;color:inherit}h1,h2{font-family:Sora,Inter,sans-serif;margin:0;letter-spacing:-.02em}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:16px 22px;border-bottom:1px solid var(--line);background:var(--panel)}
.brand{display:flex;gap:10px;align-items:center;font:800 17px Sora}.brand i{width:32px;height:32px;border-radius:9px;background:var(--amber);display:grid;place-items:center;color:#07060a;font-style:normal}
.tag{font:600 11px 'JetBrains Mono';letter-spacing:.12em;text-transform:uppercase;color:var(--amber)}
main{padding:20px 22px;display:grid;gap:14px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:18px}
.login{max-width:420px;margin:12vh auto;text-align:center}.login input{width:100%;text-align:center;letter-spacing:.5em;font:700 26px 'JetBrains Mono';background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:12px;margin:16px 0 10px}
.btn{border:1px solid var(--line);background:var(--panel2);border-radius:10px;padding:9px 16px;font-weight:700;cursor:pointer}.btn.ok{background:var(--lime);color:#07060a;border-color:var(--lime)}.btn.no{background:var(--coral-d);color:var(--coral);border-color:rgba(255,77,109,.5)}.btn.amb{background:var(--amber);color:#07060a;border-color:var(--amber)}
.err{color:var(--coral);min-height:20px;font-size:13px}.muted{color:var(--muted)}
.lock{border-color:rgba(255,77,109,.6);background:var(--coral-d)}.lock h2{color:var(--coral)}
.req{display:grid;grid-template-columns:minmax(0,1fr) 280px;gap:16px;border:1px solid var(--line);border-radius:14px;padding:16px;background:var(--panel2)}
.req.pending{border-color:rgba(255,181,71,.55);box-shadow:0 0 0 1px rgba(255,181,71,.25)}
.args{display:grid;grid-template-columns:auto minmax(0,1fr);gap:4px 14px;font:13px 'JetBrains Mono';margin:10px 0}.args b{color:var(--muted);font-weight:600}.args span{word-break:break-all}
.hid{background:var(--coral);color:#fff;border-radius:4px;padding:0 3px;font-size:11px}
.act{display:grid;gap:8px;align-content:start}.act input{text-align:center;font:700 20px 'JetBrains Mono';letter-spacing:.3em;background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:8px}
.st{font:700 11px 'JetBrains Mono';letter-spacing:.1em;text-transform:uppercase;padding:3px 8px;border-radius:999px;background:var(--panel)}
.st.pending{color:var(--amber)}.st.approved,.st.used{color:var(--lime)}.st.denied,.st.expired{color:var(--coral)}
.grid{display:grid;gap:10px}@media(max-width:760px){.req{grid-template-columns:1fr}}
</style></head><body>
<div class="top"><div class="brand"><i>&#9670;</i>Michael-V1 Approver</div><div class="tag">owner only · 127.0.0.1</div></div>
<div id="app"></div>
<script>
const $=s=>document.querySelector(s), esc=t=>String(t??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const show=v=>esc(typeof v==="string"?v:JSON.stringify(v)).replace(/[^\\x00-\\x7f]/gu,c=>(n=>n>=0x2000&&n<0x2070||n===0xfeff||n>=0xff00||n>=0x400&&n<0x500||n>=0xe0000)(c.codePointAt(0))?`<span class="hid">U+${c.codePointAt(0).toString(16).toUpperCase()}</span>`:c);
const api=(u,b)=>fetch(u,b?{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b)}:{}).then(async r=>{const d=await r.json().catch(()=>({}));if(!r.ok)throw Object.assign(new Error(d.detail||d.error||r.status),{status:r.status});return d});
function login(msg){ $("#app").innerHTML=`<div class="panel login"><div class="tag">Owner sign-in</div><h1 style="margin-top:8px">Enter your PIN</h1><p class="muted">Shown once in the Approver's terminal. The agent and the dashboard never see it.</p><input id="pin" type="password" inputmode="numeric" autocomplete="off" maxlength="12" autofocus><div class="err" id="e">${esc(msg||"")}</div><button class="btn amb" id="go" style="width:100%">Unlock Approver</button></div>`;
  const go=()=>api("/api/login",{pin:$("#pin").value}).then(load).catch(e=>login(e.message)); $("#go").onclick=go; $("#pin").onkeydown=e=>e.key==="Enter"&&go(); }
let timer, last="";
async function load(){ let s; try{ s=await api("/api/state"); }catch(e){ if(e.status===401) return login(); throw e; }
  const sig=JSON.stringify([s.lockdown,s.requests.map(r=>[r.id,r.status])]);
  clearTimeout(timer); timer=setTimeout(load,3000);
  if(sig===last&&$("#out")) return;  // nothing changed: don't redraw under the owner's cursor
  last=sig;
  const L=s.lockdown, now=s.now;
  let h=`<main>`;
  h+= L?`<div class="panel lock"><div class="tag" style="color:var(--coral)">System frozen</div><h2>Michael-V1 froze every action</h2><p>${esc(L.reason)}</p><p class="muted">Since ${L.since?new Date(L.since*1000).toLocaleTimeString():"-"} · source: ${esc(L.source||"-")}. Fix the cause first (for example re-pin the policy on purpose), then unlock.</p>
     <div style="display:flex;gap:8px;flex-wrap:wrap"><input id="upin" type="password" placeholder="PIN again" style="background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:8px 12px"><button class="btn amb" id="unlock">Unlock the shield</button><span class="err" id="ue"></span></div></div>`
   :`<div class="panel" style="border-color:rgba(184,255,60,.35)"><div class="tag" style="color:var(--lime)">Shield running</div><h2 style="margin-top:4px">No lockdown</h2><p class="muted" style="margin:4px 0 0">If the shield is attacked, it freezes every action and only you can unlock it here.</p></div>`;
  const pend=s.requests.filter(r=>r.status==="pending");
  h+=`<div class="panel"><div class="tag">Waiting for you · ${pend.length}</div><div class="grid" style="margin-top:12px">`+(s.requests.length?s.requests.map(r=>`<div class="req ${r.status}">
     <div><div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><span class="st ${r.status}">${r.status}</span><b style="font-family:Sora">${r.tool==="make_payment"?"Payment":r.tool==="send_email"?"Email":esc(r.tool)}</b><span class="muted">#${esc(r.id)}</span></div>
       <div class="args">${Object.entries(r.args).map(([k,v])=>`<b>${esc(k)}</b><span>${show(v)}</span>`).join("")}</div>
       <div class="muted" style="font-size:13px">Why the shield asked: ${esc(r.reason)}</div></div>
     <div class="act">${r.status==="pending"?`<div class="muted" style="font-size:12px">Type the code shown next to this request on the dashboard · expires in ${Math.max(0,Math.round((r.expires-now)/60))} min</div><input maxlength="2" inputmode="numeric" id="c-${r.id}" placeholder="--"><div style="display:flex;gap:8px"><button class="btn ok" style="flex:1" data-d="1" data-id="${r.id}">Approve once</button><button class="btn no" data-d="0" data-id="${r.id}">Deny</button></div><div class="err" id="e-${r.id}"></div>`
       :`<div class="muted" style="font-size:13px">${r.status==="approved"?"Signed with your private key. Valid once, for this exact action.":r.status==="used"?"Approval used once. It can't be reused.":r.status==="denied"?"You denied this action.":"Expired without a decision."}</div>`}</div></div>`).join(""):`<p class="muted">No requests yet.</p>`)+`</div></div>`;
  h+=`<div style="text-align:right"><button class="btn" id="out">Sign out</button></div></main>`;
  const focus=document.activeElement&&document.activeElement.id, val=focus&&$("#"+focus)?.value;
  $("#app").innerHTML=h; if(focus&&$("#"+focus)){ $("#"+focus).value=val||""; $("#"+focus).focus(); }
  document.querySelectorAll("[data-id]").forEach(b=>b.onclick=()=>api("/api/decide",{id:b.dataset.id,approve:b.dataset.d==="1",code:$("#c-"+b.dataset.id).value}).then(load).catch(e=>$("#e-"+b.dataset.id).textContent=e.message));
  if($("#unlock")) $("#unlock").onclick=()=>api("/api/unlock",{pin:$("#upin").value}).then(load).catch(e=>$("#ue").textContent=e.message);
  $("#out").onclick=()=>api("/api/logout",{}).then(()=>login());
  clearTimeout(timer); timer=setTimeout(load,3000); }
load();
</script></body></html>"""


def _ask(prompt, secret=False):
    """Read from the owner's terminal (hidden for the PIN); falls back to stdin when piped."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt) if secret else input(prompt)
    print(prompt, end="", flush=True)
    return sys.stdin.readline().strip()


def _setup_pin(force=False):
    import os
    env_pin = os.getenv("MICHAEL_OWNER_PIN")
    if env_pin:
        owner.set_pin(env_pin)
        return
    if owner.PIN_FILE.exists() and not force:
        print("Owner PIN already set. Forgot it? Run: python -m michael.approver --new-pin")
        return
    pin = ""
    if force:
        pin = _ask("Choose a new owner PIN (4-12 digits, blank = random): ", secret=True).strip()
        if pin and not (pin.isdigit() and 4 <= len(pin) <= 12):
            sys.exit("The PIN must be 4-12 digits.")
    pin = pin or f"{secrets.randbelow(10**6):06d}"
    owner.set_pin(pin)
    bar = "=" * 52
    print(f"\n{bar}\n  Your Michael-V1 owner PIN:  {pin}\n  Keep it private. It is shown only this once.\n{bar}\n")


def _describe(r):
    args = ", ".join(f"{k}={v!r}" for k, v in r["args"].items())
    left = max(0, int(r["expires"] - time.time()))
    return f"  #{r['id']}  {r['status']:<8} {r['tool']}({args})" + (f"  · expires in {left // 60} min" if r["status"] == "pending" else "")


def cli():
    """The owner's second private channel: the terminal. Every command needs the PIN."""
    cmd = next((a for a in sys.argv[1:] if a.startswith("--")), "")
    target = next((a for a in sys.argv[2:] if not a.startswith("--")), None)
    if not owner.PIN_FILE.exists():
        sys.exit("No owner PIN yet. Start the Approver once: python -m michael.approver")
    if not owner.check_pin(_ask("Owner PIN: ", secret=True)):
        sys.exit("Wrong PIN.")
    lock = owner.lockdown_state()
    if cmd == "--status":
        print("SYSTEM FROZEN: " + lock["reason"] if lock else "Shield running, no lockdown.")
        pend = [r for r in owner.all_requests() if r["status"] == "pending"]
        print(f"{len(pend)} approval request(s) waiting." + (" Run: python -m michael.approver --list" if pend else ""))
    elif cmd == "--list":
        reqs = owner.all_requests()[:15]
        print("\n".join(_describe(r) for r in reqs) if reqs else "No approval requests.")
    elif cmd in ("--approve", "--deny"):
        rec = owner.get(target) if target else None
        if not rec:
            sys.exit("Usage: python -m michael.approver --approve <id>   (ids: --list)")
        print("You are deciding on this exact action:\n" + _describe(rec) + f"\n  why the shield asked: {rec['reason']}")
        code = _ask("Code shown with this request on the dashboard: ")
        done, err = owner.decide(rec["id"], cmd == "--approve", code, _key)
        print(err or ("Approved and signed with your private key (valid once, 10 min)." if cmd == "--approve" else "Denied."))
    elif cmd == "--unlock":
        if not lock:
            print("Not frozen. Nothing to unlock.")
        else:
            print("Frozen because: " + lock["reason"])
            if _ask("Unlock the shield? Type UNLOCK to confirm: ").strip() == "UNLOCK":
                owner.release()
                print("Shield unlocked.")
            else:
                print("Still frozen.")


CLI_COMMANDS = {"--status", "--list", "--approve", "--deny", "--unlock"}


def main():
    global _key
    sys.stdout.reconfigure(encoding="utf-8")
    _key = owner.ensure_owner_keys()
    if CLI_COMMANDS & set(sys.argv):
        return cli()
    _setup_pin(force="--new-pin" in sys.argv)
    print(f"Michael-V1 Approver (owner only): http://{HOST}:{PORT}")
    print("Terminal instead of the browser: python -m michael.approver --status | --list | --approve <id> | --deny <id> | --unlock")
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
