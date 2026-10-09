"""Michael-V1 Owner Vault: the owner's private page to release a freeze and approve actions.

    python -m michael.approver             ->  http://127.0.0.1:8765   (the dashboard also starts it)
    python -m michael.approver --status | --list | --approve <id> | --deny <id> | --unlock   (terminal, optional)
    python -m michael.approver --reset-owner   ->  delete the owner account (the page asks to create a new one)

Why it is private:
  * separate app and port, bound to 127.0.0.1 only; the agent's web tool blocks localhost
  * owner account: username + password, stored as a salted PBKDF2 hash in ~/.michael (never in the repo)
  * 5 wrong sign-ins lock it for 60 s; the session cookie is HttpOnly + SameSite=Strict and
    expires after 5 minutes without activity; Host and Origin are checked (no CSRF, no DNS
    rebinding); the page can't be framed (no clickjacking); nothing is cached
  * approvals are signed with the owner's Ed25519 private key in ~/.michael; the shield only
    holds the public key, so nothing on the agent side can forge an approval
  * the owner types the 2-digit code shown with the request (approves the right one)
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
IDLE = 5 * 60  # session ends after 5 minutes without activity

app = FastAPI(title="Michael-V1 Owner Vault", docs_url=None, redoc_url=None, openapi_url=None)
_sessions = {}          # token -> expiry (sliding)
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
        _sessions.pop(tok, None)
        raise HTTPException(401, "sign in required")
    _sessions[tok] = time.time() + IDLE  # activity keeps the session alive


def _key_or_load():
    global _key
    if _key is None:
        _key = owner.ensure_owner_keys()
    return _key


class Login(BaseModel):
    user: str
    password: str


class Setup(BaseModel):
    user: str
    password: str
    confirm: str


class Password(BaseModel):
    password: str


class NewPassword(BaseModel):
    current: str
    new: str
    confirm: str


class Decision(BaseModel):
    id: str
    approve: bool
    code: str


def _throttle():
    if time.time() < _fails["until"]:
        raise HTTPException(429, f"too many wrong tries, wait {int(_fails['until'] - time.time())} s")


def _failed(msg):
    _fails["n"] += 1
    if _fails["n"] >= 5:
        _fails.update(n=0, until=time.time() + 60)
    raise HTTPException(403, msg)


def _check_password(pw):
    _throttle()
    if not owner.check_pin(pw):
        _failed("wrong password")
    _fails["n"] = 0


def _validate(user, pw, confirm):
    if not user.strip() or len(user.strip()) > 32:
        raise HTTPException(400, "choose a username (1-32 characters)")
    if len(pw) < 4:
        raise HTTPException(400, "the password needs at least 4 characters")
    if pw != confirm:
        raise HTTPException(400, "the two passwords don't match")


def _session_response():
    tok = secrets.token_urlsafe(32)
    _sessions[tok] = time.time() + IDLE
    resp = JSONResponse({"ok": True})
    resp.set_cookie("owner", tok, httponly=True, samesite="strict", max_age=12 * 3600)
    return resp


@app.get("/health")
def health():
    return {"ok": True, "has_owner": owner.has_owner()}


@app.post("/api/setup")
def setup(body: Setup):
    """First visit only: create the owner account. Refused once an owner exists."""
    if owner.has_owner():
        raise HTTPException(409, "an owner account already exists")
    _validate(body.user, body.password, body.confirm)
    owner.set_owner(body.user, body.password)
    _key_or_load()
    return _session_response()


@app.post("/api/login")
def login(body: Login):
    _throttle()
    if not owner.has_owner():
        raise HTTPException(409, "no owner account yet")
    if not owner.check_login(body.user, body.password):
        _failed("wrong username or password")
    _fails["n"] = 0
    return _session_response()


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
    return {"user": owner.owner_user(), "lockdown": owner.lockdown_state(), "requests": reqs, "now": time.time(), "idle": IDLE}


@app.post("/api/decide")
def decide(body: Decision, request: Request):
    _authed(request)
    rec, err = owner.decide(body.id, body.approve, body.code, _key_or_load())
    if err:
        raise HTTPException(400, err)
    return {"ok": True, "status": rec["status"]}


@app.post("/api/unlock")
def unlock(body: Password, request: Request):
    _authed(request)
    _check_password(body.password)  # releasing the freeze needs the password again
    owner.release()
    return {"ok": True}


@app.post("/api/password")
def change_password(body: NewPassword, request: Request):
    _authed(request)
    _check_password(body.current)
    _validate(owner.owner_user(), body.new, body.confirm)
    owner.set_owner(owner.owner_user(), body.new)
    _sessions.clear()  # every other session must sign in again
    return _session_response()


@app.get("/", response_class=HTMLResponse)
def page():
    return PAGE


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>Michael-V1 Owner Vault</title>
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@600;700;800&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#07060a;--panel:#100e15;--panel2:#17141e;--line:#29233a;--ink:#f1eef7;--ink2:#c4bdd3;--muted:#8a81a0;--amber:#ffb547;--amber-d:rgba(255,181,71,.13);--lime:#b8ff3c;--lime-d:rgba(184,255,60,.12);--coral:#ff4d6d;--coral-d:rgba(255,77,109,.14)}
*{box-sizing:border-box}html,body{background:var(--bg)}body{margin:0;color:var(--ink);font:14.5px/1.55 Inter,system-ui,sans-serif;min-height:100vh}
button,input{font:inherit;color:inherit}h1,h2,h3{font-family:Sora,Inter,sans-serif;margin:0;letter-spacing:-.02em}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:14px 22px;border-bottom:1px solid var(--line);background:var(--panel)}
.brand{display:flex;gap:10px;align-items:center;font:800 17px Sora}.brand i{width:32px;height:32px;border-radius:9px;background:var(--amber);display:grid;place-items:center;color:#07060a;font-style:normal;font-size:16px}
.tag{font:600 11px 'JetBrains Mono';letter-spacing:.12em;text-transform:uppercase;color:var(--amber)}
.muted{color:var(--muted)}.err{color:var(--coral);min-height:20px;font-size:13px}.ok{color:var(--lime)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px;min-width:0}
input.f{width:100%;background:var(--panel2);border:1px solid var(--line);border-radius:11px;padding:11px 13px;margin-top:6px}
input.f:focus{outline:2px solid var(--amber);outline-offset:1px}
label{display:block;font:600 11px 'JetBrains Mono';letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-top:14px}
.btn{border:1px solid var(--line);background:var(--panel2);border-radius:11px;padding:10px 16px;font-weight:700;cursor:pointer}
.btn.amb{background:var(--amber);color:#07060a;border-color:var(--amber)}.btn.ok{background:var(--lime);color:#07060a;border-color:var(--lime)}.btn.no{background:var(--coral-d);color:var(--coral);border-color:rgba(255,77,109,.5)}
.btn:disabled{opacity:.5;cursor:wait}
.auth{max-width:440px;margin:9vh auto;padding:0 16px}.auth .panel{padding:26px}
.layout{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:16px;padding:18px 22px}
.col{display:grid;gap:16px;align-content:start}
.lock{border-color:rgba(255,77,109,.6);background:var(--coral-d)}.lock h2{color:var(--coral)}
.free{border-color:rgba(184,255,60,.4)}.free h2{color:var(--lime)}
.big{font:800 26px Sora;margin:6px 0 4px}
.req{display:grid;grid-template-columns:minmax(0,1fr) 250px;gap:16px;border:1px solid var(--line);border-radius:14px;padding:16px;background:var(--panel2)}
.req.pending{border-color:rgba(255,181,71,.55)}
.args{display:grid;grid-template-columns:auto minmax(0,1fr);gap:4px 14px;font:13px 'JetBrains Mono';margin:10px 0}.args b{color:var(--muted);font-weight:600}.args span{word-break:break-all}
.hid{background:var(--coral);color:#fff;border-radius:4px;padding:0 3px;font-size:11px}
.act{display:grid;gap:8px;align-content:start}.code{text-align:center;font:700 20px 'JetBrains Mono';letter-spacing:.3em}
.st{font:700 11px 'JetBrains Mono';letter-spacing:.1em;text-transform:uppercase;padding:3px 8px;border-radius:999px;background:var(--panel)}
.st.pending{color:var(--amber)}.st.approved,.st.used{color:var(--lime)}.st.denied,.st.expired{color:var(--coral)}
.who{display:flex;gap:10px;align-items:center}.av{width:38px;height:38px;border-radius:50%;background:var(--amber-d);color:var(--amber);display:grid;place-items:center;font:800 16px Sora}
.list{display:grid;gap:10px;margin-top:12px}
.timer{font:600 12px 'JetBrains Mono';color:var(--muted)}
#shade{position:fixed;inset:0;background:rgba(7,6,10,.97);display:none;place-items:center;z-index:9;text-align:center}
@media(max-width:900px){.layout{grid-template-columns:1fr;padding:12px}.req{grid-template-columns:1fr}}
</style></head><body>
<div class="top"><div class="brand"><i>&#9670;</i>Michael-V1 Owner Vault</div><div class="tag">private · owner only · 127.0.0.1</div></div>
<div id="app"></div>
<div id="shade"><div><div class="tag">Hidden</div><h2 style="margin:8px 0">Vault hidden while you were away</h2><p class="muted">Click to show it again.</p></div></div>
<script>
const $=s=>document.querySelector(s), esc=t=>String(t??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const odd=n=>n>=0x2000&&n<0x2070||n===0xfeff||n>=0xff00||n>=0x400&&n<0x500||n>=0xe0000;
const show=v=>[...String(typeof v==="string"?v:JSON.stringify(v))].map(c=>odd(c.codePointAt(0))?`<span class="hid">U+${c.codePointAt(0).toString(16).toUpperCase()}</span>`:esc(c)).join("");
const api=(u,b)=>fetch(u,b?{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b)}:{}).then(async r=>{const d=await r.json().catch(()=>({}));if(!r.ok)throw Object.assign(new Error(d.detail||d.error||("error "+r.status)),{status:r.status});return d});
let timer, last="", idle=300, lastAct=Date.now(), S=null;

function bindForm(id, fn){ const f=$(id); f.onsubmit=async e=>{ e.preventDefault(); const b=f.querySelector("button"); b.disabled=true; try{ await fn(); }catch(err){ f.querySelector(".err").textContent=err.message; } b.disabled=false; }; }

function setupPage(){ last=""; $("#app").innerHTML=`<div class="auth"><form class="panel" id="f" autocomplete="off"><div class="tag">First time · create the owner account</div><h1 style="margin-top:8px">Create your owner account</h1>
  <p class="muted">Only this account can release a frozen shield and approve held actions. It is stored on this computer only (hashed), never in the project or the dashboard.</p>
  <label for="u">Username</label><input class="f" id="u" value="admin" autocomplete="off">
  <label for="p">Password</label><input class="f" id="p" type="password" autocomplete="new-password">
  <label for="c">Confirm password</label><input class="f" id="c" type="password" autocomplete="new-password">
  <div class="err" style="margin-top:10px"></div><button class="btn amb" style="width:100%">Create account and open the vault</button></form></div>`;
  $("#p").focus(); bindForm("#f", async()=>{ await api("/api/setup",{user:$("#u").value,password:$("#p").value,confirm:$("#c").value}); load(); }); }

function loginPage(msg){ last=""; clearTimeout(timer); $("#app").innerHTML=`<div class="auth"><form class="panel" id="f" autocomplete="off"><div class="tag">Owner sign-in</div><h1 style="margin-top:8px">Open the Owner Vault</h1>
  <p class="muted">Only the owner can release a frozen shield or approve a held action. The agent and the dashboard can't open this page.</p>
  <label for="u">Username</label><input class="f" id="u" value="admin" autocomplete="username">
  <label for="p">Password</label><input class="f" id="p" type="password" autocomplete="current-password">
  <div class="err" style="margin-top:10px">${esc(msg||"")}</div><button class="btn amb" style="width:100%">Sign in</button></form></div>`;
  $("#p").focus(); bindForm("#f", async()=>{ await api("/api/login",{user:$("#u").value,password:$("#p").value}); load(); }); }

async function start(){ const h=await api("/health").catch(()=>null); if(h&&!h.has_owner) return setupPage(); load(); }

async function load(){
  let s; try{ s=await api("/api/state"); }catch(e){ if(e.status===401) return loginPage(); return loginPage("The vault could not be reached. Is it running?"); }
  S=s; idle=s.idle||300;
  clearTimeout(timer); timer=setTimeout(load,3000);
  const sig=JSON.stringify([s.lockdown,s.requests.map(r=>[r.id,r.status])]);
  if(sig===last&&$("#out")) return; last=sig;
  const L=s.lockdown, now=s.now, pend=s.requests.filter(r=>r.status==="pending");
  let h=`<div class="layout"><div class="col">`;
  h+= L?`<div class="panel lock"><div class="tag" style="color:var(--coral)">System frozen</div><div class="big" style="color:var(--coral)">Every action is stopped</div><p>${esc(L.reason)}</p>
      <p class="muted" style="font-size:13px">Since ${L.since?new Date(L.since*1000).toLocaleTimeString():"-"} · source: ${esc(L.source||"-")}. Make sure the cause is fixed, then release the freeze.</p>
      <form id="uf" autocomplete="off" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px"><input class="f" id="upw" type="password" placeholder="Your password again" style="max-width:240px;margin:0" autocomplete="current-password"><button class="btn amb">Unlock the shield</button><span class="err"></span></form></div>`
   :`<div class="panel free"><div class="tag" style="color:var(--lime)">Shield running</div><div class="big" style="color:var(--lime)">Not frozen</div><p class="muted" style="margin:0">If the shield is attacked, it freezes every action and only you can release it here.</p></div>`;
  h+=`<div class="panel"><div class="tag">Held actions waiting for you · ${pend.length}</div><div class="list">`+(s.requests.length?s.requests.map(r=>`<div class="req ${r.status}">
     <div><div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><span class="st ${r.status}">${r.status}</span><b style="font-family:Sora">${r.tool==="make_payment"?"Payment":r.tool==="send_email"?"Email":esc(r.tool)}</b><span class="muted">#${esc(r.id)}</span></div>
       <div class="args">${Object.entries(r.args).map(([k,v])=>`<b>${esc(k)}</b><span>${show(v)}</span>`).join("")}</div>
       <div class="muted" style="font-size:13px">Why the shield held it: ${esc(r.reason)}</div></div>
     <div class="act">${r.status==="pending"?`<div class="muted" style="font-size:12px">Type the 2-digit code shown with this request on the dashboard · expires in ${Math.max(0,Math.round((r.expires-now)/60))} min</div><input class="f code" maxlength="2" inputmode="numeric" id="c-${r.id}" placeholder="--" autocomplete="off"><div style="display:flex;gap:8px"><button class="btn ok" style="flex:1" data-d="1" data-id="${r.id}">Approve once</button><button class="btn no" data-d="0" data-id="${r.id}">Deny</button></div><div class="err" id="e-${r.id}"></div>`
       :`<div class="muted" style="font-size:13px">${r.status==="approved"?"Signed with your private key. Valid once, for this exact action.":r.status==="used"?"Approval used once. It can't be reused.":r.status==="denied"?"You denied this action.":"Expired without a decision."}</div>`}</div></div>`).join(""):`<p class="muted">Nothing waiting. When the shield holds an action it appears here.</p>`)+`</div></div></div>`;
  h+=`<div class="col"><div class="panel"><div class="who"><div class="av">${esc((s.user||"?")[0].toUpperCase())}</div><div><b>${esc(s.user)}</b><div class="muted" style="font-size:12px">Owner · signed in</div></div></div>
      <p class="timer" id="idle" style="margin:12px 0 10px"></p><button class="btn" id="out" style="width:100%">Lock now (sign out)</button></div>
    <form class="panel" id="pf" autocomplete="off"><div class="tag">Change password</div>
      <label for="cp">Current password</label><input class="f" id="cp" type="password" autocomplete="current-password">
      <label for="np">New password</label><input class="f" id="np" type="password" autocomplete="new-password">
      <label for="np2">Confirm new password</label><input class="f" id="np2" type="password" autocomplete="new-password">
      <div class="err" style="margin-top:8px"></div><button class="btn" style="width:100%">Change password</button></form>
    <div class="panel"><div class="tag">Privacy</div><p class="muted" style="font-size:13px;margin:8px 0 0">This page only works on this computer (127.0.0.1). It signs out after ${Math.round(idle/60)} minutes without activity, hides itself when you switch away, can't be embedded in another page and is never cached.</p></div></div></div>`;
  const keep=document.activeElement&&document.activeElement.id, kv=keep&&$("#"+keep)?.value;
  $("#app").innerHTML=h; if(keep&&$("#"+keep)){ $("#"+keep).value=kv||""; $("#"+keep).focus(); }
  document.querySelectorAll("[data-id]").forEach(b=>b.onclick=()=>api("/api/decide",{id:b.dataset.id,approve:b.dataset.d==="1",code:$("#c-"+b.dataset.id).value}).then(()=>{last="";load();}).catch(e=>$("#e-"+b.dataset.id).textContent=e.message));
  if($("#uf")) bindForm("#uf", async()=>{ await api("/api/unlock",{password:$("#upw").value}); last=""; load(); });
  bindForm("#pf", async()=>{ await api("/api/password",{current:$("#cp").value,new:$("#np").value,confirm:$("#np2").value}); $("#pf .err").innerHTML='<span class="ok">Password changed.</span>'; ["#cp","#np","#np2"].forEach(x=>$(x).value=""); });
  $("#out").onclick=()=>api("/api/logout",{}).then(()=>loginPage("Signed out."));
}
// privacy: idle sign-out and hide the vault when the tab is in the background
["click","keydown","mousemove","touchstart"].forEach(ev=>addEventListener(ev,()=>{lastAct=Date.now();},{passive:true}));
setInterval(()=>{ if(!$("#out")) return; const left=Math.max(0,idle-(Date.now()-lastAct)/1000); const el=$("#idle"); if(el) el.textContent=`Auto sign-out in ${Math.floor(left/60)}:${String(Math.floor(left%60)).padStart(2,"0")}`;
  if(left<=0) api("/api/logout",{}).finally(()=>loginPage("Signed out after "+Math.round(idle/60)+" minutes without activity.")); },1000);
document.addEventListener("visibilitychange",()=>{ if(document.hidden&&$("#out")) $("#shade").style.display="grid"; });
$("#shade").onclick=()=>{ $("#shade").style.display="none"; lastAct=Date.now(); };
start();
</script></body></html>"""


# --- terminal (optional second channel) -----------------------------------------------

def _ask(prompt, secret=False):
    """Read from the owner's terminal (hidden for the password); falls back to stdin when piped."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt) if secret else input(prompt)
    print(prompt, end="", flush=True)
    return sys.stdin.readline().strip()


def _describe(r):
    args = ", ".join(f"{k}={v!r}" for k, v in r["args"].items())
    left = max(0, int(r["expires"] - time.time()))
    return f"  #{r['id']}  {r['status']:<8} {r['tool']}({args})" + (f"  · expires in {left // 60} min" if r["status"] == "pending" else "")


def cli():
    """The owner's terminal: the same actions as the vault page. Every command needs the password."""
    cmd = next((a for a in sys.argv[1:] if a.startswith("--")), "")
    target = next((a for a in sys.argv[2:] if not a.startswith("--")), None)
    if not owner.has_owner():
        sys.exit(f"No owner account yet. Open http://{HOST}:{PORT} to create it.")
    if not owner.check_pin(_ask("Owner password: ", secret=True)):
        sys.exit("Wrong password.")
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
        done, err = owner.decide(rec["id"], cmd == "--approve", code, _key_or_load())
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
    elif cmd == "--reset-owner":
        if _ask("Delete the owner account? Type DELETE to confirm: ").strip() == "DELETE":
            owner.PIN_FILE.unlink(missing_ok=True)
            print(f"Owner account deleted. Open http://{HOST}:{PORT} to create a new one.")


CLI_COMMANDS = {"--status", "--list", "--approve", "--deny", "--unlock", "--reset-owner"}


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    _key_or_load()
    if CLI_COMMANDS & set(sys.argv):
        return cli()
    print(f"Michael-V1 Owner Vault (owner only): http://{HOST}:{PORT}"
          + ("" if owner.has_owner() else "  -> open it to create the owner account"))
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
