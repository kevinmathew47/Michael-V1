// Michael-V1 online demo: makes the Owner Vault page work without a server.
// Preset demo login: admin / michael-demo. Demo only: checked in the browser.
(function () {
  if (!window.MICHAEL_DEMO || !window.DemoStore) return;
  const realFetch = window.fetch.bind(window);
  const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } });
  const SKEY = "michael-demo-vault-session", IDLE = 300 * 1000;
  let mem = 0;
  const authed = () => { try { return Number(sessionStorage.getItem(SKEY) || 0) > Date.now(); } catch (e) { return mem > Date.now(); } };
  const touch = () => { const t = Date.now() + IDLE; mem = t; try { sessionStorage.setItem(SKEY, String(t)); } catch (e) { } };
  const signOut = () => { mem = 0; try { sessionStorage.removeItem(SKEY); } catch (e) { } };
  const fails = { n: 0, until: 0 };

  window.fetch = async function (input, opt = {}) {
    const p = new URL(typeof input === "string" ? input : input.url, location.href).pathname;
    if (p.endsWith("/health")) return json({ ok: true, has_owner: true });
    if (!p.includes("/api/")) return realFetch(input, opt);
    const b = opt.body ? JSON.parse(opt.body) : {};
    const S = DemoStore.get();
    if (p.endsWith("/api/login")) {
      if (Date.now() < fails.until) return json({ detail: `too many wrong tries, wait ${Math.ceil((fails.until - Date.now()) / 1000)} s` }, 429);
      if (String(b.user || "").trim().toLowerCase() === S.user && b.password === S.password) { fails.n = 0; touch(); return json({ ok: true }); }
      if (++fails.n >= 5) { fails.n = 0; fails.until = Date.now() + 60000; }
      return json({ detail: "wrong username or password" }, 403);
    }
    if (p.endsWith("/api/logout")) { signOut(); return json({ ok: true }); }
    if (!authed()) return json({ detail: "sign in required" }, 401);
    touch();
    if (p.endsWith("/api/state")) {
      return json({ user: S.user, lockdown: S.lockdown, requests: S.requests.slice().sort((a, c) => c.created - a.created), now: Date.now() / 1000, idle: IDLE / 1000 });
    }
    if (p.endsWith("/api/decide")) {
      const r = S.requests.find((x) => x.id === b.id);
      if (!r || r.status !== "pending") return json({ detail: "request is not pending (expired or already decided)" }, 400);
      if (String(b.code).trim() !== r.code) return json({ detail: "the code does not match the one shown with the request" }, 400);
      r.status = b.approve ? "approved" : "denied";
      r.decided = Date.now() / 1000;
      DemoStore.set(S);
      return json({ ok: true, status: r.status });
    }
    if (p.endsWith("/api/unlock")) {
      if (b.password !== S.password) return json({ detail: "wrong password" }, 403);
      S.lockdown = null; DemoStore.set(S);
      return json({ ok: true });
    }
    if (p.endsWith("/api/password")) {
      if (b.current !== S.password) return json({ detail: "wrong password" }, 403);
      if ((b.new || "").length < 4) return json({ detail: "the password needs at least 4 characters" }, 400);
      if (b.new !== b.confirm) return json({ detail: "the two passwords don't match" }, 400);
      S.password = b.new; DemoStore.set(S);
      return json({ ok: true });
    }
    return json({ detail: "not available in the online demo" }, 404);
  };

  // Demo banner: the preset login, and the codes the dashboard shows next to each held action.
  function renderBanner() {
    const el = document.getElementById("demoBar");
    if (!el) return;
    const S = DemoStore.get();
    const pend = S.requests.filter((r) => r.status === "pending");
    const label = (r) => r.tool === "make_payment" ? `Pay ₹${Number(r.args.amount).toLocaleString("en-IN")} → ${r.args.account}` : `Email → ${r.args.to}`;
    el.innerHTML = `<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <span style="font:700 11px 'JetBrains Mono';letter-spacing:.12em;color:#3dd9ff;border:1px solid rgba(61,217,255,.4);border-radius:999px;padding:3px 9px">ONLINE DEMO VAULT</span>
        <span style="color:#c4bdd3;font-size:13px">Demo login: <b style="color:#ffb547">admin</b> / <b style="color:#ffb547">${S.password === "michael-demo" ? "michael-demo" : "(you changed it)"}</b> · On a real install this page runs only on the owner's PC with your own password.</span>
        <span style="margin-left:auto;display:flex;gap:8px"><a href="index.html#control" style="color:#c4bdd3;font-size:13px">← Dashboard</a>
        <button id="demoReset" style="background:none;border:1px solid #29233a;border-radius:8px;color:#c4bdd3;padding:3px 10px;cursor:pointer;font-size:12px">Reset demo</button></span></div>
      ${pend.length ? `<div style="margin-top:8px;color:#8a81a0;font-size:12.5px">Codes shown on the dashboard: ${pend.map((r) => `<span style="color:#f1eef7">${label(r)}</span> → <b style="color:#ffb547;font-family:'JetBrains Mono'">${r.code}</b>`).join(" · ")}</div>` : ""}`;
    document.getElementById("demoReset").onclick = () => { DemoStore.reset(); signOut(); location.reload(); };
  }
  document.addEventListener("DOMContentLoaded", () => {
    const bar = document.createElement("div");
    bar.id = "demoBar";
    bar.style.cssText = "padding:10px 22px;border-bottom:1px solid #29233a;background:rgba(61,217,255,.05)";
    document.querySelector(".top").after(bar);
    renderBanner();
    setInterval(renderBanner, 2000);
  });
})();
