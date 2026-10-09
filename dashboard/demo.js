// Michael-V1 static demo: answers the dashboard's /api calls from recorded files in data/,
// and shares freeze + approval state with the demo Owner Vault (vault.html) through DemoStore.
// Loaded only in the exported site (python -m michael.export_static), never by the real server.
(function () {
  if (!window.MICHAEL_DEMO || !window.DemoStore) return;
  const realFetch = window.fetch.bind(window);
  const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } });
  const file = (name) => realFetch("data/" + name).then((r) => r.json());
  const VAULT = "vault.html";
  let trustIndex = null;

  window.fetch = async function (input, opt = {}) {
    const url = new URL(typeof input === "string" ? input : input.url, location.href);
    const p = url.pathname;
    if (!p.startsWith("/api/")) return realFetch(input, opt);
    const body = opt.body ? JSON.parse(opt.body) : {};
    switch (p) {
      case "/api/scorecard": return json(await file("scorecard.json"));
      case "/api/models": return json(await file("models.json"));
      case "/api/benchmark": return json(await file("benchmark.json"));
      case "/api/selfdefense": return json(await file("selfdefense.json"));
      case "/api/owner/status": {
        const S = DemoStore.get();
        return json({ lockdown: S.lockdown, kill_switch: false, approver_ready: true, approver_online: true, approver_url: VAULT, demo: true,
          requests: S.requests.map((r) => ({ id: r.id, code: r.code, tool: r.tool, status: r.status, created: r.created })) });
      }
      case "/api/trust": {
        trustIndex = trustIndex || await file("trust/index.json");
        const src = (body.sources || [])[0] || {};
        const i = trustIndex[JSON.stringify([body.prompt, src.label, src.text, body.tool, body.value])];
        if (i === undefined) return json({ detail: "This online demo has the 8 examples above. To check your own values, install Michael-V1 on your PC (see Install)." }, 400);
        return json(await file(`trust/${i}.json`));
      }
      case "/api/demo/freeze": {
        const S = DemoStore.get();
        if (S.lockdown) return json({ error: "frozen", lockdown: S.lockdown, approver_url: VAULT });
        const r = await file(`freeze/${body.attack}.json`);
        if ((r.steps || []).some((s) => s.phase === "attack" && s.scope === "system")) DemoStore.update((s) => { s.lockdown = r.lockdown; });
        return json({ ...r, approver_url: VAULT });
      }
      case "/api/demo/approval": {
        const S = DemoStore.get();
        const start = await file("approval_start.json");
        if (S.lockdown) {
          start.step = { ...start.step, state: "frozen", approval: null, reason: `FROZEN by Michael-V1: system lockdown: ${S.lockdown.reason}` };
          return json({ ...start, approver_url: VAULT });
        }
        const req = DemoStore.newRequest(start.step.tool, start.step.args, start.step.reason.split(" - ")[0]);
        start.step = { ...start.step, approval: { id: req.id, code: req.code } };
        return json({ ...start, approver_url: VAULT });
      }
      case "/api/demo/memory": return json(await file("memory/demo.json"));
      case "/api/memory/check": {
        const idx = await file("memory/index.json");
        const src = (body.sources || [])[0] || {};
        const i = idx[JSON.stringify([body.prompt, src.label, src.text, body.note])];
        if (i === undefined) return json({ detail: "This online demo has the 6 examples above. To check your own notes, install Michael-V1 on your PC (see Install)." }, 400);
        return json(await file(`memory/${i}.json`));
      }
      case "/api/xray/samples": return json(await file("xray/samples.json"));
      case "/api/xray":
        if (body.sample) return json(await file(`xray/result/${body.sample}.json`));
        return json({ detail: "This online demo scans the 7 examples above. To scan your own emails, PDFs and pages, install Michael-V1 on your PC: it runs offline, nothing is uploaded." }, 400);
      case "/api/compare":
        return json({ detail: "Live AI runs need the local install (they use your own Groq key)." }, 503);
    }
    if (p.startsWith("/api/xray/sample/")) return json(await file(`xray/sample/${p.split("/").pop()}.json`));
    if (p.startsWith("/api/demo/approval/") && p.endsWith("/continue")) {
      const id = p.split("/")[4];
      const finish = await file("approval_finish.json");
      const r = DemoStore.get().requests.find((x) => x.id === id);
      if (r && r.status === "approved") {
        DemoStore.update((s) => { const q = s.requests.find((x) => x.id === id); if (q) q.status = "used"; });
        return json({ ...finish, status: { ...finish.status, status: "used" } });
      }
      // denied or never decided: nothing runs
      finish.steps = finish.steps.map((st) => ({ ...st, state: "blocked", reason: st.reason || "no valid owner approval" }));
      return json(finish);
    }
    if (p.startsWith("/api/approval/")) {
      const id = p.split("/")[3];
      const r = DemoStore.get().requests.find((x) => x.id === id);
      if (!r) return json({ detail: "no such request" }, 404);
      return json({ id: r.id, code: r.code, status: r.status, tool: r.tool, args: r.args, signed: r.status === "approved",
        expires_in: Math.max(0, r.expires - Date.now() / 1000), demo: true });
    }
    return json({ detail: "not available in the online demo" }, 404);
  };

  document.addEventListener("DOMContentLoaded", () => {
    const main = document.querySelector("main");
    const bar = document.createElement("div");
    bar.className = "panel";
    bar.style.cssText = "display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:10px 16px;border-color:rgba(61,217,255,.35);background:rgba(61,217,255,.06)";
    bar.innerHTML = '<span class="tag sky">ONLINE DEMO</span><span class="small" style="flex:1;min-width:200px;color:var(--ink2)">Real results recorded from the shield. The demo Owner Vault (login <b style="color:var(--amber)">admin</b> / <b style="color:var(--amber)">michael-demo</b>) releases freezes and approves held actions. Live AI runs work after installing it on your PC.</span><a class="btn" href="vault.html" target="_blank" rel="noopener">Open the Owner Vault ↗</a><a class="btn" href="#install">Install on your PC →</a>';
    main.prepend(bar);
    const live = document.getElementById("liveBtn");
    if (live) live.outerHTML = '<a class="btn" href="#install" style="justify-content:center">Live runs: install on your PC</a>';
  });
})();
