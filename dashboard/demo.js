// Michael-V1 static demo: answers the dashboard's /api calls from recorded files in data/.
// Loaded only in the exported site (python -m michael.export_static), never by the real server.
(function () {
  if (!window.MICHAEL_DEMO) return;
  const realFetch = window.fetch.bind(window);
  const state = { lockdown: null, approvalAt: 0 };
  const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } });
  const file = (name) => realFetch("data/" + name).then((r) => r.json());
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
      case "/api/owner/status":
        return json({ lockdown: state.lockdown, kill_switch: false, requests: [], approver_ready: true, approver_online: false, approver_url: "#install", demo: true });
      case "/api/trust": {
        trustIndex = trustIndex || await file("trust/index.json");
        const src = (body.sources || [])[0] || {};
        const i = trustIndex[JSON.stringify([body.prompt, src.label, src.text, body.tool, body.value])];
        if (i === undefined) return json({ detail: "This online demo has the 8 examples above. To check your own values, install Michael-V1 on your PC (see Install)." }, 400);
        return json(await file(`trust/${i}.json`));
      }
      case "/api/demo/freeze": {
        if (state.lockdown) return json({ error: "frozen", lockdown: state.lockdown, approver_url: "#install" });
        const r = await file(`freeze/${body.attack}.json`);
        if ((r.steps || []).some((s) => s.phase === "attack" && s.scope === "system")) state.lockdown = r.lockdown;
        return json(r);
      }
      case "/api/demo/approval":
        state.approvalAt = Date.now();
        return json(await file("approval_start.json"));
      case "/api/compare":
        return json({ detail: "Live AI runs need the local install (they use your own Groq key)." }, 503);
    }
    if (p.startsWith("/api/demo/approval/") && p.endsWith("/continue")) return json(await file("approval_finish.json"));
    if (p.startsWith("/api/approval/")) {
      const st = await file("approval_status.json");
      const waited = (Date.now() - state.approvalAt) / 1000;
      return json({ ...st, status: waited > 6 ? "approved" : "pending", expires_in: Math.max(0, 600 - waited), demo: true });
    }
    return json({ detail: "not available in the online demo" }, 404);
  };

  window.demoReset = () => { state.lockdown = null; };

  document.addEventListener("DOMContentLoaded", () => {
    const main = document.querySelector("main");
    const bar = document.createElement("div");
    bar.className = "panel";
    bar.style.cssText = "display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:10px 16px;border-color:rgba(61,217,255,.35);background:rgba(61,217,255,.06)";
    bar.innerHTML = '<span class="tag sky">ONLINE DEMO</span><span class="small" style="flex:1;min-width:200px;color:var(--ink2)">Real results recorded from the shield. Live AI runs, your own values and the private Owner Vault work after installing it on your PC.</span><a class="btn" href="#install">Install on your PC →</a>';
    main.prepend(bar);
    const live = document.getElementById("liveBtn");
    if (live) {
      live.outerHTML = '<a class="btn" href="#install" style="justify-content:center">Live runs: install on your PC</a>';
    }
  });
})();
