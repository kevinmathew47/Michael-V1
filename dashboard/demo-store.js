// Michael-V1 online demo: state shared by the dashboard tab and the demo Owner Vault tab
// (same website, so both read the browser's localStorage). Demo only: the real Vault runs on
// the owner's PC with a hashed password and signs approvals with a private key.
(function () {
  const KEY = "michael-demo-v1";
  const now = () => Date.now() / 1000;
  const TRACE = "could not be traced to the user (not named by the user, not a trusted contact)";
  const seed = () => ({
    user: "admin", password: "michael-demo", lockdown: null,
    requests: [
      { id: "a1b2c3d4e5", code: "47", tool: "make_payment", args: { account: "9090-1212", amount: 45000 },
        reason: `make_payment.account='9090-1212' ${TRACE}`, status: "pending", created: now() - 240, expires: now() + 1800 },
      { id: "f6a7b8c9d0", code: "18", tool: "send_email", args: { to: "ca-office@ledger-review.example", subject: "Q3 numbers", body: "As discussed on the call." },
        reason: `send_email.to='ca-office@ledger-review.example' ${TRACE}`, status: "pending", created: now() - 180, expires: now() + 1800 },
      { id: "1029384756", code: "63", tool: "make_payment", args: { account: "4444-1111", amount: 150000 },
        reason: "payment limit: more than 100,000 in one task", status: "pending", created: now() - 90, expires: now() + 1800 },
      { id: "5647382910", code: "29", tool: "make_payment", args: { account: "7070-5050", amount: 8500 },
        reason: `make_payment.account='7070-5050' ${TRACE}`, status: "used", created: now() - 3600, expires: now() - 3000 },
      { id: "0192837465", code: "81", tool: "send_email", args: { to: "it-desk@acme-c0rp.example", subject: "Password reset", body: "Send me the admin password." },
        reason: `send_email.to='it-desk@acme-c0rp.example' ${TRACE}`, status: "denied", created: now() - 7200, expires: now() - 6600 },
    ],
  });
  let memory = null;  // used when the browser blocks localStorage (then the two tabs can't share state)
  const DemoStore = {
    get() {
      let s = null;
      try { s = JSON.parse(localStorage.getItem(KEY)); } catch (e) { s = memory; }
      if (!s) s = this.set(seed());
      s.requests.forEach((r) => { if (r.status === "pending" && r.expires < now()) r.expires = now() + 1800; });
      return s;
    },
    set(s) { memory = s; try { localStorage.setItem(KEY, JSON.stringify(s)); } catch (e) { } return s; },
    update(fn) { const s = this.get(); fn(s); return this.set(s); },
    reset() { return this.set(seed()); },
    newRequest(tool, args, reason) {
      const r = { id: Math.random().toString(16).slice(2, 12), code: String(10 + Math.floor(Math.random() * 90)), tool, args,
        reason, status: "pending", created: now(), expires: now() + 600 };
      this.update((s) => s.requests.unshift(r));
      return r;
    },
  };
  window.DemoStore = DemoStore;
})();
