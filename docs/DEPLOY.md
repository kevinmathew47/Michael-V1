# Put the Michael-V1 website online (Vercel)

The online version is a **demo**: the real dashboard with results recorded from the shield.
It needs no server and holds no secrets. Its Owner Vault (`vault.html`) uses a public demo login, `admin` / `michael-demo`, checked in the browser: it shows the flow, it is not a security boundary. Live AI runs, checking your own values and the
private Owner Vault only work on a PC install (see [INSTALL.md](INSTALL.md)).

## Deploy (about 3 minutes)

```bash
python -m michael.export_static   # rebuilds site/ from the latest results (already in the repo)
npx vercel                        # first time: log in, accept the defaults
npx vercel --prod                 # publish to the production URL
```

Only `site/` and `vercel.json` are uploaded (see `.vercelignore`): never `.env`, keys, models or results.

**Or with Git:** on vercel.com choose *Add New → Project*, import `kevinmathew47/Michael-V1`, keep the
settings from `vercel.json` (no build, output folder `site`) and click *Deploy*. Every push to `main` then redeploys.

## What works online

| Works in the online demo | Needs the PC install |
|---|---|
| Arena replays of real recorded runs | "Run it live now" (uses your own Groq key) |
| Inside the shield, Any AI model, Proof, Install | Trust check with your own values (the 8 examples work online) |
| Trust check examples, Freeze & approve walkthrough | Your real Owner Vault (never online: it only runs on 127.0.0.1 with your own password) |
| **Demo Owner Vault** (`/vault.html`, login `admin` / `michael-demo`): release a freeze, approve or deny held actions | |
