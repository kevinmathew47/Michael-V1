# Live demo script (5 minutes)

## Before the judges arrive

1. Laptop on charger, Wi-Fi on (the live AI runs use Groq).
2. Double-click `live_demo.bat` in the project folder, or run `python -m michael.server`.
3. Two tabs open: the dashboard (`http://localhost:8000`) and the Owner Vault (`http://127.0.0.1:8765`).
4. Sign in to the Owner Vault once, so it's ready. It signs out after 5 minutes idle; just sign in again.
5. Keep `https://finels.vercel.app` open in a third tab as a backup.

## Run of show

| Time | Page | What you click | What you say |
|---|---|---|---|
| 0:00 | **Arena** | Pick *Web page orders a ₹50,000 payment*, then **Run it live now** (nothing runs until you press it) | "Nothing is pre-recorded. Same request, same AI, twice. Live, right now." |
| 0:20 | Arena | Point at the two results | "Without the shield the AI paid ₹50,000 to a stranger. With Michael-V1 it read the page but the payment was blocked: the account came from the web page, not from you." |
| 1:00 | Arena | Pick another situation (hidden email or invoice), **Run it live now** | "Works on any trap: emails, web pages, files." |
| 1:40 | **X-Ray** | Sample **Resume** (white text), scan | "Invisible white text tells AI screeners to rank this candidate first. X-Ray shows the hidden order." |
| 2:20 | **Trust check** | Pick a preset, run | "This is how a target is judged: did *you* name it, or did something the AI read?" |
| 2:50 | **Memory** | Run | "One planted rule in memory would leak data forever. Only your own words get saved." |
| 3:30 | **Freeze & approve** | Pick an attack (e.g. edited policy) | "Attack the shield itself: everything freezes, reads included." |
| 3:50 | Owner Vault tab | Sign in, **Unlock** | "Only the owner can release it, on a private page the AI can't reach." |
| 4:10 | Freeze & approve | **Start: AI wants to pay an account you never named** | "Not proven bad, not proven safe, so it asks the owner." |
| 4:25 | Owner Vault tab | Type the 2-digit code, **Approve** | "Signed with the owner's private key: this exact payment, once, 10 minutes." |
| 4:45 | **Proof** | Scroll | "0 of 20 attacks through, 99.4 on the public benchmark, 26/26 attacks on the shield blocked." |

## If something goes wrong

- **Wi-Fi down or Groq slow:** the Arena waits for *Run it live now*, so open `http://localhost:8000/?stage=all` (recorded real runs) or `https://finels.vercel.app`. X-Ray, Trust check, Memory, Freeze and Approve all work offline.
- **Run the Arena before the freeze demo**, or unlock first: while the shield is frozen, the protected side blocks every action, so the comparison is less clear.
- **"Frozen" banner you didn't expect:** unlock it in the Owner Vault.
- **Owner Vault won't open:** run `python -m michael.approver --status`; the dashboard restarts the Vault on its own within a few seconds.
- **Laptop fails:** open `https://finels.vercel.app` on any phone or laptop (demo login for the Vault: `admin` / `michael-demo`).
- **Forgot the owner password:** `python -m michael.approver --reset-owner`.
