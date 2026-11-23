# Bills — bills.rakeshvadnala.in

A tracker for monthly payday payments: credit cards, utilities, rent, EMI and transfers.
Everything is encrypted in the browser with a master password before it is saved to a private GitHub repo.

## How it works

```
Browser ──(master password → PBKDF2-SHA256 × 600,000 → AES-256-GCM key)──┐
   │                                                                     │
   │ plaintext exists only in this tab's memory                          ▼
   └── PUT ciphertext ──► github.com/<you>/bills-data/vault.json   {kdf, salt, iv, ct}
```

- **Two repos.** `bills` is public and holds this code; GitHub Pages serves it. `bills-data` is private and holds only `vault.json`, which is ciphertext.
- **Master password.** It is never stored or sent anywhere. Without it nobody can decrypt the vault: not GitHub, not anyone who reads the repo, and not you either if you forget it. There is no recovery.
- **GitHub token.** It is stored in this browser's localStorage, encrypted with the same master password, so a stolen laptop profile doesn't expose it.
- **Tamper detection.** AES-GCM is authenticated, so a vault that has been modified or corrupted fails to decrypt instead of loading wrong numbers.
- **Content Security Policy.** The page can only run its own `app.js` and can only connect to `api.github.com`.
- **Auto-lock.** The app locks after 10 minutes idle by default (change it in Settings). Locking clears the key from memory.

What is *not* hidden: that the vault exists, its approximate size, and the commit timestamps in `bills-data`.

## One-time setup

### 1. Code repo and GitHub Pages
1. Create a **public** repo named `bills` and push `index.html`, `app.js`, `style.css`, `CNAME` and this README.
2. Go to **Settings → Pages**. Set Source to *Deploy from a branch*, then pick `main` and `/ (root)`.
3. Set **Custom domain** to `bills.rakeshvadnala.in`. Once the certificate is issued (a few minutes), tick **Enforce HTTPS**.

### 2. DNS at Hostinger
Add one record:

| Type  | Name    | Points to                 | TTL  |
|-------|---------|---------------------------|------|
| CNAME | `bills` | `rakeshvadnala.github.io` | 3600 |

### 3. Data repo
Create a **private** repo named `bills-data` and tick *Add a README* so the `main` branch exists. Don't add anything else; the app creates `vault.json` itself.

### 4. Fine-grained token
Go to GitHub **Settings → Developer settings → Fine-grained tokens → Generate new token**:
- Repository access: **Only select repositories → `bills-data`**
- Permissions: **Contents → Read and write**. Metadata (read) is added automatically.
- Expiration: up to you, for example 1 year. When it expires, use "Forget this device" and reconnect with a new token. Your data is untouched.

### 5. First run
Open https://bills.rakeshvadnala.in and enter:
- owner `rakeshvadnala`, repo `bills-data`, branch `main`, path `vault.json`
- the token
- a strong master password, typed twice

If no vault exists yet, a new one is created. On a second device, use the same details and the same password; it finds the existing vault and only needs the password once (no confirm).

### 6. Import your Google Sheet history
Go to **Settings → Import from Google Sheet**. In the sheet, select columns **A to E** (date, payee, amount, note, status) for every row, copy, and paste into the box. Then:
- In the preview, rename to merge: **FAB CC → FAB Share CC**. Leave a name blank to drop its rows.
- The import works out the following:
  - a row with no status and an amount becomes **Pending**
  - `-` becomes **Skipped**
  - blank or 0 becomes **Not due**
  - a note containing "Used … CC" sets **Paid with: Card**
  - a date on or after the 25th counts toward the next month (29-Apr becomes May)
- Afterwards, check the **Payees** tab: turn off one-offs (Vamshi, Old-DU), and set fixed amounts and the order you want.

Importing the same paste twice is safe, because cycles whose date already exists are skipped.

## Monthly use
1. On payday, click **+ Start new cycle**. It adds a row for every active payee, with fixed amounts already filled in.
2. Enter the statement amounts and tick each one as you pay it. If you paid a bill by card, set **Paid with** to that card. Then **Paid from bank** shows real cash out, and the same money isn't counted again when the card bill arrives.
3. Every change auto-saves to GitHub about a second later. The dot in the header shows the status.

If you edit on two devices at once, the second save is blocked and a banner asks which version to keep. Nothing is merged silently.

## Backups
- **Settings → Download encrypted backup** saves a copy of `vault.json`. To restore, commit that file back into `bills-data`.
- The git history of `bills-data` is also a full history of encrypted versions.
- **Export CSV** is plaintext, for Excel. Treat that file as sensitive.

## Files
| File | Purpose |
|---|---|
| `index.html` | Shell and Content Security Policy |
| `app.js` | Crypto, GitHub sync, sheet import, UI |
| `style.css` | Styling (light and dark) |
| `CNAME` | Custom domain for GitHub Pages |
