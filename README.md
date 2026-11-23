# Bills

A small web app for tracking monthly payday payments, such as credit cards, utilities, rent and loans. It runs entirely in the browser, and all data is end-to-end encrypted.

## How it works

```
Browser ──(master password → PBKDF2-SHA256 × 600,000 → AES-256-GCM key)──┐
   │                                                                     │
   │ readable data exists only in the open tab's memory                  ▼
   └── saves only ciphertext ──► a private GitHub repo you choose   {kdf, salt, iv, ct}
```

- **This repo is code only.** It holds no data, no keys and no tokens.
- **Your data repo.** The data lives in a separate private repository, which you name when you first connect. The app keeps a single encrypted vault file there.
- **Master password.** It is never stored or sent anywhere. Without it the vault cannot be decrypted, and there is no recovery.
- **GitHub token.** It is kept in the browser's local storage, encrypted with the master password.
- **Tamper detection.** AES-GCM is authenticated, so a modified or corrupted vault refuses to open instead of loading wrong data.
- **Content Security Policy.** The page can only run its own script and can only talk to `api.github.com`.
- **Auto-lock.** The app locks after a period of inactivity that you set; the default is 10 minutes. Locking clears the key from memory.

Anyone who reads this repo can see *how* the app works. The security depends only on the master password, not on keeping the design secret.

## Setup

1. Host this repo as a static site, for example with GitHub Pages and a custom domain. It must be served over HTTPS.
2. Create a **private** repository for the data and give it at least one commit (a README is enough).
3. Create a **fine-grained personal access token** with access to *only* that data repository and permission **Contents: Read and write**.
4. Open the site and enter the owner, data repo, branch, file path, the token, and a strong master password.
   - If no vault exists, a new one is created.
   - On another device, enter the same details and the same password to open the existing vault.

## Importing from a spreadsheet

Go to **Settings → Import**. Paste rows copied from a sheet with five columns: **date, payee, amount, note, status**.

- Rows with the same date form one cycle, whether the date appears on every row or only the first.
- Status rules:
  - `DONE` becomes Done
  - `-` becomes Skipped
  - a blank status with an amount becomes Pending
  - a blank or zero amount becomes Not due
- In the preview you can rename payees to merge ones that changed name over time.
- Dates that are already imported are skipped, so re-pasting is safe.

## Monthly use

1. On payday, click **+ Start new cycle**. It adds every active payee, with fixed amounts already filled in.
2. Enter the amounts and tick each item as you pay it. Set **Paid with** to a card if a bill was charged to one. Then *Paid from bank* shows real cash out, and card-paid bills aren't counted twice.
3. Changes save automatically, encrypted, about a second after each edit. If two devices edit at once, you're asked which version to keep.

## Backups

- **Download encrypted backup** saves a copy of the vault file. To restore, commit it back to the data repo.
- The git history of the data repo is a history of encrypted versions.
- **Export CSV** is *not* encrypted. Handle that file with care.

## Files

| File | Purpose |
|---|---|
| `index.html` | Page shell and Content Security Policy |
| `app.js` | Encryption, GitHub sync, import and UI |
| `style.css` | Styling (light and dark) |
| `logo.svg`, `apple-touch-icon.png` | App icon |
| `CNAME` | Custom domain for GitHub Pages |
