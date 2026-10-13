# Nudge web

Laptop companion for the Nudge Android app. Static page, no server.

- Signs in with Google (scope `drive.appdata` only: a hidden, app-private folder).
- Notes are end-to-end encrypted (PBKDF2-SHA256 600k + AES-256-GCM) with a passphrase that never leaves the browser. Google stores only ciphertext.
- This repo contains code only. No notes or keys are ever stored here.
