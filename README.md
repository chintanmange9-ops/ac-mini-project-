# Secure Student Portal — Applied Cryptography Mini Project
**Stack:** Python Flask + SQLite · **Crypto:** TES-128 twin-engine cipher (lock) + SHA-256 (fingerprint)

## Simple idea
Student types 5 things (roll no, sap id, name, sem, branch) in plaintext on screen.
Browser locks each + makes fingerprint → 10 values travel. Server saves those 10 as-is.
Server returns sap_id + strong 12-char password (locked). Login also sends only
locked sap_id + password fingerprint. Plaintext never goes on wire or in DB.

## Run (2 servers)
```
pip install -r requirements.txt
# terminal 1 — BD server (API + SQLite, no pages):
python bd_server.py      # http://127.0.0.1:5001
# terminal 2 — FD server (pages only, no DB):
python fd_server.py      # http://127.0.0.1:5000
```
Open http://127.0.0.1:5000 → Register → note SAP ID + password → Login.
Pages come from :5000, data goes to :5001 (see Network tab + CORS on BD).

## Prove it in viva
1. DevTools → Network → `/api/register` payload: only `*_enc` + `*_hash`
   (+ `iv`/`algo`/`key_version` envelope) — no plaintext.
2. Open `students.db` (lives next to bd_server) or log in to see the DB table:
   only ciphertext + hashes, all columns except `algo`, rows in ascending id order.
3. Tamper test: change one hash → `400 Integrity failed`.
4. Wrong password → `401`. DB preview without a valid login → denied (`401`, or `400` if fields are missing).
5. After login, the full DB table appears next to your decrypted record
   (BD `POST /api/db-preview` needs a valid login; FD itself never touches the DB).
   Drag column edges to resize like Excel; hover a cell for the full value.
6. After login, your own DB record is shown decrypted
   (BD `POST /api/profile` returns your locked row, browser unlocks it).
7. Workflow strip after login shows the data journey, the exact FD→BD calls
   (method, URL, headers, full body values, recorded live), plus a compact
   integrity table (browser SHA256 vs stored hash → MATCH).

## Change encryption later (already planned)
- Backend: TES lives in `tes_cipher.py` (+ thin dispatch in `crypto_utils.py`).
  To swap: add functions there, change 1 line `ENCRYPTION_ALGO` in `config.py`,
  bump `KEY_VERSION`.
- Frontend: only `static/crypto.js` → `CryptoProvider` knows TES-128.
  Replace its 4 functions, keep names. `algo` + `key_version` travel in
  every payload and are stored per-row, so old rows still decrypt.
- No change needed in `bd_server.py`, `fd_server.py`, `database.py`, or HTML forms.

## Log files
- `logs/bd_server.log` — every register/login attempt, integrity failures, errors
  (only hash prefixes logged, never plaintext/passwords).
- `logs/fd_server.log` — every page served.
- Created automatically on first run (`logs/` folder + files).

## If you see `no such table: students`
- Fixed: BD now self-heals (`ensure_db()` before every request — missing/0-byte/
  corrupt DB is rebuilt instead of 500). Just restart `bd_server.py`.
- Tip: this folder is inside OneDrive — if sync ever truncates `students.db`
  to 0 bytes, the server heals it on the next request; your old rows in a
  corrupt file can't be recovered, so re-register.

## Limitations to say in viva (gets marks)
- Demo uses pre-shared key visible in JS → production needs TLS + RSA/ECDH exchange.
- Single IV per request (demo-simple) → production: fresh IV per field.
- Passwords stored as SHA-256 demo hash → production: bcrypt/argon2 + salt.
