# Secure Student Portal — Applied Cryptography Mini Project
**Stack:** Python Flask + SQLite · **Crypto:** AES-256-CBC (lock) + SHA-256 (fingerprint)

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
1. DevTools → Network → `/api/register` payload: only `*_enc` + `*_hash`, no plaintext.
2. `GET http://127.0.0.1:5001/api/db-preview` or open `students.db` (lives next to bd_server): only ciphertext + hashes.
3. Tamper test: change one hash → `400 Integrity failed`.
4. Wrong password → `401`.

## Change encryption later (already planned)
- Backend: only `crypto_utils.py` knows AES. Add new functions there,
  change 1 line `ENCRYPTION_ALGO` in `config.py`. Bump `KEY_VERSION`.
- Frontend: only `static/crypto.js` → `CryptoProvider` knows AES.
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
