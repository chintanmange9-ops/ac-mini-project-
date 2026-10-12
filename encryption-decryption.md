# Encryption & Decryption Algorithm — AES-256-CBC + SHA-256

## Which files implement it?

| Piece | File | Function / line |
|---|---|---|
| AES encrypt | `crypto_utils.py` | `_aes_cbc_encrypt()` (lines 39–45) |
| AES decrypt | `crypto_utils.py` | `_aes_cbc_decrypt()` (lines 48–55) |
| Swap point (algo dispatch) | `crypto_utils.py` | `encrypt_field()` / `decrypt_field()` (lines 60–73) |
| SHA-256 fingerprint + verify | `crypto_utils.py` | `sha256_hash()` / `verify_hash()` (lines 28–34) |
| Fresh IV | `crypto_utils.py` | `generate_iv()` → `os.urandom(16)` (lines 76–77) |
| Algo choice, key, version | `config.py` | `ENCRYPTION_ALGO`, `DEMO_KEY`, `KEY_VERSION` (lines 5–11) |
| Browser-side mirror | `static/crypto.js` | `CryptoProvider.encryptField / decryptField / sha256` |
| Callers | `bd_server.py` | `api_register`, `api_login`, `api_profile`, `api_db_preview` |

Rule of the codebase: **only `crypto_utils.py` (and `crypto.js` in the
browser) touch AES directly** — everything else calls the four helpers.
To change encryption later, add functions there and flip one line in
`config.py`; every payload/row already carries `algo` + `key_version`.

## 1. AES-256-CBC — parameters used

- **Algorithm:** AES (Rijndael), **256-bit key** (32 bytes) → 14 rounds.
- **Mode:** CBC (Cipher Block Chaining), **128-bit blocks** (16 bytes).
- **Key (demo):** `b"0123456789abcdef0123456789abcdef"` (`config.py` line 11),
  identical in `static/crypto.js`. Pre-shared and hardcoded **for college demo
  only** — production uses TLS + RSA/ECDH key exchange.
- **IV:** fresh random **128-bit** value per request (`os.urandom(16)` on BD,
  `CryptoJS.lib.WordArray.random(16)` on FD), sent alongside as base64.
- **Padding:** PKCS#7 to the 16-byte boundary.
- **Transport encoding:** raw ciphertext bytes → base64 string (JSON-safe).

## 2. Formulas

Split UTF-8 plaintext into 16-byte blocks `P₁ … Pₙ` (after PKCS#7 padding;
`E_K` = AES-256 encryption under key `K`, `D_K` = decryption, `⊕` = XOR,
`C₀ = IV`):

**Encryption (CBC):**
```
C₀ = IV
Cᵢ = E_K(Pᵢ ⊕ Cᵢ₋₁)   for i = 1 … n
ciphertext = C₁ ‖ C₂ ‖ … ‖ Cₙ        (sent as base64)
```

**Decryption (reverse):**
```
C₀ = IV
Pᵢ = D_K(Cᵢ) ⊕ Cᵢ₋₁   for i = 1 … n
plaintext = unpad(P₁ ‖ … ‖ Pₙ), decoded as UTF-8
```

Why this shape (viva points):
- **Chaining** (`⊕ Cᵢ₋₁`): identical plaintext blocks produce different
  ciphertext blocks — patterns don't leak.
- **Fresh IV** (`C₀`): the same SAP ID encrypted twice looks completely
  different on the wire. That is why login lookup uses the **hash**
  (deterministic), never ciphertext equality.
- **PKCS#7**: `k` missing bytes are filled with `k` copies of byte value `k`;
  a wrong key/IV fails at unpadding — tampering is detected, not just hidden.
- **SHA-256 is NOT encryption** — it is the one-way fingerprint next to it
  (section 3). The pair gives confidentiality (AES) + integrity (SHA-256).

## 3. SHA-256 — the fingerprint

```
H : {0,1}* → {0,1}²⁵⁶        (any input → fixed 256-bit digest, shown as 64 hex chars)
```

- Implemented with `hashlib.sha256(...).hexdigest()` (`crypto_utils.py:29`).
- Properties used: **deterministic** (same input → same digest, so BD can
  re-verify and the DB can be indexed by `sap_id_hash`), **preimage-resistant**
  (digest reveals nothing — safe on the wire), **avalanche** (1-char change →
  totally different digest → tamper evident).
- Compared with `hmac.compare_digest` (constant-time, `crypto_utils.py:34`),
  so equality checks don't leak via timing.
- Three jobs in this project: per-field integrity (`*_hash` next to each
  `*_enc`), password storage (`password_hash`, never the password), and the
  SAP-ID lookup key in SQLite.

## 4. End-to-end flow with the formulas applied

**Register** — 5 fields (`roll_no, sap_id, name, sem, branch`) → 10 cells:
```
browser, per field m:   enc = base64(CBC_AES(m)),  h = SHA256(m)
POST /api/register      {m_enc, m_hash} × 5  +  {iv, algo, key_version}
BD, per field:          m' = decrypt(enc, iv);  accept iff SHA256(m') == h
BD stores               enc + h exactly as received (no plaintext column exists)
BD creates password     (see password-generation.md), stores SHA256(password),
                        returns AES(password) under a fresh IV
```

**Login** — nothing plaintext travels:
```
browser:  sap_enc = CBC_AES(sap_id),  sap_h = SHA256(sap_id),  pw_h = SHA256(password)
POST /api/login         {sap_id_enc, sap_id_hash, password_hash, iv, algo}
BD:       sap' = decrypt(sap_enc); check SHA256(sap') == sap_h
          row = SELECT * WHERE sap_id_hash == sap_h
          allow iff row.password_hash == pw_h   (compare_digest)
```

## 5. Worked shape of one field (no fabricated values)

For `branch = "CSE"` (3 bytes → PKCS#7 pads 13 bytes of value `0x0D` → one
16-byte block → one 16-byte ciphertext block → 24-char base64), the wire
carries e.g. `branch_enc = "<24 base64 chars>"` plus
`branch_hash = SHA256("CSE")` (64 hex chars). Open DevTools → Network, or the
post-login Workflow tab, to see the real values from your own run.

## 6. Limitations to state in viva

- Pre-shared hardcoded key → production: TLS + RSA/ECDH, never a JS-visible key.
- One IV per request (demo-simple) → production: fresh IV per field.
- Passwords as plain SHA-256 (demo) → production: bcrypt/argon2 + per-user salt.
- AES-CBC gives confidentiality, not authenticity → production prefers
  AES-GCM (built-in authentication tag) over manual hash-then-encrypt.
