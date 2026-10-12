# Encryption & Decryption Algorithm — TES-128 (Twin-Engine Split) + SHA-256

> Academic framing (say this in viva): TES is an **educational cipher** built
> from real cipher principles (Vigenère layer, SPN substitution, Feistel-style
> swapping, CBC chaining). It demonstrates *how block ciphers work* — it is
> not a replacement for standardised AES.

## Which files implement it?

| Piece | File | Function |
|---|---|---|
| Whole TES engine | `tes_cipher.py` | block encrypt/decrypt, CBC, padding, wrappers, frozen vector |
| AES-style engine | `tes_cipher.py` | `aes_engine_round()` (SubBytes + ShiftRows + AddRoundKey) |
| DES-style engine | `tes_cipher.py` | `des_engine_round()` / `des_engine_inverse()` (XOR-rotate + key) |
| Swap + key schedule | `tes_cipher.py` | round loop, `derive_round_keys()`, `basic_vigenere_layer()` |
| Swap point (algo dispatch) | `crypto_utils.py` | `encrypt_field()` / `decrypt_field()` (`"TES-128"` vs `"AES-256-CBC"` v1) |
| SHA-256 hashing + verify | `crypto_utils.py` | `sha256_hash()` / `verify_hash()` (unchanged) |
| Master key, algo, version | `config.py` | `TES_MASTER_KEY`, `ENCRYPTION_ALGO="TES-128"`, `KEY_VERSION=2` |
| Browser-side mirror | `static/crypto.js` | `CryptoProvider` (TES port, sync, no new dependencies) |
| Callers (untouched) | `bd_server.py` | `api_register`, `api_login`, `api_profile`, `api_db_preview` |

## 1. TES-128 parameters

- **Block:** 128-bit (16 bytes), split into LHS 8 bytes + RHS 8 bytes.
- **Rounds:** 4. Each round: AddRoundKey (XOR) → DES-engine (LHS) + AES-engine (RHS) → swap halves (swap skipped after round 4 so decryption mirrors).
- **Pre-op:** Vigenère byte layer over the full 16-byte block with the master key.
- **Key:** fresh explicit 16-byte master key (`TES_MASTER_KEY`); round keys derived per round by circular left-shift of `(r*3) % 16` bytes, split 8+8.
- **Chaining:** CBC-style with a fresh random 16-byte IV per request; output blob = `IV ‖ blocks`, base64-encoded for JSON.
- **Rounds:** 4 — single authority is `config.TES_ROUNDS`, read by
  `tes_cipher.py` (falls back to 4 when run standalone); mirrored as `ROUNDS`
  in `static/crypto.js` (kept in sync by hand — the frozen vector catches drift).
- **Envelope:** the wire format is base64(`IV ‖ blocks`) inside each `*_enc`
  value; the payload/DB `iv` field carries the same IV (base64) for display
  and compatibility — decryption reads the IV from the blob itself.
- **Old key kept:** `config.DEMO_KEY` (32 bytes) is retained solely to decrypt
  v1 AES rows; TES never uses it.
- **Padding:** PKCS#7 to the 16-byte boundary.

## 2. Formulas

Vigenère pre-op (`K` = master key bytes, all arithmetic mod 256):
```
Cᵢ = (Pᵢ + Kᵢ) mod 256        Pᵢ = (Cᵢ − Kᵢ) mod 256
```

Per round `r` with round keys `(KL_r, KR_r)`:
```
LHS ← DES_ENG(LHS ⊕ KL_r)      where DES_ENG(x) = rotl₁(x ⊕ 0x55) per byte
RHS ← AES_ENG(RHS ⊕ KR_r)      where AES_ENG = SubBytes → ShiftRows (2×4 matrix)
(LHS, RHS) ← swap(LHS, RHS)    (skipped after round 4)
```

Decryption runs the exact mirror (rounds 4→1, un-swap first except round 4):
```
RHS ← InvShiftRows → InvSubBytes → ⊕ KR_r
LHS ← rotr₁ → ⊕ 0x55 → ⊕ KL_r
```

CBC chaining (`C₀ = IV`, `‖` = concat):
```
encrypt:  Bᵢ = ENGINE(Vigenère(Pᵢ ⊕ Cᵢ₋₁))      blob = IV ‖ B₁ ‖ … ‖ Bₙ
decrypt:  Pᵢ = Vigenère⁻¹(ENGINE⁻¹(Bᵢ)) ⊕ Cᵢ₋₁
```

Index maps (check against `aes_engine_round` in code): ShiftRows sends input
positions `[0,1,2,3,4,5,6,7]` → `[0,3,2,5,4,7,6,1]`; InvShiftRows is the exact
inverse `[0,7,2,1,4,3,6,5]`. The swap is structural — it routes each half
through both engines twice over 4 rounds; confidentiality comes from the keyed
engines + CBC, not from the swap itself.
Two defects in the first draft were fixed during the build (both in the AES
decrypt path): the round-key XOR was missing after InvSubBytes, and decrypt
returned a `list` instead of `bytes` (crashed the final concat). The frozen
test vector below guards against regressions of exactly this class.

## 3. Frozen test vector (Python AND JS reproduce it)

```
key   = "MySecret16ByteK!"          iv    = 00 01 … 0F
plain = "0123456789ABCDEF" (1 block)
blob  = 000102030405060708090a0b0c0d0e0f ‖ 7cb7d6aa386607bc2e824f1e6abf510eee9ea334c1df8031ad8b9e0bfda1c60a
```

Python: `tes_cipher.tes_self_check()` asserts this when `tes_cipher.py` is run
directly (`python tes_cipher.py`).
JavaScript: `CryptoProvider.selfTest()` runs on every page load, logs
`[TES JS] self-test PASS` in the browser console, and asserts the same hex.
Cross-language parity (JS encrypts → Python decrypts) is verified in testing.
The JS port matches Python exactly: same S-box tables and index maps,
`TextEncoder`/`TextDecoder` for UTF-8, chunked `btoa`/`atob` for base64,
`crypto.getRandomValues` for IVs.

### Worked byte-level trace (block 1 of the vector above — real output)

16-byte input → PKCS#7 appends a **full** 16-byte padding block (`0x10` × 16),
so the blob is IV + 2 blocks (48 bytes). Round-0 keys are the master key
unsplit: `KL₀ = 4d79536563726574` ("MySecret"), `KR₀ = 3136427974654b21` ("16ByteK!").

```
padded   30313233343536373839414243444546 ‖ 10101010101010101010101010101010
cbc-xor  303030303030303030304b494f494b49          (block1 ⊕ IV)
vigenère 7da9839593a295a461668dc2c3ae966a          (+ master key, mod 256)
round 1  L=ca0b0b4b4b0b4b0b R=53ea8a1fa9b3c153    (then swapped)
round 2  L=c6b95b5e11af4588 R=6d639f5a026a23d2    (then swapped)
round 3  L=ba84f7722a8c04c5 R=5dcc47742c2df746    (then swapped)
round 4  L=7cb7d6aa386607bc R=2e824f1e6abf510e    (no swap)
block 1  7cb7d6aa386607bc2e824f1e6abf510e
block 2  ee9ea334c1df8031ad8b9e0bfda1c60a          (padding block through same pipeline)
blob     000102030405060708090a0b0c0d0e0f ‖ block1 ‖ block2  = frozen vector ✓
```

## 4. SHA-256 — the hashing (unchanged from v1)

```
H : {0,1}* → {0,1}²⁵⁶        (any input → fixed 256-bit digest, 64 hex chars)
```

`hashlib.sha256(...).hexdigest()`, compared with constant-time
`hmac.compare_digest`. Three jobs: per-field integrity (`*_hash` next to each
`*_enc`), password storage (`password_hash`), SAP-ID lookup key.
Deterministic hashes are also why login works despite fresh random IVs
(same plaintext → different ciphertext every time, but always the same hash).

## 5. End-to-end flow (identical shape to v1, new cipher inside)

```
register:  per field m → TES_enc(m) + SHA256(m), 10 cells + {iv, algo:"TES-128", key_version:2}
           BD decrypts → re-hashes → compares → stores as-is → issues strong password (TES-locked)
login:     TES_enc(sap_id) + SHA256(sap_id) + SHA256(password) → BD verifies → profile/db-preview
v1 rows:   old AES-256-CBC rows still decrypt (dispatch on stored algo, key_version 1)
```

## 6. Limitations to state in viva

- Custom educational cipher — demonstrates principles; standard AES is what
  production uses. Never claim "production-ready."
- Demo uses a pre-shared hardcoded key visible in JS → production needs TLS +
  RSA/ECDH key exchange.
- Passwords as plain SHA-256 (demo) → production: bcrypt/argon2 + salt.
- Single IV per request envelope (demo-simple) → production: fresh IV per field.
