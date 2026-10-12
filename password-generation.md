# How the Student Password Is Created

## Which file creates it?

**`crypto_utils.py` → `generate_strong_password()`** (lines 82–102).
Policy comes from **`config.py`** (`PASSWORD_LENGTH = 12`, line 14).
It is called by **`bd_server.py` → `api_register()`** — the BD server creates the
password at the moment a student registers. The student never chooses it,
and the frontend never generates it.

## Password policy

| Rule | Value (in code) |
|---|---|
| Length | 12 chars (`config.PASSWORD_LENGTH`) |
| Must contain | 1 lowercase + 1 UPPERCASE + 1 digit + 1 symbol |
| Allowed symbols | `@#$!%*?&` (variable `symbols`, line 87) |
| Random source | `secrets` module (CSPRNG), never `random` |

## Algorithm, step by step (maps to code lines)

1. **Force one character from each group** (lines 89–93) — this *guarantees*
   the policy instead of hoping for it:
   ```python
   pwd = [
       secrets.choice(alphabet_lower),   # 1 × a–z
       secrets.choice(alphabet_upper),   # 1 × A–Z
       secrets.choice(digits),           # 1 × 0–9
       secrets.choice(symbols),          # 1 × @#$!%*?&
   ]
   ```
2. **Fill the remaining `length − 4 = 8` slots** with random picks from all
   four groups mixed together (lines 94–95).
3. **Shuffle** with `secrets.SystemRandom().shuffle(pwd)` (line 96), so the
   four forced characters are not sitting in predictable positions.
4. **Verify and loop** (lines 98–102): accept the candidate only if all four
   groups are present, otherwise repeat. Because step 1 forces each group,
   the loop passes on the first try in practice — it is a safety net.
5. **Return** the 12-character string, e.g. `A7k@pQ9z#W2mX`-style output.

## Why `secrets` and not `random`?

`random` is deterministic (seeded PRNG — fine for games, fatal for passwords).
`secrets` uses the operating system's cryptographic randomness
(`os.urandom` underneath), so outputs cannot be predicted or reproduced.
Viva line: *"passwords and IVs use a CSPRNG; `random` never appears in this project."*

## What happens to the password after creation? (`bd_server.py`)

1. **Stored as fingerprint only** — `password_hash = sha256_hash(password)`
   goes into the `password_hash` column. The plaintext password exists in no
   column, and the original is discarded from server memory after the response.
2. **Sent back locked** — encrypted with TES-128 (v1 used AES-256-CBC) under a **fresh IV**
   (`generate_iv()`), returned as `{user_id, password_enc, iv}`.
3. **Shown once** — the frontend decrypts it in the browser and displays it;
   the student notes it down.
4. **Login check** — the frontend sends only `SHA256(password)`; BD compares
   it with the stored hash using `hmac.compare_digest` (constant-time, in
   `_auth_student()`), so even timing leaks are avoided.

## One-line summary

`bd_server.py` calls `crypto_utils.generate_strong_password()` → 12 chars,
4 forced character classes, CSPRNG randomness, shuffled and verified →
stored as SHA-256, transported as TES ciphertext, verified by hash compare.
