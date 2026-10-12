"""crypto_utils.py — THE ONLY file that knows HOW encryption works.

Everything else (app.py, database.py, frontend) calls:
    encrypt_field() / decrypt_field() / sha256_hash() / verify_hash()
and never touches AES directly.

To swap encryption in future:
  - Add _chacha_encrypt/_decrypt (or RSA) functions below
  - Point _dispatch() to them based on config.ENCRYPTION_ALGO
  - Bump config.KEY_VERSION. Old rows keep algo+v columns so they still decrypt.
"""
import base64
import hashlib
import hmac
import os
import secrets
import string
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

import config


# ---------- Hash (fingerprint) : one-way, cannot unlock ----------

def sha256_hash(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def verify_hash(plaintext: str, expected_hex: str) -> bool:
    actual = sha256_hash(plaintext)
    return hmac.compare_digest(actual, expected_hex)


# ---------- Symmetric encryption (reversible lock) : AES-256-CBC ----------

def _aes_cbc_encrypt(plaintext: str, key: bytes, iv: bytes) -> str:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return base64.b64encode(ct).decode("utf-8")


def _aes_cbc_decrypt(cipher_b64: str, key: bytes, iv: bytes) -> str:
    ct = base64.b64decode(cipher_b64)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    pt = unpadder.update(padded) + unpadder.finalize()
    return pt.decode("utf-8")


# ---------- Pluggable dispatch (future swap point) ----------

def encrypt_field(plaintext: str, iv: bytes, key: Optional[bytes] = None, algo: Optional[str] = None) -> str:
    key = key or config.DEMO_KEY
    algo = algo or config.ENCRYPTION_ALGO
    if algo == "AES-256-CBC":
        return _aes_cbc_encrypt(plaintext, key, iv)
    raise ValueError(f"Unsupported algo: {algo} (add it here to swap encryption)")


def decrypt_field(cipher_b64: str, iv: bytes, key: Optional[bytes] = None, algo: Optional[str] = None) -> str:
    key = key or config.DEMO_KEY
    algo = algo or config.ENCRYPTION_ALGO
    if algo == "AES-256-CBC":
        return _aes_cbc_decrypt(cipher_b64, key, iv)
    raise ValueError(f"Unsupported algo: {algo}")


def generate_iv() -> bytes:
    return os.urandom(16)  # 128-bit IV for CBC


# ---------- Strong password generator ----------

def generate_strong_password(length: Optional[int] = None) -> str:
    length = length or config.PASSWORD_LENGTH
    alphabet_lower = string.ascii_lowercase
    alphabet_upper = string.ascii_uppercase
    digits = string.digits
    symbols = "@#$!%*?&"
    while True:
        pwd = [
            secrets.choice(alphabet_lower),
            secrets.choice(alphabet_upper),
            secrets.choice(digits),
            secrets.choice(symbols),
        ] + [secrets.choice(alphabet_lower + alphabet_upper + digits + symbols)
              for _ in range(length - 4)]
        secrets.SystemRandom().shuffle(pwd)
        candidate = "".join(pwd)
        if (any(c.islower() for c in candidate)
                and any(c.isupper() for c in candidate)
                and any(c.isdigit() for c in candidate)
                and any(c in symbols for c in candidate)):
            return candidate
