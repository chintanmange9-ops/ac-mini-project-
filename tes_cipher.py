"""tes_cipher.py — Twin-Engine Split (TES) Cipher, 128-bit blocks, 4 rounds.

Pipeline per block: Vigenere pre-op -> split 8+8 -> per-round AddRoundKey
-> DES-style engine (LHS) + AES-style engine (RHS) -> swap (skip last round).
Multi-block messages use CBC chaining with a fresh 16-byte IV + PKCS#7.

FIXES vs the draft blueprint (both were in the AES *decrypt* path):
  Bug 1: decrypt omitted the round-key XOR. Encrypt is XOR->Sub->Shift,
         so decrypt MUST be InvShift->InvSub->XOR. Added back.
  Bug 2: decrypt returned a `list` instead of `bytes`, which crashed the
         final `lhs + rhs` concat with TypeError. Wrapped in bytes().
"""
import base64
import os

try:
    from config import TES_ROUNDS  # single authority for round count
except Exception:
    TES_ROUNDS = 4
TES_BLOCK = 16

AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
AES_INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
]


def pad(data: bytes) -> bytes:
    pad_len = TES_BLOCK - (len(data) % TES_BLOCK)
    return data + bytes([pad_len] * pad_len)


def unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Invalid padding layout.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > TES_BLOCK:
        raise ValueError("Invalid padding layout.")
    return data[:-pad_len]


def basic_vigenere_layer(block: bytes, master_key: bytes, decrypt=False) -> bytes:
    output = bytearray(TES_BLOCK)
    for i in range(TES_BLOCK):
        if not decrypt:
            output[i] = (block[i] + master_key[i]) % 256
        else:
            output[i] = (block[i] - master_key[i]) % 256
    return bytes(output)


def derive_round_keys(master_key: bytes, total_rounds=TES_ROUNDS):
    round_keys = []
    for r in range(total_rounds):
        shift = (r * 3) % len(master_key)
        derived = master_key[shift:] + master_key[:shift]
        round_keys.append((derived[0:8], derived[8:16]))
    return round_keys


def aes_engine_round(rhs_bytes: bytes, round_key: bytes, decrypt=False) -> bytes:
    if not decrypt:
        # AddRoundKey -> SubBytes -> ShiftRows
        state = bytes([b ^ k for b, k in zip(rhs_bytes, round_key)])
        subbed = [AES_SBOX[b] for b in state]
        return bytes([
            subbed[0], subbed[3], subbed[2], subbed[5],
            subbed[4], subbed[7], subbed[6], subbed[1],
        ])
    # FIX (Bug 1+2): InvShiftRows -> InvSubBytes -> AddRoundKey, as bytes
    unshifted = [
        rhs_bytes[0], rhs_bytes[7], rhs_bytes[2], rhs_bytes[1],
        rhs_bytes[4], rhs_bytes[3], rhs_bytes[6], rhs_bytes[5],
    ]
    inv = bytes([AES_INV_SBOX[b] for b in unshifted])
    return bytes([b ^ k for b, k in zip(inv, round_key)])


def _rotl1(b: int) -> int:
    return ((b << 1) | (b >> 7)) & 0xFF


def _rotr1(b: int) -> int:
    return ((b >> 1) | (b << 7)) & 0xFF


def des_engine_round(lhs_bytes: bytes, round_key: bytes) -> bytes:
    state = bytes([b ^ k for b, k in zip(lhs_bytes, round_key)])
    return bytes([_rotl1(b ^ 0x55) for b in state])


def des_engine_inverse(lhs_bytes: bytes, round_key: bytes) -> bytes:
    unrotated = bytes([_rotr1(b) ^ 0x55 for b in lhs_bytes])
    return bytes([b ^ k for b, k in zip(unrotated, round_key)])


def twin_engine_block_encrypt(block: bytes, round_keys) -> bytes:
    lhs = block[0:8]
    rhs = block[8:16]
    for r in range(TES_ROUNDS):
        lhs = des_engine_round(lhs, round_keys[r][0])
        rhs = aes_engine_round(rhs, round_keys[r][1], decrypt=False)
        if r < TES_ROUNDS - 1:
            lhs, rhs = rhs, lhs
    return lhs + rhs


def twin_engine_block_decrypt(block: bytes, round_keys) -> bytes:
    lhs = block[0:8]
    rhs = block[8:16]
    for r in range(TES_ROUNDS - 1, -1, -1):
        if r < TES_ROUNDS - 1:
            lhs, rhs = rhs, lhs
        rhs = aes_engine_round(rhs, round_keys[r][1], decrypt=True)
        lhs = des_engine_inverse(lhs, round_keys[r][0])
    return lhs + rhs


def tes_cbc_encrypt(plaintext: bytes, master_key: bytes, iv=None) -> bytes:
    """Encrypt arbitrary bytes. Output = IV (16) || cipher blocks.

    iv may be supplied (our FD/BD envelope already carries one, keeping the
    payload format unchanged); otherwise a fresh random IV is minted.
    """
    assert len(master_key) == 16
    if iv is None:
        iv = os.urandom(TES_BLOCK)
    assert len(iv) == TES_BLOCK
    padded_pt = pad(plaintext)
    round_keys = derive_round_keys(master_key, total_rounds=TES_ROUNDS)
    ciphertext = bytearray(iv)
    previous_block = iv
    for i in range(0, len(padded_pt), TES_BLOCK):
        cbc_xor = bytes([p ^ c for p, c in zip(padded_pt[i:i + TES_BLOCK], previous_block)])
        pre_processed = basic_vigenere_layer(cbc_xor, master_key, decrypt=False)
        cipher_block = twin_engine_block_encrypt(pre_processed, round_keys)
        ciphertext.extend(cipher_block)
        previous_block = cipher_block
    return bytes(ciphertext)


def tes_cbc_decrypt(ciphertext: bytes, master_key: bytes) -> bytes:
    assert len(master_key) == 16
    if len(ciphertext) < 2 * TES_BLOCK or len(ciphertext) % TES_BLOCK != 0:
        raise ValueError("Invalid TES ciphertext layout.")
    round_keys = derive_round_keys(master_key, total_rounds=TES_ROUNDS)
    iv = ciphertext[0:TES_BLOCK]
    encrypted_data = ciphertext[TES_BLOCK:]
    plaintext = bytearray()
    previous_block = iv
    for i in range(0, len(encrypted_data), TES_BLOCK):
        cipher_block = encrypted_data[i:i + TES_BLOCK]
        engine_out = twin_engine_block_decrypt(cipher_block, round_keys)
        cbc_xor = basic_vigenere_layer(engine_out, master_key, decrypt=True)
        plaintext.extend(bytes([e ^ p for e, p in zip(cbc_xor, previous_block)]))
        previous_block = cipher_block
    return unpad(bytes(plaintext))


# ---------- Field-level API (string in/out, matches crypto_utils envelope) ----------

def tes_encrypt_field(plaintext: str, master_key: bytes, iv: bytes) -> str:
    blob = tes_cbc_encrypt(plaintext.encode("utf-8"), master_key, iv=iv)
    return base64.b64encode(blob).decode("utf-8")


def tes_decrypt_field(cipher_b64: str, master_key: bytes) -> str:
    blob = base64.b64decode(cipher_b64)
    return tes_cbc_decrypt(blob, master_key).decode("utf-8")


# ---------- Frozen test vector: Python AND JS must reproduce this exactly ----------

TES_VECTOR_KEY = b"MySecret16ByteK!"
TES_VECTOR_IV = bytes(range(16))          # 00 01 02 ... 0F
TES_VECTOR_PLAIN = b"0123456789ABCDEF"    # exactly one block
TES_VECTOR_CIPHER_HEX = (
    "000102030405060708090a0b0c0d0e0f"
    "7cb7d6aa386607bc2e824f1e6abf510eee9ea334c1df8031ad8b9e0bfda1c60a"
)


def tes_self_check() -> str:
    """Round-trip + frozen vector. Returns vector hex. Raises on failure."""
    blob = tes_cbc_encrypt(TES_VECTOR_PLAIN, TES_VECTOR_KEY, iv=TES_VECTOR_IV)
    actual = blob.hex()
    expected_iv, expected_ct = TES_VECTOR_CIPHER_HEX[:32], TES_VECTOR_CIPHER_HEX[32:]
    assert actual[:32] == expected_iv, "IV prefix mismatch"
    assert actual[32:] == expected_ct, f"Vector mismatch: {actual[32:]}"
    assert tes_cbc_decrypt(blob, TES_VECTOR_KEY) == TES_VECTOR_PLAIN
    for msg in [b"X", b"CSE", "uninamis—test ✓".encode("utf-8"),
                b"A" * 16, b"B" * 17, b"C" * 64]:
        iv = os.urandom(16)
        assert tes_cbc_decrypt(tes_cbc_encrypt(msg, TES_VECTOR_KEY, iv=iv),
                               TES_VECTOR_KEY) == msg
    return actual


if __name__ == "__main__":
    out_hex = tes_self_check()
    print(f"TES vector (hex): {out_hex}")
    print("[TES SUCCESS] round-trip + frozen vector verified.")
