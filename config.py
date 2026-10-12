# config.py — ONLY place where encryption choice lives.
# To change encryption in future (e.g. AES -> ChaCha20 / RSA):
#   1. Add new implementation in crypto_utils.py
#   2. Change ENCRYPTION_ALGO below. Nothing else changes.
ENCRYPTION_ALGO = "TES-128"
KEY_VERSION = 2
TES_ROUNDS = 4

# Fresh explicit 16-byte TES master key (evaluator-visible key tracing).
TES_MASTER_KEY = b"MySecret16ByteK!"

# Demo pre-shared key (32 bytes = 256 bit). MUST match static/crypto.js DEMO_KEY.
# WARNING (for viva/report): hardcoding is only for college demo.
# Production would use TLS + RSA/ECDH key exchange, never a JS-visible key.
DEMO_KEY = b"0123456789abcdef0123456789abcdef"

# Strong password policy
PASSWORD_LENGTH = 12
