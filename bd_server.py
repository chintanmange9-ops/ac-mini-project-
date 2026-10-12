"""bd_server.py — BD server (Backend + Database ONLY). Port 5001.
No HTML pages. Only JSON APIs. Never receives or stores plaintext."""
import base64
import hmac
import logging
from pathlib import Path

from flask import Flask, jsonify, request
from flask_cors import CORS

import config
import crypto_utils
import database

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BD] %(levelname)s: %(message)s",
    handlers=[logging.FileHandler(LOG_DIR / "bd_server.log", encoding="utf-8"),
              logging.StreamHandler()])
log = logging.getLogger("bd")

app = Flask(__name__)
# Allow FD server (port 5000) to call these APIs from the browser.
CORS(app, origins=["http://127.0.0.1:5000", "http://localhost:5000"])
database.init_db()


@app.before_request
def _ensure_db():
    database.ensure_db()


@app.errorhandler(500)
def _internal_error(e):
    log.exception("Unhandled 500: %s", e)
    return jsonify({"error": "Server error — see logs/bd_server.log"}), 500

FIELDS = ["roll_no", "sap_id", "name", "sem", "branch"]


def _get_iv(data: dict) -> bytes:
    iv_b64 = data.get("iv", "")
    if not iv_b64:
        raise ValueError("Missing iv")
    return base64.b64decode(iv_b64)


@app.get("/health")
def health():
    return jsonify({"server": "bd", "port": 5001, "algo": config.ENCRYPTION_ALGO})


@app.post("/api/register")
def api_register():
    data = request.get_json(force=True)
    try:
        for f in FIELDS:
            if not data.get(f"{f}_enc") or not data.get(f"{f}_hash"):
                return jsonify({"error": f"Missing {f}_enc/{f}_hash"}), 400
        iv = _get_iv(data)
        algo = data.get("algo", config.ENCRYPTION_ALGO)

        plain = {}
        for f in FIELDS:
            try:
                pt = crypto_utils.decrypt_field(data[f"{f}_enc"], iv, algo=algo)
            except Exception:
                log.warning("REGISTER decrypt failed field=%s", f)
                return jsonify({"error": f"Decrypt failed for {f}"}), 400
            if not crypto_utils.verify_hash(pt, data[f"{f}_hash"]):
                log.warning("REGISTER integrity failed field=%s (hash mismatch)", f)
                return jsonify({"error": f"Integrity failed for {f} (hash mismatch)"}), 400
            if not pt.strip():
                return jsonify({"error": f"{f} is empty"}), 400
            plain[f] = pt.strip()

        if database.sap_hash_exists(data["sap_id_hash"]):
            log.warning("REGISTER duplicate sap_hash=%s...", data["sap_id_hash"][:12])
            return jsonify({"error": "This SAP ID is already registered"}), 409

        password = crypto_utils.generate_strong_password()
        password_hash = crypto_utils.sha256_hash(password)

        row = {f"{f}_enc": data[f"{f}_enc"] for f in FIELDS}
        row.update({f"{f}_hash": data[f"{f}_hash"] for f in FIELDS})
        row["password_hash"] = password_hash
        row["iv"] = data["iv"]
        row["algo"] = algo
        row["key_version"] = int(data.get("key_version", config.KEY_VERSION))
        database.insert_student(row)

        iv2 = crypto_utils.generate_iv()
        password_enc = crypto_utils.encrypt_field(password, iv2)
        log.info("REGISTER ok sap_hash=%s... algo=%s",
                 data["sap_id_hash"][:12], algo)
        return jsonify({
            "user_id": plain["sap_id"],
            "password_enc": password_enc,
            "iv": base64.b64encode(iv2).decode(),
            "algo": algo,
            "key_version": config.KEY_VERSION,
        }), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/login")
def api_login():
    data = request.get_json(force=True)
    try:
        row, err = _auth_student(data)
        if err:
            return err
        assert row is not None
        log.info("LOGIN ok sap_hash=%s...", data["sap_id_hash"][:12])
        return jsonify({
            "success": True,
            "name_enc": row["name_enc"],
            "iv": row["iv"],
            "algo": row["algo"],
        }), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/profile")
def api_profile():
    """After login: return the student's OWN stored DB row (still locked).
    Frontend decrypts it with the key — proves the DB held only ciphertext."""
    data = request.get_json(force=True)
    try:
        row, err = _auth_student(data)
        if err:
            return err
        assert row is not None
        log.info("PROFILE served sap_hash=%s...", data["sap_id_hash"][:12])
        return jsonify({
            "roll_no_enc": row["roll_no_enc"],
            "roll_no_hash": row["roll_no_hash"],
            "sap_id_enc": row["sap_id_enc"],
            "sap_id_hash": row["sap_id_hash"],
            "name_enc": row["name_enc"],
            "name_hash": row["name_hash"],
            "sem_enc": row["sem_enc"],
            "sem_hash": row["sem_hash"],
            "branch_enc": row["branch_enc"],
            "branch_hash": row["branch_hash"],
            "iv": row["iv"],
            "algo": row["algo"],
            "key_version": row["key_version"],
            "created_at": row["created_at"],
        }), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


def _auth_student(data):
    """Shared check for /api/login and /api/profile.

    Decrypts the login id, verifies its fingerprint, looks the row up by
    hash, compares the password fingerprint. Plaintext never stored/returned.
    Returns (row, None) on success or (None, (response, code)) on failure.
    """
    for k in ("sap_id_enc", "sap_id_hash", "password_hash", "iv"):
        if not data.get(k):
            return None, (jsonify({"error": f"Missing {k}"}), 400)
    iv = _get_iv(data)
    algo = data.get("algo", config.ENCRYPTION_ALGO)

    # 1. Decrypt login id, verify its fingerprint (channel integrity)
    try:
        sap_plain = crypto_utils.decrypt_field(data["sap_id_enc"], iv, algo=algo)
    except Exception:
        log.warning("AUTH decrypt failed for sap_id")
        return None, (jsonify({"error": "Decrypt failed for sap_id"}), 401)
    if not crypto_utils.verify_hash(sap_plain, data["sap_id_hash"]):
        log.warning("AUTH integrity failed (sap_id hash mismatch)")
        return None, (jsonify({"error": "Integrity failed (sap_id hash mismatch)"}), 401)

    # 2. Lookup by hash (ciphertext differs every IV, hash is stable)
    row = database.find_by_sap_hash(data["sap_id_hash"])
    if row is None:
        log.warning("AUTH unknown sap_hash=%s...", data["sap_id_hash"][:12])
        return None, (jsonify({"error": "Invalid SAP ID or password"}), 401)

    # 3. Compare password fingerprints (constant-time)
    if not hmac.compare_digest(row["password_hash"], data["password_hash"]):
        log.warning("AUTH wrong password sap_hash=%s...", data["sap_id_hash"][:12])
        return None, (jsonify({"error": "Invalid SAP ID or password"}), 401)
    return row, None


@app.post("/api/db-preview")
def api_db_preview():
    """Full stored DB (still locked) — login REQUIRED.

    Same check as /api/login, so outsiders without credentials get 401.
    """
    data = request.get_json(force=True)
    try:
        _, err = _auth_student(data)
        if err:
            log.warning("DB-PREVIEW denied (no valid login)")
            return err
        conn = database.get_conn()
        rows = conn.execute(
            "SELECT id, roll_no_enc, roll_no_hash, sap_id_enc, sap_id_hash, "
            "name_enc, name_hash, sem_enc, sem_hash, branch_enc, branch_hash, "
            "password_hash, iv, key_version, created_at "
            "FROM students ORDER BY id ASC LIMIT 50").fetchall()
        conn.close()
        log.info("DB-PREVIEW served %d row(s)", len(rows))
        return jsonify([dict(r) for r in rows])
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    log.info("BD server starting on :5001 (algo=%s)", config.ENCRYPTION_ALGO)
    app.run(debug=True, port=5001)
