"""database.py — SQLite storage. Stores ONLY ciphertext + hash, never plaintext."""
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "students.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    roll_no_enc TEXT NOT NULL,  roll_no_hash TEXT NOT NULL,
    sap_id_enc TEXT NOT NULL,   sap_id_hash TEXT NOT NULL UNIQUE,
    name_enc TEXT NOT NULL,     name_hash TEXT NOT NULL,
    sem_enc TEXT NOT NULL,      sem_hash TEXT NOT NULL,
    branch_enc TEXT NOT NULL,   branch_hash TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    iv TEXT NOT NULL,
    algo TEXT NOT NULL,
    key_version INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def ensure_db():
    """Self-heal: called before every BD request.

    If the DB file is missing, 0-byte, corrupt, or the table is gone,
    rebuild it instead of crashing with 'no such table'.
    (A corrupt/empty file holds no student data, so rebuild loses nothing.)
    """
    try:
        conn = get_conn()
        try:
            row = conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='students'").fetchone()
        finally:
            conn.close()
        if row is None:
            init_db()
    except sqlite3.DatabaseError:
        try:
            if DB_PATH.exists():
                DB_PATH.unlink()
        except OSError:
            pass
        init_db()


def insert_student(row: dict) -> int:
    conn = get_conn()
    cur = conn.execute("""
        INSERT INTO students
        (roll_no_enc, roll_no_hash, sap_id_enc, sap_id_hash,
         name_enc, name_hash, sem_enc, sem_hash,
         branch_enc, branch_hash, password_hash, iv, algo, key_version)
        VALUES (:roll_no_enc, :roll_no_hash, :sap_id_enc, :sap_id_hash,
                :name_enc, :name_hash, :sem_enc, :sem_hash,
                :branch_enc, :branch_hash, :password_hash, :iv, :algo, :key_version)
    """, row)
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    assert new_id is not None
    return new_id


def find_by_sap_hash(sap_id_hash: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM students WHERE sap_id_hash = ?",
                       (sap_id_hash,)).fetchone()
    conn.close()
    return dict(row) if row else None


def sap_hash_exists(sap_id_hash: str) -> bool:
    return find_by_sap_hash(sap_id_hash) is not None
