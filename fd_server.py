"""fd_server.py — FD server (Frontend ONLY). Port 5000.
Serves HTML pages + crypto.js. Has NO database access by design.
Browser loads pages here, then JS posts ciphertext directly to BD :5001."""
import logging
from pathlib import Path

from flask import Flask, render_template

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [FD] %(levelname)s: %(message)s",
    handlers=[logging.FileHandler(LOG_DIR / "fd_server.log", encoding="utf-8"),
              logging.StreamHandler()])
log = logging.getLogger("fd")

app = Flask(__name__)

BD_URL = "http://127.0.0.1:5001"


@app.get("/")
def index():
    log.info("GET / (index page served)")
    return render_template("index.html")


@app.get("/register")
def register_page():
    log.info("GET /register (register page served)")
    return render_template("register.html", bd_url=BD_URL)


@app.get("/login")
def login_page():
    log.info("GET /login (login page served)")
    return render_template("login.html", bd_url=BD_URL)


@app.get("/health")
def health():
    return {"server": "fd", "port": 5000, "bd": BD_URL}


if __name__ == "__main__":
    log.info("FD server starting on :5000 (BD at %s)", BD_URL)
    app.run(debug=True, port=5000)
