"""Fixed version of vulnerable_app.py with the review recommendations applied."""
import hmac
import json
import os
import re
import sqlite3
import subprocess
from hashlib import scrypt
from pathlib import Path

from flask import Flask, abort, request

app = Flask(__name__)
SECRET_KEY = os.environ.get("APP_SECRET_KEY")        # from environment, not source code
DB = "users.db"
UPLOAD_DIR = Path("uploads").resolve()
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def hash_password(password: str, salt: bytes = None):
    salt = salt or os.urandom(16)
    return salt, scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)


def init_db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, salt BLOB, password BLOB)")
    con.commit()
    con.close()


@app.route("/register", methods=["POST"])
def register():
    name = request.form.get("name", "")
    password = request.form.get("password", "")
    if not name or len(password) < 8:
        abort(400, "Name required and password must be at least 8 characters")
    salt, hashed = hash_password(password)
    with sqlite3.connect(DB) as con:
        con.execute("INSERT INTO users VALUES (?, ?, ?)", (name, salt, hashed))   # parameterized
    return "registered"


@app.route("/login", methods=["POST"])
def login():
    name = request.form.get("name", "")
    password = request.form.get("password", "")
    with sqlite3.connect(DB) as con:
        row = con.execute("SELECT salt, password FROM users WHERE name = ?", (name,)).fetchone()
    if row and hmac.compare_digest(hash_password(password, row[0])[1], row[1]):
        return "welcome"
    return "denied", 401


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not HOST_RE.match(host):                                  # input validation
        abort(400, "Invalid host")
    out = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
    return out.stdout                                            # no shell, argument list


@app.route("/read")
def read_file():
    path = (UPLOAD_DIR / request.args.get("file", "")).resolve()
    if UPLOAD_DIR not in path.parents or not path.is_file():     # block ../ traversal
        abort(404)
    return path.read_text()


@app.route("/calc")
def calc():
    m = re.fullmatch(r"\s*(-?\d+(?:\.\d+)?)\s*([+\-*/])\s*(-?\d+(?:\.\d+)?)\s*", request.args.get("expr", ""))
    if not m:                                                    # allow-list, no eval
        abort(400, "Use the format: a + b")
    a, op, b = float(m.group(1)), m.group(2), float(m.group(3))
    if op == "/" and b == 0:
        abort(400, "Division by zero")
    return str({"+": a + b, "-": a - b, "*": a * b, "/": a / b if b else 0}[op])


@app.route("/load", methods=["POST"])
def load():
    try:
        return str(json.loads(request.data))                     # JSON instead of pickle
    except ValueError:
        abort(400, "Invalid JSON")


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", debug=False)                       # localhost only, no debug
