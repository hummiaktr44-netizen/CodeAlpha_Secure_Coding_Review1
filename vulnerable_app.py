"""Intentionally VULNERABLE demo app (for the secure coding review). Do not deploy."""
import hashlib
import os
import pickle
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)
SECRET_KEY = "admin123"          # hardcoded secret
DB = "users.db"


def init_db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS users(name TEXT, password TEXT)")
    con.commit()
    con.close()


@app.route("/register", methods=["POST"])
def register():
    name = request.form["name"]
    password = request.form["password"]
    hashed = hashlib.md5(password.encode()).hexdigest()      # weak hash, no salt
    con = sqlite3.connect(DB)
    con.execute(f"INSERT INTO users VALUES ('{name}', '{hashed}')")  # SQL injection
    con.commit()
    return "registered"


@app.route("/login", methods=["POST"])
def login():
    name = request.form["name"]
    password = hashlib.md5(request.form["password"].encode()).hexdigest()
    con = sqlite3.connect(DB)
    query = "SELECT * FROM users WHERE name = '" + name + "' AND password = '" + password + "'"
    row = con.execute(query).fetchone()                      # SQL injection
    return "welcome" if row else "denied"


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    return subprocess.check_output("ping -c 1 " + host, shell=True)  # command injection


@app.route("/read")
def read_file():
    filename = request.args.get("file", "")
    with open(os.path.join("uploads", filename)) as f:       # path traversal
        return f.read()


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr", "0")))          # code injection


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)                         # insecure deserialization
    return str(obj)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", debug=True)                      # debug mode + open to all interfaces
