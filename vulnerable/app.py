"""
Intentionally vulnerable Flask app for the DevSecOps pipeline demo.
DO NOT deploy this anywhere real. Every "VULN" below is planted so the
pipeline's scanners have something to detect. The CTF-style frontend is
just presentation — the flaws live in the handlers below.
"""
import os
import sqlite3
from flask import Flask, request, render_template

app = Flask(__name__)

# VULN (secrets): hardcoded secret key + cloud credentials.
# Caught by: Gitleaks (hard gate) and Semgrep.
# NOTE: these are FAKE, non-functional values in valid AWS formats. The
# canonical "AKIAIOSFODNN7EXAMPLE" doc key is allow-listed by Gitleaks/Trivy
# and would NOT trip the gate, so a non-example fake is used instead.
app.secret_key = "super-secret-flask-key-do-not-commit-12345"
AWS_ACCESS_KEY_ID = "AKIA3M7QZ9XK2WJ4NRTV"
AWS_SECRET_ACCESS_KEY = "x7Kd9SjJ2pLmQ4nRfTb1aZ0eWc8YuV3HgN6sBoPQ"

ENV = {"label": "VULNERABLE BUILD", "cls": "bad"}
SEED_USERS = ["alice", "bob", "carol", "admin"]


@app.route("/")
def index():
    return render_template("index.html", env=ENV, user_result=None, ping_result=None)


@app.route("/user")
def user():
    name = request.args.get("name", "")
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (name TEXT)")
    cur.executemany("INSERT INTO users VALUES (?)", [(u,) for u in SEED_USERS])
    # VULN (SAST): SQL injection via string formatting. Try:  ' OR '1'='1
    # Caught by: Semgrep python ruleset.
    query = "SELECT * FROM users WHERE name = '%s'" % name
    try:
        cur.execute(query)
        result = "query: %s\nrows: %s" % (query, cur.fetchall())
    except Exception as exc:  # noqa: BLE001
        result = "query: %s\nerror: %s" % (query, exc)
    return render_template("index.html", env=ENV, user_result=result, ping_result=None)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULN (SAST): OS command injection via os.system + string concat.
    # Try:  127.0.0.1; id     Caught by: Semgrep python ruleset.
    os.system("ping -c 1 " + host)
    result = "pinged %s" % host
    return render_template("index.html", env=ENV, user_result=None, ping_result=result)


if __name__ == "__main__":
    # VULN (SAST): debug mode enabled + binding to all interfaces.
    app.run(host="0.0.0.0", port=5000, debug=True)
