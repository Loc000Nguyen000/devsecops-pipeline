"""
Remediated Flask app for the DevSecOps pipeline demo.

This is the hardened counterpart to ../vulnerable/app.py: every planted
flaw has been closed so the same scanners pass. Same CTF-style frontend,
but the handlers are safe and responses carry security headers.
"""
import os
import sqlite3
import subprocess
from flask import Flask, request, render_template

app = Flask(__name__)

# FIX (secrets): no hardcoded credentials. The secret key is read from the
# environment; cloud credentials are never embedded in source.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))

ENV = {"label": "HARDENED BUILD", "cls": "good"}
SEED_USERS = ["alice", "bob", "carol", "admin"]


@app.after_request
def set_security_headers(response):
    # FIX (DAST): response security headers OWASP ZAP flags as missing on the
    # vulnerable app. CSP allows our own stylesheet (style-src 'self') and form
    # posts, but nothing else — no inline scripts, no third-party content.
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'self'; img-src 'self'; "
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Cache-Control"] = "no-store"
    return response


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
    # FIX (SAST): parameterized query — user input is bound, never
    # concatenated into the SQL string. (Output is auto-escaped by Jinja2.)
    query = "SELECT * FROM users WHERE name = ?"
    try:
        cur.execute(query, (name,))
        result = "query: %s\nrows: %s" % (query, cur.fetchall())
    except Exception as exc:  # noqa: BLE001
        result = "query: %s\nerror: %s" % (query, exc)
    return render_template("index.html", env=ENV, user_result=result, ping_result=None)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # FIX (SAST): allow-list the input, then run with no shell and an
    # argument list so user input can never be interpreted as a command.
    if not host.replace(".", "").replace("-", "").isalnum():
        return render_template("index.html", env=ENV,
                               user_result=None, ping_result="invalid host"), 400
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True, text=True, timeout=5, check=False,
        )
        reachable = proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        # e.g. no `ping` binary in the slim image — fail safe, don't 500.
        reachable = False
    result = "pinged %s (reachable=%s)" % (host, reachable)
    return render_template("index.html", env=ENV, user_result=None, ping_result=result)


if __name__ == "__main__":
    # FIX (DAST): stop the dev server leaking its version in the Server header
    # (ZAP flags "Server Leaks Version Information"). Override the WSGI handler's
    # banner before starting.
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.server_version = "webserver"
    WSGIRequestHandler.sys_version = ""
    # FIX (SAST): debug mode disabled.
    app.run(host="0.0.0.0", port=5000, debug=False)
