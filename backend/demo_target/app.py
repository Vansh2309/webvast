"""WebVAST demo target - an INTENTIONALLY VULNERABLE web app.

=========================  WARNING  =========================
This application is deliberately insecure. It exists ONLY as a
local practice target for the WebVAST scanner. NEVER deploy it
on a public or shared network. Bind it to localhost only.
=============================================================

Run:  python demo_target/app.py     (serves on http://localhost:5001)

It reproduces, on purpose, the four vulnerability classes WebVAST detects:
  * SQL injection       -> /search?q=
  * Reflected XSS       -> /greet?name=
  * Stored XSS          -> /guestbook  (POST comment)
  * Misconfiguration    -> no security headers, insecure cookie, exposed /.env
  * Vulnerable component-> outdated jQuery / Bootstrap referenced in the layout
"""
from __future__ import annotations

import sqlite3

from flask import Flask, make_response, render_template_string, request

app = Flask(__name__)

LAYOUT = """<!doctype html><html><head><title>Vuln Shop</title>
<!-- deliberately outdated components for the component scanner -->
<script src="/static/jquery-3.4.1.min.js"></script>
<link rel="stylesheet" href="/static/bootstrap-3.3.7.min.css">
</head><body style="font-family:sans-serif;max-width:720px;margin:2rem auto">
<h1>Vuln Shop (practice target)</h1>
<nav><a href="/">home</a> | <a href="/search?q=shirt">search</a> |
<a href="/greet?name=guest">greet</a> | <a href="/guestbook">guestbook</a></nav>
<hr>{{ body|safe }}</body></html>"""


def _db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE products (id INTEGER, name TEXT, price REAL)")
    conn.executemany("INSERT INTO products VALUES (?,?,?)", [
        (1, "Red Shirt", 19.99), (2, "Blue Jeans", 39.99), (3, "Green Hat", 9.99),
    ])
    return conn


GUESTBOOK: list[str] = []


def page(body: str):
    return render_template_string(LAYOUT, body=body)


@app.route("/")
def index():
    resp = make_response(page(
        "<p>Welcome to the practice target. Use the nav links above.</p>"))
    # insecure cookie: no HttpOnly / Secure / SameSite (misconfig finding)
    resp.set_cookie("session", "demo-session-token")
    return resp


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULNERABLE: user input concatenated straight into SQL
    sql = "SELECT id, name, price FROM products WHERE name LIKE '%" + q + "%'"
    try:
        rows = _db().execute(sql).fetchall()
        items = "".join(f"<li>{n} - ${p}</li>" for _, n, p in rows) or "<li>no matches</li>"
        return page(f"<h3>Results for '{q}'</h3><ul>{items}</ul>")
    except Exception as e:
        # VULNERABLE: leaks the raw database error (error-based SQLi + verbose error)
        return page(f"<pre>sqlite3.OperationalError: {e}</pre>"), 200


@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    # VULNERABLE: reflected without encoding
    return page(f"<h3>Hello, {name}!</h3>")


@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    if request.method == "POST":
        comment = request.form.get("comment", "")
        GUESTBOOK.append(comment)  # VULNERABLE: stored unencoded
    entries = "".join(f"<div class='entry'>{c}</div>" for c in GUESTBOOK)
    form = ("<form method='post'><input name='comment' placeholder='comment'>"
            "<button>post</button></form>")
    return page(f"<h3>Guestbook</h3>{form}{entries}")


@app.route("/.env")
def dotenv():
    # VULNERABLE: secret file exposed in web root
    return ("APP_KEY=base64:supersecretkey\nDB_PASSWORD=p@ssw0rd\n"
            "SECRET=do-not-expose\n", 200, {"Content-Type": "text/plain"})


if __name__ == "__main__":
    # localhost only - never expose this intentionally-vulnerable app externally
    app.run(host="127.0.0.1", port=5001, debug=False)
