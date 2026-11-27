import ast
import base64
import json
import operator
import os
import re
import sqlite3
import subprocess
from urllib.parse import urlparse

import yaml
from flask import Flask, abort, redirect, render_template, request, send_from_directory, session
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
DB = "insurance.db"
BASE = os.path.dirname(os.path.abspath(__file__))
DOC_RE = re.compile(r"policy_(\d+)\.txt")
LABEL_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")


@app.after_request
def security_headers(resp):
    # Defence in depth: even if markup were ever injected, inline scripts will not run.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "same-origin"
    return resp


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT, ssn TEXT, role TEXT);
    CREATE TABLE IF NOT EXISTS policies (id INTEGER PRIMARY KEY, number TEXT, type TEXT, coverage INTEGER, premium INTEGER, owner INTEGER);
    CREATE TABLE IF NOT EXISTS claims (id INTEGER PRIMARY KEY, policy_id INTEGER, description TEXT, status TEXT);
    """)
    if not c.execute("SELECT 1 FROM users").fetchone():
        h = generate_password_hash  # FIX CWE-327: salted scrypt instead of MD5
        c.executemany("INSERT INTO users VALUES (?,?,?,?,?,?)", [
            (1, "Alice Martin", "alice@example.com", h("alice-pass"), "123-45-6789", "customer"),
            (2, "Bob Keller", "bob@example.com", h("bob-pass"), "987-65-4321", "customer"),
            (3, "Admin", "admin@safeharbor.test", h("admin-pass"), "000-00-0000", "admin")])
        c.executemany("INSERT INTO policies VALUES (?,?,?,?,?,?)", [
            (1, "SH-1001", "Home", 350000, 1180, 1), (2, "SH-2001", "Auto", 60000, 940, 1), (3, "SH-3001", "Life", 500000, 720, 2)])
        c.executemany("INSERT INTO claims VALUES (?,?,?,?)", [
            (1, 1, "Water damage in kitchen", "Under review"), (2, 3, "Beneficiary update", "Pending")])
    c.commit()


def me():
    return session.get("uid")


def is_admin():
    # FIX CWE-285/565: role comes from the signed server-side session, never a cookie the user can edit
    return session.get("role") == "admin"


def safe_next(value):
    # FIX CWE-601: only same-site relative paths
    target = (value or "/dashboard").replace("\\", "")
    if not urlparse(target).netloc and not urlparse(target).scheme and target.startswith("/") and not target.startswith("//"):
        return target
    return "/dashboard"


@app.route("/")
def index():
    return redirect("/dashboard" if me() else "/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        # FIX CWE-89: parameterized query, password verified against the stored hash
        u = db().execute("SELECT * FROM users WHERE email = ?", (request.form.get("email", ""),)).fetchone()
        if u and check_password_hash(u["password"], request.form.get("password", "")):
            session.clear()
            session["uid"], session["name"], session["role"] = u["id"], u["name"], u["role"]
            return redirect(safe_next(request.args.get("next")))
        error = "Invalid email or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/dashboard")
def dashboard():
    if not me():
        return redirect("/login")
    pol = db().execute("SELECT * FROM policies WHERE owner = ?", (me(),)).fetchall()
    return render_template("dashboard.html", policies=pol)


@app.route("/policy/<int:pid>")
def policy(pid):
    if not me():
        return redirect("/login")
    # FIX CWE-639: a customer can only open their own policy
    p = db().execute("""SELECT p.*, u.name AS holder, u.email, '1985-04-12' AS dob FROM policies p
                        JOIN users u ON u.id = p.owner WHERE p.id = ? AND p.owner = ?""", (pid, me())).fetchone()
    if not p:
        abort(404)
    return render_template("policy.html", p=p)


@app.route("/claims", methods=["GET", "POST"])
def claims():
    if not me():
        return redirect("/login")
    c = db()
    if request.method == "POST":
        # FIX CWE-639: the policy must belong to the signed-in customer
        if not c.execute("SELECT 1 FROM policies WHERE id = ? AND owner = ?",
                         (request.form.get("policy_id", ""), me())).fetchone():
            abort(404)
        c.execute("INSERT INTO claims (policy_id, description, status) VALUES (?,?,?)",
                  (request.form["policy_id"], request.form.get("description", "")[:2000], "Submitted"))
        c.commit()
        return redirect("/claims")
    pol = c.execute("SELECT * FROM policies WHERE owner = ?", (me(),)).fetchall()
    rows = c.execute("""SELECT c.id, c.description, c.status, p.number FROM claims c
                        JOIN policies p ON p.id = c.policy_id WHERE p.owner = ?""", (me(),)).fetchall()
    return render_template("claims.html", policies=pol, claims=rows)  # FIX CWE-79: |safe removed, autoescape on


@app.route("/claims/search")
def claim_search():
    if not me():
        return redirect("/login")
    q = request.args.get("q", "")
    rows = db().execute("SELECT c.id, c.description FROM claims c JOIN policies p ON p.id = c.policy_id "
                        "WHERE p.owner = ? AND c.description LIKE ?", (me(), "%" + q + "%")).fetchall()
    return render_template("results.html", q=q, rows=rows)  # FIX CWE-79: |safe removed


@app.route("/documents/download")
def download():
    if not me():
        return redirect("/login")
    # FIX CWE-22/639: strict file-name pattern, ownership check, confined to documents/
    name = request.args.get("file", "")
    m = DOC_RE.fullmatch(name)
    if not m or not db().execute("SELECT 1 FROM policies WHERE id = ? AND owner = ?", (int(m.group(1)), me())).fetchone():
        abort(404)
    return send_from_directory(os.path.join(BASE, "documents"), name)


@app.route("/quote")
def quote():
    if not me():
        return redirect("/login")
    return render_template("quote.html")


_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv, ast.USub: operator.neg}


def _calc(node):
    if isinstance(node, ast.Expression):
        return _calc(node.body)
    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_calc(node.left), _calc(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_calc(node.operand))
    raise ValueError("unsupported expression")


@app.route("/api/quote")
def api_quote():
    # FIX CWE-95: arithmetic-only AST evaluator, eval() removed
    try:
        value = _calc(ast.parse(request.args.get("formula", "")[:200], mode="eval"))
    except (ValueError, SyntaxError, ZeroDivisionError, RecursionError):
        abort(400)
    return "Estimated premium: $%s" % value


@app.route("/admin")
def admin():
    if not is_admin():
        abort(403)
    users = db().execute("SELECT * FROM users").fetchall()
    return render_template("admin.html", users=users)


@app.route("/admin/backup")
def backup():
    if not is_admin():
        abort(403)
    label = request.args.get("label", "nightly")
    # FIX CWE-78: allow-listed label, argv list, no shell
    if not LABEL_RE.fullmatch(label):
        abort(400)
    out = subprocess.run(["echo", "backup-" + label], capture_output=True, text=True, check=False)
    return "<pre>%s</pre>" % escape(out.stdout)


@app.route("/admin/import-rates", methods=["POST"])
def import_rates():
    if not is_admin():
        abort(403)
    # FIX CWE-502: safe_load only builds plain data
    try:
        data = yaml.safe_load(request.form.get("data", ""))
    except yaml.YAMLError:
        abort(400)
    return "<pre>%s</pre>" % escape(str(data))


@app.route("/api/session/restore", methods=["POST"])
def restore():
    if not me():
        abort(401)
    # FIX CWE-502: JSON instead of pickle
    try:
        data = json.loads(base64.b64decode(request.get_data(), validate=True))
    except ValueError:
        abort(400)
    return "<pre>%s</pre>" % escape(str(data))


if __name__ == "__main__":
    init_db()
    # FIX CWE-489: debugger off and loopback only unless explicitly enabled through the environment
    app.run(host=config.HOST, port=int(os.environ.get("PORT", 5000)), debug=config.DEBUG)
