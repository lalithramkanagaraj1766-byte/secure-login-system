"""Secure Login System - Flask app: register, login, dashboard, settings, logout."""
import hmac
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

import database as db

try:  # read SECRET_KEY etc. from a .env file if python-dotenv is installed
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)

# Secret key comes from the environment, never from the source code.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
if not os.environ.get("SECRET_KEY"):
    print("WARNING: SECRET_KEY not set. Using a temporary key (logins reset on restart).")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,      # JavaScript cannot read the cookie
    SESSION_COOKIE_SAMESITE="Lax",     # cookie not sent on cross-site POSTs
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",  # set to 1 on HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),                   # idle timeout
    MAX_CONTENT_LENGTH=64 * 1024,      # reject oversized requests
)

db.init_db()

HASH_METHOD = "scrypt"
DUMMY_HASH = generate_password_hash("dummy-password", method=HASH_METHOD)
MAX_ATTEMPTS, LOCK_SECONDS = 5, 300
failed = {}  # rate-limit memory: key -> list of failure timestamps

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
USER_RE = re.compile(r"[A-Za-z0-9_]{3,20}")
NAME_RE = re.compile(r"[A-Za-z][A-Za-z .'-]{1,59}")
PASSWORD_RULES = [(r".{8,}", "at least 8 characters"), (r"[a-z]", "a lowercase letter"),
                  (r"[A-Z]", "an uppercase letter"), (r"\d", "a number"),
                  (r"[^A-Za-z0-9]", "a special character")]


# ---------- helpers ----------
def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def password_errors(pw, username=""):
    missing = [text for pattern, text in PASSWORD_RULES if not re.search(pattern, pw)]
    errors = ["Password needs " + ", ".join(missing) + "."] if missing else []
    if len(pw) > 128:
        errors.append("Password must be 128 characters or fewer.")
    if len(username) >= 3 and username.lower() in pw.lower():
        errors.append("Password must not contain your username.")
    return errors


def is_locked(key):
    recent = [t for t in failed.get(key, []) if time.time() - t < LOCK_SECONDS]
    failed[key] = recent
    return len(recent) >= MAX_ATTEMPTS


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            flash("Please log in to access that page.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def load_user_and_check_csrf():
    if request.endpoint == "static":
        return
    g.user = db.get_user_by_id(session["user_id"]) if "user_id" in session else None
    if "user_id" in session and g.user is None:   # account no longer exists
        session.clear()
    if request.method == "POST":                  # CSRF check for every form
        sent = request.form.get("csrf_token", "").encode()
        expected = session.get("_csrf", "").encode()
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400)


@app.after_request
def security_headers(resp):
    if request.endpoint != "static":
        resp.headers["Cache-Control"] = "no-store"   # back button won't show old private pages
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; form-action 'self'; frame-ancestors 'none'"
    return resp


@app.errorhandler(HTTPException)
def http_error(e):
    messages = {400: "Invalid or expired form. Go back, refresh the page and try again.",
                404: "Page not found.", 405: "That action is not allowed here.",
                413: "The request was too large."}
    return render_template("error.html", code=e.code,
                           message=messages.get(e.code, "Something went wrong on our side.")), e.code


# ---------- routes ----------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))
    form, errors = {}, []
    if request.method == "POST":
        form = {"full_name": request.form.get("full_name", "").strip(),
                "username": request.form.get("username", "").strip(),
                "email": request.form.get("email", "").strip().lower()}
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not all(form.values()) or not password or not confirm:
            errors.append("All fields are required.")
        else:
            if not NAME_RE.fullmatch(form["full_name"]):
                errors.append("Enter a valid full name (letters, spaces, . ' -).")
            if not USER_RE.fullmatch(form["username"]):
                errors.append("Username must be 3-20 characters: letters, numbers or underscore.")
            if len(form["email"]) > 120 or not EMAIL_RE.fullmatch(form["email"]):
                errors.append("Enter a valid email address.")
            errors += password_errors(password, form["username"])
            if password != confirm:
                errors.append("Passwords do not match.")
        if not errors:
            if db.username_taken(form["username"]):
                errors.append("That username is already taken.")
            if db.email_taken(form["email"]):
                errors.append("An account with that email already exists.")
        if not errors:
            try:
                db.create_user(form["full_name"], form["username"], form["email"],
                               generate_password_hash(password, method=HASH_METHOD), now())
            except sqlite3.IntegrityError:    # two people registering at the same moment
                errors.append("That username or email is already in use.")
            else:
                flash("Account created. You can log in now.", "success")
                return redirect(url_for("login"))
    return render_template("register.html", errors=errors, form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    errors, identifier = [], ""
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        if not identifier or not password:
            errors.append("Enter your username or email and your password.")
        else:
            key = f"{request.remote_addr}|{identifier.lower()}"
            if is_locked(key):
                errors.append("Too many failed attempts. Try again in 5 minutes.")
                return render_template("login.html", errors=errors, identifier=identifier), 429
            user = db.get_user_by_login(identifier)
            # Always run a hash check (even for unknown users) so timing doesn't reveal accounts.
            valid = check_password_hash(user["password_hash"] if user else DUMMY_HASH, password)
            if user and valid:
                failed.pop(key, None)
                previous_login = user["last_login"]
                session.clear()               # new session on login (prevents session fixation)
                session.permanent = True
                session["user_id"] = user["id"]
                session["prev_login"] = previous_login
                db.update_last_login(user["id"], now())
                return redirect(url_for("dashboard"))
            failed.setdefault(key, []).append(time.time())
            errors.append("Invalid username/email or password.")   # same message for both cases
    return render_template("login.html", errors=errors, identifier=identifier)


@app.route("/dashboard")
@login_required
def dashboard():
    algorithm = g.user["password_hash"].split(":")[0]
    return render_template("dashboard.html", algorithm=algorithm,
                           prev_login=session.get("prev_login"))


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    errors = []
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        key = f"pw|{g.user['id']}"
        if not (current and new and confirm):
            errors.append("All fields are required.")
        elif is_locked(key):
            errors.append("Too many failed attempts. Try again in 5 minutes.")
        elif not check_password_hash(g.user["password_hash"], current):
            failed.setdefault(key, []).append(time.time())
            errors.append("Current password is incorrect.")
        else:
            errors += password_errors(new, g.user["username"])
            if new != confirm:
                errors.append("New passwords do not match.")
            if new == current:
                errors.append("New password must be different from the current one.")
        if not errors:
            db.update_password(g.user["id"], generate_password_hash(new, method=HASH_METHOD))
            failed.pop(key, None)
            flash("Password changed successfully.", "success")
            return redirect(url_for("settings"))
    return render_template("settings.html", errors=errors)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()                           # destroys the login session
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
