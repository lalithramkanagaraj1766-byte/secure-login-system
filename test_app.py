"""Automated security tests. Run:  python test_app.py
Uses a temporary database, so your real instance/users.db is not touched."""
import re
import sqlite3
import tempfile
from pathlib import Path

import database

database.DB_PATH = Path(tempfile.mkdtemp()) / "test.db"   # must happen before importing app
import app as app_module  # noqa: E402

app = app_module.app
PASSWORD = "Str0ng!Pass"
results = []


def check(name, condition):
    results.append(condition)
    print(("PASS" if condition else "FAIL") + "  " + name)


def token(client):
    html = client.get("/login", follow_redirects=True).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def post(client, url, data, **kw):
    return client.post(url, data={**data, "csrf_token": token(client)}, **kw)


def register(client, username="alice", email="alice@example.com", password=PASSWORD, **over):
    data = {"full_name": "Alice Smith", "username": username, "email": email,
            "password": password, "confirm_password": password}
    data.update(over)
    return post(client, "/register", data)


def login(client, identifier, password):
    return post(client, "/login", {"identifier": identifier, "password": password})


def rows(sql, params=()):
    conn = sqlite3.connect(database.DB_PATH)
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


c = app.test_client()

# 1. Registration + password hashing
r = register(c)
check("1. Register new user -> redirect to login", r.status_code == 302 and "/login" in r.location)
stored = rows("SELECT password_hash FROM users WHERE username='alice'")[0][0]
check("   Password stored as scrypt hash, not plain text", stored.startswith("scrypt:") and PASSWORD not in stored)

# 2. Duplicates
check("2. Duplicate username rejected", "already taken" in register(c, email="b@example.com").get_data(as_text=True))
check("   Duplicate email rejected (case-insensitive)", "already exists" in register(c, username="bob", email="ALICE@example.com").get_data(as_text=True))
check("   Only one account stored", rows("SELECT COUNT(*) FROM users")[0][0] == 1)

# 3. Validation
check("3. Empty registration fields rejected", "All fields are required" in post(c, "/register", {"full_name": "", "username": "", "email": "", "password": "", "confirm_password": ""}).get_data(as_text=True))
check("   Weak password rejected", "Password needs" in register(c, username="bob", email="bob@example.com", password="abc").get_data(as_text=True))
check("   Mismatched passwords rejected", "do not match" in register(c, username="bob", email="bob@example.com", confirm_password="Other!Pass1").get_data(as_text=True))
check("   Invalid email rejected", "valid email" in register(c, username="bob", email="not-an-email").get_data(as_text=True))
check("   Invalid username rejected", "Username must be" in register(c, username="bob smith!", email="bob@example.com").get_data(as_text=True))

# 4. Protected pages without login
for page in ("/dashboard", "/settings"):
    r = c.get(page)
    check(f"4. {page} without login -> redirect to /login", r.status_code == 302 and "/login" in r.location)

# 5. Login failures
check("5. Empty login fields rejected", "Enter your username" in login(c, "", "").get_data(as_text=True))
wrong = login(c, "alice", "Wrong!Pass1").get_data(as_text=True)
unknown = login(c, "nobody", "Wrong!Pass1").get_data(as_text=True)
check("   Wrong password -> generic error", "Invalid username/email or password." in wrong)
check("   Unknown user -> identical error (no account leak)", "Invalid username/email or password." in unknown)

# 6. SQL injection attempts
for payload in ("' OR '1'='1' --", "alice' --", "x' OR 1=1 --", "'; DROP TABLE users; --"):
    r = login(c, payload, payload)
    check(f"6. SQL injection login blocked: {payload}", r.status_code == 200 and "Invalid" in r.get_data(as_text=True))
check("   users table still intact after attacks", rows("SELECT COUNT(*) FROM users")[0][0] == 1)
check("   SQL injection in registration rejected", "Username must be" in register(c, username="a'; DROP TABLE users;--", email="x@example.com").get_data(as_text=True))
app_module.failed.clear()

# 7. Successful login + session
r = login(c, "alice", PASSWORD)
check("7. Login with username -> redirect to dashboard", r.status_code == 302 and "/dashboard" in r.location)
cookie = r.headers.get("Set-Cookie", "")
check("   Session cookie is HttpOnly and SameSite=Lax", "HttpOnly" in cookie and "SameSite=Lax" in cookie)
dash = c.get("/dashboard")
check("   Dashboard accessible when logged in", dash.status_code == 200 and "Welcome, alice" in dash.get_data(as_text=True))
check("   Dashboard shows scrypt, never the hash itself", "scrypt" in dash.get_data(as_text=True) and stored not in dash.get_data(as_text=True))
check("   Cache-Control: no-store on private pages", dash.headers.get("Cache-Control") == "no-store")
check("   Security headers present", dash.headers.get("X-Frame-Options") == "DENY" and "default-src 'self'" in dash.headers.get("Content-Security-Policy", ""))

# 8. Password change
check("8. Wrong current password rejected", "incorrect" in post(c, "/settings", {"current_password": "Nope!Pass1", "new_password": "N3w!Password", "confirm_password": "N3w!Password"}).get_data(as_text=True))
check("   Weak new password rejected", "Password needs" in post(c, "/settings", {"current_password": PASSWORD, "new_password": "weak", "confirm_password": "weak"}).get_data(as_text=True))
r = post(c, "/settings", {"current_password": PASSWORD, "new_password": "N3w!Password", "confirm_password": "N3w!Password"})
check("   Password changed successfully", r.status_code == 302)
check("   New hash stored in database", rows("SELECT password_hash FROM users WHERE username='alice'")[0][0] != stored)

# 9. Logout + session invalidation
r = post(c, "/logout", {})
check("9. Logout -> redirect to login", r.status_code == 302 and "/login" in r.location)
check("   Dashboard blocked after logout", c.get("/dashboard").status_code == 302)

# 10. Old password dead, new password works (login by email)
check("10. Old password no longer works", "Invalid" in login(c, "alice", PASSWORD).get_data(as_text=True))
r = login(c, "alice@example.com", "N3w!Password")
check("    New password works, login by email", r.status_code == 302 and "/dashboard" in r.location)
post(c, "/logout", {})

# 11. CSRF
check("11. POST without CSRF token -> 400", c.post("/login", data={"identifier": "alice", "password": "x"}).status_code == 400)
check("    POST with forged CSRF token -> 400", c.post("/login", data={"identifier": "alice", "password": "x", "csrf_token": "forged"}).status_code == 400)
check("    Logout via GET not allowed (405)", c.get("/logout").status_code == 405)

# 12. Rate limiting
app_module.failed.clear()
for _ in range(5):
    login(c, "alice", "Wrong!Pass1")
r = login(c, "alice", "N3w!Password")
check("12. Account locked after 5 failed attempts (429), even with correct password", r.status_code == 429)
app_module.failed.clear()

# 13. Pages + safe errors
for page in ("/", "/login", "/register"):
    check(f"13. Page loads: {page}", c.get(page).status_code == 200)
r = c.get("/does-not-exist")
check("    404 page is generic", r.status_code == 404 and "Traceback" not in r.get_data(as_text=True))

print(f"\n{sum(results)}/{len(results)} checks passed")
raise SystemExit(0 if all(results) else 1)
