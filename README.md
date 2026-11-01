# SecureAuth – Secure Login System

A Flask web app that demonstrates secure authentication: registration, login, protected dashboard, account settings (password change) and logout.

**Stack:** Python, Flask, SQLite, Werkzeug (scrypt hashing), HTML, CSS, JavaScript.

## Run it (VS Code)

```bash
cd secure_login_system
python -m venv venv
venv\Scripts\activate            # Windows   (macOS/Linux: source venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env           # macOS/Linux: cp .env.example .env
python app.py
```

Open **http://127.0.0.1:5000**. Put your own random key in `.env` (`SECRET_KEY=...`).
Generate one with: `python -c "import secrets; print(secrets.token_hex(32))"`

Run the automated security tests: `python test_app.py` (uses a temporary database).

## Features

| Area | What is implemented |
|---|---|
| Registration | Full name, username, email, password, confirm password; server-side validation; duplicate username/email check |
| Passwords | scrypt hash + random salt (Werkzeug), strength rules (8+ chars, upper, lower, number, symbol), live strength meter, show/hide toggle |
| Login | Username **or** email; same generic error for wrong user or wrong password; empty-field validation |
| Sessions | HttpOnly + SameSite=Lax cookie, `Secure` flag via `COOKIE_SECURE=1` on HTTPS, 30-min idle timeout, session cleared on login and logout |
| SQL injection | 100% parameterized queries (`?` placeholders) + input validation |
| Extra protection | CSRF token on every form, login rate limiting (5 failures -> 5-minute lock), security headers (CSP, X-Frame-Options, no-store cache), generic error pages |
| Pages | Home, Register, Login, Dashboard (protected), Settings (protected) |

## How it works (for your evaluation)

**Registration.** The form is checked on the server: name/username/email formats, password strength, matching confirmation, and duplicates. If valid, the password is hashed and only the hash is saved in SQLite. Browser-side checks exist for convenience, but the server never trusts them.

**Password hashing.** `generate_password_hash(password, method="scrypt")` creates a one-way hash with a random salt, e.g. `scrypt:32768:8:1$salt$hash`. It is deliberately slow and memory-hungry, which makes brute-force guessing expensive. The same password gives a different hash every time because of the salt. Plain passwords are never stored or logged.

**Login authentication.** The user is looked up by username or email, then `check_password_hash()` compares the typed password with the stored hash. A wrong user and a wrong password give the same message ("Invalid username/email or password."), and a dummy hash check runs for unknown users so response time doesn't reveal which accounts exist. After 5 failures the account/IP pair is locked for 5 minutes.

**Session management.** On success, the old session is cleared and a new one holding only the user id is created (stops session fixation). Flask signs the cookie with `SECRET_KEY` (loaded from the environment), so it cannot be edited. HttpOnly stops JavaScript reading it, SameSite limits cross-site sending, and Secure (on HTTPS) stops sending over plain HTTP. `@login_required` redirects anonymous visitors to the login page. Logout (a POST form with a CSRF token) clears the session.

**SQL injection protection.** Queries look like `SELECT * FROM users WHERE username = ? OR email = ?` and the input is passed separately. The database treats it purely as data, so `' OR '1'='1' --` is just a wrong username. No SQL is ever built with string concatenation or f-strings.

**CSRF.** Each session gets a random token placed in every form; POST requests without the matching token are rejected (HTTP 400), so another website cannot make your browser submit forms.

## Security test results

Automated: `python test_app.py` -> **43/43 checks passed** (Flask test client, temporary database). Also verified against a live `python app.py` server with curl (pages load, `/dashboard` redirects to login when logged out, cookie shows `HttpOnly; SameSite=Lax`).

| # | Test | Result |
|---|---|---|
| 1 | Register new user; password stored as scrypt hash, not plain text | Pass |
| 2 | Duplicate username / duplicate email (any letter case) rejected | Pass |
| 3 | Login with correct credentials (username and email) | Pass |
| 4 | Wrong password and unknown user give the identical generic error | Pass |
| 5 | Dashboard and settings without login redirect to /login | Pass |
| 6 | After logout the dashboard is blocked again | Pass |
| 7 | Empty fields, weak password, mismatch, bad email, bad username rejected | Pass |
| 8 | Password change: wrong current rejected, weak rejected, success; old password stops working | Pass |
| 9 | SQL injection payloads (`' OR '1'='1' --`, `'; DROP TABLE users; --`, etc.) fail; table intact | Pass |
| 10 | CSRF: missing/forged token -> 400; logout via GET -> 405 | Pass |
| 11 | Rate limit: 6th attempt blocked (429) even with the correct password | Pass |
| 12 | Security headers, HttpOnly/SameSite cookie, generic 404 page | Pass |

**Not tested:** how the pages look in a real browser (visual layout, mobile responsiveness, the JavaScript show/hide button and strength meter), and the `Secure` cookie flag over real HTTPS. Please check these yourself before the demo.

## Limitations (good points to mention)

- 2FA (optional in the assignment) is **not** included, to keep the project simple.
- Rate-limit counters are kept in memory and reset when the server restarts; production systems use Redis or a database.
- Flask sessions are signed cookies, so logout clears the cookie but cannot revoke a copy someone already stole. Storing session ids in the database would allow that.
- For real deployment: use HTTPS, set `COOKIE_SECURE=1`, use a strong `SECRET_KEY`, and run behind a production server (Gunicorn/Waitress), not `app.run`.

## Project structure

```
secure_login_system/
  app.py            routes, validation, sessions, CSRF, rate limiting
  database.py       SQLite + parameterized queries
  test_app.py       automated security tests
  requirements.txt  .env.example  README.md
  templates/        base, index, register, login, dashboard, settings, error
  static/           style.css, script.js
  instance/         users.db (created automatically)
```
