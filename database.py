"""SQLite helpers. Every query uses '?' placeholders (parameterized queries),
so user input is never concatenated into SQL -> protection against SQL injection."""
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "instance" / "users.db"


def run(sql, params=(), fetch=None):
    """Run one SQL statement safely. `params` are passed separately from `sql`."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(sql, params)
        conn.commit()
        if fetch == "one":
            return cur.fetchone()
        return cur.lastrowid
    finally:
        conn.close()


def init_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    run("""CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name     TEXT NOT NULL,
            username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at    TEXT NOT NULL,
            last_login    TEXT)""")


def create_user(full_name, username, email, password_hash, created_at):
    return run("INSERT INTO users (full_name, username, email, password_hash, created_at) "
               "VALUES (?, ?, ?, ?, ?)", (full_name, username, email, password_hash, created_at))


def username_taken(username):
    return run("SELECT 1 FROM users WHERE username = ?", (username,), "one") is not None


def email_taken(email):
    return run("SELECT 1 FROM users WHERE email = ?", (email,), "one") is not None


def get_user_by_login(identifier):
    """Find a user by username OR email."""
    return run("SELECT * FROM users WHERE username = ? OR email = ?", (identifier, identifier), "one")


def get_user_by_id(user_id):
    return run("SELECT * FROM users WHERE id = ?", (user_id,), "one")


def update_password(user_id, password_hash):
    run("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))


def update_last_login(user_id, when):
    run("UPDATE users SET last_login = ? WHERE id = ?", (when, user_id))
