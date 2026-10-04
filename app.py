#!/usr/bin/env python3
"""DEVIL X local-only authentication lab. Standard library only."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from http import cookies
from urllib.parse import parse_qs
import hashlib
import hmac
import secrets
import time
import threading
import json
import os

HOST = "127.0.0.1"
PORT = int(os.environ.get("DEVIL_X_PORT", "8080"))
USERNAME = "labuser"
# Demo only: real systems should use a password hashing function such as Argon2id or scrypt.
PASSWORD = "CorrectHorseBatteryStaple!"
PASSWORD_DIGEST = hashlib.sha256(PASSWORD.encode()).digest()
MAX_FAILURES = 5
LOCK_SECONDS = 30
_lock = threading.Lock()
_attempts = {}     # username -> {"failures": int, "locked_until": float}
_sessions = {}     # token -> {"username": str, "expires": float}
_audit = []

def audit(event, username, detail=""):
    record = {"ts": int(time.time()), "event": event, "username": username[:80], "detail": detail[:160]}
    with _lock:
        _audit.append(record)
        del _audit[:-500]

def is_locked(username, now=None):
    now = time.time() if now is None else now
    with _lock:
        state = _attempts.get(username, {"failures": 0, "locked_until": 0})
        return state["locked_until"] > now

def authenticate(username, password, now=None):
    now = time.time() if now is None else now
    with _lock:
        state = _attempts.setdefault(username, {"failures": 0, "locked_until": 0})
        if state["locked_until"] > now:
            audit_event = ("login_blocked", "temporary lockout")
            success = False
        else:
            supplied = hashlib.sha256(password.encode()).digest()
            good_user = hmac.compare_digest(username.encode(), USERNAME.encode())
            good_password = hmac.compare_digest(supplied, PASSWORD_DIGEST)
            if good_user and good_password:
                state["failures"] = 0
                state["locked_until"] = 0
                token = secrets.token_urlsafe(32)
                _sessions[token] = {"username": username, "expires": now + 1800}
                audit_event = ("login_success", "")
                success = token
            else:
                state["failures"] += 1
                if state["failures"] >= MAX_FAILURES:
                    state["locked_until"] = now + LOCK_SECONDS
                audit_event = ("login_failure", "invalid credentials")
                success = False
    audit(audit_event[0], username, audit_event[1])
    return success

def valid_session(token, now=None):
    now = time.time() if now is None else now
    with _lock:
        session = _sessions.get(token)
        if not session or session["expires"] <= now:
            _sessions.pop(token, None)
            return False
        return True

def page(message=""):
    safe = message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>DEVIL X Auth Lab</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{{font:16px system-ui;max-width:720px;margin:3rem auto;padding:0 1rem;background:#101014;color:#eee}}
.card{{border:1px solid #454552;border-radius:14px;padding:1.5rem;background:#191920}}
input,button{{font:inherit;padding:.7rem;margin:.35rem 0;border-radius:8px;border:1px solid #555}}
input{{width:95%;background:#0e0e12;color:#fff}}button{{background:#bd2438;color:#fff;cursor:pointer}}
small,.muted{{color:#aaa}}.msg{{color:#ffcc80;min-height:1.5em}}
</style></head><body><h1>DEVIL X <span class="muted">/ AUTH LAB</span></h1>
<p class="muted">Local-only defensive authentication test harness</p><div class="card">
<p class="msg">{safe}</p><form method="post" action="/login">
<label>Username</label><br><input name="username" autocomplete="username" required maxlength="80"><br>
<label>Password</label><br><input type="password" name="password" autocomplete="current-password" required maxlength="200"><br>
<button type="submit">Sign in</button></form>
<p><small>Demo user: <code>labuser</code> · Demo password shown in README.</small></p>
</div><p><a href="/health" style="color:#aaa">Health</a> · <a href="/audit" style="color:#aaa">Local audit log</a></p></body></html>"""

class Handler(BaseHTTPRequestHandler):
    server_version = "DEVIL-X-Lab"
    def log_message(self, fmt, *args):
        # Keep HTTP request logging local and minimal.
        pass

    def send_body(self, status, body, content_type="text/html; charset=utf-8", extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self):
        if self.path == "/":
            self.send_body(200, page())
        elif self.path == "/health":
            self.send_body(200, json.dumps({"status":"ok","bind":HOST,"port":PORT}), "application/json")
        elif self.path == "/audit":
            with _lock:
                records = list(_audit[-100:])
            self.send_body(200, json.dumps(records, indent=2), "application/json")
        elif self.path == "/dashboard":
            token = self.get_token()
            if valid_session(token):
                self.send_body(200, "<h1>Authenticated lab session</h1><p>Session valid.</p><a href='/logout'>Log out</a>")
            else:
                self.send_body(401, page("Please sign in first."))
        elif self.path == "/logout":
            token = self.get_token()
            with _lock:
                _sessions.pop(token, None)
            self.send_body(200, page("Logged out."), extra_headers={"Set-Cookie":"devil_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})
        else:
            self.send_body(404, "Not found", "text/plain; charset=utf-8")

    def get_token(self):
        raw = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie()
        try:
            jar.load(raw)
            return jar["devil_session"].value if "devil_session" in jar else ""
        except Exception:
            return ""

    def do_POST(self):
        if self.path != "/login":
            self.send_body(404, "Not found", "text/plain; charset=utf-8")
            return
        length = min(int(self.headers.get("Content-Length", "0")), 8192)
        data = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        username = data.get("username", [""])[0][:80]
        password = data.get("password", [""])[0][:200]
        result = authenticate(username, password)
        if result:
            self.send_body(303, "", extra_headers={"Location":"/dashboard", "Set-Cookie":f"devil_session={result}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800"})
        else:
            # Generic response avoids revealing whether a username exists.
            self.send_body(401, page("Login failed or temporarily locked. Try again later."))

def main():
    server = HTTPServer((HOST, PORT), Handler)
    print(f"DEVIL X Auth Lab listening at http://{HOST}:{PORT}")
    print("Local-only training app. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
