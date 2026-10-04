# DEVIL X Auth Lab

A small, **local-only authentication training application** for learning about login flows, temporary lockouts, session handling, and audit logging. It uses Python's standard library and does not require third-party packages.

> **Scope:** This project is for defensive learning and testing in your own local environment. It does not access, automate, or bypass authentication on third-party services.

## Features

- Demo login form and authenticated dashboard
- Temporary lockout after repeated failed login attempts
- Random session tokens with a 30-minute lifetime
- Logout and session invalidation
- Generic login failure message to avoid revealing whether a username exists
- Local audit log and health endpoint
- Unit tests for core authentication behavior
- Python standard library only

## Requirements

- Python 3.9 or newer recommended
- Git (optional, for cloning the repository)

## Quick start

Clone the repository and enter the project directory:

```bash
git clone https://github.com/nagatoara4/devil-x-auth-lab.git
cd devil-x-auth-lab
```

Start the application:

```bash
python3 app.py
```

Then open [http://127.0.0.1:8080](http://127.0.0.1:8080) in your browser.

Stop the server with `Ctrl+C`.

### Demo credentials

- **Username:** `labuser`
- **Password:** `CorrectHorseBatteryStaple!`

These credentials are hard-coded for demonstration and must never be reused in a real service.

### Optional port setting

The server binds to `127.0.0.1` by default. You can choose another local port with the `DEVIL_X_PORT` environment variable:

```bash
DEVIL_X_PORT=8081 python3 app.py
```

Keep the bind address loopback-only. Do not expose this training app to a public network.

## Endpoints

| Path | Method | Purpose |
| --- | --- | --- |
| `/` | GET | Display the login form |
| `/login` | POST | Submit demo credentials |
| `/dashboard` | GET | Check the current session |
| `/logout` | GET | Invalidate the current session |
| `/health` | GET | Return a basic JSON health response |
| `/audit` | GET | Return recent in-memory audit events |

The audit log is stored in memory and is cleared when the process stops. The health and audit endpoints are intentionally minimal and are not production monitoring interfaces.

## Run the tests

From the project directory:

```bash
python3 -m unittest -v
```

The tests cover successful login, invalid credentials, lockout behavior, session expiration, and audit logging.

## Security notes and limitations

This is a **training example, not production-ready authentication software**.

- Password verification currently uses SHA-256 for demonstration. SHA-256 is not appropriate for storing real passwords. Production systems should use a password-hashing algorithm designed for this purpose, such as Argon2id, scrypt, or an appropriately configured PBKDF2 implementation.
- The demo username and password are hard-coded.
- Account lockout state, sessions, and audit records are held in process memory and disappear on restart.
- There is no database, CSRF protection, account management, TLS termination, or production-grade operational monitoring.
- The built-in HTTP server is intended for local experimentation only.
- Keep the server bound to `127.0.0.1`; do not deploy it directly to the internet or use real credentials.

## Defensive toolkit

`toolkit.py` adds three local defensive utilities:

### 1. Password policy check

```bash
python3 toolkit.py password-policy
```

Prompts securely without echoing the password, then reports basic length and character-category checks. It does not save or transmit the password. This is a simple policy check, not a password-strength or crack-time guarantee.

### 2. Local HTTP security-header review

Start the lab in one terminal:

```bash
python3 app.py
```

In another terminal:

```bash
python3 toolkit.py headers http://127.0.0.1:8080/
```

The check is restricted to explicit loopback hosts (`localhost`, `127.0.0.1`, and `::1`). It reports common security headers and missing items for review. It does not scan external hosts. A missing header is not automatically a vulnerability; for example, HSTS is relevant when serving HTTPS.

### 3. Audit-log summary

Save an exported JSON array of audit records to a local file, then run:

```bash
python3 toolkit.py audit-summary audit.json
```

The command summarizes event counts and the number of distinct usernames. It reads the file without modifying it. The lab's `/audit` endpoint returns JSON; copy its output to a local file if you want to summarize it.

## Run all tests

```bash
python3 -m unittest -v
```

This runs both the authentication application tests and toolkit tests.

## Project files

- `app.py` — local HTTP application and authentication logic
- `test_app.py` — authentication unit tests
- `toolkit.py` — defensive local toolkit (password policy, local headers, audit summary)
- `test_toolkit.py` — toolkit unit tests
- `LICENSE` — MIT License

## License

Distributed under the MIT License. See [LICENSE](LICENSE).
