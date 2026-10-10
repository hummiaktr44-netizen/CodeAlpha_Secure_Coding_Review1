# Secure Coding Review Report

**Project:** CodeAlpha_Secure_Coding_Review
**Language / application:** Python 3, Flask web app (user registration, login, ping tool, file reader, calculator, data loader)
**Methods:** static analysis with **Bandit** + manual code inspection
**Files:** `vulnerable_app.py` (original), `secure_app.py` (fixed), `bandit_vulnerable.txt`, `bandit_secure.txt`

## 1. Summary

| | Vulnerable version | Fixed version |
|---|---|---|
| Bandit High | 4 | 0 |
| Bandit Medium | 5 | 0 |
| Bandit Low | 3 | 3 (informational, reviewed below) |

Bandit found 12 issues in the original. A manual review found one more that Bandit missed (path traversal), so 9 distinct vulnerabilities are documented below.

## 2. Findings and remediation

| # | Vulnerability | Location | Severity | Found by | Risk |
|---|---|---|---|---|---|
| 1 | SQL injection (B608) | `/register`, `/login` | High | Bandit + manual | Attacker can log in without a password (`' OR '1'='1`) or read/modify the database |
| 2 | OS command injection (B602) | `/ping` | High | Bandit | Input like `8.8.8.8; cat /etc/passwd` runs shell commands on the server |
| 3 | Code injection via `eval` (B307) | `/calc` | High | Bandit | Attacker can run arbitrary Python code |
| 4 | Flask debug mode on (B201) | `app.run(debug=True)` | High | Bandit | Exposes an interactive debugger that allows remote code execution |
| 5 | Weak password hashing, MD5 without salt (B324) | `/register`, `/login` | High | Bandit | Passwords are cracked quickly with rainbow tables |
| 6 | Insecure deserialization, pickle (B301) | `/load` | Medium | Bandit | Crafted data can execute code when unpickled |
| 7 | Path traversal | `/read` | Medium | Manual review | `?file=../../etc/passwd` reads files outside `uploads/` |
| 8 | Binding to all interfaces (B104) | `app.run(host="0.0.0.0")` | Medium | Bandit | App is reachable from every network, not just localhost |
| 9 | Hardcoded secret (B105) | `SECRET_KEY = "admin123"` | Low | Bandit | Secret leaks through source control and is easy to guess |

## 3. Remediation steps (what was changed in `secure_app.py`)

1. **SQL injection:** use parameterized queries (`WHERE name = ?`) so input is treated as data, never as SQL.
2. **Command injection:** validate the host with an allow-list regex and call `subprocess.run([...])` with an argument list, `shell=False`, and a timeout.
3. **eval:** removed `eval`. The calculator accepts only the format `number operator number` through a strict regex.
4. **Debug mode:** `debug=False`.
5. **Password hashing:** `hashlib.scrypt` with a random 16-byte salt per user, and `hmac.compare_digest` for constant-time comparison. Added a minimum password length of 8.
6. **Deserialization:** replaced `pickle.loads` with `json.loads`, which cannot execute code.
7. **Path traversal:** resolve the requested path and check it stays inside the `uploads/` directory.
8. **Network exposure:** bind to `127.0.0.1`. Put the app behind a reverse proxy with HTTPS if it must be public.
9. **Secret:** read from the environment variable `APP_SECRET_KEY` instead of the source code.

## 4. Re-scan result

Bandit reports 0 High and 0 Medium issues on the fixed version. The 3 remaining Low items are informational:

- **B404 / B603 / B607 (subprocess):** these only flag that `subprocess` is used. The call uses an argument list without a shell, the host is validated by an allow-list, and a timeout is set, so the risk is accepted. Using the full path (`/bin/ping`) would silence B607.

## 5. General secure coding best practices

- Never trust user input: validate with allow-lists and encode output.
- Use parameterized queries or an ORM, never string concatenation for SQL.
- Avoid `eval`, `exec`, `pickle` on untrusted data, and `shell=True`.
- Store passwords with scrypt, bcrypt or Argon2, with a unique salt.
- Keep secrets in environment variables or a secrets manager, and out of Git.
- Disable debug mode in production and follow least privilege (bind only where needed).
- Run static analysis (Bandit) in your workflow and keep dependencies updated.
- Add tests for security cases such as injection strings and `../` paths.

## 6. How to reproduce

```bash
pip install bandit
bandit -r vulnerable_app.py     # 12 issues
bandit -r secure_app.py         # 0 high, 0 medium
```

> The vulnerable app is for learning only. Do not run it on a public network.
