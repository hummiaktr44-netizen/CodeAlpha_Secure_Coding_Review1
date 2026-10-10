# CodeAlpha_Secure_Coding_Review

Secure coding review of a Python/Flask application (CodeAlpha Cyber Security Internship, Task 3).

- `vulnerable_app.py`: intentionally insecure demo app
- `secure_app.py`: fixed version
- `REPORT.md`: findings, risk, remediation and best practices
- `bandit_vulnerable.txt` / `bandit_secure.txt`: Bandit scan outputs

**Result:** 12 Bandit issues (4 High, 5 Medium, 3 Low) plus 1 manual finding in the original, down to 0 High and 0 Medium after fixes.

Run the scan: `pip install bandit` then `bandit -r vulnerable_app.py`
