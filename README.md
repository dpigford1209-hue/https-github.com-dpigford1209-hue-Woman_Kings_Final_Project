# Woman_Kings_Final_Project
### IBM Final Project — Security Remediation & Test Suite
**Authors:** Tashare Hamilton, D'Nisha Pigford

---

## Project Files

| File | Purpose |
|---|---|
| `scenario1_vulnerable_app_fixed.py` | Fully remediated Python application — all CRITICAL and HIGH security vulnerabilities fixed |
| `test_my_code.py` | 35 security regression tests covering every public function |
| `README.md` | This file — grader instructions |

---

## What Was Fixed

| ID | Severity | Vulnerability | Fix Applied |
|---|---|---|---|
| CRITICAL-1 | Critical | Hardcoded database password (`admin123`) | Moved to `os.environ.get("DB_PASSWORD")` with startup guard |
| CRITICAL-2 | Critical | Hardcoded live API key in source code | Moved to `os.environ.get("API_KEY")` — original key must be revoked |
| CRITICAL-3 | Critical | SQL injection in `get_user()` — string concatenation | Replaced with parameterized query (`?` placeholder) |
| CRITICAL-4 | Critical | Command injection in `run_report()` — `shell=True` + unsanitized input | `shell=False`, list args, allowlist of 4 permitted report names |
| CRITICAL-5 | Critical | Path traversal in `read_file()` — no path normalization | `os.path.realpath()` + directory prefix assertion blocks `../../` attacks |
| CRITICAL-6 | Critical | Authentication bypass in `login()` — password never checked | PBKDF2-SHA256 hash verification with `hmac.compare_digest` (timing-safe) |
| CRITICAL-7 | Critical | SQL injection in `export_data()` — `str(user_id)` concatenated | Replaced with parameterized query |
| HIGH-1 | High | PII (SSN, salary) printed to stdout | `print()` statement removed entirely |
| HIGH-2 | High | Database connections never closed | All connections use `with` context manager |

---

## Requirements

- **Python 3.8 or higher** — no third-party packages needed
- Download Python from [python.org/downloads](https://www.python.org/downloads/) if not installed

---

## How to Run the Tests

### Option A — PowerShell / Command Prompt

```powershell
cd "C:\Users\User\OneDrive\Woman_Kings_Final_Project"
python test_my_code.py
```

If `python` is not recognised, try:

```powershell
py test_my_code.py
```

### Option B — Run directly from this folder (double-click)

Right-click `test_my_code.py` → **Open with** → **Python**

---

### Expected Output
```
test_correct_credentials_accepted (TestLogin.test_correct_credentials_accepted) ... ok
test_empty_password_rejected (TestLogin.test_empty_password_rejected) ... ok
...
----------------------------------------------------------------------
Ran 35 tests in X.XXXs

OK
```

---

## Test Coverage Summary

| Test Class | Tests | What It Verifies |
|---|---|---|
| `TestGetUser` | 5 | SQL injection prevention (OR, DROP TABLE, UNION payloads) + legitimate lookup |
| `TestRunReport` | 8 | Allowlist enforcement, `shell=False`, list args, injection/traversal rejection |
| `TestReadFile` | 6 | Path traversal blocked (`../../`, `../`, absolute paths, Windows `..\`) |
| `TestLogin` | 6 | Correct/wrong/empty/None password, SQL injection in username, unknown user |
| `TestExportData` | 4 | Valid lookup, unknown id, injection payload, no PII to stdout |
| `TestVerifyPassword` | 6 | Correct match, wrong password, empty/malformed/None inputs |

---

## Notes for Grader

- The test file is **self-contained** — it sets up and tears down its own in-memory SQLite databases. No external database is needed.
- The tests mock `subprocess.run` so no shell scripts need to be present.
- Environment variables (`DB_PASSWORD`, `API_KEY`) are automatically set to test values before each test run.
- The original vulnerable file is **not included** in this submission folder — only the fixed version is present.
