"""
scenario1_vulnerable_app_fixed.py
IBM Final Project — Security Remediation
Authors: Tashare Hamilton, D'Nisha Pigford

All CRITICAL and HIGH vulnerabilities from the original scenario have been
remediated. See README.md for a full fix-by-fix breakdown.
"""

import os
import sqlite3
import subprocess
import hashlib
import hmac
import sys
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# CRITICAL-1: Hardcoded database password removed.
# Password is now loaded from the environment at startup.
# ---------------------------------------------------------------------------
DB_PASSWORD = os.environ.get("DB_PASSWORD")
if DB_PASSWORD is None and not os.environ.get("_TESTING"):
    print("ERROR: DB_PASSWORD environment variable is not set.", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# CRITICAL-2: Hardcoded API key removed.
# Key is now loaded from the environment at startup.
# ---------------------------------------------------------------------------
API_KEY = os.environ.get("API_KEY")
if API_KEY is None and not os.environ.get("_TESTING"):
    print("ERROR: API_KEY environment variable is not set.", file=sys.stderr)
    sys.exit(1)

# Directory that read_file() is allowed to serve files from.
SAFE_BASE_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "files"))

# Allowlist of report names permitted by run_report().
ALLOWED_REPORTS = {"daily", "weekly", "monthly", "summary"}


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def _get_connection(db_path=":memory:"):
    """Return a sqlite3 connection. Callers must use it as a context manager."""
    conn = sqlite3.connect(db_path)
    return conn


def _init_db(conn):
    """Create the users table used by get_user, login, and export_data."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id      INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            salt    TEXT NOT NULL,
            ssn     TEXT,
            salary  REAL
        )
        """
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

def hash_password(password: str) -> Tuple[str, str]:
    """Return (salt_hex, hash_hex) for a plaintext password."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return salt.hex(), dk.hex()


def verify_password(stored_hash: str, stored_salt: str, provided_password: str) -> bool:
    """
    Timing-safe comparison of a provided password against a stored PBKDF2-SHA256 hash.
    Returns False for any None/empty input rather than raising.
    """
    # CRITICAL-6 supporting helper — also tested directly as TestVerifyPassword
    if not provided_password or not stored_hash or not stored_salt:
        return False
    try:
        salt_bytes = bytes.fromhex(stored_salt)
        expected = bytes.fromhex(stored_hash)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac(
        "sha256", provided_password.encode(), salt_bytes, 260_000
    )
    return hmac.compare_digest(actual, expected)


# ---------------------------------------------------------------------------
# Public application functions
# ---------------------------------------------------------------------------

def get_user(username: str, conn: sqlite3.Connection):
    """
    Return the row for *username*, or None if not found.

    CRITICAL-3 fix: uses a parameterized query — the username value is
    never interpolated into the SQL string.
    """
    cursor = conn.execute(
        "SELECT id, username FROM users WHERE username = ?", (username,)
    )
    return cursor.fetchone()


def run_report(report_name: str) -> str:
    """
    Execute a pre-approved report script and return its stdout output.

    CRITICAL-4 fix:
      - report_name is validated against ALLOWED_REPORTS allowlist.
      - subprocess is called with shell=False and a list of arguments.
      - No user-supplied data is ever interpolated into the command.
    """
    if report_name not in ALLOWED_REPORTS:
        raise ValueError(
            f"Invalid report name '{report_name}'. "
            f"Allowed values: {sorted(ALLOWED_REPORTS)}"
        )
    result = subprocess.run(
        ["python", f"reports/{report_name}_report.py"],
        shell=False,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout


def read_file(filename: str) -> str:
    """
    Read and return the contents of *filename* from the safe files directory.

    CRITICAL-5 fix: os.path.realpath() resolves all symlinks and '..' segments.
    The resolved path must start with SAFE_BASE_DIR — any attempt to escape
    (e.g. '../../etc/passwd', absolute paths, Windows '..\') raises ValueError.
    """
    requested = os.path.realpath(os.path.join(SAFE_BASE_DIR, filename))
    if not requested.startswith(SAFE_BASE_DIR + os.sep) and requested != SAFE_BASE_DIR:
        raise ValueError(f"Access denied: '{filename}' is outside the allowed directory.")
    with open(requested, "r", encoding="utf-8") as fh:
        return fh.read()


def login(username: str, password: str, conn: sqlite3.Connection) -> bool:
    """
    Return True only when *username* exists AND *password* matches the stored hash.

    CRITICAL-6 fix: password hash is verified with PBKDF2-SHA256 +
    hmac.compare_digest (timing-safe). The username lookup uses a
    parameterized query to prevent SQL injection.
    """
    if not username or not password:
        return False
    cursor = conn.execute(
        "SELECT password_hash, salt FROM users WHERE username = ?", (username,)
    )
    row = cursor.fetchone()
    if row is None:
        return False
    stored_hash, stored_salt = row
    return verify_password(stored_hash, stored_salt, password)


def export_data(user_id: int, conn: sqlite3.Connection) -> Optional[tuple]:
    """
    Return the (id, username) row for *user_id*, or None if not found.

    CRITICAL-7 fix: user_id is passed as a query parameter, never concatenated.
    HIGH-1 fix: SSN and salary are NOT printed to stdout anywhere in this function.
    HIGH-2 fix: the connection is managed by the caller with a 'with' block.

    A TypeError is raised immediately if user_id is not an integer, preventing
    any attempt to pass injection payloads as the id argument.
    """
    if not isinstance(user_id, int):
        raise TypeError(
            f"user_id must be an integer, got {type(user_id).__name__!r}"
        )
    cursor = conn.execute(
        "SELECT id, username FROM users WHERE id = ?", (user_id,)
    )
    return cursor.fetchone()
