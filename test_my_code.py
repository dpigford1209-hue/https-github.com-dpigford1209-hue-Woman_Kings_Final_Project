"""
test_my_code.py
IBM Final Project — Security Regression Tests
Authors: Tashare Hamilton, D'Nisha Pigford

35 tests across 6 classes.  Run with:
    python test_my_code.py

No third-party packages required.  All databases are in-memory SQLite.
subprocess.run is mocked so no shell scripts need to exist.
"""

import os
import sqlite3
import sys
import unittest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Set test environment variables BEFORE importing the module under test so
# that the startup guards (CRITICAL-1, CRITICAL-2) do not call sys.exit().
# ---------------------------------------------------------------------------
os.environ["DB_PASSWORD"] = "test_db_password"
os.environ["API_KEY"] = "test_api_key_12345"
os.environ["_TESTING"] = "1"

import scenario1_vulnerable_app_fixed as app  # noqa: E402


# ---------------------------------------------------------------------------
# Shared helper — build a fresh in-memory DB with one test user
# ---------------------------------------------------------------------------

def _make_db(username="alice", password="correct_password"):
    """Return an open in-memory sqlite3 connection pre-loaded with one user."""
    conn = sqlite3.connect(":memory:")
    app._init_db(conn)
    salt_hex, hash_hex = app.hash_password(password)
    conn.execute(
        "INSERT INTO users (username, password_hash, salt, ssn, salary) "
        "VALUES (?, ?, ?, ?, ?)",
        (username, hash_hex, salt_hex, "123-45-6789", 75000.00),
    )
    conn.commit()
    return conn


# ===========================================================================
# TestGetUser — 5 tests (CRITICAL-3)
# ===========================================================================

class TestGetUser(unittest.TestCase):

    def setUp(self):
        self.conn = _make_db()

    def tearDown(self):
        self.conn.close()

    def test_legitimate_user_returned(self):
        """A real username returns the correct row."""
        row = app.get_user("alice", self.conn)
        self.assertIsNotNone(row)
        self.assertEqual(row[1], "alice")

    def test_unknown_user_returns_none(self):
        """An unknown username returns None, not an error."""
        row = app.get_user("nobody", self.conn)
        self.assertIsNone(row)

    def test_sql_injection_or_1_equals_1(self):
        """Classic OR-injection payload must not return any row."""
        row = app.get_user("' OR '1'='1", self.conn)
        self.assertIsNone(row)

    def test_sql_injection_drop_table(self):
        """DROP TABLE payload must not destroy the table."""
        app.get_user("'; DROP TABLE users; --", self.conn)
        # Table must still be queryable
        cursor = self.conn.execute("SELECT COUNT(*) FROM users")
        self.assertEqual(cursor.fetchone()[0], 1)

    def test_sql_injection_union_select(self):
        """UNION SELECT payload must not leak extra rows."""
        row = app.get_user("' UNION SELECT 1, 'evil' --", self.conn)
        self.assertIsNone(row)


# ===========================================================================
# TestRunReport — 8 tests (CRITICAL-4)
# ===========================================================================

MOCK_COMPLETED = MagicMock()
MOCK_COMPLETED.stdout = "report output"


class TestRunReport(unittest.TestCase):

    @patch("scenario1_vulnerable_app_fixed.subprocess.run", return_value=MOCK_COMPLETED)
    def test_allowed_daily(self, mock_run):
        """'daily' is on the allowlist — should succeed."""
        result = app.run_report("daily")
        self.assertEqual(result, "report output")
        mock_run.assert_called_once()

    @patch("scenario1_vulnerable_app_fixed.subprocess.run", return_value=MOCK_COMPLETED)
    def test_allowed_weekly(self, mock_run):
        """'weekly' is on the allowlist — should succeed."""
        app.run_report("weekly")
        mock_run.assert_called_once()

    @patch("scenario1_vulnerable_app_fixed.subprocess.run", return_value=MOCK_COMPLETED)
    def test_allowed_monthly(self, mock_run):
        """'monthly' is on the allowlist — should succeed."""
        app.run_report("monthly")
        mock_run.assert_called_once()

    @patch("scenario1_vulnerable_app_fixed.subprocess.run", return_value=MOCK_COMPLETED)
    def test_allowed_summary(self, mock_run):
        """'summary' is on the allowlist — should succeed."""
        app.run_report("summary")
        mock_run.assert_called_once()

    def test_disallowed_name_raises(self):
        """An arbitrary name not on the allowlist must raise ValueError."""
        with self.assertRaises(ValueError):
            app.run_report("../../etc/passwd")

    def test_injection_semicolon_raises(self):
        """Shell meta-characters in report name must raise ValueError."""
        with self.assertRaises(ValueError):
            app.run_report("daily; rm -rf /")

    def test_empty_name_raises(self):
        """An empty string must raise ValueError."""
        with self.assertRaises(ValueError):
            app.run_report("")

    @patch("scenario1_vulnerable_app_fixed.subprocess.run", return_value=MOCK_COMPLETED)
    def test_shell_false_enforced(self, mock_run):
        """subprocess.run must always be called with shell=False."""
        app.run_report("daily")
        call_kwargs = mock_run.call_args.kwargs
        # shell must be explicitly set to False (not omitted, not True)
        self.assertIn("shell", call_kwargs, "shell keyword argument was not passed")
        self.assertFalse(call_kwargs["shell"], "subprocess.run was called with shell=True")


# ===========================================================================
# TestReadFile — 6 tests (CRITICAL-5)
# ===========================================================================

class TestReadFile(unittest.TestCase):

    def test_path_traversal_dotdot_slash(self):
        """'../../etc/passwd' must be blocked."""
        with self.assertRaises((ValueError, FileNotFoundError)):
            app.read_file("../../etc/passwd")

    def test_path_traversal_single_dotdot(self):
        """'../secret.txt' must be blocked."""
        with self.assertRaises((ValueError, FileNotFoundError)):
            app.read_file("../secret.txt")

    def test_path_traversal_windows_backslash(self):
        r"""'..\secret.txt' (Windows style) must be blocked."""
        with self.assertRaises((ValueError, FileNotFoundError)):
            app.read_file(r"..\secret.txt")

    def test_absolute_path_blocked(self):
        """An absolute path like /etc/passwd must be blocked."""
        with self.assertRaises((ValueError, FileNotFoundError)):
            app.read_file("/etc/passwd")

    def test_absolute_windows_path_blocked(self):
        """A Windows absolute path like C:\\Windows\\system.ini must be blocked."""
        with self.assertRaises((ValueError, FileNotFoundError)):
            app.read_file("C:\\Windows\\system.ini")

    def test_nonexistent_safe_file_raises_file_not_found(self):
        """A simple filename that doesn't exist raises FileNotFoundError, not ValueError."""
        # This confirms path validation passes but the file is simply missing.
        with self.assertRaises(FileNotFoundError):
            app.read_file("nonexistent_safe_file.txt")


# ===========================================================================
# TestLogin — 6 tests (CRITICAL-6)
# ===========================================================================

class TestLogin(unittest.TestCase):

    def setUp(self):
        self.conn = _make_db(username="alice", password="correct_password")

    def tearDown(self):
        self.conn.close()

    def test_correct_credentials_accepted(self):
        """Valid username + correct password must return True."""
        self.assertTrue(app.login("alice", "correct_password", self.conn))

    def test_wrong_password_rejected(self):
        """Valid username + wrong password must return False."""
        self.assertFalse(app.login("alice", "wrong_password", self.conn))

    def test_empty_password_rejected(self):
        """Empty-string password must return False."""
        self.assertFalse(app.login("alice", "", self.conn))

    def test_none_password_rejected(self):
        """None password must return False without raising."""
        self.assertFalse(app.login("alice", None, self.conn))

    def test_unknown_user_rejected(self):
        """Non-existent username must return False."""
        self.assertFalse(app.login("nobody", "correct_password", self.conn))

    def test_sql_injection_in_username_rejected(self):
        """SQL injection in username field must return False, not bypass auth."""
        self.assertFalse(app.login("' OR '1'='1' --", "anything", self.conn))


# ===========================================================================
# TestExportData — 4 tests (CRITICAL-7, HIGH-1)
# ===========================================================================

class TestExportData(unittest.TestCase):

    def setUp(self):
        self.conn = _make_db()
        # Retrieve the auto-assigned id for alice
        cursor = self.conn.execute("SELECT id FROM users WHERE username='alice'")
        self.alice_id = cursor.fetchone()[0]

    def tearDown(self):
        self.conn.close()

    def test_valid_id_returns_row(self):
        """A known user id returns the correct (id, username) tuple."""
        row = app.export_data(self.alice_id, self.conn)
        self.assertIsNotNone(row)
        self.assertEqual(row[1], "alice")

    def test_unknown_id_returns_none(self):
        """An id that doesn't exist returns None."""
        row = app.export_data(99999, self.conn)
        self.assertIsNone(row)

    def test_injection_payload_returns_none(self):
        """Passing a non-integer should raise TypeError (not bypass the query)."""
        with self.assertRaises((TypeError, ValueError)):
            app.export_data("1 OR 1=1", self.conn)

    def test_no_pii_printed_to_stdout(self, ):
        """export_data must not print SSN or salary to stdout (HIGH-1 fix)."""
        import io
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            app.export_data(self.alice_id, self.conn)
        finally:
            sys.stdout = old_stdout
        output = captured.getvalue()
        self.assertNotIn("123-45-6789", output)
        self.assertNotIn("75000", output)


# ===========================================================================
# TestVerifyPassword — 6 tests
# ===========================================================================

class TestVerifyPassword(unittest.TestCase):

    def setUp(self):
        self.salt_hex, self.hash_hex = app.hash_password("secret123")

    def test_correct_password_returns_true(self):
        """The correct password verifies successfully."""
        self.assertTrue(
            app.verify_password(self.hash_hex, self.salt_hex, "secret123")
        )

    def test_wrong_password_returns_false(self):
        """An incorrect password returns False."""
        self.assertFalse(
            app.verify_password(self.hash_hex, self.salt_hex, "wrongpassword")
        )

    def test_empty_password_returns_false(self):
        """An empty password string returns False without raising."""
        self.assertFalse(
            app.verify_password(self.hash_hex, self.salt_hex, "")
        )

    def test_none_password_returns_false(self):
        """None as the provided password returns False without raising."""
        self.assertFalse(
            app.verify_password(self.hash_hex, self.salt_hex, None)
        )

    def test_malformed_hash_returns_false(self):
        """A non-hex stored hash returns False instead of raising ValueError."""
        self.assertFalse(
            app.verify_password("not_valid_hex!", self.salt_hex, "secret123")
        )

    def test_malformed_salt_returns_false(self):
        """A non-hex stored salt returns False instead of raising ValueError."""
        self.assertFalse(
            app.verify_password(self.hash_hex, "not_valid_hex!", "secret123")
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
