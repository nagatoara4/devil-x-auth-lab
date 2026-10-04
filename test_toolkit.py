import json
import tempfile
import unittest
from pathlib import Path

import toolkit


class ToolkitTests(unittest.TestCase):
    def test_password_policy_reports_checks_without_storing_input(self):
        result = toolkit.password_feedback("LongUnique!Phrase2026")
        self.assertTrue(result["checks"]["length_12_plus"])
        self.assertTrue(result["checks"]["symbol"])
        self.assertNotIn("password", result)

    def test_short_password_needs_improvement(self):
        self.assertEqual(toolkit.password_feedback("abc")["rating"], "weak")

    def test_only_loopback_urls_are_allowed(self):
        self.assertTrue(toolkit.is_loopback_url("http://127.0.0.1:8080/"))
        self.assertTrue(toolkit.is_loopback_url("http://localhost:8080/"))
        self.assertFalse(toolkit.is_loopback_url("https://example.com/"))
        self.assertFalse(toolkit.is_loopback_url("file:///etc/passwd"))

    def test_header_check_refuses_external_host_before_request(self):
        with self.assertRaises(ValueError):
            toolkit.check_local_headers("https://example.com/")

    def test_audit_summary(self):
        records = [
            {"event": "login_failure", "username": "labuser"},
            {"event": "login_success", "username": "labuser"},
            {"event": "login_failure", "username": "other"},
        ]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "audit.json"
            path.write_text(json.dumps(records), encoding="utf-8")
            summary = toolkit.summarize_audit(str(path))
        self.assertEqual(summary["records"], 3)
        self.assertEqual(summary["events"]["login_failure"], 2)
        self.assertEqual(summary["distinct_usernames"], 2)

    def test_audit_summary_rejects_non_array_json(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "audit.json"
            path.write_text('{"event":"login_failure"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                toolkit.summarize_audit(str(path))


if __name__ == "__main__":
    unittest.main()
