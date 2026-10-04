import unittest
import app

class AuthLabTests(unittest.TestCase):
    def setUp(self):
        with app._lock:
            app._attempts.clear()
            app._sessions.clear()
            app._audit.clear()

    def test_successful_login_creates_session(self):
        token = app.authenticate("labuser", "CorrectHorseBatteryStaple!", now=1000)
        self.assertIsInstance(token, str)
        self.assertTrue(app.valid_session(token, now=1001))

    def test_bad_password_fails(self):
        self.assertFalse(app.authenticate("labuser", "wrong-password", now=1000))

    def test_lockout_after_threshold(self):
        for i in range(app.MAX_FAILURES):
            app.authenticate("labuser", "wrong-password", now=1000 + i)
        self.assertTrue(app.is_locked("labuser", now=1005))
        self.assertFalse(app.authenticate("labuser", "CorrectHorseBatteryStaple!", now=1005))
        self.assertFalse(app.is_locked("labuser", now=1000 + app.LOCK_SECONDS + app.MAX_FAILURES + 2))

    def test_expired_session_is_invalid(self):
        token = app.authenticate("labuser", "CorrectHorseBatteryStaple!", now=1000)
        self.assertTrue(app.valid_session(token, now=1001))
        self.assertFalse(app.valid_session(token, now=3001))

    def test_audit_records_failures(self):
        app.authenticate("labuser", "wrong-password", now=1000)
        self.assertEqual(app._audit[-1]["event"], "login_failure")

if __name__ == "__main__":
    unittest.main()
