"""Regression tests for the SafeHarbor fixes. Each test asserts the safe behaviour."""
import os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as A


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        A.DB = os.path.join(self.tmp.name, "t.db")
        A.init_db()
        self.c = A.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def login(self, who):
        email, pw = {"alice": ("alice@example.com", "alice-pass"), "admin": ("admin@safeharbor.test", "admin-pass")}[who]
        return self.c.post("/login", data={"email": email, "password": pw})


class AuthTests(Base):
    def test_valid_login_works(self):
        self.assertEqual(self.login("alice").status_code, 302)

    def test_wrong_password_rejected(self):
        r = self.c.post("/login", data={"email": "alice@example.com", "password": "nope"})
        self.assertIn(b"Invalid email or password", r.data)

    def test_sql_metacharacters_in_email_do_not_authenticate(self):
        r = self.c.post("/login", data={"email": "alice@example.com' --", "password": "x"})
        self.assertIn(b"Invalid email or password", r.data)

    def test_passwords_stored_with_salted_hash(self):
        h = A.db().execute("SELECT password FROM users WHERE id=1").fetchone()[0]
        self.assertTrue(h.startswith(("scrypt:", "pbkdf2:")))

    def test_redirect_after_login_stays_on_site(self):
        for nxt in ("https://example.org", "//example.org", "javascript:alert(1)"):
            r = self.c.post("/login?next=" + nxt, data={"email": "alice@example.com", "password": "alice-pass"})
            self.assertEqual(r.headers["Location"], "/dashboard", nxt)
            self.c.get("/logout")


class AccessControlTests(Base):
    def test_role_cookie_does_not_grant_admin(self):
        self.login("alice"); self.c.set_cookie("role", "admin")
        self.assertEqual(self.c.get("/admin").status_code, 403)

    def test_real_admin_can_open_console(self):
        self.login("admin"); self.assertEqual(self.c.get("/admin").status_code, 200)

    def test_customer_cannot_open_other_policy(self):
        self.login("alice")
        self.assertEqual(self.c.get("/policy/1").status_code, 200)
        self.assertEqual(self.c.get("/policy/3").status_code, 404)

    def test_customer_cannot_file_claim_on_other_policy(self):
        self.login("alice")
        r = self.c.post("/claims", data={"policy_id": "3", "description": "x"})
        self.assertEqual(r.status_code, 404)

    def test_documents_limited_to_own_policies(self):
        self.login("alice")
        self.assertEqual(self.c.get("/documents/download?file=policy_1.txt").status_code, 200)
        self.assertEqual(self.c.get("/documents/download?file=policy_3.txt").status_code, 404)
        self.assertEqual(self.c.get("/documents/download?file=../app.py").status_code, 404)

    def test_anonymous_redirected_to_login(self):
        self.assertEqual(self.c.get("/dashboard").status_code, 302)


class InputHandlingTests(Base):
    def test_claim_text_is_escaped_on_output(self):
        self.login("alice")
        self.c.post("/claims", data={"policy_id": "1", "description": "<b>bold</b>"})
        page = self.c.get("/claims").data
        self.assertNotIn(b"<b>bold</b>", page)
        self.assertIn(b"&lt;b&gt;bold&lt;/b&gt;", page)

    def test_search_term_is_escaped(self):
        self.login("alice")
        page = self.c.get("/claims/search?q=<i>x</i>").data
        self.assertNotIn(b"<i>x</i>", page)

    def test_quote_calculator_does_arithmetic_only(self):
        self.login("alice")
        self.assertEqual(self.c.get("/api/quote?formula=1200*1.15").data, b"Estimated premium: $1380.0")
        self.assertEqual(self.c.get("/api/quote?formula=len('abc')").status_code, 400)

    def test_backup_label_is_validated(self):
        self.login("admin")
        self.assertEqual(self.c.get("/admin/backup?label=nightly").status_code, 200)
        self.assertEqual(self.c.get("/admin/backup?label=a b").status_code, 400)

    def test_rate_import_accepts_plain_yaml_only(self):
        self.login("admin")
        ok = self.c.post("/admin/import-rates", data={"data": "auto: 1.1"})
        self.assertEqual(ok.status_code, 200)
        bad = self.c.post("/admin/import-rates", data={"data": "!!python/name:os.getcwd"})
        self.assertEqual(bad.status_code, 400)

    def test_session_restore_takes_json_only(self):
        import base64, json
        self.login("alice")
        good = self.c.post("/api/session/restore", data=base64.b64encode(json.dumps({"a": 1}).encode()))
        self.assertEqual(good.status_code, 200)
        self.assertEqual(self.c.post("/api/session/restore", data=b"not-json").status_code, 400)


class HardeningTests(Base):
    def test_security_headers_present(self):
        h = self.c.get("/login").headers
        self.assertIn("default-src 'self'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")

    def test_debug_off_and_secrets_not_in_source(self):
        self.assertFalse(A.config.DEBUG)
        src = open(os.path.join(os.path.dirname(A.__file__), "config.py")).read()
        self.assertNotIn("sk_live", src)


if __name__ == "__main__":
    unittest.main()
