import os, sys, unittest
sys.path.insert(0, os.path.dirname(__file__))
import redact as R

# Every value below is made up for the test (same shape as the real thing, never a real credential).
FAKE_NPM = "npm_FAKEfakeFAKEfake0123456789abcdefABCD"
FAKE_REG = "FAKE0000-1111-2222-3333-444455556666"
KEY_ID_PREFIX = "AKIA"
FAKE_AKIA = KEY_ID_PREFIX + "FAKE" * 4   # built at run time so no key-ID-shaped literal sits in the file
NPMRC = ("@ui:registry=https://npm.example.com/\n"
         f"//npm.example.com/:_authToken={FAKE_REG}\n"
         "@example:registry=https://example-000000000000.d.codeartifact.us-east-1.amazonaws.com/npm/private/\n"
         f"//example-000000000000.d.codeartifact.us-east-1.amazonaws.com/npm/private/:_authToken={FAKE_NPM}\n"
         "//example-000000000000.d.codeartifact.us-east-1.amazonaws.com/npm/private/:always-auth=true\n")

class TestFindSecrets(unittest.TestCase):
    def test_npmrc_two_tokens_no_values(self):
        s = R.find_secrets(NPMRC, "/.npmrc")
        self.assertEqual([x["type"] for x in s], ["npm registry token", "npm registry token"])
        self.assertEqual([x["line"] for x in s], [2, 4])
        self.assertNotIn(FAKE_NPM, repr(s)); self.assertNotIn(FAKE_REG, repr(s))

    def test_patterns(self):
        cases = {
            f"aws_access_key_id = {FAKE_AKIA}": "AWS access key id",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEfake\n-----END RSA PRIVATE KEY-----": "private key",
            "url = https://deploy:Fak3Pass42@git.example.test/repo.git": "password in URL",
            "Authorization: Bearer fakefakefakefakefake1234": "bearer token",
            "<add name='db' connectionString='Server=x;User Id=sa;Password=Fak3Pw!;' />": "password in connection string",
            "DB_PASSWORD=Fak3Passw0rd": "secret in config",
            "define('AUTH_KEY', 'Fake8Key9Value');": "secret in config",
            "key: AIzaFAKEfakeFAKEfakeFAKEfakeFAKEfake123": "Google API key",
            "slack: xoxb-0000-fake-fake": "Slack token",
        }
        for text, typ in cases.items():
            with self.subTest(typ=typ):
                self.assertEqual(R.find_secrets(text)[0]["type"], typ)

    def test_references_are_not_secrets(self):
        for text in ("password: ${DB_PASSWORD}", "API_KEY=$API_KEY", "token: << pipeline.parameters.token >>", "password_reset_url: /reset",
                     "token_ttl: 3600", "password: required", "<input type=\"password\" name=\"p\" class=\"edit\" />", "secret: '{{ vault }}'"):
            with self.subTest(text=text):
                self.assertEqual(R.find_secrets(text), [])

    def test_dependency_versions_and_switches_are_not_secrets(self):
        # false positives seen in practice: package-lock.json "jsonwebtoken": "^8.5.1" and phpinfo's tokenizer "enabled"
        for text in ('"jsonwebtoken": "^8.5.1",', '"passport-http-bearer": "1.0.1"', '"node_modules/js-tokens": "4.0.0"', "tokenizer = enabled",
                     '"auth0-js": "npm:auth0-js@9.0.0"'):
            with self.subTest(text=text):
                self.assertEqual(R.find_secrets(text), [])

    def test_secret_key(self):
        for k in ("DB_PASSWORD", "api-key", "clientSecret", "APP_KEY", "aws_secret_access_key", "TOKEN"):
            self.assertTrue(R.secret_key(k), k)
        for k in ("tokenizer", "passport", "author", "Tokenizer Support"):
            self.assertFalse(R.secret_key(k), k)

class TestRedact(unittest.TestCase):
    def test_values_replaced(self):
        out = R.redact(NPMRC + f"aws = {FAKE_AKIA}\ncard 4111 1111 1111 1111 call +14155550100\n")
        for v in (FAKE_NPM, FAKE_REG, FAKE_AKIA, "4111 1111 1111 1111", "+14155550100"):
            self.assertNotIn(v, out)
        self.assertIn("<REDACTED npm registry token>", out)
        self.assertIn("<REDACTED card>", out); self.assertIn("<REDACTED phone>", out)
        self.assertIn("npm.example.com", out)   # the registry name stays: it is where the token works

    def test_luhn(self):
        self.assertTrue(R.luhn_ok("4111111111111111"))
        self.assertFalse(R.luhn_ok("4111111111111112"))
        self.assertEqual(R.redact("order 1234567812345678"), "order 1234567812345678")

class TestClassify(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(R.classify(NPMRC, ".npmrc")[0], "credential")
        self.assertEqual(R.classify("<?php\n$db = 'x';\n", "a.php")[0], "source")
        self.assertEqual(R.classify("#!/bin/bash\nset -e\nnpm run build\n", "build.sh")[0], "source")
        self.assertEqual(R.classify("[core]\n\tbare = false\n", "config")[0], "config")
        self.assertEqual(R.classify("", "x")[0], "nothing")
        self.assertEqual(R.classify("<html><head><title>404 Not Found</title></head></html>", ".env")[0], "nothing")
        emails = "\n".join(f"user{i}@example.test" for i in range(25))
        self.assertEqual(R.classify(emails, "list.txt")[0], "data")
        self.assertEqual(R.classify("pan 4111 1111 1111 1111", "x.txt")[0], "data")

class TestHostnames(unittest.TestCase):
    """Hostname detection: a neutral built-in list of top-level domains, plus the scope's own domains when registered."""
    def tearDown(self):
        R.set_scope_suffixes([])

    def test_file_names_are_not_hostnames(self):
        for text in (".env.example", "settings.example", "app.test.js", "cp .env.example .env", "jest app.test.js"):
            self.assertEqual(R.internal_names(text), [], text)

    def test_builtin_top_level_domains(self):
        self.assertEqual(R.internal_names("db.internal, api.example.com and x.alpha.example"), ["db.internal", "api.example.com"])
        self.assertEqual(R.scope_suffixes(), ())

    def test_registered_suffix_only_on_a_label_boundary(self):
        R.set_scope_suffixes(["Alpha.Example.", "*.bravo.example"])
        self.assertEqual(R.scope_suffixes(), ("alpha.example", "bravo.example"))
        self.assertEqual(R.internal_names("www.alpha.example alpha.example a.b.bravo.example"),
                         ["www.alpha.example", "alpha.example", "a.b.bravo.example"])
        for text in ("notalpha.example", "x-alpha.example", "www.alpha.examples", "www.alpha.example-two", "alpha_example",
                     ".env.example", "settings.example"):
            self.assertEqual(R.internal_names(text), [], text)

    def test_registered_suffix_with_a_builtin_tld_keeps_the_longer_name(self):
        R.set_scope_suffixes(["alpha.example"])
        self.assertEqual(R.internal_names("x.alpha.example.org"), ["x.alpha.example.org"])

    def test_clear_and_invalid(self):
        R.set_scope_suffixes(["alpha.example"])
        R.set_scope_suffixes([])
        self.assertEqual(R.internal_names("www.alpha.example"), [])
        with self.assertRaises(ValueError):
            R.set_scope_suffixes(["bad suffix"])
        self.assertEqual(R.scope_suffixes(), ())


class TestGaps(unittest.TestCase):
    """The known gaps, each with an obviously fake value assembled at run time."""
    JWT = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiJmYWtlLXVzZXIifQ" + ".ZmFrZS1zaWduYXR1cmUtbm90LXJlYWw"
    PW = "correct" + "horse" + "fake"                      # a lowercase password
    B64 = "ZmFrZXVzZXI6" + "ZmFrZXBhc3M="                  # base64 of a made-up user:pass

    def gone(self, text, *values):
        out = R.redact(text)
        for v in values:
            self.assertNotIn(v, out, text)
        return out

    def test_lowercase_value_under_a_secret_key(self):
        for text in (f"DB_PASSWORD={self.PW}", f"password: {self.PW}", f'"api_key": "{self.PW}"', f"[db]\npassword = {self.PW}\n",
                     f"secret_key: {self.PW}-two"):
            with self.subTest(text=text):
                self.assertTrue(R.find_secrets(text), text)
                self.gone(text, self.PW)
        # still not a secret: a lowercase word under a key that only contains a keyword, and placeholders
        for text in ("passport_strategy: local", "password: required", "token: changeme", "tokenizer = enabled"):
            with self.subTest(text=text):
                self.assertEqual(R.find_secrets(text), [], text)

    def test_jwt(self):
        out = self.gone(f"session: {self.JWT}", self.JWT)
        s = R.find_secrets(f"x {self.JWT} y")
        self.assertEqual(s[0]["type"], "JSON Web Token")
        self.assertEqual(s[0]["masked"], f"eyJ...[{len(self.JWT)} chars]")
        self.assertIn("<REDACTED", out)

    def test_authorization_headers(self):
        for text, typ in ((f"Authorization: Basic {self.B64}", "basic auth"), ("Authorization: Bearer fakefakefakefake1234", "bearer token"),
                          ('Authorization: Digest username="u", response="fakefakefake"', "authorization header"),
                          ("authorization: AWS4-HMAC-SHA256 Credential=FAKE/20300101/x, Signature=fake0fake1", "authorization header"),
                          (f'{{"Authorization": "Basic {self.B64}"}}', "basic auth"), ("Proxy-Authorization: fakeopaquetoken", "authorization header")):
            with self.subTest(text=text):
                self.assertEqual(R.find_secrets(text)[0]["type"], typ)
                out = R.redact(text)
                self.assertNotIn(self.B64, out); self.assertNotIn("fakefake", out); self.assertNotIn("fakeopaque", out)

    def test_cookies_keep_names(self):
        text = "Set-Cookie: SESSIONX=fakeSess10nValue; Path=/; HttpOnly\r\nCookie: a=fakeA1value; theme=dark\r\n"
        out = self.gone(text, "fakeSess10nValue", "fakeA1value", "dark")
        for name in ("SESSIONX=", "a=", "theme=", "Path=/", "HttpOnly"):
            self.assertIn(name, out)
        self.gone(f'"set-cookie": "sid=fakeCookieValue9; Secure"', "fakeCookieValue9")
        self.gone("var x = 'PHPSESSID=fakephpsessvalue1';", "fakephpsessvalue1")

    def test_signed_url_parameters(self):
        key_id = "AKIA" + "FAKE" * 4
        urls = [f"https://bucket.s3.amazonaws.com/f.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={key_id}%2F20300101&X-Amz-Signature=fakesig0123&X-Amz-Security-Token=fakeTok",
                f"https://bucket.s3.amazonaws.com/f.pdf?AWSAccessKeyId={key_id}&Expires=1900000000&Signature=fakeSig%2Bvalue",
                "https://storage.googleapis.com/b/o?X-Goog-Credential=fake%40example.iam&X-Goog-Signature=fakegoogsig",
                "https://storage.googleapis.com/b/o?GoogleAccessId=fake@example.iam&Signature=fakeGcsSig",
                "https://acct.blob.core.windows.net/c/b?sv=2030-01-01&se=2030-01-02&sp=r&sig=fakeAzureSig%3D",
                "https://d111.cloudfront.net/x?Policy=fakePolicyB64&Signature=fakeCfSig&Key-Pair-Id=FAKEKEYPAIR"]
        secrets = (key_id, "fakesig0123", "fakeTok", "fakeSig", "fakegoogsig", "fake%40example", "fake@example", "fakeGcsSig",
                   "fakeAzureSig", "fakePolicyB64", "fakeCfSig", "FAKEKEYPAIR")
        for u in urls:
            with self.subTest(url=u):
                for fn in (R.redact, R.redact_url):
                    out = fn(u)
                    for v in secrets:
                        self.assertNotIn(v, out)
                self.assertTrue(R.redact_url(u).startswith(u.split("?")[0] + "?"))
        self.assertIn("se=2030-01-02", R.redact_url(urls[4]))   # an expiry is not a secret

    def test_redact_url(self):
        self.assertEqual(R.redact_url("https://deploy:FakePw1@git.example.test/a?b=1"), "https://git.example.test/a?b=1")
        self.assertEqual(R.redact_url("https://a.example.test/cb?code=fakecode&state=x#access_token=fakeat&type=t"),
                         "https://a.example.test/cb?code=REDACTED&state=x#access_token=REDACTED&type=t")
        self.assertEqual(R.redact_url("https://a.example.test/app;jsessionid=FAKE123?x=1"), "https://a.example.test/app;jsessionid=REDACTED?x=1")
        nested = R.redact_url("https://a.example.test/login?next=https%3A%2F%2Fb.example.test%2Fx%3Ftoken%3Dfakenested")
        self.assertNotIn("fakenested", nested); self.assertIn("b.example.test", nested)
        self.assertEqual(R.redact_url("/reset?password=fakepw&lang=en"), "/reset?password=REDACTED&lang=en")
        self.assertIsNone(R.redact_url(None)); self.assertEqual(R.redact_url(""), "")

    def test_private_key_blocks(self):
        for head in ("RSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY", "PGP PRIVATE KEY BLOCK"):
            body = "MIIfakeKEYmaterial0001"
            text = f"-----BEGIN {head}-----\n{body}\n-----END {head}-----"
            with self.subTest(head=head):
                self.gone(text, body)
                self.gone(json_escaped := text.replace("\n", "\\n"), body)
                self.assertTrue(json_escaped)

    def test_structured_text_forms(self):
        pw = self.PW
        cases = [f'{{"db": {{"password": "{pw}"}}}}',                                # JSON
                 "{\"cfg\": \"{\\\"password\\\": \\\"" + pw + "\\\"}\"}",          # JSON inside a JSON string (escaped quotes)
                 "{\\\"client_secret\\\":\\\"" + pw + "\\\"}",                     # escaped quotes on their own
                 f"db:\n  password: {pw}\n",                                       # YAML
                 f"DB_PASSWORD={pw}\nAPP_ENV=production\n",                         # .env
                 f"[mysql]\nuser = app\npassword = {pw}\n",                         # INI
                 f"export SECRET_KEY='{pw}'"]
        for text in cases:
            with self.subTest(text=text):
                self.gone(text, pw)
        self.assertIn("APP_ENV=production", R.redact(cases[4]))

    def test_redact_text_and_mask(self):
        out = R.redact_text("see https://u:FakePw1@a.example.test/?token=faketok and mail ops@corp.example.test", strict=True)
        for v in ("FakePw1", "faketok", "ops@"):
            self.assertNotIn(v, out)
        self.assertIn("<email at corp.example.test>", out)
        rnd = "Fq3x" + "9ZkLp2" + "Vw8Rt6" + "Yb1Nm4" + "Hc7Js5"   # a made-up random-looking token
        self.assertNotIn(rnd, R.redact_text(f"value {rnd} end", strict=True))
        self.assertIn(rnd, R.redact_text(f"value {rnd} end"))          # only strict masks bare random tokens
        self.assertIn("application/x-www-form-urlencoded", R.redact_text("application/x-www-form-urlencoded", strict=True))
        self.assertEqual(len(R.redact_text("x" * 50 + " DB_PASSWORD=" + self.PW, cap=60)), 60)
        self.assertNotIn(self.PW[:8], R.redact_text("x" * 50 + " DB_PASSWORD=" + self.PW, cap=70))   # cut after redaction
        self.assertEqual(R.mask("AKIA" + "FAKE" * 4), "AKIA...[20 chars]")
        self.assertEqual(R.mask(self.PW), f"...[{len(self.PW)} chars]")
        self.assertEqual(R.email_summary(["a@x.example", "B@X.example", "c@y.example"]), {"count": 3, "domains": ["x.example", "y.example"]})

    def test_docstring_says_best_effort(self):
        self.assertIn("best-effort", R.__doc__)
        self.assertIn("minimization", R.__doc__)


if __name__ == "__main__":
    unittest.main()
