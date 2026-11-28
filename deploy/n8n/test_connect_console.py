"""deploy/n8n/connect_console.py waits until n8n can serve its REST API before it asks anything.

A starting n8n (2.48.7, seen on a fresh database) goes through three phases: while it migrates, every request gets
200 "n8n is starting up. Please wait" (GET /rest/settings included); then its routes are not registered yet and
POST /rest/owner/setup gets a plain 404; only then does GET /healthz/readiness answer 200. CI once checked
/rest/settings, saw the first 200 and got the 404 on the owner setup. The fake here plays those phases.

A fresh n8n's login is checked against n8n's rules for its owner account before the owner setup (an owner once ran
the whole Rancher setup to have n8n refuse a password without a digit at its end). owner_rule_cases.json holds n8n's own
answers; the same cases run through rancher-dev.ps1's copy of the rules in CI's k3s job.

    python -m unittest discover -s deploy/n8n          (CI runs it next to the node tests: deploy/ is not in the image)
"""
import importlib.util
import io
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "connect_console.py")
CASES = os.path.join(HERE, "owner_rule_cases.json")
_spec = importlib.util.spec_from_file_location("connect_console", SCRIPT)
CC = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(CC)

STARTING = b"n8n is starting up. Please wait"
NO_ROUTE = b"<!DOCTYPE html>\n<html lang=\"en\">\n<pre>Cannot POST /rest/owner/setup</pre>\n</html>\n"


class FastTime:
    """connect_console's clock with its 2 s polls cut short (only the script's own references are swapped)."""
    time = staticmethod(time.time)

    @staticmethod
    def sleep(seconds):
        time.sleep(min(seconds, 0.01))


class StartingN8n:
    """Readiness polls move it on: `migrating` polls in the migration phase, then `unrouted` polls without routes, then
    ready. readiness=False: an n8n without /healthz/readiness (404 there), which moves on by /rest/settings polls.
    user_management: what its public settings say about accounts once it is ready (n8n 2.48.7 says
    showSetupOnFirstLoad and passwordMinLength there); None leaves it out, as the fake always did."""

    def __init__(self, migrating=3, unrouted=3, readiness=True, user_management=None):
        self.polls, self.requests = 0, []
        self.migrating, self.unrouted, self.readiness = migrating, unrouted, readiness
        self.user_management = user_management
        srv = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body, ctype="application/json"):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                phase = srv.phase()
                srv.requests.append(("GET", self.path, phase))
                if self.path == "/healthz/readiness":
                    if not srv.readiness:
                        return self._send(404, b"Cannot GET /healthz/readiness", "text/html")
                    srv.polls += 1
                    return self._send(200, b'{"status":"ok"}') if phase == "ready" else self._send(503, b'{"status":"error"}')
                if self.path == "/rest/settings":
                    if not srv.readiness:
                        srv.polls += 1
                    if phase == "migrating":
                        return self._send(200, STARTING, "text/html")
                    if phase == "unrouted":
                        return self._send(404, b"Cannot GET /rest/settings", "text/html")
                    data = {"settingsMode": "public"}
                    if srv.user_management is not None:
                        data["userManagement"] = srv.user_management
                    return self._send(200, json.dumps({"data": data}).encode())
                self._send(404, b"", "text/html")

            def do_POST(self):
                phase = srv.phase()
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                srv.requests.append(("POST", self.path, phase))
                if phase == "migrating":
                    return self._send(200, STARTING, "text/html")
                if phase == "unrouted":
                    return self._send(404, NO_ROUTE, "text/html")
                self._send(400, b'{"message":"stop here: the test ends at the first real answer"}')

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def phase(self):
        if self.polls < self.migrating:
            return "migrating"
        return "unrouted" if self.polls < self.migrating + self.unrouted else "ready"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class WaitReady(unittest.TestCase):
    def fake(self, **kw):
        f = StartingN8n(**kw)
        self.addCleanup(f.close)
        return f

    def test_waits_through_migration_and_missing_routes(self):
        f = self.fake()
        said = []
        CC.N8n(f.url).wait_ready(timeout=10, every=0.01, log=said.append)
        self.assertEqual(f.phase(), "ready")
        self.assertEqual({p for _, _, p in f.requests}, {"migrating", "unrouted", "ready"})
        self.assertEqual(len(said), 1)
        self.assertIn("/healthz/readiness: 503", said[0])

    def test_an_n8n_without_the_readiness_endpoint_needs_the_settings_json(self):
        # the "starting up" 200 and the 404 are not ready; the settings' JSON is
        f = self.fake(readiness=False)
        CC.N8n(f.url).wait_ready(timeout=10, every=0.01, log=lambda *a: None)
        self.assertEqual(f.requests[-1], ("GET", "/rest/settings", "ready"))
        self.assertTrue(any(r == ("GET", "/rest/settings", "migrating") for r in f.requests))

    def test_gives_up_with_the_reason(self):
        f = self.fake(migrating=10 ** 6)
        with self.assertRaises(RuntimeError) as e:
            CC.N8n(f.url).wait_ready(timeout=0.3, every=0.05, log=lambda *a: None)
        self.assertIn("/healthz/readiness: 503", str(e.exception))

    def test_unreachable_is_waited_for_too(self):
        with self.assertRaises(RuntimeError) as e:
            CC.N8n("http://127.0.0.1:9").wait_ready(timeout=0.2, every=0.05, log=lambda *a: None)
        self.assertIn("unreachable", str(e.exception))

    def test_the_owner_setup_comes_only_after_readiness(self):
        # the CI failure: the owner setup reached n8n in its 404 phase. Now nothing is posted before n8n is ready, and
        # the first answer the script gets is the fake's real one (400 here, which ends the run)
        f = self.fake()
        with mock.patch.object(CC, "time", FastTime), redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError) as e:
            CC.main(["--n8n", f.url, "--email", "ci@lab.test", "--password", "x", "--setup-owner", "--wait", "10",
                     "--secret-file", os.devnull])
        posts = [r for r in f.requests if r[0] == "POST"]
        self.assertEqual(posts, [("POST", "/rest/owner/setup", "ready")])
        self.assertIn("HTTP 400", str(e.exception))
        self.assertNotIn("Cannot POST", str(e.exception))


class OwnerRule(unittest.TestCase):
    """The rules as n8n answers them: every case in owner_rule_cases.json came from n8n 2.48.7's own schema."""

    @classmethod
    def setUpClass(cls):
        with open(CASES, encoding="utf-8") as f:
            cls.cases = json.load(f)

    def test_passwords_as_n8n_answers_them(self):
        for c in self.cases["password"]:
            with self.subTest(password=c["password"], min=c["min"]):
                self.assertEqual(CC.password_problem(c["password"], c["min"]), c["problem"])

    def test_e_mail_addresses_as_n8n_answers_them(self):
        for c in self.cases["email"]:
            with self.subTest(email=c["email"]):
                self.assertEqual(CC.email_ok(c["email"]), c["ok"])

    def test_the_cases_cover_each_rule_both_ways(self):
        problems = " | ".join(c["problem"] for c in self.cases["password"])
        for part in ("8 to 64 characters (it has 3)", "(it has 65)", "10 to 64", "a number", "a capital letter"):
            self.assertIn(part, problems)
        self.assertIn("", [c["problem"] for c in self.cases["password"]])
        self.assertEqual({c["ok"] for c in self.cases["email"]}, {True, False})


class OwnerSetup(unittest.TestCase):
    """--setup-owner on a fresh n8n refuses a login n8n would refuse before it posts anything; an n8n that has its
    owner gets no owner setup and no check (the login is then just a login)."""

    def run_main(self, password, email="owner@lab.test", **user_management):
        f = StartingN8n(migrating=0, unrouted=0, user_management=user_management or None)
        self.addCleanup(f.close)
        with mock.patch.object(CC, "time", FastTime), redirect_stdout(io.StringIO()):
            try:
                CC.main(["--n8n", f.url, "--email", email, "--password", password, "--setup-owner", "--wait", "10",
                         "--secret-file", os.devnull])
            except (SystemExit, RuntimeError) as e:
                return f, e
        self.fail("main went through against a fake that refuses every POST")

    def posts(self, f):
        return [r[1] for r in f.requests if r[0] == "POST"]

    def test_a_password_without_a_number_is_refused_before_anything_is_posted(self):
        f, e = self.run_main("Abcdefgh", showSetupOnFirstLoad=True, passwordMinLength=8)
        self.assertIsInstance(e, SystemExit)
        self.assertIn("the password needs a number", str(e.code))
        self.assertIn("Nothing was created", str(e.code))
        self.assertEqual(self.posts(f), [])

    def test_n8n_s_own_minimum_length_counts(self):
        f, e = self.run_main("Abcdefgh1", showSetupOnFirstLoad=True, passwordMinLength=12)
        self.assertIn("12 to 64 characters (it has 9)", str(e.code))
        self.assertEqual(self.posts(f), [])

    def test_an_e_mail_n8n_would_refuse_too(self):
        f, e = self.run_main("Abcdefg1", email="owner@lab", showSetupOnFirstLoad=True)
        self.assertIn("the e-mail is not an address n8n takes", str(e.code))
        self.assertNotIn("password", str(e.code))
        self.assertEqual(self.posts(f), [])

    def test_a_login_n8n_takes_goes_on_to_the_owner_setup(self):
        f, e = self.run_main("Abcdefg1", showSetupOnFirstLoad=True, passwordMinLength=8)
        self.assertIsInstance(e, RuntimeError)            # the fake's 400 on the owner setup
        self.assertEqual(self.posts(f), ["/rest/owner/setup"])

    def test_an_n8n_with_its_owner_gets_the_login_only(self):
        # a real n8n 2.48.7 with an owner answers this owner setup with 400 "Password must be 8 to 64 characters long."
        # (it checks the form first), which hid that the login was simply wrong
        f, e = self.run_main("x", showSetupOnFirstLoad=False, passwordMinLength=8)
        self.assertIsInstance(e, RuntimeError)            # the fake's 400 on the login
        self.assertEqual(self.posts(f), ["/rest/login"])

    def test_settings_that_do_not_say_leave_it_to_n8n(self):
        f, e = self.run_main("x")                         # no userManagement, as older n8n versions answer
        self.assertIsInstance(e, RuntimeError)
        self.assertEqual(self.posts(f), ["/rest/owner/setup"])


class CommandLine(unittest.TestCase):
    """What the command prints: n8n's answer, or what to fix, never a traceback (rancher-dev.ps1 shows it as is)."""

    def run_script(self, password, **user_management):
        f = StartingN8n(migrating=0, unrouted=0, user_management=user_management or None)
        self.addCleanup(f.close)
        return subprocess.run([sys.executable, SCRIPT, "--n8n", f.url, "--email", "owner@lab.test", "--setup-owner",
                               "--wait", "10", "--secret-file", os.devnull], capture_output=True, text=True, timeout=60,
                              env={**os.environ, "N8N_PASSWORD": password})

    def test_n8n_s_refusal_without_a_traceback(self):
        r = self.run_script("x")
        self.assertEqual(r.returncode, 1)
        self.assertTrue(r.stderr.startswith("connect_console.py: POST /rest/owner/setup: HTTP 400"), r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_a_password_n8n_would_refuse(self):
        r = self.run_script("abcdefgh", showSetupOnFirstLoad=True, passwordMinLength=8)
        self.assertEqual(r.returncode, 1)
        self.assertIn("the password needs a number, a capital letter", r.stderr)
        self.assertNotIn("Traceback", r.stderr)


if __name__ == "__main__":
    unittest.main()
