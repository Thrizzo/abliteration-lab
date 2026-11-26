"""deploy/n8n/connect_console.py waits until n8n can serve its REST API before it asks anything.

A starting n8n (2.48.7, seen on a fresh database) goes through three phases: while it migrates, every request gets
200 "n8n is starting up. Please wait" (GET /rest/settings included); then its routes are not registered yet and
POST /rest/owner/setup gets a plain 404; only then does GET /healthz/readiness answer 200. CI once checked
/rest/settings, saw the first 200 and got the 404 on the owner setup. The fake here plays those phases.

    python -m unittest discover -s app/tests
"""
import importlib.util
import io
import os
import threading
import time
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "..", "deploy", "n8n", "connect_console.py")
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
    ready. readiness=False: an n8n without /healthz/readiness (404 there), which moves on by /rest/settings polls."""

    def __init__(self, migrating=3, unrouted=3, readiness=True):
        self.polls, self.requests = 0, []
        self.migrating, self.unrouted, self.readiness = migrating, unrouted, readiness
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
                    return self._send(200, b'{"data":{"settingsMode":"public"}}')
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


if __name__ == "__main__":
    unittest.main()
