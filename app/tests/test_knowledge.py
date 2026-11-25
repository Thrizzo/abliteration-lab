"""Knowledge uploads (app/knowledge.py): preview, upload + background ingest, list with chunk counts, delete.

Qdrant is a fake (the HTTP calls copilot.ingest makes: collection info, payload index, upsert, filter delete, scroll);
the embeddings come from the model stand-in. PDF cases need pypdf (in the app image) and skip without it.

    python -m unittest discover -s app/tests
"""
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", ".."))
import copilot_runs  # noqa: E402
import k8sjobs  # noqa: E402
import knowledge as KN  # noqa: E402
import model_standin  # noqa: E402
from copilot.tests.pdf_fixture import make_pdf  # noqa: E402

try:
    import pypdf  # noqa: F401
    HAVE_PYPDF = True
except ImportError:
    HAVE_PYPDF = False


class HTTPError(Exception):
    def __init__(self, status, msg):
        super().__init__(f"{status} {msg}")
        self.status, self.msg = status, msg


class FakeQdrant:
    """Just the Qdrant API copilot.ingest uses, with real paging on scroll."""

    def __init__(self):
        self.collections, self.indexes, self.down = {}, [], False
        srv = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj):
                raw = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _handle(self, method):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if n else {}
                if srv.down:
                    return self._send(500, {"status": {"error": "storage unavailable"}})
                parts = urllib.parse.urlsplit(self.path).path.strip("/").split("/")     # collections/<c>[/...]
                c, rest = parts[1], "/".join(parts[2:])
                col = srv.collections.get(c)
                if rest == "" and method == "GET":
                    return self._send(200, {"result": {"config": {"params": {"vectors": {"size": col["size"], "distance": "Cosine"}}}}}) \
                        if col else self._send(404, {"status": {"error": f"Collection `{c}` doesn't exist!"}})
                if rest == "" and method == "PUT":
                    srv.collections[c] = {"size": body["vectors"]["size"], "points": {}}
                    return self._send(200, {"result": True})
                if col is None:
                    return self._send(404, {"status": {"error": f"Collection `{c}` doesn't exist!"}})
                if rest == "index":
                    srv.indexes.append((c, body["field_name"], body["field_schema"]))
                    return self._send(200, {"result": {"status": "acknowledged"}})
                if rest == "points" and method == "PUT":
                    for p in body["points"]:
                        col["points"][p["id"]] = p
                    return self._send(200, {"result": {"status": "completed"}})
                if rest == "points/delete":
                    want = body["filter"]["must"][0]["match"]["value"]
                    col["points"] = {k: v for k, v in col["points"].items() if v["payload"]["metadata"]["doc"] != want}
                    return self._send(200, {"result": {"status": "completed"}})
                if rest == "points/scroll":
                    ids = sorted(col["points"])
                    start = ids.index(body["offset"]) if body.get("offset") in ids else 0
                    page = ids[start:start + body["limit"]]
                    nxt = ids[start + body["limit"]] if start + body["limit"] < len(ids) else None
                    return self._send(200, {"result": {"points": [{"id": i, "payload": col["points"][i]["payload"]} for i in page],
                                                       "next_page_offset": nxt}})
                return self._send(404, {"status": {"error": "unknown"}})

            def do_GET(self):
                self._handle("GET")

            def do_PUT(self):
                self._handle("PUT")

            def do_POST(self):
                self._handle("POST")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def docs(self, c="writeups"):
        out = {}
        for p in (self.collections.get(c) or {}).get("points", {}).values():
            d = p["payload"]["metadata"]["doc"]
            out[d] = out.get(d, 0) + 1
        return out

    def content(self, doc, c="writeups"):
        return " ".join(p["payload"]["content"] for p in self.collections[c]["points"].values() if p["payload"]["metadata"]["doc"] == doc)

    def close(self):
        self.httpd.shutdown()


WRITEUP = "# Lame\n\n" + "\n\n".join(f"## Step {i}\n" + ("Enumerate SMB with smbclient -N -L and check the Samba version. " * 25)
                                      for i in range(4))
NOTES = "# Client notes\n\nDomain admin is jane.doe@client-corp.com, she logged in from 10.20.30.40.\nPassword: Summer2026!\n"


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.emb = ThreadingHTTPServer(("127.0.0.1", 0), model_standin.H)
        threading.Thread(target=cls.emb.serve_forever, daemon=True).start()
        cls.emb_url = f"http://127.0.0.1:{cls.emb.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.emb.shutdown()

    def setUp(self):
        self.project = tempfile.mkdtemp()
        self.q = FakeQdrant()
        self.feed = copilot_runs.Feed()
        self.audit = k8sjobs.Audit(self.project, feed=self.feed)
        self.kn = KN.Knowledge(self.project, self.q.url, "writeups", self.emb_url, "nomic-embed-text", self.feed, self.audit,
                               http_error=HTTPError, chunk_chars=600)

    def tearDown(self):
        self.q.close()
        shutil.rmtree(self.project, ignore_errors=True)

    def wait(self, doc, t=10):
        t0 = time.time()
        while time.time() - t0 < t:
            d = next((x for x in self.kn.list()["docs"] if x["doc"] == doc), None)
            if d and d["status"] in ("indexed", "error", "not indexed"):
                return d
            time.sleep(0.02)
        self.fail(f"{doc} still {d and d['status']}")

    def expect(self, status, fn, *a):
        with self.assertRaises(HTTPError) as e:
            fn(*a)
        self.assertEqual(e.exception.status, status, e.exception.msg)
        return e.exception.msg


class TestNames(unittest.TestCase):
    def test_safe_name(self):
        self.assertEqual(KN.safe_name("../../etc/passwd.md"), "passwd.md")
        self.assertEqual(KN.safe_name("C:\\Users\\me\\HTB Lame (retired).PDF"), "HTB-Lame-retired.pdf")
        self.assertEqual(KN.safe_name("ｗｒｉｔｅｕｐ.md"), "writeup.md")                    # full-width letters, NFKC
        self.assertEqual(len(KN.safe_name("a" * 300 + ".txt")), 104)
        for bad in ("evil.exe", "noext", ".md", "../..", "x.pdf.sh"):
            with self.assertRaises(ValueError):
                KN.safe_name(bad)


class TestKnowledge(Base):
    def test_upload_ingest_list_reupload_delete(self):
        out = self.kn.upload("htb", "Lame.md", WRITEUP.encode(), {"user": "admin"})
        self.assertEqual((out["doc"], out["status"]), ("htb/Lame.md", "queued"))
        d = self.wait("htb/Lame.md")
        self.assertEqual(d["status"], "indexed", d)
        n = d["chunks"]
        self.assertGreater(n, 1)
        self.assertEqual(self.q.docs(), {"htb/Lame.md": n})
        self.assertTrue(os.path.isfile(os.path.join(self.project, "writeups", "htb", "Lame.md")))
        self.assertEqual((d["title"], d["source"], d["file"]), ("Lame", "htb", True))
        self.assertIn(("writeups", "metadata.doc", "keyword"), self.q.indexes)          # deletes don't scan
        self.kn.upload("htb", "Lame.md", WRITEUP.encode(), {"user": "admin"})          # again: replaced, not doubled
        self.assertEqual(self.wait("htb/Lame.md")["chunks"], n)
        self.assertEqual(self.q.docs(), {"htb/Lame.md": n})
        self.kn.delete("htb/Lame.md", {"user": "admin"})
        self.assertEqual(self.q.docs(), {})
        self.assertFalse(os.path.exists(os.path.join(self.project, "writeups", "htb", "Lame.md")))
        self.assertEqual(self.kn.list()["docs"], [])
        audit = [(r["stage"], r["who"].get("user")) for r in reversed(self.audit.recent(10))]
        self.assertEqual(audit, [("upload", "admin"), ("ingest", "admin"), ("upload", "admin"), ("ingest", "admin"), ("delete", "admin")])
        self.assertTrue(all(e["source"] == "knowledge" for e in self.feed.since(0)["events"]))

    def test_engagement_preview_shows_the_redactions_and_stores_nothing(self):
        p = self.kn.preview("engagement", "notes.md", NOTES.encode())
        self.assertTrue(p["redactions"], p)
        self.assertNotIn("jane.doe@client-corp.com", p["scrubbed"])
        self.assertNotIn("Summer2026!", p["scrubbed"])
        self.assertEqual(p["chunks"], 1)
        self.assertIsNone(self.kn.preview("htb", "Lame.md", WRITEUP.encode())["scrubbed"])   # only engagement notes
        self.assertFalse(os.path.exists(os.path.join(self.project, "writeups")))
        self.assertEqual(self.q.collections, {})

    def test_engagement_upload_is_scrubbed_in_the_store(self):
        self.kn.upload("engagement", "notes.md", NOTES.encode())
        self.assertEqual(self.wait("engagement/notes.md")["status"], "indexed")
        stored = self.q.content("engagement/notes.md")
        self.assertNotIn("jane.doe@client-corp.com", stored)
        self.assertNotIn("Summer2026!", stored)

    def test_refusals(self):
        self.expect(400, self.kn.upload, "secrets", "x.md", b"x")
        self.expect(400, self.kn.upload, "htb", "x.exe", b"x")
        self.expect(400, self.kn.upload, "htb", "x.md", b"")
        old, KN.MAX_BYTES = KN.MAX_BYTES, 10
        try:
            self.expect(413, self.kn.upload, "htb", "x.md", b"x" * 11)
        finally:
            KN.MAX_BYTES = old
        self.expect(422, self.kn.upload, "htb", "blank.md", b"   \n\n ")
        for rel in ("../app/server.py", "htb/../../x.md", "/etc/passwd", "htb\\x.md", "", "htb//x.md"):
            self.expect(400, self.kn.delete, rel)
        self.assertEqual(self.audit.recent(5), [])                                           # nothing happened

    def test_vectors_without_a_file_are_listed_and_deletable(self):
        self.kn.upload("blog", "post.md", WRITEUP.encode())
        self.wait("blog/post.md")
        os.remove(os.path.join(self.project, "writeups", "blog", "post.md"))                   # e.g. ingested by the CLI elsewhere
        d = next(x for x in self.kn.list()["docs"] if x["doc"] == "blog/post.md")
        self.assertEqual((d["file"], d["status"]), (False, "indexed"))
        self.assertEqual(self.kn.delete("blog/post.md")["file"], False)
        self.assertEqual(self.q.docs(), {})

    def test_store_down(self):
        self.q.down = True
        self.kn.upload("htb", "Lame.md", WRITEUP.encode())                                     # stored; ingest fails visibly
        d = self.wait("htb/Lame.md")
        self.assertEqual(d["status"], "error")
        self.assertIn("storage unavailable", d["error"])
        self.assertIn("storage unavailable", self.kn.list()["qdrant_error"])
        self.assertEqual(self.audit.recent(1)[0]["level"], "error")
        self.expect(502, self.kn.delete, "htb/Lame.md")                                        # nothing removed then
        self.assertTrue(os.path.isfile(os.path.join(self.project, "writeups", "htb", "Lame.md")))

    def test_not_configured(self):
        kn = KN.Knowledge(self.project, None, "writeups", None, "m", http_error=HTTPError)
        self.assertFalse(kn.list()["configured"])
        self.expect(409, kn.upload, "htb", "x.md", b"text")


@unittest.skipUnless(HAVE_PYPDF, "pypdf is not installed here (it is in the app image)")
class TestPdfUploads(Base):
    def test_pdf_text_is_ingested(self):
        pdf = make_pdf([["Lame (retired)", "smbclient -N -L //target lists the shares"], ["Samba 3.0.20: usermap_script"]])
        self.assertGreater(self.kn.preview("htb", "lame.pdf", pdf)["chars"], 40)
        self.kn.upload("htb", "lame.pdf", pdf)
        self.assertEqual(self.wait("htb/lame.pdf")["status"], "indexed")
        self.assertIn("usermap_script", self.q.content("htb/lame.pdf"))

    def test_scanned_pdf_is_refused_before_anything_is_stored(self):
        msg = self.expect(422, self.kn.upload, "htb", "scan.pdf", make_pdf([[]]))
        self.assertIn("no text layer", msg)
        self.assertFalse(os.path.exists(os.path.join(self.project, "writeups", "htb", "scan.pdf")))
        self.assertEqual(self.q.collections, {})


if __name__ == "__main__":
    unittest.main()
