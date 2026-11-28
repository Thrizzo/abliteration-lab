"""PDF text for retrieval (copilot/pdftext.py through sources.read_pdf, in its own limited process) and the shared
ingest step (ingest.ingest_document). PDF tests need pypdf (in the app image); they skip without it.

    python -m unittest discover -s copilot/tests -t .
"""
import os
import shutil
import tempfile
import unittest

from copilot import ingest, sources
from copilot.tests.pdf_fixture import make_pdf

try:
    import pypdf  # noqa: F401
    HAVE_PYPDF = True
except ImportError:
    HAVE_PYPDF = False


@unittest.skipUnless(HAVE_PYPDF, "pypdf is not installed here (it is in the app image)")
class TestPdfText(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, name, data):
        p = os.path.join(self.dir, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def test_text_of_every_page_in_order(self):
        p = self.write("box.pdf", make_pdf([["SMB enumeration (null session)", "smbclient -N -L //target"],
                                            ["Then: enum4linux -a target"]]))
        text = sources.read_pdf(p)
        self.assertIn("SMB enumeration (null session)", text)
        self.assertLess(text.index("smbclient"), text.index("enum4linux"))
        self.assertEqual(sources.read_text(p), text)                     # read_text dispatches on .pdf

    def test_no_text_layer_is_explained(self):
        p = self.write("scan.pdf", make_pdf([[], []]))
        with self.assertRaises(ValueError) as e:
            sources.read_pdf(p)
        self.assertIn("no text layer", str(e.exception))

    def test_not_a_pdf(self):
        p = self.write("fake.pdf", b"<html>not a pdf</html>")
        with self.assertRaises(ValueError):
            sources.read_pdf(p)

    def test_memory_limit_fails_the_child_not_the_caller(self):
        # The cap is set once the interpreter runs, so it counts what is already mapped. 1 MiB is below any CPython's
        # own footprint and the child's next allocation fails everywhere; a 40 MiB cap is environment-dependent (a slim
        # image's Python starts small enough to import pypdf and read this PDF within it).
        p = self.write("box.pdf", make_pdf([["hello"]]))
        with self.assertRaises(ValueError):                              # a clean error here, whatever the child hit
            sources.read_pdf(p, {"memory": 1024 * 1024})
        self.assertIn("hello", sources.read_pdf(p))                      # and the caller is unharmed

    def test_timeout(self):
        p = self.write("box.pdf", make_pdf([["hello"]]))
        with self.assertRaises(ValueError) as e:
            sources.read_pdf(p, {"timeout_s": 0.001})
        self.assertIn("took longer", str(e.exception))

    def test_iter_documents_reads_pdfs_and_skips_scans_with_the_reason(self):
        os.makedirs(os.path.join(self.dir, "htb"))
        self.write("htb/box.pdf", make_pdf([["# Box writeup", "nmap -sV first"]]))
        self.write("htb/scan.pdf", make_pdf([[]]))
        docs = sources.iter_documents(self.dir)
        self.assertEqual([d.rel for d in docs], ["htb/box.pdf"])
        self.assertEqual(docs[0].source, "htb")
        self.assertEqual(dict(sources.iter_documents.skipped)["htb/scan.pdf"].split(":")[0], "no text layer (a scanned PDF?)")


class FakeOllama:
    def embed(self, texts):
        return [[float(len(t) % 7), 1.0, 0.5] for t in texts]


class FakeQdrant:
    def __init__(self):
        self.points, self.calls = {}, []

    def ensure(self, dim, recreate=False):
        self.calls.append(("ensure", dim, recreate))
        return "exists"

    def delete_doc(self, rel):
        self.calls.append(("delete", rel))
        self.points = {k: v for k, v in self.points.items() if v["payload"]["metadata"]["doc"] != rel}

    def upsert(self, pts):
        self.calls.append(("upsert", len(pts)))
        for p in pts:
            self.points[p["id"]] = p


class TestIngestDocument(unittest.TestCase):
    def doc(self, text, rel="engagement/notes.md", source="engagement"):
        return sources.Document("/x/" + rel, rel, source, "Notes", text)

    def test_replaces_the_documents_earlier_chunks(self):
        q, progress = FakeQdrant(), []
        text = "\n\n".join(f"## Step {i}\n" + ("SMB enumeration details. " * 40) for i in range(6))
        chunks, _ = ingest.ingest_document(self.doc(text), [], FakeOllama(), q, chunk_chars=600, batch=2,
                                           progress=lambda d, t: progress.append((d, t)))
        n = len(chunks)
        self.assertGreater(n, 2)
        self.assertEqual(len(q.points), n)
        self.assertEqual(progress[-1], (n, n))
        self.assertEqual(q.calls[0], ("ensure", 3, False))
        self.assertEqual(q.calls[1], ("delete", "engagement/notes.md"))   # before the first write
        ingest.ingest_document(self.doc(text), [], FakeOllama(), q, chunk_chars=600, batch=2)
        self.assertEqual(len(q.points), n)                                # the same ids again: no duplicates

    def test_engagement_text_is_scrubbed_before_embedding(self):
        q = FakeQdrant()
        _, report = ingest.ingest_document(self.doc("Admin is jane.doe@client-corp.com on 10.20.30.40\n"), [], FakeOllama(), q)
        content = " ".join(p["payload"]["content"] for p in q.points.values())
        self.assertNotIn("jane.doe@client-corp.com", content)
        self.assertTrue(report)
        self.assertTrue(all(p["payload"]["metadata"]["scrubbed"] for p in q.points.values()))


if __name__ == "__main__":
    unittest.main()
