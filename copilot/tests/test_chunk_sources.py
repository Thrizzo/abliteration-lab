"""Tests for copilot.chunk and copilot.sources. Run: python -m unittest discover -s copilot/tests -t ."""
import os
import unittest

from copilot.chunk import chunk_markdown
from copilot.sources import NO_TRAIN_SOURCES, iter_documents, read_text

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "writeups")


class Chunking(unittest.TestCase):
    def setUp(self):
        self.text = read_text(os.path.join(FIX, "htb", "lantern.md"))
        self.chunks = chunk_markdown(self.text, target=400, hard_limit=800)

    def test_code_fences_never_split(self):
        for c in self.chunks:
            self.assertEqual(c.text.count("```") % 2, 0, f"unbalanced fence in chunk {c.index}:\n{c.text}")

    def test_heading_path_prefix(self):
        smb = [c for c in self.chunks if "smbclient -N -L" in c.text]
        self.assertTrue(smb)
        self.assertTrue(smb[0].text.startswith("[") and "Enumeration > SMB" in smb[0].heading, smb[0].heading)

    def test_command_kept_with_its_explanation(self):
        gob = [c for c in self.chunks if "gobuster dir" in c.text][0]
        self.assertIn("Directory brute force", gob.text)

    def test_sizes_bounded(self):
        self.assertTrue(all(len(c.text) <= 800 + 200 for c in self.chunks), [len(c.text) for c in self.chunks])
        self.assertTrue(all(c.text.strip() for c in self.chunks))

    def test_huge_code_block_is_split(self):
        big = "# T\n\n```bash\n" + "\n".join(f"echo line {i}" for i in range(500)) + "\n```\n"
        chunks = chunk_markdown(big, target=500, hard_limit=1000)
        self.assertGreater(len(chunks), 3)
        self.assertTrue(all(len(c.text) <= 1100 for c in chunks))


class Sources(unittest.TestCase):
    def test_tags_and_skips(self):
        docs = iter_documents(FIX)
        by = {d.rel: d.source for d in docs}
        self.assertEqual(by["htb/lantern.md"], "htb")
        self.assertEqual(by["engagement/acme-internal.md"], "engagement")
        self.assertEqual(by["pwk/sample-notes.md"], "pwk")
        self.assertNotIn("redact_terms.txt", by)

    def test_exclude_and_training_policy(self):
        docs = iter_documents(FIX, exclude={"pwk"})
        self.assertFalse(any(d.source == "pwk" for d in docs))
        self.assertIn("pwk", NO_TRAIN_SOURCES)

    def test_title_from_h1(self):
        d = [d for d in iter_documents(FIX) if d.rel == "htb/lantern.md"][0]
        self.assertTrue(d.title.startswith("Lantern"))

    def test_html_is_converted(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(os.path.join(td, "blog"))
            with open(os.path.join(td, "blog", "post.html"), "w", encoding="utf-8") as f:
                f.write("<html><head><script>x()</script></head><body><h1>Post</h1><p>Use this:</p>"
                        "<pre>nmap -sV 10.0.0.1</pre></body></html>")
            d = iter_documents(td)[0]
            self.assertEqual(d.source, "blog")
            self.assertIn("```", d.text)
            self.assertIn("nmap -sV 10.0.0.1", d.text)
            self.assertNotIn("x()", d.text)


if __name__ == "__main__":
    unittest.main()
