"""Dataset workbench status (app/datasets.py): which source each prompt copy came from, as abliterate.data recorded it
(ABL_HARMFUL_DATASET / ABL_HARMLESS_DATASET), and a dataset without a test split.

    python -m unittest discover -s app/tests
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import datasets as DSW  # noqa: E402  (app/datasets.py, the workbench; not Hugging Face's package)


class Status(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def write(self, fname, prompts):
        path = os.path.join(self.dir, fname)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            for i, p in enumerate(prompts):
                f.write(json.dumps({"id": f"{fname[:-6]}-{i}", "prompt": p}) + "\n")
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def status(self):
        return {s["file"]: s for s in DSW.Datasets(self.dir).status()}

    def test_the_selected_source_and_a_missing_test_split(self):
        manifest = {
            "harmful_train.jsonl": {"repo": "org/harmful-no-test", "split": "train", "revision": "5" * 40, "column": "prompt",
                                    "rows": 3, "sha256": self.write("harmful_train.jsonl", ["a", "b", "c"])},
            "harmful_test.jsonl": {"repo": "org/harmful-no-test", "split": "test", "revision": "5" * 40, "absent": True},
            "harmless_train.jsonl": {"repo": "databricks/databricks-dolly-15k", "split": "train", "revision": "4" * 40,
                                     "requested": "v1.0", "column": "instruction", "rows": 2,
                                     "sha256": self.write("harmless_train.jsonl", ["x", "y"])},
        }
        with open(os.path.join(self.dir, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f)
        st = self.status()
        h = st["harmless_train.jsonl"]
        self.assertEqual((h["repo"], h["column"], h["requested"], h["revision"], h["edited"], h["absent"]),
                         ("databricks/databricks-dolly-15k", "instruction", "v1.0", "4" * 40, False, False))
        t = st["harmful_test.jsonl"]
        self.assertEqual((t["repo"], t["present"], t["absent"], t["rows_now"]), ("org/harmful-no-test", False, True, 0))
        d = st["dpo_train.jsonl"]                     # never exported: the default label, nothing present
        self.assertEqual((d["repo"], d["present"], d["absent"]), ("mlabonne/orpo-dpo-mix-40k", False, False))

        # a test set built in the workbench for such a dataset is what the pipeline uses, and counts as edited
        DSW.Datasets(self.dir).add("harmful_test.jsonl", {"prompt": "my held-out prompt"})
        t = self.status()["harmful_test.jsonl"]
        self.assertEqual((t["present"], t["absent"], t["edited"], t["rows_now"]), (True, False, True, 1))


if __name__ == "__main__":
    unittest.main()
