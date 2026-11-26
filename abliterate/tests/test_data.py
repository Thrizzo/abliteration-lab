"""abliterate.data without the Hugging Face Hub (a fake catalogue stands in for `datasets` and `huggingface_hub`):
- ABL_HARMFUL_DATASET / ABL_HARMLESS_DATASET choose where the prompt files come from (id, @revision, #column);
- switching the source exports again and keeps the old copy (and the rows removed from it) under data/replaced/,
  keeping the source never fetches anything;
- a dataset without a test split: the held-out prompts come from the end of harmful_train;
- offline (every stage but download), a switch fails with a clear message and the old copy stays;
- provenance() is what a run records: source, revision, column, rows, hash, edited.

    python -m unittest discover -s abliterate/tests -t .
"""
import glob
import hashlib
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

from abliterate import data as D

HARMFUL, HARMLESS, DOLLY, NO_TEST = ("mlabonne/harmful_behaviors", "mlabonne/harmless_alpaca",
                                     "databricks/databricks-dolly-15k", "org/harmful-no-test")
SHA = {HARMFUL: "1" * 40, HARMLESS: "2" * 40, DOLLY: "3" * 40, NO_TEST: "5" * 40}
DOLLY_V1 = "4" * 40                                   # the commit behind DOLLY's tag v1.0
CATALOGUE = {
    HARMFUL: {"splits": {"train": [{"text": f"harmful {i}"} for i in range(40)],
                         "test": [{"text": f"held-out {i}"} for i in range(12)]}},
    HARMLESS: {"splits": {"train": [{"text": f"harmless {i}"} for i in range(40)]}},
    DOLLY: {"refs": {"v1.0": DOLLY_V1}, "commits": {DOLLY_V1},
            "splits": {"train": [{"instruction": f"dolly {i}", "context": "", "response": "r", "category": "open_qa"}
                                 for i in range(40)]}},
    NO_TEST: {"splits": {"train": [{"prompt": f"no-test {i}"} for i in range(40)]}},
}
FILES = ("harmful_train.jsonl", "harmful_test.jsonl", "harmless_train.jsonl")
NO_HUB = {"datasets": None, "huggingface_hub": None}  # importing either raises: proves nothing was fetched


class FakeDataset:
    def __init__(self, rows):
        self.rows, self.column_names = rows, list(rows[0])

    def __len__(self):
        return len(self.rows)

    def __iter__(self):
        return iter(self.rows)


class FakeHub:
    """The Hub as abliterate.data uses it: HfApi().dataset_info(repo, revision=...).sha and load_dataset(repo, split,
    revision). Records every call; offline, both fail like HF_HUB_OFFLINE=1 does."""

    def __init__(self, offline=False):
        self.offline, self.infos, self.loads = offline, [], []

    def modules(self):
        hub = self

        class HfApi:
            def dataset_info(self, repo_id, *, revision=None, **_):
                hub.infos.append((repo_id, revision))
                if hub.offline:
                    raise ConnectionError("You are trying to access the Hub while offline mode is enabled")
                if repo_id not in CATALOGUE:
                    raise FileNotFoundError(f"404 Client Error: dataset {repo_id} not found")
                d = CATALOGUE[repo_id]
                if revision in (None, "main", SHA[repo_id]):
                    return types.SimpleNamespace(sha=SHA[repo_id])
                if revision in d.get("refs", {}):
                    return types.SimpleNamespace(sha=d["refs"][revision])
                if revision in d.get("commits", ()):
                    return types.SimpleNamespace(sha=revision)
                raise FileNotFoundError(f"404 Client Error: revision {revision} not found")

        def load_dataset(path, split=None, revision=None, **_):
            hub.loads.append((path, split, revision))
            if hub.offline:
                raise ConnectionError("offline")
            splits = CATALOGUE[path]["splits"]
            if split not in splits:                   # datasets 5.2, arrow_reader.py
                raise ValueError(f'Unknown split "{split}". Should be one of {list(splits)}.')
            return FakeDataset(splits[split])

        return {"datasets": types.SimpleNamespace(load_dataset=load_dataset),
                "huggingface_hub": types.SimpleNamespace(HfApi=HfApi)}


class ParseSource(unittest.TestCase):
    def test_default_when_unset(self):
        for value in (None, "", "   "):
            self.assertEqual(D.parse_source(value, D.DEFAULT_HARMLESS),
                             {"repo": HARMLESS, "revision": None, "column": None})

    def test_revision_and_column(self):
        self.assertEqual(D.parse_source(f"{DOLLY}@v1.0#instruction", D.DEFAULT_HARMLESS),
                         {"repo": DOLLY, "revision": "v1.0", "column": "instruction"})
        self.assertEqual(D.parse_source("org/name#my column", "x/y"), {"repo": "org/name", "revision": None, "column": "my column"})
        self.assertEqual(D.parse_source("org/name@refs/pr/1", "x/y")["revision"], "refs/pr/1")

    def test_what_is_not_a_dataset_id_is_refused(self):
        # a local path would make load_dataset read files instead of the Hub; the rest are not repo ids on the Hub
        for bad in ("dolly", "json", "../data/x", "/abs/path", "org/", "/name", "org/name/extra", "org/..", "org/-name",
                    "org/name-", "org/na--me", "org/na..me", "org/näme", "https://huggingface.co/datasets/a/b",
                    "org/name@bad rev", "org/name@-x"):
            with self.assertRaises(ValueError, msg=bad):
                D.parse_source(bad, "x/y")

    def test_sources_from_the_environment(self):
        src = D.sources({"ABL_HARMLESS_DATASET": f"{DOLLY}#instruction"})
        self.assertEqual([f for _, _, f in src], list(FILES))
        self.assertEqual([(s["repo"], split) for s, split, _ in src], [(HARMFUL, "train"), (HARMFUL, "test"), (DOLLY, "train")])
        self.assertEqual(src[2][0]["column"], "instruction")
        with self.assertRaises(ValueError):
            D.sources({"ABL_HARMFUL_DATASET": "not a dataset"})


class EnsureLocal(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        cwd = os.getcwd()
        os.chdir(self.dir)                            # load_dataset resolves relative folders against the cwd
        self.addCleanup(os.chdir, cwd)
        self.data = os.path.join(self.dir, "data")
        self.log = []

    def export(self, env, hub=None):
        hub = hub or FakeHub()
        with mock.patch.dict(sys.modules, hub.modules()):
            D.ensure_local(self.data, self.log.append, env)
        return hub

    def keep(self, env):
        """ensure_local with the Hub unreachable for imports: passes only if nothing needs fetching."""
        with mock.patch.dict(sys.modules, NO_HUB):
            D.ensure_local(self.data, self.log.append, env)

    def manifest(self):
        with open(os.path.join(self.data, "manifest.json"), encoding="utf-8") as f:
            return json.load(f)

    def prompts(self, fname):
        return D.read_jsonl(os.path.join(self.data, fname))

    def replaced(self, pattern):
        return sorted(glob.glob(os.path.join(self.data, "replaced", pattern)))

    def test_default_export_records_source_revision_column_and_hash(self):
        hub = self.export({})
        self.assertEqual(hub.loads, [(HARMFUL, "train", SHA[HARMFUL]), (HARMFUL, "test", SHA[HARMFUL]),
                                     (HARMLESS, "train", SHA[HARMLESS])])
        self.assertEqual(self.prompts("harmful_test.jsonl")[:2], ["held-out 0", "held-out 1"])
        with open(os.path.join(self.data, "harmless_train.jsonl"), encoding="utf-8") as f:
            self.assertEqual(json.loads(f.readline()), {"id": "harmless_train-0", "prompt": "harmless 0"})
        m = self.manifest()["harmless_train.jsonl"]
        with open(os.path.join(self.data, "harmless_train.jsonl"), "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual({k: m[k] for k in ("repo", "split", "revision", "column", "rows", "sha256")},
                         {"repo": HARMLESS, "split": "train", "revision": SHA[HARMLESS], "column": "text", "rows": 40,
                          "sha256": digest})
        self.assertNotIn("requested", m)              # unpinned: the commit it was exported at
        self.assertFalse(os.path.isdir(os.path.join(self.data, "replaced")))

    def test_nothing_is_fetched_while_the_source_stays(self):
        self.export({})
        self.keep({})
        self.keep({"ABL_HARMLESS_DATASET": HARMLESS, "ABL_HARMFUL_DATASET": f"  {HARMFUL}  "})
        # copies exported before the source was selectable: no column recorded (and, older still, no repo)
        m = self.manifest()
        for entry in m.values():
            entry.pop("column")
        m["harmful_train.jsonl"].pop("repo")
        with open(os.path.join(self.data, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(m, f)
        self.keep({})

    def test_switching_the_harmless_source_exports_it_again_and_keeps_the_old_copy(self):
        self.export({})
        with open(os.path.join(self.data, "harmless_train.jsonl"), "rb") as f:
            old = f.read()
        harmful_before = {k: v for k, v in self.manifest().items() if k.startswith("harmful")}
        os.makedirs(os.path.join(self.data, "removed"))
        with open(os.path.join(self.data, "removed", "harmless_train.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps({"id": "harmless_train-3", "prompt": "harmless 3", "reason": "dupe"}) + "\n")

        hub = self.export({"ABL_HARMLESS_DATASET": f"{DOLLY}#instruction"})
        self.assertEqual(hub.loads, [(DOLLY, "train", SHA[DOLLY])])        # the harmful files are not fetched again
        self.assertEqual(self.prompts("harmless_train.jsonl")[:2], ["dolly 0", "dolly 1"])
        m = self.manifest()
        self.assertEqual((m["harmless_train.jsonl"]["repo"], m["harmless_train.jsonl"]["column"]), (DOLLY, "instruction"))
        self.assertEqual({k: v for k, v in m.items() if k.startswith("harmful")}, harmful_before)
        [kept] = self.replaced("harmless_train.jsonl.*")
        with open(kept, "rb") as f:
            self.assertEqual(f.read(), old)
        # the rows removed from the Alpaca copy go with it: a restore can't put them into the Dolly copy
        self.assertFalse(os.path.exists(os.path.join(self.data, "removed", "harmless_train.jsonl")))
        self.assertEqual(len(self.replaced("removed-harmless_train.jsonl.*")), 1)
        self.assertTrue(any("kept as replaced" in line for line in self.log), self.log)

        # and back: the copy came from Dolly now, so the default is exported again (both old copies stay)
        hub = self.export({})
        self.assertEqual(hub.loads, [(HARMLESS, "train", SHA[HARMLESS])])
        self.assertEqual(self.prompts("harmless_train.jsonl")[0], "harmless 0")
        self.assertEqual(len(self.replaced("harmless_train.jsonl.*")), 2)

    def test_a_dataset_without_test_split_takes_the_held_out_prompts_from_the_end_of_train(self):
        self.export({})
        env = {"ABL_HARMFUL_DATASET": NO_TEST}
        hub = self.export(env)
        self.assertEqual(hub.loads, [(NO_TEST, "train", SHA[NO_TEST]), (NO_TEST, "test", SHA[NO_TEST])])
        self.assertFalse(os.path.exists(os.path.join(self.data, "harmful_test.jsonl")))
        self.assertEqual(len(self.replaced("harmful_test.jsonl.*")), 1)    # AdvBench's test split is kept aside
        t = self.manifest()["harmful_test.jsonl"]
        self.assertEqual((t["repo"], t["revision"], t["absent"]), (NO_TEST, SHA[NO_TEST], True))
        self.assertTrue(any("no test split" in line for line in self.log), self.log)

        with mock.patch.dict(os.environ, env), mock.patch.dict(sys.modules, NO_HUB):   # a later stage: offline
            train, test, harmless, harmless_val = D.load_prompts(self.data, 10, 5)
        self.assertEqual(train, [f"no-test {i}" for i in range(10)])
        self.assertEqual(test, [f"no-test {i}" for i in range(10, 15)])
        self.assertEqual(len(harmless), 10)
        self.assertEqual(D.provenance(self.data)["harmful_test.jsonl"]["absent"], True)

    def test_offline_a_switch_fails_and_the_old_copy_stays(self):
        self.export({})
        with open(os.path.join(self.data, "harmless_train.jsonl"), "rb") as f:
            old = f.read()
        before = self.manifest()
        with self.assertRaises(RuntimeError) as cm:
            self.export({"ABL_HARMLESS_DATASET": DOLLY}, FakeHub(offline=True))
        self.assertIn("Only the download stage has internet", str(cm.exception))
        self.assertIn("ABL_HARMLESS_DATASET", str(cm.exception))
        with open(os.path.join(self.data, "harmless_train.jsonl"), "rb") as f:
            self.assertEqual(f.read(), old)
        self.assertEqual(self.manifest(), before)
        self.assertEqual(self.replaced("*"), [])

    def test_an_unknown_dataset_or_column_fails_before_the_copy_is_replaced(self):
        self.export({})
        before = self.manifest()
        for env, msg in (({"ABL_HARMLESS_DATASET": f"{DOLLY}#prompt_text"}, "no column 'prompt_text'"),
                         ({"ABL_HARMLESS_DATASET": "org/does-not-exist"}, "not found")):
            with self.assertRaises(RuntimeError, msg=env) as cm:
                self.export(env)
            self.assertIn(msg, str(cm.exception))
            self.assertEqual(self.prompts("harmless_train.jsonl")[0], "harmless 0")
            self.assertEqual(self.manifest(), before)
            self.assertEqual(self.replaced("*"), [])

    def test_a_pinned_revision_is_resolved_to_its_commit_and_kept(self):
        hub = self.export({"ABL_HARMLESS_DATASET": f"{DOLLY}@v1.0#instruction"})
        self.assertIn((DOLLY, "v1.0"), hub.infos)
        self.assertIn((DOLLY, "train", DOLLY_V1), hub.loads)               # the tag's commit, not the tag
        m = self.manifest()["harmless_train.jsonl"]
        self.assertEqual((m["revision"], m["requested"], m["column"]), (DOLLY_V1, "v1.0", "instruction"))
        self.keep({"ABL_HARMLESS_DATASET": f"{DOLLY}@v1.0#instruction"})   # same pin: nothing fetched
        self.keep({"ABL_HARMLESS_DATASET": f"{DOLLY}@{DOLLY_V1}"})         # the same commit by its hash
        self.keep({"ABL_HARMLESS_DATASET": DOLLY})                         # unpinned: the exported commit stays
        hub = self.export({"ABL_HARMLESS_DATASET": f"{DOLLY}@{SHA[DOLLY]}"})   # another commit: exported again
        self.assertEqual(hub.loads, [(DOLLY, "train", SHA[DOLLY])])
        self.assertEqual(self.manifest()["harmless_train.jsonl"]["revision"], SHA[DOLLY])

    def test_a_folder_named_like_the_dataset_is_refused(self):
        self.export({})
        os.makedirs(os.path.join(self.dir, "data", "replaced"), exist_ok=True)
        hub = FakeHub()
        with self.assertRaises(RuntimeError) as cm:
            self.export({"ABL_HARMLESS_DATASET": "data/replaced"}, hub)
        self.assertIn("is also a folder", str(cm.exception))
        self.assertEqual((hub.infos, hub.loads), ([], []))

    def test_provenance_reports_source_and_edits(self):
        self.export({"ABL_HARMLESS_DATASET": f"{DOLLY}#instruction"})
        p = D.provenance(self.data)
        self.assertEqual(sorted(p), sorted(FILES))
        self.assertEqual({k: p["harmless_train.jsonl"][k] for k in ("repo", "revision", "column", "rows", "edited")},
                         {"repo": DOLLY, "revision": SHA[DOLLY], "column": "instruction", "rows": 40, "edited": False})
        path = os.path.join(self.data, "harmless_train.jsonl")
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
        with open(path, "w", encoding="utf-8", newline="\n") as f:          # the workbench removed a row
            f.writelines(lines[1:])
        p = D.provenance(self.data)
        self.assertTrue(p["harmless_train.jsonl"]["edited"])
        self.assertFalse(p["harmful_train.jsonl"]["edited"])


if __name__ == "__main__":
    unittest.main()
