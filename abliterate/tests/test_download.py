"""The model download: a copy that lacks something is not taken as complete, and a download that could never be used here
is refused before it starts.
- copy_problem: a finished download (local_copy.json), an interrupted one (config.json and the index came, the tokenizer
  and shards did not: the owner's GLM-5.3-Flash run then failed at the tokenizer), a folder copied by hand;
- step_download goes on with an interrupted download and records it, says what is missing when Hugging Face cannot be
  asked, and refuses a model whose weights this machine could never load for measure and scan, or the disk could not hold,
  before any byte is downloaded (the faked Hub sizes GLM-5.3-Flash's 62 shards);
- fit_problem: one GPU, all GPUs plus RAM, the CPU, and RAM that cannot be read;
- main: the refusal ends the run with its reason, without a traceback.

    python -m unittest discover -s abliterate/tests -t .
"""
import contextlib
import io
import json
import os
import shutil
import tempfile
import types
import unittest
from unittest import mock

from abliterate import pipeline as P

GB = 10 ** 9
SHARDS = [f"model-{i:05d}-of-00062.safetensors" for i in range(1, 63)]


def write(path, text=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def index(dst, shards):
    write(os.path.join(dst, "model.safetensors.index.json"),
          json.dumps({"metadata": {}, "weight_map": {f"w{i}": s for i, s in enumerate(shards)}}))


class Sibling:
    def __init__(self, name, size):
        self.rfilename, self.size = name, size


def flash_siblings(shard_gb=5.3):
    """What the Hub lists for GLM-5.3-Flash (its non-weight files plus 62 shards of about 5.3 GB: 328 GB)."""
    small = [("config.json", 69416), ("generation_config.json", 194), ("model.safetensors.index.json", 4_000_000),
             ("tokenizer.json", 20217442), ("tokenizer_config.json", 761), ("chat_template.jinja", 10830),
             ("processor_config.json", 600), ("README.md", 9000)]
    return [Sibling(n, s) for n, s in small] + [Sibling(s, int(shard_gb * GB)) for s in SHARDS]


class FakeRun:
    def __init__(self):
        self.logs, self.events = [], []

    def log(self, msg):
        self.logs.append(msg)

    def event(self, step, status, **kw):
        self.events.append((step, status, kw))


def args_for(stage="all", device_map="cuda", no_fit_check=False):
    return types.SimpleNamespace(stage=stage, device_map=device_map, dtype="auto", no_fit_check=no_fit_check)


class CopyProblem(unittest.TestCase):
    def setUp(self):
        self.dst = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dst, True)

    def test_a_finished_download_is_complete(self):
        write(os.path.join(self.dst, "config.json"), "{}")
        write(os.path.join(self.dst, "local_copy.json"), "{}")
        self.assertEqual(P.copy_problem(self.dst), "")

    def test_an_interrupted_download_is_not(self):
        # the owner's folder: config.json, tokenizer_config.json and the index came first; tokenizer.json and shards did not
        write(os.path.join(self.dst, "config.json"), "{}")
        write(os.path.join(self.dst, "tokenizer_config.json"), "{}")
        index(self.dst, SHARDS[:2])
        write(os.path.join(self.dst, SHARDS[0]), "x")
        self.assertEqual(P.copy_problem(self.dst), f"{SHARDS[1]}, the tokenizer (tokenizer.json)")

    def test_many_missing_files_are_counted(self):
        write(os.path.join(self.dst, "config.json"), "{}")
        write(os.path.join(self.dst, "tokenizer.json"), "{}")
        index(self.dst, SHARDS)
        self.assertEqual(P.copy_problem(self.dst), f"{SHARDS[0]}, {SHARDS[1]}, {SHARDS[2]} and 59 more")

    def test_a_folder_copied_by_hand(self):
        write(os.path.join(self.dst, "config.json"), "{}")
        write(os.path.join(self.dst, "model.safetensors"), "x")
        self.assertEqual(P.copy_problem(self.dst), "the tokenizer (tokenizer.json)")
        write(os.path.join(self.dst, "tokenizer.json"), "{}")
        self.assertEqual(P.copy_problem(self.dst), "")

    def test_no_config_and_a_broken_index(self):
        self.assertEqual(P.copy_problem(self.dst), "config.json")
        write(os.path.join(self.dst, "config.json"), "{}")
        write(os.path.join(self.dst, "model.safetensors.index.json"), "{not json")
        self.assertEqual(P.copy_problem(self.dst), "a readable model.safetensors.index.json")


class StepDownload(unittest.TestCase):
    repo = "zai-org/GLM-5.3-Flash"

    def setUp(self):
        self.models = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.models, True)
        self.dst = os.path.join(self.models, "glm-5.3-flash")
        self.downloads = []

    def interrupted_copy(self):
        write(os.path.join(self.dst, "config.json"), "{}")
        write(os.path.join(self.dst, "tokenizer_config.json"), "{}")
        index(self.dst, ["model-00001-of-00002.safetensors", "model-00002-of-00002.safetensors"])

    def hub(self, siblings, fail=None):
        """huggingface_hub with model_info answering from siblings (or raising fail) and snapshot_download writing every file."""
        dl = self.downloads

        class Api:
            def __init__(self, token=None):
                pass

            def model_info(self, repo, files_metadata=True):
                if fail:
                    raise fail
                return types.SimpleNamespace(sha="46a050bec130" + "0" * 28, siblings=siblings)

        def snapshot_download(repo, revision=None, local_dir=None, token=None, allow_patterns=None):
            dl.append(local_dir)
            for s in siblings:
                write(os.path.join(local_dir, s.rfilename), "{}" if s.rfilename.endswith(".json") else "x")
            return local_dir

        return mock.patch.multiple("huggingface_hub", HfApi=Api, snapshot_download=snapshot_download)

    def small_model(self):
        return [Sibling("config.json", 100), Sibling("tokenizer.json", 100), Sibling("tokenizer_config.json", 100),
                Sibling("model.safetensors.index.json", 100), Sibling("model-00001-of-00002.safetensors", GB),
                Sibling("model-00002-of-00002.safetensors", GB)]

    def test_an_interrupted_download_goes_on(self):
        self.interrupted_copy()
        run = FakeRun()
        with self.hub(self.small_model()), mock.patch.object(P, "free_ram_gb", return_value=64.0):
            dst = P.step_download(run, self.repo, self.models, args=args_for())
        self.assertEqual(dst, self.dst)
        self.assertEqual(self.downloads, [self.dst])
        self.assertTrue(any("incomplete (it lacks model-00001-of-00002.safetensors, model-00002-of-00002.safetensors, the "
                            "tokenizer (tokenizer.json))" in m for m in run.logs), run.logs)
        self.assertTrue(os.path.isfile(os.path.join(self.dst, "local_copy.json")))
        self.assertEqual(P.copy_problem(self.dst), "")
        self.assertEqual(run.events[-1][:2], ("download", "done"))

    def test_without_the_hub_it_says_what_is_missing(self):
        self.interrupted_copy()
        with self.hub([], fail=OSError("no network")), self.assertRaises(P.UsageError) as e:
            P.step_download(FakeRun(), self.repo, self.models, args=args_for("scan"))
        self.assertIn("is incomplete (it lacks", str(e.exception))
        self.assertIn("run the download again where it can", str(e.exception))
        self.assertEqual(self.downloads, [])

    def test_a_model_this_machine_cannot_load_is_not_downloaded(self):
        # GLM-5.3-Flash on one 24 GB GPU and 32 GB of RAM: 328 GB of weights, refused before the first byte
        fake_cuda = types.SimpleNamespace(is_available=lambda: True, device_count=lambda: 1,
                                          get_device_properties=lambda i: types.SimpleNamespace(total_memory=24 * GB))
        with self.hub(flash_siblings()), mock.patch.object(P, "free_ram_gb", return_value=32.0), \
                mock.patch("torch.cuda", fake_cuda), self.assertRaises(P.UsageError) as e:
            P.step_download(FakeRun(), self.repo, self.models, args=args_for("all", "auto"))
        self.assertIn("zai-org/GLM-5.3-Flash does not fit this machine: its weights alone are 329 GB, and this machine has "
                      "24 GB on 1 GPU plus 32 GB of free RAM for measure and scan", str(e.exception))
        self.assertEqual(self.downloads, [])

    def test_the_download_stage_alone_is_not_held_to_the_machine(self):
        # downloading for later, or for the GPU node that shares the workspace: only the disk counts
        fake_usage = types.SimpleNamespace(total=2000 * GB, used=0, free=2000 * GB)
        with self.hub(flash_siblings()), mock.patch.object(P, "free_ram_gb", return_value=8.0), \
                mock.patch("shutil.disk_usage", return_value=fake_usage):
            P.step_download(FakeRun(), self.repo, self.models, args=args_for("download"))
        self.assertEqual(self.downloads, [self.dst])

    def test_the_disk_must_hold_the_download_and_the_edited_copy(self):
        fake_usage = types.SimpleNamespace(total=100 * GB, used=0, free=3 * GB)
        with self.hub(self.small_model()), mock.patch.object(P, "free_ram_gb", return_value=64.0), \
                mock.patch("shutil.disk_usage", return_value=fake_usage), self.assertRaises(P.UsageError) as e:
            P.step_download(FakeRun(), self.repo, self.models, args=args_for("all"))
        self.assertIn("does not fit the disk: it needs 4 GB on the disk of", str(e.exception))
        self.assertIn("(2 GB still to download, 2 GB for the edited copy)", str(e.exception))
        self.assertEqual(self.downloads, [])

    def test_no_fit_check_lets_it_through(self):
        with self.hub(flash_siblings(0.001)), mock.patch.object(P, "free_ram_gb", return_value=0.01):
            P.step_download(FakeRun(), self.repo, self.models, args=args_for("all", "cpu", no_fit_check=True))
        self.assertEqual(self.downloads, [self.dst])


class FitProblem(unittest.TestCase):
    def cuda(self, *gb):
        return mock.patch("torch.cuda", types.SimpleNamespace(
            is_available=lambda: bool(gb), device_count=lambda: len(gb),
            get_device_properties=lambda i: types.SimpleNamespace(total_memory=gb[i] * GB)))

    def test_all_gpus_and_the_ram_for_device_auto(self):
        with self.cuda(24, 24), mock.patch.object(P, "free_ram_gb", return_value=30.0):
            self.assertEqual(P.fit_problem(70, "auto"), "")
            self.assertEqual(P.fit_problem(100, "auto"), "its weights alone are 100 GB, and this machine has 48 GB on 2 GPUs "
                                                         "plus 30 GB of free RAM for measure and scan")

    def test_one_gpu_for_device_cuda(self):
        with self.cuda(16), mock.patch.object(P, "free_ram_gb", return_value=64.0):
            self.assertEqual(P.fit_problem(9, "cuda"), "")          # GLM-Edge-4B in bf16 on a 16 GB card
            self.assertIn("19 GB, and this machine has 16 GB on its GPU (device auto adds the RAM, slowly)", P.fit_problem(19, "cuda"))

    def test_the_cpu(self):
        with self.cuda(), mock.patch.object(P, "free_ram_gb", return_value=20.0):
            self.assertEqual(P.fit_problem(7, "cuda"), "")          # cuda without a GPU runs on the CPU
            self.assertIn("this machine has 20 GB of free RAM and no GPU this process can use", P.fit_problem(30, "cpu"))

    def test_ram_that_cannot_be_read_decides_nothing(self):
        with self.cuda(), mock.patch.object(P, "free_ram_gb", return_value=None):
            self.assertEqual(P.fit_problem(1000, "cpu"), "")
        with self.cuda(24), mock.patch.object(P, "free_ram_gb", return_value=None):
            self.assertEqual(P.fit_problem(1000, "auto"), "")


class CommandLine(unittest.TestCase):
    def test_the_refusal_ends_the_run_with_its_reason(self):
        project = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, project, True)
        t = StepDownload("test_an_interrupted_download_goes_on")
        t.downloads = []
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        with t.hub(flash_siblings()), mock.patch.object(P, "free_ram_gb", return_value=16.0), \
                mock.patch("torch.cuda", types.SimpleNamespace(is_available=lambda: False)), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit) as e:
            P.main(["--model", "zai-org/GLM-5.3-Flash", "--project", project])
        self.assertEqual(e.exception.code, 2)
        self.assertEqual(t.downloads, [])
        runs = os.listdir(os.path.join(project, "runs"))
        meta = json.load(open(os.path.join(project, "runs", runs[0], "run.json"), encoding="utf-8"))
        self.assertEqual(meta["status"], "error")
        self.assertIn("does not fit this machine", meta["error"])
        self.assertIn("16 GB of free RAM and no GPU this process can use", meta["error"])


if __name__ == "__main__":
    unittest.main()
