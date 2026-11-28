"""What this machine can run, checked before a model is loaded (findings of the Docker audit):
- gpu_problem / cuda_usable / resolve_device: a GPU the image's torch build has no kernels for (cu128: Turing to
  Blackwell) counts as no GPU for the runs that would use it, so a run goes to the CPU with the reason and the way out
  (cu126 for an older GPU, cu128 for a newer one), instead of failing at its first kernel; device cuda checks the current
  GPU only, device auto keeps to it when another GPU is outside the build; fit_problem then counts the RAM only and says
  why, and _ram_check warns from the capped RAM;
- cgroup_room_gb / free_ram_gb: a container's memory limit caps MemAvailable (in a Kubernetes Job /proc/meminfo shows the
  node's RAM), and the page cache the kernel can drop does not count as used;
- fp8_kernel: an FP8 checkpoint's Triton kernel is fetched with the model (through transformers' own mapping) on every
  path of the download stage, a stage without internet whose GPU needs it (8.9 and newer) stops before the load when the
  cache lacks it, a missing kernels package is named as such, and a cached kernel is used when the Hub is out of reach;
- arch.inspect refuses legacy ChatGLM remote code, which transformers 5 cannot load, and points at glm-4-9b-chat-hf
  (model_type glm, the real config).

    python -m unittest discover -s abliterate/tests -t .
"""
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

import torch

from abliterate import arch as A
from abliterate import hooks as H
from abliterate import pipeline as P
from abliterate.tests.test_download import FakeRun

CU128 = ["sm_75", "sm_80", "sm_86", "sm_90", "sm_100", "sm_120"]           # torch 2.11.0+cu128 (PyTorch's build script)
CU126 = ["sm_50", "sm_60", "sm_70", "sm_75", "sm_80", "sm_86", "sm_90"]


def fake_cuda(caps, archs=CU128, names=None, total_gb=16):
    names = names or [f"GPU {i}" for i in range(len(caps))]
    return types.SimpleNamespace(
        is_available=lambda: bool(caps), device_count=lambda: len(caps), get_arch_list=lambda: list(archs),
        get_device_capability=lambda i: caps[i], get_device_name=lambda i: names[i], current_device=lambda: 0,
        get_device_properties=lambda i: types.SimpleNamespace(total_memory=total_gb * 10 ** 9))


def gpus(caps, cuda="12.8", **kw):
    """torch.cuda faked with these compute capabilities, and a CUDA build of torch."""
    stack = mock.patch("torch.cuda", fake_cuda(caps, **kw)), mock.patch.object(torch.version, "cuda", cuda)

    class Both:
        def __enter__(self):
            for s in stack:
                s.__enter__()

        def __exit__(self, *exc):
            for s in reversed(stack):
                s.__exit__(*exc)
    return Both()


class GpuArch(unittest.TestCase):
    def test_which_builds_run_where(self):
        for archs, cap, ok in ((CU128, (6, 1), False),                  # Pascal (GTX 10xx, P40): no sm_6x at all
                               (CU128, (7, 0), False),                  # Volta: sm_75 machine code does not run on 7.0
                               (CU128, (7, 5), True), (CU128, (8, 9), True),   # sm_86 code runs on 8.9 (same major)
                               (CU128, (12, 0), True),                  # the owner's RTX 5080
                               (CU126, (6, 1), True), (CU126, (7, 0), True),
                               (CU126, (12, 0), False),                 # no Blackwell machine code, no PTX
                               (CU126 + ["compute_90"], (12, 0), True),  # PTX: the driver compiles it for newer GPUs
                               (["sm_90a"], (9, 0), True), ([], (8, 0), False)):
            self.assertEqual(H._arch_covers(archs, *cap), ok, (archs, cap))

    def test_an_old_gpu_is_named_with_the_way_out(self):
        with gpus([(6, 1)], names=["Tesla P40"]):
            problem = H.gpu_problem()
            self.assertIn("no kernels for GPU 0, Tesla P40 (compute capability 6.1)", problem)
            self.assertIn("TORCH_FLAVOR=cu126, which covers Maxwell, Pascal and Volta", problem)
            self.assertIn("--build-arg for the image Kubernetes runs", problem)
            self.assertFalse(H.cuda_usable())
            logs = []
            self.assertEqual(H.resolve_device("cuda", "float32", logs.append), ("cpu", "float32"))
            self.assertEqual(H.resolve_device("auto", "float32", logs.append), ("cpu", "float32"))   # accelerate would use it
            self.assertEqual(len(logs), 2)
            self.assertIn("Running on the CPU instead", logs[0])
            self.assertEqual(H.resolve_device("cpu", "float32", logs.append), ("cpu", "float32"))
            self.assertEqual(len(logs), 2)                                # asked for the CPU: nothing to say

    def test_a_gpu_the_build_covers_stays(self):
        with gpus([(12, 0)], names=["NVIDIA GeForce RTX 5080"]):
            self.assertEqual(H.gpu_problem(), "")
            self.assertTrue(H.cuda_usable())
            self.assertEqual(H.resolve_device("cuda", "bfloat16", lambda *a: None), ("cuda", "bfloat16"))
        with gpus([(8, 6), (6, 1)], names=["RTX 3090", "GTX 1080"]):     # a display card beside it
            self.assertIn("GPU 1, GTX 1080 (compute capability 6.1)", H.gpu_problem())
            self.assertNotIn("RTX 3090", H.gpu_problem())
            self.assertTrue(H.cuda_usable())                             # device cuda: the current GPU, the 3090
            self.assertEqual(H.resolve_device("cuda", "bfloat16", lambda *a: None), ("cuda", "bfloat16"))
            logs = []
            self.assertEqual(H.resolve_device("auto", "bfloat16", logs.append), ("cuda", "bfloat16"))   # not onto the 1080
            self.assertIn("Device auto keeps to GPU 0", logs[0])
            self.assertIn("CUDA_VISIBLE_DEVICES", logs[0])
        with gpus([(6, 1), (8, 6)], names=["GTX 1080", "RTX 3090"]):     # the current GPU is the old one
            logs = []
            self.assertEqual(H.resolve_device("cuda", "float32", logs.append), ("cpu", "float32"))
            self.assertIn("CUDA_VISIBLE_DEVICES can put one of the 1 GPU this build covers first", logs[0])

    def test_a_gpu_newer_than_the_build_is_sent_to_the_default_build(self):
        with gpus([(12, 0)], archs=CU126, names=["NVIDIA GeForce RTX 5080"]):   # a cu126 image on the owner's card
            problem = H.gpu_problem()
            self.assertIn("the default TORCH_FLAVOR=cu128, which covers Turing to Blackwell", problem)
            self.assertNotIn("cu126, which covers", problem)

    def test_no_gpu_or_a_cpu_build_has_no_problem(self):
        with gpus([]):
            self.assertEqual(H.gpu_problem(), "")
        with gpus([(6, 1)], cuda=None):                                  # a CPU build of torch
            self.assertEqual(H.gpu_problem(), "")
        with mock.patch("torch.cuda", types.SimpleNamespace(is_available=lambda: True)), \
                mock.patch.object(torch.version, "cuda", "12.8"):        # a torch.cuda that cannot tell: no verdict
            self.assertEqual(H.gpu_problem(), "")
        with gpus([(6, 1)], archs=[]):                                   # a build without an arch list: no verdict
            self.assertEqual(H.gpu_problem(), "")

    def test_the_fit_check_counts_ram_only_with_an_old_gpu(self):
        with gpus([(7, 0)], total_gb=32), mock.patch.object(P, "free_ram_gb", return_value=20.0):
            problem = P.fit_problem(30, "auto")
            self.assertIn("20 GB of free RAM and no GPU this process can use (this image's PyTorch", problem)   # and why
            self.assertEqual(P.fit_problem(10, "cuda"), "")
            self.assertNotIn("PyTorch", P.fit_problem(30, "cpu"))         # asked for the CPU: the GPU is beside the point
            args = types.SimpleNamespace(stage="all", device_map="auto", dtype="auto", no_fit_check=False)
            with self.assertRaises(P.UsageError) as e:
                P.check_fit("zai-org/GLM-4.5-Air", 30, args)
            self.assertIn("does not fit this machine as this image runs it", str(e.exception))
            self.assertNotIn("needs a node with enough GPUs", str(e.exception))   # it has GPUs: the image is the problem
        with gpus([(8, 0)], total_gb=32), mock.patch.object(P, "free_ram_gb", return_value=20.0):
            self.assertEqual(P.fit_problem(30, "cuda"), "")              # an A100 slice the build covers: its 32 GB


class Memory(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def put(self, rel, text):
        path = os.path.join(self.d, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="ascii") as f:
            f.write(text)

    def test_cgroup_v2_limit_minus_what_is_really_used(self):
        self.put("memory.max", "12884901888\n")                        # 12Gi, the dev overlay's gpu class
        self.put("memory.current", "6000000000\n")
        self.put("memory.stat", "anon 1500000000\nfile 4500000000\nactive_file 500000000\ninactive_file 4000000000\n")
        self.assertAlmostEqual(P.cgroup_room_gb(self.d), (12884901888 - 2000000000) / 1e9)

    def test_at_or_over_the_limit_there_is_no_room(self):
        self.put("memory.max", "1000000000\n")
        self.put("memory.current", "1200000000\n")                      # a moment over the limit: no room, not less
        self.assertEqual(P.cgroup_room_gb(self.d), 0.0)
        self.put("memory.current", "100000000\n")                       # inactive_file above current (counted apart):
        self.put("memory.stat", "inactive_file 300000000\n")             # nothing used, the whole limit
        self.assertAlmostEqual(P.cgroup_room_gb(self.d), 1.0)

    def test_no_limit(self):
        self.put("memory.max", "max\n")
        self.put("memory.current", "123\n")
        self.assertIsNone(P.cgroup_room_gb(self.d))
        self.assertIsNone(P.cgroup_room_gb(os.path.join(self.d, "nothing-here")))

    def test_cgroup_v1(self):
        self.put("memory/memory.limit_in_bytes", "9223372036854771712\n")   # v1's "no limit"
        self.put("memory/memory.usage_in_bytes", "5\n")
        self.assertIsNone(P.cgroup_room_gb(self.d))
        self.put("memory/memory.limit_in_bytes", "8000000000\n")
        self.put("memory/memory.usage_in_bytes", "3000000000\n")
        self.put("memory/memory.stat", "cache 2000000000\ntotal_inactive_file 1000000000\n")
        self.assertAlmostEqual(P.cgroup_room_gb(self.d), 6.0)

    def test_free_ram_is_the_smaller_of_the_two(self):
        meminfo, cg = os.path.join(self.d, "meminfo"), os.path.join(self.d, "cg")
        self.put("meminfo", "MemAvailable:    6000000 kB\n")
        self.put("cg/memory.max", "12000000000\n")
        self.put("cg/memory.current", "2000000000\n")
        self.assertAlmostEqual(P.free_ram_gb(meminfo, cg), 6.0)        # the node is fuller than the Job's limit
        self.assertAlmostEqual(P.free_ram_gb(os.path.join(self.d, "none"), cg), 10.0)   # no meminfo: the limit

    def test_the_ram_warning_uses_the_capped_figure(self):
        model = os.path.join(self.d, "model")
        os.makedirs(model)
        with open(os.path.join(model, "config.json"), "w", encoding="utf-8") as f:
            json.dump({"torch_dtype": "bfloat16"}, f)
        with open(os.path.join(model, "model.safetensors"), "wb") as f:
            f.truncate(5 * 10 ** 9)                                        # 5 GB in bf16: 10 GB in float32
        for free, warned in ((10.5, True), (12.0, False), (None, False)):  # warns above 0.9 x free; nothing to say without
            logs = []
            with mock.patch.object(P, "free_ram_gb", return_value=free):
                H._ram_check(model, "float32", logs.append)
            self.assertEqual(bool(logs), warned, free)
            if warned:
                self.assertIn("about 10 GB of RAM in float32 but only 10 GB are free", logs[0])
                self.assertIn("its memory limit", logs[0])

    def test_free_ram_is_capped_by_the_limit(self):
        meminfo, cg = os.path.join(self.d, "meminfo"), os.path.join(self.d, "cg")
        self.put("meminfo", "MemTotal:       64000000 kB\nMemAvailable:   40000000 kB\n")
        self.put("cg/memory.max", "12000000000\n")
        self.put("cg/memory.current", "2000000000\n")
        self.assertAlmostEqual(P.free_ram_gb(meminfo, cg), 10.0)       # the Job's limit, not the node's 40 GB
        self.put("cg/memory.max", "max\n")
        self.assertAlmostEqual(P.free_ram_gb(meminfo, cg), 40.0)       # Docker Desktop sets no limit: the VM's
        self.assertIsNone(P.free_ram_gb(os.path.join(self.d, "none"), os.path.join(self.d, "none")))   # Windows, macOS


class Fp8Kernel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # transformers' own mapping, imported before kernels is faked (it imports the real package when installed)
        from transformers.integrations.hub_kernels import _HUB_KERNEL_MAPPING
        cls.spec = _HUB_KERNEL_MAPPING["finegrained-fp8"]

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.calls, self.logs = [], []

    def config(self, quant):
        with open(os.path.join(self.d, "config.json"), "w", encoding="utf-8") as f:
            json.dump({"model_type": "glm5_next", **({"quantization_config": quant} if quant else {})}, f)

    def kernels(self, fail=None):
        def install_kernel(repo_id, revision=None, version=None, local_files_only=False):
            self.calls.append((repo_id, revision, version, local_files_only))
            if fail:
                raise fail
            return "/cache/kernels--kernels-community--finegrained-fp8/build/torch-cuda"
        return mock.patch.dict(sys.modules, {"kernels": types.SimpleNamespace(install_kernel=install_kernel)})

    def run_it(self, offline=False, cuda="12.8", caps=()):
        from huggingface_hub import constants
        with mock.patch.object(constants, "HF_HUB_OFFLINE", offline), gpus(list(caps), cuda=cuda):
            P.fp8_kernel(self.d, self.logs.append)
            return constants.HF_HUB_OFFLINE

    def test_fetched_with_an_fp8_model(self):
        self.config({"quant_method": "fp8", "fmt": "e4m3", "weight_block_size": [128, 128]})   # GLM-5.3-Flash's
        with self.kernels():
            self.run_it(caps=[])                                       # the download Job: internet, no GPU
        self.assertEqual(self.calls, [(self.spec["repo_id"], self.spec.get("revision"), self.spec.get("version"), False)])
        self.assertIn("is in the cache", self.logs[-1])

    def test_offline_without_the_kernel_stops_before_the_load(self):
        self.config({"quant_method": "fp8"})
        with self.kernels(fail=ValueError("Version 4 is not available in the local cache")), \
                self.assertRaises(P.UsageError) as e:
            self.run_it(offline=True, caps=[(9, 0)])                   # an H100 measure Job
        self.assertIn("Run the download stage again", str(e.exception))
        self.assertIn("not available in the local cache", str(e.exception))
        self.assertTrue(self.calls[0][3])                              # it looked in the cache only

    def test_offline_on_a_gpu_that_dequantizes_only_warns(self):
        self.config({"quant_method": "fp8"})
        for cap in ((8, 0), (8, 6)):                                   # A100, RTX 3090: dequantized, no kernel
            with self.kernels(fail=ValueError("not in the local cache")):
                self.run_it(offline=True, caps=[cap])
            self.assertIn("WARNING", self.logs[-1], cap)
        with self.kernels(fail=ValueError("not in the local cache")), self.assertRaises(P.UsageError):
            self.run_it(offline=True, caps=[(8, 9)])                   # RTX 4090, L4, L40S keep FP8: they need it

    def test_a_failed_fetch_online_warns(self):
        self.config({"quant_method": "fp8"})
        with self.kernels(fail=OSError("Hub unreachable")):
            self.assertFalse(self.run_it(caps=[(9, 0)]))
        self.assertIn("the kernel is not in the cache (OSError: Hub unreachable)", self.logs[-1])
        self.assertEqual([c[3] for c in self.calls], [False, True])     # asked the Hub, then looked in the cache

    def test_a_cached_kernel_is_used_when_the_hub_is_out_of_reach(self):
        self.config({"quant_method": "fp8"})

        def install_kernel(repo_id, revision=None, version=None, local_files_only=False):
            self.calls.append(local_files_only)
            if not local_files_only:
                raise ValueError("could not verify publisher trust status")
            return "/cache/build/torch-cuda"
        with mock.patch.dict(sys.modules, {"kernels": types.SimpleNamespace(install_kernel=install_kernel)}):
            offline_after = self.run_it(caps=[(9, 0)])
        self.assertTrue(offline_after)                                 # transformers' get_kernel then reads the cache
        self.assertIn("the FP8 kernel is in the cache: this run uses the cache", self.logs[-1])

    def test_a_missing_kernels_package_is_named(self):
        self.config({"quant_method": "fp8"})
        with mock.patch.dict(sys.modules, {"kernels": None}):          # import kernels raises ImportError
            with self.assertRaises(P.UsageError) as e:
                self.run_it(caps=[(9, 0)])                             # a GPU that needs it: stop before the load
            self.run_it(caps=[])                                       # the download Job: a warning
        self.assertIn("pip install kernels==0.18.3", str(e.exception))
        self.assertIn("WARNING", self.logs[-1])
        self.assertIn("pip install kernels==0.18.3", self.logs[-1])

    def test_nothing_to_fetch(self):
        self.config(None)                                              # bf16
        with self.kernels():
            self.run_it()
        self.config({"quant_method": "fp8"})
        with self.kernels():
            self.run_it(cuda=None)                                     # a CPU build: FP8 is dequantized
        self.assertEqual((self.calls, self.logs), ([], []))

    def test_the_download_stage_fetches_it_for_a_copy_already_here(self):
        models = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, models, True)
        dst = os.path.join(models, "glm-5.3-flash")
        os.makedirs(dst)
        for name, text in (("config.json", "{}"), ("tokenizer.json", "{}"), ("model.safetensors", "")):
            with open(os.path.join(dst, name), "w", encoding="utf-8") as f:
                f.write(text)
        run = FakeRun()
        with mock.patch.object(P, "fp8_kernel") as k:
            self.assertEqual(P.step_download(run, "zai-org/GLM-5.3-Flash", models), dst)
        k.assert_called_once_with(dst, run.log)


class DownloadPaths(unittest.TestCase):
    """The kernel comes with every way the download stage ends: a fresh download (the Kubernetes download Job) and a
    folder copied from the disk, as well as a copy already there (above)."""
    def test_a_fresh_download_and_a_local_folder(self):
        from abliterate.tests.test_download import StepDownload
        t = StepDownload("test_an_interrupted_download_goes_on")
        t.setUp()
        self.addCleanup(t.doCleanups)
        run = FakeRun()
        with t.hub(t.small_model()), mock.patch.object(P, "free_ram_gb", return_value=64.0), \
                mock.patch.object(P, "fp8_kernel") as k:
            dst = P.step_download(run, t.repo, t.models)
        k.assert_called_once_with(dst, run.log)
        src = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, src, True)
        for name, text in (("config.json", "{}"), ("tokenizer.json", "{}"), ("model.safetensors", "")):
            with open(os.path.join(src, name), "w", encoding="utf-8") as f:
                f.write(text)
        models = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, models, True)
        with mock.patch.object(P, "fp8_kernel") as k:
            dst = P.step_download(run, src, models)
        k.assert_called_once_with(dst, run.log)


class LegacyChatGLM(unittest.TestCase):
    def test_refused_with_the_hf_checkpoint_named(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        cfg = os.path.join(d, "config.json")
        with open(cfg, "w", encoding="utf-8") as f:
            json.dump({"model_type": "chatglm", "architectures": ["ChatGLMModel"], "num_layers": 40, "hidden_size": 4096,
                       "auto_map": {"AutoModel": "modeling_chatglm.ChatGLMForConditionalGeneration"}}, f)
        info = A.inspect(d)
        self.assertEqual(info["support"], "unsupported")
        self.assertTrue(any("glm-4-9b-chat-hf" in n and "transformers 5" in n for n in info["notes"]), info["notes"])
        self.assertFalse(any("needs --trust-remote-code" in n for n in info["notes"]))   # refused: no loading advice
        with open(cfg, "w", encoding="utf-8") as f:   # the -hf checkpoint of the same model, its real config (the Hub's)
            json.dump({"model_type": "glm", "architectures": ["GlmForCausalLM"], "num_hidden_layers": 40, "hidden_size": 4096}, f)
        info = A.inspect(d)
        self.assertEqual((info["support"], info["post_norm"]), ("exact", False))
        self.assertIn("glm-4-9b-chat-hf", info["family"])


if __name__ == "__main__":
    unittest.main()
