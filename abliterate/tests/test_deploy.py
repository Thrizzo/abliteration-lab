"""abliterate.deploy without llama.cpp or Ollama (stdlib only; a fake converter stands in for llama.cpp):
- the GGUF converter (llama.cpp pins transformers 4.x) reads model folders whose tokenizer transformers v5 saved,
  and the folder is never changed;
- the Ollama template is chosen from the chat template alone.

    python -m unittest discover -s abliterate/tests -t .
"""
import hashlib
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

from abliterate import deploy as DP

# what transformers 5.x writes for GLM-Edge's tokenizer (shortened)
V5 = {"backend": "tokenizers", "clean_up_tokenization_spaces": False, "eos_token": "<|endoftext|>",
      "extra_special_tokens": ["<|endoftext|>", "[gMASK]", "<sop>", "<|user|>"], "is_local": True,
      "local_files_only": False, "model_max_length": 8192, "pad_token": "<|endoftext|>", "padding_side": "left",
      "tokenizer_class": "TokenizersBackend"}
# what transformers 4.x writes (extra_special_tokens is a dict of named tokens there)
V4 = {"additional_special_tokens": ["<|user|>"], "eos_token": "<|endoftext|>",
      "extra_special_tokens": {"image_token": "<|image|>"}, "model_max_length": 8192,
      "tokenizer_class": "PreTrainedTokenizerFast"}

# records what it was asked to convert, then writes the output file like the real converter
FAKE_CONVERTER = r'''
import json, os, sys
src, out = sys.argv[1], sys.argv[sys.argv.index("--outfile") + 1]
cfg = json.load(open(os.path.join(src, "tokenizer_config.json"), encoding="utf-8"))
weights = open(os.path.join(src, "model.safetensors"), "rb").read().decode()
json.dump({"src": src, "tokenizer_class": cfg.get("tokenizer_class"), "weights": weights}, open(out, "w"))
'''


def make_model(root, name, tokenizer_config):
    d = os.path.join(root, name)
    os.makedirs(os.path.join(d, "original"))
    for fn, text in (("config.json", '{"model_type": "glm"}'), ("model.safetensors", "WEIGHTS"),
                     ("tokenizer.json", "{}"), ("tokenizer_config.json", json.dumps(tokenizer_config))):
        with open(os.path.join(d, fn), "w", encoding="utf-8") as f:
            f.write(text)
    return d


def digest(folder):
    h = hashlib.sha256()
    for r, _, fs in sorted(os.walk(folder)):
        for fn in sorted(fs):
            h.update(fn.encode() + open(os.path.join(r, fn), "rb").read())
    return h.hexdigest()


class V4TokenizerConfig(unittest.TestCase):
    def test_v5_file_is_translated(self):
        out = DP.v4_tokenizer_config(V5)
        self.assertEqual(out["tokenizer_class"], "PreTrainedTokenizerFast")
        self.assertNotIn("extra_special_tokens", out)
        self.assertEqual(out["additional_special_tokens"], V5["extra_special_tokens"])
        for k in ("backend", "is_local", "local_files_only"):
            self.assertNotIn(k, out)
        self.assertEqual(out["model_max_length"], 8192)            # everything else is kept

    def test_merges_into_existing_additional_tokens_without_duplicates(self):
        out = DP.v4_tokenizer_config({**V5, "additional_special_tokens": ["<|user|>", "<|x|>"]})
        self.assertEqual(out["additional_special_tokens"], ["<|user|>", "<|x|>", "<|endoftext|>", "[gMASK]", "<sop>"])

    def test_v4_file_needs_no_change(self):
        self.assertIsNone(DP.v4_tokenizer_config(V4))

    def test_input_is_not_modified(self):
        before = json.dumps(V5, sort_keys=True)
        DP.v4_tokenizer_config(V5)
        self.assertEqual(json.dumps(V5, sort_keys=True), before)


class ConverterView(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.work = os.path.join(self.root, "gguf")
        os.makedirs(self.work)

    def tearDown(self):
        self.tmp.cleanup()

    def test_v5_folder_gets_a_temporary_view(self):
        model = make_model(self.root, "tiny-glm", V5)
        before = digest(model)
        with DP.converter_view(model, self.work, lambda m: None) as view:
            self.assertNotEqual(view, model)
            self.assertEqual(os.path.basename(view), "tiny-glm")   # the converter names the model after its folder
            with open(os.path.join(view, "model.safetensors"), encoding="utf-8") as f:
                self.assertEqual(f.read(), "WEIGHTS")
            self.assertTrue(os.path.samefile(os.path.join(view, "model.safetensors"), os.path.join(model, "model.safetensors")))
            with open(os.path.join(view, "tokenizer_config.json"), encoding="utf-8") as f:
                self.assertEqual(json.load(f)["tokenizer_class"], "PreTrainedTokenizerFast")
            self.assertFalse(os.path.exists(os.path.join(view, "original")))   # only top-level files
        self.assertEqual(os.listdir(self.work), [])                # the view is removed afterwards
        self.assertEqual(digest(model), before)                    # and the model folder never changed

    def test_view_is_removed_when_the_converter_fails(self):
        model = make_model(self.root, "tiny-glm", V5)
        with self.assertRaises(RuntimeError):
            with DP.converter_view(model, self.work, lambda m: None):
                raise RuntimeError("converter crashed")
        self.assertEqual(os.listdir(self.work), [])

    def test_v4_folder_is_used_as_is(self):
        model = make_model(self.root, "glm-edge", V4)
        with DP.converter_view(model, self.work, lambda m: None) as view:
            self.assertEqual(view, model)
        self.assertEqual(os.listdir(self.work), [])

    def test_folder_without_tokenizer_config_is_used_as_is(self):
        model = make_model(self.root, "m", V4)
        os.remove(os.path.join(model, "tokenizer_config.json"))
        with DP.converter_view(model, self.work, lambda m: None) as view:
            self.assertEqual(view, model)

    def test_hard_link_when_symlinks_are_not_allowed(self):
        model = make_model(self.root, "tiny-glm", V5)
        with mock.patch.object(DP.os, "symlink", side_effect=OSError("privilege not held")):
            with DP.converter_view(model, self.work, lambda m: None) as view:
                p = os.path.join(view, "model.safetensors")
                self.assertFalse(os.path.islink(p))
                self.assertTrue(os.path.samefile(p, os.path.join(model, "model.safetensors")))
        self.assertTrue(os.path.isfile(os.path.join(model, "model.safetensors")))


class ConvertGguf(unittest.TestCase):
    def test_converter_reads_the_view_and_the_folder_stays_unchanged(self):
        with tempfile.TemporaryDirectory() as root:
            llama = os.path.join(root, "llama.cpp")
            os.makedirs(llama)
            with open(os.path.join(llama, "convert_hf_to_gguf.py"), "w", encoding="utf-8") as f:
                f.write(FAKE_CONVERTER)
            model = make_model(root, "tiny-glm", V5)
            before = digest(model)
            out = os.path.join(root, "gguf", "tiny-abl-q8_0.gguf")
            with mock.patch.dict(os.environ, {"ABL_GGUF_PY": sys.executable, "ABL_LLAMA_CPP": llama}):
                DP.convert_gguf(root, model, out, lambda m: None, outtype="q8_0")
            with open(out, encoding="utf-8") as f:
                seen = json.load(f)
            self.assertEqual(seen["tokenizer_class"], "PreTrainedTokenizerFast")
            self.assertEqual(seen["weights"], "WEIGHTS")
            self.assertEqual(os.path.basename(seen["src"]), "tiny-glm")
            self.assertEqual(sorted(os.listdir(os.path.dirname(out))), ["tiny-abl-q8_0.gguf"])
            self.assertEqual(digest(model), before)


GLM_EDGE_CHAT = "{% for item in messages %}{% if item['role'] == 'user' %}<|user|>\n{{ item['content'] }}{% endif %}{% endfor %}"
GLM4_CHAT = "[gMASK]<sop>{% for item in messages %}<|{{ item['role'] }}|>\n{{ item['content'] }}{% endfor %}"


class ChatTemplate(unittest.TestCase):
    def folder(self, files):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        for fn, content in files.items():
            with open(os.path.join(d, fn), "w", encoding="utf-8") as f:
                f.write(content if isinstance(content, str) else json.dumps(content))
        return d

    def test_glm_edge_gets_the_glm_edge_template_although_its_special_tokens_name_gmask(self):
        # GLM-Edge as published: the template inside tokenizer_config.json, [gMASK] only among the special tokens
        d = self.folder({"tokenizer_config.json": {"chat_template": GLM_EDGE_CHAT, "tokenizer_class": "PreTrainedTokenizerFast",
                                                   "added_tokens_decoder": {"151331": {"content": "[gMASK]", "special": True}}}})
        self.assertEqual(DP.chat_template_text(d), GLM_EDGE_CHAT)
        self.assertEqual(DP.template_for(DP.chat_template_text(d)), DP.GLM_EDGE_TEMPLATE)

    def test_v5_save_reads_chat_template_jinja(self):
        d = self.folder({"chat_template.jinja": GLM_EDGE_CHAT, "tokenizer_config.json": V5})
        self.assertEqual(DP.template_for(DP.chat_template_text(d)), DP.GLM_EDGE_TEMPLATE)

    def test_glm4_template_starts_with_gmask(self):
        d = self.folder({"tokenizer_config.json": {"chat_template": GLM4_CHAT}})
        self.assertEqual(DP.template_for(DP.chat_template_text(d)), DP.GLM4_TEMPLATE)

    def test_named_templates_use_default(self):
        d = self.folder({"tokenizer_config.json": {"chat_template": [{"name": "tool_use", "template": GLM4_CHAT},
                                                                     {"name": "default", "template": GLM_EDGE_CHAT}]}})
        self.assertEqual(DP.chat_template_text(d), GLM_EDGE_CHAT)

    def test_no_template_files(self):
        self.assertEqual(DP.chat_template_text(self.folder({})), "")
        self.assertEqual(DP.chat_template_text(self.folder({"tokenizer_config.json": "not json"})), "")
        self.assertEqual(DP.chat_template_text(None), "")


if __name__ == "__main__":
    unittest.main()
